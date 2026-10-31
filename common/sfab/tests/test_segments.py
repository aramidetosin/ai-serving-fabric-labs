"""Build A revision 2's segments and firewall: the checks validate adds (one IP MTU per segment,
App-ID on every allow rule, discard and tunnel routes), the operator's VPN router (swanctl.conf
mirrored from the firewall's proxy IDs, its init's dry run), the ingress nodes' VLAN unit and its
routing table, the per-lab pre-shared key and its redaction.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_segments -v
"""

from __future__ import annotations

import dataclasses
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
IMAGES = ROOT / "images"
NETSETUP = IMAGES / "vm-node" / "node-files" / "netsetup.sh"
VPNGW_INIT = IMAGES / "vpngw" / "vpngw-init.sh"

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def _bash():
    for b in ("/opt/homebrew/bin/bash", "/usr/local/bin/bash", shutil.which("bash")):
        if b and os.path.exists(b):
            r = subprocess.run([b, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip().isdigit() and int(r.stdout.strip()) >= 4:
                return b
    return None


BASH = _bash()
_CACHE: dict = {}


def spec():
    if "spec" not in _CACHE:
        from sfab.spec import load

        _CACHE["spec"] = load(ROOT)
    return _CACHE["spec"]


def model(lab: str = "ch02"):
    if lab not in _CACHE:
        from sfab.spec import select

        _CACHE[lab] = select(spec(), ROOT / lab)
    return _CACHE[lab]


def ctx(lab: str = "ch02"):
    from sfab.render import Context

    return Context(outdir=ROOT / lab, labdir=ROOT / lab, root=ROOT, spec=spec())


def parse_env(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k] = v.strip("'")
    return out


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class Validate(unittest.TestCase):
    def test_the_spec_is_clean(self):
        from sfab.validate import problems

        self.assertEqual(problems(model()), [])

    def test_an_allow_rule_names_its_app_ids(self):
        from sfab.validate import check_firewall

        m = model()
        fw = m.firewall
        r = next(x for x in fw.rules if x.name == "staff-to-users-gateway")
        for change, want in ((dict(applications=("any",)), "names its App-IDs"),
                             (dict(services=("any",)), "never any"),
                             (dict(profile_group=None), "carries the profile group")):
            bad = dataclasses.replace(r, **change)
            fw2 = dataclasses.replace(fw, rules=tuple(bad if x is r else x for x in fw.rules))
            probs = check_firewall(dataclasses.replace(m, nodes=dict(m.nodes, fw=fw2)))
            self.assertTrue(any(want in p for p in probs), (want, probs))

    def test_routes_discard_and_tunnel(self):
        from sfab.validate import check_firewall

        m = model()
        fw = m.firewall
        kinds = {r.name: (r.kind, r.interface, r.nexthop) for r in fw.routes}
        self.assertEqual(kinds["discard-10"], ("discard", None, None))
        self.assertEqual(kinds["operator-site"], ("interface", "tunnel.1", None))
        bad = dataclasses.replace(next(r for r in fw.routes if r.name == "operator-site"), interface="ethernet1/5")
        fw2 = dataclasses.replace(fw, routes=tuple(bad if r.name == "operator-site" else r for r in fw.routes))
        probs = check_firewall(dataclasses.replace(m, nodes=dict(m.nodes, fw=fw2)))
        self.assertTrue(any("goes out a tunnel interface" in p for p in probs), probs)

    def test_one_ip_mtu_per_segment(self):
        from sfab.validate import check_segment_mtu

        m = model()
        self.assertEqual(check_segment_mtu(m), [])
        fw = m.firewall
        ifs = tuple(dataclasses.replace(i, mtu=9216) if i.name == "ae1.110" else i for i in fw.interfaces)
        probs = check_segment_mtu(dataclasses.replace(m, nodes=dict(m.nodes, fw=dataclasses.replace(fw, interfaces=ifs))))
        self.assertEqual(probs, ["firewall ae1.110: mtu 9216 differs from segment ingress's IP MTU 1500"])
        g = m.nodes["k8s-gpu1"]
        vi = dataclasses.replace(g.bond.vlan_ifs[0], mtu=1500)
        g2 = dataclasses.replace(g, bond=dataclasses.replace(g.bond, vlan_ifs=(vi,)))
        probs = check_segment_mtu(dataclasses.replace(m, nodes=dict(m.nodes, **{"k8s-gpu1": g2})))
        self.assertEqual(probs, ["k8s-gpu1: bond0.120 mtu 1500 differs from segment storage-data's IP MTU 9000"])

    def test_segments_and_units(self):
        m = model()
        self.assertEqual({k: (s.prefix, s.vlan, s.mtu) for k, s in m.segments.items() if k in ("nodes", "ingress", "storage-data")},
                         {"nodes": ("10.20.1.0/24", 100, 9000), "ingress": ("10.20.11.0/24", 110, 1500),
                          "storage-data": ("10.20.12.0/24", 120, 9000)})
        self.assertIsNone(m.vlans[120].gw, "storage data is Layer 2 only")
        ing = m.nodes["k8s-ingress1"].bond.vlan_ifs[0]
        self.assertEqual((ing.name, ing.address, ing.table, ing.gateway, ing.prefix), ("bond0.110", "10.20.11.11/24", 110, "10.20.11.1", "10.20.11.0/24"))
        st = m.nodes["k8s-gpu2"].bond.vlan_ifs[0]
        self.assertEqual((st.name, st.address, st.table, st.gateway), ("bond0.120", "10.20.12.22/24", None, None))
        self.assertEqual({g.name: g.vip for g in m.gateways.values()}, {"gw-internal": "10.20.11.200", "gw-users": "10.20.11.210"})
        self.assertEqual(m.nodes["k8s-cp1"].oob.netns, "bmc")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class VpnRouter(unittest.TestCase):
    def test_swanctl_mirrors_the_proxy_ids(self):
        from sfab.render import host

        m = model()
        text = host.swanctl_conf(m, m.nodes["ops-gw"], ctx())
        for want in ("local_addrs = 192.0.2.22", "remote_addrs = 198.51.100.2", "proposals = aes256-sha256-modp2048",
                     "esp_proposals = aes256-sha256-modp2048", "keyingtries = 0"):
            self.assertIn(want, text)
        self.assertEqual(text.count("local_ts = 192.0.2.0/30"), 2)
        self.assertIn("remote_ts = 10.20.11.0/24", text)
        self.assertIn("remote_ts = 10.20.3.0/24", text)
        self.assertNotIn("secret", text, "the key is never rendered")
        env = parse_env(host.init_env(m, m.nodes["ops-gw"], ctx()))
        self.assertEqual((env["IPSEC_DIR"], env["IPSEC_PSK"], env["IPSEC_PEER_ID"]), ("/sfab/ipsec", "ops-gw", "198.51.100.2"))
        self.assertEqual((env["ETH1_MTU"], env["ETH2_MTU"]), ("1500", "1500"))

    def test_a_router_with_no_tunnel_is_refused(self):
        from sfab.render import host

        m = model()
        h = m.nodes["ops-gw"]
        h2 = dataclasses.replace(h, props=dict(h.props, vpn={"firewall_vpn": "nowhere"}))
        with self.assertRaisesRegex(host.HostRenderError, "is not a tunnel of the firewall"):
            host.swanctl_conf(m, h2, ctx())

    def test_the_topology_binds_the_key_directory(self):
        from sfab.render import clab

        text, st = clab.build(model(), ctx())
        self.assertEqual(st["ipsec"], ["ops-gw"])
        t = yaml.safe_load(text)
        node = t["topology"]["nodes"]["ops-gw"]
        self.assertIn("state/secrets/ipsec:/sfab/ipsec:ro", node["binds"])
        self.assertIn("state/secrets/authorized_keys:/sfab/authorized_keys:ro", node["binds"])
        self.assertEqual(node["image"], "sfab/vpngw:3")
        self.assertEqual(t["topology"]["nodes"]["web-client"]["exec"][1], "sh -c 'nohup python3 /sfab/bootstrap/listen.py >/dev/null 2>&1 &'")

    @unittest.skipUnless(BASH, "bash 4 or later is needed")
    def test_init_dry_run(self):
        from sfab.render import host

        m = model()
        with tempfile.TemporaryDirectory() as t:
            d = Path(t)
            (d / "init.env").write_text(host.init_env(m, m.nodes["ops-gw"], ctx()))
            (d / "swanctl.conf").write_text(host.swanctl_conf(m, m.nodes["ops-gw"], ctx()))
            net = d / "net-init.sh"
            net.write_text("#!/bin/sh\necho net-init \"$@\"\n")
            net.chmod(0o755)
            r = subprocess.run([BASH, str(VPNGW_INIT), str(d / "init.env")], capture_output=True, text=True, timeout=30,
                               env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "SFAB_DRY_RUN": "1", "SFAB_NET_INIT": str(net)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("+ sysctl net.ipv4.ip_forward=1", r.stdout)
        mgmt = m.nodes["ops-gw"].mgmt
        self.assertIn(f"+ login admin (key only, sudo, group ipsec for swanctl) from /sfab/authorized_keys; sshd on {mgmt}:22", r.stdout)
        self.assertIn("+ write /etc/swanctl/conf.d/sfab-secrets.conf (0600) from /sfab/ipsec/ops-gw.psk", r.stdout)


@unittest.skipUnless(HAVE_YAML and BASH, "PyYAML and bash 4 or later are needed")
class IngressNode(unittest.TestCase):
    def test_vlan_unit_and_its_table(self):
        from sfab.render import host

        m = model()
        env = host.node_env(m, m.nodes["k8s-ingress1"], ctx())
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "node.env"
            f.write_text(env)
            r = subprocess.run([BASH, str(NETSETUP)], capture_output=True, text=True, timeout=60,
                               env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "SFAB_DRY_RUN": "1",
                                    "SFAB_NODE_ENV": str(f)})
        self.assertEqual(r.returncode, 0, r.stderr)
        cmds = [x[2:] for x in r.stdout.splitlines() if x.startswith("+ ")]
        for want in ("ip link add link bond0 name bond0.110 type vlan id 110", "ip link set bond0.110 mtu 1500",
                     "ip addr replace 10.20.11.11/24 dev bond0.110",
                     "ip route replace 10.20.11.0/24 dev bond0.110 src 10.20.11.11 table 110",
                     "ip route replace default via 10.20.11.1 dev bond0.110 table 110",
                     "ip rule add from 10.20.11.0/24 lookup 110",
                     "ip addr replace 10.20.1.31/24 dev bond0", "ip route replace default via 10.20.1.1 dev bond0"):
            self.assertIn(want, cmds)


class KeysAndRedaction(unittest.TestCase):
    def _mod(self, path: Path, name: str):
        s = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(s)
        s.loader.exec_module(mod)
        return mod

    def test_the_pre_shared_key_is_made_once_and_redacted(self):
        sec = self._mod(ROOT / "common" / "bin" / "secrets.py", "sfab_test_secrets")
        red = self._mod(ROOT / "common" / "audit" / "redact.py", "sfab_test_redact")
        with tempfile.TemporaryDirectory() as t:
            lab = Path(t)
            (lab / "gen").mkdir()
            (lab / "gen" / "clab-state.json").write_text('{"tsig": [], "ipsec": ["ops-gw"]}')
            state = lab / "state"
            p = sec.paths(str(state))
            os.makedirs(p["dir"], mode=0o700)
            made = sec.write_ipsec(p, str(state))
            self.assertEqual(made, ["ops-gw"])
            f = state / "secrets" / "ipsec" / "ops-gw.psk"
            key = f.read_text().strip()
            self.assertRegex(key, r"^[A-Za-z0-9]{40}$")
            self.assertEqual(f.stat().st_mode & 0o777, 0o600)
            self.assertEqual(sec.write_ipsec(p, str(state)), [], "a key that exists is kept")
            self.assertEqual(f.read_text().strip(), key)
            vals = red.secret_values(str(state / "secrets.env"))
            self.assertIn(key, vals)
            out = red.redact_text(f"psk {key}\nset network ike gateway ops-gw authentication pre-shared-key key -AQ==abc\n", vals)
            self.assertNotIn(key, out)
            self.assertNotIn("-AQ==abc", out)
            self.assertIn("pre-shared-key key <redacted hmac:", out)


if __name__ == "__main__":
    unittest.main()
