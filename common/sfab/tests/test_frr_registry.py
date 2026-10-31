"""FRR and registry tests: render/frr.py (the uplink and ISP routers), the sfab/frr image's
scripts (frr-init.sh, frr-restore.sh) in dry runs, and the sfab/registry image's seed
(images/registry/seed.py) against an in-memory registry, plus the image build wiring and the
cross-checks with the spec (upstream hosts, chart path, mirror address).

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_frr_registry -v

Hermetic: no network, no docker. The scripts run with stand-ins for ssh, sshpass and docker first
on PATH (standins.py); the seed's registry, upstream and docker calls are replaced by fakes. The
script tests need bash 4 or later and are skipped without it; the render tests need PyYAML.
"""

from __future__ import annotations

import dataclasses
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.parse
from pathlib import Path

from sfab.tests import standins

ROOT = Path(__file__).resolve().parents[3]
IMAGES = ROOT / "images"
FRR_DIR = IMAGES / "frr"
REG_DIR = IMAGES / "registry"
FRR_INIT = FRR_DIR / "frr-init.sh"
FRR_RESTORE = FRR_DIR / "frr-restore.sh"
SEED_PY = REG_DIR / "seed.py"
DASHES = (chr(0x2014), chr(0x2013))  # the em and en dash

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def _bash() -> str | None:
    b = shutil.which("bash")
    if not b:
        return None
    try:
        v = subprocess.run([b, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return b if v.strip().isdigit() and int(v) >= 4 else None


BASH = _bash()


def _load_seed():
    spec = importlib.util.spec_from_file_location("sfab_registry_seed", SEED_PY)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sfab_registry_seed"] = mod
    spec.loader.exec_module(mod)
    return mod


seed = _load_seed()


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


# ------------------------------------------------------------------------------------------
# Labs, rendered once


class Labs:
    """The spec, and the frr renders of dev/m2 (A/one) and an A/many lab at step 10."""

    _cache: dict = {}

    @classmethod
    def get(cls) -> dict:
        if not cls._cache:
            from sfab.render import Context, frr
            from sfab.spec import load, select

            spec = load(ROOT)
            out = {"spec": spec}
            for key, sel in (("m2", ROOT / "dev" / "m2"), ("many", {"lab": "sfab-ch10", "profile": "a", "state": "many"})):
                model = select(spec, sel)
                ctx = Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-frr", labdir=ROOT / "dev" / "m2", root=ROOT, spec=spec)
                out[key] = {"model": model, "ctx": ctx, "files": frr.render(model, ctx)}
            cls._cache = out
        return cls._cache


def env_of(text: str) -> dict:
    out = {}
    for line in text.splitlines()[1:]:
        k, _, v = line.partition("=")
        out[k] = v.strip("'")
    return out


# ------------------------------------------------------------------------------------------
# render/frr.py


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class FrrRender(unittest.TestCase):
    def test_m2_renders_the_uplink_router_only(self):
        files = Labs.get()["m2"]["files"]
        self.assertEqual(sorted(files), [f"bootstrap/uplink-rtr/{f}" for f in ("daemons", "frr.conf", "init.env", "vtysh.conf")])

    def test_uplink_frr_conf(self):
        conf = Labs.get()["m2"]["files"]["bootstrap/uplink-rtr/frr.conf"]
        lines = conf.splitlines()
        self.assertTrue(lines[0].startswith("! sfab-m2 uplink-rtr: rendered from spec/profile-a.yaml"))
        body = [ln for ln in lines if not ln.startswith("!")]
        inside = ["10.20.1.0/24", "10.20.11.0/24", "10.20.2.0/24", "10.20.3.0/24", "10.20.13.0/24", "10.20.14.0/24", "10.20.9.0/24", "10.24.10.0/24"]
        self.assertEqual(body, [
            "frr defaults traditional",
            "hostname uplink-rtr",
            "log stdout informational",
            "service integrated-vtysh-config",
            # the operator's site LAN, behind its VPN router
            "ip route 192.0.2.0/30 192.0.2.22",
            *[f"ip route {p} 198.51.100.2" for p in inside],
            "interface eth1", " description fw-eth5", " ip address 198.51.100.1/29", "exit",
            "interface eth3", " description inet-registry-eth1", " ip address 192.0.2.5/30", "exit",
            "interface eth5", " description inet-ntp-eth1", " ip address 192.0.2.13/30", "exit",
            "interface eth6", " description web-client-eth1", " ip address 192.0.2.17/30", "exit",
            "interface eth7", " description ops-gw-eth1", " ip address 192.0.2.21/30", "exit",
            "end",
        ])
        # The operator resolver's port (eth4) is not wired in M2, the management port is never
        # configured, and the uplink router has no default route: only build A's inside prefixes
        # route inward, to the firewall's public address, each after a
        # comment naming its id and decision.
        self.assertNotIn("eth4", conf)
        self.assertNotIn("eth0", [ln.split()[-1] for ln in body if ln.startswith("interface")])
        self.assertNotIn("ip route 0.0.0.0/0", conf)
        i = lines.index("ip route 10.20.1.0/24 198.51.100.2")
        self.assertEqual(lines[i - 1], "! inside-nodes: dec-route-inside-via-fw")
        self.assertLess(lines.index("ip route 10.24.10.0/24 198.51.100.2"), lines.index("interface eth1"))
        self.assertNotIn("frr: uplink-rtr", " ".join(Labs.get()["m2"]["ctx"].warnings))
        self.assertTrue(conf.endswith("end\n"))

    def test_the_uplink_router_routes_only_what_the_firewall_gateways(self):
        # without the enterprise client, the firewall's ethernet1/4 is unwired: 10.24.10.0/24 would
        # come back on the firewall's default route, so it is left out, with a comment saying why
        from sfab.render import Context, frr
        from sfab.spec import select

        spec = Labs.get()["spec"]
        m = select(spec, {"lab": "sfab-ch04", "profile": "a", "state": "one",
                          "slice": {"nodes": ["fe", "oob", "fw", "bastion", "uplink-rtr", "ops-client"]},
                          "features": {"k8s": False, "serving": False, "storage_setup": False}})
        ctx = Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-frr", labdir=ROOT / "dev" / "m2", root=ROOT, spec=spec)
        conf = frr.render(m, ctx)["bootstrap/uplink-rtr/frr.conf"]
        self.assertIn("ip route 10.20.9.0/24 198.51.100.2", conf)
        self.assertNotIn("ip route 10.24.10.0/24", conf)
        self.assertIn("! inside-enterprise: dec-route-inside-via-fw: not rendered, the firewall gateways no 10.24.10.0/24 in this lab", conf)
        r = next(x for x in m.routers["uplink-rtr"].routes if x.id == "inside-nodes")
        self.assertEqual((r.dest, r.via, r.dest_ref, r.via_ref, r.decision), ("10.20.1.0/24", "198.51.100.2", "seg:nodes", "public",
                                                                              "dec-route-inside-via-fw"))
        from sfab.render.inventory import inventory
        self.assertEqual([x["dest"] for x in inventory(m)["nodes"]["uplink-rtr"]["routes"]],
                         ["192.0.2.0/30", "10.20.1.0/24", "10.20.11.0/24", "10.20.2.0/24", "10.20.3.0/24", "10.20.13.0/24", "10.20.14.0/24",
                          "10.20.9.0/24"])

    def test_route_references_are_checked(self):
        from sfab.spec import SpecError, select

        spec = Labs.get()["spec"]
        bad = json.loads(json.dumps(spec.profiles["a"]))
        bad["hosts"]["uplink-rtr"]["routes"][0]["dest"] = "seg:nowhere"
        spec2 = dataclasses.replace(spec, profiles=dict(spec.profiles, a=bad))
        with self.assertRaisesRegex(SpecError, "no segment 'nowhere'"):
            select(spec2, ROOT / "dev" / "m2")
        bad["hosts"]["uplink-rtr"]["routes"][0]["dest"] = "seg:data"
        bad["hosts"]["uplink-rtr"]["routes"][0]["metric"] = 5
        with self.assertRaisesRegex(SpecError, "unknown key"):
            select(dataclasses.replace(spec, profiles=dict(spec.profiles, a=bad)), ROOT / "dev" / "m2")

    def test_no_command_zebra_does_not_know(self):
        # zebra has no MTU command for a kernel interface (vtysh -C refuses ' mtu 9000'), so an
        # interface block holds only its description and address.
        for lab in ("m2", "many"):
            for path, text in Labs.get()[lab]["files"].items():
                if not path.endswith("frr.conf"):
                    continue
                block = None
                for ln in text.splitlines():
                    if ln.startswith("interface "):
                        block = ln
                        continue
                    if block and ln == "exit":
                        block = None
                        continue
                    if block:
                        self.assertRegex(ln, r"^ (description \S+|ip address \S+|ipv6 address \S+)$", f"{path}: {ln!r}")

    def test_isp_router_routes_the_public_address_inward(self):
        files = Labs.get()["many"]["files"]
        conf = files["bootstrap/isp-rtr/frr.conf"]
        lines = conf.splitlines()
        i = lines.index("ip route 198.51.100.2/32 198.51.100.10")
        self.assertEqual(lines[i - 1], "! public-address")
        self.assertIn(" ip address 198.51.100.9/30", lines)
        self.assertIn(" ip address 203.0.113.1/30", lines)
        self.assertIn(" ip address 203.0.113.5/30", lines)
        # the routes come before the interfaces, as show running-config prints them
        self.assertLess(i, lines.index("interface eth1"))
        self.assertNotIn("frr: isp-rtr", " ".join(Labs.get()["many"]["ctx"].warnings))

    def test_daemons_file(self):
        from sfab.render import frr

        text = Labs.get()["m2"]["files"]["bootstrap/uplink-rtr/daemons"]
        kv = dict(ln.split("=", 1) for ln in text.splitlines() if ln and not ln.startswith("#"))
        # every daemon FRR 10.5.4's own daemons file lists is off; zebra, mgmtd and staticd always run
        stock = ["bgpd", "ospfd", "ospf6d", "ripd", "ripngd", "isisd", "pimd", "pim6d", "ldpd", "nhrpd", "eigrpd",
                 "babeld", "sharpd", "pbrd", "bfdd", "fabricd", "vrrpd", "pathd"]
        self.assertEqual(list(frr.OPTIONAL), stock)
        for d in stock:
            self.assertEqual(kv[d], "no")
        for d in frr.ALWAYS:
            self.assertNotIn(d, kv)
            self.assertIn(f"{d}_options", kv)
        self.assertEqual(kv["vtysh_enable"], "yes")
        self.assertEqual(kv["zebra_options"], '"  -A 127.0.0.1 -s 90000000"')

    def test_vtysh_conf(self):
        text = Labs.get()["m2"]["files"]["bootstrap/uplink-rtr/vtysh.conf"]
        self.assertEqual(text.splitlines()[1:], ["service integrated-vtysh-config"])

    def test_init_env(self):
        text = Labs.get()["m2"]["files"]["bootstrap/uplink-rtr/init.env"]
        lines = text.splitlines()
        self.assertTrue(lines[0].startswith("# sfab-m2 uplink-rtr:"))
        self.assertEqual(lines[1:], sorted(lines[1:]), "init.env keys must be sorted")
        env = env_of(text)
        self.assertEqual(env["MGMT_IF"], "eth0")
        self.assertEqual(env["MGMT_ADDR"], "172.21.40.61/24")
        self.assertEqual(env["MGMT_GW"], "172.21.40.1")
        self.assertEqual(env["MGMT_VRF"], "mgmt")
        self.assertEqual(env["MGMT_TABLE"], "150")
        self.assertEqual(env["IFACES"], "eth1 eth3 eth5 eth6 eth7")
        self.assertEqual(env["TX_OFF"], "eth1 eth3 eth5 eth6 eth7")
        self.assertEqual((env["ETH1_MTU"], env["ETH7_MTU"]), ("1500", "1500"), "the uplink side's IP MTU")
        self.assertEqual((env["IP_FORWARD"], env["RP_FILTER"], env["LINK_WAIT_S"]), ("1", "0", "180"))
        self.assertEqual(env["NODE_NAME"], "uplink-rtr")
        self.assertNotIn("CORE_IFS", env)
        self.assertNotIn("VRFS", env)
        # the lab's domain, so frr-init.sh replaces the search line Docker copied from the lab host
        self.assertEqual(env["SEARCH"], "ai.tarnwick.example")
        self.assertNotIn("DNS_SERVERS", env)

    def test_byte_stable_and_plain(self):
        from sfab.render import frr

        lab = Labs.get()["m2"]
        again = frr.render(lab["model"], lab["ctx"])
        self.assertEqual(again, lab["files"])
        for lab in ("m2", "many"):
            for path, text in Labs.get()[lab]["files"].items():
                self.assertTrue(text.endswith("\n"), path)
                self.assertNotIn("\t", text, path)
                self.assertNotIn("\r", text, path)
                for d in DASHES:
                    self.assertNotIn(d, text, path)

    def _router(self, **routes):
        from sfab.model import Route

        lab = Labs.get()["many"]
        h = lab["model"].routers["isp-rtr"]
        return dataclasses.replace(h, routes=tuple(Route(**r) for r in routes["routes"]))

    def _routes(self, *routes):
        from sfab.render import Context, frr

        h = self._router(routes=routes)
        ctx = Context(outdir=Path(tempfile.gettempdir()), labdir=ROOT, root=ROOT, spec=Labs.get()["spec"])
        return frr.static_routes(Labs.get()["many"]["model"], h, ctx), ctx.warnings

    def test_route_forms(self):
        lines, warns = self._routes({"dest": "203.0.113.64/26", "via": "203.0.113.2"},
                                    {"dest": "203.0.113.128/26", "dev": "eth2"},
                                    {"dest": "203.0.113.192/26", "via": "203.0.113.6", "dev": "eth3"})
        self.assertEqual(lines, ["ip route 203.0.113.64/26 203.0.113.2", "ip route 203.0.113.128/26 eth2",
                                 "ip route 203.0.113.192/26 203.0.113.6 eth3"])
        self.assertEqual(warns, [])

    def test_route_warnings(self):
        lines, warns = self._routes({"dest": "192.0.2.64/26", "via": "192.0.2.65", "id": "far"},
                                    {"dest": "192.0.2.128/26", "dev": "eth9", "id": "noport"})
        self.assertEqual(len(lines), 2)
        self.assertTrue(any("far via 192.0.2.65 is on no port" in w for w in warns), warns)
        self.assertTrue(any("noport names port eth9" in w for w in warns), warns)

    def test_route_errors(self):
        from sfab.render.frr import FrrRenderError

        bad = [
            {"dest": "198.51.100.2", "via": "198.51.100.10"},            # not a prefix
            {"dest": "198.51.100.3/24", "via": "198.51.100.10"},         # host bits set
            {"dest": "198.51.100.0/24", "via": "qemu-user"},             # a symbol, not an address
            {"dest": "198.51.100.0/24", "via": "2001:db8::1"},           # another family
            {"dest": "198.51.100.0/24", "via": "198.51.100.10", "src": "198.51.100.9"},
            {"dest": "198.51.100.0/24"},                                 # neither next hop nor port
        ]
        for r in bad:
            with self.assertRaises(FrrRenderError, msg=str(r)):
                self._routes(r)

    def test_pending_router_is_skipped(self):
        from sfab.render import Context, frr

        lab = Labs.get()["m2"]
        m = lab["model"]
        h = dataclasses.replace(m.routers["uplink-rtr"], pending="not settled")
        nodes = dict(m.nodes)
        nodes["uplink-rtr"] = h
        m2 = dataclasses.replace(m, nodes=nodes)
        ctx = Context(outdir=Path(tempfile.gettempdir()), labdir=ROOT, root=ROOT, spec=Labs.get()["spec"])
        self.assertEqual(frr.render(m2, ctx), {})
        self.assertTrue(any("pending" in w for w in ctx.warnings))


# ------------------------------------------------------------------------------------------
# The sfab/frr image


class FrrImage(unittest.TestCase):
    def test_dockerfile(self):
        text = (FRR_DIR / "Dockerfile").read_text()
        self.assertIn("ARG FRR_BASE\nFROM ${FRR_BASE}", text)
        self.assertIn('ENTRYPOINT ["/sbin/tini", "--", "/usr/local/sbin/frr-init.sh"]', text)
        self.assertIn('CMD ["/usr/lib/frr/docker-start"]', text)
        self.assertIn("vtysh -c 'show version'", text)
        self.assertIn("COPY frr-restore.sh /usr/local/sbin/sfab-frr-restore", text)
        labels = re.findall(r"(\S+)=\"", text.split("LABEL", 1)[1].split("RUN", 1)[0])
        self.assertTrue(labels and all(k.startswith("org.opencontainers.image.") for k in labels), labels)

    def test_pins(self):
        sys.path.insert(0, str(IMAGES))
        try:
            import versions  # noqa: PLC0415
        finally:
            sys.path.remove(str(IMAGES))
        tree = versions.load()
        up = tree["images"]["frr_upstream"]
        self.assertEqual(up["ref"], "quay.io/frrouting/frr:10.5.4")
        self.assertRegex(str(up["digest"]), r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(tree["images"]["frr"]["ref"], "sfab/frr:10.5.4-3")
        self.assertEqual(tree["images"]["frr"]["base"], "frr_upstream")
        self.assertEqual(versions.image(tree, "frr_upstream"), f"quay.io/frrouting/frr:10.5.4@{up['digest']}")

    def test_dockerignore_keeps_the_scripts(self):
        ignored = [ln for ln in (FRR_DIR / ".dockerignore").read_text().splitlines() if ln and not ln.startswith("#")]
        for f in ("Dockerfile", "frr-init.sh", "frr-restore.sh"):
            self.assertFalse(any(Path(f).match(p) for p in ignored), f)

    def test_shellcheck(self):
        sc = shutil.which("shellcheck")
        if not sc:
            self.skipTest("shellcheck is not installed")
        r = subprocess.run([sc, "-s", "bash", str(FRR_INIT), str(FRR_RESTORE)], capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


@unittest.skipUnless(BASH, "bash 4 or later is needed")
class FrrInitDryRun(unittest.TestCase):
    """frr-init.sh with SFAB_DRY_RUN=1: every change printed, nothing made."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-frr-"))
        self.bin = standins.make_bin(self.tmp / "bin", {})
        self.conf = self.tmp / "bootstrap"
        self.conf.mkdir()
        self.frrdir = self.tmp / "etc-frr"
        self.frrdir.mkdir()
        self.sshd = self.tmp / "sshd"
        self.sshd.write_text("#!/bin/sh\nexit 0\n")
        self.sshd.chmod(0o755)
        self.resolv = self.tmp / "resolv.conf"
        self.resolv.write_text(standins.DOCKER_RESOLV_CONF)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _env_text(self, extra: dict | None = None) -> str:
        env = {
            "NODE_NAME": "uplink-rtr", "MGMT_IF": "eth0", "MGMT_ADDR": "172.21.40.61/24", "MGMT_GW": "172.21.40.1",
            "MGMT_TABLE": "150", "MGMT_VRF": "mgmt", "IFACES": "'eth1 eth2 eth3'", "TX_OFF": "'eth1 eth2 eth3'",
            "IP_FORWARD": "1", "RP_FILTER": "0", "LINK_WAIT_S": "180", "GUEST_USER": "admin",
        }
        env.update(extra or {})
        return "# test init.env\n" + "".join(f"{k}={v}\n" for k, v in sorted(env.items()))

    def _run(self, env_text: str | None, files=("frr.conf", "daemons", "vtysh.conf"), extra_env: dict | None = None):
        if env_text is not None:
            (self.conf / "init.env").write_text(env_text)
        for f in files:
            (self.conf / f).write_text(f"! {f}\n")
        env = dict(os.environ, PATH=standins.path_with(self.bin), SFAB_DRY_RUN="1",
                   SFAB_INIT_ENV=str(self.conf / "init.env"), SFAB_FRR_DIR=str(self.frrdir),
                   SFAB_AUTHORIZED_KEYS=str(self.tmp / "no-keys"), SFAB_SSHD=str(self.sshd),
                   SFAB_SSHD_CONFIG=str(self.tmp / "sshd_config"), SFAB_RESOLV_CONF=str(self.resolv))
        env.update(extra_env or {})
        standins.check(env, self.bin)
        return subprocess.run([BASH, str(FRR_INIT)], env=env, capture_output=True, text=True,
                              timeout=standins.SCRIPT_TIMEOUT_S)

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
    def test_rendered_init_env(self):
        text = Labs.get()["m2"]["files"]["bootstrap/uplink-rtr/init.env"]
        r = self._run(text)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout.splitlines()
        want = [
            "+ wait for links: eth1 eth3 eth5 eth6 eth7 ",
            "+ sysctl -q -w net.ipv4.ip_forward=1",
            "+ sysctl -q -w net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0",
            "+ sysctl -q -w net.ipv4.conf.eth1.rp_filter=0",
            "+ ip link add mgmt type vrf table 150",
            "+ ip link set mgmt up",
            "+ ip link set eth0 master mgmt",
            "+ ip addr replace 172.21.40.61/24 dev eth0",
            "+ ip route replace default via 172.21.40.1 dev eth0 table 150",
            "+ ip link set eth3 up",
            "+ ethtool -K eth7 tx off",
            # Docker's nameserver and options kept, its search line replaced by the lab's domain
            f"+ write {self.resolv}: search ai.tarnwick.example; nameserver 127.0.0.11; options edns0 trust-ad ndots:0",
            f"+ ln -sfn {self.conf}/frr.conf {self.frrdir}/frr.conf",
            f"+ ln -sfn {self.conf}/daemons {self.frrdir}/daemons",
            f"+ ln -sfn {self.conf}/vtysh.conf {self.frrdir}/vtysh.conf",
            "+ adduser -D -s /bin/bash admin",
            "+ addgroup admin frrvty",
            f"+ {self.sshd} -f {self.tmp}/sshd_config",
            "+ exec /usr/lib/frr/docker-start",
        ]
        for w in want:
            self.assertIn(w, out)
        # the order that matters: resolv.conf before anything can fail, then the links, the VRF
        # before the ports, FRR last
        self.assertLess(out.index(want[11]), out.index(want[0]), "resolv.conf is written before the wait for links")
        self.assertLess(out.index(want[0]), out.index(want[4]))
        self.assertLess(out.index("+ ip link set eth0 master mgmt"), out.index("+ ip link set eth1 up"))
        self.assertEqual(out[-1], "+ exec /usr/lib/frr/docker-start")
        sshd = next(ln for ln in out if ln.startswith(f"+ write {self.tmp}/sshd_config"))
        for part in ("ListenAddress 0.0.0.0 rdomain mgmt", "PermitRootLogin no", "PasswordAuthentication no"):
            self.assertIn(part, sshd)
        self.assertFalse(any(ln.startswith("+ ") and "mpls" in ln for ln in out))
        self.assertFalse(any(ln.startswith("+ ip link add") and "vrf table" in ln and "mgmt" not in ln for ln in out))
        self.assertFalse([ln for ln in out if "lab-host.invalid" in ln])
        # a dry run makes nothing
        self.assertEqual(self.resolv.read_text(), standins.DOCKER_RESOLV_CONF)
        self.assertEqual(list(self.frrdir.iterdir()), [])
        self.assertFalse((self.tmp / "sshd_config").exists())

    def test_carrier_shape(self):
        r = self._run(self._env_text({"CORE_IFS": "'eth1 eth2'", "MPLS_LABELS": "1048575", "VRFS": "'red,1001,eth3 blue,1002,eth4+eth5'",
                                      "IFACES": "'eth1 eth2 eth3 eth4 eth5'", "ETH3_MTU": "9000"}))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout.splitlines()
        for w in ("+ sysctl -q -w net.mpls.platform_labels=1048575", "+ sysctl -q -w net.mpls.conf.eth1.input=1",
                  "+ sysctl -q -w net.mpls.conf.eth2.input=1", "+ ip link add red type vrf table 1001",
                  "+ ip link set eth3 master red", "+ ip link add blue type vrf table 1002", "+ ip link set eth4 master blue",
                  "+ ip link set eth5 master blue", "+ ip link set eth3 mtu 9000"):
            self.assertIn(w, out)
        self.assertNotIn("+ sysctl -q -w net.mpls.conf.eth3.input=1", out)

    def test_missing_env_refuses(self):
        r = self._run(None)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("make render", r.stdout + r.stderr)

    def test_missing_key_refuses(self):
        r = self._run(self._env_text().replace("MGMT_VRF=mgmt\n", ""))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("sets no MGMT_VRF", r.stdout + r.stderr)

    def test_missing_frr_conf_refuses(self):
        r = self._run(self._env_text(), files=("daemons", "vtysh.conf"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("frr.conf", r.stdout + r.stderr)


@unittest.skipUnless(BASH, "bash 4 or later is needed")
class FrrRestore(unittest.TestCase):
    """frr-restore.sh with a stand-in frr-reload.py that prints what the test asks."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-frr-restore-"))
        self.bin = standins.make_bin(self.tmp / "bin", {})
        self.conf = self.tmp / "bootstrap"
        self.conf.mkdir()
        for f in ("frr.conf", "daemons", "vtysh.conf"):
            (self.conf / f).write_text(f"! {f}\n")
        self.frrdir = self.tmp / "etc-frr"
        self.frrdir.mkdir()
        (self.frrdir / "frr.conf").write_text("a copy a write memory left\n")
        self.calls = self.tmp / "calls"
        self.reload = self.tmp / "frr-reload.py"
        self.reload.write_text('#!/bin/sh\necho "$*" >> "$CALLS"\ncase " $* " in *" --test "*) cat "$DIFF" 2>/dev/null ;; esac\n'
                               'echo "INFO: noise on stderr" >&2\nexit 0\n')
        self.reload.chmod(0o755)
        self.diff = self.tmp / "diff"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, *args):
        env = dict(os.environ, PATH=standins.path_with(self.bin), SFAB_FRR_CONF_DIR=str(self.conf),
                   SFAB_FRR_DIR=str(self.frrdir), SFAB_FRR_RELOAD=str(self.reload), CALLS=str(self.calls), DIFF=str(self.diff))
        standins.check(env, self.bin)
        return subprocess.run([BASH, str(FRR_RESTORE), *args], env=env, capture_output=True, text=True,
                              timeout=standins.SCRIPT_TIMEOUT_S)

    def test_check_in_step(self):
        self.diff.write_text("")
        r = self._run("check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("is the render", r.stdout)
        self.assertIn(f"--test --log-level warning {self.conf}/frr.conf", self.calls.read_text())

    def test_check_drift(self):
        self.diff.write_text("\nLines To Add\n============\nno ip route 10.99.0.0/16 blackhole\n\n")
        r = self._run("check")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("no ip route 10.99.0.0/16 blackhole", r.stdout)
        self.assertNotIn("====", r.stdout)

    def test_restore_reloads_through_the_link(self):
        self.diff.write_text("")
        r = self._run("restore")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for f in ("frr.conf", "daemons", "vtysh.conf"):
            p = self.frrdir / f
            self.assertTrue(p.is_symlink(), f)
            self.assertEqual(os.readlink(p), str(self.conf / f))
        calls = self.calls.read_text().splitlines()
        # given the render's own path, frr-reload.py would end with a write memory
        self.assertEqual(calls[0], f"--reload --log-level warning {self.frrdir}/frr.conf")
        self.assertIn("--test", calls[1])

    def test_usage(self):
        r = self._run("bogus")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("usage", r.stderr)


# ------------------------------------------------------------------------------------------
# The seed: pins, references, hosts.toml


class SeedPins(unittest.TestCase):
    def setUp(self):
        self.tree, _ = seed.load_tree(None)

    def test_registry_and_skopeo_pins(self):
        imgs = self.tree["images"]
        self.assertEqual(imgs["registry_upstream"]["ref"], "registry:2")
        self.assertRegex(str(imgs["registry_upstream"]["digest"]), r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(imgs["registry"]["ref"], "sfab/registry:3")
        self.assertEqual(imgs["registry"]["base"], "registry_upstream")
        sk = imgs["skopeo"]
        self.assertTrue(str(sk["ref"]).startswith("quay.io/skopeo/stable:"), sk)
        self.assertRegex(str(sk["digest"]), r"^sha256:[0-9a-f]{64}$")

    def test_collect_the_real_pins(self):
        images, charts = seed.collect(self.tree)
        refs = [im.ref for im in images]
        self.assertEqual(len(refs), len(set(refs)))
        for im in images:
            self.assertRegex(im.digest, r"^sha256:[0-9a-f]{64}$")
            self.assertTrue(im.mirror_path.startswith(im.host + "/"), im)
            # one platform from Docker Hub, and from any host whose pin says platforms: one
            self.assertEqual(im.platform is not None, im.host in seed.ONE_PLATFORM_HOSTS or self._says_one(im), im)
        for c in charts:
            self.assertTrue(c.mirror_path.startswith(seed.CHARTS_PATH + "/"), c)
            self.assertRegex(c.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual([im.mirror_path for im in images], sorted(im.mirror_path for im in images))

    def _says_one(self, im) -> bool:
        cur = self.tree
        for part in im.id.split("."):
            cur = cur[part]
        return cur.get("platforms") == "one"

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
    def test_spec_agrees_with_the_seed(self):
        spec = Labs.get()["spec"]
        from sfab.spec import select

        m = select(spec, ROOT / "dev" / "m2")
        reg = m.spec.get("registry") or {}
        images, _ = seed.collect(self.tree)
        # every upstream the seed copies from gets a hosts.toml on every node
        missing = set(seed.upstreams(images)) - set(reg.get("upstreams") or [])
        self.assertEqual(missing, set(), "spec registry.upstreams lacks a host the seed copies from")
        self.assertEqual(reg.get("charts"), seed.CHARTS_PATH)
        self.assertEqual(reg.get("scheme"), "https", "the registry serves TLS with its leaf of the lab's internet intermediate")
        self.assertEqual(int(reg.get("port")), 5000)
        self.assertEqual(m.registry.mirror, "192.0.2.6:5000")
        # the registry sits on the operator side, behind the uplink router
        self.assertEqual(m.node("inet-registry").gateway, "192.0.2.5")


class SeedRefs(unittest.TestCase):
    def test_parse_ref(self):
        self.assertEqual(seed.parse_ref("docker.io/busybox:1.37.0", "t"), ("docker.io", "library/busybox", "1.37.0"))
        self.assertEqual(seed.parse_ref("index.docker.io/library/busybox:1", "t"), ("docker.io", "library/busybox", "1"))
        self.assertEqual(seed.parse_ref("registry.k8s.io/sig-storage/csi-attacher:v4.4.0", "t"),
                         ("registry.k8s.io", "sig-storage/csi-attacher", "v4.4.0"))
        self.assertEqual(seed.parse_ref("localhost:5000/x/y:1", "t"), ("localhost:5000", "x/y", "1"))
        for bad in ("busybox:1.37.0", "library/busybox:1", "quay.io/x/y", "quay.io/x/y:1@sha256:" + "0" * 64,
                    "quay.io/X/y:1", "quay.io/x/y:bad tag"):
            with self.assertRaises(seed.SeedError, msg=bad):
                seed.parse_ref(bad, "t")

    def test_platform_modes(self):
        d = "sha256:" + "a" * 64
        self.assertEqual(seed._image("t", {"ref": "docker.io/library/busybox:1", "digest": d}).platform, seed.PLATFORM_NAME)
        self.assertIsNone(seed._image("t", {"ref": "docker.io/library/busybox:1", "digest": d, "platforms": "all"}).platform)
        self.assertEqual(seed._image("t", {"ref": "quay.io/x/y:1", "digest": d, "platforms": "one"}).platform, seed.PLATFORM_NAME)
        self.assertIsNone(seed._image("t", {"ref": "quay.io/x/y:1", "digest": d}).platform)
        self.assertIsNone(seed._image("t", {"ref": "quay.io/x/y:1", "digest": d, "used": False}))
        with self.assertRaises(seed.SeedError):
            seed._image("t", {"ref": "quay.io/x/y:1", "digest": d, "platforms": "some"})
        with self.assertRaises(seed.SeedError):
            seed._image("t", {"ref": "quay.io/x/y:1"})
        with self.assertRaises(seed.SeedError):
            seed._image("t", {"ref": "quay.io/x/y:1", "digest": "sha256:short"})

    def test_collect_refuses_two_digests(self):
        a, b = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        tree = {"kubernetes": {"one": {"image": {"ref": "quay.io/x/y:1", "digest": a}}},
                "mirror": {"images": {"two": {"ref": "quay.io/x/y:1", "digest": b}}}}
        with self.assertRaises(seed.SeedError):
            seed.collect(tree)
        tree["mirror"]["images"]["two"]["digest"] = a
        images, _ = seed.collect(tree)
        self.assertEqual(len(images), 1)

    def test_collect_sources(self):
        d = "sha256:" + "c" * 64
        s = "d" * 64
        tree = {
            "images": {"base": {"ref": "docker.io/library/alpine:3.20", "digest": d},
                       "mirrored": {"ref": "ghcr.io/o/m:1", "digest": d, "mirror": True}},
            "kubernetes": {"version": "v1", "addon": {"images": {"a": {"ref": "quay.io/o/a:1", "digest": d}},
                                                      "chart": {"name": "addon", "version": "1.2.3+up", "sha256": s, "repo": "https://charts.example/"}}},
            "mirror": {"charts": {"other": {"name": "other", "version": "0.1.0", "sha256": s, "url": "https://x.example/other-0.1.0.tgz"}}},
        }
        images, charts = seed.collect(tree)
        self.assertEqual([im.ref for im in images], ["ghcr.io/o/m:1", "quay.io/o/a:1"])
        self.assertEqual([c.mirror_path for c in charts], ["charts/addon:1.2.3_up", "charts/other:0.1.0"])
        self.assertEqual(charts[0].repo, "https://charts.example")

    def test_hosts_toml(self):
        self.assertEqual(seed.hosts_toml("registry.k8s.io", "192.0.2.6:5000"),
                         'server = "https://registry.k8s.io"\n\n'
                         '[host."http://192.0.2.6:5000/v2/registry.k8s.io"]\n'
                         '  capabilities = ["pull", "resolve"]\n'
                         '  override_path = true\n')
        self.assertTrue(seed.hosts_toml("docker.io", "192.0.2.6:5000").startswith('server = "https://registry-1.docker.io"\n'))
        r = subprocess.run([sys.executable, str(SEED_PY), "hosts-toml", "--mirror", "192.0.2.6:5000", "quay.io"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, seed.hosts_toml("quay.io", "192.0.2.6:5000"))

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
    def test_rendered_hosts_toml_matches(self):
        """When render/host.py writes the nodes' mirrors, each must be the seed's own file."""
        from sfab.render import Context, host
        from sfab.spec import select

        spec = Labs.get()["spec"]
        m = select(spec, ROOT / "dev" / "m2")
        ctx = Context(outdir=Path(tempfile.gettempdir()), labdir=ROOT / "dev" / "m2", root=ROOT, spec=spec)
        out = host.render(m, ctx)
        found = {p: t for p, t in out.items() if p.endswith("/hosts.toml")}
        if not found:
            self.skipTest("render/host.py writes no containerd hosts.toml yet")
        ups = set((m.spec.get("registry") or {}).get("upstreams") or [])
        per_node: dict = {}
        for p, t in found.items():
            parts = p.split("/")   # bootstrap/<node>/containerd/<upstream>/hosts.toml
            self.assertEqual(parts[2], "containerd", p)
            per_node.setdefault(parts[1], set()).add(parts[3])
            if parts[3] == m.registry.mirror:
                self.assertEqual(t, seed.hosts_toml_local(m.registry.mirror, "https", "/shared/ca/root.crt"), p)
            else:
                self.assertEqual(t, seed.hosts_toml(parts[3], m.registry.mirror, "https", "/shared/ca/root.crt"), p)
        for node, hosts in per_node.items():
            self.assertEqual(hosts, ups, node)


# ------------------------------------------------------------------------------------------
# Charts


def chart_tgz(name: str, version: str, extra: str = "") -> bytes:
    text = (f"apiVersion: v2\nname: {name}\nversion: {version}\ndescription: 'a test chart'\nappVersion: \"1.0\"\n"
            f"keywords:\n  - x\n{extra}").encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo(f"{name}/Chart.yaml")
        info.size = len(text)
        t.addfile(info, io.BytesIO(text))
        sub = b"name: dep\nversion: 9.9.9\n"
        info = tarfile.TarInfo(f"{name}/charts/dep/Chart.yaml")
        info.size = len(sub)
        t.addfile(info, io.BytesIO(sub))
    return buf.getvalue()


class SeedCharts(unittest.TestCase):
    def setUp(self):
        self.tgz = chart_tgz("democratic-csi", "0.15.1")
        self.chart = seed.Chart(id="t", name="democratic-csi", version="0.15.1", sha256=hashlib.sha256(self.tgz).hexdigest(),
                                repo="https://charts.example")
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-seed-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_chart_meta_and_manifest(self):
        meta = seed.chart_meta(self.tgz, self.chart)
        self.assertEqual(meta, {"apiVersion": "v2", "name": "democratic-csi", "version": "0.15.1",
                                "description": "a test chart", "appVersion": "1.0"})
        cfg = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
        body = seed.chart_manifest(cfg, self.tgz, self.chart)
        self.assertEqual(body, seed.chart_manifest(cfg, self.tgz, self.chart))
        doc = json.loads(body)
        self.assertEqual(doc["mediaType"], seed.OCI_MANIFEST)
        self.assertEqual(doc["config"]["mediaType"], seed.HELM_CONFIG)
        self.assertEqual(doc["layers"], [{"mediaType": seed.HELM_LAYER, "digest": sha(self.tgz), "size": len(self.tgz)}])
        wrong = dataclasses.replace(self.chart, version="0.15.2")
        with self.assertRaises(seed.SeedError):
            seed.chart_meta(self.tgz, wrong)
        with self.assertRaises(seed.SeedError):
            seed.chart_meta(b"not a tarball", self.chart)

    def test_index_url(self):
        index = """apiVersion: v1
entries:
  democratic-csi:
  - apiVersion: v2
    dependencies:
    - name: dep
      version: 0.15.1
    name: democratic-csi
    urls:
    - https://github.example/releases/democratic-csi-0.15.0.tgz
    version: 0.15.0
  - name: democratic-csi
    urls:
    - democratic-csi-0.15.1.tgz
    version: 0.15.1
  other:
  - name: other
    urls: [https://elsewhere.example/other-0.15.1.tgz]
    version: 0.15.1
generated: "2026-10-14T00:00:00Z"
"""
        self.assertEqual(seed.index_url(index, self.chart, "https://charts.example"), "https://charts.example/democratic-csi-0.15.1.tgz")
        other = seed.Chart(id="t", name="other", version="0.15.1", sha256="0" * 64, repo="https://charts.example")
        self.assertEqual(seed.index_url(index, other, "https://charts.example"), "https://elsewhere.example/other-0.15.1.tgz")
        missing = dataclasses.replace(self.chart, version="9.9.9")
        self.assertIsNone(seed.index_url(index, missing, "https://charts.example"))

    def test_chart_file_downloads_once(self):
        calls = []
        index = f"entries:\n  democratic-csi:\n  - name: democratic-csi\n    urls:\n    - https://mirror.example/dc.tgz\n    version: 0.15.1\n"

        def opener(req):
            calls.append(req.full_url)
            if req.full_url.endswith("/index.yaml"):
                return Resp(200, body=index.encode())
            if req.full_url == "https://mirror.example/dc.tgz":
                return Resp(200, body=self.tgz)
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

        got = seed.chart_file(self.chart, self.tmp, opener)
        self.assertEqual(got, self.tgz)
        self.assertEqual(calls, ["https://charts.example/democratic-csi-0.15.1.tgz", "https://charts.example/index.yaml",
                                 "https://mirror.example/dc.tgz"])
        self.assertEqual((self.tmp / "charts" / self.chart.file).read_bytes(), self.tgz)
        calls.clear()
        self.assertEqual(seed.chart_file(self.chart, self.tmp, opener), self.tgz)
        self.assertEqual(calls, [])
        bad = dataclasses.replace(self.chart, sha256="0" * 64)
        with self.assertRaises(seed.SeedError):
            seed.chart_file(bad, self.tmp / "other", opener)


# ------------------------------------------------------------------------------------------
# An in-memory registry for the seed's HTTP client


class Resp:
    def __init__(self, status: int, headers: dict | None = None, body: bytes = b""):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


INDEX_MT = "application/vnd.oci.image.index.v1+json"
IMAGE_MT = "application/vnd.oci.image.manifest.v1+json"


class FakeRegistry:
    """Enough of the distribution API for Http: /v2/, manifests by tag or digest, blob uploads."""

    def __init__(self, base: str = "http://127.0.0.1:5099", up: bool = True):
        self.base = base
        self.up = up
        self.repos: dict = {}      # repo -> {ref: (media type, body)}
        self.blobs: dict = {}      # digest -> bytes
        self.uploads: dict = {}
        self.writes = 0

    def store(self, repo: str, tag: str, body: bytes, mt: str) -> str:
        d = sha(body)
        r = self.repos.setdefault(repo, {})
        r[d] = (mt, body)
        r[tag] = (mt, body)
        self.blobs[d] = body
        return d

    def __call__(self, req):
        u = urllib.parse.urlsplit(req.full_url)
        path, method = u.path, req.get_method()
        if not self.up:
            raise urllib.error.URLError("connection refused")
        if path == "/v2/":
            return Resp(200)
        m = re.match(r"^/v2/(.+)/manifests/([^/]+)$", path)
        if m:
            repo, ref = m.groups()
            if method in ("GET", "HEAD"):
                e = self.repos.get(repo, {}).get(ref)
                if e is None:
                    return Resp(404)
                return Resp(200, {"Docker-Content-Digest": sha(e[1]), "Content-Type": e[0]}, e[1] if method == "GET" else b"")
            if method == "PUT":
                self.writes += 1
                body = req.data
                doc = json.loads(body)
                for ref_d in [doc["config"]["digest"]] + [x["digest"] for x in doc.get("layers") or []]:
                    if ref_d not in self.blobs:
                        return Resp(400, body=b"blob unknown")
                d = self.store(repo, ref, body, req.get_header("Content-type"))
                return Resp(201, {"Docker-Content-Digest": d})
        m = re.match(r"^/v2/(.+)/blobs/(sha256:[0-9a-f]{64})$", path)
        if m and method == "HEAD":
            return Resp(200 if m.group(2) in self.blobs else 404)
        m = re.match(r"^/v2/(.+)/blobs/uploads/$", path)
        if m and method == "POST":
            uid = f"u{len(self.uploads)}"
            self.uploads[uid] = m.group(1)
            return Resp(202, {"Location": f"/v2/{m.group(1)}/blobs/uploads/{uid}"})
        m = re.match(r"^/v2/(.+)/blobs/uploads/(u[0-9]+)$", path)
        if m and method == "PUT":
            self.writes += 1
            want = urllib.parse.parse_qs(u.query)["digest"][0]
            if sha(req.data) != want:
                return Resp(400, body=b"digest mismatch")
            self.blobs[want] = req.data
            return Resp(201)
        return Resp(405)


class FakeUpstream:
    """An upstream registry that asks for a bearer token first, as Docker Hub does."""

    def __init__(self, manifests: dict):
        self.manifests = manifests  # (repo, ref) -> (media type, body)
        self.calls: list = []

    def __call__(self, req):
        self.calls.append((req.full_url, req.get_header("Authorization")))
        u = urllib.parse.urlsplit(req.full_url)
        if u.netloc == "auth.example":
            q = urllib.parse.parse_qs(u.query)
            assert q == {"service": ["registry.example"], "scope": ["repository:library/busybox:pull"]}, q
            return Resp(200, body=b'{"token": "t0ken"}')  # stand-in values: a made-up bearer token
        if req.get_header("Authorization") != "Bearer t0ken":
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {
                "WWW-Authenticate": 'Bearer realm="https://auth.example/token",service="registry.example",scope="repository:library/busybox:pull"'},
                io.BytesIO(b""))
        m = re.match(r"^/v2/(.+)/manifests/([^/]+)$", u.path)
        e = self.manifests.get(m.groups()) if m else None
        if e is None:
            return Resp(404)
        return Resp(200, {"Content-Type": e[0]}, e[1])


def image_manifest(tag: str) -> bytes:
    return json.dumps({"schemaVersion": 2, "mediaType": IMAGE_MT, "config": {"digest": sha(tag.encode())},
                       "layers": []}, sort_keys=True).encode()


class SeedFlow(unittest.TestCase):
    """seed() against FakeRegistry: every platform, one platform, charts, and a second run."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-seed-"))
        self.reg = FakeRegistry()
        self.http = seed.Http(self.reg.base, opener=self.reg)
        # an image copied with every platform: the pin is its index
        self.k8s_index = json.dumps({"schemaVersion": 2, "mediaType": INDEX_MT, "manifests": [
            {"digest": sha(b"amd64"), "platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
        self.k8s = seed.Image(id="k", host="registry.k8s.io", repo="pause", tag="3.10.1", digest=sha(self.k8s_index))
        # a docker.io image copied for linux/amd64 only
        self.amd64 = image_manifest("busybox-amd64")
        self.hub_index = json.dumps({"schemaVersion": 2, "mediaType": INDEX_MT, "manifests": [
            {"digest": sha(b"attest"), "platform": {"os": "unknown", "architecture": "unknown"},
             "annotations": {"vnd.docker.reference.type": "attestation-manifest"}},
            {"digest": sha(b"v8"), "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
            {"digest": sha(self.amd64), "platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
        self.hub = seed.Image(id="h", host="docker.io", repo="library/busybox", tag="1.37.0", digest=sha(self.hub_index),
                              platform=seed.PLATFORM_NAME)
        self.upstream = FakeUpstream({("library/busybox", self.hub.digest): (INDEX_MT, self.hub_index)})
        self.tgz = chart_tgz("dc", "1.0.0")
        self.chart = seed.Chart(id="c", name="dc", version="1.0.0", sha256=hashlib.sha256(self.tgz).hexdigest(), repo="https://x.example")
        (self.tmp / "charts").mkdir()
        (self.tmp / "charts" / self.chart.file).write_bytes(self.tgz)
        self.copies: list = []
        self.bodies = {self.k8s.digest: (INDEX_MT, self.k8s_index), sha(self.amd64): (IMAGE_MT, self.amd64)}

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def copy(self, im, digest):
        self.copies.append((im.ref, digest))
        mt, body = self.bodies[digest or im.digest]
        self.reg.store(im.mirror_repo, im.tag, body, mt)

    def up(self, host):
        self.assertEqual(host, "docker.io")
        return seed.Upstream(host, opener=self.upstream)

    def test_first_run_then_second_run(self):
        res = seed.seed([self.hub, self.k8s], [self.chart], self.http, self.copy, self.tmp, upstream=self.up)
        self.assertEqual(self.copies, [(self.hub.ref, sha(self.amd64)), (self.k8s.ref, None)])
        self.assertEqual([(im.ref, d, a) for im, d, a in res.images],
                         [(self.hub.ref, sha(self.amd64), "copied"), (self.k8s.ref, self.k8s.digest, "copied")])
        self.assertEqual([a for _, _, a in res.charts], ["pushed"])
        # the token flow: one refused request, the token, the retry
        self.assertEqual([c[1] for c in self.upstream.calls], [None, None, "Bearer t0ken"])
        rec = json.loads(seed.seed_record(res, "v" * 64))
        self.assertEqual(rec["upstreams"], ["docker.io", "registry.k8s.io"])
        hub = next(e for e in rec["images"] if e["ref"] == self.hub.ref)
        self.assertEqual((hub["digest"], hub["served"], hub["platform"]), (self.hub.digest, sha(self.amd64), "linux/amd64"))
        k8s = next(e for e in rec["images"] if e["ref"] == self.k8s.ref)
        self.assertEqual((k8s["served"], k8s["platform"]), (self.k8s.digest, "all"))
        # the chart, as helm reads it
        man = json.loads(self.reg.repos["charts/dc"]["1.0.0"][1])
        self.assertEqual(man["layers"][0]["digest"], sha(self.tgz))
        self.assertEqual(json.loads(self.reg.blobs[man["config"]["digest"]])["name"], "dc")

        # the second run: nothing copied, nothing written, no upstream request
        self.copies.clear()
        writes = self.reg.writes

        def no_upstream(host):
            raise AssertionError("the second run must not read the upstream")

        second = seed.seed([self.hub, self.k8s], [self.chart], self.http, self.copy, self.tmp, upstream=no_upstream, record=rec)
        self.assertEqual(self.copies, [])
        self.assertEqual(self.reg.writes, writes)
        self.assertEqual([a for _, _, a in second.images] + [a for _, _, a in second.charts], ["present"] * 3)

    def test_wrong_copy_fails(self):
        def bad_copy(im, digest):
            self.reg.store(im.mirror_repo, im.tag, b'{"something": "else"}', IMAGE_MT)

        with self.assertRaises(seed.SeedError):
            seed.seed([self.k8s], [], self.http, bad_copy, self.tmp, upstream=self.up)

    def test_index_must_match_the_pin(self):
        self.upstream.manifests[("library/busybox", self.hub.digest)] = (INDEX_MT, self.hub_index + b" ")
        with self.assertRaises(seed.SeedError):
            seed.seed([self.hub], [], self.http, self.copy, self.tmp, upstream=self.up)
        self.assertEqual(self.copies, [])

    def test_platform_digest(self):
        idx = json.loads(self.hub_index)
        self.assertEqual(seed.platform_digest(idx, "t"), sha(self.amd64))
        only_variant = {"manifests": [{"digest": sha(b"v3"), "platform": {"os": "linux", "architecture": "amd64", "variant": "v3"}}]}
        self.assertEqual(seed.platform_digest(only_variant, "t"), sha(b"v3"))
        with self.assertRaises(seed.SeedError):
            seed.platform_digest({"manifests": [idx["manifests"][0], idx["manifests"][1]]}, "t")

    def test_single_manifest_pin_is_its_own_platform(self):
        img = dataclasses.replace(self.hub, digest=sha(self.amd64))
        up = FakeUpstream({("library/busybox", img.digest): (IMAGE_MT, self.amd64)})
        self.assertEqual(seed.resolve_platform(img, seed.Upstream("docker.io", opener=up)), img.digest)

    def test_skopeo_and_registry_args(self):
        a = seed.skopeo_args("quay.io/skopeo/stable:v1@sha256:" + "e" * 64, self.k8s, "127.0.0.1:5099", "sfab-x-copy")
        self.assertEqual(a[:6], ["run", "--rm", "--name", "sfab-x-copy", "--network", "host"])
        self.assertIn("--all", a)
        self.assertIn("--preserve-digests", a)
        self.assertEqual(a[-2:], [f"docker://registry.k8s.io/pause@{self.k8s.digest}", "docker://127.0.0.1:5099/registry.k8s.io/pause:3.10.1"])
        one = seed.skopeo_args("s", self.hub, "127.0.0.1:5099", "n", sha(self.amd64))
        self.assertNotIn("--all", one)
        self.assertEqual(one[-2], f"docker://docker.io/library/busybox@{sha(self.amd64)}")
        r = seed.registry_args("sfab-x", "sfab/registry:2", Path("/data"), 5099)
        self.assertIn("REGISTRY_HTTP_ADDR=127.0.0.1:5099", r)
        self.assertIn("/data:/var/lib/registry", r)
        self.assertEqual(r[r.index("--network") + 1], "host")
        self.assertNotIn("-p", r)
        self.assertEqual(r[-1], "/etc/sfab/registry-seed.yml")
        self.assertIn("COPY seed.yml /etc/sfab/registry-seed.yml", (REG_DIR / "Dockerfile").read_text())


class SeedData(unittest.TestCase):
    """check_data over a data directory in the registry's own filesystem layout."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-seed-data-"))
        self.store = self.tmp / "docker" / "registry" / "v2"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def blob(self, body: bytes) -> str:
        d = sha(body)
        p = self.store / "blobs" / "sha256" / d[7:9] / d[7:] / "data"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)
        return d

    def tag(self, repo: str, tag: str, digest: str) -> None:
        p = self.store / "repositories" / repo / "_manifests" / "tags" / tag / "current" / "link"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(digest)

    def test_check(self):
        idx = b'{"manifests": []}'
        k8s = seed.Image(id="k", host="registry.k8s.io", repo="pause", tag="3.10.1", digest=self.blob(idx))
        self.tag(k8s.mirror_repo, k8s.tag, k8s.digest)
        amd64 = image_manifest("x")
        hub = seed.Image(id="h", host="docker.io", repo="library/busybox", tag="1", digest="sha256:" + "1" * 64, platform=seed.PLATFORM_NAME)
        self.tag(hub.mirror_repo, hub.tag, self.blob(amd64))
        tgz = chart_tgz("dc", "1.0.0")
        chart = seed.Chart(id="c", name="dc", version="1.0.0", sha256=hashlib.sha256(tgz).hexdigest(), repo="https://x.example")
        layer = self.blob(tgz)
        man = json.dumps({"layers": [{"digest": layer}]}).encode()
        self.tag(chart.mirror_repo, chart.tag, self.blob(man))

        # without SEED.json the one-platform image cannot be judged
        probs = seed.check_data(self.tmp, [k8s, hub], [chart])
        self.assertEqual(len(probs), 1)
        self.assertIn("SEED.json", probs[0])

        rec = {"images": [{"ref": hub.ref, "digest": hub.digest, "served": sha(amd64)}]}
        (self.tmp / seed.SEED_FILE).write_text(json.dumps(rec))
        self.assertEqual(seed.check_data(self.tmp, [k8s, hub], [chart]), [])

        other = dataclasses.replace(k8s, digest="sha256:" + "2" * 64)
        self.assertTrue(any("holds" in p for p in seed.check_data(self.tmp, [other], [])))
        os.remove(self.store / "blobs" / "sha256" / layer[7:9] / layer[7:] / "data")
        self.assertTrue(any("chart blob missing" in p for p in seed.check_data(self.tmp, [], [chart])))
        missing = seed.Image(id="m", host="quay.io", repo="o/n", tag="1", digest="sha256:" + "3" * 64)
        self.assertTrue(any("missing" in p for p in seed.check_data(self.tmp, [missing], [])))

    def test_link_data(self):
        data = self.tmp / "store" / "registry-data"
        data.mkdir(parents=True)
        link = self.tmp / "checkout" / "data"
        seed.link_data(data, link)
        self.assertEqual(link.resolve(), data.resolve())
        seed.link_data(data, link)           # again: nothing to do
        other = self.tmp / "elsewhere"
        other.mkdir()
        link.unlink()
        link.symlink_to(other)
        seed.link_data(data, link)           # a wrong link is replaced
        self.assertEqual(link.resolve(), data.resolve())
        link.unlink()
        link.mkdir()
        (link / "file").write_text("x")
        with self.assertRaises(seed.SeedError):
            seed.link_data(data, link)       # a directory with data is never removed
        seed.link_data(data, None)


class SeedRun(unittest.TestCase):
    """run() with docker and the registry replaced: the order of its steps and its names."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-seed-run-"))
        self.reg = FakeRegistry(up=False)
        self.calls: list = []
        self.saved = {k: getattr(seed, k) for k in ("docker", "Http", "wait_ready")}
        idx = b'{"mediaType": "application/vnd.oci.image.index.v1+json", "manifests": []}'
        self.img = seed.Image(id="k", host="registry.k8s.io", repo="pause", tag="3.10.1", digest=sha(idx))
        bodies = {self.img.digest: idx}

        def fake_docker(args, check=True, capture=True):
            self.calls.append(list(args))
            rc = 0
            if args[:2] == ["container", "inspect"]:
                rc = 0 if args[2].endswith("-copy") else 1        # a leftover copier from an earlier run
            elif args[0] == "run" and "-d" in args:
                self.reg.up = True
            elif args[0] == "run" and "copy" in args:
                src = args[-2]
                self.reg.store(self.img.mirror_repo, self.img.tag, bodies[src.split("@", 1)[1]], INDEX_MT)
            elif args[:2] == ["rm", "-f"]:
                self.reg.up = False if args[2] == "sfab-test-seed" else self.reg.up
            return subprocess.CompletedProcess(args, rc, "", "")

        seed.docker = fake_docker
        seed.Http = lambda base, opener=None: self.saved["Http"](base, opener=self.reg)
        seed.wait_ready = lambda http, seconds=60: None

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(seed, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_run(self):
        data = self.tmp / "store" / "registry-data"
        link = self.tmp / "checkout" / "data"
        args = type("A", (), {"data": str(data), "port": 5099, "name": "sfab-test-seed", "image": "sfab/registry:2",
                              "skopeo": "quay.io/skopeo/stable:v1@sha256:" + "e" * 64, "vendor": str(self.tmp / "vendor"),
                              "link": str(link)})()
        self.assertEqual(seed.run(args, [self.img], [], "v" * 64), 0)
        verbs = [" ".join(c[:3]) for c in self.calls]
        self.assertEqual(verbs[:3], ["container inspect sfab-test-seed", "container inspect sfab-test-seed-copy",
                                     "rm -f sfab-test-seed-copy"])
        start = next(c for c in self.calls if c[0] == "run" and "-d" in c)
        self.assertEqual(start[start.index("--name") + 1], "sfab-test-seed")
        copy = next(c for c in self.calls if c[0] == "run" and "copy" in c)
        self.assertEqual(copy[copy.index("--name") + 1], "sfab-test-seed-copy")
        self.assertEqual(self.calls[-1], ["rm", "-f", "sfab-test-seed"])
        rec = json.loads((data / seed.SEED_FILE).read_text())
        self.assertEqual(rec["images"][0]["served"], self.img.digest)
        self.assertEqual(rec["versions_sha256"], "v" * 64)
        self.assertFalse((data / (seed.SEED_FILE + ".part")).exists())
        self.assertEqual(link.resolve(), data.resolve())
        # every container the seed starts carries the seed's name
        for c in self.calls:
            if c[0] == "run":
                self.assertTrue(c[c.index("--name") + 1].startswith("sfab-test-seed"), c)

    def test_refuses_a_busy_port(self):
        self.reg.up = True
        args = type("A", (), {"data": str(self.tmp / "d"), "port": 5099, "name": "sfab-test-seed", "image": "i",
                              "skopeo": "s", "vendor": str(self.tmp), "link": None})()
        with self.assertRaises(seed.SeedError):
            seed.run(args, [self.img], [], "v")
        self.assertEqual(self.calls, [])


# ------------------------------------------------------------------------------------------
# The registry image and the build wiring


class RegistryImage(unittest.TestCase):
    def test_dockerfile(self):
        text = (REG_DIR / "Dockerfile").read_text()
        self.assertIn("ARG REGISTRY_BASE\nFROM ${REGISTRY_BASE}", text)
        self.assertIn("COPY --from=client init.sh /usr/local/sbin/sfab-init.sh", text)
        self.assertIn('ENTRYPOINT ["/entrypoint.sh"]', text)
        self.assertIn('CMD ["/etc/docker/registry/config.yml"]', text)
        labels = re.findall(r"(\S+)=\"", text.split("LABEL", 1)[1].split("RUN", 1)[0])
        self.assertTrue(labels and all(k.startswith("org.opencontainers.image.") for k in labels), labels)
        ignored = (REG_DIR / ".dockerignore").read_text().splitlines()
        self.assertIn("data", ignored)

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the registry configuration")
    def test_configs(self):
        lab = yaml.safe_load((REG_DIR / "config.yml").read_text())
        self.assertTrue(lab["storage"]["maintenance"]["readonly"]["enabled"])
        self.assertFalse(lab["storage"]["delete"]["enabled"])
        self.assertEqual(lab["storage"]["filesystem"]["rootdirectory"], "/var/lib/registry")
        self.assertEqual(lab["http"]["addr"], ":5000")
        # the lab's registry serves HTTPS with the leaf the topology binds at /sfab/tls; the seeding
        # registry, on the lab host's loopback, plain HTTP
        self.assertEqual(lab["http"]["tls"], {"certificate": "/sfab/tls/chain.crt", "key": "/sfab/tls/tls.key", "minimumtls": "tls1.2"})
        self.assertNotIn("tls", yaml.safe_load((REG_DIR / "seed.yml").read_text())["http"])
        sd = yaml.safe_load((REG_DIR / "seed.yml").read_text())
        self.assertNotIn("readonly", (sd["storage"].get("maintenance") or {}))
        self.assertEqual(sd["http"]["addr"], "127.0.0.1:5000")
        self.assertEqual(sd["storage"]["filesystem"]["rootdirectory"], "/var/lib/registry")


class BuildWiring(unittest.TestCase):
    """images/frr/image.mk and images/registry/image.mk, read by make -n (nothing runs)."""

    def _make(self, *targets, dry: bool = True, **var):
        mk = shutil.which("make")
        if not mk:
            self.skipTest("make is not installed")
        cmd = [mk, "-s", *(["-n"] if dry else []), "-C", str(IMAGES), "-f", "Makefile", "-f", "frr/image.mk", "-f", "registry/image.mk",
               *targets, *[f"{k}={v}" for k, v in var.items()]]
        env = dict(os.environ, PATH=standins.path_with(standins.make_bin(Path(tempfile.mkdtemp(prefix="sfab-mk-")) / "bin", {})))
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def test_frr(self):
        out = self._make("frr")
        self.assertIn("build-if-stale.sh sfab/frr:10.5.4-3", out)
        self.assertRegex(out, r"--build-arg FRR_BASE=quay\.io/frrouting/frr:10\.5\.4@sha256:[0-9a-f]{64}")
        self.assertIn("--watch " + str(FRR_DIR / "frr-restore.sh"), out)

    def test_registry_seed(self):
        out = self._make("registry-seed", SEED_NAME="sfab-test-seed", SFAB_IMAGE_STORE="/nonexistent/store")
        self.assertIn("build-if-stale.sh sfab/registry:3", out)
        self.assertRegex(out, r"--build-arg REGISTRY_BASE=registry:2@sha256:[0-9a-f]{64}")
        self.assertIn("--build-context client=" + str(IMAGES / "client"), out)
        self.assertIn("seed.py run --data /nonexistent/store/registry-data --image sfab/registry:3", out)
        self.assertRegex(out, r"--skopeo quay\.io/skopeo/stable:\S+@sha256:[0-9a-f]{64}")
        self.assertIn("--name sfab-test-seed", out)
        self.assertIn("--link " + str(REG_DIR / "data"), out)

    def test_registry_check_and_link(self):
        out = self._make("registry-check", SFAB_IMAGE_STORE="/nonexistent/store")
        self.assertIn("seed.py check --data /nonexistent/store/registry-data", out)
        out = self._make("registry-link", SFAB_IMAGE_STORE="/nonexistent/store")
        self.assertIn("ln -sfn /nonexistent/store/registry-data " + str(REG_DIR / "data"), out)
        # without a store the data lives in the checkout: the target only says so (it runs here)
        self.assertIn("nothing to link", self._make("registry-link", dry=False, SFAB_IMAGE_STORE="", REGISTRY_DATA=str(REG_DIR / "data")))


class Clean(unittest.TestCase):
    FILES = [FRR_DIR / f for f in ("Dockerfile", "frr-init.sh", "frr-restore.sh", "image.mk", "README.md", ".dockerignore")] + \
            [REG_DIR / f for f in ("Dockerfile", "config.yml", "seed.yml", "seed.py", "image.mk", "README.md", ".dockerignore")] + \
            [ROOT / "common" / "sfab" / "render" / "frr.py", Path(__file__)]

    def test_plain_prose(self):
        for p in self.FILES:
            text = p.read_text(encoding="utf-8")
            for d in DASHES:
                self.assertNotIn(d, text, p)

    def test_namecheck(self):
        # masked, so a failure prints where, never what; 3 is skipped (no scrub list), not a failure
        r = subprocess.run([sys.executable, str(ROOT / "common" / "tools" / "namecheck.py"), "--mask", *map(str, self.FILES)],
                           capture_output=True, text=True, timeout=120)
        self.assertIn(r.returncode, (0, 3), r.stdout + r.stderr)

    def test_no_names_in_the_images(self):
        # the images carry no lab, organization or label domain; those arrive through init.env
        for p in self.FILES[:-2]:
            text = p.read_text(encoding="utf-8").lower()
            for word in ("tarnwick", "corvane"):
                self.assertNotIn(word, text, p)


if __name__ == "__main__":
    unittest.main()
