"""Host tests: render/host.py (node.env for VM guests, init.env for container hosts), the golden
node.env files of dev/m1's GPU nodes, and dry runs of the scripts that consume them
(images/vm-node/vm-init.sh, images/vm-node/node-files/netsetup.sh, images/client/init.sh), and the
client's resolv.conf rewrite run for real on a stand-in of Docker's file.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_hosts -v

After a deliberate change, refresh the golden files with SFAB_UPDATE_GOLDEN=1 and review the
diff. The script tests need bash 4 or later on PATH and are skipped without it.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from sfab import addr
from sfab.tests import standins

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = Path(__file__).resolve().parent / "golden" / "m1-hosts"
IMAGES = ROOT / "images"
VM_INIT = IMAGES / "vm-node" / "vm-init.sh"
NETSETUP = IMAGES / "vm-node" / "node-files" / "netsetup.sh"
CLIENT_INIT = IMAGES / "client" / "init.sh"

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
DASHES = ("\u2014", "\u2013")


def _ctx(spec, labdir: Path):
    from sfab.render import Context

    return Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-hosts", labdir=labdir, root=ROOT, spec=spec)


class Labs:
    """The spec loaded once, and the host renders of three labs: dev/m1, a full A/one lab and a
    full A/many lab at step 9."""

    _cache: dict = {}

    @classmethod
    def get(cls) -> dict:
        if not cls._cache:
            from sfab.render import host
            from sfab.spec import load, select

            spec = load(ROOT)
            labs = {}
            for key, sel in (("m1", ROOT / "dev" / "m1"),
                             ("one", {"lab": "sfab-ch03", "profile": "a", "state": "one"}),
                             ("many", {"lab": "sfab-ch09", "profile": "a", "state": "many"})):
                model = select(spec, sel)
                ctx = _ctx(spec, ROOT / "dev" / "m1")
                labs[key] = {"model": model, "ctx": ctx, "out": host.render(model, ctx)}
            cls._cache.update(spec=spec, labs=labs)
        return cls._cache


def parse_env(text: str) -> dict:
    """KEY=value lines as the shell reads them (header and blank lines skipped)."""
    env = {}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        k, _, v = line.partition("=")
        words = shlex.split(v) if v else [""]
        env[k] = words[0] if words else ""
    return env


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestGolden(unittest.TestCase):
    def test_m1_gpu_node_env(self):
        out = Labs.get()["labs"]["m1"]["out"]
        want = {p: d for p, d in out.items() if p.endswith("/node.env")}
        self.assertEqual(sorted(want), ["bootstrap/k8s-gpu1/node.env", "bootstrap/k8s-gpu2/node.env"])
        self.assertEqual(sorted(out), sorted(want), "dev/m1 has no container host, so host.py renders node.env only")
        if os.environ.get("SFAB_UPDATE_GOLDEN") == "1":
            if GOLDEN.exists():
                shutil.rmtree(GOLDEN)
            for p, data in want.items():
                f = GOLDEN / p
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(data, encoding="utf-8")
        have = sorted(p.relative_to(GOLDEN).as_posix() for p in GOLDEN.rglob("*") if p.is_file())
        self.assertEqual(have, sorted(want), "the set of golden files differs from the render")
        for p, data in sorted(want.items()):
            self.assertEqual(data, (GOLDEN / p).read_text(encoding="utf-8"),
                             f"{p} differs from tests/golden/m1-hosts/{p} (SFAB_UPDATE_GOLDEN=1 refreshes it)")

    def test_render_is_stable(self):
        from sfab.render import host

        lab = Labs.get()["labs"]["one"]
        self.assertEqual(host.render(lab["model"], lab["ctx"]), lab["out"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestEnvFormat(unittest.TestCase):
    def files(self):
        for key, lab in Labs.get()["labs"].items():
            for p, text in sorted(lab["out"].items()):
                if p.endswith(".env"):
                    yield key, lab, p, text

    def test_shape(self):
        for key, lab, p, text in self.files():
            with self.subTest(lab=key, path=p):
                self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"))
                lines = text.splitlines()
                self.assertTrue(lines[0].startswith(f"# {lab['model'].lab} "), lines[0])
                self.assertIn("rendered from spec/profile-a.yaml", lines[0])
                self.assertFalse(any(x.startswith("#") for x in lines[1:]), "one header comment line only")
                keys = [x.split("=", 1)[0] for x in lines[1:]]
                self.assertEqual(keys, sorted(keys))
                self.assertEqual(len(keys), len(set(keys)))
                self.assertEqual(lines, sorted(lines, key=lambda s: s.encode()), "sort leaves the file unchanged")
                for x in lines[1:]:
                    self.assertRegex(x, r"^[A-Z][A-Z0-9_]*=\S")
                for d in DASHES:
                    self.assertNotIn(d, text)

    def test_every_host_searches_the_lab_domain(self):
        # with or without a lab resolver: a container that kept Docker's search line would search
        # the lab host's own domains. The platform's hosts search the platform's zone; the
        # enterprise's own hosts (the corporate resolver's local names) the corporate domain.
        for key, lab, p, text in self.files():
            with self.subTest(lab=key, path=p):
                m = lab["model"]
                node = p.split("/")[1]
                corporate = any(node in r.local for r in m.dns.resolvers)
                want = m.org.domain if corporate else m.org.zone
                self.assertEqual(parse_env(text).get("SEARCH"), want)
                self.assertEqual(parse_env(text).get("DOMAIN"), want)

    def test_contents_stay_in_the_build(self):
        for key, lab, p, text in self.files():
            with self.subTest(lab=key, path=p):
                body = "\n".join(x for x in text.splitlines() if not x.startswith("ISCSI_IQN="))
                for dom in re.findall(r"[a-z0-9-]+(?:\.[a-z0-9-]+)*\.example\b", body):
                    self.assertTrue(dom == "tarnwick.example" or dom.endswith(".tarnwick.example"), dom)
                for mac in re.findall(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", text):
                    self.assertTrue(mac.startswith("02:5a:"), mac)
                for a in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d+)?\b", text):
                    self.assertFalse(addr.in_slirp(a), f"{a} is in 10.0.0.0/24")
                self.assertNotRegex(text, r"(?i)password|passwd|secret|BEGIN [A-Z ]*KEY")

    @unittest.skipUnless(BASH, "bash 4 or later is needed")
    def test_bash_reads_what_python_reads(self):
        for key, lab, p, text in self.files():
            with self.subTest(lab=key, path=p):
                env = parse_env(text)
                with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
                    f.write(text)
                try:
                    script = 'set -euo pipefail; set -a; . "$1"; set +a; shift; for k; do printf "%s=%s\\0" "$k" "${!k}"; done'
                    r = subprocess.run([BASH, "-c", script, "x", f.name, *env], capture_output=True, check=True)
                finally:
                    os.unlink(f.name)
                got = dict(x.split("=", 1) for x in r.stdout.decode().split("\0") if x)
                self.assertEqual(got, env)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestGuestServices(unittest.TestCase):
    """The bastion's time and the registry mirrors reach the Kubernetes guests (M2)."""

    def test_containerd_mirrors_on_every_kubernetes_guest(self):
        lab = Labs.get()["labs"]["one"]
        m, out = lab["model"], lab["out"]
        ups = (m.spec.get("registry") or {}).get("upstreams") or []
        self.assertEqual(ups, ["docker.io", "ghcr.io", "quay.io", "registry.k8s.io"])
        tomls = {p: t for p, t in out.items() if p.endswith("/hosts.toml")}
        guests = sorted(h.name for h in m.hosts.values() if h.kind == "vm-node" and h.k8s)
        self.assertEqual(guests, ["k8s-cp1", "k8s-cp2", "k8s-cp3", "k8s-gpu1", "k8s-gpu2", "k8s-ingress1", "k8s-ingress2"])
        # A/one runs the serving recipe, so each guest also gets the mirror's own file, for the images
        # this repository builds (served as <mirror>/<repository>:<tag>)
        self.assertTrue(m.features.get("serving"))
        hosts = ups + [m.registry.mirror]
        self.assertEqual(sorted(tomls), sorted(f"bootstrap/{g}/containerd/{u}/hosts.toml" for g in guests for u in hosts))
        self.assertEqual(tomls["bootstrap/k8s-gpu1/containerd/192.0.2.6:5000/hosts.toml"],
                         'server = "https://192.0.2.6:5000"\n\n'
                         '[host."https://192.0.2.6:5000"]\n'
                         '  capabilities = ["pull", "resolve"]\n'
                         '  ca = "/shared/ca/root.crt"\n')
        self.assertEqual(tomls["bootstrap/k8s-cp1/containerd/registry.k8s.io/hosts.toml"],
                         'server = "https://registry.k8s.io"\n\n'
                         '[host."https://192.0.2.6:5000/v2/registry.k8s.io"]\n'
                         '  capabilities = ["pull", "resolve"]\n'
                         '  override_path = true\n'
                         '  ca = "/shared/ca/root.crt"\n')
        self.assertTrue(tomls["bootstrap/k8s-gpu2/containerd/docker.io/hosts.toml"].startswith('server = "https://registry-1.docker.io"\n'))

    def test_no_mirrors_or_time_without_the_cluster(self):
        out = Labs.get()["labs"]["m1"]["out"]
        self.assertFalse([p for p in out if "/containerd/" in p])
        self.assertNotIn("NTP_SERVERS", parse_env(out["bootstrap/k8s-gpu1/node.env"]))

    def test_guests_take_the_resolvers_time(self):
        # two time sources per client, the two resolvers' chrony: never the bastion
        out = Labs.get()["labs"]["one"]["out"]
        for g in ("k8s-cp1", "k8s-gpu2"):
            self.assertEqual(parse_env(out[f"bootstrap/{g}/node.env"])["NTP_SERVERS"], "10.20.13.21 10.20.14.21")

    def test_registry_over_tls(self):
        # the registry serves HTTPS with a leaf of the lab's internet intermediate: every mirror is
        # named https:// with the lab root, which every guest mounts at /shared/ca/root.crt
        out = Labs.get()["labs"]["one"]["out"]
        for p, t in out.items():
            if p.endswith("/hosts.toml"):
                with self.subTest(path=p):
                    self.assertIn('[host."https://192.0.2.6:5000', t)
                    self.assertTrue(t.endswith('  ca = "/shared/ca/root.crt"\n'), t)
                    self.assertNotIn("http://", t)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestNodeEnv(unittest.TestCase):
    def env(self, lab: str, node: str) -> dict:
        return parse_env(Labs.get()["labs"][lab]["out"][f"bootstrap/{node}/node.env"])

    def test_bond_and_tables(self):
        e = self.env("m1", "k8s-gpu1")
        self.assertEqual((e["BOND_NAME"], e["BOND_MEMBERS"], e["BOND_MODE"], e["BOND_LACP_RATE"], e["BOND_HASH"],
                          e["BOND_MIIMON"], e["BOND_MTU"]), ("bond0", "eth1 eth2", "802.3ad", "fast", "layer3+4", "100", "9000"))
        self.assertEqual((e["BOND_ADDR"], e["BOND_GW"], e["BOND_MAC"]), ("10.20.1.21/24", "10.20.1.1", "02:5a:6f:00:00:01"))
        self.assertEqual((e["MGMT_IF"], e["MGMT_ADDR"], e["MGMT_GW"], e["MGMT_TABLE"]),
                         ("eth0", "172.21.40.111/24", "172.21.40.1", "150"))
        self.assertEqual((e["OOB_IF"], e["OOB_ADDR"], e["OOB_GW"], e["OOB_TABLE"]),
                         ("eth3", "10.20.9.21/24", "10.20.9.254", "100"))

    def test_guest_matches_the_model_and_the_topology(self):
        lab = Labs.get()["labs"]["m1"]
        for name in ("k8s-gpu1", "k8s-gpu2"):
            h = lab["model"].nodes[name]
            e = self.env("m1", name)
            self.assertEqual(e["VM_NICS"], " ".join(h.eths))
            self.assertEqual(int(e["VM_MEMORY_MB"]), int(round(h.budget.mem_gib * 1024)))
            self.assertEqual(int(e["VM_SMP"]), int(h.budget.vcpus))
            self.assertEqual(int(e["VM_DISK_GIB"]), h.disk_gib)
            self.assertEqual(e["VM_TX_OFF"], "1")
            self.assertEqual(e["MGMT_MAC"], h.mgmt_mac)
            for n in h.nics:
                k = f"NIC{n.index:02d}"
                self.assertEqual(e[f"{k}_MAC"], n.mac)
                self.assertEqual(e[f"{k}_NAME"], n.ifname or n.eth)
                self.assertEqual(e[f"{k}_ROLE"], n.role)
            # The topology's env for the same container carries the same values.
            try:
                from sfab.render import clab
            except ImportError:
                continue
            topo = yaml.safe_load(clab.render(lab["model"], lab["ctx"])["topo.clab.yml"])
            tenv = topo["topology"]["nodes"][name].get("env") or {}
            for k in ("VM_MEMORY_MB", "VM_SMP", "VM_DISK_GIB", "VM_NICS", "VM_TX_OFF"):
                if k in tenv:
                    self.assertEqual(str(tenv[k]), e[k], f"{name} {k}: topology and node.env disagree")

    def test_relay(self):
        e = self.env("m1", "k8s-gpu1")
        self.assertEqual(e["RAIL_MODE"], "relay")
        self.assertEqual(e["RAILS"], "1 2 3 4 5 6 7 8")
        self.assertEqual((e["RELAY_BRIDGE"], e["RELAY_RP_FILTER"], e["RELAY_IP_FORWARD"], e["RELAY_MTU"]),
                         ("relay0", "2", "1", "9000"))
        self.assertEqual(e["BOND_MAC"], e["NIC01_MAC"], "the bond takes its first member's MAC")
        macs = [v for k, v in e.items() if k.endswith("_MAC") and k != "BOND_MAC"]
        self.assertEqual(len(set(macs)), len(macs), "every other MAC is distinct")
        nss = set()
        for r in range(1, 9):
            self.assertNotIn(f"RAIL{r}_TABLE", e, "relay rails have no table")
            self.assertEqual(e[f"RAIL{r}_ADDR"], f"10.21.{r}.11/24")
            self.assertEqual(e[f"RELAY{r}_ADDR"], f"10.21.250.{r}/24")
            nss.add(e[f"RELAY{r}_NS"])
            routes = e[f"RELAY{r}_ROUTES"].split()
            self.assertEqual(len(routes), 7)
            seen = set()
            for rt in routes:
                dest, via, dev, src = rt.split(",")
                j = int(dest.split(".")[2])
                self.assertNotEqual(j, r)
                self.assertNotEqual(dest, "0.0.0.0/0")
                self.assertEqual((dest, via, dev, src), (f"10.21.{j}.0/24", f"10.21.250.{j}", "relay", f"10.21.{r}.11"))
                seen.add(j)
            self.assertEqual(seen, set(range(1, 9)) - {r})
        self.assertEqual(len(nss), 8)
        self.assertEqual(self.env("m1", "k8s-gpu2")["RAIL3_ADDR"], "10.21.3.12/24")

    def test_identity_is_per_node_and_lab(self):
        a, b = self.env("m1", "k8s-gpu1"), self.env("m1", "k8s-gpu2")
        c = self.env("one", "k8s-gpu1")
        self.assertEqual(len({a["VM_UUID"], b["VM_UUID"], c["VM_UUID"]}), 3)
        self.assertEqual(a["ISCSI_IQN"], "iqn.2026-10.example.tarnwick:k8s-gpu1")
        self.assertEqual(a["FQDN"], "k8s-gpu1.ai.tarnwick.example")

    def test_m1_has_no_cluster_and_no_resolver(self):
        e = self.env("m1", "k8s-gpu1")
        self.assertFalse([k for k in e if k.startswith("K8S_")])
        self.assertNotIn("DNS_SERVERS", e, "the resolvers are not in sfab-m1")
        self.assertEqual(e["SEARCH"], "ai.tarnwick.example", "every platform host searches the platform's zone")

    def test_control_node_with_kubernetes(self):
        e = self.env("one", "k8s-cp1")
        self.assertNotIn("RAILS", e)
        self.assertEqual((e["K8S_ROLE"], e["K8S_VERSION"], e["K8S_API_VIP"], e["K8S_API_FQDN"]),
                         ("init", "v1.35.8", "10.20.1.10", "k8s.ai.tarnwick.example"))
        self.assertEqual(e["HOSTS"], "10.20.1.10,k8s.ai.tarnwick.example")
        self.assertEqual(e["DNS_SERVERS"], "10.20.13.21 10.20.14.21", "both resolvers, never the bastion")
        self.assertEqual(self.env("one", "k8s-gpu2")["K8S_ROLE"], "join-worker")

    def test_routed_rails(self):
        from sfab.render import host

        lab = Labs.get()["labs"]["m1"]
        h = dataclasses.replace(lab["model"].nodes["k8s-gpu1"], relay=None)
        e = parse_env(host.node_env(lab["model"], h, lab["ctx"]))
        self.assertEqual(e["RAIL_MODE"], "routed")
        for r in range(1, 9):
            self.assertEqual(e[f"RAIL{r}_TABLE"], str(300 + r))
            self.assertEqual(e[f"RAIL{r}_ADDR"], f"10.21.{r}.11/24")
            self.assertNotIn(f"RAIL{r}_GW", e, "build A's rails have no gateway")
        self.assertFalse([k for k in e if k.startswith("RELAY")])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestInitEnv(unittest.TestCase):
    def out(self, lab: str) -> dict:
        return Labs.get()["labs"][lab]["out"]

    def env(self, lab: str, node: str) -> dict:
        return parse_env(self.out(lab)[f"bootstrap/{node}/init.env"])

    def test_which_nodes(self):
        out = self.out("one")
        inits = sorted(p.split("/")[1] for p in out if p.endswith("/init.env"))
        envs = sorted(p.split("/")[1] for p in out if p.endswith("/node.env"))
        self.assertEqual(inits, ["bastion", "dns-auth1", "dns-auth2", "dns-res1", "dns-res2", "ent-client", "ent-dns", "inet-ntp",
                                 "inet-registry", "ops-client", "ops-dns", "ops-gw", "web-client"])
        self.assertEqual(envs, ["k8s-cp1", "k8s-cp2", "k8s-cp3", "k8s-gpu1", "k8s-gpu2", "k8s-ingress1", "k8s-ingress2"])

    def test_pending_node_is_skipped(self):
        from sfab.render import host

        lab = Labs.get()["labs"]["many"]
        self.assertIn("bootstrap/inet-client/init.env", lab["out"])
        m = lab["model"]
        h = dataclasses.replace(m.nodes["ent-dns"], pending="its layout is not settled")
        m2 = dataclasses.replace(m, nodes={**m.nodes, "ent-dns": h})
        ctx = _ctx(Labs.get()["spec"], ROOT / "ch01")
        out = host.render(m2, ctx)
        self.assertNotIn("bootstrap/ent-dns/init.env", out)
        self.assertTrue(any("ent-dns" in w for w in ctx.warnings))
        self.assertNotIn("DNS_SERVERS", parse_env(out["bootstrap/ent-client/init.env"]), "a pending resolver is no resolver")
        self.assertEqual(parse_env(out["bootstrap/ent-client/init.env"])["SEARCH"], "tarnwick.example")

    def test_client(self):
        e = self.env("one", "ent-client")
        # the staff client on its own firewall port, a /30 of the enterprise LAN; its resolver is the
        # corporate one, and it searches the corporate domain
        self.assertEqual((e["IFACES"], e["ETH1_ADDR"], e["GATEWAY"], e["GATEWAY_DEV"], e["TX_OFF"]),
                         ("eth1", "10.24.10.10/30", "10.24.10.9", "eth1", "eth1"))
        self.assertEqual((e["MGMT_ADDR"], e["MGMT_TABLE"], e["DNS_SERVERS"], e["SEARCH"]),
                         ("172.21.40.82/24", "150", "10.24.10.53", "tarnwick.example"))

    def test_bastion(self):
        # a jump host only: one leg, in VLAN 300; no BMC leg, no DNS role, the two resolvers as its
        # resolvers, the lab root to trust and the operators' kubeconfig directory
        e = self.env("one", "bastion")
        self.assertEqual((e["BOND_MEMBERS"], e["BOND_ADDR"], e["GATEWAY"], e["GATEWAY_DEV"]),
                         ("eth1 eth2", "10.20.3.10/24", "10.20.3.1", "bond0"))
        self.assertNotIn("BOND_MAC", e, "the bastion is a container: its bond keeps the kernel's MAC")
        for k in ("OOB_IF", "OOB_ADDR", "DNS_ROLE", "IFACES", "TLS_DIR", "TSIG_DIR"):
            self.assertNotIn(k, e)
        self.assertEqual(e["TX_OFF"], "eth1 eth2")
        self.assertEqual((e["DNS_SERVERS"], e["CA_ROOT"], e["OPERATOR_DIR"]),
                         ("10.20.13.21 10.20.14.21", "/shared/ca/root.crt", "/sfab/operators"))

    def test_resolver_and_registry(self):
        self.assertEqual(self.env("one", "ops-dns")["DNS_ROLE"], "bind-auth")
        r = self.env("one", "inet-registry")
        self.assertEqual((r["ETH1_ADDR"], r["GATEWAY"], r["TLS_DIR"]), ("192.0.2.6/30", "192.0.2.5", "/sfab/tls"))

    def test_services_hosts(self):
        # the authoritative pair and the resolvers: containers bonded to the pair in VLANs 130 and
        # 131 at IP MTU 1500; the pair holds the TSIG keys, the resolvers ask themselves
        for node, role, addr_, vlan in (("dns-auth1", "bind-auth", "10.20.13.11/24", "130"), ("dns-res1", "bind-recursive", "10.20.13.21/24", "130"),
                                        ("dns-auth2", "bind-auth", "10.20.14.11/24", "131"), ("dns-res2", "bind-recursive", "10.20.14.21/24", "131")):
            with self.subTest(node=node):
                e = self.env("one", node)
                self.assertEqual((e["DNS_ROLE"], e["BOND_ADDR"], e["BOND_VLAN"], e["BOND_MTU"], e["BOND_MEMBERS"], e["GATEWAY_DEV"]),
                                 (role, addr_, vlan, "1500", "eth1 eth2", "bond0"))
                self.assertEqual(e["DNS_SERVERS"], "10.20.13.21 10.20.14.21")
                self.assertEqual(e.get("TSIG_DIR"), "/sfab/tsig" if role == "bind-auth" else None)
        e = self.env("one", "ent-dns")
        self.assertEqual((e["DNS_ROLE"], e["ETH1_ADDR"], e["GATEWAY"], e["SEARCH"]), ("dnsmasq", "10.24.10.53/30", "10.24.10.54", "tarnwick.example"))
        e = self.env("one", "inet-ntp")
        self.assertNotIn("DNS_ROLE", e, "the time reference serves no DNS")
        self.assertEqual((e["ETH1_ADDR"], e["GATEWAY"], e["TLS_DIR"]), ("192.0.2.14/30", "192.0.2.13", "/sfab/tls"))

    def test_search_without_a_lab_resolver(self):
        # The operator segment's resolver, ops-dns, is in the full A/one lab but not in chapter 4's
        # lab (nor in sfab-m2 or chapter 3's): ops-client and web-client get no DNS_SERVERS there,
        # and still search the lab's domain. The registry, an upstream stand-in, names no resolver.
        from sfab.render import host
        from sfab.spec import select

        model = select(Labs.get()["spec"], ROOT / "ch04")
        out = host.render(model, _ctx(Labs.get()["spec"], ROOT / "ch04"))
        self.assertNotIn("ops-dns", model.nodes)
        self.assertNotIn("DNS_SERVERS", self.env("one", "inet-registry"))
        for node in ("ops-client", "web-client"):
            with self.subTest(node=node):
                full = self.env("one", node)
                self.assertEqual(full["DNS_SERVERS"], "192.0.2.10")
                e = parse_env(out[f"bootstrap/{node}/init.env"])
                self.assertNotIn("DNS_SERVERS", e)
                self.assertNotIn("RESOLV_OPTIONS", e)
                self.assertEqual((e["SEARCH"], full["SEARCH"]), ("ai.tarnwick.example", "ai.tarnwick.example"))


class TestQuote(unittest.TestCase):
    def test_words(self):
        from sfab.render.host import quote

        self.assertEqual(quote("layer3+4"), "layer3+4")
        self.assertEqual(quote("eth1 eth2"), "'eth1 eth2'")
        self.assertEqual(quote(""), "''")
        self.assertEqual(quote(True), "1")
        self.assertEqual(quote("a'b"), "'a'\\''b'")
        self.assertEqual(quote("~x"), "'~x'")
        for s in ("a b", "it's", "$HOME", "x;y", "`id`", "a\\b"):
            self.assertEqual(shlex.split(quote(s)), [s])

    def test_rejects(self):
        from sfab.render.host import HostRenderError, env_file

        with self.assertRaises(HostRenderError):
            env_file("# h", {"lower": "x"})
        with self.assertRaises(HostRenderError):
            env_file("# h", {"A": "x\ny"})
        with self.assertRaises(HostRenderError):
            env_file("no comment", {"A": "x"})


# ------------------------------------------------------------------------------------------
# The consumers, in dry runs.


def _run(script: Path, env: dict, *args: str) -> subprocess.CompletedProcess:
    full = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", **env}
    return subprocess.run([BASH, str(script), *args], env=full, capture_output=True, text=True, timeout=60)


@unittest.skipUnless(HAVE_YAML and BASH, "PyYAML and bash 4 or later are needed")
class TestNetsetupDryRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        env = Path(cls.tmp.name) / "node.env"
        env.write_text(Labs.get()["labs"]["m1"]["out"]["bootstrap/k8s-gpu1/node.env"])
        r = _run(NETSETUP, {"SFAB_DRY_RUN": "1", "SFAB_NODE_ENV": str(env)})
        cls.rc, cls.err = r.returncode, r.stderr
        cls.cmds = [x[2:] for x in r.stdout.splitlines() if x.startswith("+ ")]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def has(self, line: str):
        self.assertIn(line, self.cmds)

    def test_runs(self):
        self.assertEqual(self.rc, 0, self.err)

    def test_bond(self):
        self.has("ip link add bond0 type bond mode 802.3ad lacp_rate fast miimon 100 xmit_hash_policy layer3+4")
        self.has("ip link set bond0 address 02:5a:6f:00:00:01")
        for m in ("eth1", "eth2"):
            self.has(f"ethtool -s {m} speed 10000 duplex full autoneg off")
            self.has(f"ip link set {m} master bond0")
        self.has("ip addr replace 10.20.1.21/24 dev bond0")
        self.has("ip route replace default via 10.20.1.1 dev bond0")

    def test_management_and_oob_tables(self):
        self.has("ip route replace default via 172.21.40.1 dev eth0 table 150")
        self.has("ip rule add from 172.21.40.111 lookup 150")
        # the BMC stand-in: eth3 in namespace bmc with the BMC address, nothing of it in the host OS
        self.has("ip netns add bmc")
        self.has("ip -n bmc addr replace 10.20.9.21/24 dev eth3")
        self.has("ip -n bmc route replace default via 10.20.9.254 dev eth3")
        self.has("ip netns exec bmc sshd on 10.20.9.21:22")
        self.has("ip netns exec bmc listener on 10.20.9.21:443")
        self.assertFalse([c for c in self.cmds if c.startswith("ip addr replace 10.20.9.")], "no BMC address in the host OS")
        self.assertFalse([c for c in self.cmds if "table 100" in c], "no out-of-band table in the host OS")

    def test_storage_vlan_unit(self):
        self.has("ip link add link bond0 name bond0.120 type vlan id 120")
        self.has("ip link set bond0.120 mtu 9000")
        self.has("ip addr replace 10.20.12.21/24 dev bond0.120")
        self.has("ethtool -K bond0.120 tx off")
        self.assertFalse([c for c in self.cmds if c.startswith("ip rule add from 10.20.12.")], "the storage VLAN keeps the main table")
        self.assertFalse([c for c in self.cmds if c.startswith("ip route") and "default" in c and "eth0" in c
                          and "table 150" not in c])

    def test_tx_off_everywhere(self):
        for d in ("eth1", "eth2", "bond0", *(f"rail{r}" for r in range(1, 9)), *(f"rl{r}" for r in range(1, 9))):
            self.has(f"ethtool -K {d} tx off")
        self.has("ip netns exec bmc ethtool -K eth3 tx off")
        for r in range(1, 9):
            self.has(f"ip netns exec gpu{r} ethtool -K rail{r} tx off")
            self.has(f"ip netns exec gpu{r} ethtool -K relay tx off")

    def test_relay_namespaces(self):
        self.has("ip link add relay0 type bridge")
        self.assertEqual(sorted(c for c in self.cmds if c.startswith("ip netns add ")),
                         sorted([f"ip netns add gpu{r}" for r in range(1, 9)] + ["ip netns add bmc"]), "the relay's eight and the BMC's")
        for r in range(1, 9):
            ns, eth = f"gpu{r}", r + 3
            self.has(f"ip link add link rail{r} name sfmv{r} address 02:5a:6f:01:00:{eth:02x} type macvlan mode bridge")
            self.has(f"ip -n {ns} link set sfmv{r} name rail{r}")
            self.has(f"ip link add rl{r} type veth peer name relay netns {ns}")
            self.has(f"ip link set rl{r} master relay0 mtu 9000 up")
            self.has(f"ip -n {ns} addr replace 10.21.{r}.11/24 dev rail{r}")
            self.has(f"ip -n {ns} addr replace 10.21.250.{r}/24 dev relay")
            self.has(f"ip netns exec {ns} sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=2 "
                     f"net.ipv4.conf.default.rp_filter=2 net.ipv4.conf.rail{r}.rp_filter=2 net.ipv4.conf.relay.rp_filter=2")
            routes = [c for c in self.cmds if c.startswith(f"ip -n {ns} route ")]
            self.assertEqual(len(routes), 7)
            for c in routes:
                self.assertRegex(c, rf"^ip -n {ns} route replace 10\.21\.\d\.0/24 via 10\.21\.250\.\d dev relay src 10\.21\.{r}\.11$")
                self.assertNotIn("default", c)
        # The rail NICs themselves hold no address.
        self.assertFalse([c for c in self.cmds if re.match(r"ip addr replace \S+ dev rail\d$", c)])

    def test_order(self):
        i = self.cmds.index
        self.assertLess(i("ip netns add gpu3"), i("ip link add link rail3 name sfmv3 address 02:5a:6f:01:00:06 type macvlan mode bridge"))
        self.assertLess(i("ip netns exec gpu3 sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1"),
                        i("ip link set sfmv3 netns gpu3"))
        self.assertLess(i("ip link set eth1 down"), i("ip link set eth1 master bond0"))


@unittest.skipUnless(HAVE_YAML and BASH, "PyYAML and bash 4 or later are needed")
class TestVmInitDryRun(unittest.TestCase):
    # stand-in values: an authorized_keys line in the ed25519 shape, with no real key in it
    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOnlyAKeyShapedTestValue lab"

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        (t / "bootstrap").mkdir()
        cls.node_env = Labs.get()["labs"]["m1"]["out"]["bootstrap/k8s-gpu1/node.env"]
        (t / "bootstrap" / "node.env").write_text(cls.node_env)
        (t / "keys").write_text(f"# the lab key\n{cls.KEY}\n")
        cls.env = {"SFAB_DRY_RUN": "1", "SFAB_BOOTSTRAP": str(t / "bootstrap"), "SFAB_VM_DIR": str(t / "vm"),
                   "SFAB_SHARED": str(t / "shared"), "SFAB_AUTHORIZED_KEYS": str(t / "keys"),
                   "SFAB_NODE_FILES": str(IMAGES / "vm-node" / "node-files"), "SFAB_NODE": "k8s-gpu1",
                   "VM_MEMORY_MB": "16384", "VM_SMP": "8"}
        r = _run(VM_INIT, cls.env)
        cls.rc, cls.out, cls.err = r.returncode, r.stdout, r.stderr
        cls.seed = t / "vm" / "seed"

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_runs(self):
        self.assertEqual(self.rc, 0, self.out + self.err)

    def test_user_data(self):
        ud = (self.seed / "user-data").read_text()
        self.assertTrue(ud.startswith("#cloud-config\n"))
        d = yaml.safe_load(ud)
        self.assertEqual((d["hostname"], d["fqdn"]), ("k8s-gpu1", "k8s-gpu1.ai.tarnwick.example"))
        self.assertFalse(d["ssh_pwauth"])
        (u,) = d["users"]
        self.assertEqual((u["name"], u["lock_passwd"], u["ssh_authorized_keys"]), ("admin", True, [self.KEY]))
        # the user's own group, made when missing: Ubuntu's cloud image already holds a group admin
        self.assertEqual((u["primary_group"], u["groups"]), ("admin", ["admin"]))
        self.assertNotIn("passwd", u)
        self.assertEqual([f["path"] for f in d["write_files"]],
                         ["/opt/sfab/bin/seed-sync.sh", "/etc/systemd/system/sfab-netsetup.service"])
        self.assertIn(["systemctl", "enable", "--now", "sfab-netsetup.service"], d["runcmd"])

    def test_network_config(self):
        d = yaml.safe_load((self.seed / "network-config").read_text())
        eth0 = d["ethernets"]["eth0"]
        self.assertEqual(eth0["match"]["macaddress"], "02:5a:6f:00:00:00")
        self.assertEqual(eth0["addresses"], ["172.21.40.111/24"])
        self.assertEqual(eth0["routes"], [{"to": "default", "via": "172.21.40.1", "table": 150}])
        self.assertEqual(eth0["routing-policy"], [{"from": "172.21.40.111", "table": 150}])
        self.assertEqual((self.seed / "meta-data").read_text(), "instance-id: sfab-m1-k8s-gpu1\nlocal-hostname: k8s-gpu1\n")

    def test_manifest(self):
        lines = (self.seed / "sfab" / "MANIFEST").read_text().splitlines()
        paths = [x.split()[3] for x in lines]
        self.assertEqual(paths, sorted(paths))
        for x in lines:
            sha, mode, owner, path = x.split()
            data = (self.seed / "sfab" / "root" / path.lstrip("/")).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), sha, path)
            self.assertRegex(mode, r"^0[0-7]{3}$")
        by = {x.split()[3]: x.split() for x in lines}
        self.assertEqual(by["/etc/sfab/node.env"][0], hashlib.sha256(self.node_env.encode()).hexdigest())
        self.assertEqual(by["/home/admin/.ssh/authorized_keys"][1:3], ["0600", "admin:admin"])
        self.assertEqual(by["/opt/sfab/bin/netsetup.sh"][1], "0755")
        for p in ("/etc/systemd/system/sfab-netsetup.service", "/etc/systemd/networkd.conf.d/10-sfab-foreign.conf",
                  "/etc/lldpd.d/sfab.conf", "/opt/sfab/bin/seed-sync.sh", "/etc/systemd/network/05-sfab-unmanaged.network"):
            self.assertIn(p, by)
        # M1's guests are no Kubernetes nodes: no cluster files, no unit, no mirrors
        self.assertFalse([p for p in by if "/k8s/" in p or "cluster" in p or "/containerd/" in p], sorted(by))

    def test_link_files(self):
        h = Labs.get()["labs"]["m1"]["model"].nodes["k8s-gpu1"]
        net = self.seed / "sfab" / "root" / "etc" / "systemd" / "network"
        for n in h.nics:
            name = n.ifname or n.eth
            text = (net / f"10-sfab-{name}.link").read_text()
            want = f"[Match]\nMACAddress={n.mac}\n\n[Link]\nName={name}\n" + (f"MTUBytes={n.mtu}\n" if n.mtu else "")
            self.assertEqual(text, want)
        unmanaged = (net / "05-sfab-unmanaged.network").read_text()
        self.assertIn("Unmanaged=yes", unmanaged)
        names = unmanaged.split("Name=", 1)[1].split("\n", 1)[0].split()
        self.assertEqual(set(names), {"eth1", "eth2", "eth3", "bond0", "bond0.120", "relay0", *(f"rail{r}" for r in range(1, 9)),
                                      *(f"rl{r}" for r in range(1, 9))})
        self.assertNotIn("eth0", names)

    def test_qemu_command(self):
        cmd = next(x for x in self.out.splitlines() if x.startswith("+ qemu-system-x86_64 "))
        argv = cmd[2:].split()
        e = parse_env(self.node_env)
        self.assertEqual(argv[argv.index("-uuid") + 1], e["VM_UUID"])
        self.assertEqual(argv[argv.index("-smp") + 1], "8")
        self.assertEqual(argv[argv.index("-m") + 1], "16384")
        devices = [argv[i + 1] for i, a in enumerate(argv) if a == "-device" and argv[i + 1].startswith("virtio-net-pci")]
        self.assertEqual(len(devices), 12)
        self.assertEqual(devices[0], "virtio-net-pci,netdev=n0,mac=02:5a:6f:00:00:00,romfile=")
        for k in range(1, 12):
            self.assertEqual(devices[k], f"virtio-net-pci,netdev=n{k},mac={e[f'NIC{k:02d}_MAC']},speed=10000,duplex=full,romfile=")
        self.assertIn("tap,id=n11,ifname=tap11,script=no,downscript=no", argv)

    def test_wrong_node_refused(self):
        r = _run(VM_INIT, {**self.env, "SFAB_NODE": "k8s-gpu2", "SFAB_VM_DIR": str(Path(self.tmp.name) / "vm2")})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("node.env is for k8s-gpu1", r.stdout + r.stderr)

    def test_topology_disagreement_is_reported(self):
        r = _run(VM_INIT, {**self.env, "VM_SMP": "4", "SFAB_VM_DIR": str(Path(self.tmp.name) / "vm3")})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("the topology sets VM_SMP=4", r.stdout)
        self.assertIn("-smp 8 ", r.stdout)


@unittest.skipUnless(HAVE_YAML and BASH, "PyYAML and bash 4 or later are needed")
@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestVmInitDryRunCluster(unittest.TestCase):
    """A Kubernetes guest's seed: its cluster files, the bootstrap and its unit, and the mirrors."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        out = Labs.get()["labs"]["one"]["out"]
        boot = t / "bootstrap"
        for p, text in out.items():
            if p.startswith("bootstrap/k8s-cp1/"):
                f = boot / p[len("bootstrap/k8s-cp1/"):]
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(text)
        (boot / "k8s").mkdir()
        (boot / "k8s" / "cluster.env").write_text("# a stand-in\nCLUSTER_ROLE=init\n")
        (boot / "k8s" / "kubeadm.yaml").write_text("# a stand-in\n")
        env = {"SFAB_DRY_RUN": "1", "SFAB_BOOTSTRAP": str(boot), "SFAB_VM_DIR": str(t / "vm"), "SFAB_SHARED": str(t / "shared"),
               "SFAB_AUTHORIZED_KEYS": str(t / "nokeys"), "SFAB_NODE_FILES": str(IMAGES / "vm-node" / "node-files"),
               "SFAB_NODE": "k8s-cp1"}
        r = _run(VM_INIT, env)
        cls.rc, cls.out = r.returncode, r.stdout + r.stderr
        lines = (t / "vm" / "seed" / "sfab" / "MANIFEST").read_text().splitlines() if cls.rc == 0 else []
        cls.by = {x.split()[3]: x.split() for x in lines}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_cluster_files_bootstrap_and_unit(self):
        self.assertEqual(self.rc, 0, self.out)
        self.assertEqual(self.by["/etc/sfab/k8s/cluster.env"][1:3], ["0644", "root:root"])
        self.assertEqual(self.by["/etc/sfab/k8s/kubeadm.yaml"][1], "0644")
        self.assertEqual(self.by["/opt/sfab/bin/cluster-bootstrap.sh"][1], "0755")
        self.assertEqual(self.by["/etc/systemd/system/sfab-cluster.service"][1], "0644")
        unit = (IMAGES / "vm-node" / "node-files" / "sfab-cluster.service").read_text()
        self.assertIn("ConditionPathExists=/etc/sfab/k8s/cluster.env", unit)

    def test_mirrors(self):
        self.assertEqual(self.rc, 0, self.out)
        self.assertEqual(sorted(p for p in self.by if p.startswith("/etc/containerd/certs.d/")),
                         [f"/etc/containerd/certs.d/{u}/hosts.toml"
                          for u in ("192.0.2.6:5000", "docker.io", "ghcr.io", "quay.io", "registry.k8s.io")])

    def test_seed_sync_enables_the_unit(self):
        text = (IMAGES / "vm-node" / "node-files" / "seed-sync.sh").read_text()
        self.assertIn('systemctl enable "$u"', text)
        self.assertIn('systemctl start --no-block "$u"', text)


@unittest.skipUnless(HAVE_YAML and BASH, "PyYAML and bash 4 or later are needed")
class TestClientInitDryRun(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.resolv = str(Path(self.tmp.name) / "resolv.conf")
        Path(self.resolv).write_text(standins.DOCKER_RESOLV_CONF)

    def tearDown(self):
        self.tmp.cleanup()

    def run_for(self, node: str, env: dict | None = None) -> list[str]:
        text = Labs.get()["labs"]["one"]["out"][f"bootstrap/{node}/init.env"]
        for k, v in (env or {}).items():
            text = re.sub(rf"^{k}=.*\n", "", text, flags=re.M) + (f"{k}={v}\n" if v is not None else "")
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write(text)
        try:
            r = _run(CLIENT_INIT, {"SFAB_DRY_RUN": "1", "SFAB_RESOLV_CONF": self.resolv}, f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return [x[2:] for x in r.stdout.splitlines() if x.startswith("+ ")]

    def test_enterprise_client(self):
        cmds = self.run_for("ent-client")
        for c in ("ip addr replace 10.24.10.10/30 dev eth1",
                  "ip route replace default via 172.21.40.1 dev eth0 table 150",
                  "ip rule add from 172.21.40.82 lookup 150",
                  "ip route replace default via 10.24.10.9 dev eth1",
                  "ethtool -K eth1 tx off",
                  # the spec's resolv_options: a lookup outlasts an LACP failover on the pair; the
                  # corporate resolver, and the corporate domain
                  f"write {self.resolv}: search tarnwick.example; nameserver 10.24.10.53; options timeout:10 attempts:4"):
            self.assertIn(c, cmds)
        self.assertLess(cmds.index("ip rule add from 172.21.40.82 lookup 150"), cmds.index("ip route replace default via 10.24.10.9 dev eth1"))
        # resolv.conf before anything that can fail: a missing link must not leave Docker's file
        write = next(i for i, c in enumerate(cmds) if c.startswith(f"write {self.resolv}: "))
        wait = next(i for i, c in enumerate(cmds) if c.startswith("wait for links"))
        self.assertLess(write, wait)

    def test_client_without_a_lab_resolver(self):
        # ops-client as sfab-m2 and the chapter 3 and 4 labs render it: no DNS_SERVERS. Docker's
        # nameserver and options stay; its search line becomes the lab's domain
        cmds = self.run_for("ops-client", {"DNS_SERVERS": None})
        write = f"write {self.resolv}: search ai.tarnwick.example; nameserver 127.0.0.11; options edns0 trust-ad ndots:0"
        self.assertIn(write, cmds)
        self.assertLess(cmds.index(write), next(i for i, c in enumerate(cmds) if c.startswith("wait for links")))
        self.assertFalse([c for c in cmds if "lab-host.invalid" in c])

    def test_bastion_shape(self):
        # one leg: the bond in VLAN 300, no out-of-band NIC
        cmds = self.run_for("bastion")
        for c in ("ip link add bond0 type bond mode 802.3ad lacp_rate fast miimon 100 xmit_hash_policy layer3+4",
                  "ip link set eth1 master bond0", "ip link set eth2 master bond0",
                  "ip addr replace 10.20.3.10/24 dev bond0",
                  "ip route replace default via 10.20.3.1 dev bond0"):
            self.assertIn(c, cmds)
        self.assertFalse([c for c in cmds if "eth3" in c or "lookup 100" in c])

    def test_services_host_shape(self):
        # a resolver on the pair: the bond at the VLAN's IP MTU, its gateway the firewall's unit
        cmds = self.run_for("dns-res2")
        for c in ("ip link add bond0 type bond mode 802.3ad lacp_rate fast miimon 100 xmit_hash_policy layer3+4",
                  "ip link set bond0 mtu 1500", "ip addr replace 10.20.14.21/24 dev bond0",
                  "ip route replace default via 10.20.14.1 dev bond0",
                  f"write {self.resolv}: search ai.tarnwick.example; nameserver 10.20.13.21; nameserver 10.20.14.21"):
            self.assertIn(c, cmds)


@unittest.skipUnless(BASH, "bash 4 or later is needed")
class TestClientResolver(unittest.TestCase):
    """init.sh's resolver() for real, on a stand-in of Docker's resolv.conf."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.f = Path(self.tmp.name) / "resolv.conf"
        self.f.write_text(standins.DOCKER_RESOLV_CONF)

    def tearDown(self):
        self.tmp.cleanup()

    def run_it(self, env: dict) -> str:
        r = standins.run_resolver(BASH, CLIENT_INIT, self.f, env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return self.f.read_text()

    def test_keeps_dockers_nameserver_and_options(self):
        inode = self.f.stat().st_ino
        want = "search tarnwick.example\nnameserver 127.0.0.11\noptions edns0 trust-ad ndots:0\n"
        self.assertEqual(self.run_it({"SEARCH": "tarnwick.example", "DOMAIN": "tarnwick.example"}), want)
        self.assertEqual(self.f.stat().st_ino, inode, "rewritten in place: Docker binds the file into the container")
        self.assertEqual(self.run_it({"SEARCH": "tarnwick.example", "DOMAIN": "tarnwick.example"}), want, "a second run changes nothing")

    def test_lab_resolver_replaces_dockers_lines(self):
        got = self.run_it({"SEARCH": "tarnwick.example", "DNS_SERVERS": "10.20.3.10", "RESOLV_OPTIONS": "timeout:10 attempts:4"})
        self.assertEqual(got, "search tarnwick.example\nnameserver 10.20.3.10\noptions timeout:10 attempts:4\n")

    def test_domain_when_the_env_has_no_search(self):
        # an init.env rendered before SEARCH went to every host still loses Docker's search line
        self.assertEqual(self.run_it({"DOMAIN": "tarnwick.example"}).splitlines()[0], "search tarnwick.example")

    def test_no_search_or_domain_drops_dockers_search(self):
        self.assertEqual(self.run_it({}), "nameserver 127.0.0.11\noptions edns0 trust-ad ndots:0\n")

    def test_frr_init_has_the_same_rewrite(self):
        def body(p: Path) -> str:
            return re.search(r"^resolver\(\) \{\n.*?^\}\n", p.read_text(), re.M | re.S).group(0)
        for other in (IMAGES / "frr" / "frr-init.sh", IMAGES / "bastion" / "bastion-init.sh"):
            with self.subTest(script=other.relative_to(ROOT).as_posix()):
                self.assertEqual(body(other), body(CLIENT_INIT))

    def test_bastion_without_a_lab_resolver(self):
        # the bastion's own copy of the rewrite, run for real: a bastion rendered with no
        # DNS_SERVERS still loses Docker's search line
        r = standins.run_resolver(BASH, IMAGES / "bastion" / "bastion-init.sh", self.f, {"SEARCH": "tarnwick.example"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.f.read_text(), "search tarnwick.example\nnameserver 127.0.0.11\noptions edns0 trust-ad ndots:0\n")


class TestImageFiles(unittest.TestCase):
    SCRIPTS = (VM_INIT, NETSETUP, IMAGES / "vm-node" / "node-files" / "seed-sync.sh", IMAGES / "vm-node" / "bake" / "bake.sh",
               IMAGES / "vm-node" / "bake" / "provision.sh", CLIENT_INIT, IMAGES / "build-if-stale.sh")

    def test_scripts(self):
        for p in self.SCRIPTS:
            with self.subTest(path=p.relative_to(ROOT).as_posix()):
                text = p.read_text()
                self.assertTrue(text.startswith("#!/usr/bin/env bash\n"))
                self.assertRegex(text, r"\nset -E?euo pipefail\n")
                self.assertTrue(os.access(p, os.X_OK), "executable")

    def test_no_dashes_and_no_secrets(self):
        files = [p for d in (IMAGES / "vm-node", IMAGES / "client") for p in d.rglob("*")
                 if p.is_file() and "/base/" not in p.as_posix()]
        files += [IMAGES / "Makefile", IMAGES / "README.md", IMAGES / "versions.py", IMAGES / "build-if-stale.sh",
                  ROOT / "common" / "sfab" / "render" / "host.py"]
        for p in files:
            with self.subTest(path=p.relative_to(ROOT).as_posix()):
                text = p.read_text(encoding="utf-8")
                for d in DASHES:
                    self.assertNotIn(d, text)
                self.assertNotRegex(text, r"(?i)(?<![a-z_])(passwd|password)\s*[:=]\s*\S")
                self.assertNotRegex(text, r"BEGIN [A-Z ]*PRIVATE KEY")

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to compare the readers")
    def test_versions_reader(self):
        spec = importlib.util.spec_from_file_location("sfab_images_versions", IMAGES / "versions.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        text = (ROOT / "spec" / "versions.yaml").read_text()
        self.assertEqual(mod.mini_load(text), yaml.safe_load(text))
        tree = mod.load()
        self.assertEqual(mod.image(tree, "ubuntu_base"), f"ubuntu:24.04@{tree['images']['ubuntu_base']['digest']}")
        self.assertEqual(mod.image(tree, "vm_node"), "sfab/vm-node:6-k8s1.35.8")
        self.assertEqual(mod.get(tree, "kubernetes.version"), "v1.35.8")

    @unittest.skipUnless(BASH, "bash 4 or later is needed")
    def test_containerd_config_edit(self):
        """provision.sh's config_path edit, on both shapes of containerd's default config."""
        text = (IMAGES / "vm-node" / "bake" / "provision.sh").read_text()
        sed = re.search(r'^sed -i -E ("s#\^\(\[\[:space:\]\]\*config_path.*?") \\$', text, re.M)
        awk = re.search(r"^(awk '/\^.*?\{print\}')", text, re.M | re.S)
        self.assertTrue(sed and awk, "provision.sh's config_path edit has moved")
        v17 = '[plugins."io.containerd.grpc.v1.cri".registry]\n      config_path = ""\n\n      [plugins."io.containerd.grpc.v1.cri".registry.mirrors]\n'
        v2 = ("[plugins.'io.containerd.cri.v1.images'.registry]\n    config_path = '/etc/containerd/certs.d:/etc/docker/certs.d'\n"
              "[plugins.'io.containerd.transfer.v1.local']\n  config_path = '/etc/containerd/certs.d:/etc/docker/certs.d'\n"
              "  plugin_config_path = ''\n[plugins.'io.containerd.other']\n  config_path = ''\n")
        for name, src, want in (
            ("1.7", v17, ['config_path = "/etc/containerd/certs.d"']),
            ("2.x", v2, ['config_path = "/etc/containerd/certs.d"', 'config_path = "/etc/containerd/certs.d"', "config_path = ''"]),
        ):
            with self.subTest(containerd=name), tempfile.TemporaryDirectory() as d:
                f = Path(d) / "config.toml"
                f.write_text(src)
                # The same expressions, written to a new file (BSD and GNU sed differ on -i).
                script = (f'sed -E {sed.group(1)} "$1" > "$1.sed" && mv "$1.sed" "$1"\n'
                          + awk.group(1) + ' "$1" > "$1.new" && mv "$1.new" "$1"')
                subprocess.run([BASH, "-c", script, "x", str(f)], check=True)
                got = [x.strip() for x in f.read_text().splitlines() if x.strip().startswith("config_path")]
                self.assertEqual(got, want)


if __name__ == "__main__":
    unittest.main()
