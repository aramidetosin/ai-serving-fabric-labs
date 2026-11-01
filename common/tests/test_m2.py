"""Milestone M2's harness: the selection, the collection plans of the new roles, their judges, the
trace's judgment, the memory watchdog and node-sync. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_m2*.py'

Hermetic: dev/m2 is rendered into a temporary directory (PyYAML), the inventory's service blocks
are checked against services_block (augment() is then a no-op), and every device is
a stand-in (common/tests/shims/, common/tests/shims-m2/, m2_world.py). Fixtures use the book's own
addressing plan and made-up names only.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
HERE = Path(__file__).resolve().parent
SHIMS = HERE / "shims"
SHIMS_M2 = HERE / "shims-m2"
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(COMMON))
sys.path.insert(0, str(HERE))

import judge  # noqa: E402
import m2_world  # noqa: E402
import runscope  # noqa: E402
import vocab  # noqa: E402


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


M2_NODES = ("fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw fw truenas1 k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2 k8s-ingress1 k8s-ingress2 bastion uplink-rtr "
            "ops-client ops-gw web-client inet-registry ent-client dns-auth1 dns-auth2 dns-res1 dns-res2 ent-dns inet-ntp")

_RENDER = None


def m2_render() -> Path:
    """dev/m2 rendered once into a temporary directory, its inventory augmented with the blocks
    the M2 harness reads (services_block), written back as gen/inventory.json."""
    global _RENDER
    if _RENDER is None:
        out = Path(tempfile.mkdtemp(prefix="sfab-test-m2-"))
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(ROOT / "dev" / "m2"), "--out", str(out), "-q"],
                       check=True, capture_output=True)
        from services_block import augment
        from sfab.spec import load, select
        model = select(load(str(ROOT)), str(ROOT / "dev" / "m2"))
        inv = json.loads((out / "gen" / "inventory.json").read_text())
        augment(inv, model)
        (out / "gen" / "inventory.json").write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n")
        _RENDER = out
    return _RENDER


def m2_inv() -> dict:
    return json.loads((m2_render() / "gen" / "inventory.json").read_text())


def tearDownModule():
    if _RENDER is not None:
        shutil.rmtree(_RENDER, ignore_errors=True)


# ------------------------------------------------------------------------------------------------


@unittest.skipUnless(have_yaml(), "PyYAML renders dev/m2")
class SelectionTest(unittest.TestCase):
    def test_slice_budget_and_ports(self):
        inv = m2_inv()
        self.assertEqual(inv["lab"], "sfab-m2")
        self.assertEqual(sorted(inv["order"]), sorted(M2_NODES.split()))
        self.assertEqual(inv["features"], {"k8s": True, "serving": False, "storage_setup": True})
        # M2's 114.25 GiB before revision 2, plus the two ingress nodes (6 each) and the VPN router
        # and the internet host (0.25 each)
        self.assertEqual(inv["budget"]["mem_gib"], 126.75)
        self.assertEqual(inv["budget"]["need_gib"], 142.75)
        # The disk budget is growth, not virtual size (FRAMEWORK.md 3.1): under state/ the lab's
        # own files, TrueNAS, three control nodes and two GPU nodes; in the container layers the
        # five switches and the PA-VM. The registry's data is seeded beforehand and budgeted nowhere.
        self.assertEqual((inv["budget"]["state_base_gib"], inv["budget"]["state_gib"], inv["budget"]["layer_gib"]),
                         (1.0, 95.0, 56.0))
        self.assertEqual({n: (inv["nodes"][n]["budget"]["state_gib"], inv["nodes"][n]["budget"]["layer_gib"])
                          for n in ("truenas1", "k8s-cp1", "k8s-gpu1", "fe-sw1", "fw", "inet-registry", "bastion")},
                         {"truenas1": (40.0, 0.0), "k8s-cp1": (6.0, 0.0), "k8s-gpu1": (12.0, 0.0), "fe-sw1": (0.0, 8.0),
                          "fw": (0.0, 16.0), "inet-registry": (0.0, 0.0), "bastion": (0.0, 0.0)})
        self.assertEqual({n: inv["nodes"][n]["disk_gib"] for n in ("k8s-cp1", "k8s-cp2", "k8s-cp3", "k8s-gpu1", "k8s-gpu2")},
                         {"k8s-cp1": 40, "k8s-cp2": 40, "k8s-cp3": 40, "k8s-gpu1": 80, "k8s-gpu2": 80})
        self.assertEqual({s: inv["nodes"][s]["num_nics"] for s in ("fe-sw1", "fe-sw2", "rail-sw1", "rail-sw2", "oob-sw")},
                         {"fe-sw1": 19, "fe-sw2": 19, "rail-sw1": 8, "rail-sw2": 8, "oob-sw": 8})
        pcs = sorted(inv["nodes"]["fe-sw1"]["portchannels"], key=judge.natural)
        self.assertEqual(pcs, ["PortChannel1", "PortChannel10", "PortChannel11", "PortChannel12", "PortChannel13", "PortChannel14",
                               "PortChannel15", "PortChannel21", "PortChannel22", "PortChannel30", "PortChannel31", "PortChannel32",
                               "PortChannel41", "PortChannel42", "PortChannel43", "PortChannel44"])
        self.assertEqual(len(inv["nodes"]["fe-sw1"]["portchannels"]["PortChannel31"]["members"]), 2)
        self.assertEqual(len(inv["nodes"]["fe-sw1"]["portchannels"]["PortChannel32"]["members"]), 1, "one management leg per switch")
        self.assertEqual(inv["watchdog"]["order"], ["k8s-gpu2", "k8s-gpu1", "k8s-ingress2", "k8s-ingress1", "k8s-cp3", "k8s-cp2", "k8s-cp1"])

    def test_addresses_are_the_plan(self):
        inv = m2_inv()
        n = inv["nodes"]
        want = {"bastion": "10.20.3.10/24", "k8s-cp1": "10.20.1.11/24", "k8s-cp3": "10.20.1.13/24", "k8s-gpu2": "10.20.1.22/24",
                "uplink-rtr": "198.51.100.1/29", "ops-client": "192.0.2.2/30", "inet-registry": "192.0.2.6/30",
                "ent-client": "10.24.10.10/30", "dns-auth1": "10.20.13.11/24", "dns-res1": "10.20.13.21/24", "dns-auth2": "10.20.14.11/24",
                "dns-res2": "10.20.14.21/24", "ent-dns": "10.24.10.53/30", "inet-ntp": "192.0.2.14/30"}
        self.assertEqual({k: n[k]["address"] for k in want}, want)
        self.assertEqual({k: n[k]["mgmt"] for k in ("bastion", "uplink-rtr", "inet-registry", "ops-client", "ent-client", "truenas1")},
                         {"bastion": "172.21.40.50", "uplink-rtr": "172.21.40.61", "inet-registry": "172.21.40.70",
                          "ops-client": "172.21.40.81", "ent-client": "172.21.40.82", "truenas1": "172.21.40.121"})
        self.assertEqual({k: n[k]["mgmt"] for k in ("ent-dns", "dns-auth1", "dns-res1", "dns-auth2", "dns-res2", "inet-ntp")},
                         {"ent-dns": "172.21.40.55", "dns-auth1": "172.21.40.56", "dns-res1": "172.21.40.57", "dns-auth2": "172.21.40.58",
                          "dns-res2": "172.21.40.59", "inet-ntp": "172.21.40.63"})
        self.assertIsNone(n["bastion"]["oob"], "the jump host has one leg")
        self.assertEqual(n["truenas1"]["data"]["address"], "10.20.12.31/24")
        self.assertEqual(n["truenas1"]["mgmt_if"]["address"], "10.20.2.31/24")
        self.assertEqual(inv["k8s"]["api_vip"], "10.20.1.10")
        self.assertEqual({g: v["vip"] for g, v in inv["gateways"].items()}, {"gw-internal": "10.20.11.200", "gw-users": "10.20.11.210"})
        self.assertEqual({k: n[k]["address"] for k in ("k8s-ingress1", "k8s-ingress2", "ops-gw", "web-client")},
                         {"k8s-ingress1": "10.20.1.31/24", "k8s-ingress2": "10.20.1.32/24", "ops-gw": "192.0.2.22/30", "web-client": "192.0.2.18/30"})
        self.assertNotIn("ops-dns", n, "the operator's resolver arrives with sfab/resolver")

    def test_trace_block_keys_are_strings(self):
        # A bare YAML "on" key is the boolean true, which broke the inventory's sorted dump.
        inv = m2_inv()
        for p in inv["trace"]["points"]:
            self.assertTrue(all(isinstance(k, str) for k in p), p)
        f = inv["trace"]["flows"][0]
        self.assertEqual((f["client"], f["gateway"], f["sport"], f["ttl_drop_after"]), ("ent-client", "gw-users", 41443, 2))

    def test_inventory_carries_the_service_blocks(self):
        # render/inventory.py emits what services_block builds, so augment() adds nothing
        from services_block import services, storage_csi
        from sfab.spec import load, select
        out = Path(tempfile.mkdtemp(prefix="sfab-test-m2-raw-"))
        try:
            subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(ROOT / "dev" / "m2"), "--out", str(out), "-q"],
                           check=True, capture_output=True)
            raw = json.loads((out / "gen" / "inventory.json").read_text())
        finally:
            shutil.rmtree(out, ignore_errors=True)
        model = select(load(str(ROOT)), str(ROOT / "dev" / "m2"))
        for k, v in services(model).items():
            self.assertEqual(raw.get(k), json.loads(json.dumps(v)), k)
        for name, csi in storage_csi(model).items():
            self.assertEqual(raw["nodes"][name].get("csi"), csi, name)
        self.assertEqual(raw["stages"]["modules"], ["bonding", "vrf"], "the uplink router's VRF needs the vrf module")

    def test_m1_probes_no_population(self):
        # without the cluster no Gateway answers: M1's GPU nodes sit inside the nodes population
        inv = json.loads((ROOT / "dev" / "m1" / "gen" / "inventory.json").read_text())
        for g in ("k8s-gpu1", "k8s-gpu2"):
            self.assertFalse([r for r in judge.plan(inv, g) if r["slug"].startswith("pop_")], g)
        self.assertEqual(inv["stages"]["modules"], ["bonding"])

    def test_kubernetes_ca_permits_the_control_nodes(self):
        inv = m2_inv()
        dns = inv["ca"]["intermediates"]["kubernetes"]["dns"]
        for c in inv["k8s"]["control"]:
            self.assertIn(c, dns)


# ------------------------------------------------------------------------------------------------


@unittest.skipUnless(have_yaml(), "PyYAML renders dev/m2")
class PlanTest(unittest.TestCase):
    def setUp(self):
        self.inv = m2_inv()

    def slugs(self, node):
        return {r["slug"]: r for r in judge.plan(self.inv, node)}

    def test_every_line_resolves_and_has_a_known_surface(self):
        for node in self.inv["order"]:
            for r in judge.plan(self.inv, node):
                self.assertIn(r["surface"], judge.SURFACE_EXT, (node, r))
                self.assertNotRegex(r["command"], judge.FIELD.pattern, f"{node} {r['slug']}: an unfilled field")

    def test_bastion_reads_itself_and_the_cluster(self):
        # the bastion reads itself and its operator's credential; the cluster is read on the init node
        p = self.slugs("bastion")
        for s in ("bonding", "services", "resolv_conf", "ca_certs", "shared_keys", "stor_mgmt_https", "admin_kubeconfig",
                  "operator_cert", "operator_can_i"):
            self.assertIn(s, p)
        for s in ("nodes", "leases", "table_oob"):
            self.assertNotIn(s, p)
        self.assertIn("https://10.20.2.31/", p["stor_mgmt_https"]["command"])
        self.assertIn("now=", p["operator_cert"]["command"])
        k = self.slugs(self.inv["stages"]["kubectl"])
        for s in ("nodes", "leases", "gateways", "httproutes", "api_cert", "wildcard_cert", "events_warning"):
            self.assertIn(s, k)
        self.assertEqual(k["nodes"]["surface"], "kubectl-json")
        # the first Gateway's own listener certificate (one per Gateway)
        self.assertIn("-n gateways get secret gw-internal-tls", k["wildcard_cert"]["command"])
        self.assertIn("openssl s_client -connect 10.20.1.10:6443 -servername k8s.ai.tarnwick.example", k["api_cert"]["command"])
        # the jsonpath braces are not fields
        self.assertIn("'{.clusters[0].cluster.server}'", k["kube_server"]["command"])

    def test_kubernetes_nodes(self):
        for g in ("k8s-cp1", "k8s-cp2", "k8s-cp3", "k8s-gpu1", "k8s-gpu2"):
            p = self.slugs(g)
            self.assertEqual(p["registry_v2"]["command"],
                             "curl -sS -o /dev/null -D - --max-time 15 --cacert /shared/ca/root.crt https://192.0.2.6:5000/v2/")
            self.assertTrue(p["ntp_resolvers"]["command"].startswith("for a in 10.20.13.21 10.20.14.21; do"))
            self.assertEqual(p["dns_storage"]["command"], "dig +time=5 +tries=2 +short truenas1.ai.tarnwick.example @10.20.13.21")
            self.assertTrue(p["dns_both"]["command"].startswith("for r in 10.20.13.21 10.20.14.21; do"))
            self.assertIn("/dev/tcp/10.20.12.31/$p", p["storage_ports"]["command"])
        self.assertNotIn("cluster_unit", self.slugs("bastion"))

    def test_router_peers(self):
        p = self.slugs("uplink-rtr")
        # host peers are pinged; the firewall is read by ARP (its rulebase admits no ping from zone uplink)
        self.assertEqual({s: r["command"] for s, r in p.items() if s.startswith(("ping_", "arp_"))},
                         {"arp_fw": "arping -c 3 -w 6 -I eth1 198.51.100.2", "ping_ops_gw": "ping -c 3 -W 2 192.0.2.22",
                          "ping_inet_registry": "ping -c 3 -W 2 192.0.2.6", "ping_inet_ntp": "ping -c 3 -W 2 192.0.2.14",
                          "ping_web_client": "ping -c 3 -W 2 192.0.2.18"})
        self.assertEqual(p["frr_routes"]["surface"], "frr-json")

    def test_populations_and_their_probes(self):
        op, ent, c1 = self.slugs("ops-client"), self.slugs("ent-client"), self.slugs("k8s-cp1")
        # ops-dns is not in M2: no resolver line, and the names are pinned to the internal Gateway's
        # VIP, which the operator reaches through the tunnel
        self.assertNotIn("pop_dns_users", op)
        self.assertIn("--resolve llm.ai.tarnwick.example:443:10.20.11.200", op["pop_https_users"]["command"])
        self.assertIn("--resolve admin.ai.tarnwick.example:443:10.20.11.200", op["pop_https_admin"]["command"])
        self.assertNotIn("pop_https_users", self.slugs("web-client"), "an internet host with no audience probes no Gateway")
        self.assertEqual(ent["pop_dns_users"]["command"], "dig +time=5 +tries=2 +short llm.ai.tarnwick.example @10.24.10.53")
        self.assertNotIn("--resolve", ent["pop_https_users"]["command"])
        self.assertIn("--cacert /shared/ca/root.crt", ent["pop_https_users"]["command"])
        self.assertIn("msg=sfab-audit-nodes", c1["pop_https_users"]["command"])
        self.assertEqual(c1["pop_dns_infra"]["surface"], "node")
        self.assertNotIn("pop_https_users", self.slugs("k8s-cp2"), "one probe node per population")

    def test_literal_braces(self):
        self.assertEqual(judge.fill("curl -w '%{{http_code}}' {gateway}", {}, {"gateway": "10.20.1.1"}, {}),
                         "curl -w '%{http_code}' 10.20.1.1")

    def test_no_cluster_no_cluster_lines(self):
        inv = json.loads(json.dumps(self.inv))
        inv["stages"]["cluster"] = False
        self.assertNotIn("nodes", {r["slug"] for r in judge.plan(inv, "bastion")})
        self.assertNotIn("cluster_unit", {r["slug"] for r in judge.plan(inv, "k8s-cp1")})


# ------------------------------------------------------------------------------------------------


@unittest.skipUnless(have_yaml(), "PyYAML renders dev/m2")
class JudgeTest(unittest.TestCase):
    GROUPS = ("cluster-nodes", "bastion", "services", "routers", "registry", "clients", "storage", "cluster", "populations")

    @classmethod
    def setUpClass(cls):
        cls.inv = m2_inv()
        cls.render = m2_render()
        cls.world = m2_world.healthy(cls.inv, cls.render)

    def run_groups(self, world, groups=GROUPS):
        with tempfile.TemporaryDirectory() as d:
            m2_world.write_set(Path(d), world)
            buf = io.StringIO()
            v = vocab.Vocab(verdict=os.path.join(d, "verdict.txt"), known=set(self.inv.get("known") or []), out=buf)
            j = judge.Judge(judge.ResultSet(d), self.inv, self.render, v)
            for g in groups:
                getattr(j, judge.GROUPS[g])([])
            return buf.getvalue()

    def fails(self, out):
        return [l for l in out.splitlines() if l.startswith("  FAIL  ")]

    def test_healthy_lab_is_green(self):
        out = self.run_groups(self.world)
        fails = self.fails(out)
        pinned = json.loads((self.render / "gen" / "RENDER.json").read_text())["versions"]["kubernetes"].get("helm") or {}
        if not pinned.get("version"):
            fails = [f for f in fails if "helm is the pinned version" not in f]
        self.assertEqual(fails, [], out)
        for line in (
                "== k8s-cp1: cluster node", "  PASS  sfab-cluster.service finished in this boot with status 0",
                "  PASS  containerd mirrors: a hosts.toml for each of docker.io, ghcr.io, quay.io, registry.k8s.io naming https://192.0.2.6:5000 with override_path",
                "  PASS  the registry answers through the firewall's source NAT (GET https://192.0.2.6:5000/v2/ is 200)",
                "  PASS  dns-res1 answers NTP from k8s-cp1's segment (10.20.13.21, stratum 3)",
                "  PASS  dns-res2 answers NTP from k8s-cp1's segment (10.20.14.21, stratum 3)",
                "  PASS  systemd-timesyncd names both resolvers as its time servers",
                "  PASS  the internal view answers llm.ai.tarnwick.example with 10.20.11.200",
                "  PASS  each of the node's 2 resolvers answers llm.ai.tarnwick.example with 10.20.11.200",
                "  PASS  the internal view answers an infrastructure name: truenas1.ai.tarnwick.example is 10.20.12.31",
                "  PASS  TrueNAS's data address 10.20.12.31 answers on NFS 2049",
                "== bastion: bastion, the jump host", "  PASS  bond0 holds 10.20.3.10/24 and is up",
                "  PASS  one leg only: no NIC in the BMC VLAN (the render names none)",
                "  PASS  no DNS or time server runs on the jump host (named, chronyd, dnsmasq absent)",
                "  PASS  the bastion asks the lab's resolvers (dns-res1, dns-res2)",
                "  PASS  the lab root CA published: state/shared/ca/root.crt, subject Tarnwick Lab Root CA",
                "  PASS  the platform intermediate (Tarnwick Platform CA) chains to the lab root",
                "  PASS  the platform intermediate's name constraints: 10.20.0.0/14, 10.24.10.0/24, ai.tarnwick.example",
                "  PASS  no private key under state/shared/ (kubeadm's keys retracted once every control node joined)",
                "  PASS  no kubeconfig for root on the bastion (the admin kubeconfig stays on the init node)",
                "  PASS  admin's kubeconfig on the bastion carries a client certificate for admin in group operators",
                "  PASS  the client certificate is short-lived: it expires within 8 hours of its issue, not a standing credential",
                "  PASS  admin may read the workloads and the nodes and change nothing, no Secrets (ClusterRole view and operators-cluster-view)",
                "== dns-auth1: dns-auth", "== dns-auth2: dns-auth", "== dns-res1: dns-res", "== ent-dns: dns-corporate", "== inet-ntp: inet-ntp",
                "  PASS  recursion is off: a name outside its zones is REFUSED",
                "  PASS  a name outside the platform's zone is NXDOMAIN at once, from the resolver's own empty root (aa)",
                "  PASS  chrony follows the reference inet-ntp (192.0.2.14): selected, marked ^*",
                "  PASS  the reference is authenticated with NTS (chronyc authdata: mode NTS, a key and cookies)",
                "  PASS  the reverse name of 10.20.1.10 is k8s.ai.tarnwick.example",
                "  PASS  the reference accepted NTS key exchanges",
                "== uplink-rtr: router", "  PASS  FRR 10.5.4 running", "  PASS  eth0 in VRF mgmt",
                "  PASS  connected route 192.0.2.4/30 on eth3", "  PASS  inet-registry answers ping on 192.0.2.6",
                "  PASS  inet-ntp answers ping on 192.0.2.14",
                "== inet-registry: registry",
                "  PASS  its access log shows pulls from 198.51.100.2, the firewall's public address (a node's pull crossed the source NAT)",
                "== ent-client: client", "  PASS  resolv.conf names 10.24.10.53", "  PASS  resolv.conf options timeout:10 attempts:4",
                "== truenas1: storage",
                "== cluster", "  PASS  the harness's kubectl reaches the API from k8s-cp1 with the admin kubeconfig kubeadm wrote there: server v1.35.8",
                "  PASS  k8s-cp1 Ready, kubelet v1.35.8, InternalIP 10.20.1.11, label node-role.tarnwick.example/control",
                "  PASS  no kube-proxy DaemonSet (Cilium replaces kube-proxy)",
                "  PASS  the API VIP 10.20.1.10: the kube-vip lease held by a control node (k8s-cp1)",
                "  PASS  the API server's certificate is issued by Tarnwick Kubernetes CA and verifies against the lab root",
                "  PASS  Cilium devices are the spec's (bond0,bond0.110)", "  PASS  ClusterIssuer lab-ca Ready",
                "  PASS  the wildcard certificate in gw-internal-tls (*.ai.tarnwick.example) is issued by Tarnwick Platform CA",
                "  PASS  Gateway gw-users Programmed with address 10.20.11.210",
                "  PASS  a load-balancer pool covers gw-users's range 10.20.11.210 to 10.20.11.214",
                "  PASS  an L2 announcement policy on ^bond0\\.110$ from the ingress nodes (node-role.tarnwick.example/ingress)",
                "  PASS  gw-users's Service announced: its lease held by an ingress node (k8s-ingress1)",
                "  PASS  the test backend echo/echo: 2 of 2 replicas ready",
                "  PASS  an HTTPRoute on gw-users Accepted with its references resolved, listing llm.ai.tarnwick.example, to echo",
                "  PASS  StorageClass truenas-nvmeof present, the cluster's default",
                "  PASS  no Warning event since finish archived them",
                "== population enterprise",
                "  PASS  ent-client: admin.ai.tarnwick.example has no answer: the enterprise view publishes no admin name to this population",
                "  PASS  ent-client: k8s-cp1.ai.tarnwick.example has no answer, never 10.20.1.11: the enterprise view holds no infrastructure record",
                "  PASS  ent-client: https://admin.ai.tarnwick.example/echo: 404 from gw-users (the Gateway has no route for the name)",
                "  PASS  k8s-cp1: k8s-cp1.ai.tarnwick.example is 10.20.1.11: the internal view holds the infrastructure records",
                "== population operator"):
            self.assertIn(line, out)
        self.assertIn("ops-client: https://llm.ai.tarnwick.example/echo: 200, the message echoed, the chain verified against the lab root "
                      "(name pinned to 10.20.11.200: the population's resolver is not in this lab)", out)
        # every container whose resolv.conf the audit reads searches its own domain only: the platform
        # zone for the router, the registry, the operator's client and the internet host, the corporate
        # domain for the enterprise client (a corporate resolver's local host)
        self.assertEqual(out.count("  PASS  resolv.conf searches the lab's domain only (ai.tarnwick.example)\n"), 4, out)
        self.assertEqual(out.count("  PASS  resolv.conf searches the lab's domain only (tarnwick.example)\n"), 1, out)
        # the secondary at the primary's serial in both views
        self.assertEqual(out.count("from dns-auth1 by transfer) "), 0)
        self.assertEqual(len([l for l in out.splitlines() if l.startswith("  PASS  view ") and "secondary here" in l]), 2, out)

    def test_faults_are_failures(self):
        want = {
            "admin-timeout": "FAIL  ent-client: https://admin.ai.tarnwick.example/echo: 404 from gw-users",
            "admin-404-not-envoy": "FAIL  ent-client: https://admin.ai.tarnwick.example/echo: 404 from gw-users",
            "lease-on-gpu": "FAIL  the API VIP 10.20.1.10: the kube-vip lease held by a control node (k8s-gpu1)",
            "cilium-devices": "FAIL  Cilium devices are the spec's (bond0,bond0.110) -> want bond0,bond0.110, got eth0",
            "kube-proxy": "FAIL  no kube-proxy DaemonSet",
            "stray-key": "FAIL  no private key under state/shared/ (kubeadm's keys retracted once every control node joined) -> state/shared/cluster/ca/ca.key (600)",
            "no-snat-pull": "FAIL  its access log shows pulls from 198.51.100.2",
            "ntp-silent": "FAIL  dns-res1 answers NTP from k8s-cp2's segment",
            "enterprise-sees-infra": "FAIL  ent-client: k8s-cp1.ai.tarnwick.example has no answer, never 10.20.1.11",
            "router-no-vrf": "FAIL  eth0 in VRF mgmt -> want mgmt, got no master",
            "nfs-closed": "FAIL  TrueNAS's data address 10.20.12.31 answers on NFS 2049 -> closed: 2049",
            "client-host-search": "FAIL  resolv.conf searches the lab's domain only (ai.tarnwick.example) -> 1 other domain in the search list (not printed)",
            "router-host-search": "FAIL  resolv.conf searches the lab's domain only (ai.tarnwick.example) -> 3 other domains in the search list (not printed)",
            "registry-no-search": "FAIL  resolv.conf searches the lab's domain only (ai.tarnwick.example) -> no search line",
            "frr-other-release": "FAIL  FRR 10.5.4 running -> FRRouting 10.4.1_git",
            "secondary-stale": "FAIL  view enterprise: ai.tarnwick.example is secondary here",
            "nts-off": "FAIL  the reference is authenticated with NTS",
            "bastion-named": "FAIL  no DNS or time server runs on the jump host (named, chronyd, dnsmasq absent) -> running: named",
        }
        for fault, line in want.items():
            out = self.run_groups(m2_world.break_world(self.world, fault))
            self.assertIn(line, out, fault)
            # a domain from the lab host's file never reaches the verdict, nor the host's kernel release
            self.assertNotIn(".invalid", out, fault)
            self.assertNotIn("stand-in", out, fault)

    def test_missing_files_fail_never_pass(self):
        w = json.loads(json.dumps(self.world))
        del w["k8s-cp1"]["leases"]
        w["k8s-cp1"]["gateways"] = ""
        out = self.run_groups(w, ("cluster",))
        self.assertIn("  FAIL  the leases -> leases not collected", out)
        self.assertIn("  FAIL  the Gateways -> gateways is not kubectl JSON", out)

    def test_helm_pin(self):
        with tempfile.TemporaryDirectory() as d:
            r = Path(d)
            (r / "gen").mkdir()
            rj = json.loads((self.render / "gen" / "RENDER.json").read_text())
            rj["versions"]["kubernetes"]["helm"] = {"version": "v3.22.0"}
            (r / "gen" / "RENDER.json").write_text(json.dumps(rj))
            self.assertEqual(judge.Judge(judge.ResultSet(d), self.inv, r, vocab.Vocab(out=io.StringIO())).pinned("helm"), "v3.22.0")
            rj["versions"]["kubernetes"]["helm"] = {"version": None}
            (r / "gen" / "RENDER.json").write_text(json.dumps(rj))
            self.assertIsNone(judge.Judge(judge.ResultSet(d), self.inv, r, vocab.Vocab(out=io.StringIO())).pinned("helm"))

    def test_parsers(self):
        self.assertEqual(judge.p_dig("10.20.11.210\n;; connection timed out\n"), ["10.20.11.210"])
        code, h, body = judge.p_curl_i("HTTP/1.1 100 Continue\n\nHTTP/2 404 \r\nserver: envoy\r\n\r\n")
        self.assertEqual((code, h.get("server"), body.strip()), (404, "envoy", ""))
        x = judge.p_x509(m2_world.x509("CN=Tarnwick Platform CA,O=Tarnwick", "CN=Tarnwick Lab Root CA", True, "/x.crt",
                                       ["ai.tarnwick.example", "10.20.0.0/14"]))
        self.assertEqual((x["cn"], x["issuer_cn"], x["verified"]), ("Tarnwick Platform CA", "Tarnwick Lab Root CA", True))
        self.assertEqual(sorted(x["permitted"]), ["10.20.0.0/14", "ai.tarnwick.example"])
        self.assertEqual(judge.p_http_status("HTTP/1.1 200 OK\nX: y"), 200)
        self.assertEqual(sorted(judge.p_sections("== a\n1\n== b\n2\n")), ["a", "b"])


# ------------------------------------------------------------------------------------------------
# the trace's planning and judgment (dev/m2/trace-md.py)

TMD = ROOT / "dev" / "m2" / "trace-md.py"


def syn(ts, vlan, ttl, src="10.24.10.10", dst="10.20.11.210", seq=1234567890, sport=41443, flags="S", cksum="correct"):
    eth = (f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan
           else "ethertype IPv4 (0x0800), length 74: ")
    return (f"2026-10-20 10:00:{ts:09.6f} 0c:00:aa:bb:cc:01 > 02:5a:66:00:00:01, {eth}(tos 0x0, ttl {ttl}, id 4321, offset 0, "
            f"flags [DF], proto TCP (6), length 60)\n    {src}.{sport} > {dst}.443: Flags [{flags}], cksum 0x1a2b ({cksum}), "
            f"seq {seq}, win 64240, options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length 0")


TLOG = """admin@fw> show log traffic direction equal backward receive_time in last-15-minutes dport equal 443

Time                App             From            Src Port   Source
Rule                Action          To              Dst Port   Destination
                    Src User        Dst User                   End Reason
Rule_UUid
====================================================================================================
2026/10/20 10:00:01 ssl             enterprise      41442      10.24.10.10
staff-to-users-gate allow           ingress         443        10.20.11.210
                                                               tcp-fin
3f0a5f6e-0000-4000-8000-000000000001
2026/10/20 10:00:05 ssl             enterprise      41443      10.24.10.10
staff-to-users-gate allow           ingress         443        10.20.11.210
                                                               tcp-fin
3f0a5f6e-0000-4000-8000-000000000001
"""


@unittest.skipUnless(have_yaml(), "PyYAML renders dev/m2")
class TraceTest(unittest.TestCase):
    def tmd(self, *args, env=None):
        e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        e.update(env or {})
        return subprocess.run([sys.executable, str(TMD), *args], capture_output=True, text=True, env=e, timeout=60)

    def setUp(self):
        self.inv_path = m2_render() / "gen" / "inventory.json"
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-trace-"))

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def test_flow_and_points(self):
        r = self.tmd("flow", "--inv", str(self.inv_path), "--k8s", str(m2_render() / "gen" / "k8s.json"))
        self.assertEqual(r.returncode, 0, r.stderr)
        env = dict(l.split("=", 1) for l in r.stdout.splitlines())
        self.assertEqual((env["CLIENT"], env["CLIENT_ADDR"], env["VIP"], env["FQDN"], env["SPORT"], env["WARM_SPORT"]),
                         ("ent-client", "10.24.10.10", "10.20.11.210", "llm.ai.tarnwick.example", "41443", "41442"))
        self.assertEqual(env["RULE"], "staff-to-users-gateway")
        r = self.tmd("points", "--inv", str(self.inv_path), "--holder", "k8s-ingress1")
        self.assertEqual(r.returncode, 0, r.stderr)
        rows = [l.split("\t") for l in r.stdout.splitlines()]
        self.assertEqual([x[0] for x in rows], ["1-ent-client-eth1", "2-fw-ethernet1-4", "3-fw-ae1-leg1", "3-fw-ae1-leg2",
                                                "4-fe-sw1-Ethernet2", "4-fe-sw2-Ethernet2", "5-fe-sw1-Ethernet13", "5-fe-sw2-Ethernet13",
                                                "6-k8s-ingress1-bond0"])
        self.assertEqual(rows[-1][1:5], ["guest", "k8s-ingress1", "bond0", "110"], "the ingress node's bond carries the VIPs' VLAN tagged")
        self.assertEqual(rows[6][1:4], ["container", "fe-sw1", "eth14"])
        r = self.tmd("points", "--inv", str(self.inv_path))
        self.assertNotEqual(r.returncode, 0, "the lease holder's points need the holder")

    def test_holder(self):
        f = self.t / "leases.json"
        f.write_text(json.dumps({"items": [
            {"metadata": {"namespace": "kube-system", "name": "cilium-l2announce-gateways-cilium-gateway-gw-internal"}, "spec": {"holderIdentity": "k8s-cp1"}},
            {"metadata": {"namespace": "kube-system", "name": "cilium-l2announce-gateways-cilium-gateway-gw-users"}, "spec": {"holderIdentity": "k8s-cp3"}}]}))
        r = self.tmd("holder", "--leases", str(f), "--namespace", "gateways", "--gateway", "gw-users")
        self.assertEqual(r.stdout.strip(), "k8s-cp3")
        r = self.tmd("holder", "--leases", str(f), "--gateway", "gw-users", "--lease", "kube-system/cilium-l2announce-gateways-cilium-gateway-gw-internal")
        self.assertEqual(r.stdout.strip(), "k8s-cp1")

    def evidence(self, faults=()):
        rs = self.t / "set"
        cap = rs / "captures"
        cap.mkdir(parents=True)
        holder = "k8s-ingress1"
        pts = self.tmd("points", "--inv", str(self.inv_path), "--holder", holder).stdout
        (rs / "points.tsv").write_text(pts)
        flow = self.tmd("flow", "--inv", str(self.inv_path)).stdout + f"HOLDER={holder}\n"
        (rs / "flow.env").write_text(flow)
        other = syn(0.5, None, 64, sport=41442, seq=99)
        legs = {"1-ent-client-eth1": syn(1, None, 64), "2-fw-ethernet1-4": syn(1.001, None, 64),
                "3-fw-ae1-leg1": syn(1.002, 110, 63), "3-fw-ae1-leg2": syn(0.6, 110, 63, seq=99, sport=41442),
                "4-fe-sw1-Ethernet2": syn(1.002, 110, 63), "4-fe-sw2-Ethernet2": "",
                "5-fe-sw1-Ethernet13": syn(1.003, 110, 63), "5-fe-sw2-Ethernet13": "",
                "6-k8s-ingress1-bond0": syn(1.004, 110, 63)}
        if "nat" in faults:
            legs["6-k8s-ingress1-bond0"] = syn(1.004, 110, 63, dst="10.20.11.200")
        if "both-legs" in faults:
            legs["3-fw-ae1-leg2"] = syn(1.002, 110, 63)
        if "untagged-server" in faults:
            legs["5-fe-sw1-Ethernet13"] = syn(1.003, None, 63)
        if "ttl" in faults:
            legs["6-k8s-ingress1-bond0"] = syn(1.004, 110, 62)
        if "missing-bond0" in faults:
            legs["6-k8s-ingress1-bond0"] = other
        for pid, text in legs.items():
            (cap / f"{pid}.txt").write_text((other + "\n" if pid.startswith("1-") else "") + text + "\n")
            (cap / f"{pid}.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")
        (rs / "dns.txt").write_text("10.20.11.210\n")
        (rs / "warmup.txt").write_text("HTTP/2 200 \nserver: envoy\n\nsfab-m2-trace")
        (rs / "request.txt").write_text("HTTP/2 200 \nserver: envoy\n\nsfab-m2-trace" if "no-reply" not in faults
                                        else "curl: (28) Connection timed out")
        (rs / "fw-traffic-log.txt").write_text(TLOG.replace("staff-to-users-gate allow           ingress         443        10.20.11.210\n"
                                                            "                                                               tcp-fin\n"
                                                            "3f0a5f6e-0000-4000-8000-000000000001\n", "", 1)
                                               if "tlog-late" not in faults else TLOG.split("2026/10/20 10:00:05")[0])
        (rs / "RUN.json").write_text(json.dumps({"labs_repo": {"commit": "none"}, "utc_start": "2026-10-20T10:00:00Z"}))
        return rs

    def judge(self, rs):
        r = self.tmd("judge", "--set", str(rs), "--inv", str(self.inv_path), "--points", str(rs / "points.tsv"),
                     "--env", str(rs / "flow.env"), env={"SFAB_VERDICT": str(rs / "verdict.txt")})
        return r, (rs / "verdict.txt").read_text() if (rs / "verdict.txt").exists() else ""

    def test_green_trace(self):
        rs = self.evidence()
        r, verdict = self.judge(rs)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("FAIL", verdict, verdict)
        for line in ("  PASS  ent-client resolves llm.ai.tarnwick.example through 10.24.10.53 to the users' VIP 10.20.11.210",
                     "  PASS  the recorded SYN leaves ent-client from the pinned source port 41443 (seq 1234567890)",
                     "  PASS  9 capture points decoded (9 with a decode)",
                     "  PASS  exactly one of the ae1 points carries the SYN (3-fw-ae1-leg1, 3-fw-ae1-leg2)",
                     "  PASS  the SYN's trunk port is the pair port its ae1 leg lands on (3-fw-ae1-leg1 to fe-sw1:eth3)",
                     "  PASS  the SYN leaves the pair on the switch that received it (fe-sw1)",
                     "  PASS  3-fw-ae1-leg1: tagged 802.1Q 110", "  PASS  6-k8s-ingress1-bond0: tagged 802.1Q 110",
                     "  PASS  TTL 64 up to the firewall, 63 after it: one routed hop",
                     "  PASS  source 10.24.10.10 and destination 10.20.11.210:443 unchanged at every point (no translation)",
                     "  PASS  https://llm.ai.tarnwick.example/echo?msg=sfab-m2-trace answers 200 with the echoed message sfab-m2-trace",
                     "  PASS  the firewall's traffic log has the session allowed by staff-to-users-gateway (shown as staff-to-users-gate), zone enterprise to zone ingress"):
            self.assertIn(line, verdict)
        md = (rs / "TRACE.md").read_text()
        self.assertIn("capture points: 9", md)
        self.assertIn("`captures/6-k8s-ingress1-bond0.txt:1`", md)
        self.assertIn("== RESULT: ", md)
        self.assertNotIn(chr(0x2014), md, "no em dash in TRACE.md")
        self.assertNotIn(chr(0x2013), md, "no en dash in TRACE.md")

    def test_faults(self):
        want = {"nat": "FAIL  source 10.24.10.10 and destination 10.20.11.210:443 unchanged at every point (no translation) -> 6-k8s-ingress1-bond0 10.24.10.10 > 10.20.11.200",
                "both-legs": "FAIL  exactly one of the ae1 points carries the SYN",
                "untagged-server": "FAIL  5-fe-sw1-Ethernet13: tagged 802.1Q 110 -> untagged",
                "ttl": "FAIL  TTL 64 up to the firewall, 63 after it: one routed hop -> 6-k8s-ingress1-bond0 62",
                "missing-bond0": "FAIL  6-k8s-ingress1-bond0: the recorded SYN seen (seq 1234567890)",
                "no-reply": "FAIL  https://llm.ai.tarnwick.example/echo?msg=sfab-m2-trace answers 200",
                "tlog-late": "FAIL  the firewall's traffic log has the session allowed by staff-to-users-gateway"}
        for fault, line in want.items():
            shutil.rmtree(self.t / "set", ignore_errors=True)
            r, verdict = self.judge(self.evidence((fault,)))
            self.assertEqual(r.returncode, 1, fault)
            self.assertIn(line, verdict, fault)

    def test_traffic_log_entry(self):
        sys.path.insert(0, str(TMD.parent))
        import importlib.util
        spec = importlib.util.spec_from_file_location("trace_md", TMD)
        tm = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tm)
        e = tm.tlog_find(TLOG, "10.24.10.10", 41443, "10.20.11.210", 443)
        self.assertEqual((e["from"], e["rule"], e["action"], e["to"]), ("enterprise", "staff-to-users-gate", "allow", "ingress"))
        self.assertIsNone(tm.tlog_find(TLOG, "10.24.10.10", 41444, "10.20.11.210", 443))
        pk = tm.packets(syn(1, 100, 63) + "\n")
        self.assertEqual((pk[0]["vlan"], pk[0]["ttl"], pk[0]["seq"], pk[0]["flags"], pk[0]["dport"]), (100, 63, 1234567890, "S", 443))


# ------------------------------------------------------------------------------------------------
# the scripts, against stand-ins, in a throwaway copy of dev/m2


@unittest.skipUnless(have_yaml(), "PyYAML renders dev/m2")
class M2LabTest(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-m2lab-"))
        self.scope = runscope.Scope(self)
        self.lab = self.t / "dev" / "m2"
        self.lab.mkdir(parents=True)
        shutil.copy(ROOT / "dev" / "m2" / "chapter.yaml", self.lab / "chapter.yaml")
        r = m2_render()
        for part in ("gen", "bootstrap"):
            shutil.copytree(r / part, self.lab / part)
        shutil.copy(r / "topo.clab.yml", self.lab / "topo.clab.yml")
        self.inv = json.loads((self.lab / "gen" / "inventory.json").read_text())
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS_M2}:{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab), "SHIM_STATE": str(self.state), "SHIM_LOG": str(self.log),
            "SHIM_NODES": M2_NODES, "SFAB_HOST_LOCK": str(self.t / "sfab.lock"), "SFAB_TICK_OVERRIDE": "1",
            "SHIM_INV": str(self.lab / "gen" / "inventory.json"), "SHIM_RENDER": str(self.lab),
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        self.env.pop("VARIANT", None)
        self.world()

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def world(self, running=True, drop=()):
        cs = {}
        for i, n in enumerate(self.inv["order"]):
            if n in drop:
                continue
            node = self.inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            if node.get("passthrough"):
                env.append("CLAB_MGMT_PASSTHROUGH=true")
            cmd = ["--username", "admin", "--password", "shimpw"] if node["kind"] in ("dell_sonic", "paloalto_panos") else []
            if node["kind"] == "truenas":
                # stand-in values: a made-up launcher password, never a real credential
                env += ["USERNAME=truenas_admin", "PASSWORD=Tt0123456789abcdefgh"]
            cs[node["container"]] = {"running": running, "started": f"2026-10-20T09:00:{i:02d}Z", "pid": 4000 + i,
                                     "health": "healthy", "env": env, "cmd": cmd}
        self.state.write_text(json.dumps({"containers": cs}))

    def containers(self):
        return json.loads(self.state.read_text())["containers"]

    def calls(self, tool):
        out = []
        for line in self.log.read_text().splitlines():
            if line.startswith("["):
                c = json.loads(line)
                if c[0] == tool:
                    out.append(c[1:])
        return out

    def run_cmd(self, argv, timeout=600, env=None):
        e = dict(self.env)
        e.update(env or {})
        return self.scope.run([str(x) for x in argv], env=e, capture_output=True, text=True, cwd=self.lab, timeout=timeout)

    def secrets(self):
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-m2"], check=True, capture_output=True)


class BootPiecesTest(M2LabTest):
    """Two of boot's steps, run as boot.sh defines them, with the harness helpers stubbed: the join
    token for the guests, and the storage bonds set aside in the fabric and bond waits."""

    @staticmethod
    def functions(*names) -> str:
        lines = (COMMON / "stages" / "boot.sh").read_text().splitlines()
        out = []
        for n in names:
            start = next(i for i, l in enumerate(lines) if l.startswith(f"{n}() {{"))
            if lines[start].rstrip().endswith("}"):
                out.append(lines[start])
                continue
            end = next(i for i in range(start, len(lines)) if lines[i] == "}")
            out.extend(lines[start:end + 1])
        return "\n".join(out) + "\n"

    def run_bash(self, body: str, env=None) -> subprocess.CompletedProcess:
        stubs = 'ok() { echo "PASS $*"; }; bad() { echo "FAIL $1 -> $2"; }; sec() { :; }; skip() { echo "SKIP $*"; }\n'
        return subprocess.run(["bash", "-c", "set -euo pipefail\n" + stubs + body], capture_output=True, text=True, timeout=60,
                              env={**self.env, **(env or {})})

    def test_join_token(self):
        self.secrets()
        st = self.lab / "state"
        body = self.functions("join_token") + "join_token\n"
        r = self.run_bash(body, {"STATEDIR": str(st)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS the lab's kubeadm join token in state/shared/cluster/kubeadm.env (0600, from state/secrets.env)", r.stdout)
        tok = next(l.split("=", 1)[1] for l in (st / "secrets.env").read_text().splitlines() if l.startswith("SFAB_KUBEADM_TOKEN="))
        f = st / "shared" / "cluster" / "kubeadm.env"
        self.assertEqual(f.read_text(), f"SFAB_KUBEADM_TOKEN={tok}\n")
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(tok, r.stdout + r.stderr, "the token is never printed")
        (st / "secrets.env").write_text("SFAB_KUBEADM_TOKEN=not-a-token\n")
        r = self.run_bash(body, {"STATEDIR": str(st)})
        self.assertIn("FAIL the kubeadm join token for the guests", r.stdout)

    def test_storage_bonds_set_aside(self):
        body = (self.functions("storage_except", "wait_fabric", "wait_bonds") +
                'pair_wait() { printf "%s|%s\\n" "$1" "$3"; }\n'
                'WAIT_FABRIC=mclag STAGE_GUEST_HOLD=1 RUNDIR=/nonexistent\n'
                'GUESTS=(k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2); STORAGE=(truenas1)\n'
                'wait_fabric; wait_bonds; STORAGE=(); wait_bonds\n')
        r = self.run_bash(body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        fabric, bonds, no_storage = r.stdout.splitlines()
        self.assertTrue(fabric.endswith("|k8s-cp1,k8s-cp2,k8s-cp3,k8s-gpu1,k8s-gpu2,truenas1"), fabric)
        self.assertIn("the storage bonds set aside until finish's storage setup", fabric)
        self.assertTrue(bonds.endswith("the guest bonds included, the storage bonds set aside until finish's storage setup|truenas1"), bonds)
        self.assertTrue(no_storage.endswith("the guest bonds included|"), no_storage)

    def test_dns_zones_loaded_or_retransferred(self):
        """dns_zones: a loaded secondary zone passes as it is; one BIND left unloaded behind its backed-off
        retries (ch04's second revision 2 attempt: dns-auth2's internal forward zone, many minutes after
        the firewall was up) is told to transfer at once, then passes; one that never loads fails.
        Every zone is read in each round, so a primary BIND caches as unreachable holds no zone up
        behind another (ch06's first clean-clone attempt)."""
        run = self.t / "dnsz"
        (run / "bootstrap" / "dns-auth2").mkdir(parents=True)
        (run / "bootstrap" / "dns-auth2" / "named.conf").write_text(
            'view "internal" {\n'
            '    zone "ai.tarnwick.example" { type secondary; primaries { 10.20.13.11; }; file "s/a"; };\n'
            '    zone "1.20.10.in-addr.arpa" { type secondary; primaries { 10.20.13.11; }; file "s/b"; };\n'
            '};\n'
            'view "enterprise" {\n'
            '    zone "ai.tarnwick.example" { type secondary; primaries { 10.20.13.11; }; file "s/c"; };\n'
            '};\n')
        (run / "bootstrap" / "dns-auth1").mkdir()
        (run / "bootstrap" / "dns-auth1" / "named.conf").write_text('view "internal" {\n    zone "ai.tarnwick.example" { type primary; file "p"; };\n};\n')
        stubs = (
            'sleep() { :; }\n'
            'declare -A NODE_KIND=([dns-auth1]=resolver [dns-auth2]=resolver)\n'
            'X() { local n="$1"; shift; echo "$n $*" >>"$RUNDIR/x.log"\n'
            '  case "$*" in\n'
            '    *"retransfer ai.tarnwick.example IN internal"*) touch "$RUNDIR/xfr" ;;\n'
            '    *"zonestatus ai.tarnwick.example IN internal"*) [ -e "$RUNDIR/xfr" ] && echo "serial: 7" || echo "rndc: zone not loaded" ;;\n'
            '    *"zonestatus 1.20.10.in-addr.arpa IN internal"*) [ -n "${NEVER:-}" ] && echo "rndc: zone not loaded" || echo "serial: 5" ;;\n'
            '    *zonestatus*) echo "serial: 9" ;;\n'
            '  esac; }\n')
        body = self.functions("secondary_zones", "dns_zones") + stubs + "dns_zones\n"
        r = self.run_bash(body, {"RUNDIR": str(run), "RENDERDIR": str(run)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS dns-auth2: view internal's secondary zone ai.tarnwick.example loaded at serial 7 (by rndc retransfer)", r.stdout)
        self.assertIn("PASS dns-auth2: view internal's secondary zone 1.20.10.in-addr.arpa loaded at serial 5 (by transfer)", r.stdout)
        self.assertIn("PASS dns-auth2: view enterprise's secondary zone ai.tarnwick.example loaded at serial 9 (by transfer)", r.stdout)
        log = (run / "x.log").read_text()
        self.assertNotIn("dns-auth1", log, "a primary is not asked")
        self.assertEqual(log.count("retransfer"), 1, log)
        r = self.run_bash(body + "", {"RUNDIR": str(run), "RENDERDIR": str(run), "NEVER": "1"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL dns-auth2: view internal's secondary zone 1.20.10.in-addr.arpa loaded -> not loaded after 900 s, rndc retransfer sent", r.stdout)

    def test_iccp_listener_put_in_its_vrf(self):
        """iccp_listen: a listener in the session VRF passes; one left in the default VRF is put right
        by one restart of iccpd on that switch (ch01's first deployment: both pair members)."""
        run = self.t / "iccp"
        run.mkdir()
        # The listener as SONiC 4.6.0's ss prints it: unbound until iccpd restarts on that switch.
        stubs = (
            'inv() { [ "$1" = get ] && echo mgmt; }\n'
            'SH() { local sw="$1"; shift; echo "$sw $*" >>"$RUNDIR/sh.log"\n'
            '  case "$*" in\n'
            '    *"restart iccpd"*) touch "$RUNDIR/restarted-$sw" ;;\n'
            '    *"ss -tanp"*) if [ "$sw" = fe-sw1 ] || [ -e "$RUNDIR/restarted-$sw" ]; then a="0.0.0.0%mgmt"; else a="0.0.0.0"; fi\n'
            '      echo "LISTEN    0      20      $a:8888       0.0.0.0:*     users:((\\"iccpd\\",pid=22058,fd=17))"\n'
            '      echo "ESTAB     0      0       172.21.40.12%mgmt:8888  172.21.40.11:34443 users:((\\"iccpd\\",pid=22058,fd=24))" ;;\n'
            '  esac; }\n'
            'PAIRS=(fe); declare -A PAIR_MEMBERS=([fe]="fe-sw1 fe-sw2"); TO_ICCP_POLL_S=0\n')
        r = self.run_bash(self.functions("iccp_vrf", "iccp_listen") + stubs + "iccp_listen\n", {"RUNDIR": str(run)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("PASS fe-sw1: iccpd listens on TCP 8888 in VRF mgmt\n", r.stdout)
        self.assertIn("boot: fe-sw2: iccpd's listener is in VRF default, not mgmt; restarting iccpd", r.stdout)
        self.assertIn("PASS fe-sw2: iccpd listens on TCP 8888 in VRF mgmt (iccpd restarted: its listener was in VRF default)", r.stdout)
        log = (run / "sh.log").read_text()
        self.assertNotIn("fe-sw1 sudo systemctl restart iccpd", log, "a listener in its VRF is left alone")
        self.assertEqual(log.count("fe-sw2 sudo systemctl restart iccpd"), 1)
        self.assertEqual((run / "iccp-listen.tsv").read_text(), "fe-sw1\tmgmt\nfe-sw2\tdefault\nfe-sw2\tmgmt\trestarted\n")
        # a listener the restart does not move fails, and so does no listener at all
        for f in run.iterdir():
            f.unlink()
        r = self.run_bash(self.functions("iccp_vrf", "iccp_listen") + stubs.replace('touch "$RUNDIR/restarted-$sw"', ':') +
                          'TO_ICCP_POLLS=2; iccp_listen\n', {"RUNDIR": str(run)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL fe-sw2: iccpd listens on TCP 8888 in VRF mgmt -> after a restart of iccpd: default", r.stdout)
        r = self.run_bash(self.functions("iccp_vrf", "iccp_listen") + 'inv() { echo mgmt; }; SH() { :; }\n'
                          'PAIRS=(fe); declare -A PAIR_MEMBERS=([fe]="fe-sw1 fe-sw2"); TO_ICCP_POLL_S=0 TO_ICCP_POLLS=2\niccp_listen\n',
                          {"RUNDIR": str(run)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FAIL fe-sw1: iccpd listens on TCP 8888 in VRF mgmt -> no listener", r.stdout)


class PreflightRegistryTest(M2LabTest):
    """pf_registry: the registry's bind source must hold a seed before containerlab binds it."""

    def pf(self, root: Path, inv: Path) -> str:
        script = ('ok() { echo "PASS $*"; }; bad() { echo "FAIL $1 -> $2"; }; '
                  'inv() { python3 "$SFAB_COMMON/bin/inv.py" --inv "$INV" "$@"; }; '
                  'SFAB_PF_LIB=1 . "$SFAB_COMMON/stages/preflight.sh"; pf_registry')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                           env={**self.env, "SFAB_ROOT": str(root), "SFAB_COMMON": str(COMMON), "INV": str(inv)})
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_registry_data(self):
        inv = self.lab / "gen" / "inventory.json"
        root = self.t / "root"
        data = root / "images" / "registry" / "data"
        self.assertIn("FAIL registry data seeded -> no images/registry/data", self.pf(root, inv))
        data.mkdir(parents=True)
        self.assertIn("holds no SEED.json", self.pf(root, inv))
        (data / "SEED.json").write_text("{}\n")
        self.assertIn("PASS registry data seeded: images/registry/data holds SEED.json", self.pf(root, inv))
        # a lab without the registry says nothing
        self.assertEqual(self.pf(root, ROOT / "dev" / "m1" / "gen" / "inventory.json"), "")


class MemWatchdogTest(M2LabTest):
    WD = COMMON / "host" / "mem-watchdog.sh"

    def meminfo(self, kib):
        f = self.t / "meminfo"
        f.write_text(f"MemTotal:       394000000 kB\nMemFree:          1000000 kB\nMemAvailable:   {kib} kB\n")
        return {"SFAB_MEMINFO": str(f)}

    def test_below_the_floor_stops_one_guest_per_poll_in_order(self):
        low = self.meminfo(8 * 1024 * 1024)
        r = self.run_cmd([self.WD, "sfab-m2", "--once"], env=low)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("watching: floor 16.0 GiB, victims in order: k8s-gpu2 k8s-gpu1 k8s-ingress2 k8s-ingress1 k8s-cp3 k8s-cp2 k8s-cp1", r.stdout)
        self.assertIn("stopping sfab-m2-k8s-gpu2", r.stdout)
        self.assertFalse(self.containers()["sfab-m2-k8s-gpu2"]["running"])
        self.assertTrue(self.containers()["sfab-m2-k8s-gpu1"]["running"])
        self.assertIn(["update", "--restart=no", "sfab-m2-k8s-gpu2"], self.calls("docker"))
        self.assertIn(["stop", "-t", "3", "sfab-m2-k8s-gpu2"], self.calls("docker"))
        r = self.run_cmd([self.WD, "sfab-m2", "--once"], env=low)
        self.assertIn("stopping sfab-m2-k8s-gpu1", r.stdout)
        log = (self.lab / "state" / "logs" / "memwatch.log").read_text()
        self.assertIn("stopped sfab-m2-k8s-gpu2", log)
        self.assertIn("stopped sfab-m2-k8s-gpu1", log)
        for c in self.calls("docker"):
            if c[0] in ("stop", "update", "rm", "kill"):
                self.assertTrue(all(a.startswith("sfab-m2-") for a in c[1:] if not a.startswith("-") and not a.isdigit()), c)
        stopped = [c[-1] for c in self.calls("docker") if c[0] == "stop"]
        self.assertTrue(all(x[len("sfab-m2-"):] in ("k8s-gpu1", "k8s-gpu2", "k8s-ingress1", "k8s-ingress2", "k8s-cp1", "k8s-cp2", "k8s-cp3") for x in stopped), stopped)

    def test_dry_run_and_above_the_floor(self):
        r = self.run_cmd([self.WD, "sfab-m2", "--once", "--dry-run"], env=self.meminfo(1024 * 1024))
        self.assertIn("would stop sfab-m2-k8s-gpu2 (dry run)", r.stdout)
        r = self.run_cmd([self.WD, "sfab-m2", "--once"], env=self.meminfo(200 * 1024 * 1024))
        self.assertNotIn("stopping", r.stdout)
        self.assertEqual([c for c in self.calls("docker") if c[0] == "stop"], [])
        self.assertTrue(all(c["running"] for c in self.containers().values()))

    def test_refuses_another_lab_and_exits_when_the_lab_is_gone(self):
        r = self.run_cmd([self.WD, "sfab-m1", "--once"], env=self.meminfo(1024 * 1024))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing", r.stderr)
        self.state.write_text(json.dumps({"containers": {"other-lab-x": {"running": True}}}))
        r = self.run_cmd([self.WD, "sfab-m2"], env=dict(self.meminfo(200 * 1024 * 1024), SFAB_MEMWATCH_POLL_S="0",
                                                       SFAB_MEMWATCH_GRACE_S="0"), timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no container of sfab-m2 appeared within 0s of the start: watchdog off", r.stdout)
        # seen, then gone: a stand-in docker whose ps lists the lab only on its first call
        fake = self.t / "fakebin"
        fake.mkdir()
        (fake / "docker").write_text('#!/usr/bin/env bash\nf="$SHIM_STATE.ps"\nif [ "$1" = ps ] && [ ! -f "$f" ]; then : >"$f"; echo sfab-m2-k8s-gpu1; exit 0; fi\n'
                                     f'if [ "$1" = ps ]; then exit 0; fi\nexec "{SHIMS_M2 / "docker"}" "$@"\n')
        (fake / "docker").chmod(0o755)
        r = self.run_cmd([self.WD, "sfab-m2"], env=dict(self.meminfo(200 * 1024 * 1024), SFAB_MEMWATCH_POLL_S="0",
                                                       PATH=f"{fake}:{self.env['PATH']}"), timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no container of sfab-m2 for three polls: the lab is down, watchdog off", r.stdout)

    def test_nothing_left_to_stop(self):
        self.world(running=False)
        r = self.run_cmd([self.WD, "sfab-m2", "--once"], env=self.meminfo(1024 * 1024))
        self.assertIn("no guest of sfab-m2 is left running to stop", r.stdout)


class NodeSyncTest(M2LabTest):
    NS = COMMON / "host" / "node-sync.sh"

    def setUp(self):
        super().setUp()
        self.secrets()
        self.fs = self.t / "guest-fs"
        self.fs.mkdir()
        self.env["SHIM_GUEST_FS"] = str(self.fs)

    def test_install_then_in_sync_then_drift(self):
        r = self.run_cmd([self.NS])
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("k8s-cp1 UPDATED /etc/sfab/node.env", r.stdout)
        self.assertIn("k8s-cp1 BOOTSTRAP-CHANGED", r.stdout)
        self.assertIn("k8s-gpu2 APPLIED netsetup.sh run again", r.stdout)
        fs = json.loads((self.fs / "k8s-gpu1.json").read_text())
        self.assertEqual(fs["/etc/sfab/node.env"]["content"], (self.lab / "bootstrap" / "k8s-gpu1" / "node.env").read_text())
        self.assertIn("/opt/sfab/bin/netsetup.sh", fs["_applied"])
        r = self.run_cmd([self.NS])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("node-sync: 7/7 guests match the render", r.stdout)
        self.assertRegex(r.stdout, r"k8s-cp2 IN-SYNC \(\d+ files\)")
        # a render change on a running lab: --check reports it, the run installs it and applies it live
        envf = self.lab / "bootstrap" / "k8s-gpu1" / "node.env"
        envf.write_text(envf.read_text() + "NIC_SPEED=25000\n")
        r = self.run_cmd([self.NS, "--check"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("k8s-gpu1 DRIFT /etc/sfab/node.env", r.stdout)
        self.assertNotIn("UPDATED", r.stdout)
        r = self.run_cmd([self.NS, "k8s-gpu1"])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("k8s-gpu1 UPDATED /etc/sfab/node.env", r.stdout)
        self.assertIn("k8s-gpu1 APPLIED netsetup.sh run again", r.stdout)
        self.assertNotIn("BOOTSTRAP-CHANGED", r.stdout, "no K8S_ line changed")

    def test_a_guest_that_does_not_answer(self):
        r = self.run_cmd([self.NS, "k8s-cp3", "k8s-gpu1"], env={"SHIM_SSH_DOWN": "k8s-cp3"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("k8s-cp3 UNREACHABLE", r.stdout)
        self.assertIn("k8s-gpu1 UPDATED /etc/sfab/node.env", r.stdout, "the other guest is still synced")
        self.assertIn("node-sync: 1 problem(s) on 2 guest(s)", r.stdout)

    def test_refuses_a_node_that_is_not_a_guest(self):
        r = self.run_cmd([self.NS, "bastion"])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("bastion is not a VM guest of sfab-m2", r.stderr)



def set_timeouts(lab: Path, **kw):
    """Shorter waits for the tests, written into the lab copy's inventory."""
    f = lab / "gen" / "inventory.json"
    inv = json.loads(f.read_text())
    inv["timeouts"].update(kw)
    f.write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n")


class FinishTest(M2LabTest):
    def setUp(self):
        super().setUp()
        self.secrets()
        set_timeouts(self.lab, events_quiet_s=10, fabric_poll_s=1, cluster_poll_s=1)
        # the lab's CA on the lab host, as up makes it before deploy (sfab-ca init)
        subprocess.run([str(COMMON / "ca" / "sfab-ca"), "-C", str(self.lab), "init"], check=True, capture_output=True, timeout=120)
        stub = self.t / "truenas-setup-stub.py"
        stub.write_text("import sys\nprint('truenas-setup stand-in:', ' '.join(sys.argv[1:]))\n")
        self.env["SFAB_TRUENAS_SETUP"] = str(stub)
        fw = self.lab / "bootstrap" / "fw"
        self.env.update({"SHIM_FW_XML": str(fw / "startup-config.xml"), "SHIM_FW_ENFORCED": str(fw / "enforced.txt")})

    def test_finish_with_the_cluster_on(self):
        r = self.run_cmd([COMMON / "stages" / "finish.sh"], timeout=900)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out[-5000:])
        self.assertNotIn("  FAIL  ", r.stdout)
        for line in ("  PASS  k8s-cp1: sfab-cluster.service finished in this boot with status 0 (poll 1, 0 restarts)",
                     "  PASS  all 7 nodes Ready: k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2 k8s-ingress1 k8s-ingress2 (poll 1)",
                     "  PASS  kubeadm's keys retracted: no private key left under state/shared/ (sfab-ca retract)",
                     "  PASS  Cilium devices are the spec's: bond0",
                     "  PASS  every Cilium agent started after cilium-config last changed",
                     "  PASS  9 manifests applied on k8s-cp1 (server-side)",
                     "  PASS  1 CA key pair(s) written as Secrets from the lab host (sfab-ca k8s-secret, through a pipe to kubectl on k8s-cp1)",
                     "  PASS  1 operator kubeconfig(s) issued on k8s-cp1 for 8 h in group operators (state/operators/<user>/kubeconfig, 0600; the bastion installs each for its user)",
                     "  PASS  1 charts (k8s) installed from the in-lab registry",
                     "  PASS  no manifest waited for a chart",
                     "  PASS  truenas1: truenas-setup.py all",
                     "  PASS  2 charts (storage) installed from the in-lab registry",
                     "  PASS  rails: clean rounds between k8s-gpu1 and k8s-gpu2",
                     "  PASS  Warning events archived, cleared and held at 0 for 10s (round 1)"):
            self.assertIn(line, r.stdout)
        self.assertRegex(r.stdout, r"  PASS  pair: every PortChannel up with every member, the storage bonds included \(2 consecutive polls, poll 2\)")
        self.assertRegex(r.stdout, r"  PASS  frontend: 3 clean rounds \(round 3, 0 nodes bounced; nodes, storage, 1 Gateway VIP on TCP 443, the populations' clients\)")
        # the harness's kubectl and helm run on the init node over SSH with kubeadm's admin kubeconfig
        cp1 = self.inv["nodes"]["k8s-cp1"]["mgmt"]
        k = [c[-1] for c in self.calls("ssh-m2") if any(a.endswith("@" + cp1) for a in c) and c[-1].startswith("sudo env KUBECONFIG=")]
        applied = [x for x in k if " kubectl apply --server-side " in x and "/tmp/sfab-k8s/" in x]
        self.assertTrue(applied[0].endswith("/tmp/sfab-k8s/05-namespaces.yaml "), applied[:1])
        self.assertEqual(len(applied), 9)
        helm = [x for x in k if "helm\\ upgrade\\ --install" in x or "helm upgrade --install" in x]
        self.assertEqual(len(helm), 3, k)
        self.assertTrue(all("--ca-file" in h and "--plain-http" not in h for h in helm), helm)
        self.assertFalse([c for c in self.calls("docker-m2") if c[:2] == ["exec", "sfab-m2-bastion"]],
                         "nothing in finish runs in the bastion: it is a jump host only")
        # the operator's kubeconfig, 0600 on the lab host, for the bastion to pick up
        kc = self.lab / "state" / "operators" / "admin" / "kubeconfig"
        self.assertEqual(kc.stat().st_mode & 0o777, 0o600)
        self.assertIn("kind: Config", kc.read_text())
        self.assertLess(r.stdout.index("== kubeadm keys"), r.stdout.index("== Cilium devices and agents"))
        # every docker call stays inside the lab
        for c in self.calls("docker") + self.calls("docker-m2"):
            if c[0] == "exec":
                names = [next(a for a in c[1:] if not a.startswith("-"))]
            elif c[0] == "cp":
                names = [a.split(":")[0] for a in c[1:] if ":" in a]
            elif c[0] in ("rm", "stop", "update"):
                names = [a for a in c[1:] if not a.startswith("-") and not a.isdigit()]
            else:
                continue
            self.assertTrue(names and all(n.startswith("sfab-m2-") for n in names), c)
        # a second run acts on nothing
        r = self.run_cmd([COMMON / "stages" / "finish.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        for step in ("cluster", "ready", "retract", "cilium", "apply", "ca-secrets", "charts", "apply-late", "storage", "settle", "events"):
            self.assertIn(f"marker  finish.{step} matches; nothing to do", r.stdout)

    def test_a_key_left_under_shared_stops_finish(self):
        pki = self.lab / "state" / "shared" / "cluster" / "pki"
        pki.mkdir(parents=True)
        # stand-in values: a key file's shape with no key material in it
        (pki / "sa.key").write_text("-----BEGIN PRIVATE KEY-----\nstand-in\n-----END PRIVATE KEY-----\n")
        # sfab-ca retract removes kubeadm's keys; a key anywhere else under state/shared/ stops finish
        (self.lab / "state" / "shared" / "stray.pem").write_text("-----BEGIN PRIVATE KEY-----\nstand-in\n-----END PRIVATE KEY-----\n")
        r = self.run_cmd([COMMON / "stages" / "finish.sh"], timeout=300)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse((pki / "sa.key").exists(), "sfab-ca retract removed kubeadm's key")
        self.assertIn("  FAIL  kubeadm's keys retracted from state/shared/ -> still there: shared/stray.pem", r.stdout)
        self.assertNotIn("== Cilium devices and agents", r.stdout)

    def test_a_bootstrap_that_failed_for_good_stops_at_once(self):
        r = self.run_cmd([COMMON / "stages" / "finish.sh"], timeout=300, env={"SHIM_M2_FAULT": "cluster-failed"})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("  FAIL  k8s-cp1: sfab-cluster.service finished in this boot -> the unit failed for good: cluster-bootstrap: done", r.stdout)
        self.assertNotIn("== nodes Ready", r.stdout)

    def test_storage_setup_failure_stops_finish(self):
        bad = self.t / "truenas-setup-fails.py"
        bad.write_text("import sys\nprint('truenas-setup: the API did not answer')\nsys.exit(1)\n")
        r = self.run_cmd([COMMON / "stages" / "finish.sh"], timeout=900, env={"SFAB_TRUENAS_SETUP": str(bad)})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("  FAIL  truenas1: truenas-setup.py all -> truenas-setup: the API did not answer", r.stdout)
        self.assertNotIn("charts (storage) installed", r.stdout)
        self.assertNotIn("== settle", r.stdout)


class M2AuditTest(M2LabTest):
    """The M2 audit end to end: collection through every new surface, then every judge."""

    def setUp(self):
        super().setUp()
        os.symlink(COMMON, self.t / "common")
        os.symlink(ROOT / "spec", self.t / "spec")
        shutil.copy(ROOT / "dev" / "m2" / "audit.sh", self.lab / "audit.sh")
        self.secrets()
        fw = self.lab / "bootstrap" / "fw"
        self.env.update({"SHIM_FW_XML": str(fw / "startup-config.xml"), "SHIM_FW_ENFORCED": str(fw / "enforced.txt"),
                         "SFAB_AUDIT_CLEAN": "0", "SFAB_VOLUME_POLL_S": "0"})
        (self.lab / "state" / "preflight.last").write_text("# preflight 2026-10-20T09:00:00Z\n== preflight\n  PASS  host tick 10000\n")

    def audit(self, *args, env=None):
        return self.run_cmd([self.lab / "audit.sh", *args], timeout=1200, env=env)

    def test_m2_audit_green(self):
        r = self.audit()
        fails = [l for l in r.stdout.splitlines() if l.startswith("  FAIL  ")]
        self.assertEqual(fails, [], r.stdout[-6000:] + r.stderr[-3000:])
        self.assertEqual(r.returncode, 0)
        rs = sorted((self.lab / "audits").glob("sfab-m2_audit_*"))[-1]
        verdict = (rs / "verdict.txt").read_text()
        for sec in ("== bastion: bastion, the jump host", "== dns-auth1: dns-auth", "== dns-auth2: dns-auth", "== dns-res1: dns-res",
                    "== dns-res2: dns-res", "== ent-dns: dns-corporate", "== inet-ntp: inet-ntp", "== uplink-rtr: router", "== inet-registry: registry", "== ent-client: client",
                    "== ops-client: client", "== truenas1: storage", "== k8s-cp1: cluster node", "== k8s-gpu2: cluster node", "== cluster",
                    "== population operator", "== population nodes", "== population enterprise", "== storage: a volume on each class",
                    "== pair fe-sw1 fe-sw2", "== fw: firewall", "== k8s-cp3: guest"):
            self.assertIn(sec, verdict)
        self.assertIn("  PASS  truenas-nvmeof: the claim binds; a pod on k8s-gpu1 writes 1 MiB and a second pod reads back the same sha256", verdict)
        self.assertIn("  PASS  truenas-nvmeof: with the claim bound, TrueNAS's data address 10.20.12.31 answers on NVMe/TCP 4420 "
                      "from every node in its VLAN (2 of 2)", verdict)
        self.assertIn("  PASS  truenas-nvmeof: no node outside the storage data VLAN reaches 10.20.12.31:4420 (5 tried)", verdict)
        self.assertNotIn("truenas-nfs: with the claim bound", verdict)
        self.assertIn("  PASS  fw answers ARP on 198.51.100.2 (eth1)", verdict)
        self.assertNotIn("fw answers ping", verdict)
        self.assertIn("  PASS  fe-sw1: PortChannel31 up with Ethernet9,Ethernet10", verdict)
        # revision 2: the keepalive on its own link and VRF, its backup, the forwarding-only reads around
        # exactly the keepalive addresses, and the Layer 2 hygiene of the pair and the rail switches
        for line in ("  PASS  fe-sw1: keepalive in VRF VrfMclagKa",
                     "  PASS  fe-sw2: keepalive source is its address on the keepalive link Ethernet12, 10.20.255.1",
                     "  PASS  fe-sw1: backup keepalive session up on Vlan3966, 10.20.255.4 to 10.20.255.5 in VRF VrfMclagKa",
                     "  PASS  show ip interfaces lists only Management0 and the keepalive addresses (Ethernet12,Management0,Vlan3966)",
                     "  PASS  VRF VrfMclagKa holds only its connected keepalive /31s",
                     "  PASS  no address on any served VLAN's interface Vlan block (only Vlan3966, the backup keepalive)",
                     "  PASS  spanning-tree mode pvst",
                     "  PASS  every used port (19) at its rendered MTU (9216)",
                     "  PASS  BPDU guard with port-shutdown on every edge port (14)",
                     "  PASS  BPDU guard on no other port (the peer link and the firewall's trunk are not edge ports)",
                     "  PASS  storm control on every member and access port (8): broadcast 10000 kbps, unknown-multicast 10000 kbps, unknown-unicast 10000 kbps"):
            self.assertIn(line, verdict)
        for sec in ("== fe-sw1: Layer 2 hygiene", "== rail-sw2: Layer 2 hygiene"):
            self.assertIn(sec, verdict)
        # the one SKIP a host whose tick is not 10000 prints under SFAB_TICK_OVERRIDE (preflight, read again)
        self.assertRegex((rs / "RESULT.txt").read_text(), r"== RESULT: \d+ passed, 0 failed, 0 known platform limitation\(s\), [01] skipped")
        self.assertEqual([l for l in verdict.splitlines() if l.startswith("  SKIP  ") and "host tick" not in l], [])
        for node in ("bastion", "uplink-rtr", "truenas1"):
            self.assertTrue(list((rs / node).glob("[0-9][0-9]_*")), f"{node}: no saved command")
        self.assertTrue((rs / "storage-volumes" / "truenas-nfs-read.txt").is_file())
        self.assertEqual(sorted(p.name for p in rs.rglob("*ALL*OUTPUT*")), [], "each output is saved once")
        cmds = (rs / "commands.txt").read_text()
        self.assertRegex(cmds, r"(?m)^### \S+ k8s-cp1 kubectl$")
        self.assertRegex(cmds, r"(?m)^### \S+ uplink-rtr frr$")
        self.assertRegex(cmds, r"(?m)^### \S+ inet-registry container$")
        login = (rs / "truenas1" / [p.name for p in (rs / "truenas1").iterdir() if "launcher_login" in p.name][0]).read_text()
        self.assertIn("password: present", login)
        # the keyed mark redact.py leaves, under the lab's key: nobody without the key can test a guess
        import redact  # noqa: PLC0415
        key = redact.read_key(str(self.lab / "state" / "secrets" / "redact.key"))
        self.assertIsNotNone(key)
        self.assertIn("password: present, from the container env (PASSWORD), " + redact.mark("Tt0123456789abcdefgh", key), login)
        self.assertNotIn("sha256", login)
        secrets = [l.split("=", 1)[1] for l in (self.lab / "state" / "secrets.env").read_text().splitlines() if "=" in l and "PASSWORD" in l]
        for p in rs.rglob("*"):
            if p.is_file():
                data = p.read_bytes()
                for v in secrets + ["shimpw", "Tt0123456789abcdefgh"]:
                    self.assertNotIn(v.encode(), data, f"{p}: a credential leaked")

    def test_m2_audit_red(self):
        r = self.audit(env={"SHIM_M2_FAULT": "admin-404-not-envoy"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("  FAIL  ent-client: https://admin.ai.tarnwick.example/echo: 404 from gw-users (the Gateway has no route for the name) (pinned to 10.20.11.210: the enterprise view publishes no admin name) -> HTTP 404, server nginx", r.stdout)

    def test_m2_audit_nvme_refused_from_one_node(self):
        r = self.audit(env={"SHIM_M2_FAULT": "nvme-closed"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("  FAIL  truenas-nvmeof: with the claim bound, TrueNAS's data address 10.20.12.31 answers on NVMe/TCP 4420 "
                      "from every node in its VLAN -> refused from k8s-gpu2 (1 of 2)", r.stdout)

    def test_m2_audit_keeps_the_pulls_behind_the_healthcheck(self):
        # an hour of the registry's own healthcheck after the pulls: the lines kept are the pulls,
        # not the healthcheck (chapter 3's first deploy failed this line an hour after its deploy)
        r = self.audit(env={"SHIM_M2_FAULT": "healthcheck-flood"})
        self.assertIn("  PASS  its access log shows pulls from 198.51.100.2", r.stdout, r.stdout[-4000:])
        rs = sorted((self.lab / "audits").glob("sfab-m2_audit_*"))[-1]
        log = (rs / "inet-registry" / [p.name for p in (rs / "inet-registry").iterdir() if "access_log" in p.name][0]).read_text()
        self.assertIn("198.51.100.2", log)
        self.assertNotIn("127.0.0.1", log)

    def test_quick_audit_reads_the_switches_and_the_firewall_only(self):
        r = self.audit("--quick")
        self.assertEqual(r.returncode, 0, r.stdout[-4000:])
        self.assertNotIn("== bastion: bastion", r.stdout)
        self.assertNotIn("== cluster", r.stdout)
        self.assertIn("== pair fe-sw1 fe-sw2", r.stdout)
        # the storage appliance's container links too: fe-sw2 learns its management MAC over the peer link
        self.assertIn("  PASS  collect truenas1: 1 of 1 commands saved", r.stdout)
        self.assertNotIn("== truenas1: storage", r.stdout)
        self.assertEqual(sorted((self.lab / "audits").glob("sfab-m2_audit_*")), [], "a quick audit records nothing")



class TraceShTest(M2LabTest):
    """dev/m2/trace.sh end to end: the lease holder, the captures (host and guest), the client's
    attempts, the firewall's log and the judgment, against stand-ins."""

    def setUp(self):
        super().setUp()
        os.symlink(COMMON, self.t / "common")
        shutil.copy(ROOT / "dev" / "m2" / "trace.sh", self.lab / "trace.sh")
        shutil.copy(ROOT / "dev" / "m2" / "trace-md.py", self.lab / "trace-md.py")
        self.secrets()
        self.env.update({"SHIM_TRACE_HOLDER": "k8s-ingress1", "SFAB_TRACE_SETTLE_S": "0", "SFAB_TRACE_TAIL_S": "0",
                         "SFAB_TRACE_GAP_S": "0", "SFAB_TRACE_TLOG_PAUSE_S": "0"})

    def test_trace_green(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-3000:])
        rs = sorted((self.lab / "audits").glob("sfab-m2_trace_*"))[-1]
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("FAIL", verdict, verdict)
        for line in ("  PASS  the gw-users Service's L2 announcement lease holder is an ingress node (k8s-ingress1)",
                     "  PASS  9 capture points decoded (9 with a decode)",
                     "  PASS  6-k8s-ingress1-bond0: the recorded SYN seen (seq 1234567890)",
                     "  PASS  the SYN leaves the pair on the switch that received it (fe-sw1)",
                     "  PASS  the firewall's traffic log has the session allowed by staff-to-users-gateway (shown as staff-to-users-gate), zone enterprise to zone ingress"):
            self.assertIn(line, verdict)
        for f in ("TRACE.md", "RESULT.txt", "points.tsv", "captures/6-k8s-ingress1-bond0.pcap", "captures/5-fe-sw1-Ethernet13.txt",
                  "fw-traffic-log.txt", "request.txt"):
            self.assertTrue((rs / f).is_file(), f)
        self.assertIn("== RESULT: ", (rs / "TRACE.md").read_text())
        cmds = (rs / "commands.txt").read_text()
        self.assertIn("nsenter -t", cmds)
        self.assertIn("--local-port 41443", cmds)
        # no capture is left running
        left = self.scope.left("_trace.py")
        self.assertEqual(left, [])


if __name__ == "__main__":
    unittest.main()
