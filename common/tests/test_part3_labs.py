"""Part III's lab harness (ch08 to ch11): the audit groups (audiences, split-horizon, zone-nat,
isolation), the traces (chapter 8's keyed trace from a node of the cluster, the split-horizon trace,
the zone-keyed NAT trace, the capture ladder), chapter 10's held-connection measurement, the drills
(the lease-holder loss, the isolation drill under load), the matrix's own-caller cells and breaks 8a
to 11a. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_part3_labs*.py'

Hermetic: each lab is rendered into a temporary directory (PyYAML) and every device is a stand-in
(common/tests/shims/, shims-ch07/ and shims-part3/; the facts the stand-ins need are written from the
lab's model by common/tests/p3_world.py). The stand-in world is a simple deterministic model, so the
figures asserted here are the model's, never a lab's. Made-up names and keys only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
HERE = Path(__file__).resolve().parent
SHIMS, SHIMS_CH07, SHIMS_P3 = HERE / "shims", HERE / "shims-ch07", HERE / "shims-part3"
sys.path.insert(0, str(HERE))

NODES_BASE = ("fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw fw k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2 k8s-ingress1 k8s-ingress2 bastion "
              "uplink-rtr ops-client ops-dns ops-gw inet-registry ent-client ent-dns")
KEYS = ("5" * 32, "6" * 32, "8" * 32, "9" * 32)


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


def load(p):
    return json.loads(Path(p).read_text())


_RENDERS: dict = {}


def rendered(lab: str) -> Path:
    if lab not in _RENDERS:
        out = Path(tempfile.mkdtemp(prefix=f"sfab-test-{lab}-"))
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(ROOT / lab), "--out", str(out), "-q"], check=True, capture_output=True)
        import p3_world  # noqa: PLC0415

        p3_world.write(ROOT / lab, out / "p3-facts.json")
        _RENDERS[lab] = out
    return _RENDERS[lab]


def tearDownModule():
    for p in _RENDERS.values():
        shutil.rmtree(p, ignore_errors=True)


class P3LabTest(unittest.TestCase):
    LAB = "ch08"
    SCRIPTS = ("chapter.yaml", "audit.sh", "trace.sh")

    def setUp(self):
        if not have_yaml():
            self.skipTest("PyYAML is needed to render the lab")
        self.t = Path(tempfile.mkdtemp(prefix=f"sfab-test-{self.LAB}lab-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        self.lab = self.t / self.LAB
        self.lab.mkdir()
        r = rendered(self.LAB)
        for part in ("gen", "bootstrap"):
            shutil.copytree(r / part, self.lab / part)
        shutil.copy(r / "topo.clab.yml", self.lab / "topo.clab.yml")
        for f in os.listdir(ROOT / self.LAB):
            if f.endswith(".sh") or f == "chapter.yaml":
                shutil.copy(ROOT / self.LAB / f, self.lab / f)
        if (ROOT / self.LAB / "breaks").is_dir():
            shutil.copytree(ROOT / self.LAB / "breaks", self.lab / "breaks")
        for d in ("common", "spec", "serving-layer"):
            os.symlink(ROOT / d, self.t / d)
        self.inv = load(self.lab / "gen" / "inventory.json")
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS_P3}:{SHIMS_CH07}:{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab), "SHIM_STATE": str(self.state), "SHIM_LOG": str(self.log), "SHIM_NODES": " ".join(self.inv["order"]),
            "SFAB_HOST_LOCK": str(self.t / "sfab.lock"), "SFAB_TICK_OVERRIDE": "1", "SHIM_INV": str(self.lab / "gen" / "inventory.json"),
            "SHIM_RENDER": str(self.lab), "SHIM_CH06_STATE": str(self.t / "world.json"), "PYTHONDONTWRITEBYTECODE": "1",
            "SHIM_P3_FACTS": str(r / "p3-facts.json"),
            "SFAB_DRILL_AUDIT": "0", "SFAB_BREAK_SETTLE_S": "0", "SFAB_HEAL_AUDIT": "0", "SFAB_RETRY_PAUSE": "0",
            "SFAB_RAILCAP_SETTLE_S": "0", "SFAB_RAILCAP_TAIL_S": "0.2", "SFAB_DRILL_POLL_S": "0.3", "SFAB_POD_POLL_S": "0.3",
            "SFAB_RAILCAP_START_S": "3", "SFAB_TRACE_TLOG_PAUSE_S": "0.2", "SFAB_TN_AUDIT_HOLD_S": "30", "SFAB_HOLD_AFTER_S": "0.2",
            "SFAB_KEYJOB_WAIT_S": "2", "SFAB_MATRIX_TLOG_PAUSE_S": "0.2",
        })
        self.env.pop("VARIANT", None)
        cs = {}
        for i, n in enumerate(self.inv["order"]):
            node = self.inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            cmd = ["--username", "admin", "--password", "shimpw"] if node["kind"] in ("dell_sonic", "paloalto_panos") else []
            cs[node["container"]] = {"running": True, "started": f"2026-10-22T09:00:{i % 60:02d}Z", "pid": 6000 + i, "health": "healthy",
                                     "env": env, "cmd": cmd}
        self.state.write_text(json.dumps({"containers": cs}))
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", self.inv["lab"]], check=True, capture_output=True)

    def run_cmd(self, argv, timeout=900, env=None):
        e = dict(self.env)
        e.update(env or {})
        return subprocess.run([str(x) for x in argv], env=e, capture_output=True, text=True, cwd=self.lab, timeout=timeout)

    def group(self, fn, timeout=600):
        """One audit group in a result set of its own, as audit.sh runs it."""
        rs = self.t / "set"
        rs.mkdir(exist_ok=True)
        script = (f". {COMMON}/lib.sh; sfab_init audit --set {rs}; . {COMMON}/audit/lib-audit.sh; . {COMMON}/audit/lib-tenancy.sh; "
                  f"{fn}; summary")
        r = self.run_cmd(["bash", "-c", script], timeout=timeout)
        return r, rs

    def edit(self, rel, fn):
        p = self.lab / rel
        d = load(p)
        fn(d)
        p.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n")

    def world_p3(self, **kw):
        """Part III's part of the stand-in world, set before the run (shims-part3/_p3.py p3())."""
        p = self.t / "world.json"
        w = load(p) if p.exists() else {}
        c = {"ready": True, "events": [], "cuts": [], "shut": {}, "holds": {}, "pinned": None, "cache": {}, "rule_dst": {}, "route_add": {},
             "policy": {}, "files": {}, "probes": {}, "iso": {}, "held": {}, "sid": 0}
        c.update(kw)
        w["p3"] = c
        p.write_text(json.dumps(w))

    def last_set(self, kind):
        return sorted((self.lab / "audits").glob(f"{self.inv['lab']}_{kind}_*"))[-1]

    def fails(self, text):
        return [l for l in text.splitlines() if l.startswith("  FAIL  ")]

    def no_key_in(self, d: Path):
        for p in d.rglob("*"):
            if p.is_file():
                b = p.read_bytes()
                for k in KEYS:
                    self.assertNotIn(k.encode(), b, str(p))


# --------------------------------------------------------------------------------------------
# chapter 8


class Ch08AudiencesTest(P3LabTest):
    LAB = "ch08"

    def test_audiences_green(self):
        r, rs = self.group("audit_audiences")
        out = r.stdout
        self.assertIn("== audiences: a Gateway per audience (chapter 8)", out, out[-4000:] + r.stderr[-3000:])
        self.assertEqual(self.fails(out), [], out[-6000:])
        self.assertRegex(out, r"  PASS  gw-inet \(internet\): its routes are its audience's row, llm\.ai\.tarnwick\.example /echo, /models/[0-9a-f-]+\n")
        self.assertIn("  PASS  gw-inet: the namespaces labelled routes.tarnwick.example/gw-inet=true are echo, inference alone", out)
        self.assertIn("  PASS  gw-internal: admin hostnames admin.ai.tarnwick.example, grafana.ai.tarnwick.example, as the render puts them", out)
        self.assertRegex(out, r"  PASS  staff's route admits helpdesk, staff, each a caller whose audience may call staff")
        self.assertRegex(out, r"  PASS  each Gateway's certificate has its own key: 3 distinct public key fingerprints for 3 Gateways")
        self.assertIn("  PASS  gw-users: its lease cilium-l2announce-gateways-cilium-gateway-gw-users held by k8s-ingress1, an ingress node, "
                      "duration 3 s", out)
        self.assertIn("  PASS  cilium-config l2-announcements-lease-duration: 3s (the tuned 3s)", out)
        self.assertIn("  PASS  gw-inet: the announcement policy gateways-internet selects the internet audience's Services "
                      "(tarnwick.example/audience=internet) on ^bond0\\.110$", out)
        self.assertRegex(out, r"  PASS  the key Job asked for inetapp's key for staff, outside the internet audience, failed \(Failed\) with the "
                              r"key tool's refusal")
        self.assertRegex(out, r"  PASS  the key Secret holds the same \d+ fields and fingerprints after the refused mint, and no inetapp\.fe000000")
        self.assertIn("refused: caller inetapp is in audience internet", (rs / "audiences" / "refused-mint.log").read_text())
        # the internet Gateway's column for the Part II rows
        self.assertIn("  PASS  enterprise (ent-client) to gw-inet's VIP 10.20.11.220:443: refused by deny-all-log from enterprise to ingress", out)
        self.assertIn("  PASS  operator (ops-client) to gw-inet's VIP 10.20.11.220:443: refused by deny-all-log from operator-vpn to ingress", out)
        self.assertIn("  PASS  nodes (k8s-cp2) to gw-inet's VIP 10.20.11.220:443: connected, its own datapath answering", out)
        self.assertIn("  SKIP  web to gw-inet's VIP 10.20.11.220:443", out)
        self.no_key_in(rs)

    def test_column_fails_when_the_staff_reach_the_internet_vip(self):
        """A staff connect to 10.20.11.220 that the firewall lets through fails the column."""
        self.world_p3(rule_dst={})
        facts = load(self.env["SHIM_P3_FACTS"])
        facts["connects"]["ent-client|10.20.11.220|443"].update(outcome="reached", rule="staff-to-users-gateway", at="10.20.11.220")
        f2 = self.t / "facts.json"
        f2.write_text(json.dumps(facts))
        self.env["SHIM_P3_FACTS"] = str(f2)
        r, _rs = self.group("audit_audiences")
        self.assertTrue(any(l.startswith("  FAIL  enterprise (ent-client) to gw-inet's VIP 10.20.11.220:443: refused by deny-all-log")
                            for l in self.fails(r.stdout)), r.stdout[-5000:])

    def test_a_route_for_staff_on_the_internet_gateway_fails(self):
        """break-11a's fault seen by chapter 8's group: the internet Gateway's route set is not its row."""
        self.world_p3(route_add={"models-gw-inet": ["staff"]})
        r, _rs = self.group("audit_audiences")
        bad = self.fails(r.stdout)
        self.assertTrue(any(l.startswith("  FAIL  gw-inet (internet): its routes are its audience's row") for l in bad), r.stdout[-5000:])


class GatewayLayerMixin:
    """Chapter 7's placement, keys and gateway-layer groups as a full audit runs them on a Part III
    lab: every key check asks through a Gateway its client reaches at this step, and each Gateway's
    chain is read from a node that reaches it (tenancy.json audiences.reach and tls_from)."""

    def gateway_layer(self):
        subprocess.run([str(COMMON / "ca" / "sfab-ca"), "-C", str(self.lab), "init"], check=True, capture_output=True, timeout=120)
        r, rs = self.group("audit_placement; audit_gateway_layer")
        out = r.stdout
        self.assertIn("== keys: the callers' keys at the API gateway (chapter 7)", out, out[-4000:] + r.stderr[-3000:])
        bad = [l for l in self.fails(out) if "gw-" in l or "through" in l or "chain" in l]
        self.assertEqual(bad, [], out[-8000:])
        targets = [json.loads(l) for l in (rs / "keys" / "targets.jsonl").read_text().splitlines() if l.strip()]
        tls = {g: (rs / "gateway-layer" / f"tls-from-{g}.txt").read_text().strip() for g in ("gw-inet", "gw-internal", "gw-users")}
        for g in tls:
            self.assertRegex(out, rf"  PASS  {g}: the chain for llm\.ai\.tarnwick\.example verifies against the lab root")
        return out, targets, tls, load(self.t / "world.json")["p3"].get("tls") or []


class Ch08GatewayLayerTest(GatewayLayerMixin, P3LabTest):
    LAB = "ch08"

    def test_gateway_layer_reaches_every_gateway(self):
        _out, targets, tls, reads = self.gateway_layer()
        self.assertEqual(sorted({t["gateway"] for t in targets}), ["gw-internal", "gw-users"])
        # no population reaches the internet Gateway in chapter 8: its chain is read from k8s-cp2
        self.assertEqual(tls, {"gw-inet": "k8s-cp2", "gw-internal": "ops-client", "gw-users": "ent-client"})
        self.assertIn({"node": "k8s-cp2", "address": "10.20.11.220", "outcome": "reached"}, reads)


class Ch09GatewayLayerTest(GatewayLayerMixin, P3LabTest):
    LAB = "ch09"

    def test_no_key_check_through_the_untranslated_internet_gateway(self):
        _out, targets, tls, reads = self.gateway_layer()
        # the internet users meet deny-all-log until chapter 10: no key check asks from inet-client
        self.assertNotIn("inet-client", {t["client"] for t in targets})
        self.assertEqual(tls["gw-inet"], "k8s-cp2")
        self.assertFalse([x for x in reads if x["outcome"] != "reached"], reads)


class Ch10GatewayLayerTest(GatewayLayerMixin, P3LabTest):
    LAB = "ch10"

    def test_internet_gateway_through_the_published_address(self):
        _out, targets, tls, reads = self.gateway_layer()
        inet = [t for t in targets if t["gateway"] == "gw-inet"]
        self.assertTrue(inet and all(t["client"] == "inet-client" for t in inet), targets)
        self.assertEqual(tls["gw-inet"], "inet-client")
        self.assertIn({"node": "inet-client", "address": "198.51.100.10", "outcome": "reached"}, reads)


class Ch08TraceTest(P3LabTest):
    LAB = "ch08"

    def test_keyed_trace_from_a_node(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertIn("  PASS  k8s-cp2 answers gw-users's VIP 10.20.11.210 itself: no SYN to it left the node on its 2 port(s) "
                      "(0-k8s-cp2-eth1, 0-k8s-cp2-eth2), so the lease holder (k8s-ingress1) never saw the request", v)
        self.assertRegex(v, r"  PASS  hop 1, the Gateway's proxy to api-gateway-6c9f-a1: POST /models/[0-9a-f-]+/v1/chat/completions with "
                            r"Authorization <redacted hmac:[0-9a-f]{12}>, the caller's staff key \(helpdesk\.")
        self.assertRegex(v, r"  PASS  POST https://llm\.ai\.tarnwick\.example/models/[0-9a-f-]+/v1/chat/completions\?msg=sfab-trace-also-gw-inet "
                            r"from k8s-cp2 through gw-inet \(10\.20\.11\.220\) with staff's key: HTTP 404 from the Gateway \(server envoy\)")
        self.assertIn("  PASS  no API gateway pod saw it: no request carrying sfab-trace-also-gw-inet at 2 API gateway pods (so no API gateway "
                      "line names it)", v)
        self.assertIn("  PASS  k8s-cp2 answered it itself: no SYN from port 42807 to 10.20.11.220 left the node", v)
        md = (rs / "TRACE.md").read_text()
        self.assertIn("## The same key through gw-inet", md)
        self.no_key_in(rs)


class Ch08LeaseDrillTest(P3LabTest):
    LAB = "ch08"

    def test_lease_holder_loss_one_pass(self):
        self.edit("gen/drills.json", lambda d: d["timing"].update({"lead_s": 2, "hold_s": 4, "tail_s": 2, "settle_max_s": 20, "whole_polls": 1}))
        r = self.run_cmd([self.lab / "drills.sh", "--passes", "1"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-8000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        # the users' Gateway on k8s-ingress1, the other two on k8s-ingress2: k8s-ingress2 holds the most
        self.assertIn("  PASS  pass 1 lease-holder-loss: gw-inet's lease, held by k8s-ingress2 at the cut, taken by k8s-ingress1", v)
        self.assertIn("  PASS  pass 1 lease-holder-loss: gw-users's lease held by k8s-ingress1 before the cut, not the cut node k8s-ingress2", v)
        self.assertRegex(v, r"  PASS  pass 1 lease-holder-loss: ops-client through gw-internal: \d+ of \d+ echo requests lost, the gap [\d.]+ s")
        self.assertRegex(v, r"  PASS  pass 1 lease-holder-loss: the prediction, 2 to 4 s at the timers 3s, 1s, 200ms")
        self.assertRegex(v, r"  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10\.20\.11\.200 names k8s-ingress1's bond MAC")
        self.assertIn("  KNOWN pass 1 lease-holder-loss: the cut node sees no loss of carrier", v)
        an = load(rs / "pass1" / "lease-holder-loss" / "analysis.json")
        self.assertEqual(an["cut"], "k8s-ingress2")
        self.assertTrue(an["gateways"]["gw-inet"]["moved"])
        self.assertTrue((rs / "DRILLS.md").is_file())
        self.no_key_in(rs)

    def test_no_arp_entry_for_a_vip_no_probe_drives(self):
        """The cut node holds gw-inet's lease, and the firewall has learned no MAC for 10.20.11.220,
        which no population reaches in chapter 8: recorded, not a failure."""
        self.edit("gen/drills.json", lambda d: d["timing"].update({"lead_s": 2, "hold_s": 4, "tail_s": 2, "settle_max_s": 20, "whole_polls": 1}))
        self.world_p3(arp_omit=["10.20.11.220"])
        r = self.run_cmd([self.lab / "drills.sh", "--passes", "1"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-8000:] + r.stderr[-3000:])
        v = (self.last_set("drills") / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertIn("  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-inet's VIP 10.20.11.220 while k8s-ingress2 is cut names "
                      "nothing (recorded, not judged: no probe of the drill reaches gw-inet through the firewall)", v)
        self.assertRegex(v, r"  PASS  pass 1 lease-holder-loss: the firewall's ARP entry for gw-internal's VIP 10\.20\.11\.200 names k8s-ingress1's bond MAC")


# --------------------------------------------------------------------------------------------
# chapter 9


class Ch09Test(P3LabTest):
    LAB = "ch09"

    def test_split_horizon_green(self):
        r, rs = self.group("audit_split_horizon")
        out = r.stdout
        self.assertEqual(self.fails(out), [], out[-6000:] + r.stderr[-2000:])
        self.assertIn("  PASS  inet-dns-auth (203.0.113.6): llm.ai.tarnwick.example A 198.51.100.10, authoritative: NOERROR, A 198.51.100.10 "
                      "(flags qr aa)", out)
        self.assertRegex(out, r"  PASS  inet-dns-auth holds none of the \d+ admin, internal, identity and infrastructure names")
        self.assertRegex(out, r"  PASS  inet-dns-auth: registry\.k8s\.io asked with recursion desired, outside its zone: REFUSED")
        self.assertRegex(out, r"  PASS  inet-dns-res refuses a source outside its clients \(203\.0\.113\.0/26\): isp-rtr from 198\.51\.100\.9")
        self.assertRegex(out, r"  PASS  enterprise \(ent-client through ent-dns, view enterprise\): llm\.ai\.tarnwick\.example A 10\.20\.11\.210, and AAAA "
                              r"NOERROR with no record")
        self.assertRegex(out, r"  PASS  nodes \(k8s-cp2 through dns-res1, view internal\): admin\.ai\.tarnwick\.example A 10\.20\.11\.200")
        self.assertRegex(out, r"  PASS  ops-dns \(192\.0\.2\.10\), the uplink side's public server, holds no platform name")
        self.assertRegex(out, r"  PASS  isp-rtr holds no route into 10\.0\.0\.0/8 \(4 routes read\)")
        self.assertIn("  PASS  inet-client's connect to 198.51.100.10:443 from port 42390 refused (TIMEOUT), logged by deny-all-log from isp to isp", out)
        self.assertIn("  PASS  Cilium's copies of the Gateway certificates in cilium-secrets recorded (3 copies, each named by a hash, "
                      "labelled with the Secret it copies: gw-inet-tls, gw-internal-tls, gw-users-tls)", out)
        for n in ("k8s-ingress1", "k8s-ingress2", "k8s-cp1"):
            self.assertIn(f"  PASS  {n}'s Envoy: its loaded certificates as cilium-dbg envoy admin certs lists them recorded "
                          f"(envoy-certs-{n}.txt, 3 certificates loaded; by serial, the certificates of gw-inet, gw-internal, "
                          f"gw-users), not judged", out)
            self.assertNotIn("PRIVATE KEY", (rs / "split-horizon" / f"envoy-certs-{n}.txt").read_text())

    def test_dns_trace(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertRegex(v, r"  PASS  ent-dns received ent-client's query for llm\.ai\.tarnwick\.example A \(1\) and answered 10\.20\.11\.210")
        self.assertRegex(v, r"  PASS  \.\.\. which it asked of its authority 10\.20\.13\.11, which answered 10\.20\.11\.210")
        self.assertIn("  PASS  k8s-cp2's connect to 10.20.11.200:443 from port 42907: CONNECTED (answered on the node)", v)
        self.assertIn("  PASS  ... no SYN to it left the node: none at 0-k8s-cp2-eth1, 0-k8s-cp2-eth2", v)
        self.assertRegex(v, r"  PASS  \.\.\. on exactly one leg of the bundle \(3-fw-ae1-leg\d\), its destination 10\.20\.11\.210")
        self.assertRegex(v, r"  PASS  \.\.\. its SYN at 1-isp-rtr-eth1")
        self.assertIn("  PASS  ... nothing of it past the device that refuses it: none at 3-fw-ae1-leg1, 3-fw-ae1-leg2", v)
        self.assertRegex(v, r"  PASS  \.\.\. the traffic log: deny-all-log \(deny\), zone isp to isp")
        self.assertIn("# Split-horizon trace", (rs / "TRACE.md").read_text())
        # the warm-up before the captures: the two answered populations only, from their own ports
        self.assertEqual(sorted(p.name for p in (rs / "warmup").iterdir()), ["enterprise.txt", "nodes.txt"])
        self.assertIn(" 42916 ", (rs / "warmup" / "enterprise.txt").read_text())


# --------------------------------------------------------------------------------------------
# chapter 10


class Ch10Test(P3LabTest):
    LAB = "ch10"

    def test_zone_nat_green(self):
        self.edit("gen/tenancy.json", lambda d: d["hold"].update({"n": 3, "every_s": 1, "hold_s": 30}))
        r, rs = self.group("audit_zone_nat")
        out = r.stdout
        self.assertEqual(self.fails(out), [], out[-6000:] + r.stderr[-2000:])
        self.assertIn("  PASS  the NAT rulebase in the rendered order: dnat-internet-gateway, no-nat-public, internet-snat", out)
        self.assertIn("  PASS  the isp zone's NAT rules are dnat-internet-gateway alone: from isp to isp, destination 198.51.100.10, "
                      "0:tcp/any/443, translated dst: 10.20.11.220", out)
        self.assertRegex(out, r"  PASS  the isp zone's allow rules are isp-to-internet-gateway alone: destination 198\.51\.100\.10")
        self.assertIn("  PASS  enterprise (ent-client) to 198.51.100.10:443: untranslated, refused by deny-all-log from enterprise to isp "
                      "(the client: TIMEOUT)", out)
        self.assertRegex(out, r"  PASS  operator \(ops-client\) to 198\.51\.100\.10:443: silence at uplink-rtr, which holds no route to it")
        self.assertRegex(out, r"  PASS  internet: 3 connection\(s\) from inet-client held to gw-inet at 198\.51\.100\.10:443")
        self.assertIn("  PASS  internet: the firewall counts 3 session(s) from isp destination 198.51.100.10 destination-port 443 while they are "
                      "held, within the plan's bound 3 to 6", out)

    def test_nat_trace(self):
        self.edit("gen/trace.json", lambda d: [x.update(hold_s=1) for x in d["sessions"]])
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertRegex(v, r"  PASS  internet: the same SYN on exactly one leg \(3-fw-ae1-leg\d\), tagged 110: destination rewritten to "
                            r"10\.20\.11\.220, source and sequence number kept")
        self.assertRegex(v, r"  PASS  operator: the same SYN on exactly one leg \(3-fw-ae1-leg\d\), tagged 110: destination 10\.20\.11\.200 as sent")
        self.assertRegex(v, r"  PASS  show session id names the security rule isp-to-internet-gateway")
        self.assertRegex(v, r"  PASS  \.\.\. and the NAT rule dnat-internet-gateway")
        # the warm-up before the captures: one connect per session, from its own port
        self.assertEqual(sorted(p.name for p in (rs / "warmup").iterdir()), ["enterprise.txt", "internet.txt", "operator.txt"])
        self.assertIn(" 42946 ", (rs / "warmup" / "internet.txt").read_text())

    def test_hold_measurement(self):
        self.edit("gen/tenancy.json", lambda d: d["hold"].update({"n": 2, "every_s": 1, "hold_s": 30}))
        r = self.run_cmd([self.lab / "hold.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("hold")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertRegex(v, r"  PASS  enterprise: the firewall counts 2 session\(s\) from enterprise destination 10\.20\.11\.210")
        self.assertRegex(v, r"  PASS  internet: chat through gw-inet with inetapp's key \(inetapp\.[0-9a-f]{8}\): HTTP 200")
        self.assertIn("  PASS  show session info: tcp 3600 s, the plan's 3600 s", v)
        self.assertIn("  PASS  show session info: discard tcp 90 s, the plan's 90 s", v)
        md = (rs / "HOLD.md").read_text()
        self.assertIn("## Little's law per zone", md)
        self.assertNotRegex(md, r"(?i)per second|/s\b")
        self.no_key_in(rs)


# --------------------------------------------------------------------------------------------
# chapter 11


class Ch11Test(P3LabTest):
    LAB = "ch11"

    def test_isolation_negative_checks(self):
        self.edit("gen/tenancy.json", lambda d: d["hold"].update({"n": 2, "every_s": 1, "hold_s": 30}))
        r, rs = self.group("audit_audiences; audit_split_horizon; audit_zone_nat; audit_isolation", timeout=900)
        out = r.stdout
        self.assertEqual(self.fails(out), [], out[-6000:] + r.stderr[-2000:])
        self.assertIn("== isolation: the negative checks (chapter 11)", out)
        self.assertRegex(out, r"  PASS  no HTTPRoute for staff's path on gw-inet")
        self.assertIn("  PASS  no admin or identity hostname on gw-inet (admin.ai.tarnwick.example, grafana.ai.tarnwick.example, "
                      "id.ai.tarnwick.example)", out)
        self.assertRegex(out, r"  PASS  no enterprise allow rule beyond 10\.20\.11\.210/32 reaches another Gateway's pool")
        self.assertIn("  PASS  the isp zone translates to 10.20.11.220 alone, the internet Gateway's VIP", out)

    def test_ladder(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertRegex(v, r"  PASS  internet/gw-inet: allowed \(CONNECTED\), its SYN at 1-isp-rtr-eth1, on one leg")
        self.assertRegex(v, r"  PASS  internet/gw-users: silence at isp-rtr \(TIMEOUT\): 3 SYNs by distinct sequence number reached no rung, and none past it")
        self.assertRegex(v, r"  PASS  enterprise/gw-inet: log-line at fw \(TIMEOUT\): 3 SYNs by distinct sequence number reached 2-fw-ethernet1-4 3")
        self.assertRegex(v, r"  PASS  nodes/gw-users: answered on k8s-cp2 itself \(CONNECTED\): no SYN at any rung")
        self.assertRegex(v, r"  PASS  every rung's forbidden tally is zero \(11 rungs, \d+ forbidden flows\)")
        self.assertIn("Forbidden tally per rung", (rs / "TRACE.md").read_text())

    def test_isolation_drill(self):
        def fast(d):
            d["timing"].update({"lead_s": 1, "tail_s": 1})
            x = d["list"][0]
            x.update(rounds=2, interval_s=0.2)
            x["hold"].update(n=2, every_s=1)
        self.edit("gen/drills.json", fast)
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "isolation-under-load", "--passes", "1"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-8000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertRegex(v, r"  PASS  pass 1 isolation-under-load x1 internet \(inet-client\): its own Gateway 2 of 2 answered 200; "
                            r"gw-internal 0/2 through; gw-users 0/2 through; gw-inet 2/2 allowed; staff 0/2 through; admin 0/2 through")
        self.assertRegex(v, r"  PASS  pass 1 isolation-under-load x2 enterprise: 4 connection\(s\) from ent-client held")

    def test_leaked_key_drill(self):
        def fast(d):
            d["timing"].update({"lead_s": 1, "tail_s": 1})
            x = next(i for i in d["list"] if i["id"] == "leaked-key")
            x.update(interval_s=0.3, accept_max_s=30)
        self.edit("gen/drills.json", fast)
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "leaked-key", "--passes", "1"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-8000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        v = (rs / "verdict.txt").read_text()
        self.assertEqual(self.fails(v), [], v)
        self.assertIn("  PASS  pass 1 leaked-key: the key Job minted batch.fb000001, a key of batch, a caller of the enterprise audience", v)
        self.assertRegex(v, r"  PASS  pass 1 leaked-key: inet-client, a client of the internet audience, through gw-inet to chat with "
                            r"batch\.fb000001: HTTP 200 [\d.]+ s after the mint: no network layer refuses it")
        self.assertRegex(v, r"  PASS  pass 1 leaked-key: the API gateway's access log names caller batch for it")
        self.assertRegex(v, r"  PASS  pass 1 leaked-key: after the revoke the same key refused HTTP 401, [\d.]+ s after it")
        self.assertRegex(v, r"  PASS  pass 1 leaked-key: the key Secret holds the same \d+ fields and fingerprints after the drill as before")
        self.no_key_in(rs)

    def test_matrix_own_caller(self):
        script = (f". {COMMON}/lib.sh; sfab_init matrix --no-record; . {COMMON}/matrix/matrix.sh; d={self.t}/cells; mkdir -p $d; "
                  f"matrix_cells $d internet/chat internet/staff; py $MXP judge --plan $MX_PLAN --dir $d --only internet/chat internet/staff")
        r = self.run_cmd(["bash", "-c", script], timeout=600)
        out = r.stdout
        self.assertEqual(self.fails(out), [], out[-5000:] + r.stderr[-3000:])
        self.assertIn("matrix: inetapp's key handed to inet-client", out)
        self.assertRegex(out, r"  PASS  \[key\] Internet users / Route to chat: with inetapp's key, the population's own caller: the API gateway's "
                              r"access log names caller inetapp")
        self.assertRegex(out, r"  PASS  \[routeset\] Internet users / Route to staff: 404 from gw-inet")


# --------------------------------------------------------------------------------------------
# breaks 8a to 11a


class BreakMixin:
    def bh(self, *args):
        return self.run_cmd([sys.executable, COMMON / "breakheal.py", *args], timeout=900)

    def broke_and_healed(self, bid):
        r = self.bh("break", bid)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        vb = (self.last_set(f"break-{bid}") / "verdict.txt").read_text()
        self.assertEqual(self.fails(vb), [], vb)
        r = self.bh("heal", bid)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        vh = (self.last_set(f"heal-{bid}") / "verdict.txt").read_text()
        self.assertEqual(self.fails(vh), [], vh)
        return vb, vh


class Break8aTest(BreakMixin, P3LabTest):
    LAB = "ch08"

    def test_break_heal(self):
        vb, vh = self.broke_and_healed("8a")
        self.assertRegex(vb, r"  PASS  .*gateways-internet")
        # the symptom where chapter 8 shows it: the internet VIP unanswered on VLAN 110, the users' VIP
        # answered by its holder, the staff's requests answered; healed, the internet VIP answered again
        self.assertIn("  PASS  gw-inet: 10.20.11.220 asked for by ARP from k8s-ingress1 on bond0.110: no answer", vb)
        self.assertIn("  PASS  gw-users: 10.20.11.210 asked for by ARP from k8s-ingress2 on bond0.110: answered with k8s-ingress1's bond MAC", vb)
        self.assertRegex(vb, r"  PASS  staff: every \S+ succeeds")
        self.assertIn("  PASS  gw-inet: 10.20.11.220 asked for by ARP from k8s-ingress1 on bond0.110: answered with k8s-ingress2's bond MAC", vh)
        rec = self.last_set("break-8a") / "record"
        self.assertTrue(any(p.name.startswith("broken-l2-policy-gw-inet") for p in rec.iterdir()), sorted(p.name for p in rec.iterdir()))
        w = load(self.t / "world.json")
        self.assertEqual(w["p3"]["policy"].get("gateways-internet"), ["^bond0\\.110$"])


class Break9aTest(BreakMixin, P3LabTest):
    LAB = "ch09"

    def test_break_heal(self):
        vb, vh = self.broke_and_healed("9a")
        self.assertRegex(vb, r"  PASS  ent-dns: the platform's zone no longer forwarded; llm\.ai\.tarnwick\.example id\.ai\.tarnwick\.example pinned to 10\.20\.11\.210 with address=")
        self.assertRegex(vb, r"  PASS  staff: ")
        self.assertRegex(vh, r"  PASS  staff: .*AAAA")
        self.assertRegex(vb, r"  PASS  staff: AAAA: REFUSED with 0 answer\(s\), not NOERROR with 0 answer\(s\)")
        self.assertIsNone(load(self.t / "world.json")["p3"]["pinned"])

    def test_a_reload_that_meets_a_busy_socket_is_tried_again(self):
        """dnsmasq's restart finding its listening address still held fails the reload once; the break
        tries it again and says so in its record."""
        self.world_p3(reload_busy=1)
        vb, _vh = self.broke_and_healed("9a")
        self.assertRegex(vb, r"  PASS  ent-dns: the platform's zone no longer forwarded")
        rec = (self.last_set("break-9a") / "record" / "break-ent-dns-reload.txt").read_text()
        self.assertIn("Address in use", rec)
        self.assertIn("[breakheal] the reload met a listening socket still in use; reload attempt 2", rec)

    def test_a_local_line_over_the_zone_gives_no_symptom(self):
        """With local=/tarnwick.example/ kept, the server answers the pinned name's AAAA itself (NODATA):
        the break check sees no symptom and fails."""
        def keep_local(d):
            a = d["breaks"]["9a"]["break"][0]
            self.assertFalse([x for x in a["content"].splitlines() if x.startswith("local=")], a["content"])
            a["content"] = a["content"].replace("host-record=", "local=/tarnwick.example/\nhost-record=", 1)
        self.edit("gen/breaks.json", keep_local)
        r = self.bh("break", "9a")
        vb = (self.last_set("break-9a") / "verdict.txt").read_text()
        self.assertTrue(any("AAAA as the check wants" in l for l in self.fails(vb)), vb)
        self.bh("heal", "9a")


class Break10aTest(BreakMixin, P3LabTest):
    LAB = "ch10"

    def test_break_heal(self):
        def fast(d):
            for a in d["breaks"]["10a"]["record"]:
                if a["kind"] in ("probe_http", "probe_syn"):
                    a["count"] = min(a["count"], 3)
                    a["interval_s"] = 0.1
                    a["timeout_s"] = 1
        self.edit("gen/breaks.json", fast)
        vb, vh = self.broke_and_healed("10a")
        self.assertRegex(vb, r"  PASS  internet: ")
        self.assertRegex(vb, r"deny-all-log")
        self.assertRegex(vh, r"isp-to-internet-gateway")


class Break11aTest(BreakMixin, P3LabTest):
    LAB = "ch11"

    def test_break_heal(self):
        vb, vh = self.broke_and_healed("11a")
        self.assertRegex(vb, r"  PASS  internet/staff: mode \S+.*, not 404")
        self.assertRegex(vb, r"  PASS  models-gw-inet: its rules carry .*; beyond its audience's row: /models/")
        self.assertRegex(vh, r"  PASS  models-gw-inet: its rules carry /models/[0-9a-f-]+, the audience's row \(chat\)")
        self.assertRegex(vh, r"  PASS  internet/staff: ")
        self.assertRegex(vh, r"  PASS  internet/chat: ")
        self.assertEqual(load(self.t / "world.json")["p3"]["route_add"].get("models-gw-inet"), [])


class SettleTargetsTest(unittest.TestCase):
    """finish's settle connects each population's client to its answer only where the firewall lets
    it through at that step (gen/tenancy.json audiences.reach): chapter 9's internet users are
    refused by deny-all-log by design, so a settle round that waited on them could never be clean."""

    @staticmethod
    def targets(lab: str) -> list[str]:
        src = (COMMON / "stages" / "finish.sh").read_text(encoding="utf-8")
        body = src.split("settle_targets() {", 1)[1].split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        gen = ROOT / lab / "gen"
        out = subprocess.run([sys.executable, "-c", body, str(gen / "inventory.json"), str(gen / "tenancy.json")],
                             capture_output=True, text=True, check=True).stdout
        return [ln for ln in out.splitlines() if ln.startswith("client ")]

    def test_ch09_leaves_out_the_internet_users(self):
        self.assertEqual(self.targets("ch09"), ["client ent-client 10.20.11.210 enterprise",
                                                "client ops-client 10.20.11.200 operator"])

    def test_ch10_keeps_them_once_translated(self):
        self.assertIn("client inet-client 198.51.100.10 internet", self.targets("ch10"))

    def test_lab_without_tenancy_unchanged(self):
        self.assertEqual(self.targets("ch07"), ["client ent-client 10.20.11.210 enterprise",
                                                "client ops-client 10.20.11.200 operator"])


class Ch09PopulationsTest(unittest.TestCase):
    """The populations group in chapter 9's lab: the internet users' requests to the published
    address are refused by deny-all-log at this step (gen/tenancy.json audiences.reach), so the
    judge wants them unanswered, and an answer there fails."""

    def run_judge(self, users: str, admin: str) -> str:
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "inet-client"
            d.mkdir()
            for name, text in (("09_pop_dns_users", "198.51.100.10\n"), ("10_pop_dns_admin", ""), ("11_pop_dns_infra", ""),
                               ("12_pop_https_users", users), ("13_pop_https_admin", admin)):
                (d / f"{name}.txt").write_text(text, encoding="utf-8")
            return subprocess.run([sys.executable, str(COMMON / "audit" / "judge.py"), "run", "--set", td,
                                   "--inv", str(ROOT / "ch09" / "gen" / "inventory.json"), "--render", str(ROOT / "ch09"),
                                   "populations", "inet-client"], capture_output=True, text=True).stdout

    def test_refused_requests_pass(self):
        out = self.run_judge("curl: (28) Connection timed out after 20002 milliseconds\n",
                             "curl: (28) Connection timed out after 20002 milliseconds\n")
        self.assertIn("  PASS  inet-client: https://llm.ai.tarnwick.example/echo: no answer, refused at fw by deny-all-log at "
                      "198.51.100.10 (no translation or rule at this step)", out)
        self.assertRegex(out, r"  PASS  inet-client: https://admin\.ai\.tarnwick\.example/echo: no answer, refused at fw")
        self.assertNotIn("FAIL", out)

    def test_an_answer_fails(self):
        out = self.run_judge("HTTP/1.1 200 OK\r\nserver: envoy\r\n\r\nsfab\n", "curl: (28) Connection timed out\n")
        self.assertRegex(out, r"  FAIL  inet-client: https://llm\.ai\.tarnwick\.example/echo: no answer, .* -> HTTP 200")


if __name__ == "__main__":
    unittest.main()
