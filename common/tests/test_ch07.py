"""Chapter 7's lab harness (ch07/): the keys and gateway-layer groups the audit adds, the keyed trace
with its refusal, the three gateway drills and break-7a with its heal and cleanup. Run from the repo
root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_ch07*.py'

Hermetic: ch07 is rendered into a temporary directory (PyYAML) and every device is a stand-in
(common/tests/shims/, shims-ch06/, shims-ch07/). The stand-in world is a simple deterministic model
of the gateway layer (shims-ch07/_ch07.py, on chapter 6's model of the serving layer), so the
figures asserted here are the model's, never the lab's. Fixtures use the book's own addressing plan
and made-up names and keys only.
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
CH07 = ROOT / "ch07"
HERE = Path(__file__).resolve().parent
SHIMS, SHIMS_CH06, SHIMS_CH07 = HERE / "shims", HERE / "shims-ch06", HERE / "shims-ch07"

NODES = "fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw fw k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2 bastion uplink-rtr ops-client ops-dns inet-registry ent-client"
# the stand-in world's made-up keys: the models' first keys, the router's master key, the backend key,
# and the keys the drills and the break mint (the stand-in repeats their ids)
KEYS = ("5" * 32, "6" * 32, "8" * 32, "9" * 32, "fd000001" * 4, "fa000001" * 4)
STUB_AUDIT = """#!/usr/bin/env bash
# a stand-in for ch07/audit.sh in these tests: chapter 7's groups alone, as the quick audit runs them
set -euo pipefail
. "$(dirname "$0")/../common/lib.sh"
sfab_init audit "$@"
. "$SFAB_COMMON/audit/lib-audit.sh"
audit_gateway_layer
summary
"""


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


def load(p):
    return json.loads(Path(p).read_text())


_RENDER = None


def ch07_render() -> Path:
    global _RENDER
    if _RENDER is None:
        out = Path(tempfile.mkdtemp(prefix="sfab-test-ch07-"))
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(CH07), "--out", str(out), "-q"], check=True, capture_output=True)
        _RENDER = out
    return _RENDER


def tearDownModule():
    if _RENDER is not None:
        shutil.rmtree(_RENDER, ignore_errors=True)


class Ch07LabTest(unittest.TestCase):
    def setUp(self):
        if not have_yaml():
            self.skipTest("PyYAML is needed to render ch07")
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-ch07lab-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        self.lab = self.t / "ch07"
        self.lab.mkdir()
        r = ch07_render()
        for part in ("gen", "bootstrap"):
            shutil.copytree(r / part, self.lab / part)
        shutil.copy(r / "topo.clab.yml", self.lab / "topo.clab.yml")
        for f in ("chapter.yaml", "audit.sh", "trace.sh", "drills.sh"):
            shutil.copy(CH07 / f, self.lab / f)
        (self.lab / "audit.sh").write_text(STUB_AUDIT)
        (self.lab / "audit.sh").chmod(0o755)
        for d in ("common", "spec", "serving-layer"):
            os.symlink(ROOT / d, self.t / d)
        dr = load(self.lab / "gen" / "drills.json")
        # accept_max_s bounds the per-pod probes' rounds too (the refusal probe runs from before the
        # revoke until every pod refuses): 60 s leaves a busy machine time for the revoke's Job, and a
        # probe that finds every pod refusing stops at once
        dr["timing"].update({"lead_s": 1, "tail_s": 1, "accept_max_s": 60, "settle_max_s": 20, "whole_polls": 3})
        for d in dr["list"]:
            if d["kind"] == "idle-timeout":
                d["silent_s"] = 4
        (self.lab / "gen" / "drills.json").write_text(json.dumps(dr, indent=2, sort_keys=True) + "\n")
        br = load(self.lab / "gen" / "breaks.json")
        for a in br["breaks"]["7a"]["record"]:
            if a["kind"] == "key_probe":
                a["wait_s"] = 4
            if a["kind"] == "probe_gateway":
                a["count"], a["interval_s"] = 8, 0.5
        (self.lab / "gen" / "breaks.json").write_text(json.dumps(br, indent=2, sort_keys=True) + "\n")
        self.inv = load(self.lab / "gen" / "inventory.json")
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS_CH07}:{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab), "SHIM_STATE": str(self.state), "SHIM_LOG": str(self.log), "SHIM_NODES": NODES,
            "SFAB_HOST_LOCK": str(self.t / "sfab.lock"), "SFAB_TICK_OVERRIDE": "1", "SHIM_INV": str(self.lab / "gen" / "inventory.json"),
            "SHIM_RENDER": str(self.lab), "SHIM_CH06_STATE": str(self.t / "ch07-world.json"), "PYTHONDONTWRITEBYTECODE": "1",
            "SFAB_DRILL_AUDIT": "0", "SFAB_BREAK_SETTLE_S": "0", "SFAB_HEAL_AUDIT": "0", "SFAB_RETRY_PAUSE": "0",
            "SFAB_RAILCAP_SETTLE_S": "0", "SFAB_RAILCAP_TAIL_S": "0.2", "SFAB_DRILL_POLL_S": "0.3", "SFAB_POD_POLL_S": "0.3",
            "SFAB_RAILCAP_START_S": "3",
        })
        self.env.pop("VARIANT", None)
        cs = {}
        for i, n in enumerate(self.inv["order"]):
            node = self.inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            cmd = ["--username", "admin", "--password", "shimpw"] if node["kind"] in ("dell_sonic", "paloalto_panos") else []
            cs[node["container"]] = {"running": True, "started": f"2026-10-22T09:00:{i:02d}Z", "pid": 6000 + i, "health": "healthy",
                                     "env": env, "cmd": cmd}
        self.state.write_text(json.dumps({"containers": cs}))
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-ch07"], check=True, capture_output=True)

    def run_cmd(self, argv, timeout=900, env=None):
        e = dict(self.env)
        e.update(env or {})
        return subprocess.run([str(x) for x in argv], env=e, capture_output=True, text=True, cwd=self.lab, timeout=timeout)

    def world(self):
        try:
            return load(self.t / "ch07-world.json")
        except (OSError, ValueError):
            return {}

    def last_set(self, kind):
        return sorted((self.lab / "audits").glob(f"sfab-ch07_{kind}_*"))[-1]

    def no_key_in(self, d: Path):
        for p in d.rglob("*"):
            if p.is_file():
                b = p.read_bytes()
                for k in KEYS:
                    self.assertNotIn(k.encode(), b, str(p))
        b = self.log.read_bytes()
        for k in KEYS[:4]:
            self.assertNotIn(k.encode(), b, "the stand-ins' command log")

    def no_rate_in(self, d: Path):
        """No saved file, a capture included, holds a timing value llama-server writes."""
        rx = re.compile(rb'"(?:prompt|predicted)_(?:ms|per_token_ms|per_second)"[ \t]*:[ \t]*-?\d')
        seen = 0
        for p in d.rglob("*"):
            if p.is_file():
                b = p.read_bytes()
                if p.suffix == ".gz":
                    import gzip  # noqa: PLC0415

                    b = gzip.decompress(b)
                seen += b.count(b'_per_second"')
                self.assertIsNone(rx.search(b), str(p))
        return seen

    def verdict_lines(self, text, start):
        return [l for l in text.splitlines() if l.startswith(start)]


class GatewayLayerAuditTest(Ch07LabTest):
    def test_green(self):
        rs = self.t / "set"
        rs.mkdir()
        # the lab's CA on the lab host, as up makes it (sfab-ca init): the audit reads its proof there
        subprocess.run([str(COMMON / "ca" / "sfab-ca"), "-C", str(self.lab), "init"], check=True, capture_output=True, timeout=120)
        script = f". {COMMON}/lib.sh; sfab_init audit --set {rs}; . {COMMON}/audit/lib-audit.sh; audit_gateway_layer; summary"
        r = self.run_cmd(["bash", "-c", script], timeout=600)
        out = r.stdout
        self.assertIn("== keys: the callers' keys at the API gateway (chapter 7)", out, out[-4000:] + r.stderr[-3000:])
        self.assertEqual(self.verdict_lines(out, "  FAIL  "), [], out[-6000:])
        for line in ("  PASS  chat through gw-users from ent-client, no key: HTTP 401 from key authentication (Authorization Failed)",
                     "  PASS  chat through gw-users from ent-client, a key no Secret holds: HTTP 401 (Authorization Failed)",
                     "  PASS  chat through gw-users from ent-client, staff's key: HTTP 401 with the unknown key's own message (Authorization "
                     "Failed), so a key that works elsewhere reads as none",
                     # a person's OpenID Connect token at the API gateway
                     "  PASS  ent-client signs in from ent-client (client staff-cli): a token from https://id.ai.tarnwick.example for "
                     "ent-client@tarnwick.example, verified, its audience ['staff-cli', 'ai-gateway'], valid 3600 s",
                     "  PASS  ent-client's token on chat through gw-users: HTTP 200 (caller staff may call it)",
                     "  PASS  ent-client's token asked without the API gateway's audience names only ['staff-cli']",
                     "  PASS  the API gateway's access log names the person: consumer staff_ent_client of caller staff, 4 answered request(s)",
                     "  PASS  every API gateway pod (api-gateway-6c9f-a1, api-gateway-6c9f-b2) answers its own first key on chat's route with HTTP 200",
                     "  PASS  every API gateway pod (api-gateway-6c9f-a1, api-gateway-6c9f-b2) answers chat's key on staff's route with HTTP 401",
                     "  PASS  GatewayClass cilium Accepted",
                     "  PASS  gw-users: its listener https admits HTTPRoutes from the namespaces labelled routes.tarnwick.example/gw-users=true only "
                     "(allowedRoutes from Selector)",
                     "  PASS  gw-internal: the namespaces carrying its label are the render's (echo, identity, inference, serving)",
                     "  PASS  gw-users: no HTTPRoute on it names an admin hostname"):
            self.assertIn(line, out)
        self.assertRegex(out, r"  PASS  gw-users answers exactly the render's hostnames and paths: id\.ai\.tarnwick\.example /; llm\.ai\.tarnwick\.example /echo, /models/")
        self.assertRegex(out, r"  PASS  gw-internal, the internal Gateway, carries the bare /models prefix and the admin hostnames")
        self.assertRegex(out, r"  PASS  gw-users: 10\.20\.11\.210 from k8s-ingress2 answers ARP \(02:5a:0c:00:00:01\) and TCP 443, and no ICMP echo \(0 of 3 answered\)")
        self.assertRegex(out, r"  PASS  the platform intermediate's leaf for DNS:llm\.corvane\.example, outside its name constraints, fails verification")
        self.assertRegex(out, r"  PASS  the chain nests: the router's 2 attempts of 280 s < the API gateway's upstream read 600 s < backendRequest 620 s")
        self.assertRegex(out, r"  PASS  gw-users: its listener's stream idle timeout as Cilium's operator wrote it: 2s")
        self.assertTrue((rs / "keys" / "probe.log").is_file())
        self.no_key_in(rs)


class KeyedTraceTest(Ch07LabTest):
    def test_trace_keyed_green(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        rid = load(self.lab / "gen" / "trace.json")["route_id"]
        self.assertRegex(verdict, rf"  PASS  hop 1, the Gateway's proxy to api-gateway-6c9f-a1: POST /models/{rid}/v1/chat/completions with "
                                  r"Authorization <redacted hmac:[0-9a-f]{12}>, the caller's chat key \(batch\.0a1b2c3d sha256:[0-9a-f]{12}\)")
        self.assertRegex(verdict, r"  PASS  hop 2, api-gateway-6c9f-a1 to the router pod router-7d4b-a1: POST /engines/chat/chat/completions with "
                                  r"Authorization <redacted hmac:[0-9a-f]{12}>, the router's master key")
        self.assertIn("  PASS  ... and the caller's key nowhere on hop 2 (0 requests to the router carry its mark)", verdict)
        self.assertRegex(verdict, r"  PASS  hop 3, router-7d4b-a1 to the server at 10\.22\.\d+\.\d+: Authorization <redacted hmac:[0-9a-f]{12}>, the backend key")
        self.assertRegex(verdict, r"  PASS  every Authorization value in the keyed captures is a mark, none a value")
        self.assertIn("  PASS  GET https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused from ent-client: HTTP 404 from the Gateway (server envoy)",
                      verdict)
        self.assertRegex(verdict, r"  PASS  no API gateway pod saw it: no request for admin\.ai\.tarnwick\.example at 2 API gateway pods, which received 1 request")
        md = (rs / "TRACE.md").read_text()
        self.assertIn("## The keys at the in-cluster hops", md)
        self.assertIn("## The refusal", md)
        for ch in (chr(0x2014), chr(0x2013)):
            self.assertNotIn(ch, md)
        pl = (rs / "captures" / "2-api-gateway-6c9f-a1-eth0-payload.txt").read_text()
        self.assertIn("authorization: Bearer <redacted hmac:", pl)
        self.assertTrue((rs / "captures" / "scrub.log").is_file())
        self.assertRegex((rs / "captures" / "scrub.log").read_text(), r"keyscrub: \d+ value\(s\) replaced by their marks, [1-9]\d* timing value\(s\) blanked")
        self.assertGreater(self.no_rate_in(rs), 0, "the stand-in's answers carry timings, blanked in place")
        self.no_key_in(rs)


class GwDrillTest(Ch07LabTest):
    def test_three_drills_one_pass(self):
        r = self.run_cmd([self.lab / "drills.sh", "--passes", "1"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-8000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        self.assertRegex(verdict, r"  PASS  pass 1 key-lifecycle: the key Job minted batch\.fd000001 into the key Secret \(sha256:[0-9a-f]{12}\)")
        self.assertRegex(verdict, r"  PASS  pass 1 key-lifecycle: every API gateway pod accepted it, each on its own schedule: api-gateway-6c9f-a1 [\d.]+ s, "
                                  r"api-gateway-6c9f-b2 [\d.]+ s after the Secret's write")
        self.assertRegex(verdict, r"  PASS  pass 1 key-lifecycle: the first 200 through llm\.ai\.tarnwick\.example came [\d.]+ s after the write")
        self.assertRegex(verdict, r"  PASS  pass 1 key-lifecycle: the new chat key on staff's route: 401 at every API gateway pod")
        self.assertRegex(verdict, r"  PASS  pass 1 key-lifecycle: after the revoke every API gateway pod refused it")
        self.assertRegex(verdict, r"  PASS  pass 1 key-lifecycle: chat through gw-users: 0 of \d+ requests failed")
        self.assertRegex(verdict, r"  PASS  pass 1 key-lifecycle: the key Secret holds the same fields and fingerprints after the drill as before")
        self.assertRegex(verdict, r"  PASS  pass 1 rejected-code: staff's route without rejected_code: a chat key answered HTTP 403 at every API gateway pod")
        self.assertRegex(verdict, r"the plugin's own message: The consumer_group_id is forbidden\.")
        self.assertRegex(verdict, r"  PASS  pass 1 rejected-code: the rendered routes back: HTTP 401 at every pod again, with the unknown key's message")
        self.assertRegex(verdict, r"  PASS  pass 1 rejected-code: the routes ConfigMap is the render's again")
        self.assertRegex(verdict, r"  PASS  pass 1 idle-timeout, as rendered \(the listener's stream idle timeout 2s\): the request silent for 4 s ended "
                                  r"HTTP 504 after [\d.]+ s, answered by envoy")
        self.assertRegex(verdict, r"  PASS  pass 1 idle-timeout, as rendered: the Gateway's proxy closed its connection to the test backend")
        self.assertRegex(verdict, r"  PASS  pass 1 idle-timeout, corrected \(the listener's stream idle timeout 600s, the route's request 420 s and "
                                  r"backendRequest 400 s\): the same silence answered HTTP 200 after [\d.]+ s")
        self.assertRegex(verdict, r"  PASS  pass 1 idle-timeout: the rendered chain back: idle 2s \(before the drill 2s\), the same; route timeouts none; "
                                  r"helm values rendered")
        md = (rs / "DRILLS.md").read_text()
        self.assertIn("## key-lifecycle:", md)
        an = json.loads((rs / "pass1" / "idle-timeout" / "analysis.json").read_text())
        self.assertEqual(sorted(an["helm"]), ["corrected", "rendered"])
        self.assertEqual(sorted(an["helm"]["corrected"]), ["cilium-envoy_s", "cilium-operator_s", "cilium_s", "upgrade_s"])
        self.assertEqual(sorted(an["leases"]), ["after-corrected", "after-rendered", "before-corrected", "before-rendered"])
        self.assertEqual(an["leases"]["after-corrected"]["gw-users"], "k8s-ingress1, 0 transitions")
        w = self.world()
        self.assertNotIn("batch.fd000001", w["secrets"]["inference/api-keys"], "the drill's key is revoked")
        self.assertIsNone(w["ch07"].get("route_timeouts"))
        self.assertIn("[redacted: throughput]", (rs / "pass1" / "rejected-code" / "own-vip-body.txt").read_text())
        self.assertTrue((rs / "pass1" / "idle-timeout" / "events" / "events-kube-system.json").is_file(), "the idle drill archives Cilium's events")
        self.assertFalse((rs / "pass1" / "key-lifecycle" / "events" / "events-kube-system.json").exists())
        self.no_rate_in(rs)
        self.no_key_in(rs)


class Break7aTest(Ch07LabTest):
    def bh(self, *args):
        return self.run_cmd([sys.executable, COMMON / "breakheal.py", *args])

    def test_break_heal_cleanup(self):
        r = self.bh("break", "7a")
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        verdict = (self.last_set("break-7a") / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        self.assertIn("  PASS  api-gateway-6c9f-b2, the API gateway pod at place 1 of 2 by name, held: its sidecar keeps the apisix.yaml it has "
                      "(hold file /standalone/hold)", verdict)
        self.assertRegex(verdict, r"  PASS  the key Job minted batch\.fa000001 in Secret inference/api-keys \(sha256:[0-9a-f]{12}\)")
        self.assertRegex(verdict, r"  PASS  pods: only api-gateway-6c9f-b2, the held pod, never accepted the key \(401\); api-gateway-6c9f-a1 accepted it")
        self.assertRegex(verdict, r"  PASS  users: some requests fail and some succeed \(\d+ of 8 across the passes\)")
        rec = self.last_set("break-7a") / "record"
        self.assertTrue((rec / "broken-secret-fields.txt").is_file())
        r = self.bh("heal", "7a")
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        verdict = (self.last_set("heal-7a") / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        self.assertRegex(verdict, r"  PASS  api-gateway-6c9f-b2 deleted, and its Deployment api-gateway rolled out with a new pod in its place")
        self.assertRegex(verdict, r"  PASS  pods: every API gateway pod accepted the key")
        self.assertRegex(verdict, r"  PASS  users: every request succeeds")
        self.assertRegex(verdict, r"  PASS  the key Job revoked batch\.fa000001 in Secret inference/api-keys")
        w = self.world()
        self.assertNotIn("batch.fa000001", w["secrets"]["inference/api-keys"])
        self.no_key_in(self.last_set("break-7a"))
        self.no_key_in(self.last_set("heal-7a"))


class KeyFirstVipTest(unittest.TestCase):
    """gwdrill.py's bound on the first 200 through the VIP: the per-pod probe pod starts some seconds
    after the Secret's write, so the VIP may answer before the probe's first round; it may never answer
    before a round of the probe that found no pod holding the key."""

    def setUp(self):
        sys.path.insert(0, str(COMMON / "drill"))
        sys.path.insert(0, str(COMMON / "audit"))
        import gwdrill  # noqa: PLC0415
        import vocab  # noqa: PLC0415
        self.G, self.V = gwdrill, vocab
        self.d = Path(tempfile.mkdtemp(prefix="sfab-test-gwkey-"))
        self.addCleanup(shutil.rmtree, self.d, True)

    def world(self, rounds, vip_first):
        d, t0 = self.d, 1000.0
        (d / "timeline.txt").write_text(f"{t0} MINTED batch.fd000001\n{t0 + 60} REVOKED batch.fd000001\n")
        (d / "field.txt").write_text("batch.fd000001\n")
        (d / "mint.log").write_text("minted batch.fd000001 sha256:0123456789ab\n")
        lines = []
        for n, (t, sts) in enumerate(rounds, 1):
            for pod, st in sts.items():
                lines.append(json.dumps({"label": "accept", "round": n, "t": t0 + t, "pod": pod, "status": st}))
        (d / "accept.log").write_text("\n".join(lines) + "\n")
        (d / "records-new.jsonl").write_text(json.dumps({"n": 1, "sent": t0 + vip_first, "status": 200}) + "\n")
        return {"id": "key-lifecycle", "kind": "key-lifecycle", "model": "chat", "cross": "staff",
                "url": "https://llm.ai.tarnwick.example/models/x/v1/chat/completions"}

    def check(self, dd):
        import io  # noqa: PLC0415
        buf = io.StringIO()
        v = self.V.Vocab(verdict="", known=set(), out=buf)
        self.G.analyze_keys(v, {"timing": {"accept_max_s": 300}, "probes": {"gateway": {"models": []}}}, dd, self.d, "1")
        return next(l for l in buf.getvalue().splitlines() if "the first 200 through" in l)

    def test_a_200_before_the_probe_first_round_is_consistent(self):
        line = self.check(self.world([(7.2, {"a1": 200, "b2": 401}), (8.2, {"a1": 200, "b2": 200})], 5.0))
        self.assertTrue(line.startswith("  PASS  "), line)

    def test_a_200_before_a_round_with_no_pod_holding_it_fails(self):
        line = self.check(self.world([(4.0, {"a1": 401, "b2": 401}), (9.0, {"a1": 401, "b2": 401}), (10.0, {"a1": 200, "b2": 200})], 5.0))
        self.assertTrue(line.startswith("  FAIL  "), line)
        self.assertIn("before the probe's round at 9.0 s in which no pod held the key", line)


if __name__ == "__main__":
    unittest.main()
