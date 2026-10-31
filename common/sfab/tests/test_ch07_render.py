"""Chapter 7's render: the Gateways' allowedRoutes and the namespaces labelled for them, the per-pod
key probe's account, the keyed trace's plan with its refusal, the gateway drills' plans
(key-lifecycle, rejected-code, idle-timeout) and break-7a; and the tools the harness adds for them:
the key probe's and the key Jobs' manifests (common/trace/keyprobe.py), the capture scrubber
(common/trace/keyscrub.py) and the key marks (common/trace/servekeys.py).

- With serving on each Gateway's listener admits HTTPRoutes from the namespaces labelled for it,
  and exactly the namespaces the render attaches routes from carry the label; without serving
  (chapters 3 and 4, M2) every Gateway keeps from: All.
- The rejected-code drill's routes differ from the render only by the one route's rejected code
  and message, and both survive sfab-keys compose.
- The idle-timeout drill's corrected values are the rendered ones with the two stream idle keys;
  its corrected route the rendered one with timeouts; a chain that would not outlast the silence
  is refused.
- break-7a holds a pod, mints a key, probes it per pod and through the VIP, restarts the held pod
  and revokes the key in its cleanup; a break whose cleanup revokes a key it never minted, or
  whose heal restarts a pod it never held, is refused.
- The scrubber replaces every Authorization value in a pcap by its mark at the same length, and
  the mark is redact.py's (and servekeys.py's) for the same key.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_ch07_render -v
"""

from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sfab.render import RenderError
from sfab.render import drills as RD
from sfab.render import trace as RT

ROOT = Path(__file__).resolve().parents[3]
CH07 = ROOT / "ch07"
COMMON = ROOT / "common"
DASHES = (chr(0x2014), chr(0x2013))
KEY = "sk-tw-chat-" + "7" * 32
MASTER = "sk-tw-router-" + "8" * 32

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch07():
    if "m" not in _CACHE:
        from sfab.render import Context  # noqa: PLC0415
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415

        spec = load(ROOT)
        ch = load_chapter(CH07)
        m = select(spec, ch)
        ctx = Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-ch07", labdir=CH07, root=ROOT, spec=spec)
        _CACHE.update(m=m, spec=spec, ch=ch, inv=inventory(m), ctx=ctx)
    return _CACHE


def docs(text: str) -> list:
    return [d for d in yaml.safe_load_all(text) if d]


def load_tool(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class GatewayRender(unittest.TestCase):
    def setUp(self):
        from sfab.render import k8s  # noqa: PLC0415

        c = ch07()
        self.m, self.ctx = c["m"], c["ctx"]
        self.out = k8s.render(self.m, self.ctx)

    def test_allowed_routes_and_labels(self):
        gws = {d["metadata"]["name"]: d for d in docs(self.out["bootstrap/k8s/50-gateways.yaml"])}
        for g in ("gw-internal", "gw-users"):
            ar = gws[g]["spec"]["listeners"][0]["allowedRoutes"]
            self.assertEqual(ar["namespaces"], {"from": "Selector", "selector": {"matchLabels": {f"routes.tarnwick.example/{g}": "true"}}})
            self.assertEqual(ar["kinds"], [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}])
        ns = {d["metadata"]["name"]: d["metadata"].get("labels") or {} for d in docs(self.out["bootstrap/k8s/05-namespaces.yaml"])}
        self.assertEqual({k: v for k, v in ns["echo"].items() if k.startswith("routes.")},
                         {"routes.tarnwick.example/gw-internal": "true", "routes.tarnwick.example/gw-users": "true"})
        self.assertFalse([k for k in ns["gateways"] if k.startswith("routes.")], "the Gateways' own namespace attaches no route")
        base = docs(self.out["bootstrap/k8s/60-inference-base.yaml"])
        inf = next(d for d in base if d["kind"] == "Namespace")
        self.assertEqual(inf["metadata"]["labels"]["routes.tarnwick.example/gw-users"], "true")
        self.assertEqual(inf["metadata"]["labels"]["routes.tarnwick.example/gw-internal"], "true")
        self.assertIn("SERVING_NAMESPACE_LABELS=routes.tarnwick.example/gw-internal=true\n", self.out["bootstrap/k8s/serving.env"])
        k8s = json.loads(self.out["gen/k8s.json"])
        # the identity provider is published on both Gateways
        self.assertEqual(k8s["gateways"]["gw-internal"]["allowed_routes"]["namespaces"], ["echo", "identity", "inference", "serving"])
        self.assertEqual(k8s["gateways"]["gw-users"]["allowed_routes"]["namespaces"], ["echo", "identity", "inference"])
        self.assertEqual(k8s["gateways"]["gw-users"]["cec"], "gateways/cilium-gateway-gw-users")

    def test_without_serving_from_all(self):
        from sfab.render import k8s  # noqa: PLC0415
        from sfab.spec import load, select  # noqa: PLC0415

        m = select(load(ROOT), {"lab": "sfab-ch04", "profile": "a", "state": "one",
                                "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2", "k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion",
                                                    "inet-registry", "uplink-rtr", "ops-client", "ent-client"]},
                                "features": {"k8s": True, "serving": False, "storage_setup": False}})
        out = k8s.render(m, self.ctx)
        for g in docs(out["bootstrap/k8s/50-gateways.yaml"]):
            self.assertEqual(g["spec"]["listeners"][0]["allowedRoutes"], {"namespaces": {"from": "All"}})
        for n in docs(out["bootstrap/k8s/05-namespaces.yaml"]):
            self.assertFalse([k for k in (n["metadata"].get("labels") or {}) if k.startswith("routes.")])
        self.assertNotIn("allowed_routes", json.loads(out["gen/k8s.json"])["gateways"]["gw-users"])

    def test_probe_account(self):
        base = docs(self.out["bootstrap/k8s/60-inference-base.yaml"])
        role = next(d for d in base if d["kind"] == "Role" and d["metadata"]["name"] == "key-probe")
        self.assertEqual(role["rules"], [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}])
        self.assertTrue(any(d["kind"] == "ServiceAccount" and d["metadata"]["name"] == "key-probe" for d in base))
        rb = next(d for d in base if d["kind"] == "RoleBinding" and d["metadata"]["name"] == "key-probe")
        self.assertEqual(rb["subjects"], [{"kind": "ServiceAccount", "name": "key-probe", "namespace": "inference"}])
        for text in self.out.values():
            if isinstance(text, str):
                for d in DASHES:
                    self.assertNotIn(d, text)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class TracePlan(unittest.TestCase):
    def setUp(self):
        self.c = ch07()

    def test_keyed_and_refuse(self):
        p = RT.serving_plan(self.c["m"], self.c["ch"].trace["serving"])
        self.assertTrue(p["keys"]["capture"])
        self.assertEqual(p["keys"]["master"], {"secret": "router-master-key", "field": "key"})
        self.assertEqual(p["keys"]["backend"], {"secret": "backend-key", "field": "key"})
        self.assertEqual(p["keys"]["router_path"], "/engines/chat/chat/completions")
        self.assertEqual(p["snaplen"]["keyed"], 2048)
        self.assertEqual(p["refuse"]["url"], "https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused")
        self.assertEqual(p["refuse"]["expect"], 404)
        # the enterprise view publishes no admin name: the refused request is pinned to the users' Gateway
        self.assertEqual(p["refuse"]["resolve"], "admin.ai.tarnwick.example:443:10.20.11.210")
        self.assertIsNone(p["client"]["resolve"], "the users' name is the enterprise view's, answered through ent-dns")

    def test_refuse_refusals(self):
        raw = copy.deepcopy(self.c["ch"].trace["serving"])
        raw["refuse"]["hostname"] = "llm"
        with self.assertRaisesRegex(RenderError, "carries llm.ai.tarnwick.example"):
            RT.serving_plan(self.c["m"], raw)
        raw = copy.deepcopy(self.c["ch"].trace["serving"])
        raw["keys"] = False
        with self.assertRaisesRegex(RenderError, "needs keys: true"):
            RT.serving_plan(self.c["m"], raw)
        raw = copy.deepcopy(self.c["ch"].trace["serving"])
        raw["refuse"]["sport"] = raw["sport"]
        with self.assertRaisesRegex(RenderError, "other than the request's"):
            RT.serving_plan(self.c["m"], raw)

    def test_points_keyed(self):
        sys.path.insert(0, str(COMMON / "trace"))
        import servetrace as ST  # noqa: PLC0415

        p = RT.serving_plan(self.c["m"], self.c["ch"].trace["serving"])
        d = Path(tempfile.mkdtemp(prefix="sfab-test-ch07-pts-"))
        (d / "cluster").mkdir()
        pods = {"items": [{"metadata": {"name": "api-gateway-x", "labels": {"app.kubernetes.io/name": "api-gateway"}},
                           "spec": {"nodeName": "k8s-gpu1"}, "status": {"phase": "Running", "podIP": "10.22.1.5"}},
                          {"metadata": {"name": "router-x", "labels": {"app.kubernetes.io/name": "router"}},
                           "spec": {"nodeName": "k8s-gpu2"}, "status": {"phase": "Running", "podIP": "10.22.2.5"}}]}
        (d / "cluster" / "pods-inference.json").write_text(json.dumps(pods))
        rows = {r[0]: r for r in ST.point_rows(p, d)}
        self.assertEqual(rows["2-api-gateway-x-eth0"][7:], (2048, 1))
        self.assertEqual(rows["3-router-x-eth0"][7:], (2048, 1))
        self.assertTrue(all(r[8] == 0 for k, r in rows.items() if not k.startswith(("2-", "3-"))))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class DrillsPlan(unittest.TestCase):
    def setUp(self):
        self.c = ch07()
        self.plan = RD.drills(self.c["inv"], self.c["ch"].drills, self.c["m"])
        self.by = {d["id"]: d for d in self.plan["list"]}

    def test_kinds_and_layer(self):
        self.assertEqual([(d["id"], d["kind"]) for d in self.plan["list"]],
                         [("key-lifecycle", "key-lifecycle"), ("rejected-code", "rejected-code"), ("idle-timeout", "idle-timeout")])
        gl = self.plan["gateway_layer"]
        self.assertEqual(gl["api_gateway"]["hold"], "/standalone/hold")
        self.assertEqual(gl["keys"]["sa"], "inference-keys")
        self.assertEqual(gl["probe"]["sa"], "key-probe")
        self.assertEqual(gl["gateways"], ["gw-internal", "gw-users"])
        self.assertEqual(self.by["idle-timeout"]["max_passes"], 1)
        self.assertEqual(self.plan["timing"]["accept_max_s"], 300)

    def test_rejected_code_routes(self):
        d = self.by["rejected-code"]
        r, v = d["configmap_rendered"], d["configmap_default"]
        self.assertEqual(r["metadata"], v["metadata"])
        a, b = r["data"]["apisix.yaml"].splitlines(), v["data"]["apisix.yaml"].splitlines()
        import collections  # noqa: PLC0415

        gone = collections.Counter(x.strip() for x in a) - collections.Counter(x.strip() for x in b)
        self.assertEqual(sorted(gone.elements()), ["rejected_code: 401", 'rejected_msg: "Authorization Failed"'])
        self.assertFalse(collections.Counter(b) - collections.Counter(a), "nothing added")
        routes = yaml.safe_load(v["data"]["apisix.yaml"].replace("#END", ""))["routes"]
        cr = {x["id"]: x["plugins"]["consumer-restriction"] for x in routes}
        self.assertEqual(cr["staff"], {"type": "consumer_group_id", "whitelist": ["helpdesk", "staff"]})
        self.assertEqual(cr["chat"]["rejected_code"], 401)
        keys = load_tool("sfab_keys_ch07", ROOT / "images" / "keys" / "sfab-keys")
        for text in (r["data"]["apisix.yaml"], v["data"]["apisix.yaml"]):
            out = keys.composed(text, [("batch", "0a1b2c3d", KEY)], "Bearer {key}")
            self.assertTrue(out.endswith("#END\n"))
        self.assertEqual(d["expect"], {"default": 403, "rendered": 401, "rendered_message": "Authorization Failed"})

    def test_idle_timeout_plan(self):
        d = self.by["idle-timeout"]
        vr, vc = d["cilium"]["values_rendered"], d["cilium"]["values_corrected"]
        self.assertNotIn("extraConfig", vr)
        self.assertNotIn("streamIdleTimeoutDurationSeconds", vr["envoy"])
        self.assertEqual(vc["extraConfig"], {"proxy-stream-idle-timeout-seconds": "600"})
        self.assertEqual(vc["envoy"]["streamIdleTimeoutDurationSeconds"], 600)
        self.assertEqual({k: x for k, x in vc.items() if k != "extraConfig"} | {"envoy": vr["envoy"]}, vr)
        rr, rc = d["test_backend"]["route_rendered"], d["test_backend"]["route_corrected"]
        self.assertNotIn("timeouts", rr["spec"]["rules"][0])
        self.assertEqual(rc["spec"]["rules"][0]["timeouts"], {"request": "420s", "backendRequest": "400s"})
        self.assertEqual(rr["metadata"]["name"], "echo-gw-users")
        self.assertEqual(d["url"], "https://llm.ai.tarnwick.example/echo?msg=sfab-drill-idle")
        self.assertEqual(d["cec"], "gateways/cilium-gateway-gw-users")
        self.assertEqual(d["cilium"]["config_keys"], ["http-stream-idle-timeout", "proxy-stream-idle-timeout-seconds"])

    def test_refusals(self):
        raw = copy.deepcopy(self.c["ch"].drills)
        it = next(x for x in raw["list"] if x["id"] == "idle-timeout")
        it["idle_timeout"]["silent_s"] = 200
        with self.assertRaisesRegex(RenderError, "must outlast Envoy's default"):
            RD.drills(self.c["inv"], raw, self.c["m"])
        raw = copy.deepcopy(self.c["ch"].drills)
        it = next(x for x in raw["list"] if x["id"] == "idle-timeout")
        it["idle_timeout"]["corrected"]["stream_idle_s"] = 320
        with self.assertRaisesRegex(RenderError, "must outlast the silence"):
            RD.drills(self.c["inv"], raw, self.c["m"])
        raw = copy.deepcopy(self.c["ch"].drills)
        kl = next(x for x in raw["list"] if x["id"] == "key-lifecycle")
        kl["key_lifecycle"]["cross"] = "chat"
        with self.assertRaisesRegex(RenderError, "another model"):
            RD.drills(self.c["inv"], raw, self.c["m"])
        raw = copy.deepcopy(self.c["ch"].drills)
        kl = next(x for x in raw["list"] if x["id"] == "key-lifecycle")
        kl["probes"] = []
        with self.assertRaisesRegex(RenderError, "must lose nothing"):
            RD.drills(self.c["inv"], raw, self.c["m"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Break7a(unittest.TestCase):
    def setUp(self):
        self.c = ch07()
        from sfab.spec import read_yaml  # noqa: PLC0415

        self.raw = read_yaml(CH07 / "breaks" / "7a.yaml")

    def test_resolved(self):
        b = RD._break(self.c["inv"], "7a", self.raw, self.c["m"])
        self.assertEqual([a["kind"] for a in b["break"]], ["key_hold", "key_mint"])
        self.assertEqual(b["break"][0]["index"], 1)
        # the new key for chat is the batch application's (the caller that stands for chat)
        self.assertEqual(b["break"][1]["field"], "batch.fa000001")
        pr = b["record"][0]
        self.assertEqual((pr["kind"], pr["field"], pr["expect"], pr["route"]), ("key_probe", "batch.fa000001", 200, "chat"))
        self.assertEqual(b["record"][1]["key"], "batch.fa000001")
        self.assertEqual([a["kind"] for a in b["heal"]], ["gateway_restart"])
        self.assertEqual([a["kind"] for a in b["cleanup"]], ["key_revoke"])
        self.assertEqual(b["expect_broken"][0], {"kind": "key_pods", "probe": "pods", "refusing": "held"})

    def test_refused(self):
        raw = copy.deepcopy(self.raw)
        raw["cleanup"] = [{"key_revoke": {"model": "chat", "id": "fa000002"}}]
        with self.assertRaisesRegex(RenderError, "revokes a key break: does not mint"):
            RD._break(self.c["inv"], "7a", raw, self.c["m"])
        raw = copy.deepcopy(self.raw)
        raw["break"] = [{"key_mint": {"model": "chat", "id": "fa000001"}}]
        with self.assertRaisesRegex(RenderError, "holds none|holds no API gateway pod"):
            RD._break(self.c["inv"], "7a", raw, self.c["m"])
        raw = copy.deepcopy(self.raw)
        raw["expect_broken"] = [{"probe_share": {"probe": "pods", "failing": "some"}}]
        with self.assertRaisesRegex(RenderError, "a key_probe: its check is key_pods"):
            RD._break(self.c["inv"], "7a", raw, self.c["m"])

    def test_breaks_without_cleanup_render_as_before(self):
        from sfab.spec import read_yaml  # noqa: PLC0415

        c6 = ROOT / "ch06" / "breaks" / "6a.yaml"
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415
        from sfab.render.inventory import inventory  # noqa: PLC0415

        m6 = select(load(ROOT), load_chapter(ROOT / "ch06"))
        b = RD._break(inventory(m6), "6a", read_yaml(c6), m6)
        self.assertNotIn("cleanup", b)


class Tools(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(COMMON / "audit"))
        sys.path.insert(0, str(COMMON / "trace"))
        import keyscrub  # noqa: PLC0415
        import redact  # noqa: PLC0415

        self.ks, self.redact = keyscrub, redact
        self.key = b"0123456789abcdef0123456789abcdef"

    @staticmethod
    def pcap(payloads: list) -> bytes:
        out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        for i, pl in enumerate(payloads):
            eth = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00"
            tcp = struct.pack("!HHIIBBHHH", 41000, 9080, 1, 1, 0x50, 0x18, 502, 0, 0)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(pl), 1, 0, 64, 6, 0, bytes([10, 22, 9, 7]), bytes([10, 22, 1, 12]))
            frame = eth + ip + tcp + pl
            out += struct.pack("<IIII", 1792611812 + i, 0, len(frame), len(frame)) + frame
        return out

    def test_scrub_pcap(self):
        p1 = (b"POST /models/x/v1/chat/completions HTTP/1.1\r\nhost: llm.ai.tarnwick.example\r\nauthorization: Bearer " + KEY.encode()
              + b"\r\ncontent-type: application/json\r\n\r\n")
        p2 = b"POST /engines/chat/chat/completions HTTP/1.1\r\nAuthorization: Bearer " + MASTER.encode() + b"\r\n\r\n{\"k\": \"" + KEY.encode() + b"\"}"
        raw = self.pcap([p1, p2, b"GET /health/readiness HTTP/1.1\r\n\r\n"])
        out, n, bad = self.ks.scrub_pcap(raw, self.key)
        self.assertEqual((n, bad), (3, 0))
        self.assertEqual(len(out), len(raw))
        self.assertNotIn(KEY.encode(), out)
        self.assertNotIn(MASTER.encode(), out)
        mark = self.redact.mark(KEY, self.key).encode()
        self.assertIn(b"authorization: Bearer " + mark, out)
        self.assertIn(b"Authorization: Bearer " + self.redact.mark(MASTER, self.key).encode(), out)
        again, n2, _ = self.ks.scrub_pcap(out, self.key)
        self.assertEqual((again, n2), (out, 0), "a second pass changes nothing")
        junk, _, bad = self.ks.scrub_pcap(b"\x00" * 30, self.key)
        self.assertEqual(bad, 1)
        self.assertEqual(junk[24:], b"_" * 6)

    def test_scrub_blanks_timings(self):
        body = (b'{"choices":[],"timings":{"cache_n":24,"prompt_n":15,"prompt_ms":62.187,"prompt_per_token_ms":4.1458,'
                b'"prompt_per_second":241.2,"predicted_n":16,"predicted_ms":181.156,"predicted_per_token_ms":12.077,"predicted_per_second":82.8}}')
        raw = self.pcap([b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n" + body])
        counts: dict = {}
        out, n, bad = self.ks.scrub_pcap(raw, self.key, counts)
        self.assertEqual((n, bad, counts["timings"]), (0, 0, 6))
        self.assertEqual(len(out), len(raw))
        self.assertIn(b'"prompt_n":15,"prompt_ms":______,', out)
        self.assertIn(b'"predicted_per_second":____}}', out)
        self.assertNotIn(b"82.8", out)
        again, _, _ = self.ks.scrub_pcap(out, self.key, counts)
        self.assertEqual(again, out, "a second pass changes nothing")
        text, nt = self.ks.blank_timings(body)
        self.assertEqual(nt, 6)
        self.assertNotIn(b"241.2", text)
        line = '{"x":1,"predicted_per_second":82.8,"predicted_n":16}\n'
        self.assertEqual(self.redact.redact_text(line, []), '{"x":1,"predicted_per_second":[redacted: throughput],"predicted_n":16}\n')

    def test_scrub_text_and_servekeys_mark(self):
        text = f"Authorization: Bearer {KEY}\nnothing else {MASTER}\n".encode()
        out, n = self.ks.scrub_bytes(text, self.key)
        self.assertEqual(n, 2)
        self.assertNotIn(KEY.encode(), out)
        import base64  # noqa: PLC0415

        d = Path(tempfile.mkdtemp(prefix="sfab-test-ch07-sk-"))
        kf = d / "redact.key"
        kf.write_text(self.key.decode())
        doc = {"data": {"key": base64.b64encode(MASTER.encode()).decode(), "chat.0a1b2c3d": base64.b64encode(KEY.encode()).decode()}}
        r = subprocess.run([sys.executable, str(COMMON / "trace" / "servekeys.py"), "mark", "--field", "key", "--mark-key", str(kf)],
                           input=json.dumps(doc), capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split()[2:], self.redact.mark(MASTER, self.key).split())
        self.assertNotIn(MASTER, r.stdout + r.stderr)
        r = subprocess.run([sys.executable, str(COMMON / "trace" / "servekeys.py"), "which", "--model", "chat", "--mark-key", str(kf)],
                           input=json.dumps(doc), capture_output=True, text=True)
        self.assertRegex(r.stdout, r"^chat\.0a1b2c3d sha256:[0-9a-f]{12} <redacted hmac:[0-9a-f]{12}>$")
        r = subprocess.run([sys.executable, str(COMMON / "trace" / "servekeys.py"), "list"], input=json.dumps(doc), capture_output=True, text=True)
        self.assertEqual([l.split()[0] for l in r.stdout.splitlines()], ["chat.0a1b2c3d", "key"])
        self.assertNotIn(KEY, r.stdout)

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
    def test_keyprobe_manifests(self):
        from sfab.render import k8s  # noqa: PLC0415

        c = ch07()
        kj = Path(tempfile.mkdtemp(prefix="sfab-test-ch07-kp-")) / "k8s.json"
        kj.write_text(k8s.render(c["m"], c["ctx"])["gen/k8s.json"])
        kp = COMMON / "trace" / "keyprobe.py"
        r = subprocess.run([sys.executable, str(kp), "pod", "--k8s", str(kj), "--name", "key-probe-t", "--check", "own-chat", "chat",
                            "chat.0a1b2c3d", "200", "--check", "cross", "staff", "chat.0a1b2c3d", "401", "--repeat", "--max-s", "60"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        pod = json.loads(r.stdout)
        sp = pod["spec"]
        self.assertEqual(sp["serviceAccountName"], "key-probe")
        self.assertEqual(sp["securityContext"]["runAsUser"], 65532)
        self.assertEqual(sp["volumes"][0]["secret"]["secretName"], "api-keys")
        c0 = sp["containers"][0]
        self.assertEqual(c0["securityContext"], {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}})
        script = c0["command"][2]
        self.assertEqual(script.count("sfab-keys probe"), 2)
        self.assertIn("--key-file /keys/chat.0a1b2c3d", script)
        self.assertIn("--json", script)
        self.assertIn("--repeat --interval 1.0 --max-s 60.0", script)
        self.assertIn(f"/models/{c['m'].models['staff'].route_id}/v1/chat/completions", script)
        r = subprocess.run([sys.executable, str(kp), "job", "--k8s", str(kj), "--name", "key-probe-mint", "--mint", "--model", "chat", "--id",
                            "fd000001"], capture_output=True, text=True)
        job = json.loads(r.stdout)
        self.assertEqual(job["spec"]["template"]["spec"]["containers"][0]["command"],
                         ["sfab-keys", "mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "batch",
                          "--id", "fd000001"])
        self.assertEqual(job["spec"]["template"]["spec"]["serviceAccountName"], "inference-keys")
        r = subprocess.run([sys.executable, str(kp), "job", "--k8s", str(kj), "--name", "x", "--revoke", "--model", "nope", "--id", "fd000001"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)



class OperatorLoadPin(unittest.TestCase):
    """Chapter 7's operator resolves through ops-dns, whose public view publishes no platform name in
    state one, so make load and make client name the internal Gateway's VIP for the recipe's host."""

    def test_the_load_names_the_vip(self):
        env = dict(l.split("=", 1) for l in (CH07 / "bootstrap" / "k8s" / "serving.env").read_text().splitlines()
                   if l and not l.startswith("#") and "=" in l)
        self.assertEqual(env.get("SERVING_LOAD_RESOLVE"), "serve.ai.tarnwick.example:443:10.20.11.200")
        self.assertEqual(env.get("SERVING_LOAD_EXEC"), "'docker exec -i sfab-ch07-ops-client'")


if __name__ == "__main__":
    unittest.main()
