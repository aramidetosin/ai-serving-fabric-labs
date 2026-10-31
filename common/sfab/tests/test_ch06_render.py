"""Chapter 6's render: the API gateway and the router (render/inference.py), the pods' fixed rail
MACs and the MAC tables that expect them, the serving trace's plan (sfab.render.trace), the serving
drills and break-6a (sfab.render.drills).

- The inference files exist only with serving on; they hold no key; the API gateway's routes
  authenticate the key on the Authorization header, restrict it to the model's group with 401, and
  rewrite to the router's path for the model with the master key from the environment; the
  router's deployments sit on the models' Services; the timeouts nest; one model route per
  Gateway; the key Job ensures the master key, mints the first key a model and copies the
  recipe's key; the base routes survive sfab-keys compose.
- Every placement row has a MAC that names its rail and address, given once; each rail switch
  expects the MACs of the rows on its rails at the port facing the row's node.
- The trace plan follows chat's copies with their workers on the other node and beside the server.
- The drills plan: which copies a dark switch and a worker's port take out; a worker beside its
  server is refused; the rail-move row; break-6a's moved row, its MAC and the heal's wait; break-6b's
  rerouted server, the copy of its attachment, the pod network it routes and the peer it is tried from.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_ch06_render -v
"""

from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from sfab.render import RenderError
from sfab.render import drills as RD
from sfab.render import trace as RT

ROOT = Path(__file__).resolve().parents[3]
CH06 = ROOT / "ch06"
DASHES = (chr(0x2014), chr(0x2013))

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch06():
    if "m" not in _CACHE:
        from sfab.render import Context  # noqa: PLC0415
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415

        spec = load(ROOT)
        ch = load_chapter(CH06)
        m = select(spec, ch)
        ctx = Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-ch06", labdir=CH06, root=ROOT, spec=spec)
        _CACHE.update(m=m, spec=spec, ch=ch, inv=inventory(m), ctx=ctx)
    return _CACHE


def docs(text: str) -> list:
    return [d for d in yaml.safe_load_all(text) if d]


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class InferenceRender(unittest.TestCase):
    def setUp(self):
        from sfab.render import inference, k8s  # noqa: PLC0415

        c = ch06()
        self.m, self.ctx = c["m"], c["ctx"]
        self.out = k8s.render(self.m, self.ctx)
        self.s = inference.settings(self.m)

    def test_files_and_no_key(self):
        names = sorted(k for k in self.out if "inference" in k)
        self.assertEqual(names, ["bootstrap/k8s/60-inference-base.yaml", "bootstrap/k8s/61-inference-keys.yaml",
                                 "bootstrap/k8s/62-inference.yaml", "bootstrap/k8s/63-inference-policy.yaml"])
        self.assertNotIn("60-inference-base.yaml", self.out["bootstrap/k8s/apply.list"], "finish applies them after the recipe")
        for n in names:
            text = self.out[n]
            self.assertIsNone(re.search(r"sk-tw-[a-z]+-[0-9a-f]{32}", text), n)
            for d in DASHES:
                self.assertNotIn(d, text, n)
        k8s = json.loads(self.out["gen/k8s.json"])
        self.assertEqual(k8s["inference"]["namespace"], "inference")
        self.assertEqual(k8s["inference"]["files"]["layer"], "62-inference.yaml")

    def test_no_inference_without_serving(self):
        from sfab.render import inference, k8s  # noqa: PLC0415
        from sfab.spec import load, select  # noqa: PLC0415

        m = select(load(ROOT), {"lab": "sfab-ch04", "profile": "a", "state": "one",
                                "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2", "k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion",
                                                    "inet-registry", "uplink-rtr", "ops-client", "ent-client"]},
                                "features": {"k8s": True, "serving": False, "storage_setup": False}})
        self.assertFalse(inference.enabled(m))
        out = k8s.render(m, self.ctx)
        self.assertFalse([k for k in out if "inference" in k])
        self.assertNotIn("inference", json.loads(out["gen/k8s.json"]))

    def test_api_gateway(self):
        d = docs(self.out["bootstrap/k8s/62-inference.yaml"])
        cms = {x["metadata"]["name"]: x for x in d if x["kind"] == "ConfigMap"}
        conf = yaml.safe_load(cms["api-gateway-config"]["data"]["config.yaml"])
        self.assertEqual(conf["deployment"], {"role": "data_plane", "role_data_plane": {"config_provider": "yaml"}})
        self.assertFalse(conf["apisix"]["enable_admin"])
        self.assertEqual(conf["nginx_config"]["envs"], ["ROUTER_MASTER_KEY"])
        base = cms["api-gateway-routes"]["data"]["apisix.yaml"]
        self.assertTrue(base.endswith("#END\n"))
        routes = yaml.safe_load(base.replace("#END", ""))
        chat = next(r for r in routes["routes"] if r["id"] == "chat")
        rid = self.m.models["chat"].route_id
        self.assertEqual(chat["uris"], [f"/models/{rid}/v1/chat/completions", f"/models/{rid}/v1/completions"])
        self.assertEqual(chat["methods"], ["POST"])
        pl = chat["plugins"]
        # a key first, then a person's token (the identity provider is on in this lab)
        auth = pl["multi-auth"]["auth_plugins"]
        self.assertEqual(auth[0], {"key-auth": {"header": "Authorization", "hide_credentials": True}})
        self.assertEqual(auth[1]["oidc-consumer"], {"issuer": "https://id.ai.tarnwick.example", "audience": "ai-gateway", "claim": "email",
                                                    "jwks_uri": "http://idp.identity.svc.cluster.local:5556/keys"})
        # the callers that may call chat: the batch application and the staff
        self.assertEqual(pl["consumer-restriction"]["whitelist"], ["batch", "staff"])
        self.assertEqual(pl["consumer-restriction"]["rejected_code"], 401)
        self.assertEqual(pl["consumer-restriction"]["rejected_msg"], "Authorization Failed")
        self.assertEqual(pl["response-rewrite"], {"headers": {"set": {"WWW-Authenticate": 'Bearer realm="llm.ai.tarnwick.example"'}},
                                                  "vars": [["status", "==", 401]]})
        self.assertEqual(pl["file-logger"]["log_format"]["consumer"], "$consumer_name")
        self.assertNotIn("Authorization", json.dumps(pl["file-logger"]))
        self.assertEqual(pl["proxy-rewrite"]["regex_uri"][1], "/engines/chat/$1")
        self.assertEqual(pl["proxy-rewrite"]["headers"]["set"]["Authorization"], "Bearer ${{ROUTER_MASTER_KEY}}")
        self.assertEqual([g["id"] for g in routes["consumer_groups"]], ["batch", "helpdesk", "staff"])
        groups = {g["id"]: g for g in routes["consumer_groups"]}
        self.assertEqual(groups["staff"]["plugins"]["limit-count"],
                         {"count": 600, "time_window": 60, "key_type": "var", "key": "consumer_group_id", "rejected_code": 429, "policy": "local"})
        self.assertEqual(routes["consumers"], [{"username": "staff_ent_client", "group_id": "staff",
                                                "plugins": {"oidc-consumer": {"subject": "ent-client@tarnwick.example"}}}])
        self.assertIn("multi-auth", conf["plugins"])
        self.assertIn("oidc-consumer", conf["plugins"])
        up = routes["upstreams"][0]
        self.assertEqual(up["nodes"], [{"host": "router.inference.svc.cluster.local", "port": 4000, "weight": 1}])
        self.assertEqual(up["timeout"]["read"], 600)
        dep = next(x for x in d if x["kind"] == "Deployment" and x["metadata"]["name"] == "api-gateway")
        sp = dep["spec"]["template"]["spec"]
        self.assertEqual(dep["spec"]["replicas"], 2)
        self.assertEqual(sp["securityContext"]["runAsUser"], 636)
        self.assertEqual([c["name"] for c in sp["initContainers"]], ["compose"])
        self.assertEqual([c["name"] for c in sp["containers"]], ["apisix", "keys"])
        ap = sp["containers"][0]
        self.assertTrue(ap["image"].startswith("docker.io/apache/apisix@sha256:"))
        self.assertEqual(ap["env"], [{"name": "ROUTER_MASTER_KEY", "valueFrom": {"secretKeyRef": {"name": "router-master-key", "key": "key"}}}])
        self.assertIn({"name": "standalone", "mountPath": "/usr/local/apisix/conf/apisix.yaml", "subPath": "apisix.yaml"}, ap["volumeMounts"])
        self.assertIn("--hold", sp["containers"][1]["command"])
        self.assertIn("--once", sp["initContainers"][0]["command"])
        self.assertEqual(sp["volumes"][2]["secret"]["secretName"], "api-keys")
        self.assertIn({"name": "plugins", "mountPath": "/usr/local/apisix/apisix/plugins/oidc-consumer.lua",
                       "subPath": "oidc-consumer.lua", "readOnly": True}, ap["volumeMounts"])
        # on the ingress nodes, tolerating their taint
        self.assertEqual(sp["nodeSelector"], {"node-role.tarnwick.example/ingress": ""})
        self.assertEqual(sp["tolerations"], [{"key": "node-role.tarnwick.example/ingress", "operator": "Exists", "effect": "NoSchedule"}])
        plug = next(x for x in d if x["kind"] == "ConfigMap" and x["metadata"]["name"] == "api-gateway-plugins")
        self.assertIn('name = plugin_name', plug["data"]["oidc-consumer.lua"])

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "PyYAML")
    def test_base_routes_survive_compose(self):
        loader = importlib.machinery.SourceFileLoader("sfab_keys_ch06", str(ROOT / "images" / "keys" / "sfab-keys"))
        spec = importlib.util.spec_from_loader("sfab_keys_ch06", loader)
        keys = importlib.util.module_from_spec(spec)
        loader.exec_module(keys)
        d = docs(self.out["bootstrap/k8s/62-inference.yaml"])
        base = next(x for x in d if x["kind"] == "ConfigMap" and x["metadata"]["name"] == "api-gateway-routes")["data"]["apisix.yaml"]
        text = keys.composed(base, [("batch", "0a1b2c3d", "sk-tw-batch-" + "1" * 32), ("helpdesk", "0a1b2c3e", "sk-tw-helpdesk-" + "2" * 32)],
                             "Bearer {key}")
        doc = yaml.safe_load(text.replace("#END", ""))
        # the people's consumers come with the base; each key adds one to its caller's group
        self.assertEqual([(c["username"], c["group_id"]) for c in doc["consumers"]],
                         [("staff_ent_client", "staff"), ("batch_key_0a1b2c3d", "batch"), ("helpdesk_key_0a1b2c3e", "helpdesk")])
        self.assertEqual(doc["routes"][0]["plugins"]["proxy-rewrite"]["headers"]["set"]["Authorization"], "Bearer ${{ROUTER_MASTER_KEY}}")
        self.assertTrue(text.endswith("#END\n"))

    def test_router(self):
        d = docs(self.out["bootstrap/k8s/62-inference.yaml"])
        cfg = yaml.safe_load(next(x for x in d if x["kind"] == "ConfigMap" and x["metadata"]["name"] == "router-config")["data"]["config.yaml"])
        self.assertEqual([m["model_name"] for m in cfg["model_list"]], ["chat", "staff"])
        p = cfg["model_list"][0]["litellm_params"]
        self.assertEqual(p, {"model": "openai/chat", "api_base": "http://chat.serving.svc.cluster.local:8080/v1",
                             "api_key": "os.environ/SERVING_KEY", "timeout": 280, "stream_timeout": 60, "max_retries": 0})
        self.assertEqual(cfg["router_settings"]["num_retries"], 1)
        self.assertEqual(cfg["general_settings"], {"master_key": "os.environ/ROUTER_MASTER_KEY"})
        dep = next(x for x in d if x["kind"] == "Deployment" and x["metadata"]["name"] == "router")
        c = dep["spec"]["template"]["spec"]["containers"][0]
        env = {e["name"]: e for e in c["env"]}
        self.assertEqual(env["SERVING_KEY"]["valueFrom"]["secretKeyRef"], {"name": "backend-key", "key": "key"})
        self.assertEqual(env["LITELLM_LOCAL_MODEL_COST_MAP"]["value"], "True")
        self.assertEqual(c["readinessProbe"]["httpGet"]["path"], "/health/readiness")
        self.assertEqual(dep["spec"]["template"]["spec"]["securityContext"]["runAsUser"], 65532)

    def test_routes_and_timeouts(self):
        d = docs(self.out["bootstrap/k8s/62-inference.yaml"])
        rts = {x["metadata"]["name"]: x for x in d if x["kind"] == "HTTPRoute"}
        self.assertEqual(sorted(rts), ["models-gw-internal", "models-gw-users"])
        users = rts["models-gw-users"]["spec"]
        self.assertEqual(users["hostnames"], ["llm.ai.tarnwick.example"])
        self.assertEqual([r["matches"][0]["path"]["value"] for r in users["rules"]],
                         [f"/models/{self.m.models[x].route_id}" for x in ("chat", "staff")])
        internal = rts["models-gw-internal"]["spec"]
        self.assertEqual([r["matches"][0]["path"]["value"] for r in internal["rules"]], ["/models"])
        for r in users["rules"] + internal["rules"]:
            self.assertEqual(r["timeouts"], {"request": "620s", "backendRequest": "620s"})
            self.assertEqual(r["backendRefs"], [{"name": "api-gateway", "port": 9080}])
        t = self.s["timeouts"]
        self.assertLess((t["router_retries"] + 1) * t["router_attempt_s"], t["gateway_read_s"])
        self.assertLess(t["gateway_read_s"], t["backend_request_s"])
        self.assertLessEqual(t["backend_request_s"], t["request_s"])

    def test_keys_job_and_roles(self):
        (job,) = docs(self.out["bootstrap/k8s/61-inference-keys.yaml"])
        cmd = job["spec"]["template"]["spec"]["containers"][0]["command"]
        lines = cmd[2].strip().splitlines()
        self.assertEqual(lines[0], "set -e")
        self.assertEqual(lines[1], "sfab-keys ensure --namespace inference --secret router-master-key --field key --prefix sk-tw-router")
        self.assertEqual(lines[2], "sfab-keys mint --namespace inference --secret api-keys --prefix sk-tw --model batch --if-none")
        self.assertEqual(lines[3], "sfab-keys mint --namespace inference --secret api-keys --prefix sk-tw --model helpdesk --if-none")
        self.assertEqual(lines[4], "sfab-keys copy --from-namespace serving --from-secret llm-api-key --field key --namespace inference "
                                   "--secret backend-key")
        base = docs(self.out["bootstrap/k8s/60-inference-base.yaml"])
        self.assertEqual(base[0]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")
        roles = [x for x in base if x["kind"] == "Role"]
        self.assertEqual(roles[0]["rules"][0]["resourceNames"], ["router-master-key", "api-keys", "backend-key"])
        self.assertEqual((roles[1]["metadata"]["namespace"], roles[1]["rules"][0]["resourceNames"], roles[1]["rules"][0]["verbs"]),
                         ("serving", ["llm-api-key"], ["get"]))

    def test_refusals(self):
        from sfab.render import inference  # noqa: PLC0415

        cases = {
            "timeouts that do not nest": {"route": {"request_s": 50, "backend_request_s": 40}},
            "the recipe's namespace": {"namespace": "serving"},
            "one Secret for two kinds of key": {"keys": {"models": {"secret": "k"}, "master": {"secret": "k", "field": "key", "prefix": "router"},
                                                         "backend": {"secret": "b"}}},
            "a path ending in a slash": {"path": "/models/"},
        }
        for what, over in cases.items():
            m = copy.copy(self.m)
            spec = copy.deepcopy(self.m.spec)
            spec["inference"].update(over)
            object.__setattr__(m, "spec", spec)
            with self.subTest(what=what), self.assertRaises(RenderError):
                inference.settings(m)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class PodMacs(unittest.TestCase):
    def test_rows_and_switches(self):
        from sfab.render import expect, k8s  # noqa: PLC0415

        m = ch06()["m"]
        rows = k8s.placement(m)
        macs = [r["mac"] for r in rows]
        self.assertEqual(len(set(macs)), len(macs))
        r0 = next(r for r in rows if r["pod"] == "chat-a-worker0-0")
        self.assertEqual((r0["address"], r0["mac"]), ("10.21.3.101/24", "02:5a:fe:03:00:65"))
        env = k8s.serving_env(m, ch06()["ctx"])
        self.assertIn("SERVING_POD_COLUMNS='pod model copy role index node rail nad address decision mac'", env)
        km = expect.expect(m, m.switches["rail-sw1"])["known_macs"]
        self.assertEqual(km["02:5a:fe:03:00:65"], {"node": "k8s-gpu1", "pod": "chat-a-worker0-0", "vlan": 103, "via": "Ethernet1", "source": "pod-macvlan"})
        self.assertEqual(km["02:5a:fe:07:00:65"], {"node": "k8s-gpu2", "pod": "chat-c-worker0-0", "vlan": 107, "via": "Ethernet7", "source": "pod-macvlan"})
        self.assertNotIn("02:5a:fe:06:00:64", km, "rail 6 is rail-sw2's")
        guests = {n.mac for h in m.nodes.values() for n in getattr(h, "nics", ()) if getattr(n, "mac", None)}
        self.assertFalse(set(macs) & guests)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class TracePlan(unittest.TestCase):
    def test_serving_plan(self):
        c = ch06()
        p = RT.serving_plan(c["m"], c["ch"].trace["serving"])
        self.assertEqual(p["kind"], "serving")
        self.assertEqual(p["url"], f"https://llm.ai.tarnwick.example/models/{c['m'].models['chat'].route_id}/v1/chat/completions")
        self.assertFalse(p["client"]["pin"], "the enterprise client's resolver is the lab's bastion")
        self.assertEqual(p["gateway"]["lease"], "kube-system/cilium-l2announce-gateways-cilium-gateway-gw-users")
        a = next(x for x in p["copies"] if x["copy"] == "a")
        self.assertEqual((a["rail"], a["nad"], a["switch"], a["spans"]), (3, "rail3", "rail-sw1", False))
        self.assertEqual([(w["pod"], w["remote"]) for w in a["workers"]], [("chat-a-worker0-0", False)])
        self.assertEqual([(x["native"], x["faces"]) for x in a["switch_ports"]], [("Ethernet1", "k8s-gpu1")])
        c_ = next(x for x in p["copies"] if x["copy"] == "c")
        self.assertEqual((c_["rail"], c_["nad"], c_["switch"], c_["spans"]), (7, "rail7", "rail-sw1", True))
        self.assertEqual([(w["pod"], w["remote"]) for w in c_["workers"]], [("chat-c-worker0-0", True), ("chat-c-worker1-0", False)])
        self.assertEqual([(x["native"], x["faces"]) for x in c_["switch_ports"]], [("Ethernet3", "k8s-gpu1"), ("Ethernet7", "k8s-gpu2")])
        self.assertEqual(p["pin"], {"copy": "c", "tries": 12, "server": "chat-c-server-0", "container": "server"})
        self.assertEqual(p["snaplen"]["http"], 66)
        for bad in ({"client": "k8s-gpu1", "gateway": "gw-users", "model": "chat", "sport": 42606},
                    {"client": "ent-client", "gateway": "gw-internal", "model": "chat", "sport": 42606},
                    {"client": "ent-client", "gateway": "gw-users", "model": "nope", "sport": 42606},
                    {"client": "ent-client", "gateway": "gw-users", "model": "chat", "sport": 80},
                    {"client": "ent-client", "gateway": "gw-users", "model": "chat", "sport": 42606, "extra": 1},
                    {"client": "ent-client", "gateway": "gw-users", "model": "chat", "sport": 42606, "copy": "z"},
                    {"client": "ent-client", "gateway": "gw-users", "model": "chat", "sport": 42606, "tries": 3},
                    {"client": "ent-client", "gateway": "gw-users", "model": "chat", "sport": 42606, "copy": "c", "tries": 0}):
            with self.subTest(bad=bad), self.assertRaises(RenderError):
                RT.serving_plan(c["m"], bad)

    def test_committed(self):
        c = ch06()
        want = json.loads((CH06 / "gen" / "trace.json").read_text())
        self.assertEqual(RT.serving_plan(c["m"], c["ch"].trace["serving"]), want)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class DrillsPlan(unittest.TestCase):
    def setUp(self):
        c = ch06()
        self.m, self.inv, self.raw = c["m"], c["inv"], copy.deepcopy(c["ch"].drills)

    def plan(self, raw=None):
        return RD.drills(self.inv, raw or self.raw, self.m)

    def test_committed(self):
        self.assertEqual(json.loads(RD.dumps(self.plan())), json.loads((CH06 / "gen" / "drills.json").read_text()))

    def test_drills(self):
        p = self.plan()
        d = {x["id"]: x for x in p["list"]}
        dk = d["dark-switch"]
        self.assertEqual((dk["kind"], dk["switch"], dk["klish"][1]), ("serve-dark", "rail-sw1", "interface range Ethernet0-7"))
        # the copy that spans the nodes loses its RPC across the dark switch; the node-local copies on its
        # rails keep theirs inside their nodes (the virtual switch drops no carrier: KNOWN L9)
        self.assertEqual(dk["expect"]["dead_copies"], ["chat-c"])
        self.assertEqual(dk["expect"]["in_node"], ["chat-a", "staff-b"])
        self.assertEqual(dk["expect"]["services"]["chat"]["while_down"], ["chat-a-server-0", "chat-b-server-0"])
        self.assertEqual(dk["expect"]["services"]["chat-a"]["while_down"], ["chat-a-server-0"])
        self.assertEqual(dk["expect"]["services"]["chat-c"]["while_down"], [])
        wp = d["worker-port"]
        self.assertEqual((wp["switch"], wp["natives"], wp["klish"][1]), ("rail-sw1", ["Ethernet7"], "interface Ethernet7"))
        self.assertEqual(wp["expect"]["dead_copies"], ["chat-c"])
        self.assertEqual(wp["expect"]["in_node"], [])
        self.assertEqual(wp["expect"]["services"]["staff"]["while_down"], ["staff-a-server-0", "staff-b-server-0"])
        rm = d["rail-move"]
        self.assertEqual((rm["row"]["rail"], rm["moved"]["rail"], rm["moved"]["address"], rm["moved"]["mac"]),
                         (3, 5, "10.21.5.102/24", "02:5a:fe:05:00:66"))
        self.assertEqual(p["probes"]["gateway"]["models"][1]["model"], "staff")
        self.assertEqual((p["probes"]["gateway"]["interval_s"], p["probes"]["gateway"]["timeout_s"]), (2, 400))
        # staff, the slower model, on every 15th interval only; chat on every one (no key)
        self.assertEqual([m.get("every") for m in p["probes"]["gateway"]["models"]], [None, 15])
        self.assertEqual([s["name"] for s in p["probes"]["endpoints"]["services"]],
                         ["chat", "staff", "chat-a", "chat-b", "chat-c", "staff-a", "staff-b"])
        self.assertEqual(p["timing"]["return_max_s"], 600)
        self.assertEqual(p["serving"]["readiness"], {"period_s": 2, "failure_threshold": 2, "timeout_s": 2})

    def test_refusals(self):
        cases = {
            "a worker beside its server": {"id": "x", "worker_port": {"model": "chat", "copy": "a", "worker": 0}, "probes": ["gateway", "endpoints"]},
            "the spanning copy's worker beside its server": {"id": "x", "worker_port": {"model": "chat", "copy": "c", "worker": 1},
                                                             "probes": ["gateway", "endpoints"]},
            "no such worker": {"id": "x", "worker_port": {"model": "chat", "copy": "a", "worker": 7}, "probes": ["gateway", "endpoints"]},
            "a rail move to the same rail": {"id": "x", "rail_move": {"model": "chat", "copy": "a", "worker": 0, "to_rail": 3}},
            "a dark drill without the endpoints probe": {"id": "x", "dark": {"switch": "rail-sw1"}, "probes": ["gateway"]},
            "two faults": {"id": "x", "dark": {"switch": "rail-sw1"}, "worker_port": {"model": "chat", "copy": "c", "worker": 0},
                           "probes": ["gateway", "endpoints"]},
        }
        for what, d in cases.items():
            raw = copy.deepcopy(self.raw)
            raw["list"] = [d]
            with self.subTest(what=what), self.assertRaises(RenderError):
                self.plan(raw)
        raw = copy.deepcopy(self.raw)
        raw["probes"]["gateway"]["models"] = ["nope"]
        with self.assertRaises(RenderError):
            self.plan(raw)
        for every in ({"nope": 2}, {"staff": 0}, {"staff": 1.5}, {"staff": True}, [15]):
            raw = copy.deepcopy(self.raw)
            raw["probes"]["gateway"]["every"] = every
            with self.subTest(every=every), self.assertRaises(RenderError):
                self.plan(raw)
        raw = copy.deepcopy(self.raw)
        raw["probes"]["gateway"]["every"] = {"staff": 1}
        self.assertNotIn("every", self.plan(raw)["probes"]["gateway"]["models"][1])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class BreakPlan(unittest.TestCase):
    def test_6a(self):
        c = ch06()
        b = RD.breaks(c["inv"], CH06, c["m"])["breaks"]["6a"]
        mv = b["break"][0]
        self.assertEqual((mv["kind"], mv["pod"], mv["new_nad"]), ("pod_rail", "chat-b-worker0-0", True))
        self.assertEqual((mv["moved"]["address"], mv["moved"]["mac"], mv["moved"]["master"], mv["moved"]["switch"], mv["moved"]["native"]),
                         ("10.21.8.100/24", "02:5a:fe:08:00:64", "rail8", "rail-sw2", "Ethernet7"))
        gone = next(x for x in b["expect_healed"] if x["kind"] == "mac_gone")
        self.assertEqual((gone["switch"], gone["vlan"], gone["mac"], gone["wait_s"]), ("rail-sw2", 108, "02:5a:fe:08:00:64", 660))
        self.assertEqual(b["heal"], [{"kind": "serve", "replace": ["chat-b-server-0"], "namespace": "serving"}])
        self.assertEqual(json.loads(RD.dumps({"x": b}))["x"], json.loads((CH06 / "gen" / "breaks.json").read_text())["breaks"]["6a"])

    def test_6b(self):
        c = ch06()
        b = RD.breaks(c["inv"], CH06, c["m"])["breaks"]["6b"]
        rt = b["break"][0]
        self.assertEqual((rt["kind"], rt["pod"], rt["nad"], rt["dst"], rt["via"], rt["master"]),
                         ("pod_route", "chat-c-server-0", "rail7-route", "10.22.0.0/16", "10.21.7.101", "rail7"))
        self.assertEqual((rt["row"]["address"], rt["row"]["mac"]), ("10.21.7.100/24", "02:5a:fe:07:00:64"))
        pn = next(x for x in b["record"] if x["kind"] == "pod_net")
        self.assertEqual((pn["node"], pn["peer"], pn["iface"], pn["port"]),
                         ("k8s-gpu1", {"namespace": "inference", "selector": "app.kubernetes.io/name=router", "name": "router"}, "rail7", 8080))
        rp = [x for x in b["expect_broken"] + b["expect_healed"] if x["kind"] == "reply_path"]
        self.assertEqual([(x["leaves"], x["nad"], x["iface"], x["via"]) for x in rp],
                         [("rail", "rail7-route", "rail7", "10.21.7.101"), ("eth0", "rail7-route", "rail7", "10.21.7.101")])
        self.assertEqual(b["heal"], [{"kind": "serve", "replace": ["chat-c-server-0"], "namespace": "serving"}])
        self.assertEqual(json.loads(RD.dumps({"x": b}))["x"], json.loads((CH06 / "gen" / "breaks.json").read_text())["breaks"]["6b"])

    def test_6b_refusals(self):
        c = ch06()
        heal = [{"serve": {"replace": ["chat-c-server-0"]}}]
        cases = {
            "a gateway off the rail": {"break": [{"pod_route": {"pod": "chat-c-server-0", "via": "10.21.4.101"}}], "heal": heal},
            "the pod's own address": {"break": [{"pod_route": {"pod": "chat-c-server-0", "via": "10.21.7.100"}}], "heal": heal},
            "a connection from a peer pod": {"break": [{"pod_route": {"pod": "chat-c-server-0", "via": "10.21.7.101"}}], "heal": heal,
                                             "record": [{"pod_net": {"pod": "chat-c-server-0", "from": "staff-a-server-0"}}]},
            "a pod_net of a worker": {"break": [{"pod_route": {"pod": "chat-c-server-0", "via": "10.21.7.101"}}], "heal": heal,
                                      "record": [{"pod_net": {"pod": "chat-c-worker0-0", "from": "router"}}]},
            "a reply_path with no pod_net": {"break": [{"pod_route": {"pod": "chat-c-server-0", "via": "10.21.7.101"}}], "heal": heal,
                                             "expect_broken": [{"reply_path": {"pod": "chat-c-server-0", "leaves": "rail"}}]},
            "a pod_route in heal": {"break": [{"pod_route": {"pod": "chat-c-server-0", "via": "10.21.7.101"}}],
                                    "heal": [{"pod_route": {"pod": "chat-c-server-0", "via": "10.21.7.101"}}]},
        }
        for what, raw in cases.items():
            with self.subTest(what=what), self.assertRaises(RenderError):
                RD._break(c["inv"], "6z", raw, c["m"])

    def test_refusals(self):
        c = ch06()
        cases = {
            "a pod not in the table": {"break": [{"pod_rail": {"pod": "nope", "to_rail": 8}}], "heal": [{"serve": {}}]},
            "a mac_gone with no pod moved": {"break": [{"pod_rail": {"pod": "chat-b-worker0-0", "to_rail": 8}}], "heal": [{"serve": {}}],
                                             "expect_healed": [{"mac_gone": {"pod": "chat-a-worker0-0"}}]},
            "too many ready endpoints": {"break": [{"pod_rail": {"pod": "chat-b-worker0-0", "to_rail": 8}}], "heal": [{"serve": {}}],
                                         "expect_broken": [{"endpoints": {"service": "chat-b", "ready": 2}}]},
            "a serve in break": {"break": [{"serve": {}}], "heal": [{"serve": {}}]},
        }
        for what, raw in cases.items():
            with self.subTest(what=what), self.assertRaises(RenderError):
                RD._break(c["inv"], "6z", raw, c["m"])


if __name__ == "__main__":
    unittest.main()
