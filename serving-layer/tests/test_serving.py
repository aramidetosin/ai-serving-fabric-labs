"""serving.py: serving.env, the manifests it renders, and serve, status and load against a stand-in
kubectl that keeps a small cluster in memory. No cluster and no network.

Run from serving-layer/:  python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
EXAMPLE = HERE / "serving.env.example"
DASHES = (chr(0x2014), chr(0x2013))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


sv = _load("sfab_serving", HERE / "serving.py")

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def env() -> dict:
    return sv.read_env(EXAMPLE)


def settings(**over):
    e = env()
    e.update(over)
    return sv.settings(e)


class EnvFile(unittest.TestCase):
    def test_example_reads(self):
        s = settings()
        self.assertEqual(s.namespace, "serving")
        self.assertEqual(s.kubectl, ["kubectl"])
        self.assertEqual(len(s.pods), 5)
        self.assertEqual(sorted(s.copies), [("chat", "a"), ("chat", "b")])
        self.assertEqual(s.copies[("chat", "a")]["server"]["pod"], "chat-a-server-0")
        self.assertEqual([w["pod"] for w in s.copies[("chat", "b")]["workers"]], ["chat-b-worker0-0", "chat-b-worker1-0"])
        self.assertEqual(s.server_args, ["-ngl", "99", "-c", "4096", "-np", "8", "-n", "256", "-t", "2", "--reasoning-budget", "0",
                                         "--cache-ram", "0", "--ctx-checkpoints", "0"])
        self.assertEqual(s.models_path, "/srv/models")
        self.assertEqual(s.models[0]["file"], "LFM2.5-24B-A2B-Q4_K_M.gguf")
        self.assertEqual(s.load["exec"], [])

    def test_quoting_and_errors(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-serving-"))
        try:
            p = d / "e"
            p.write_text("# c\nA_B='x y'\nC=\nD=plain\n")
            self.assertEqual(sv.read_env(p), {"A_B": "x y", "C": "", "D": "plain"})
            for bad in ("a=1\n", "A=x y\n", "A='x\n", "nonsense\n"):
                p.write_text(bad)
                with self.assertRaises(sv.ServingError, msg=bad):
                    sv.read_env(p)
        finally:
            shutil.rmtree(d)

    def test_rows_padded_or_not_and_no_extra(self):
        e = env()
        e["SERVING_NAD_1"] = e.pop("SERVING_NAD_01")
        self.assertEqual(sv.table(e, "NAD")[0]["name"], "rail3")
        e["SERVING_NAD_09"] = "x y 10.0.0.0/24 1"
        with self.assertRaises(sv.ServingError):
            sv.table(e, "NAD")

    def test_placement_rules(self):
        e = env()
        cases = {
            "a copy on two rails": {"SERVING_POD_05": "chat-b-worker1-0 chat b worker 1 node1 3 rail3 10.21.3.110/24 -"},
            "two servers": {"SERVING_POD_02": "chat-a-worker0-0 chat a server 0 node1 3 rail3 10.21.3.101/24 -"},
            "an address off its rail": {"SERVING_POD_02": "chat-a-worker0-0 chat a worker 0 node1 3 rail3 10.21.4.101/24 -"},
            "one address twice": {"SERVING_POD_02": "chat-a-worker0-0 chat a worker 0 node1 3 rail3 10.21.3.100/24 -"},
            "an unknown attachment": {"SERVING_POD_02": "chat-a-worker0-0 chat a worker 0 node1 3 rail9 10.21.3.101/24 -"},
            "an unknown model": {"SERVING_POD_02": "chat-a-worker0-0 other a worker 0 node1 3 rail3 10.21.3.101/24 -"},
            "a pod not a StatefulSet's pod 0": {"SERVING_POD_02": "chat-a-worker0 chat a worker 0 node1 3 rail3 10.21.3.101/24 -"},
            "a backend timeout past the request's": {"SERVING_ROUTE_BACKEND_TIMEOUT": "901s"},
            "a model file with a directory": {"SERVING_MODEL_01": "chat chat chat sub/m.gguf 10"},
            "a model with no size": {"SERVING_MODEL_01": "chat chat chat m.gguf none"},
            "a models path that is not absolute": {"SERVING_MODELS_PATH": "srv/models"},
            "no worker": {"SERVING_PODS": "3", "SERVING_POD_02": "chat-b-server-0 chat b server 0 node2 6 rail6 10.21.6.100/24 -",
                          "SERVING_POD_03": "chat-b-worker0-0 chat b worker 0 node2 6 rail6 10.21.6.101/24 -"},
        }
        for what, over in cases.items():
            e2 = dict(e)
            e2.update(over)
            if what == "no worker":
                for k in ("SERVING_POD_04", "SERVING_POD_05"):
                    e2.pop(k)
            with self.subTest(what=what), self.assertRaises(sv.ServingError):
                sv.settings(e2)


class Macs(unittest.TestCase):
    """The table's optional mac column: each pod's fixed rail MAC, in its networks annotation."""

    def with_macs(self) -> dict:
        e = env()
        e["SERVING_POD_COLUMNS"] = e["SERVING_POD_COLUMNS"] + " mac"
        for i in range(1, int(e["SERVING_PODS"]) + 1):
            k = f"SERVING_POD_{i:02d}"
            last = e[k].split()[8].split("/")[0].split(".")[-1]
            e[k] = e[k] + f" 02:5a:fe:{int(e[k].split()[6]):02x}:00:{int(last):02x}"
        return e

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the manifests")
    def test_mac_in_the_annotation(self):
        s = sv.settings(self.with_macs())
        w = list(yaml.safe_load_all(sv.manifests(s)["20-workers.yaml"]))[0]
        nets = json.loads(w["spec"]["template"]["metadata"]["annotations"]["k8s.v1.cni.cncf.io/networks"])
        self.assertEqual(nets, [{"name": "rail3", "namespace": "serving", "interface": "rail3", "ips": ["10.21.3.101/24"],
                                 "mac": "02:5a:fe:03:00:65"}])
        self.assertIn("02:5a:fe:03:00:65", sv.placement_table(s))

    def test_macs_checked(self):
        e = self.with_macs()
        e["SERVING_POD_02"] = e["SERVING_POD_02"].rsplit(" ", 1)[0] + " " + e["SERVING_POD_01"].rsplit(" ", 1)[1]
        with self.assertRaises(sv.ServingError):
            sv.settings(e)
        e = self.with_macs()
        e["SERVING_POD_02"] = e["SERVING_POD_02"].rsplit(" ", 1)[0] + " 03:5a:fe:03:00:65"
        with self.assertRaises(sv.ServingError):
            sv.settings(e)


class Manifests(unittest.TestCase):
    def setUp(self):
        self.s = settings()
        self.files = sv.manifests(self.s)

    def test_deterministic_and_plain(self):
        self.assertEqual(sv.manifests(settings()), self.files)
        for name, text in self.files.items():
            for d in DASHES:
                self.assertNotIn(d, text, name)
        for f in ("serving.py", "load.py", "Makefile", "serving.env.example", "README.md", "image/Dockerfile", "image/sfab-ready"):
            text = (HERE / f).read_text(encoding="utf-8")
            for d in DASHES:
                self.assertNotIn(d, text, f)

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the manifests")
    def test_statefulsets(self):
        workers = list(yaml.safe_load_all(self.files["20-workers.yaml"]))
        servers = list(yaml.safe_load_all(self.files["30-servers.yaml"]))
        self.assertEqual([d["kind"] for d in workers + servers], ["StatefulSet"] * 5)
        self.assertEqual([p["metadata"]["name"] for p in workers], ["chat-a-worker0", "chat-b-worker0", "chat-b-worker1"])
        self.assertEqual([p["metadata"]["name"] for p in servers], ["chat-a-server", "chat-b-server"])
        for d in workers + servers:
            sp = d["spec"]
            self.assertEqual((sp["replicas"], sp["updateStrategy"], sp["podManagementPolicy"]), (1, {"type": "OnDelete"}, "Parallel"))
            self.assertEqual(sp["selector"]["matchLabels"], {"app.kubernetes.io/name": "serving",
                                                             "serving.example/pod": d["metadata"]["name"] + "-0"})
            self.assertEqual(sp["template"]["metadata"]["labels"]["serving.example/pod"], d["metadata"]["name"] + "-0")
        w = workers[0]["spec"]["template"]
        self.assertEqual(w["spec"]["nodeSelector"], {"kubernetes.io/hostname": "node1"})
        nets = json.loads(w["metadata"]["annotations"]["k8s.v1.cni.cncf.io/networks"])
        self.assertEqual(nets, [{"name": "rail3", "namespace": "serving", "interface": "rail3", "ips": ["10.21.3.101/24"]}])
        c = w["spec"]["containers"][0]
        self.assertEqual(c["command"], ["ggml-rpc-server", "-H", "10.21.3.101", "-p", "50052", "-t", "4"])
        self.assertEqual(c["readinessProbe"]["exec"]["command"], ["sfab-ready", "worker", "--rpc-port", "50052", "10.21.3.101"])
        # a worker's memory: its share of the file plus the headroom; copy b's two workers hold half each
        full = -(-14526258464 // (1 << 20)) + sv.WORKER_HEADROOM_MIB
        half = -(-14526258464 // (2 << 20)) + sv.WORKER_HEADROOM_MIB
        self.assertEqual(c["resources"]["requests"]["memory"], f"{full}Mi")
        self.assertEqual(c["resources"]["limits"]["memory"], f"{full + sv.WORKER_LIMIT_MIB}Mi")
        self.assertEqual(workers[1]["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["memory"], f"{half}Mi")
        srv = servers[0]["spec"]["template"]["spec"]["containers"][0]
        cmd = srv["command"]
        self.assertEqual(cmd[cmd.index("-m") + 1], "/models/LFM2.5-24B-A2B-Q4_K_M.gguf")
        self.assertEqual(cmd[cmd.index("--host") + 1], "$(POD_IP)", "bound to the pod's own cluster address")
        self.assertEqual(srv["env"][0], {"name": "POD_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}})
        self.assertEqual(srv["env"][1], {"name": "SFAB_READY_HOST", "value": "$(POD_IP)"}, "the probe asks the bound address")
        self.assertEqual(cmd[cmd.index("--rpc") + 1], "10.21.3.101:50052")
        self.assertNotIn("--tensor-split", cmd, "one worker takes every layer")
        cmd_b = servers[1]["spec"]["template"]["spec"]["containers"][0]["command"]
        self.assertEqual(cmd_b[cmd_b.index("--rpc") + 1], "10.21.6.101:50052,10.21.6.102:50052")
        self.assertEqual(cmd_b[cmd_b.index("--tensor-split") + 1], "1,1", "two workers take half the layers each")
        self.assertEqual(cmd[cmd.index("--api-key-file") + 1], "/secret/key")
        self.assertIn("--no-ui", cmd)
        rp = srv["readinessProbe"]
        self.assertEqual((rp["periodSeconds"], rp["failureThreshold"], rp["timeoutSeconds"]), (2, 2, 2))
        self.assertEqual(rp["exec"]["command"], ["sfab-ready", "server", "--port", "8080", "--rpc-port", "50052",
                                                 "--probe-port", "50053", "10.21.3.101"])
        vols = {v["name"]: v for v in servers[0]["spec"]["template"]["spec"]["volumes"]}
        self.assertEqual(vols["key"]["secret"]["secretName"], "llm-api-key")
        self.assertEqual(vols["models"]["persistentVolumeClaim"], {"claimName": "models-node1", "readOnly": True})
        self.assertIn({"name": "models", "mountPath": "/models", "readOnly": True}, srv["volumeMounts"])
        self.assertEqual(servers[1]["spec"]["template"]["spec"]["volumes"][1]["persistentVolumeClaim"]["claimName"], "models-node2")
        for d in workers + servers:
            sp = d["spec"]["template"]["spec"]
            self.assertEqual(sp["securityContext"]["runAsUser"], 65532)
            self.assertTrue(sp["securityContext"]["runAsNonRoot"])
            self.assertEqual(sp["containers"][0]["securityContext"], {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}})
            self.assertFalse(sp["automountServiceAccountToken"])
            self.assertRegex(d["spec"]["template"]["metadata"]["annotations"]["serving.example/spec"], r"^[0-9a-f]{16}$")

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the manifests")
    def test_base_services_and_route(self):
        base = list(yaml.safe_load_all(self.files["00-base.yaml"]))
        kinds = [d["kind"] for d in base]
        self.assertEqual(kinds, ["Namespace", "NetworkAttachmentDefinition", "NetworkAttachmentDefinition",
                                 "ServiceAccount", "Role", "RoleBinding",
                                 "PersistentVolume", "PersistentVolumeClaim", "PersistentVolume", "PersistentVolumeClaim"])
        self.assertEqual(base[0]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")
        conf = json.loads(base[1]["spec"]["config"])
        self.assertEqual(conf, {"cniVersion": "1.0.0", "name": "rail3", "type": "macvlan", "master": "rail3", "mode": "bridge",
                                "mtu": 9000, "capabilities": {"ips": True, "mac": True}, "ipam": {"type": "static"}})
        role = base[4]
        self.assertEqual(role["rules"][0], {"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["llm-api-key"], "verbs": ["get"]})
        pv, pvc = base[6], base[7]
        self.assertEqual(pv["metadata"]["name"], "serving-models-node1")
        self.assertEqual(pv["spec"]["local"], {"path": "/srv/models"})
        self.assertEqual(pv["spec"]["accessModes"], ["ReadOnlyMany"])
        self.assertEqual(pv["spec"]["claimRef"], {"namespace": "serving", "name": "models-node1"})
        self.assertEqual(pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"],
                         [{"key": "kubernetes.io/hostname", "operator": "In", "values": ["node1"]}])
        self.assertEqual((pvc["metadata"]["name"], pvc["spec"]["volumeName"]), ("models-node1", "serving-models-node1"))
        self.assertEqual(pv["spec"]["capacity"]["storage"], "14Gi")
        svcs = list(yaml.safe_load_all(self.files["40-services.yaml"]))
        self.assertEqual([x["metadata"]["name"] for x in svcs], ["chat", "chat-a", "chat-b"])
        self.assertEqual(svcs[1]["spec"]["selector"], {"serving.example/model": "chat", "serving.example/copy": "a", "serving.example/role": "server"})
        (rt,) = yaml.safe_load_all(self.files["50-route.yaml"])
        self.assertEqual(rt["spec"]["parentRefs"], [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": "internal",
                                                     "namespace": "gateways", "sectionName": "https"}])
        self.assertEqual(rt["spec"]["hostnames"], ["serve.example.com"])
        self.assertEqual([r["matches"][0]["path"]["value"] for r in rt["spec"]["rules"]], ["/chat", "/chat-a", "/chat-b"])
        for r in rt["spec"]["rules"]:
            self.assertEqual(r["timeouts"], {"request": "900s", "backendRequest": "900s"})
            self.assertEqual(r["filters"][0]["urlRewrite"]["path"], {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"})
        (job,) = yaml.safe_load_all(self.files["10-key-job.yaml"])
        cmd = job["spec"]["template"]["spec"]["containers"][0]["command"]
        self.assertEqual(cmd[:2], ["sfab-keys", "ensure"])
        self.assertEqual(cmd[cmd.index("--prefix") + 1], "sk-ex-serving")

    def test_namespace_labels(self):
        s = settings(SERVING_NAMESPACE_LABELS="routes.example.test/gw-internal=true team=ml")
        ns = next(d for d in sv.base_docs(s) if d["kind"] == "Namespace")
        self.assertEqual(ns["metadata"]["labels"]["routes.example.test/gw-internal"], "true")
        self.assertEqual(ns["metadata"]["labels"]["team"], "ml")
        self.assertEqual(ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")
        plain = next(d for d in sv.base_docs(settings()) if d["kind"] == "Namespace")
        self.assertEqual(sorted(plain["metadata"]["labels"]), ["app.kubernetes.io/name", "pod-security.kubernetes.io/enforce"])
        for bad in ("noequals", "Bad Key=x", "k=v w", "k=-bad"):
            with self.assertRaises(sv.ServingError):
                settings(SERVING_NAMESPACE_LABELS=bad)

    def test_stamp_moves_with_the_spec(self):
        s2 = settings(SERVING_SERVER_ARGS="-ngl 99 -c 8192 -t 2 -np 2")

        def stamps(s, f):
            return {d["metadata"]["name"]: sv.template_stamp(s, d) for d in sv._docs_of(s, f)}

        self.assertNotEqual(stamps(self.s, "30-servers.yaml")["chat-a-server"], stamps(s2, "30-servers.yaml")["chat-a-server"])
        self.assertEqual(stamps(self.s, "20-workers.yaml"), stamps(s2, "20-workers.yaml"))

    def test_render_files(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-serving-render-"))
        try:
            names = sv.render(self.s, d)
            self.assertEqual(names, ["00-base.yaml", "10-key-job.yaml", "20-workers.yaml", "30-servers.yaml", "40-services.yaml",
                                     "50-route.yaml", "placement.txt"])
            table = (d / "placement.txt").read_text()
            self.assertIn("chat-a-worker0-0  chat   a     worker  node1  3     rail3  10.21.3.101/24", table)
        finally:
            shutil.rmtree(d)


# ------------------------------------------------------------------------------------------
# A stand-in kubectl with a small cluster in memory: StatefulSets make their pod 0 from their
# template whenever it is missing, as the controller does with updateStrategy OnDelete.


class FakeCluster:
    def __init__(self, secret: bool = False, ready: bool = True):
        self.calls: list = []
        self.stdin: list = []
        self.secrets = {"llm-api-key": base64.b64encode(b"sk-ex-serving-" + b"0" * 32).decode()} if secret else {}
        self.pods: dict = {}
        self.sts: dict = {}
        self.pvs: dict = {}
        self.ready = ready
        self.job_runs = 0
        self.n = 10

    def __call__(self, argv, stdin):
        self.calls.append(list(argv))
        self.stdin.append(stdin)
        a = argv[1:]
        if a[:1] == ["apply"]:
            for d in yaml.safe_load_all(stdin.decode()):
                if d and d["kind"] == "StatefulSet":
                    self.sts[d["metadata"]["name"]] = d
                if d and d["kind"] == "PersistentVolume":
                    self.pvs.setdefault(d["metadata"]["name"], dict(d, status={"phase": "Bound"}))
                if d and d["kind"] == "Job":
                    self.job_runs += 1
                    self.secrets[d["metadata"]["name"]] = base64.b64encode(b"sk-ex-serving-" + b"1" * 32).decode()
            self._controllers()
            return R(0)
        if a[:2] == ["get", "secret"] and "-o" in a and a[a.index("-o") + 1].startswith("jsonpath"):
            return R(0, self.secrets.get(a[2], "").encode())
        if a[:2] == ["get", "secret"]:
            return R(0 if a[2] in self.secrets else 1)
        if a[:2] == ["get", "pods"]:
            return R(0, json.dumps({"items": list(self.pods.values())}).encode())
        if a[:2] == ["get", "statefulsets"]:
            return R(0, json.dumps({"items": list(self.sts.values())}).encode())
        if a[:2] == ["get", "pv"]:
            return R(0, json.dumps({"items": list(self.pvs.values())}).encode())
        if a[:2] == ["get", "endpointslices"]:
            name = a[a.index("-l") + 1].split("=", 1)[1]
            sel = self._selector(name)
            eps = [{"addresses": [p["status"]["podIP"]], "conditions": {"ready": self.ready}} for p in self.pods.values()
                   if all(p["metadata"]["labels"].get(k) == v for k, v in sel.items())]
            return R(0, json.dumps({"items": [{"endpoints": eps}]}).encode())
        if a[:2] == ["delete", "pod"]:
            for n in [x for x in a[2:] if not x.startswith("-") and x not in ("serving",)]:
                self.pods.pop(n, None)
            self._controllers()
            return R(0)
        if a[:2] == ["delete", "statefulset"]:
            for n in [x for x in a[2:] if not x.startswith("-") and x not in ("serving",)]:
                self.sts.pop(n, None)
                self.pods.pop(f"{n}-0", None)
            return R(0)
        if a[:2] == ["delete", "pv"]:
            self.pvs.pop(a[2], None)
            return R(0)
        if a[:1] == ["logs"] or a[2:3] == ["logs"]:
            return R(0, b"Secret serving/llm-api-key: created, key sha256:000000000000\n")
        return R(0)

    def _controllers(self):
        for name, d in self.sts.items():
            if f"{name}-0" not in self.pods:
                self.pods[f"{name}-0"] = self._run(name, d)

    def _selector(self, svc: str) -> dict:
        model, _, cp = svc.partition("-")
        sel = {"serving.example/model": model, "serving.example/role": "server"}
        if cp:
            sel["serving.example/copy"] = cp
        return sel

    def _run(self, name: str, sts: dict) -> dict:
        t = json.loads(json.dumps(sts["spec"]["template"]))
        d = {"apiVersion": "v1", "kind": "Pod", "metadata": dict(t["metadata"], name=f"{name}-0", namespace="serving",
                                                               ownerReferences=[{"kind": "StatefulSet", "name": name}]),
             "spec": t["spec"]}
        nets = json.loads(d["metadata"]["annotations"]["k8s.v1.cni.cncf.io/networks"])
        self.n += 1
        status = [{"name": "cilium", "interface": "eth0", "ips": [f"10.22.1.{self.n}"], "default": True},
                  {"name": f"serving/{nets[0]['name']}", "interface": nets[0]["interface"], "ips": [nets[0]["ips"][0].split("/")[0]]}]
        d["metadata"]["annotations"]["k8s.v1.cni.cncf.io/network-status"] = json.dumps(status)
        d["spec"]["nodeName"] = d["spec"]["nodeSelector"]["kubernetes.io/hostname"]
        d["status"] = {"phase": "Running", "podIP": f"10.22.1.{self.n}",
                       "conditions": [{"type": "Ready", "status": "True" if self.ready else "False"}]}
        return d


class R:
    def __init__(self, rc: int, out: bytes = b"", err: bytes = b""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _deleted_pods(calls: list) -> list:
    return sorted(y for x in calls if x[1:3] == ["delete", "pod"] for y in x[3:] if y.startswith("chat"))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed by the stand-in cluster")
class Serve(unittest.TestCase):
    def setUp(self):
        self._poll = sv.WAIT_POLL_S
        sv.WAIT_POLL_S = 0.0

    def tearDown(self):
        sv.WAIT_POLL_S = self._poll

    def run_serve(self, cluster, s=None, replace=None):
        import io

        out = io.StringIO()
        rc = sv.serve(sv.Kube(["kubectl"], run=cluster), s or settings(), sv.Report(out), replace)
        return rc, out.getvalue()

    def test_first_run_then_second(self):
        c = FakeCluster(secret=False)
        rc, out = self.run_serve(c)
        self.assertEqual(rc, 0, out)
        verbs = [" ".join(x[1:4]) for x in c.calls]
        self.assertEqual(verbs[0], "-n kube-system rollout")
        self.assertIn("generated in the cluster by the key tool", out)
        self.assertEqual(c.job_runs, 1)
        self.assertIn("== RESULT: ", out)
        self.assertRegex(out, r"PASS  chat-a-worker0-0 of StatefulSet chat-a-worker0 on node1, rail3 10\.21\.3\.101, Ready")
        self.assertRegex(out, r"PASS  Service chat: 2 ready endpoint\(s\)")
        self.assertEqual(sorted(c.pods), ["chat-a-server-0", "chat-a-worker0-0", "chat-b-server-0", "chat-b-worker0-0", "chat-b-worker1-0"])
        self.assertEqual(sorted(c.pvs), ["serving-models-node1", "serving-models-node2"])
        # the key travels on no command line, and no manifest holds it
        for argv, stdin in zip(c.calls, c.stdin):
            self.assertFalse(any("sk-ex-serving-" in x for x in argv), argv)
            if stdin:
                self.assertNotIn(b"sk-ex-serving-0", stdin)
        # the workers' StatefulSets are applied and their pods waited for before the servers'
        applied = [(i, x) for i, x in enumerate(c.calls) if x[1:2] == ["apply"]]
        servers_at = next(i for i, _ in applied if b"name: chat-a-server" in c.stdin[i])
        worker_reads = [i for i, x in enumerate(c.calls) if x[1:3] == ["get", "pods"] and i < servers_at]
        self.assertTrue(worker_reads)
        # the second run: the key kept, no pod replaced
        c.calls.clear()
        rc, out = self.run_serve(c)
        self.assertEqual(rc, 0, out)
        self.assertEqual(c.job_runs, 1)
        self.assertIn("present (kept as it is)", out)
        self.assertIn("0 pod(s) replaced or removed, 5 kept as rendered", out)
        self.assertFalse(_deleted_pods(c.calls))

    def test_a_changed_pod_is_replaced(self):
        c = FakeCluster(secret=True)
        self.assertEqual(self.run_serve(c)[0], 0)
        old = c.pods["chat-a-server-0"]["metadata"]["annotations"]["serving.example/spec"]
        c.calls.clear()
        c.stdin.clear()
        s2 = settings(SERVING_SERVER_ARGS="-ngl 99 -c 8192 -t 2 -np 2")
        rc, out = self.run_serve(c, s2)
        self.assertEqual(rc, 0, out)
        self.assertEqual(_deleted_pods(c.calls), ["chat-a-server-0", "chat-b-server-0"])
        self.assertNotEqual(c.pods["chat-a-server-0"]["metadata"]["annotations"]["serving.example/spec"], old,
                            "made again from the StatefulSet's new template")
        # the delete comes after the StatefulSet holds the new template
        i_apply = max(i for i, x in enumerate(c.calls) if x[1:2] == ["apply"] and b"name: chat-a-server" in c.stdin[i])
        i_del = next(i for i, x in enumerate(c.calls) if x[1:3] == ["delete", "pod"])
        self.assertLess(i_apply, i_del)

    def test_a_pod_detached_from_its_rail_is_replaced(self):
        # after a boot on a kept disk: the sandbox made again with Cilium alone, a new address, the old annotation
        c = FakeCluster(secret=True)
        self.assertEqual(self.run_serve(c)[0], 0)
        c.pods["chat-a-worker0-0"]["status"]["podIP"] = "10.22.2.143"
        del c.pods["chat-b-server-0"]["metadata"]["annotations"]["k8s.v1.cni.cncf.io/network-status"]
        c.calls.clear()
        rc, out = self.run_serve(c)
        self.assertEqual(rc, 0, out)
        self.assertEqual(_deleted_pods(c.calls), ["chat-a-worker0-0", "chat-b-server-0"])
        self.assertIn("2 pod(s) replaced or removed, 3 kept as rendered", out)
        self.assertFalse(sv._detached({"metadata": {}, "status": {}}), "a pod with no address yet is not judged")

    def test_rows_and_pods_no_row_names_are_removed(self):
        c = FakeCluster(secret=True)
        self.assertEqual(self.run_serve(c)[0], 0)
        # a bare pod of an earlier recipe, and a StatefulSet the table no longer names
        c.pods["chat-a-server"] = json.loads(json.dumps(c.pods["chat-a-server-0"]), object_hook=None)
        c.pods["chat-a-server"]["metadata"]["name"] = "chat-a-server"
        c.sts["chat-c-server"] = json.loads(json.dumps(c.sts["chat-a-server"]))
        c.sts["chat-c-server"]["metadata"]["name"] = "chat-c-server"
        c._controllers()
        c.calls.clear()
        rc, out = self.run_serve(c)
        self.assertEqual(rc, 0, out)
        self.assertIn(["kubectl", "delete", "statefulset", "-n", "serving", "--wait=true", f"--timeout={sv.WAIT['delete']}s",
                       "chat-c-server"], c.calls)
        self.assertNotIn("chat-a-server", c.pods)
        self.assertNotIn("chat-c-server-0", c.pods)
        self.assertIn("StatefulSet(s) no row names removed: chat-c-server", out)

    def test_a_released_models_volume_is_made_again(self):
        c = FakeCluster(secret=True)
        self.assertEqual(self.run_serve(c)[0], 0)
        c.pvs["serving-models-node1"]["status"] = {"phase": "Released"}
        c.calls.clear()
        rc, out = self.run_serve(c)
        self.assertEqual(rc, 0, out)
        self.assertIn(["kubectl", "delete", "pv", "serving-models-node1", "--wait=true", f"--timeout={sv.WAIT['delete']}s"], c.calls)
        self.assertEqual(c.pvs["serving-models-node1"]["status"]["phase"], "Bound")

    def test_replace_named_pods(self):
        c = FakeCluster(secret=True)
        self.assertEqual(self.run_serve(c)[0], 0)
        c.calls.clear()
        rc, out = self.run_serve(c, replace=["chat-b-server-0"])
        self.assertEqual(rc, 0, out)
        self.assertEqual(_deleted_pods(c.calls), ["chat-b-server-0"])
        self.assertIn("chat-b-server-0", c.pods)
        rc, _ = self.run_serve(c, replace=["nobody"])
        self.assertEqual(rc, 1)

    def test_an_attachment_the_table_does_not_use_is_removed(self):
        c = FakeCluster(secret=True)

        def run(argv, stdin):
            if argv[1:3] == ["get", "network-attachment-definitions"]:
                return R(0, json.dumps({"items": [{"metadata": {"name": n}} for n in ("rail3", "rail6", "rail8")]}).encode())
            return c(argv, stdin)

        rc, out = self.run_serve(run)
        self.assertEqual(rc, 0, out)
        self.assertIn(["kubectl", "delete", "network-attachment-definitions", "-n", "serving", "rail8"], c.calls)
        self.assertIn("rail attachment(s) the table does not use removed: rail8", out)

    def test_move(self):
        import io

        c = FakeCluster(secret=True)
        self.assertEqual(self.run_serve(c)[0], 0)
        stamp = c.pods["chat-b-worker0-0"]["metadata"]["annotations"]["serving.example/spec"]
        c.calls.clear()
        c.stdin.clear()
        out = io.StringIO()
        rc = sv.move(sv.Kube(["kubectl"], run=c), settings(), sv.Report(out), "chat-b-worker0-0", "8", "10.21.8.100/24", "rail8",
                     "02:5a:fe:08:00:64")
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(c.calls[0][1:2], ["apply"])
        self.assertEqual(c.calls[1][1:3], ["delete", "pod"])
        docs = [d for d in yaml.safe_load_all(c.stdin[0].decode()) if d]
        self.assertEqual([d["kind"] for d in docs], ["NetworkAttachmentDefinition", "StatefulSet"])
        self.assertEqual(json.loads(docs[0]["spec"]["config"])["master"], "rail8")
        pod = c.pods["chat-b-worker0-0"]
        nets = json.loads(pod["metadata"]["annotations"]["k8s.v1.cni.cncf.io/networks"])
        self.assertEqual(nets, [{"name": "rail8", "namespace": "serving", "interface": "rail8", "ips": ["10.21.8.100/24"],
                                 "mac": "02:5a:fe:08:00:64"}])
        self.assertEqual(pod["metadata"]["labels"]["serving.example/rail"], "rail6", "the labels still name the table's rail")
        self.assertEqual(pod["spec"]["containers"][0]["command"][:3], ["ggml-rpc-server", "-H", "10.21.8.100"])
        self.assertNotEqual(pod["metadata"]["annotations"]["serving.example/spec"], stamp)
        self.assertIn("Running and Ready on rail8", out.getvalue())
        # serve puts it back: its stamp differs from the rendered one
        c.calls.clear()
        rc, out2 = self.run_serve(c)
        self.assertEqual(rc, 0, out2)
        self.assertIn("1 pod(s) replaced or removed", out2)
        self.assertEqual(c.pods["chat-b-worker0-0"]["metadata"]["annotations"]["serving.example/spec"], stamp)

    def test_reroute(self):
        import io

        c = FakeCluster(secret=True)
        self.assertEqual(self.run_serve(c)[0], 0)
        stamp = c.pods["chat-b-server-0"]["metadata"]["annotations"]["serving.example/spec"]
        c.calls.clear()
        c.stdin.clear()
        out = io.StringIO()
        rc = sv.reroute(sv.Kube(["kubectl"], run=c), settings(), sv.Report(out), "chat-b-server-0", "rail6-route", "10.22.0.0/16",
                        "10.21.6.102")
        self.assertEqual(rc, 0, out.getvalue())
        self.assertEqual(c.calls[1][1:3], ["delete", "pod"])
        docs = [d for d in yaml.safe_load_all(c.stdin[0].decode()) if d]
        self.assertEqual([d["kind"] for d in docs], ["NetworkAttachmentDefinition", "StatefulSet"])
        nad, sts = docs
        conf = json.loads(nad["spec"]["config"])
        self.assertEqual((nad["metadata"]["name"], conf["name"], conf["master"]), ("rail6-route", "rail6-route", "rail6"))
        self.assertEqual(conf["ipam"], {"type": "static", "routes": [{"dst": "10.22.0.0/16", "gw": "10.21.6.102"}]})
        self.assertEqual(nad["metadata"]["labels"], {"app.kubernetes.io/name": "serving"}, "serve removes it as one the table does not use")
        pod = c.pods["chat-b-server-0"]
        nets = json.loads(pod["metadata"]["annotations"]["k8s.v1.cni.cncf.io/networks"])
        row = next(p for p in settings().pods if p["pod"] == "chat-b-server-0")
        self.assertEqual(nets, [{"name": "rail6-route", "namespace": "serving", "interface": "rail6", "ips": [row["address"]]}])
        self.assertEqual(pod["metadata"]["labels"], sv.pod_labels(settings(), row), "still selected by its Services")
        self.assertNotEqual(pod["metadata"]["annotations"]["serving.example/spec"], stamp)
        self.assertIn("Ready through rail6-route", out.getvalue())
        rc = sv.reroute(sv.Kube(["kubectl"], run=c), settings(), sv.Report(io.StringIO()), "chat-b-server-0", "rail6", "10.22.0.0/16",
                        "10.21.6.102")
        self.assertNotEqual(rc, 0, "a name the table uses is refused")

    def test_not_ready_fails(self):
        c = FakeCluster(secret=True, ready=False)
        old = dict(sv.WAIT)
        sv.WAIT.update(workers=0, servers=0)
        try:
            rc, out = self.run_serve(c)
        finally:
            sv.WAIT.update(old)
        self.assertEqual(rc, 1)
        self.assertIn("FAIL  3 worker pod(s) Ready", out)
        self.assertIn("chat-a-worker0-0 (not Ready)", out)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed by the stand-in cluster")
class Load(unittest.TestCase):
    def args(self, **kw):
        base = dict(users=3, seconds=5, max_tokens=64, url="", model="", resolve=None, records="", cut_ok=False, local=False)
        base.update(kw)
        return type("A", (), base)()

    def test_through_the_client(self):
        c = FakeCluster(secret=True)
        s = settings(SERVING_LOAD_EXEC="docker exec -i sfab-chXX-ops-client", SERVING_LOAD_RESOLVE="serve.example.com:443:198.51.100.2")
        runs = []
        d = Path(tempfile.mkdtemp(prefix="sfab-serving-load-"))

        def run(argv, stdin=None, capture=False):
            runs.append((list(argv), stdin))
            return R(0, b'{"n": 1}\n' if argv[-2:] == ["cat", sv.LOAD_RECORDS] else b"")

        try:
            rc = sv.load(sv.Kube(["kubectl"], run=c), s, self.args(records=str(d / "rec.jsonl")), run=run)
            self.assertEqual(rc, 0)
            self.assertEqual(runs[0][0], ["docker", "exec", "-i", "sfab-chXX-ops-client", "sh", "-c", f"umask 077; cat > {sv.LOAD_KEY}"])
            self.assertEqual(runs[0][1], b"sk-ex-serving-" + b"0" * 32)
            argv = runs[1][0]
            self.assertEqual(argv[4:6], ["python3", "-"])
            self.assertEqual(argv[argv.index("--resolve") + 1], "serve.example.com:443:198.51.100.2")
            self.assertEqual(argv[argv.index("--url") + 1], "https://serve.example.com/chat/v1")
            self.assertEqual(argv[argv.index("--key-file") + 1], sv.LOAD_KEY)
            self.assertEqual(runs[1][1], sv.LOAD_PY.read_bytes())
            self.assertEqual(runs[-1][0][-4:], ["rm", "-f", sv.LOAD_KEY, sv.LOAD_RECORDS])
            self.assertEqual((d / "rec.jsonl").read_bytes(), b'{"n": 1}\n')
            for argv, _ in runs:
                self.assertFalse(any("sk-ex-serving-" in x for x in argv), argv)
        finally:
            shutil.rmtree(d)

    def test_here(self):
        c = FakeCluster(secret=True)
        seen = {}

        def run(argv, stdin=None, capture=False):
            kf = argv[argv.index("--key-file") + 1]
            seen["mode"] = Path(kf).stat().st_mode & 0o777
            seen["key"] = Path(kf).read_bytes()
            return R(0)

        self.assertEqual(sv.load(sv.Kube(["kubectl"], run=c), settings(), self.args(local=True), run=run), 0)
        self.assertEqual(seen["mode"], 0o600)
        self.assertEqual(seen["key"], b"sk-ex-serving-" + b"0" * 32)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed by the stand-in cluster")
class Client(unittest.TestCase):
    def args(self, **kw):
        base = dict(max_tokens=64, url="", model="", resolve=None, local=False)
        base.update(kw)
        return type("A", (), base)()

    def test_through_the_client(self):
        c = FakeCluster(secret=True)
        s = settings(SERVING_LOAD_EXEC="docker exec -i sfab-chXX-ops-client", SERVING_LOAD_RESOLVE="")
        runs = []

        def run(argv, stdin=None, capture=False):
            runs.append((list(argv), stdin))
            return R(0)

        self.assertEqual(sv.client(sv.Kube(["kubectl"], run=c), s, self.args(), run=run), 0)
        self.assertEqual(runs[0][0], ["docker", "exec", "-i", "sfab-chXX-ops-client", "sh", "-c", f"umask 077; cat > {sv.CLIENT_KEY}"])
        self.assertEqual(runs[0][1], b"sk-ex-serving-" + b"0" * 32)
        argv = runs[1][0]
        self.assertEqual(argv[4:6], ["python3", "-"])
        self.assertEqual(argv[argv.index("--base-url") + 1], "https://serve.example.com/chat/v1")
        self.assertEqual(argv[argv.index("--key-file") + 1], sv.CLIENT_KEY)
        self.assertNotIn("--resolve", argv)
        self.assertEqual(runs[1][1], sv.CLIENT_PY.read_bytes())
        self.assertEqual(runs[-1][0][-3:], ["rm", "-f", sv.CLIENT_KEY])
        for argv, _ in runs:
            self.assertFalse(any("sk-ex-serving-" in x for x in argv), argv)

    def test_pinned_when_the_env_pins(self):
        c = FakeCluster(secret=True)
        s = settings(SERVING_LOAD_EXEC="docker exec -i sfab-chXX-ops-client", SERVING_LOAD_RESOLVE="serve.example.com:443:198.51.100.2")
        runs = []
        sv.client(sv.Kube(["kubectl"], run=c), s, self.args(), run=lambda argv, stdin=None, capture=False: runs.append(list(argv)) or R(0))
        self.assertEqual(runs[1][runs[1].index("--resolve") + 1], "serve.example.com:443:198.51.100.2")


class Cli(unittest.TestCase):
    def test_render_from_the_example(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-serving-cli-"))
        try:
            self.assertEqual(sv.main(["render", "--env", str(EXAMPLE), "--out", str(d)]), 0)
            self.assertTrue((d / "30-servers.yaml").read_text().startswith("# serving-layer manifests for this cluster"))
        finally:
            shutil.rmtree(d)

    def test_makefile_targets(self):
        mk = (HERE / "Makefile").read_text()
        for t in ("serve:", "load:", "client:", "status:", "render:", "delete:", "image:", "test:"):
            self.assertIn(f"\n{t}", mk)
        self.assertIn("USERS       ?= 10", mk)
        self.assertIn("SECONDS     ?= 60", mk)
        self.assertTrue(re.search(r"--users \$\(USERS\) --seconds \$\(SECONDS\)", mk))


if __name__ == "__main__":
    unittest.main()
