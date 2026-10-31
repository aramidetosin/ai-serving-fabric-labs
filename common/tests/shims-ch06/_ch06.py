#!/usr/bin/env python3
"""Stand-ins for sfab-ch06's placement audit, serving trace, drills and break-6a, for
common/tests/test_ch06.py.

They model the serving layer as the render places it and hand everything else to the shared
stand-ins (common/tests/shims/). The world lives in $SHIM_CH06_STATE (JSON); times are the host
clock, as the harness's are. Made-up values only (never the book's figures):

- the pods are made from the recipe's own StatefulSets (serving.py on the rendered serving.env), one
  pod <controller>-0 each, Running on its row's node with a pod address of 10.22.<node>.<n> and a
  network-status annotation naming its rail attachment, address and MAC as its networks annotation
  asks; a deleted pod is made again from its StatefulSet's template at once, as the controller does;
  the API gateway and the router run two pods each;
- a worker is Ready while Running; a server is Ready while every address of its --rpc list is held
  by a Running worker on its own attachment, its session to its workers was never broken (a worker
  deleted under it breaks it until the server is made again), and no rail switch port its RPC
  crosses (the ports facing the server's and a worker's nodes on the copy's rail, when the two differ)
  went dark more than REMOVE_S before, and came back less than RETURN_S before;
- a Service's ready endpoints are its Ready servers; a request through a Gateway is answered when
  its model's Service holds a ready endpoint, and a request sent within RETRY_S of a cut on one of
  its model's copies is answered after one router retry;
- the trace's request, from the enterprise client, is served by the model's ready copies in turn
  (the first request by the first, the next by the next), and the serving pod's log holds one
  launched slot per request it served: its frames are written at every capture point it crosses,
  with kubelet probes beside them as noise;
- a KLISH shutdown of an interface or an interface range on a rail switch darkens those ports until
  no shutdown; show mac address-table lists every Running serving pod's rail MAC at its port.
"""

import base64
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "shims"
ROOT = HERE.parents[2]
INV = json.load(open(os.environ["SHIM_INV"]))
NODES = INV["nodes"]
BY_IP = {n["mgmt"]: name for name, n in NODES.items()}
PREFIX = INV["prefix"]
STATE = os.environ["SHIM_CH06_STATE"]
RENDER = Path(os.environ.get("SHIM_RENDER", ""))
K8S = json.load(open(RENDER / "gen" / "k8s.json"))
REMOVE_S = float(os.environ.get("SHIM_REMOVE_S", "1.0"))
RETURN_S = float(os.environ.get("SHIM_RETURN_S", "1.0"))
RETRY_S = 2.0
SNS = K8S["serving"]["namespace"]
INS = K8S["inference"]["namespace"]
CLIENT_ADDR = {n: (d.get("address") or "").split("/")[0] for n, d in NODES.items()}


def _serving():
    spec = importlib.util.spec_from_file_location("sfab_serving_shim", ROOT / "serving-layer" / "serving.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["sfab_serving_shim"] = mod
    spec.loader.exec_module(mod)
    return mod


SV = _serving()


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(s):
    tmp = f"{STATE}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(s, f, indent=1, sort_keys=True)
    os.replace(tmp, STATE)


class locked:
    def __enter__(self):
        import fcntl  # noqa: PLC0415
        self.f = open(STATE + ".lock", "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        import fcntl  # noqa: PLC0415
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def log(tool, argv):
    with open(os.environ["SHIM_LOG"], "a") as f:
        f.write(json.dumps([tool + "-ch06"] + argv) + "\n")


def delegate(tool, argv, stdin=None):
    script = SHARED / ("_devices.py" if tool in ("ssh", "sshpass") else "_shim.py")
    r = subprocess.run([sys.executable, str(script), tool] + argv, input=stdin, text=True, capture_output=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


# ---------------------------------------------------------------------------- the world

def node_index(node):
    return sorted(n for n, d in NODES.items() if d.get("k8s")).index(node) + 1


def from_sts(sts):
    """The pod a StatefulSet of one replica makes: <name>-0 from its template, owned by it."""
    tm = json.loads(json.dumps(sts["spec"]["template"]))
    name = sts["metadata"]["name"]
    md = dict(tm.get("metadata") or {}, name=f"{name}-0", namespace=sts["metadata"].get("namespace") or SNS,
              ownerReferences=[{"apiVersion": "apps/v1", "kind": "StatefulSet", "name": name, "controller": True}])
    return {"apiVersion": "v1", "kind": "Pod", "metadata": md, "spec": tm["spec"]}


def controllers(s):
    """Every StatefulSet's pod 0 made when it is missing."""
    for name, sts in sorted((s.get("sts") or {}).items()):
        if f"{name}-0" not in s["pods"]:
            s["pods"][f"{name}-0"] = materialize(s, from_sts(sts))
            s["broken"] = [x for x in s.get("broken") or [] if x != f"{name}-0"]


def materialize(s, doc):
    d = json.loads(json.dumps(doc))
    md = d["metadata"]
    md.setdefault("namespace", SNS)
    node = d["spec"]["nodeSelector"]["kubernetes.io/hostname"]
    s["seq"] = s.get("seq", 0) + 1
    ip = f"10.22.{node_index(node)}.{10 + s['seq']}"
    nets = json.loads(md["annotations"].get("k8s.v1.cni.cncf.io/networks") or "[]")
    status = [{"name": "cilium", "interface": "eth0", "ips": [ip], "default": True}]
    for n in nets:
        x = {"name": f"{md['namespace']}/{n['name']}", "interface": n.get("interface"), "ips": [a.split("/")[0] for a in n.get("ips") or []]}
        if n.get("mac"):
            x["mac"] = n["mac"]
        status.append(x)
    md["annotations"]["k8s.v1.cni.cncf.io/network-status"] = json.dumps(status)
    d["spec"]["nodeName"] = node
    d["status"] = {"phase": "Running", "podIP": ip, "startTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    d["_born"] = time.time()
    return d


def init(s):
    if s.get("pods"):
        return
    st = SV.settings(SV.read_env(RENDER / "bootstrap" / "k8s" / "serving.env"))
    s["pods"] = {}
    s["sts"] = {}
    for p in st.pods:
        doc = SV.worker_pod(st, p) if p["role"] == "worker" else SV.server_pod(st, p, st.copies[(p["model"], p["copy"])]["workers"])
        s["sts"][doc["metadata"]["name"]] = doc
        s["pods"][p["pod"]] = materialize(s, from_sts(doc))
    for name, node in (("api-gateway-6c9f-a1", "k8s-gpu1"), ("api-gateway-6c9f-b2", "k8s-gpu2"), ("router-7d4b-a1", "k8s-gpu1"), ("router-7d4b-b2", "k8s-gpu2")):
        app = name.rsplit("-", 2)[0]
        s["seq"] = s.get("seq", 0) + 1
        s["pods"][name] = {"metadata": {"name": name, "namespace": INS, "labels": {"app.kubernetes.io/name": app}, "annotations": {}},
                           "spec": {"nodeName": node, "containers": [{"name": app}]},
                           "status": {"phase": "Running", "podIP": f"10.22.{node_index(node)}.{10 + s['seq']}"}}
    s["nads"] = sorted(n["name"] for n in st.nads)
    # the key Job's first key of each application caller (inference.callers), the ids made up
    apps = [c["id"] for c in K8S["inference"].get("callers") or [] if c.get("kind") == "application"] or ["chat", "staff"]
    s["secrets"] = {f"{INS}/{K8S['inference']['keys']['models']['secret']}": {
        f"{c}.0a1b2c3{'de'[i % 2]}": f"sk-tw-{c}-" + "56"[i % 2] * 32 for i, c in enumerate(apps)}}
    s["broken"] = []
    s["dark"] = {}


def rail_switch(rail):
    for n, d in NODES.items():
        if d.get("role") == "rail_vlan" and rail in (d.get("rails") or []):
            return n
    return None


def port_facing(node, rail):
    ri = (NODES[node].get("rails") or {}).get(str(rail)) or {}
    return ri.get("switch"), ri.get("switch_native"), ri.get("switch_eth")


def dark_windows(s, sw, native):
    return [x for x in (s.get("dark") or {}).get(sw, []) if native in x["ports"]]


def port_dark(s, sw, native, t):
    return any(x["since"] <= t and (x.get("until") is None or t < x["until"]) for x in dark_windows(s, sw, native))


def cut(s, sw, native, t):
    """Whether a port's darkness has taken effect for readiness at t."""
    return any(x["since"] + REMOVE_S <= t and (x.get("until") is None or t < x["until"] + RETURN_S) for x in dark_windows(s, sw, native))


def att(pod):
    nets = json.loads(pod["metadata"]["annotations"].get("k8s.v1.cni.cncf.io/network-status") or "[]")
    return next((n for n in nets if not n.get("default")), None)


def rail_of(pod):
    a = att(pod)
    return int(str(a["name"]).split("/")[-1][4:]) if a else None


def is_server(pod):
    return (pod["metadata"].get("labels") or {}).get("app.kubernetes.io/component") == "server"


def is_worker(pod):
    return (pod["metadata"].get("labels") or {}).get("app.kubernetes.io/component") == "worker"


def rpc_list(pod):
    cmd = pod["spec"]["containers"][0].get("command") or []
    return [x.split(":")[0] for x in cmd[cmd.index("--rpc") + 1].split(",")] if "--rpc" in cmd else []


def ready(s, pod, t):
    if pod["status"].get("phase") != "Running":
        return False
    if not is_server(pod):
        return True
    if pod["metadata"]["name"] in (s.get("broken") or []):
        return False
    r = rail_of(pod)
    node = pod["spec"]["nodeName"]
    for addr in rpc_list(pod):
        w = next((x for x in s["pods"].values() if is_worker(x) and att(x) and addr in att(x)["ips"] and rail_of(x) == r), None)
        if w is None:
            return False
        if w["spec"]["nodeName"] != node:
            for n in (node, w["spec"]["nodeName"]):
                sw, native, _ = port_facing(n, r)
                if cut(s, sw, native, t):
                    return False
    return True


def view(s, pod, t):
    d = {k: v for k, v in pod.items() if not k.startswith("_")}
    d = json.loads(json.dumps(d))
    ok = ready(s, pod, t)
    d["status"]["conditions"] = [{"type": "Ready", "status": "True" if ok else "False"}]
    d["status"]["containerStatuses"] = [{"name": c.get("name"), "ready": ok} for c in d["spec"].get("containers") or []]
    return d


def services(s):
    out = []
    for m in K8S["serving"]["models"]:
        out.append((m["name"], {"model": m["name"]}))
        for c in m["copies"]:
            out.append((f"{m['name']}-{c}", {"model": m["name"], "copy": c}))
    return out


def svc_ready(s, name, sel, t):
    lp = INV["org"]["label_domain"]
    ips = []
    for p in s["pods"].values():
        lb = p["metadata"].get("labels") or {}
        if p["metadata"].get("namespace") == SNS and is_server(p) and all(lb.get(f"{lp}/{k}") == v for k, v in sel.items()) and ready(s, p, t):
            ips.append(p["status"]["podIP"])
    return sorted(ips)


def endpointslices(s, t, only=None):
    items = []
    for name, sel in services(s):
        if only and name != only:
            continue
        eps = [{"addresses": [ip], "conditions": {"ready": True}} for ip in svc_ready(s, name, sel, t)]
        items.append({"metadata": {"name": f"{name}-x1", "labels": {"kubernetes.io/service-name": name}}, "endpoints": eps})
    return {"items": items}


# ---------------------------------------------------------------------------- kubectl

def ns_of(args):
    for i, a in enumerate(args):
        if a in ("-n", "--namespace") and i + 1 < len(args):
            return args[i + 1]
    return None


def strip(args):
    out, i = [], 0
    while i < len(args):
        if args[i] in ("-n", "--namespace", "-o", "-l", "--field-selector", "--timeout", "--sort-by") and i + 1 < len(args):
            i += 2
            continue
        if args[i].startswith("-"):
            i += 1
            continue
        out.append(args[i])
        i += 1
    return out


def opt(args, name):
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            return args[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None


def pods_wide(s, ns, t):
    rows = ["NAME                     READY   STATUS    RESTARTS   AGE   IP            NODE"]
    for n, p in sorted(s["pods"].items()):
        if p["metadata"].get("namespace") == ns:
            rows.append(f"{n:<25}{'1/1' if ready(s, p, t) else '0/1':<8}Running   0          5m    {p['status']['podIP']:<14}{p['spec']['nodeName']}")
    return "\n".join(rows)


def kubectl(s, args, stdin, now):
    """(rc, stdout) for one kubectl run in the bastion."""
    ns = ns_of(args) or "default"
    words = strip(args)
    o = opt(args, "-o")
    if words[:1] == ["apply"]:
        import yaml  # noqa: PLC0415
        for d in yaml.safe_load_all(stdin or ""):
            if not d:
                continue
            if d["kind"] == "Pod":
                name = d["metadata"]["name"]
                s["pods"][name] = materialize(s, d)
                s["broken"] = [x for x in s.get("broken") or [] if x != name]
            elif d["kind"] == "StatefulSet":
                s.setdefault("sts", {})[d["metadata"]["name"]] = d
            elif d["kind"] == "NetworkAttachmentDefinition":
                s["nads"] = sorted(set(s.get("nads") or []) | {d["metadata"]["name"]})
        controllers(s)
        return 0, ""
    if words[:2] == ["delete", "pod"]:
        for n in words[2:]:
            p = s["pods"].pop(n, None)
            if p is not None and is_worker(p):
                for srv in s["pods"].values():
                    if is_server(srv) and set(att(p)["ips"]) & set(rpc_list(srv)) and srv["metadata"]["name"] not in s["broken"]:
                        s["broken"].append(srv["metadata"]["name"])
        controllers(s)
        return 0, ""
    if words[:1] == ["logs"]:
        n = (s.get("served") or {}).get(words[1] if len(words) > 1 else "", 0)
        return 0, "\n".join(["0.00.001 I srv  llama_server: model loaded"]
                            + [f"0.0{i}.000 I slot launch_slot_: id  0 | task {i} | processing task" for i in range(n)])
    if words[:2] == ["delete", "statefulset"]:
        for n in words[2:]:
            (s.get("sts") or {}).pop(n, None)
            s["pods"].pop(f"{n}-0", None)
        return 0, ""
    if words[:2] == ["get", "statefulsets"]:
        return 0, json.dumps({"items": [v for _, v in sorted((s.get("sts") or {}).items())]})
    if words[:2] in (["get", "persistentvolumeclaims"], ["get", "persistentvolumes"], ["get", "pv"]):
        st = SV.settings(SV.read_env(RENDER / "bootstrap" / "k8s" / "serving.env"))
        kind = "PersistentVolumeClaim" if words[1] == "persistentvolumeclaims" else "PersistentVolume"
        items = [dict(x, status={"phase": "Bound"}) for x in SV.models_docs(st) if x["kind"] == kind]
        return 0, json.dumps({"items": items})
    if words[:2] == ["delete", "network-attachment-definitions"]:
        s["nads"] = [x for x in s.get("nads") or [] if x not in words[2:]]
        return 0, ""
    if words[:2] == ["delete", "events"] or words[:2] == ["delete", "job"]:
        return 0, ""
    if words[:1] == ["rollout"]:
        return 0, "rolled out"
    if words[:1] == ["wait"]:
        sel = opt(args, "-l")
        target = [x for x in words[1:] if x.startswith("pod/")]
        if target:
            p = s["pods"].get(target[0][4:])
            return (0, "condition met") if p and ready(s, p, now) else (1, "timed out")
        want = dict(kv.split("=", 1) for kv in (sel or "").split(",") if "=" in kv)
        ps = [p for p in s["pods"].values() if p["metadata"].get("namespace") == ns
              and all((p["metadata"].get("labels") or {}).get(k) == v for k, v in want.items())]
        return (0, "condition met") if ps and all(ready(s, p, now) for p in ps) else (1, "timed out")
    if words[:2] == ["get", "pods"]:
        if o == "wide":
            return 0, pods_wide(s, ns, now)
        items = [view(s, p, now) for n, p in sorted(s["pods"].items()) if p["metadata"].get("namespace") == ns]
        sel = opt(args, "-l")
        if sel:
            want = dict(kv.split("=", 1) for kv in sel.split(",") if "=" in kv)
            items = [p for p in items if all((p["metadata"].get("labels") or {}).get(k) == v for k, v in want.items())]
        return 0, json.dumps({"items": items})
    if words[:2] == ["get", "pod"]:
        p = s["pods"].get(words[2]) if len(words) > 2 else None
        return (0, json.dumps(view(s, p, now))) if p else (1, "")
    if words[:2] == ["get", "endpointslices"]:
        sel = opt(args, "-l") or ""
        only = sel.split("=", 1)[1] if sel.startswith("kubernetes.io/service-name=") else None
        doc = endpointslices(s, now, only)
        if o == "wide":
            return 0, "\n".join(["NAME        ADDRESSTYPE   PORTS   ENDPOINTS"] + [
                f"{x['metadata']['name']:<12}IPv4          8080    {','.join(a for e in x['endpoints'] for a in e['addresses']) or '<unset>'}"
                for x in doc["items"]])
        return 0, json.dumps(doc)
    if words[:2] == ["get", "services"]:
        return 0, json.dumps({"items": [{"metadata": {"name": n}} for n, _ in services(s)]})
    if words[:2] == ["get", "network-attachment-definitions"]:
        st = SV.settings(SV.read_env(RENDER / "bootstrap" / "k8s" / "serving.env"))
        items = []
        for n in s.get("nads") or []:
            x = next((a for a in st.nads if a["name"] == n), None) or {"name": n, "master": n, "prefix": "10.21.0.0/24", "mtu": "9000"}
            items.append(SV.nad_doc(st, x))
        return 0, json.dumps({"items": items})
    if words[:2] == ["get", "lease"]:
        return 0, json.dumps({"metadata": {"name": words[2]}, "spec": {"holderIdentity": s.get("lease_holder", "k8s-cp2")}})
    if words[:2] == ["get", "secret"]:
        sec = s["secrets"].get(f"{ns}/{words[2]}")
        if o == "name":
            return (0, f"secret/{words[2]}") if sec or words[2] == K8S["serving"]["key"]["secret"] else (1, "")
        if sec is None:
            return 1, ""
        return 0, json.dumps({"metadata": {"name": words[2]}, "data": {k: base64.b64encode(v.encode()).decode() for k, v in sec.items()}})
    if words[:2] == ["get", "events"]:
        return 0, json.dumps({"items": []}) if o == "json" else "No resources found."
    return 0, ""


# ---------------------------------------------------------------------------- the client container

def model_of_url(url):
    for m in K8S["inference"]["models"]:
        if m["route_id"] in url:
            return m["name"]
    return None


def answer(s, model, t):
    ok = bool(svc_ready(s, model, {"model": model}, t))
    return ok


def response_headers(model, status):
    return (f"HTTP/1.1 {status} {'OK' if status == 200 else 'Internal Server Error'}\r\nserver: envoy\r\n"
            f"x-litellm-model-name: openai/{model}\r\nx-litellm-model-api-base: http://{model}.{SNS}.svc.cluster.local:8080/v1\r\n"
            f"x-litellm-attempted-retries: 0\r\n\r\n")


def client_files(s, ctr):
    return s.setdefault("files", {}).setdefault(ctr, {})


def curl(s, ctr, argv, now):
    out, hdr, fmt, lp = opt(argv, "-o"), opt(argv, "-D"), opt(argv, "-w") or "", opt(argv, "--local-port")
    url = next((a for a in argv if a.startswith("https://")), "")
    model = model_of_url(url)
    status = 200 if model and answer(s, model, now) else 500
    files = client_files(s, ctr)
    if hdr:
        files[hdr] = response_headers(model, status)
    if out and out != "/dev/null":
        files[out] = json.dumps({"id": "chatcmpl-stand-in", "model": model, "choices": [{"index": 0, "message": {"role": "assistant",
                                                                                                                  "content": "A rail is a network."}}]})
    if lp and ctr.endswith("ent-client"):
        cp = next(c for c in K8S["serving"]["models"] if c["name"] == model)["copies"]
        up = [c for c in cp if svc_ready(s, f"{model}-{c}", {"model": model, "copy": c}, now)] or cp[:1]
        served = up[s.get("trace_n", 0) % len(up)]
        s["trace_n"] = s.get("trace_n", 0) + 1
        s.setdefault("served", {})[f"{model}-{served}-server-0"] = s.get("served", {}).get(f"{model}-{served}-server-0", 0) + 1
        s["trace_req"] = {"t": now, "model": model, "copy": served, "sport": int(lp)}
    return fmt.replace("%{http_code}", str(status)).replace("%{local_port}", lp or "51000").replace("\\n", "\n")


def probe_records(s, run, until):
    out = {}
    t0, iv = run["start"], run["interval"]
    n = 0
    while True:
        t = t0 + n * iv
        if t > until or (run.get("count") and n >= run["count"]):
            break
        n += 1
        for m in run["models"]:
            if (n - 1) % (run.get("every") or {}).get(m, 1):
                continue
            ok = answer(s, m, t) or answer(s, m, t + RETRY_S)
            retried = 0
            for c in next(x for x in K8S["serving"]["models"] if x["name"] == m)["copies"]:
                for sw, wins in (s.get("dark") or {}).items():
                    for w in wins:
                        if w["since"] <= t < w["since"] + RETRY_S and not svc_ready(s, f"{m}-{c}", {"model": m, "copy": c}, w["since"] + REMOVE_S + 0.5):
                            retried = 1
            rec = {"n": len(out.get(m, [])) + 1, "model": m, "sent": round(t, 6), "done": round(t + 0.3 + (15 if retried else 0), 6), "status": 200 if ok else 500,
                   "outcome": "answered" if ok else "failed", "why": "" if ok else "http 500", "answered_by": f"openai/{m}",
                   "base": f"http://{m}.{SNS}.svc.cluster.local:8080/v1", "retries": retried}
            out.setdefault(m, []).append(rec)
    return out


def client_exec(s, ctr, argv, stdin, now):
    files = client_files(s, ctr)
    if argv[:1] == ["curl"]:
        return 0, curl(s, ctr, argv, now)
    if argv[:1] == ["cat"]:
        f = argv[1]
        m = re.match(r"^(\S+)/records-(\w+)\.jsonl$", f)
        if m and s.get("probe") and s["probe"].get("dir") == m.group(1):
            run = s["probe"]
            recs = probe_records(s, run, run.get("stop") or now).get(m.group(2), [])
            return 0, "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        if f in files:
            return 0, files[f]
        return 1, ""
    if argv[:1] == ["test"]:
        return (0, "") if files.get(argv[-1]) else (1, "")
    if argv[:1] == ["touch"]:
        files[argv[1]] = ""
        if s.get("probe") and argv[1] == f"{s['probe']['dir']}/stop":
            s["probe"]["stop"] = now
        return 0, ""
    if argv[:2] == ["rm", "-rf"]:
        for k in [k for k in files if k == argv[2] or k.startswith(argv[2] + "/")]:
            del files[k]
        return 0, ""
    if argv[:2] == ["sh", "-c"]:
        sc = argv[2]
        if "read -r k; read -r h" in sc:
            lines = (stdin or "").splitlines()
            mk = re.search(r">(\S+/key-\w+);", sc)
            mh = re.search(r">(\S+/hdr-\w+)$", sc)
            if len(lines) >= 2 and mk and mh:
                files[mk.group(1)] = lines[0] + "\n"
                files[mh.group(1)] = lines[1] + "\n"
            return 0, ""
        m = re.search(r"cat >(\S+)$", sc)
        if m:
            files[m.group(1)] = stdin or ""
            return 0, ""
        if "mkdir -p" in sc:
            return 0, ""
        if "pgrep -f '[p]robe_gateway.py'" in sc:
            p = s.get("probe")
            return (0, "") if p and p.get("stop") is None else (1, "")
        if "probe_gateway.py" in sc:
            a = shlex.split(sc.split(";", 1)[1].replace("nohup ", "").replace(" &", "").split(">")[0])
            if "" in a:
                # argparse refuses an empty argument, as the real probe did when an absent --resolve
                # pin was quoted into the command line as ''
                return 2, "probe_gateway: error: unrecognized arguments: "
            targets = [a[i + 1] for i, x in enumerate(a) if x == "--target"]
            d = a[a.index("--dir") + 1]
            for t_ in targets:
                if not files.get(f"{d}/key-{t_}"):
                    return 2, f"probe_gateway: no key for {t_}"
            run = {"dir": d, "models": targets, "interval": float(a[a.index("--interval") + 1]), "start": now + 0.05,
                   "every": {a[i + 1]: int(a[i + 2]) for i, x in enumerate(a) if x == "--every"}}
            if "--count" in a:
                run["count"] = int(a[a.index("--count") + 1])
                recs = probe_records(s, run, now + run["count"] * run["interval"])
                for m, rs in recs.items():
                    files[f"{d}/records-{m}.jsonl"] = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rs)
                return 0, "\n".join(f"{m}: sent {len(rs)}, answered {sum(1 for r in rs if r['outcome'] == 'answered')}, "
                                    f"failed {sum(1 for r in rs if r['outcome'] != 'answered')}" for m, rs in recs.items())
            run["stop"] = None
            s["probe"] = run
            return 0, ""
    return 0, ""


def docker_tool(argv):
    if argv[:1] != ["exec"]:
        return delegate("docker", argv)
    rest = argv[1:]
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in ("-e", "-u", "-w") else rest[1:]
    ctr, cmd = rest[0], rest[1:]
    stdin = sys.stdin.read() if "-i" in argv[1:argv.index(ctr)] else None
    node = ctr[len(PREFIX):] if ctr.startswith(PREFIX) else ""
    kind = (NODES.get(node) or {}).get("kind")
    if kind == "bastion" and cmd[:1] == ["kubectl"]:
        with locked():
            s = load()
            init(s)
            rc, out = kubectl(s, cmd[1:], stdin, time.time())
            save(s)
        log("docker", argv)
        if out:
            print(out)
        return rc
    if kind == "client":
        with locked():
            s = load()
            init(s)
            rc, out = client_exec(s, ctr, cmd, stdin, time.time())
            save(s)
        log("docker", argv)
        if out:
            sys.stdout.write(out if out.endswith("\n") else out + "\n")
        return rc
    return delegate("docker", argv, stdin)


# ---------------------------------------------------------------------------- the guests

POD_PID_BASE = 70000


def pid_of_pod(s, name):
    return POD_PID_BASE + sorted(s["pods"]).index(name) if name in s["pods"] else None


def pod_of_pid(s, pid):
    names = sorted(s["pods"])
    i = pid - POD_PID_BASE
    return names[i] if 0 <= i < len(names) else None


def frame(t, src, sp, dst, dp, flags, length):
    return {"t": t, "src": src, "sp": sp, "dst": dst, "dp": dp, "flags": flags, "len": length}


def fmt(f):
    return (f"{f['t']:.6f} 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype IPv4 (0x0800), length {66 + min(f['len'], 0)}: (tos 0x0, ttl 64, "
            f"id 1, offset 0, flags [DF], proto TCP (6), length {52 + f['len']})\n"
            f"    {f['src']}.{f['sp']} > {f['dst']}.{f['dp']}: Flags [{f['flags']}], seq 1:{1 + f['len']}, ack 1, win 502, "
            f"options [nop,nop,TS val 1 ecr 1], length {f['len']}"
            # tcpdump names the protocol it recognises on the port after a payload's length, as the
            # lab's decodes read on 8080 ("length 742: HTTP")
            + (": HTTP" if f["len"] > 0 and 8080 in (f["sp"], f["dp"]) else ""))


def trace_frames(s, point):
    """The frames of the trace's request at one capture point: ('guest', node, iface), ('pod', name, iface)
    or ('host', switch, eth)."""
    r = s.get("trace_req")
    if not r:
        return []
    t = r["t"]
    pods = s["pods"]
    api = sorted(n for n, p in pods.items() if (p["metadata"].get("labels") or {}).get("app.kubernetes.io/name") == "api-gateway")
    rtr = sorted(n for n, p in pods.items() if (p["metadata"].get("labels") or {}).get("app.kubernetes.io/name") == "router")
    a, ro = pods[api[0]], pods[rtr[0]]
    srv_name = f"{r['model']}-{r['copy']}-server-0"
    srv = pods.get(srv_name)
    out = []
    kind, who, iface = point
    if kind == "guest" and iface == "bond0":
        vip = K8S["gateways"]["gw-users"]["vip"]
        c = CLIENT_ADDR.get("ent-client")
        out = [frame(t, c, r["sport"], vip, 443, "S", 0), frame(t + 0.01, c, r["sport"], vip, 443, "P.", 517),
               frame(t + 0.4, vip, 443, c, r["sport"], "P.", 1200)]
    elif kind == "pod" and who in api:
        ip = pods[who]["status"]["podIP"]
        out = [frame(t, "10.22.9.1", 41000, ip, 9080, "S", 0)]  # the kubelet's TCP probe: no data
        if who == api[0]:
            out += [frame(t + 0.02, "10.22.9.7", 41010, ip, 9080, "P.", 400), frame(t + 0.03, ip, 42010, ro["status"]["podIP"], 4000, "P.", 380),
                    frame(t + 0.35, ro["status"]["podIP"], 4000, ip, 42010, "P.", 700)]
    elif kind == "pod" and who in rtr:
        ip = pods[who]["status"]["podIP"]
        out = [frame(t, "10.22.9.1", 43000, ip, 4000, "P.", 120)]  # the kubelet's HTTP probe, from no API gateway pod
        if who == rtr[0] and srv:
            out += [frame(t + 0.04, a["status"]["podIP"], 42010, ip, 4000, "P.", 380),
                    frame(t + 0.05, ip, 44010, srv["status"]["podIP"], 8080, "P.", 360)]
    elif kind == "pod" and who in pods:
        p = pods[who]
        a_ = att(p)
        if who == srv_name and iface == "eth0":
            out = [frame(t + 0.06, ro["status"]["podIP"], 44010, p["status"]["podIP"], 8080, "P.", 360),
                   frame(t + 0.3, p["status"]["podIP"], 8080, ro["status"]["podIP"], 44010, "P.", 650)]
        elif who == srv_name and a_ and iface == a_["interface"]:
            for addr in rpc_list(p):
                out += [frame(t + 0.07, a_["ips"][0], 45000, addr, 50052, "P.", 1400), frame(t + 0.08, addr, 50052, a_["ips"][0], 45000, "P.", 64)]
        elif is_worker(p) and a_ and iface == a_["interface"] and srv and a_["ips"][0] in rpc_list(srv) and rail_of(p) == rail_of(srv):
            sa = att(srv)["ips"][0]
            out = [frame(t + 0.07, sa, 45000, a_["ips"][0], 50052, "P.", 1400), frame(t + 0.08, a_["ips"][0], 50052, sa, 45000, "P.", 64)]
    elif kind == "host" and srv:
        sa = att(srv)["ips"][0]
        rail = rail_of(srv)
        for w in pods.values():
            if not (is_worker(w) and att(w) and att(w)["ips"][0] in rpc_list(srv) and w["spec"]["nodeName"] != srv["spec"]["nodeName"]):
                continue
            for n in (srv["spec"]["nodeName"], w["spec"]["nodeName"]):
                sw, _, eth = port_facing(n, rail)
                if (sw, eth) == (who, iface):
                    wa = att(w)["ips"][0]
                    out += [frame(t + 0.07, sa, 45000, wa, 50052, "P.", 1400), frame(t + 0.08, wa, 50052, sa, 45000, "P.", 64)]
    return out


def guest_cmd(node, script):
    with locked():
        s = load()
        init(s)
        out = _guest(s, node, script, time.time())
        save(s)
    return out


def _guest(s, node, script, now):
    sc = script.strip()
    caps = s.setdefault("gcaps", {})
    m = re.search(r"crictl pods --namespace '\^(\S+)\$' --name '\^(\S+)\$'", sc)
    if m:
        p = s["pods"].get(m.group(2))
        if p is None or p["spec"]["nodeName"] != node:
            return ("", 1)
        return str(pid_of_pod(s, m.group(2)))
    m = re.search(r"tcpdump -i (\S+) .*-w /tmp/sfab-rail-(\S+)\.pcap", sc)
    if m and "exec " in sc:
        mp = re.search(r"nsenter -t (\d+) -n", sc)
        pod = pod_of_pid(s, int(mp.group(1))) if mp else None
        caps[m.group(2)] = {"node": node, "pod": pod, "iface": m.group(1), "start": now, "stop": None}
        return ""
    m = re.match(r"^test -f /tmp/sfab-rail-(\S+)\.pcap$", sc)
    if m:
        return "" if m.group(1) in caps else ("", 1)
    m = re.match(r"^pkill -INT -f '\[s\]fab-rail-(\S+)\.pcap'", sc)
    if m:
        c = caps.get(m.group(1))
        if c and c["stop"] is None:
            c["stop"] = now
        return ""
    m = re.match(r"^pgrep -f '\[s\]fab-rail-(\S+)\.pcap'", sc)
    if m:
        c = caps.get(m.group(1))
        return "" if c and c["stop"] is None else ("", 1)
    m = re.match(r"^tcpdump (.*) -r /tmp/sfab-rail-(\S+)\.pcap > ", sc)
    if m:
        c = caps.get(m.group(2)) or {}
        pt = ("pod", c.get("pod"), c.get("iface")) if c.get("pod") else ("guest", c.get("node"), c.get("iface"))
        fs = [f for f in trace_frames(s, pt) if c.get("start", 0) <= f["t"] <= (c.get("stop") or now) + 1]
        c["decode"] = "\n".join(fmt(f) for f in fs)
        return str(len(fs))
    m = re.match(r"^cat /tmp/sfab-rail-(\S+)\.txt$", sc)
    if m:
        return (caps.get(m.group(1)) or {}).get("decode", "")
    if sc.startswith("base64 -w0 /tmp/sfab-rail-"):
        return "c3RhbmQtaW4K"
    if sc.startswith("rm -f /tmp/sfab-rail-"):
        return ""
    m = re.match(r"^nsenter -t (\d+) -n ip (-j )?(route|addr) show$", sc)
    if m:
        p = s["pods"].get(pod_of_pid(s, int(m.group(1))) or "")
        if p is None:
            return ("", 1)
        a = att(p)
        gw = ".".join(p["status"]["podIP"].split(".")[:3] + ["1"])
        if m.group(3) == "route":
            rows = [{"dst": "default", "gateway": gw, "dev": "eth0", "flags": []}, {"dst": gw, "dev": "eth0", "scope": "link", "flags": []}]
            if a:
                net = ".".join(a["ips"][0].split(".")[:3]) + ".0/24"
                rows.append({"dst": net, "dev": a["interface"], "protocol": "kernel", "scope": "link", "prefsrc": a["ips"][0], "flags": []})
            if m.group(2):
                return json.dumps(rows)
            return "\n".join(f"{r['dst']}" + (f" via {r['gateway']}" if r.get("gateway") else "") + f" dev {r['dev']}"
                             + (" proto kernel scope link src " + r["prefsrc"] if r.get("prefsrc") else "") for r in rows)
        addrs = [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": p["status"]["podIP"], "prefixlen": 32}]}]
        if a:
            addrs.append({"ifname": a["interface"], "address": a.get("mac"), "addr_info": [{"family": "inet", "local": a["ips"][0], "prefixlen": 24}]})
        return json.dumps(addrs)
    m = re.match(r"^nsenter -t (\d+) -n ss -Hltn$", sc)
    if m:
        p = s["pods"].get(pod_of_pid(s, int(m.group(1))) or "")
        if p is None:
            return ("", 1)
        if is_server(p):
            return f"LISTEN 0      512    {p['status']['podIP']}:{K8S['serving']['ports']['http']}      0.0.0.0:*"
        a = att(p)
        return f"LISTEN 0      4096   {(a or {}).get('ips', ['0.0.0.0'])[0]}:{K8S['serving']['ports']['rpc']}      0.0.0.0:*"
    if sc.startswith("ip -br link show"):
        return "\n".join(f"rail{r:<13} UP             02:5a:00:00:00:{r:02x} <BROADCAST,MULTICAST,UP,LOWER_UP>" for r in range(1, 9))
    return None


def guest_script(remote):
    if not remote.startswith(("sudo bash -c ", "sudo setsid bash -c ")):
        return None
    idx = 3
    if remote.startswith("sudo setsid bash -c "):
        remote, idx = remote.split(" </dev/null", 1)[0], 4
    r = subprocess.run(["bash", "-c", f'eval "a=($1)"; printf %s "${{a[{idx}]}}"', "_", remote], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


# ---------------------------------------------------------------------------- switches

def all_natives():
    return [f"Ethernet{i}" for i in range(48)] + [f"Ethernet{48 + 4 * k}" for k in range(8)]


def interface_status(s, sw, now):
    n = NODES[sw]
    nics = {x["native"]: x for x in (n.get("nics") or {}).values()}
    out = ["-" * 134, "Name                Description                   Oper        Reason         AutoNeg   Speed          MTU            Alternate Name",
           "-" * 134]
    for i, nat in enumerate(all_natives()):
        if nat in nics and not port_dark(s, sw, nat, now):
            oper, reason, desc = "up", "oper-up", nics[nat].get("desc") or "-"
        elif nat in nics:
            oper, reason, desc = "down", "admin-down", nics[nat].get("desc") or "-"
        else:
            oper, reason, desc = "down", "admin-down", "-"
        mtu = (n.get("access") or {}).get(nat, {}).get("mtu") or 9100  # the rendered port MTU (the l2 policy's 9216)
        out.append(f"{nat:<20}{desc:<30}{oper:<12}{reason:<17}off       25000          {mtu:<15}Eth1/{i + 1}")
    return "\n".join(out)


def mac_table(s, sw):
    rows = ["-" * 60, "VLAN     MAC Address         Type          Interface", "-" * 60]
    for p in s["pods"].values():
        a = att(p)
        if not a or not a.get("mac"):
            continue
        r = rail_of(p)
        psw, native, _ = port_facing(p["spec"]["nodeName"], r)
        if psw == sw:
            rows.append(f"{100 + r:<9}{a['mac']}   DYNAMIC       {native}")
    return "\n".join(rows)


def expand(spec):
    m = re.match(r"^Ethernet(\d+)-(\d+)$", spec)
    if m:
        return [f"Ethernet{i}" for i in range(int(m.group(1)), int(m.group(2)) + 1)]
    return [spec]


def sonic_cli(sw, data):
    with locked():
        s = load()
        init(s)
        out = _sonic_cli(s, sw, data, time.time())
        save(s)
    return out


def _sonic_cli(s, sw, data, now):
    if NODES[sw].get("role") != "rail_vlan":
        return None
    sys.path.insert(0, str(SHARED))
    import _devices  # noqa: PLC0415
    out, ctx, mode = [], None, "#"
    for line in data.splitlines():
        out.append(f"{sw}{mode} {line}")
        l = line.strip()
        if l == "exit" and mode == "#":
            break
        if l == "configure terminal":
            mode = "(config)#"
            continue
        if l == "end":
            mode, ctx = "#", None
            continue
        if l == "exit":
            ctx, mode = None, "(config)#"
            continue
        m = re.match(r"^interface (range )?(\S+)$", l)
        if m:
            ctx, mode = expand(m.group(2)), "(config-if)#"
            if m.group(1):
                out.append("%Info: Configuring only existing interfaces in range")
            continue
        if l in ("shutdown", "no shutdown") and ctx:
            d = s.setdefault("dark", {}).setdefault(sw, [])
            if l == "shutdown":
                d.append({"ports": ctx, "since": now, "until": None})
            else:
                for x in d:
                    if x.get("until") is None and set(x["ports"]) & set(ctx):
                        x["until"] = now
            continue
        if l == "terminal length 0":
            continue
        if l == "show interface status":
            out.append(interface_status(s, sw, now))
        elif l == "show mac address-table":
            out.append(mac_table(s, sw))
        elif l == "show running-configuration":
            out.append(_devices.running_config(sw))
        elif l.startswith("show"):
            fn = _devices.KLISH.get(l)
            out.append(fn(sw) if fn else "")
        else:
            out.append("% Error: Invalid input detected at \"^\" marker.")
    return "\n".join(out)


# ---------------------------------------------------------------------------- the tools

def target_of(argv):
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-o", "-i", "-p", "-l"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a, argv[i + 1:]
    return None, []


KNODE = (INV.get("stages") or {}).get("kubectl")
# a later chapter's stand-in answers the init node's kubectl and scripts first: f(cmd, stdin, now) on
# the locked, initialised world s, as f(s, cmd, stdin, now) -> (rc, out) or None
KUBE_HOOK = None


def knode_cmd(remote):
    """lib.sh K/KI ('sudo env KUBECONFIG=... kubectl ARGS') or KSH/KSHI ('sudo env KUBECONFIG=... PATH=...
    bash -c SCRIPT') -> ['kubectl', ARGS...] or ['bash', '-c', SCRIPT], else None."""
    if not remote.startswith("sudo env KUBECONFIG="):
        return None
    r = subprocess.run(["bash", "-c", 'eval "a=($1)"; printf "%s\\0" "${a[@]}"', "_", remote], capture_output=True, text=True)
    if r.returncode != 0:
        return None
    w = r.stdout.split("\0")[:-1][2:]
    while w and "=" in w[0] and not w[0].startswith("-"):
        w = w[1:]
    return w or None


def ssh_tool(argv):
    target, rest = target_of(argv)
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = BY_IP.get(host)
    if node and node == KNODE:
        cmd = knode_cmd(" ".join(rest))
        if cmd is not None:
            stdin = sys.stdin.read() if "-n" not in argv[:argv.index(target)] else None
            if cmd[:2] == ["bash", "-c"] and cmd[2:3] and cmd[2].startswith("kubectl ") and not any(c in cmd[2] for c in "|;&><$"):
                cmd = shlex.split(cmd[2])
            with locked():
                s = load()
                init(s)
                now = time.time()
                r = KUBE_HOOK(s, cmd, stdin, now) if KUBE_HOOK else None
                if r is None and cmd[:1] == ["kubectl"]:
                    r = kubectl(s, cmd[1:], stdin, now)
                save(s)
            if r is not None:
                log("ssh", argv)
                rc, out = r
                if out:
                    sys.stdout.write(out if out.endswith("\n") else out + "\n")
                return rc
            return delegate("ssh", argv, stdin)
    if node and NODES[node]["kind"] == "vm-node":
        script = guest_script(" ".join(rest))
        if script is not None and node == KNODE and script.startswith("kubeadm kubeconfig user "):
            # finish's operators step: a kubeconfig with a stand-in client certificate (no key material)
            user = script.split("--client-name ", 1)[1].split()[0]
            log("ssh", argv)
            print(f"apiVersion: v1\nkind: Config\nusers:\n- name: {user}\n  user:\n    client-certificate-data: c3RhbmQtaW4=")
            return 0
        if script is not None:
            out = guest_cmd(node, script)
            if out is not None:
                log("ssh", argv)
                rc = 0
                if isinstance(out, tuple):
                    out, rc = out
                if out:
                    print(out)
                return rc
    os.execv(sys.executable, [sys.executable, str(SHARED / "_devices.py"), "ssh"] + argv)


def sshpass(argv):
    data = sys.stdin.read()
    target, rest = target_of(argv[2:])
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = BY_IP.get(host)
    if node and NODES[node]["kind"] == "dell_sonic" and " ".join(rest) == "sonic-cli":
        out = sonic_cli(node, data)
        if out is not None:
            log("sshpass", argv)
            print(out)
            return 0
    return delegate("sshpass", argv, data)


def node_of_pid(pid):
    st = json.load(open(os.environ["SHIM_STATE"]))
    name = next((n for n, c in (st.get("containers") or {}).items() if c.get("pid") == pid), "")
    return name[len(PREFIX):] if name.startswith(PREFIX) else None


def tcpdump(argv, node=None):
    if "-w" in argv:
        out = os.path.abspath(argv[argv.index("-w") + 1])
        iface = argv[argv.index("-i") + 1] if "-i" in argv else None
        with locked():
            s = load()
            s.setdefault("hcaps", {})[out] = {"node": node, "eth": iface, "start": time.time()}
            save(s)
        open(out, "wb").write(b"\xd4\xc3\xb2\xa1stand-in\n")
        import signal  # noqa: PLC0415
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        for _ in range(6000):
            time.sleep(0.1)
        return 0
    if "-r" in argv:
        f = os.path.abspath(argv[argv.index("-r") + 1])
        s = load()
        c = (s.get("hcaps") or {}).get(f)
        if c is None:
            return 0
        fs = [x for x in trace_frames(s, ("host", c["node"], c["eth"])) if x["t"] >= c["start"]]
        print("\n".join(fmt(x) for x in fs))
        return 0
    return 0


def nsenter(argv):
    pid = int(argv[argv.index("-t") + 1])
    cmd = argv[argv.index("-n") + 1:]
    if cmd[:1] == ["timeout"]:
        cmd = cmd[2:]
    if cmd[:1] == ["tcpdump"] and "-w" in cmd:
        log("nsenter", argv)
        return tcpdump(cmd[1:], node_of_pid(pid))
    os.execv(sys.executable, [sys.executable, str(SHARED / "_shim.py"), "nsenter"] + argv)


if __name__ == "__main__":
    tool = sys.argv[1]
    sys.exit({"ssh": ssh_tool, "sshpass": sshpass, "nsenter": nsenter, "tcpdump": tcpdump, "docker": docker_tool}[tool](sys.argv[2:]))
