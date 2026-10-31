#!/usr/bin/env python3
"""Stand-ins for sfab-ch07's gateway-layer audit, keyed trace, gateway drills and break-7a, for
common/tests/test_ch07.py.

They extend chapter 6's stand-in world (shims-ch06/_ch06.py, which models the serving layer) with
the gateway layer as the render makes it, and hand everything else to it. The world lives in the
same JSON file; times are the host clock. Made-up values only (never the book's figures):

- the key Secret's history (every mint and revoke, timed); each API gateway pod loads a change
  KEY_LOAD_S times its place among the pods by name, plus one, after it, unless it is held (its
  sidecar's hold file), and a pod made again starts with the Secret as it is; a request with a key
  is answered 200 on its model's route by a pod that holds the key, 401 by one that does not, and
  on another model's route 401 (403 while that route's ConfigMap without rejected_code has reached
  the pod, CM_LOAD_S after it is applied); the Gateway's proxy spreads requests over the pods in
  turn;
- the per-pod probe's pod and the key Jobs run as the key tool would, their logs made when read;
- the test backend's processes stop and continue on kill -STOP and -CONT in their guests; a request
  to it through the Gateway ends at the listener's stream idle timeout with 504 and the body
  "stream timeout" from envoy (the request was complete, as the lab's deployment recorded it), at
  the route's request timeout with 504 and "upstream request timeout", or when the backend is
  continued with 200, whichever comes first; the listener's timeout is the one the helm values last applied set (IDLE_S as rendered);
- the keyed trace's frames at the API gateway and router pods carry their HTTP requests, the
  Authorization headers with the keys in them, in a real pcap, which the harness must scrub;
- the Gateways, routes, namespaces, leases, the Gateways' CiliumEnvoyConfigs, the CA's proof and
  each VIP's chain read as the render makes them, healthy.
"""

import base64
import json
import os
import re
import shlex
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shims-ch06"))
import _ch06 as W  # noqa: E402

RENDER = W.RENDER
K8S = W.K8S
INF = K8S["inference"]
INS = INF["namespace"]
KEY_LOAD_S = float(os.environ.get("SHIM_KEY_LOAD_S", "0.6"))
CM_LOAD_S = float(os.environ.get("SHIM_CM_LOAD_S", "0.6"))
IDLE_S = float(os.environ.get("SHIM_IDLE_S", "2"))
# the refusals as the render configures them: one message for any credential with multi-auth on
MSG = {401: INF["rejected"]["message"], 403: "The consumer_group_id is forbidden.",
       "missing": INF["rejected"]["message"] if INF.get("oidc") else "Missing API key found in request"}
# which models each caller (a key field's <caller>.) may call
CALLS = {c["id"]: set(c["models"]) for c in INF.get("callers") or []}
TB = K8S["test_backend"]
DOMAIN = W.INV["org"]["domain"]


def yload(path):
    import yaml  # noqa: PLC0415
    return [d for d in yaml.safe_load_all(open(path)) if d]


def init7(s):
    W.init(s)
    c = s.setdefault("ch07", {})
    if c.get("ready"):
        return
    c["ready"] = True
    ks = s["secrets"][f"{INS}/{INF['keys']['models']['secret']}"]
    c["values"] = {v: f for f, v in ks.items()}
    c["events"] = []          # {t, op: add|del, field, value}
    c["base"] = dict(ks)       # the Secret at time 0
    c["holds"] = {}            # pod -> [[since, until]]
    c["born"] = {}             # pod -> time it was made
    c["cm"] = []               # {t, variant: default|rendered, model}
    c["sig"] = []              # {t, sig, pod}
    c["idle_reqs"] = {}        # client dir -> request
    c["helm"] = {"idle": None, "t": 0}
    c["route_timeouts"] = None
    c["rr"] = 0
    c["probes"] = {}           # client dir -> probe run
    c["kpods"] = {}            # key probe pods and Jobs
    s["secrets"][f"{INS}/{INF['keys']['master']['secret']}"] = {"key": "sk-tw-router-" + "8" * 32}
    s["secrets"][f"{INS}/{INF['keys']['backend']['secret']}"] = {"key": "sk-tw-serving-" + "9" * 32}
    for name, node in (("echo-5f7d-a1", "k8s-gpu1"), ("echo-5f7d-b2", "k8s-gpu2")):
        s["seq"] = s.get("seq", 0) + 1
        s["pods"][name] = {"metadata": {"name": name, "namespace": TB["namespace"], "labels": {"app.kubernetes.io/name": TB["deployment"]},
                                        "annotations": {}},
                           "spec": {"nodeName": node, "containers": [{"name": TB["deployment"]}]},
                           "status": {"phase": "Running", "podIP": f"10.22.{W.node_index(node)}.{10 + s['seq']}"}}


# ---------------------------------------------------------------------------- keys at the API gateway

def api_pods(s):
    return sorted(n for n, p in s["pods"].items() if (p["metadata"].get("labels") or {}).get("app.kubernetes.io/name") == INF["gateway"]["name"])


def delay(s, pod):
    names = api_pods(s)
    return KEY_LOAD_S * ((names.index(pod) if pod in names else 0) + 1)


def secret_at(s, t):
    c = s["ch07"]
    out = dict(c["base"])
    for e in c["events"]:
        if e["t"] <= t:
            if e["op"] == "add":
                out[e["field"]] = e["value"]
            else:
                out.pop(e["field"], None)
    return out


def loaded(s, pod, t):
    c = s["ch07"]
    born = c["born"].get(pod, 0)
    seen = t
    for since, until in c["holds"].get(pod, []):
        if since <= t and (until is None or t < until):
            seen = since
    return secret_at(s, max(born, seen - delay(s, pod)) if seen > born else born)


def variant(s, pod, t, model):
    v = "rendered"
    for e in s["ch07"]["cm"]:
        if e["t"] + CM_LOAD_S <= t:
            v = e["variant"] if e["model"] == model else v
    return v


def field_of(s, key):
    return s["ch07"]["values"].get(key)


def answer_at(s, pod, t, route_model, key):
    """(status, message) of one request at one API gateway pod."""
    if not key:
        return 401, MSG["missing"]
    f = field_of(s, key)
    if f is None or f not in loaded(s, pod, t):
        return 401, MSG[401]
    if route_model not in CALLS.get(f.split(".")[0], {f.split(".")[0]}):
        return (403, MSG[403]) if variant(s, pod, t, route_model) == "default" else (401, MSG[401])
    return 200, ""


def pick(s, n=None):
    pods = api_pods(s)
    c = s["ch07"]
    if n is None:
        c["rr"] += 1
        n = c["rr"]
    return pods[n % len(pods)]


def model_of_url(url):
    for m in INF["models"]:
        if m["route_id"] in url:
            return m["name"]
    return None


# ---------------------------------------------------------------------------- kubectl in the bastion

def gw_docs():
    return yload(RENDER / "bootstrap" / "k8s" / "50-gateways.yaml")


def routes(s):
    out = [d for d in yload(RENDER / "bootstrap" / "k8s" / "55-test-backend.yaml") if d["kind"] == "HTTPRoute"]
    out += [d for d in yload(RENDER / "bootstrap" / "k8s" / "62-inference.yaml") if d["kind"] == "HTTPRoute"]
    out += [d for d in identity_docs() if d["kind"] == "HTTPRoute"]
    st = W.SV.settings(W.SV.read_env(RENDER / "bootstrap" / "k8s" / "serving.env"))
    out.append(W.SV.route(st))
    rt = s["ch07"].get("route_timeouts")
    for r in out:
        if r["metadata"]["name"] == TB["routes"].get("gw-users") and rt:
            for rule in r["spec"]["rules"]:
                rule["timeouts"] = rt
        gws = [p["name"] for p in r["spec"]["parentRefs"]]
        r["status"] = {"parents": [{"parentRef": {"name": g}, "conditions": [{"type": "Accepted", "status": "True"},
                                                                              {"type": "ResolvedRefs", "status": "True"}]} for g in gws]}
    return out


def identity_docs():
    f = RENDER / "bootstrap" / "k8s" / "57-identity.yaml"
    return yload(f) if f.exists() else []


def namespaces():
    out = yload(RENDER / "bootstrap" / "k8s" / "05-namespaces.yaml")
    out += [d for d in identity_docs() if d["kind"] == "Namespace"]
    out += [d for d in yload(RENDER / "bootstrap" / "k8s" / "60-inference-base.yaml") if d["kind"] == "Namespace"]
    st = W.SV.settings(W.SV.read_env(RENDER / "bootstrap" / "k8s" / "serving.env"))
    out += [d for d in W.SV.base_docs(st) if d["kind"] == "Namespace"]
    out.append({"metadata": {"name": "kube-system", "labels": {}}})
    return out


def idle_now(s):
    i = s["ch07"]["helm"].get("idle")
    return float(i) if i else IDLE_S


def cec(s, name=None):
    items = []
    for g in K8S["gateways"].values():
        n = g["cec"].split("/", 1)[1]
        if name and n != name:
            continue
        hcm = {"@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
               "streamIdleTimeout": f"{int(idle_now(s)) if idle_now(s).is_integer() else idle_now(s)}s"}
        items.append({"metadata": {"name": n, "namespace": K8S["gateway_namespace"]},
                      "spec": {"resources": [{"@type": "type.googleapis.com/envoy.config.listener.v3.Listener",
                                              "filterChains": [{"filters": [{"name": "hcm", "typedConfig": hcm}]}]}]}})
    return {"items": items}


def configmaps(s):
    out = [d for d in yload(RENDER / "bootstrap" / "k8s" / "62-inference.yaml") if d["kind"] == "ConfigMap"]
    live = s["ch07"].get("cm_live")
    for d in out:
        if live and d["metadata"]["name"] == live["metadata"]["name"]:
            d["data"] = live["data"]
    return out


def probe_script_runs(doc):
    """[(label, route path, key field, expect, repeat, interval, max_s)] from a probe pod's script."""
    script = doc["spec"]["containers"][0]["command"][2]
    out = []
    for line in script.splitlines():
        a = shlex.split(line.replace(" || true", ""))
        if a[:2] != ["sfab-keys", "probe"]:
            continue
        g = lambda k, d=None: a[a.index(k) + 1] if k in a else d  # noqa: E731
        out.append({"label": g("--label", ""), "path": g("--path"), "field": g("--key-file").rsplit("/", 1)[1], "expect": int(g("--expect")),
                    "repeat": "--repeat" in a, "interval": float(g("--interval", "1")), "max_s": float(g("--max-s", "240"))})
    return out


def run_probe(s, kp, upto):
    """The probe pod's lines up to time upto, and the time it ends (None while it runs)."""
    secret = secret_at(s, kp["t"])
    lines, t = [], kp["t"] + 0.5
    for chk in kp["checks"]:
        key = secret.get(chk["field"])
        route_model = model_of_url(chk["path"])
        start, n = t, 0
        while True:
            n += 1
            res = [(p, answer_at(s, p, t, route_model, key)) for p in api_pods(s)]
            for p, (st, msg) in res:
                rec = {"label": chk["label"], "round": n, "t": round(t, 3), "pod": p, "ip": s["pods"][p]["status"]["podIP"], "status": st}
                if st != 200 and msg:
                    rec["message"] = msg
                lines.append(json.dumps(rec, sort_keys=True))
            done = all(st == chk["expect"] for _, (st, _) in res)
            if not chk["repeat"] or done or t - start >= chk["max_s"]:
                break
            t += chk["interval"]
            if t > upto:
                return lines, None
        lines.append(json.dumps({"label": chk["label"], "summary": {"rounds": n, "all": done, "expect": chk["expect"]}}, sort_keys=True))
        t += 0.2
    return lines, t


def kubectl7(s, args, stdin, now):
    """(rc, out) for what chapter 7 asks of kubectl, or None to hand it to chapter 6's stand-in."""
    ns = W.ns_of(args) or "default"
    words = W.strip(args)
    o = W.opt(args, "-o")
    c = s["ch07"]
    if words[:1] in (["create"], ["apply"]) and stdin:
        doc = json.loads(stdin) if stdin.lstrip().startswith("{") else None
        if doc is None:
            return None
        k = doc["kind"]
        name = doc["metadata"]["name"]
        if k == "Pod" and (doc["metadata"].get("labels") or {}).get("app.kubernetes.io/component") == "key-probe":
            c["kpods"][name] = {"kind": "pod", "t": now, "checks": probe_script_runs(doc)}
            return 0, f"pod/{name} created"
        if k == "Job":
            cmd = doc["spec"]["template"]["spec"]["containers"][0]["command"]
            field = f"{cmd[cmd.index('--model') + 1]}.{cmd[cmd.index('--id') + 1]}"
            sec = s["secrets"][f"{INS}/{INF['keys']['models']['secret']}"]
            if cmd[1] == "mint":
                if field in sec:
                    c["kpods"][name] = {"kind": "job", "t": now, "log": f"sfab-keys: Secret {INS}/{INF['keys']['models']['secret']} already holds {field}", "ok": False}
                    return 0, f"job/{name} created"
                val = f"sk-tw-{cmd[cmd.index('--model') + 1]}-" + (cmd[cmd.index('--id') + 1] * 4)
                sec[field] = val
                c["values"][val] = field
                c["events"].append({"t": now, "op": "add", "field": field, "value": val})
                import hashlib  # noqa: PLC0415
                log = f"minted {field} in Secret {INS}/{INF['keys']['models']['secret']}: sha256:{hashlib.sha256(val.encode()).hexdigest()[:12]}"
            else:
                if field not in sec:
                    c["kpods"][name] = {"kind": "job", "t": now, "log": f"sfab-keys: Secret {INS}/{INF['keys']['models']['secret']} holds no {field}", "ok": False}
                    return 0, f"job/{name} created"
                sec.pop(field)
                c["events"].append({"t": now, "op": "del", "field": field})
                log = f"revoked {field} from Secret {INS}/{INF['keys']['models']['secret']}: sha256:{'ab' * 6}"
            c["kpods"][name] = {"kind": "job", "t": now, "log": log, "ok": True}
            return 0, f"job/{name} created"
        if k == "ConfigMap":
            c["cm_live"] = doc
            rendered = next(d for d in configmaps({"ch07": {}}) if d["metadata"]["name"] == name)
            ap = doc["data"].get("apisix.yaml", "")
            changed = [m["name"] for m in INF["models"]] if ap != rendered["data"].get("apisix.yaml") else []
            import yaml  # noqa: PLC0415
            rts = yaml.safe_load(ap.replace("#END", "")) or {}
            for r in rts.get("routes") or []:
                cr = r["plugins"]["consumer-restriction"]
                c["cm"].append({"t": now, "model": r["id"], "variant": "rendered" if "rejected_code" in cr else "default"})
            _ = changed
            return 0, f"configmap/{name} serverside-applied"
        if k == "HTTPRoute":
            rules = doc["spec"]["rules"]
            c["route_timeouts"] = rules[0].get("timeouts") if rules else None
            return 0, f"httproute.gateway.networking.k8s.io/{name} serverside-applied"
        return None
    if words[:2] == ["get", "pod"] and len(words) > 2 and words[2] in c["kpods"]:
        kp = c["kpods"][words[2]]
        _, end = run_probe(s, kp, now)
        return 0, "Succeeded" if end is not None and end <= now else "Running"
    if words[:1] == ["logs"] and len(words) > 1 and words[1] in api_pods(s) and W.opt(args, "-c") == "apisix":
        # the API gateway's access lines (file-logger), every request the stand-in answered, on each pod alike
        lines = [json.dumps({"time": a["time"], "client": "10.24.10.10", "host": f"llm.{DOMAIN}", "route": a["route"],
                             "request": "POST /models", "status": a["status"], "consumer": a["consumer"], "caller": a["caller"],
                             "upstream_status": "200" if a["status"] == "200" else "", "request_time": "0.300"})
                 for a in c.get("access") or []]
        return 0, "\n".join(lines)
    if IDP and words[:2] == ["get", "pods"] and ns == IDP["namespace"]:
        pods = [{"metadata": {"name": f"{IDP['name']}-5d8c-a1", "namespace": ns, "labels": {"app.kubernetes.io/name": IDP["name"]}},
                 "spec": {"nodeName": "k8s-ingress1"}, "status": {"phase": "Running", "podIP": "10.22.3.40",
                                                          "conditions": [{"type": "Ready", "status": "True"}]}}]
        if o == "json":
            return 0, json.dumps({"items": pods})
        return 0, f"NAME   READY   STATUS    NODE\n{pods[0]['metadata']['name']}   1/1   Running   k8s-ingress1"
    if IDP and words[:2] == ["get", "pods,services,httproutes"]:
        return 0, f"pod/{IDP['name']}-5d8c-a1   1/1   Running   k8s-ingress1\nservice/{IDP['name']}   ClusterIP   {IDP['port']}/TCP"
    if words[:1] == ["logs"] and len(words) > 1:
        name = words[1].split("/", 1)[-1]
        kp = c["kpods"].get(name)
        if kp is None:
            return None
        if kp["kind"] == "job":
            return 0, kp["log"]
        lines, _ = run_probe(s, kp, now)
        return 0, "\n".join(lines)
    if words[:1] == ["wait"] and any(w.startswith("job/") for w in words):
        name = next(w for w in words if w.startswith("job/"))[4:]
        kp = c["kpods"].get(name)
        return (0, "condition met") if kp and kp.get("ok") else (1, "timed out")
    if words[:1] == ["delete"] and len(words) > 2 and words[1] in ("pod", "job"):
        for n in words[2:]:
            if n in c["kpods"]:
                c["kpods"].pop(n, None)
            elif words[1] == "pod" and n in s["pods"] and n in api_pods(s):
                p = s["pods"].pop(n)
                s["seq"] = s.get("seq", 0) + 1
                new = f"{INF['gateway']['name']}-6c9f-n{s['seq']}"
                p = json.loads(json.dumps(p))
                p["metadata"]["name"] = new
                p["status"]["podIP"] = f"10.22.{W.node_index(p['spec']['nodeName'])}.{10 + s['seq']}"
                s["pods"][new] = p
                c["born"][new] = now
        return 0, ""
    if words[:1] == ["exec"] and len(words) > 1:
        pod = words[1]
        if "touch" in args and pod in s["pods"]:
            c["holds"].setdefault(pod, []).append([now, None])
            return 0, ""
        return 0, ""
    if words[:2] == ["get", "gatewayclasses"]:
        return 0, json.dumps({"items": [{"metadata": {"name": "cilium"}, "status": {"conditions": [{"type": "Accepted", "status": "True"}]}}]})
    if words[:2] in (["get", "gateways"], ["get", "gateway"]):
        rts = routes(s)
        items = []
        for d in gw_docs():
            g = d["metadata"]["name"]
            n = sum(1 for r in rts if any(p["name"] == g for p in r["spec"]["parentRefs"]))
            d["status"] = {"addresses": [{"type": "IPAddress", "value": K8S["gateways"][g]["vip"]}],
                           "conditions": [{"type": "Programmed", "status": "True"}, {"type": "Accepted", "status": "True"}],
                           "listeners": [{"name": "https", "attachedRoutes": n}]}
            items.append(d)
        if o == "wide":
            return 0, "NAMESPACE   NAME          CLASS    ADDRESS       PROGRAMMED   AGE\n" + "\n".join(
                f"gateways    {d['metadata']['name']:<14}cilium   {K8S['gateways'][d['metadata']['name']]['vip']:<14}True         9m" for d in items)
        return 0, json.dumps({"items": items})
    if words[:2] in (["get", "httproutes"], ["get", "httproute"]):
        rts = routes(s)
        if len(words) > 2:
            r = next((x for x in rts if x["metadata"]["name"] == words[2]), None)
            return (0, json.dumps(r)) if r else (1, "")
        if o == "json":
            return 0, json.dumps({"items": rts})
        return 0, "NAMESPACE   NAME   HOSTNAMES   AGE\n" + "\n".join(f"{r['metadata']['namespace']}   {r['metadata']['name']}   "
                                                                    f"{json.dumps(r['spec']['hostnames'])}   9m" for r in rts)
    if words[:2] == ["get", "namespaces"]:
        if o == "json":
            return 0, json.dumps({"items": namespaces()})
        return 0, "NAME   STATUS   AGE\n" + "\n".join(f"{d['metadata']['name']}   Active   9m" for d in namespaces())
    if words[:2] == ["get", "leases"]:
        items = [{"metadata": {"name": g["l2_lease"].split("/", 1)[1], "namespace": "kube-system"},
                  "spec": {"holderIdentity": "k8s-ingress1" if n == "gw-users" else "k8s-ingress2"}} for n, g in sorted(K8S["gateways"].items())]
        return (0, json.dumps({"items": items})) if o == "json" else (0, "NAME   HOLDER   AGE\n" + "\n".join(
            f"{i['metadata']['name']}   {i['spec']['holderIdentity']}   9m" for i in items))
    if words[:2] == ["get", "lease"] and o and o.startswith("jsonpath"):
        return 0, "k8s-ingress1" if "gw-users" in words[2] else "k8s-ingress2"
    if words[:2] == ["get", "ciliumenvoyconfigs"]:
        return 0, json.dumps(cec(s))
    if words[:2] == ["get", "ciliumenvoyconfig"]:
        items = cec(s, words[2])["items"]
        return (0, json.dumps(items[0])) if items else (1, "")
    if words[:2] == ["get", "configmap"] and len(words) > 2 and words[2] == "cilium-config":
        idle = s["ch07"]["helm"].get("idle")
        data = {"http-stream-idle-timeout": str(int(idle)) if idle else "300", "enable-gateway-api": "true"}
        if idle:
            data["proxy-stream-idle-timeout-seconds"] = str(int(idle))
        return 0, json.dumps({"metadata": {"name": "cilium-config"}, "data": data})
    if words[:2] == ["get", "configmap"] and len(words) > 2:
        d = next((x for x in configmaps(s) if x["metadata"]["name"] == words[2]), None)
        return (0, json.dumps(d)) if d else (1, "")
    if words[:2] == ["get", "configmaps"]:
        return 0, json.dumps({"items": configmaps(s)})
    if words[:2] == ["get", "deployments"]:
        return 0, json.dumps({"items": [{"metadata": {"name": TB["deployment"], "namespace": TB["namespace"]}, "spec": {"replicas": 2},
                                         "status": {"readyReplicas": 2}}]})
    if words[:2] == ["get", "secret"] and o and o.startswith("jsonpath"):
        return 0, "2026-10-22T09:00:00Z"
    if words[:1] == ["rollout"]:
        return 0, "deployment successfully rolled out"
    if words[:2] == ["get", "pods"] and ns == INS:
        items = [W.view(s, p, now) for n, p in sorted(s["pods"].items()) if p["metadata"].get("namespace") == ns]
        sel = W.opt(args, "-l")
        if sel:
            want = dict(kv.split("=", 1) for kv in sel.split(",") if "=" in kv)
            items = [p for p in items if all((p["metadata"].get("labels") or {}).get(k) == v for k, v in want.items())]
        if o == "wide":
            return 0, "NAME   READY   STATUS   IP   NODE\n" + "\n".join(f"{p['metadata']['name']}   1/1   Running   {p['status']['podIP']}   "
                                                                       f"{p['spec']['nodeName']}" for p in items)
        return 0, json.dumps({"items": items})
    return None


def bastion_other(s, cmd, stdin, now):
    """(rc, out) for the bastion's commands other than kubectl."""
    c = s["ch07"]
    if cmd[:2] == ["sfab-ca", "proof"]:
        proof = json.load(open(RENDER / "bootstrap" / "bastion" / "ca" / "proof.json"))
        out = [f"== lab CA proof (/sfab/bootstrap/ca/proof.json)"]
        for lf in proof["leaves"]:
            sans = ",".join(lf["san"])
            out.append(f"  PASS  {lf['ca']}: {sans} " + ("verifies" if lf["expect"] == "verify" else "refused (permitted subtree violation)"))
        out.append(f"== RESULT: {len(proof['leaves'])} passed, 0 failed, 0 known platform limitation(s), 0 skipped")
        return 0, "\n".join(out)
    sc = cmd[2] if cmd[:2] in (["sh", "-c"], ["bash", "-c"]) else ""
    if "openssl s_client" in sc:
        return 0, ("depth=2 CN = Tarnwick Lab Root CA\ndepth=1 CN = Tarnwick Platform CA\ndepth=0 \n 0 s:\n   i:CN = Tarnwick Platform CA\n"
                   " 1 s:CN = Tarnwick Platform CA\n   i:CN = Tarnwick Lab Root CA\nVerify return code: 0 (ok)")
    if "/sfab/ca/proof/" in sc:
        return 0, "== /sfab/ca/proof/platform-outside-1.verify.txt\nCN=proof platform-outside-1\nerror 47 at 0 depth lookup: permitted subtree violation"
    m = re.search(r"cat >(\S+)$", sc)
    if m:
        c.setdefault("bfiles", {})[m.group(1)] = stdin or ""
        return 0, ""
    if sc.startswith("helm ") and " upgrade " in sc:
        f = re.search(r"-f (\S+)", sc).group(1)
        vals = json.loads(c.get("bfiles", {}).get(f) or "{}")
        idle = (vals.get("extraConfig") or {}).get("proxy-stream-idle-timeout-seconds")
        c["helm"] = {"idle": float(idle) if idle else None, "t": now, "values": vals}
        return 0, "Release \"cilium\" has been upgraded. Happy Helming!"
    if sc.startswith("helm ") and " get values " in sc:
        vals = c["helm"].get("values")
        if vals is None:
            vals = json.load(open(RENDER / "gen" / "drills.json"))["list"][2]["cilium"]["values_rendered"]
        return 0, json.dumps(vals)
    return None


# ---------------------------------------------------------------------------- the identity provider

IDP = K8S.get("identity") or {}
SIG = "c2lnbmVkLWJ5LXRoZS1zdGFuZC1pbg"   # the stand-in's one signature: a token altered anywhere fails


def b64u(d) -> str:
    return base64.urlsafe_b64encode(json.dumps(d, sort_keys=True).encode()).decode().rstrip("=")


def token_for(scope: str, user: str) -> str:
    """An ID token as the stand-in's Dex issues it: the person's claims, the client's audience, and
    the API gateway's too when the scope asks for it."""
    cl = (IDP.get("clients") or [{}])[0].get("id")
    aud = [cl] + ([IDP["audience"]] if f"audience:server:client_id:{IDP.get('audience')}" in scope else [])
    claims = {"iss": IDP.get("issuer"), "sub": "c3ViLW9mLXRoZS1wZXJzb24", "aud": aud if len(aud) > 1 else aud[0], "azp": cl,
              "email": user, "email_verified": True, "iat": 1000, "exp": 4600, "name": user.split("@")[0]}
    return f"{b64u({'alg': 'RS256', 'kid': 'k1'})}.{b64u(claims)}.{SIG}"


def token_caller(tok: str):
    """The caller a token authenticates as, or None: the signature, the issuer, the API gateway's
    audience and a consumer for the email, as the oidc-consumer plugin checks them."""
    parts = tok.split(".")
    if len(parts) != 3 or parts[2] != SIG:
        return None
    try:
        c = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
    except ValueError:
        return None
    aud = c.get("aud") if isinstance(c.get("aud"), list) else [c.get("aud")]
    if c.get("iss") != IDP.get("issuer") or IDP.get("audience") not in aud or c.get("email_verified") is not True:
        return None
    for cl in INF.get("callers") or []:
        for x in cl.get("consumers") or []:
            if x["subject"] == c.get("email"):
                return cl["id"], x["username"]
    return None


def log_access(s, now, route, status, consumer, caller):
    s["ch07"].setdefault("access", []).append({"time": now, "route": route, "status": str(status), "consumer": consumer or "",
                                               "caller": caller or ""})


# ---------------------------------------------------------------------------- the clients

def client_key(files, argv):
    h = None
    for i, a in enumerate(argv):
        if a == "-H" and i + 1 < len(argv) and argv[i + 1].startswith("@"):
            h = argv[i + 1][1:]
    if not h:
        return None
    line = (files.get(h) or "").strip()
    return line.split("Bearer ", 1)[1] if "Bearer " in line else None


def idle_end(s, req):
    """(end time, status, body) of a request to the silent test backend."""
    c = s["ch07"]
    sent = req["sent"]
    cont = next((e["t"] for e in c["sig"] if e["sig"] == "CONT" and e["t"] >= sent), None)
    stopped = any(e["sig"] == "STOP" and e["t"] <= sent for e in c["sig"])
    idle = req["idle"]
    rt = req.get("route_s")
    ends = [(sent + idle, 504, "stream timeout")]
    if rt:
        ends.append((sent + rt, 504, "upstream request timeout"))
    if not stopped:
        ends.append((sent + 0.02, 200, None))
    elif cont is not None:
        ends.append((cont + 0.02, 200, None))
    t, st, body = min(ends, key=lambda e: e[0])
    return t, st, body


def curl7(s, ctr, argv, now):
    files = W.client_files(s, ctr)
    c = s["ch07"]
    url = next((a for a in argv if a.startswith("https://")), "")
    out, hdr, fmt = W.opt(argv, "-o"), W.opt(argv, "-D"), W.opt(argv, "-w") or ""
    host = url.split("/")[2] if url else ""
    if host.startswith("admin."):
        lp = W.opt(argv, "--local-port")
        s["refuse_req"] = {"t": now, "sport": int(lp) if lp else 51001}
        if hdr:
            files[hdr] = "HTTP/1.1 404 Not Found\r\nserver: envoy\r\ncontent-length: 0\r\n\r\n"
        if out and out != "/dev/null":
            files[out] = ""
        return fmt.replace("%{http_code}", "404").replace("%{local_port}", lp or "51001").replace("\\n", "\n")
    if "/echo" in url:
        st = 200
        if any(e["sig"] == "STOP" for e in c["sig"]) and not any(e["sig"] == "CONT" and e["t"] >= max(x["t"] for x in c["sig"] if x["sig"] == "STOP")
                                                                  for e in c["sig"]):
            st = 0
        if out and out != "/dev/null":
            files[out] = url.split("msg=", 1)[-1]
        return fmt.replace("%{http_code}", str(st)).replace("\\n", "\n")
    if IDP and host == IDP.get("hostname"):
        path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
        if path.startswith("/.well-known/openid-configuration"):
            st, body = 200, json.dumps({"issuer": IDP["issuer"], "jwks_uri": f"{IDP['issuer']}/keys",
                                        "grant_types_supported": ["authorization_code", "password"]})
        elif path.startswith(IDP.get("token_path", "/token")):
            data = [argv[i + 1] for i, a in enumerate(argv) if a in ("-d", "--data-urlencode") and i + 1 < len(argv)]
            kv = dict(x.split("=", 1) for x in data if "=" in x)
            cfg = files.get(W.opt(argv, "-K") or "", "")
            if kv.get("grant_type") != "password" or "password=" not in cfg or "user = " not in cfg:
                st, body = 401, json.dumps({"error": "invalid_client"})
            else:
                st, body = 200, json.dumps({"id_token": token_for(kv.get("scope", ""), kv.get("username", "")), "token_type": "bearer"})
        else:
            st, body = 404, ""
        if out and out != "/dev/null":
            files[out] = body
        return fmt.replace("%{http_code}", str(st)).replace("\\n", "\n")
    model = model_of_url(url)
    if model is None:
        return None
    if "--local-port" in argv:
        return None  # the trace's keyed request: chapter 6's stand-in
    key = client_key(files, argv)
    who = token_caller(key) if key and key.count(".") == 2 else None
    if key and key.count(".") == 2:
        # a person's token: answered by the caller it maps onto, refused with the one message otherwise
        ok = who is not None and model in CALLS.get(who[0], set())
        st, msg = (200, "") if ok else (int(INF["rejected"]["code"]), INF["rejected"]["message"])
    else:
        st, msg = answer_at(s, pick(s), now, model, key)
    f = field_of(s, key) if key and not who else None
    log_access(s, now, model, st, who[1] if who else (f"{f.split('.')[0]}_key_{f.split('.')[1]}" if f and st == 200 else ""),
               who[0] if who else (f.split(".")[0] if f and st == 200 else ""))
    if hdr:
        files[hdr] = (f"HTTP/1.1 {st} {'OK' if st == 200 else 'Unauthorized'}\r\nserver: envoy\r\n"
                      + (f"www-authenticate: {INF['www_authenticate']}\r\n" if st == 401 and INF.get("www_authenticate") else "")
                      + "\r\n")
    if out and out != "/dev/null":
        files[out] = json.dumps({"message": msg}) if st != 200 else json.dumps({"choices": [{"message": {"content": "yes"}}], "timings": TIMINGS})
    return fmt.replace("%{http_code}", str(st)).replace("\\n", "\n")


def probe_records7(s, run, until):
    out = {}
    t0, iv = run["start"], run["interval"]
    n = 0
    while True:
        t = t0 + n * iv
        if t > until or (run.get("count") and n >= run["count"]):
            break
        n += 1
        for m in run["models"]:
            key = run["keys"].get(m)
            st, msg = answer_at(s, pick(s, n), t, m, key)
            rec = {"n": n, "model": m, "sent": round(t, 6), "done": round(t + 0.3, 6), "status": st,
                   "outcome": "answered" if st == 200 else "failed", "why": "" if st == 200 else f"http {st}",
                   "answered_by": f"openai/{m}" if st == 200 else None, "base": None, "retries": 0 if st == 200 else None}
            out.setdefault(m, []).append(rec)
    return out


def client7(s, ctr, argv, stdin, now):
    files = W.client_files(s, ctr)
    c = s["ch07"]
    if argv[:1] == ["python3"] and len(argv) >= 3 and argv[1] == "-c":
        code = argv[2]
        if "id_token" in code and len(argv) >= 5:
            d, n = argv[3], argv[4]
            raw = files.pop(f"{d}/tok-{n}.json", None)
            try:
                t = json.loads(raw)["id_token"]
            except (TypeError, ValueError, KeyError):
                return 1, ""
            p = t.split(".")[1]
            cl = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
            files[f"{d}/hdr-{n}"] = f"Authorization: Bearer {t}\n"
            keep = {k: cl.get(k) for k in ("iss", "aud", "azp", "email", "email_verified")}
            keep["lifetime_s"] = cl["exp"] - cl["iat"]
            files[f"{d}/claims-{n}.json"] = json.dumps(keep, sort_keys=True) + "\n"
            return 0, ""
        if "open(sys.argv[2], \"w\")" in code and len(argv) >= 5:
            t = (files.get(argv[3]) or "").rstrip("\n")
            if not t:
                return 1, ""
            i = len(t) - 10
            files[argv[4]] = t[:i] + ("A" if t[i] != "A" else "B") + t[i + 1:] + "\n"
            return 0, ""
        return None
    if argv[:1] == ["cat"] and len(argv) == 2 and (argv[1].endswith("/discovery.json") or "/claims-" in argv[1]):
        v = files.get(argv[1])
        return (0, v) if v is not None else (1, "")
    if argv[:2] == ["sh", "-c"] and "openssl s_client" in argv[2]:
        # each Gateway's chain, read from a client of its population (the audit's gateway layer)
        return 0, ("depth=2 CN = Tarnwick Lab Root CA\ndepth=1 CN = Tarnwick Platform CA\ndepth=0 \n 0 s:\n   i:CN = Tarnwick Platform CA\n"
                   " 1 s:CN = Tarnwick Platform CA\n   i:CN = Tarnwick Lab Root CA\nVerify return code: 0 (ok)")
    if argv[:2] == ["sh", "-c"] and "cat > " in argv[2] and "/idp-" in argv[2]:
        m = re.search(r"cat > (\S+)$", argv[2])
        if m:
            files[m.group(1)] = stdin or ""
            return 0, ""
    if argv[:2] == ["sh", "-c"] and argv[2].startswith("rm -f ") and "/idp-" in argv[2]:
        files.pop(argv[2].split()[-1], None)
        return 0, ""
    if argv[:1] == ["curl"]:
        r = curl7(s, ctr, argv, now)
        return None if r is None else (0, r)
    if argv[:1] == ["cat"]:
        f = argv[1]
        m = re.match(r"^(\S+)/records-(\w+)\.jsonl$", f)
        if m and m.group(1) in c["probes"]:
            run = c["probes"][m.group(1)]
            recs = probe_records7(s, run, run.get("stop") or now).get(m.group(2), [])
            return 0, "".join(json.dumps(r, sort_keys=True) + "\n" for r in recs)
        m = re.match(r"^(\S+)/idle-(result|headers|body|sent)$", f)
        if m and m.group(1) in c["idle_reqs"]:
            req = c["idle_reqs"][m.group(1)]
            if m.group(2) == "sent":
                return 0, f"{req['sent']:.6f}\n"
            end, st, why = idle_end(s, req)
            if m.group(2) == "result":
                total = round(end - req["sent"], 3)
                return 0, f"{st} {total if st == 200 else 0} {total}\n"
            if m.group(2) == "headers":
                return 0, f"HTTP/1.1 {st} {'OK' if st == 200 else 'Gateway Timeout'}\r\nserver: envoy\r\n\r\n"
            return 0, (req["url"].split("msg=", 1)[-1] if st == 200 else why)
        return None
    if argv[:1] == ["touch"]:
        d = argv[1].rsplit("/", 1)[0]
        if argv[1].endswith("/stop") and d in c["probes"]:
            c["probes"][d]["stop"] = now
            files[argv[1]] = ""
            return 0, ""
        return None
    if argv[:2] == ["sh", "-c"]:
        sc = argv[2]
        m = re.search(r"pgrep -f '\[p\]robe_gateway.py --dir (\S+)'", sc)
        if m:
            p = c["probes"].get(m.group(1))
            return (0, "") if p and p.get("stop") is None else (1, "")
        m = re.search(r"pgrep -f '\[c\]url -sS --max-time", sc)
        if m:
            req = next(iter(c["idle_reqs"].values()), None) if c["idle_reqs"] else None
            if req is None:
                return 1, ""
            end, _, _ = idle_end(s, req)
            return (0, "") if now < end else (1, "")
        if "nohup curl" in sc and "idle-result" in sc:
            d = re.search(r"print\(time\.time\(\)\)' >(\S+)/idle-sent", sc).group(1)
            url = re.search(r"'(https://[^']+)'", sc).group(1)
            rt = c.get("route_timeouts")
            c["idle_reqs"] = {d: {"sent": now, "url": url, "idle": idle_now(s),
                                  "route_s": float(rt["request"].rstrip("s")) if rt else None}}
            return 0, ""
        if "probe_gateway.py" in sc and "nohup" in sc:
            a = shlex.split(sc.split(";", 1)[1].replace("nohup ", "").replace(" &", "").split(">")[0])
            d = a[a.index("--dir") + 1]
            targets = [a[i + 1] for i, x in enumerate(a) if x == "--target"]
            keys = {t_: (files.get(f"{d}/key-{t_}") or "").strip() for t_ in targets}
            c["probes"][d] = {"dir": d, "models": targets, "keys": keys, "interval": float(a[a.index("--interval") + 1]), "start": now + 0.05,
                              "stop": None}
            return 0, ""
        if "probe_gateway.py" in sc and "--count" in sc:
            a = shlex.split(sc.split(";", 1)[1])
            d = a[a.index("--dir") + 1]
            targets = [a[i + 1] for i, x in enumerate(a) if x == "--target"]
            keys = {t_: (files.get(f"{d}/key-{t_}") or "").strip() for t_ in targets}
            run = {"dir": d, "models": targets, "keys": keys, "interval": float(a[a.index("--interval") + 1]), "start": now + 0.05,
                   "count": int(a[a.index("--count") + 1])}
            recs = probe_records7(s, run, now + run["count"] * run["interval"])
            for m_, rs in recs.items():
                files[f"{d}/records-{m_}.jsonl"] = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rs)
            return 0, "\n".join(f"{m_}: sent {len(rs)}, answered {sum(1 for r in rs if r['outcome'] == 'answered')}, "
                                f"failed {sum(1 for r in rs if r['outcome'] != 'answered')}" for m_, rs in recs.items())
        if "-unknown-" in sc and "hdr-" in sc:
            d = re.search(r"mkdir -p (\S+);", sc).group(1)
            name = re.search(r">\S+/hdr-(\w+)", sc).group(1)
            k = "sk-tw-unknown-" + "4" * 32
            files[f"{d}/key-{name}"] = k + "\n"
            files[f"{d}/hdr-{name}"] = f"Authorization: Bearer {k}\n"
            return 0, ""
        if "timeout 5 bash -c" in sc:
            return 0, ""
    return None


# ---------------------------------------------------------------------------- guests: the test backend, the VIPs, keyed captures

def echo_pid(s, pod):
    return 90000 + sorted(s["pods"]).index(pod)


def pod_by_echo_pid(s, pid):
    for n in s["pods"]:
        if echo_pid(s, n) == pid:
            return n
    return None


def frame_bytes(f, payload=b""):
    flags = 0
    for ch, bit in (("F", 1), ("S", 2), ("R", 4), ("P", 8), (".", 16)):
        if ch in f["flags"]:
            flags |= bit
    eth = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    tcp = struct.pack("!HHIIBBHHH", f["sp"], f["dp"], 1, 1, 0x50, flags, 502, 0, 0)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp) + len(payload), 1, 0x4000, 64, 6, 0,
                     bytes(int(x) for x in f["src"].split(".")), bytes(int(x) for x in f["dst"].split(".")))
    return eth + ip + tcp + payload


def build_pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 2048, 1)
    for f, pl in frames:
        b = frame_bytes(f, pl)
        sec_, usec = int(f["t"]), int(round((f["t"] - int(f["t"])) * 1e6))
        out += struct.pack("<IIII", sec_, usec, len(b), len(b)) + b
    return out


# llama-server's timings in an answer, made-up figures: a rate no saved file may hold
TIMINGS = {"cache_n": 2, "prompt_n": 15, "prompt_ms": 62.5, "prompt_per_token_ms": 4.1, "prompt_per_second": 240.25,
           "predicted_n": 16, "predicted_ms": 181.5, "predicted_per_token_ms": 12.25, "predicted_per_second": 82.75}


def keyed_frames(s, pod, iface):
    """(frame, payload) at a keyed point: the trace's request with its headers."""
    r = s.get("trace_req")
    if not r:
        return []
    out = []
    plain = W.trace_frames(s, ("pod", pod, iface))
    files = W.client_files(s, f"{W.PREFIX}ent-client")
    ck = next(((v.strip().split("Bearer ", 1)[1]) for k, v in files.items() if k.endswith("/hdr-chat") and "Bearer " in v), "")
    master = s["secrets"][f"{INS}/{INF['keys']['master']['secret']}"]["key"]
    backend = s["secrets"][f"{INS}/{INF['keys']['backend']['secret']}"]["key"]
    m = next(x for x in INF["models"] if x["name"] == r["model"])
    for f in plain:
        pl = b""
        if f["len"] and f["dp"] == INF["gateway"]["port"]:
            pl = (f"POST {m['path']}/v1/chat/completions HTTP/1.1\r\nhost: llm.{DOMAIN}\r\nauthorization: Bearer {ck}\r\n"
                  f"content-type: application/json\r\n\r\n").encode()
        elif f["len"] and f["dp"] == INF["router"]["port"] and f["src"] == "10.22.9.1":
            pl = b"GET /health/readiness HTTP/1.1\r\n\r\n"  # the kubelet's probe
        elif f["len"] and f["dp"] == INF["router"]["port"]:
            pl = (f"POST /engines/{r['model']}/chat/completions HTTP/1.1\r\nHost: router.{INS}.svc.cluster.local:4000\r\n"
                  f"Authorization: Bearer {master}\r\n\r\n").encode()
        elif f["len"] and f["dp"] == 8080:
            pl = f"POST /v1/chat/completions HTTP/1.1\r\nHost: {r['model']}.serving\r\nAuthorization: Bearer {backend}\r\n\r\n".encode()
        elif f["len"]:
            # an answer, with the timings llama-server adds to it (the harness must blank them)
            pl = b"HTTP/1.1 200 OK\r\n\r\n" + json.dumps({"choices": [], "timings": TIMINGS}).encode()
        g = dict(f, len=len(pl))
        out.append((g, pl))
    return out


def echo_frames(s, pod):
    c = s["ch07"]
    req = next(iter(c["idle_reqs"].values()), None) if c["idle_reqs"] else None
    if not req:
        return []
    ip = s["pods"][pod]["status"]["podIP"]
    if pod != sorted(n for n in s["pods"] if n.startswith("echo-"))[0]:
        return []
    end, st, _ = idle_end(s, req)
    t = req["sent"]
    # the kubelet's TCP probe first (no data, its own FIN), then the proxy's request
    out = [W.frame(t + 0.002, "10.22.9.1", 41600, ip, 8080, "S", 0), W.frame(t + 0.004, "10.22.9.1", 41600, ip, 8080, "F.", 0),
           W.frame(t + 0.01, "10.22.9.7", 41500, ip, 8080, "P.", 120)]
    if st == 200:
        out.append(W.frame(end, ip, 8080, "10.22.9.7", 41500, "P.", 60))
    else:
        out.append(W.frame(end, "10.22.9.7", 41500, ip, 8080, "F.", 0))
    return out


ORIG_TRACE_FRAMES = W.trace_frames


def trace_frames7(s, point):
    kind, who, iface = point
    if kind == "pod" and who and who.startswith("echo-"):
        return echo_frames(s, who)
    out = ORIG_TRACE_FRAMES(s, point)
    rr = s.get("refuse_req")
    if kind == "guest" and iface == "bond0" and rr:
        vip = K8S["gateways"]["gw-users"]["vip"]
        out.append(W.frame(rr["t"], W.CLIENT_ADDR.get("ent-client"), rr["sport"], vip, 443, "S", 0))
    return out


W.trace_frames = trace_frames7


def guest7(s, node, script, now):
    sc = script.strip()
    c = s["ch07"]
    m = re.search(r"crictl ps --label io.kubernetes.pod.name=(\S+) --label io.kubernetes.container.name=(\S+) -q", sc)
    if m:
        p = s["pods"].get(m.group(1))
        if p is None or p["spec"]["nodeName"] != node:
            return ("", 1)
        return str(echo_pid(s, m.group(1)))
    m = re.match(r"^kill -(STOP|CONT) (\d+)$", sc)
    if m:
        c["sig"].append({"t": now, "sig": m.group(1), "pod": pod_by_echo_pid(s, int(m.group(2)))})
        return ""
    if sc.startswith("ping -c 3 -W 1 "):
        vip = sc.split()[5].rstrip(";")
        return (f"PING {vip} ({vip}) 56(84) bytes of data.\n\n--- {vip} ping statistics ---\n3 packets transmitted, 0 received, 100% packet loss, "
                f"time 2043ms\n\ntcp-open\n{vip} dev bond0.110 lladdr 02:5a:0c:00:00:01 REACHABLE")
    m = re.match(r"^base64 -w0 /tmp/sfab-rail-(\S+)\.pcap$", sc)
    if m:
        cap = (s.get("gcaps") or {}).get(m.group(1)) or {}
        pod = cap.get("pod")
        if pod and (pod in api_pods(s) or pod.startswith(INF["router"]["name"])):
            fs = [x for x in keyed_frames(s, pod, cap.get("iface")) if cap.get("start", 0) <= x[0]["t"] <= (cap.get("stop") or now) + 1]
            return base64.b64encode(build_pcap(fs)).decode()
        return None
    return None


ORIG_GUEST = W._guest


def _guest7(s, node, script, now):
    init7(s)
    r = guest7(s, node, script, now)
    if r is not None:
        return r
    return ORIG_GUEST(s, node, script, now)


W._guest = _guest7


# ---------------------------------------------------------------------------- tcpdump on the lab host: a real pcap read back

def read_pcap(path):
    b = open(path, "rb").read()
    if len(b) < 24 or b[:4] != b"\xd4\xc3\xb2\xa1":
        return None
    out, i = [], 24
    while i + 16 <= len(b):
        sec_, usec, incl, _ = struct.unpack("<IIII", b[i:i + 16])
        fr = b[i + 16:i + 16 + incl]
        i += 16 + incl
        if len(fr) < 54:
            continue
        ip = fr[14:34]
        src, dst = ".".join(str(x) for x in ip[12:16]), ".".join(str(x) for x in ip[16:20])
        sp, dp, _, _, off, fl = struct.unpack("!HHIIBB", fr[34:48])
        hl = (off >> 4) * 4
        pl = fr[34 + hl:]
        flags = "".join(ch for ch, bit in (("F", 1), ("S", 2), ("R", 4), ("P", 8)) if fl & bit) + ("." if fl & 16 else "")
        out.append(({"t": sec_ + usec / 1e6, "src": src, "sp": sp, "dst": dst, "dp": dp, "flags": flags, "len": len(pl)}, pl))
    return out


def tcpdump7(argv):
    if "-r" in argv and "-w" not in argv:
        f = os.path.abspath(argv[argv.index("-r") + 1])
        frs = read_pcap(f)
        if frs is not None:
            lines = []
            for fr, pl in frs:
                lines.append(W.fmt(fr))
                if "-A" in argv:
                    lines.append(pl.decode("latin-1").replace("\r", ""))
            print("\n".join(lines))
            return 0
    return W.tcpdump(argv)


# ---------------------------------------------------------------------------- the tools

def docker7(argv):
    if argv[:1] != ["exec"]:
        return W.delegate("docker", argv)
    rest = argv[1:]
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in ("-e", "-u", "-w") else rest[1:]
    ctr, cmd = rest[0], rest[1:]
    stdin = sys.stdin.read() if "-i" in argv[1:argv.index(ctr)] else None
    node = ctr[len(W.PREFIX):] if ctr.startswith(W.PREFIX) else ""
    kind = (W.NODES.get(node) or {}).get("kind")
    if kind in ("bastion", "client"):
        with W.locked():
            s = W.load()
            init7(s)
            now = time.time()
            if kind == "bastion":
                r = kubectl7(s, cmd[1:], stdin, now) if cmd[:1] == ["kubectl"] else bastion_other(s, cmd, stdin, now)
                if r is None and cmd[:1] == ["kubectl"]:
                    r = W.kubectl(s, cmd[1:], stdin, now)
            else:
                r = client7(s, ctr, cmd, stdin, now)
                if r is None:
                    r = W.client_exec(s, ctr, cmd, stdin, now)
            W.save(s)
        if r is not None:
            W.log("docker", argv)
            rc, out = r
            if out:
                sys.stdout.write(out if out.endswith("\n") else out + "\n")
            return rc
    return W.delegate("docker", argv, stdin)


def knode7(s, cmd, stdin, now):
    """The init node's kubectl and scripts (lib.sh K, KSH): chapter 7's answers first."""
    init7(s)
    r = kubectl7(s, cmd[1:], stdin, now) if cmd[:1] == ["kubectl"] else bastion_other(s, cmd, stdin, now)
    if r is None and cmd[:1] == ["kubectl"]:
        r = W.kubectl(s, cmd[1:], stdin, now)
    return r


if __name__ == "__main__":
    tool = sys.argv[1]
    W.KUBE_HOOK = knode7
    if tool == "docker":
        sys.exit(docker7(sys.argv[2:]))
    if tool == "tcpdump":
        sys.exit(tcpdump7(sys.argv[2:]))
    sys.exit({"ssh": W.ssh_tool, "sshpass": W.sshpass, "nsenter": W.nsenter}[tool](sys.argv[2:]))
