"""The placement group of judge.py (chapter 6): the serving pods read back against the placement table.

audit_placement in lib-audit.sh saves the reads into the set's placement/ (the table it judges
against as placement/serving.env: the rendered bootstrap/k8s/serving.env, or the one audit.sh
--table names), then `judge.py run ... placement` judges them, from the saved files only:

  the table       the recipe's own rules (serving-layer/serving.py check): every pod of a copy on one
                  rail, one server and at least one worker a copy, every rail address inside its
                  rail's prefix and given once, every row the pod 0 of its own StatefulSet; and the
                  failure domains: every model keeps a copy through the loss of either rail switch
                  (a copy counts as lost with the switch of its rail) and of any one GPU node (a copy
                  counts as lost with every node one of its pods sits on)
  each row        its pod Running and Ready on the row's node, owned by the row's StatefulSet, its
                  network-status annotation naming the row's attachment with the row's address and
                  MAC, its labels naming the row's model, copy, role and rail
  StatefulSets    one a row, one replica, updating on delete; none the table does not name
  each server     llama-server's --rpc naming its workers' rail addresses at the RPC port, bound to
                  the pod's own cluster address (--host from the downward API's POD_IP) and listening
                  there alone, its model read from the models volume (read-only), and its readiness
                  probe the RPC-aware one (sfab-ready server, over the rail) with the table's timers;
                  each worker ggml-rpc-server bound to its own rail address and listening there alone
  models volumes  for every node that runs a server, a local PersistentVolume of the models path on
                  that node, read-only, Bound to its claim in the namespace
  attachments     one macvlan NetworkAttachmentDefinition per rail the table uses: the rail NIC as
                  master, bridge mode, the rail MTU, the static IPAM plugin and no route; none other
  Services        one per model and one per copy, each with exactly its servers' pod addresses as
                  ready endpoints
  routes          inside every pod: the default route on eth0, and on the rail attachment only its
                  connected prefix (read on the pod's node, in its network namespace)
  no stray pod    no server or worker pod the table does not name
  the Gateways    one request a model through each model route a client of the lab reaches, with
                  the model's key: HTTP 200, answered by the router's deployment for that model

Each check is a PASS or FAIL line; a FAIL names the row, the pod or the Service.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NETWORK_STATUS = "k8s.v1.cni.cncf.io/network-status"
NETWORKS = "k8s.v1.cni.cncf.io/networks"


def recipe():
    """serving-layer/serving.py, loaded by path (it is the recipe's own tool)."""
    name = "sfab_serving_recipe_placement"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, ROOT / "serving-layer" / "serving.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _json(p: Path):
    import evfile  # noqa: PLC0415

    try:
        return json.loads(evfile.read_text(p, "strict"))
    except (OSError, ValueError):
        return None


def _text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _ready(p: dict) -> bool:
    st = p.get("status") or {}
    cs = st.get("containerStatuses") or []
    return st.get("phase") == "Running" and bool(cs) and all(c.get("ready") for c in cs)


def _status_nets(pod: dict) -> list:
    raw = ((pod.get("metadata") or {}).get("annotations") or {}).get(NETWORK_STATUS)
    try:
        return json.loads(raw) if raw else []
    except ValueError:
        return []


def _container(pod: dict, name: str) -> dict:
    return next((c for c in (pod.get("spec") or {}).get("containers") or [] if c.get("name") == name), {})


def _controller(p: dict) -> str:
    """A row's StatefulSet: its pod's name without the ordinal (every row's pod is pod 0)."""
    return p["pod"][:-2] if p["pod"].endswith("-0") else p["pod"]


def _listening(p: Path):
    """The (address, port) pairs of the listening TCP sockets ss -Hltn saved, or None when unread."""
    text = _text(p)
    if not text.strip():
        return None
    out = []
    for line in text.splitlines():
        w = line.split()
        if len(w) >= 4 and w[0] == "LISTEN":
            a, _, port = w[3].rpartition(":")
            out.append((a.strip("[]"), port))
    return out


def _arg(cmd: list, flag: str):
    return cmd[cmd.index(flag) + 1] if flag in cmd and cmd.index(flag) + 1 < len(cmd) else None


def g_placement(self, names):
    d = self.rs.path / "placement"
    v = self.v
    v.sec("placement: the serving pods read back against the table (chapter 6)")
    sv = recipe()
    try:
        env = sv.read_env(d / "serving.env")
    except sv.ServingError as e:
        v.bad("the placement table", str(e))
        return
    # the table, by the recipe's own rules
    try:
        s = sv.settings(env)
        v.ok(f"the table: {len(s.pods)} pods of {len(s.copies)} copies of {len(s.models)} models; every copy on one rail with one server and "
             f"{min(len(c['workers']) for c in s.copies.values())} or more workers, every rail address inside its rail's prefix and given once")
    except sv.ServingError as e:
        v.bad("the table keeps the recipe's rules (every pod of a copy on one rail, one server and a worker a copy, every address once)", str(e))
        s = None
        # judge the rows anyway: the table may break the rules and still name every pod
        try:
            pods_ = sv.table(env, "POD")
            nads_ = sv.table(env, "NAD")
        except sv.ServingError as e2:
            v.bad("the table's rows", str(e2))
            return
    if s is not None:
        pods_, nads_ = s.pods, s.nads
    ns = env.get("SERVING_NAMESPACE", "serving")
    rails_sw = {}
    for name, n in (self.inv.get("nodes") or {}).items():
        for r, ri in ((n.get("rails") or {}).items() if isinstance(n.get("rails"), dict) else []):
            rails_sw.setdefault(int(r), ri.get("switch"))
    copies: dict = {}
    nodes_of: dict = {}
    for p in pods_:
        copies.setdefault((p["model"], p["copy"]), set()).add(int(p["rail"]))
        nodes_of.setdefault((p["model"], p["copy"]), set()).add(p["node"])
    by_model: dict = {}
    for (m, c), rs in copies.items():
        by_model.setdefault(m, []).append((c, sorted(rs)))
    switches = sorted({x for x in rails_sw.values() if x})
    gpu_nodes = sorted({p["node"] for p in pods_})
    lost = []
    for m, cs in sorted(by_model.items()):
        for sw in switches:
            if all(any(rails_sw.get(r) == sw for r in rs) for _, rs in cs):
                lost.append(f"{m}: every copy rides {sw}")
        for n in gpu_nodes:
            if all(n in nodes_of[(m, c)] for c, _ in cs):
                lost.append(f"{m}: every copy has a pod on {n}")
    v.check("each model keeps a copy through the loss of either rail switch and of any one GPU node: "
            + "; ".join(f"{m}: " + ", ".join(f"{c} rail {'/'.join(map(str, r))} ({rails_sw.get(r[0])}) on {'+'.join(sorted(nodes_of[(m, c)]))}"
                                             for c, r in sorted(cs)) for m, cs in sorted(by_model.items())),
            not lost, "; ".join(lost))
    pods = _json(d / "pods.json")
    if pods is None:
        v.bad("the serving pods", "placement/pods.json was not read")
        return
    items = {i["metadata"]["name"]: i for i in pods.get("items") or []}
    label = env.get("SERVING_LABEL_PREFIX", "")
    rpc = env.get("SERVING_RPC_PORT", "50052")
    period, fails, tmo = (env.get(k) for k in ("SERVING_READINESS_PERIOD_S", "SERVING_READINESS_FAILURES", "SERVING_READINESS_TIMEOUT_S"))
    workers_of: dict = {}
    for p in pods_:
        if p["role"] == "worker":
            workers_of.setdefault((p["model"], p["copy"]), []).append(p)
    v.sec("placement: each row of the table")
    for p in pods_:
        got = items.get(p["pod"])
        ip = str(ipaddress.ip_interface(p["address"]).ip)
        mac = f" {p['mac']}" if p.get("mac") not in (None, "", "-") else ""
        lab_ = f"{p['pod']} ({p['model']} copy {p['copy']}, {p['role']}): on {p['node']}, rail {p['rail']} as {p['nad']} {ip}{mac}, Ready"
        if got is None:
            v.bad(lab_, "no such pod")
            continue
        probs = []
        node = (got.get("spec") or {}).get("nodeName")
        if node != p["node"]:
            probs.append(f"on {node}")
        nets = _status_nets(got)
        att = next((n for n in nets if n.get("name") in (p["nad"], f"{ns}/{p['nad']}")), None)
        others = [f"{n.get('name')} {','.join(n.get('ips') or [])}" for n in nets if not n.get("default") and n is not att]
        if att is None:
            probs.append("network-status names " + ("; ".join(others) or "no rail attachment"))
        elif ip not in (att.get("ips") or []):
            probs.append(f"{p['nad']} at {','.join(att.get('ips') or [])}")
        if att is not None and p.get("mac") not in (None, "", "-") and str(att.get("mac") or "").lower() != p["mac"]:
            probs.append(f"MAC {att.get('mac') or 'none'}, not the row's {p['mac']}")
        if att is not None and others:
            probs.append("also " + "; ".join(others))
        lb = (got.get("metadata") or {}).get("labels") or {}
        for k, want in (("model", p["model"]), ("copy", p["copy"]), ("role", p["role"]), ("rail", p["nad"])):
            if lb.get(f"{label}/{k}") != want:
                probs.append(f"label {k}={lb.get(f'{label}/{k}')}")
        owners = [o.get("name") for o in (got.get("metadata") or {}).get("ownerReferences") or [] if o.get("kind") == "StatefulSet"]
        if owners != [_controller(p)]:
            probs.append(f"owned by {', '.join(owners) or 'no StatefulSet'}, not StatefulSet {_controller(p)}")
        if not _ready(got):
            probs.append("not Ready")
        v.check(lab_, not probs, "; ".join(probs))
    v.sec("placement: the StatefulSets")
    sts = _json(d / "statefulsets.json")
    if sts is None:
        v.bad("the StatefulSets", "placement/statefulsets.json was not read")
    else:
        have = {i["metadata"]["name"]: i for i in sts.get("items") or []}
        bad = []
        for p in pods_:
            i = have.get(_controller(p))
            if i is None:
                bad.append(f"{_controller(p)}: absent")
                continue
            sp = i.get("spec") or {}
            if sp.get("replicas") != 1 or (sp.get("updateStrategy") or {}).get("type") != "OnDelete":
                bad.append(f"{_controller(p)}: replicas {sp.get('replicas')}, update {(sp.get('updateStrategy') or {}).get('type')}")
        extra = sorted(n for n, i in have.items() if ((i.get("metadata") or {}).get("labels") or {}).get("app.kubernetes.io/name") == "serving"
                       and n not in {_controller(p) for p in pods_})
        v.check(f"one StatefulSet a row ({len(pods_)}), each of one replica that updates on delete, so a pod made again keeps its row's "
                "name, node, rail address and MAC", not bad, "; ".join(bad))
        v.check("no StatefulSet the table does not name", not extra, ", ".join(extra))
    v.sec("placement: the servers' RPC lists, the workers' bind addresses and the readiness probes")
    for p in pods_:
        got = items.get(p["pod"])
        if got is None:
            continue
        ip = str(ipaddress.ip_interface(p["address"]).ip)
        if p["role"] == "server":
            c = _container(got, "server")
            cmd = [str(x) for x in c.get("command") or []]
            want = ",".join(f"{ipaddress.ip_interface(w['address']).ip}:{rpc}" for w in workers_of.get((p["model"], p["copy"]), []))
            have = _arg(cmd, "--rpc")
            v.check(f"{p['pod']}: llama-server --rpc {want}, its workers' rail addresses", have == want, f"--rpc {have}")
            env_ = {e.get("name"): e for e in c.get("env") or []}
            fr = (((env_.get("POD_IP") or {}).get("valueFrom") or {}).get("fieldRef") or {}).get("fieldPath")
            v.check(f"{p['pod']}: llama-server bound to the pod's own cluster address (--host $(POD_IP), POD_IP from status.podIP)",
                    _arg(cmd, "--host") == "$(POD_IP)" and fr == "status.podIP", f"--host {_arg(cmd, '--host')}, POD_IP from {fr}")
            pod_ip = (got.get("status") or {}).get("podIP") or ""
            lis = _listening(d / f"pod-{p['pod']}-listen.txt")
            http = env.get("SERVING_HTTP_PORT", "8080")
            on = sorted(a for a, port in lis if port == http)
            v.check(f"{p['pod']}: listening on {pod_ip}:{http} alone, nothing on the rail or every address", on == [pod_ip],
                    f"port {http} on {', '.join(on) or 'nothing'}" if lis is not None else "the pod's sockets were not read")
            mnt = next((m for m in c.get("volumeMounts") or [] if m.get("name") == "models"), {})
            vol = next((x for x in (got.get("spec") or {}).get("volumes") or [] if x.get("name") == "models"), {})
            claim = (vol.get("persistentVolumeClaim") or {})
            mfile = _arg(cmd, "-m") or ""
            v.check(f"{p['pod']}: its model {mfile} from the models volume of {p['node']}, read-only (claim models-{p['node']})",
                    mnt.get("readOnly") is True and claim.get("readOnly") is True and claim.get("claimName") == f"models-{p['node']}"
                    and mfile.startswith(str(mnt.get("mountPath") or "/models") + "/"),
                    f"mount {mnt.get('mountPath')} readOnly {mnt.get('readOnly')}, claim {claim.get('claimName')} readOnly {claim.get('readOnly')}")
            rp = c.get("readinessProbe") or {}
            pc = [str(x) for x in ((rp.get("exec") or {}).get("command") or [])]
            ok_ = (pc[:2] == ["sfab-ready", "server"] and all(str(ipaddress.ip_interface(w["address"]).ip) in pc
                                                                for w in workers_of.get((p["model"], p["copy"]), []))
                   and str(rp.get("periodSeconds")) == period and str(rp.get("failureThreshold")) == fails and str(rp.get("timeoutSeconds")) == tmo)
            v.check(f"{p['pod']}: readiness over the rail (sfab-ready server, every worker), every {period} s, out after {fails} failures, "
                    f"each probe up to {tmo} s", ok_,
                    f"{' '.join(pc[:2]) or 'no exec probe'}, every {rp.get('periodSeconds')} s, {rp.get('failureThreshold')} failures, "
                    f"{rp.get('timeoutSeconds')} s")
        else:
            c = _container(got, "worker")
            cmd = [str(x) for x in c.get("command") or []]
            have = f"{_arg(cmd, '-H')}:{_arg(cmd, '-p')}"
            v.check(f"{p['pod']}: ggml-rpc-server bound to its rail address {ip}:{rpc}", have == f"{ip}:{rpc}", f"bound to {have}")
            lis = _listening(d / f"pod-{p['pod']}-listen.txt")
            on = sorted(a for a, port in (lis or []) if port == rpc)
            v.check(f"{p['pod']}: listening on {ip}:{rpc} alone (ggml-rpc only on the rail; the pod's cluster interface answers nothing)",
                    lis is not None and on == [ip] and len(lis) == 1,
                    f"listening on {', '.join(f'{a}:{q}' for a, q in lis) or 'nothing'}" if lis is not None else "the pod's sockets were not read")
    v.sec("placement: the models volumes")
    pvs, pvcs = _json(d / "pvs.json"), _json(d / "pvcs.json")
    mpath = env.get("SERVING_MODELS_PATH", "")
    snodes = sorted({p["node"] for p in pods_ if p["role"] == "server"})
    if pvs is None or pvcs is None:
        v.bad("the models volumes", "placement/pvs.json or pvcs.json was not read")
    else:
        pv_by = {i["metadata"]["name"]: i for i in pvs.get("items") or []}
        pvc_by = {i["metadata"]["name"]: i for i in pvcs.get("items") or []}
        for n in snodes:
            claim = pvc_by.get(f"models-{n}") or {}
            pv = pv_by.get((claim.get("spec") or {}).get("volumeName") or "") or {}
            ps = pv.get("spec") or {}
            terms = (((ps.get("nodeAffinity") or {}).get("required") or {}).get("nodeSelectorTerms") or [{}])[0].get("matchExpressions") or []
            ok_ = ((claim.get("status") or {}).get("phase") == "Bound" and (ps.get("local") or {}).get("path") == mpath
                   and ps.get("accessModes") == ["ReadOnlyMany"] and any(t_.get("values") == [n] for t_ in terms))
            v.check(f"{n}: claim models-{n} Bound to a local PersistentVolume of {mpath} on {n}, read-only many", ok_,
                    f"claim {(claim.get('status') or {}).get('phase') or 'absent'}, path {(ps.get('local') or {}).get('path')}, "
                    f"modes {ps.get('accessModes')}")
    v.sec("placement: the rail attachments")
    nads = _json(d / "nads.json")
    if nads is None:
        v.bad("the rail attachments", "placement/nads.json was not read")
    else:
        have = {i["metadata"]["name"]: i for i in nads.get("items") or []}
        used = sorted({p["nad"] for p in pods_})
        want = {n["name"]: n for n in nads_}
        bad = []
        for name in used:
            i = have.get(name)
            if i is None:
                bad.append(f"{name}: absent")
                continue
            try:
                conf = json.loads((i.get("spec") or {}).get("config") or "{}")
            except ValueError:
                bad.append(f"{name}: config is not JSON")
                continue
            w = want.get(name) or {}
            probs = []
            if conf.get("type") != "macvlan" or conf.get("mode") != "bridge":
                probs.append(f"{conf.get('type')} {conf.get('mode')}")
            if w and conf.get("master") != w.get("master"):
                probs.append(f"master {conf.get('master')}")
            if w and str(conf.get("mtu")) != str(w.get("mtu")):
                probs.append(f"mtu {conf.get('mtu')}")
            ipam = conf.get("ipam") or {}
            if ipam.get("type") != "static" or ipam.get("routes") or conf.get("routes"):
                probs.append(f"ipam {ipam.get('type')}{' with routes' if ipam.get('routes') or conf.get('routes') else ''}")
            if probs:
                bad.append(f"{name}: {', '.join(probs)}")
        extra = sorted(set(have) - set(used))
        v.check(f"one macvlan attachment per rail the table uses ({', '.join(used)}): the rail NIC as master, bridge mode, MTU "
                f"{(nads_[0] if nads_ else {}).get('mtu', '?')}, the static IPAM plugin and no route", not bad, "; ".join(bad))
        v.check("no rail attachment the table does not use", not extra, ", ".join(extra))
    v.sec("placement: the Services")
    eps = _json(d / "endpointslices.json")
    ready: dict = {}
    for sl in (eps or {}).get("items") or []:
        svc = ((sl.get("metadata") or {}).get("labels") or {}).get("kubernetes.io/service-name")
        for e in sl.get("endpoints") or []:
            if svc and (e.get("conditions") or {}).get("ready"):
                ready.setdefault(svc, set()).update(e.get("addresses") or [])
    ip_of = {n: (i.get("status") or {}).get("podIP") for n, i in items.items()}
    svcs = []
    for m in sorted(by_model):
        svcs.append((m, [p["pod"] for p in pods_ if p["model"] == m and p["role"] == "server"]))
    for (m, c) in sorted(copies):
        svcs.append((f"{m}-{c}", [p["pod"] for p in pods_ if p["model"] == m and p["copy"] == c and p["role"] == "server"]))
    for name, servers in svcs:
        want = sorted(ip_of.get(x) or f"{x}?" for x in servers)
        have = sorted(ready.get(name) or [])
        v.check(f"Service {name}: its ready endpoints are its servers ({', '.join(servers)}: {' '.join(want)})", eps is not None and have == want,
                f"ready: {' '.join(have) or 'none'}")
    v.sec("placement: each pod's routes")
    rbad, seen = [], 0
    for p in pods_:
        rt = _json(d / f"pod-{p['pod']}-routes.json")
        if rt is None:
            rbad.append(f"{p['pod']}: not read")
            continue
        seen += 1
        prefix = str(ipaddress.ip_interface(p["address"]).network)
        dflt = [r for r in rt if r.get("dst") == "default"]
        on_rail = [r for r in rt if r.get("dev") == p["nad"]]
        if not dflt or any(r.get("dev") != "eth0" for r in dflt):
            rbad.append(f"{p['pod']}: default " + ",".join(f"dev {r.get('dev')}" for r in dflt) if dflt else f"{p['pod']}: no default route")
        if [r.get("dst") for r in on_rail] != [prefix] or any(r.get("gateway") for r in on_rail):
            rbad.append(f"{p['pod']}: on {p['nad']}: " + ", ".join(f"{r.get('dst')}{' via ' + r['gateway'] if r.get('gateway') else ''}" for r in on_rail))
    v.check(f"in every pod the default route on eth0, and on its rail attachment only the rail's connected prefix ({seen} pods read on their "
            "nodes)", seen == len(pods_) and not rbad, "; ".join(rbad[:3]))
    stray = sorted(n for n, i in items.items()
                   if ((i.get("metadata") or {}).get("labels") or {}).get("app.kubernetes.io/component") in ("server", "worker")
                   and n not in {p["pod"] for p in pods_})
    v.check("no server or worker pod the table does not name", not stray, ", ".join(stray))
    gws = sorted(d.glob("gateway-*-result.txt"))
    if gws:
        v.sec("placement: a request a model through the Gateways")
    for f in gws:
        tag = f.name[len("gateway-"):-len("-result.txt")]
        meta = _json(d / f"gateway-{tag}.json") or {}
        res = _text(f).split()
        status = res[0] if res else "none"
        hdr = {}
        for line in _text(d / f"gateway-{tag}-headers.txt").splitlines():
            k, sep, val = line.partition(":")
            if sep:
                hdr[k.strip().lower()] = val.strip()
        want = f"openai/{meta.get('model')}"
        v.check(f"{meta.get('model')} through {meta.get('gateway')} from {meta.get('client')}: HTTP 200, answered by the router's {want} deployment",
                status == "200" and hdr.get("x-litellm-model-name") == want, f"HTTP {status}, {hdr.get('x-litellm-model-name') or 'no router header'}")
