#!/usr/bin/env python3
"""gwdrill.py: chapter 7's gateway drills, the Python half (common/drill/lib-gwdrill.sh runs them).

    gwdrill.py get     --plan gen/drills.json PATH       a value of the plan (lists one item a line)
    gwdrill.py kid     --plan gen/drills.json --drill ID --pass N
                                                         the key id a key-lifecycle pass mints: the
                                                         drill's id base plus the pass number
    gwdrill.py whole   --plan gen/drills.json --dir DIR  the gateway layer whole, from one poll's saved
                                                         reads: every API gateway and router pod Ready
                                                         at the Deployment's count, both Gateways
                                                         Programmed, the test backend ready
    gwdrill.py idle    --cec FILE --name NAME            a Gateway's listener stream idle timeout as its
                                                         CiliumEnvoyConfig holds it ("unset" when its
                                                         connection manager sets none)
    gwdrill.py analyze --plan gen/drills.json --dir DIR --drill ID --pass N
    gwdrill.py summarize --set DIR [--stamp TEXT]        DRILLS.md

analyze reads one pass of one drill from its directory, prints the result vocabulary (appending
to $SFAB_VERDICT) and writes analysis.json and analysis.txt:

  key-lifecycle  the mint and the revoke as the key Jobs logged them (each key by its fingerprint);
                 per API gateway pod, when it first accepted the new key (the per-pod probe's
                 rounds) and when it first refused it after the revoke; the first 200 through the
                 VIP and how many of the VIP's requests were refused while some pod still lacked
                 the key; the new key refused on the other model's route through the VIP and at
                 every pod; the gateway probe's requests by how they ended (the criterion: none
                 failed); the Secret's fields the same before and after
  rejected-code  per pod, the status and message the route without its rejected code answered,
                 and when; then the rendered 401 and its message back at every pod; the same
                 through the VIP; the route's own key answered; none of the probe's requests failed;
                 the routes ConfigMap the render's again
  idle-timeout   each half's request: its status, when it ended, the server that answered and the
                 listener's stream idle timeout then; the backend's pod capture: whether the backend
                 sent a byte before it was continued and who closed its connection, and when;
                 the rendered chain back (the listener's timeout, the route's timeouts, the helm
                 values)

Every time is the lab host's clock (the timeline's stamps, the probe pod's and the client's, whose
clocks are a guest's and a container's). Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
sys.path.insert(0, str(HERE.parent / "trace"))
import evfile  # noqa: E402
import vocab  # noqa: E402

TCP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]")
# the TCP payload length: the first ", length N" after the flags (tcpdump may follow it with the
# protocol it recognises on the port, as in "length 742: HTTP" on 8080)
LEN = re.compile(r"Flags \[[^\]]*\].*?, length (\d+)")
TS = re.compile(r"^(\d+\.\d+) ")


def load(p):
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def jlines(p) -> list:
    out = []
    for line in read(p).splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def drill(plan: dict, did: str) -> dict:
    return next(d for d in plan["list"] if d["id"] == did)


def cmd_get(a) -> int:
    cur = load(a.plan)
    for part in a.path.split("."):
        if isinstance(cur, list):
            cur = next((x for x in cur if isinstance(x, dict) and x.get("id") == part), None) if not part.isdigit() else (
                cur[int(part)] if int(part) < len(cur) else None)
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = None
        if cur is None:
            return 1
    if isinstance(cur, list):
        print("\n".join(json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else str(x) for x in cur))
    elif isinstance(cur, dict):
        print(json.dumps(cur, sort_keys=True))
    elif isinstance(cur, bool):
        print("1" if cur else "0")
    else:
        print(cur)
    return 0


def cmd_kid(a) -> int:
    d = drill(load(a.plan), a.drill)
    base = int(d["id_base"], 16)
    print(f"{base + int(a.pass_):08x}")
    return 0


def _ready(p: dict) -> bool:
    st = p.get("status") or {}
    cs = st.get("containerStatuses") or []
    return st.get("phase") == "Running" and bool(cs) and all(c.get("ready") for c in cs)


def cmd_whole(a) -> int:
    plan = load(a.plan)
    gl = plan["gateway_layer"]
    d = Path(a.dir)
    bad = []
    try:
        pods = load(d / "pods.json").get("items") or []
    except (OSError, ValueError):
        pods = []
    for who in ("api_gateway", "router"):
        sel = gl[who]["selector"]
        k, _, v = sel.partition("=")
        ps = [p for p in pods if ((p.get("metadata") or {}).get("labels") or {}).get(k) == v]
        notready = [p["metadata"]["name"] for p in ps if not _ready(p)]
        if not ps or notready:
            bad.append(f"{gl[who]['name']}: {len(ps)} pods, not Ready {', '.join(notready) or '-'}")
    try:
        deps = load(d / "deployments.json").get("items") or []
    except (OSError, ValueError):
        deps = []
    for dp in deps:
        s = dp.get("status") or {}
        if (s.get("readyReplicas") or 0) != ((dp.get("spec") or {}).get("replicas") or 0):
            bad.append(f"deployment {dp['metadata']['name']}: {s.get('readyReplicas') or 0} of {(dp.get('spec') or {}).get('replicas')} ready")
    try:
        gws = load(d / "gateways.json").get("items") or []
    except (OSError, ValueError):
        gws = []
    want = set((plan.get("gateway_layer") or {}).get("gateways") or [])
    prog = {g["metadata"]["name"] for g in gws if any(c.get("type") == "Programmed" and c.get("status") == "True"
                                                    for c in (g.get("status") or {}).get("conditions") or [])}
    if not gws or (want and not want <= prog):
        bad.append(f"Gateways Programmed: {', '.join(sorted(prog)) or 'none'}")
    if bad:
        print("; ".join(bad))
        return 1
    print("every API gateway and router pod Ready, both Gateways Programmed, the test backend ready")
    return 0


def idle_of(doc: dict, name: str) -> str:
    sys.path.insert(0, str(HERE.parent / "audit"))
    from gwlayer import _idle  # noqa: PLC0415

    items = {"items": [i for i in (doc or {}).get("items") or [doc] if (i.get("metadata") or {}).get("name") == name]}
    vals = _idle(items).get(name)
    return ",".join(vals) if vals else "absent"


def cmd_idle(a) -> int:
    try:
        doc = load(a.cec)
    except (OSError, ValueError):
        print("unreadable")
        return 1
    print(idle_of(doc, a.name))
    return 0


# --------------------------------------------------------------------------------------------
# the timeline and the probes


def timeline(d: Path) -> list:
    out = []
    for line in read(d / "timeline.txt").splitlines():
        parts = line.split(" ", 2)
        if len(parts) >= 2:
            try:
                out.append((float(parts[0]), parts[1], parts[2] if len(parts) > 2 else ""))
            except ValueError:
                pass
    return out


def stamp(tl: list, event: str):
    return next((t for t, e, _ in tl if e == event), None)


def probe_counts(v, d: Path, plan: dict, label: str) -> list:
    out = []
    for m in [x["model"] for x in plan["probes"]["gateway"]["models"]]:
        rs = jlines(d / f"records-{m}.jsonl")
        failed = [r for r in rs if r.get("outcome") != "answered"]
        v.check(f"{label}: {m} through {plan['probes']['gateway']['gateway']}: {len(failed)} of {len(rs)} requests failed",
                bool(rs) and not failed, ", ".join(f"#{r.get('n')} {r.get('why')}" for r in failed[:4]) or "no request recorded")
        out.append({"model": m, "sent": len(rs), "failed": len(failed)})
    return out


def per_pod(rows: list, expect: int, since=None) -> dict:
    out: dict = {}
    for r in sorted((x for x in rows if "pod" in x), key=lambda x: x.get("t") or 0):
        if since is not None and (r.get("t") or 0) < since:
            continue
        p = out.setdefault(r["pod"], {"first": None, "rounds": 0, "statuses": [], "message": None})
        p["rounds"] += 1
        st = r.get("status")
        if not p["statuses"] or p["statuses"][-1] != st:
            p["statuses"].append(st)
        if st == expect and p["first"] is None:
            p["first"] = r.get("t")
            p["message"] = r.get("message")
    return out


def log_line(path: Path, pat: str) -> str:
    return next((l.strip() for l in read(path).splitlines() if re.search(pat, l)), "")


def _fp(line: str) -> str:
    m = re.search(r"sha256:[0-9a-f]{12}", line)
    return m.group(0) if m else "-"


def curl_res(path: Path) -> dict:
    """curl's -w line: the status, and the times to the first byte and to the end when it printed them."""
    parts = (read(path).strip().splitlines() or [""])[-1].split()
    out = {"status": 0, "ttfb": None, "total": None}
    try:
        out["status"] = int(parts[0])
        out["ttfb"] = float(parts[1]) if len(parts) > 1 else None
        out["total"] = float(parts[2]) if len(parts) > 2 else None
    except (IndexError, ValueError):
        pass
    return out


def headers(path: Path) -> dict:
    out = {}
    for line in read(path).splitlines():
        k, sep, val = line.partition(":")
        if sep and k.strip() and " " not in k.strip():
            out[k.strip().lower()] = val.strip()
    return out


def frames(text: str) -> list:
    out = []
    lines = (text or "").splitlines()
    i = 0
    while i < len(lines):
        m0 = TS.match(lines[i])
        if not m0:
            i += 1
            continue
        body = lines[i]
        while i + 1 < len(lines) and lines[i + 1][:1].isspace():
            i += 1
            body += " " + lines[i].strip()
        i += 1
        m = TCP.search(body)
        if not m:
            continue
        lm = LEN.search(body)
        out.append({"t": float(m0.group(1)), "src": m.group(1), "sport": int(m.group(2)), "dst": m.group(3), "dport": int(m.group(4)),
                    "flags": m.group(5), "length": int(lm.group(1)) if lm else 0})
    return out


# --------------------------------------------------------------------------------------------
# analyze


def analyze_keys(v, plan: dict, dd: dict, d: Path, pass_: str) -> dict:
    tl = timeline(d)
    minted, revoked = stamp(tl, "MINTED"), stamp(tl, "REVOKED")
    pre = f"pass {pass_} {dd['id']}"
    out: dict = {"drill": dd["id"], "kind": dd["kind"], "model": dd["model"], "cross": dd["cross"]}
    field = read(d / "field.txt").strip()
    out["field"] = field
    ml = log_line(d / "mint.log", r"minted ")
    v.check(f"{pre}: the key Job minted {field} into the key Secret ({_fp(ml)}), on the host clock at {minted}",
            bool(ml) and field in ml and minted is not None, ml or "no mint line")
    acc = per_pod(jlines(d / "accept.log"), 200)
    pods = sorted(acc)
    firsts = {p: acc[p]["first"] for p in pods}
    late = [p for p in pods if firsts[p] is None]
    last = max((t for t in firsts.values() if t is not None), default=None)
    first_pod = min((t for t in firsts.values() if t is not None), default=None)
    rel = lambda t: None if t is None or minted is None else round(t - minted, 1)  # noqa: E731
    out["accepted"] = {p: rel(firsts[p]) for p in pods}
    v.check(f"{pre}: every API gateway pod accepted it, each on its own schedule: "
            + ", ".join(f"{p} {rel(firsts[p])} s" for p in pods) + " after the Secret's write; the last pod's acceptance "
            f"{rel(last)} s", bool(pods) and not late and last is not None and last - minted <= plan["timing"]["accept_max_s"],
            f"never accepted at {', '.join(late)}" if late else "no probe round")
    vip = jlines(d / "records-new.jsonl")
    ok200 = [r for r in vip if r.get("status") == 200 and (revoked is None or r.get("sent", 0) < revoked)]
    first_vip = min((r["sent"] for r in ok200), default=None)
    refused_before_all = [r for r in vip if r.get("status") == 401 and last is not None and first_vip is not None and first_vip <= r["sent"] < last]
    out.update({"first_vip": rel(first_vip), "last_pod": rel(last), "vip_401_between": len(refused_before_all)})
    # the per-pod probe's rounds bound when the first pod took the key from both sides: its last round
    # in which no pod accepted it, and its first round in which one did. The probe pod starts some
    # seconds after the write, so a 200 through the VIP may come before the probe's first round; it
    # may never come before a round that found no pod holding the key (2 s of slack: the probe and
    # the client stamp their own requests)
    rounds: dict = {}
    for r in (x for x in jlines(d / "accept.log") if "pod" in x and x.get("t") is not None):
        rounds.setdefault(r.get("round", r["t"]), []).append(r)
    none_t = [min(x["t"] for x in rs) for rs in rounds.values() if rs and all(x.get("status") != 200 for x in rs)]
    last_none = max((t_ for t_ in none_t if first_pod is None or t_ <= first_pod), default=None)
    v.check(f"{pre}: the first 200 through {dd.get('url', 'the VIP').split('/')[2]} came {rel(first_vip)} s after the write, once a pod held "
            f"the key (the first pod {rel(first_pod)} s), and {len(refused_before_all)} of the VIP's requests were refused 401 between it and the "
            "last pod's acceptance: a first 200 shows one pod holds a key, the last pod's acceptance that all do",
            first_vip is not None and first_pod is not None and minted is not None and first_vip >= minted
            and (last_none is None or first_vip >= last_none - 2.0),
            "no 200 through the VIP" if first_vip is None else
            f"first 200 {rel(first_vip)} s, before the probe's round at {rel(last_none)} s in which no pod held the key")
    cr = per_pod(jlines(d / "cross.log"), 401)
    cvip = curl_res(d / "cross-vip-result.txt")
    v.check(f"{pre}: the new {dd['model']} key on {dd['cross']}'s route: 401 at every API gateway pod ("
            + ", ".join(f"{p} {','.join(map(str, cr[p]['statuses']))}" for p in sorted(cr)) + f") and through the VIP (HTTP {cvip['status']})",
            bool(cr) and all(x["statuses"] == [401] for x in cr.values()) and cvip["status"] == 401, f"VIP HTTP {cvip['status']}")
    rl = log_line(d / "revoke.log", r"revoked ")
    v.check(f"{pre}: the key Job revoked {field} ({_fp(rl)}), on the host clock at {revoked}", bool(rl) and field in rl and revoked is not None,
            rl or "no revoke line")
    # the refusals count from when the revoke began (REVOKE): the key Job's end (REVOKED) can come
    # after the pods have already dropped the key
    rv0 = stamp(tl, "REVOKE") or revoked
    ref = per_pod(jlines(d / "refuse.log"), 401, since=rv0)
    rfirst = {p: ref[p]["first"] for p in sorted(ref)}
    rlate = [p for p, t in rfirst.items() if t is None]
    rlast = max((t for t in rfirst.values() if t is not None), default=None)
    relr = lambda t: None if t is None or rv0 is None else round(t - rv0, 1)  # noqa: E731
    out["refused"] = {p: relr(t) for p, t in rfirst.items()}
    v.check(f"{pre}: after the revoke every API gateway pod refused it: " + ", ".join(f"{p} {relr(t)} s" for p, t in rfirst.items())
            + f"; the last pod's refusal {relr(rlast)} s after the revoke", bool(ref) and not rlate and rlast is not None,
            f"still accepted at {', '.join(rlate)}" if rlate else "no probe round after the revoke")
    last200 = max((r["sent"] for r in vip if r.get("status") == 200), default=None)
    tail = [r for r in vip if revoked is not None and rlast is not None and r.get("sent", 0) > rlast]
    out["last_vip_200"] = relr(last200)
    v.check(f"{pre}: through the VIP the last 200 with it came {relr(last200)} s after the revoke, and every request after the last pod's "
            f"refusal was refused ({len(tail)} request{'s' if len(tail) != 1 else ''})", bool(tail) and all(r.get("status") == 401 for r in tail),
            f"{sum(1 for r in tail if r.get('status') != 401)} answered otherwise" if tail else "no request after the last refusal")
    out["probe"] = probe_counts(v, d, plan, pre)
    before, after = read(d / "secret-before.txt").strip(), read(d / "secret-after.txt").strip()
    v.check(f"{pre}: the key Secret holds the same fields and fingerprints after the drill as before ({len(before.splitlines())} fields)",
            bool(before) and before == after, "differs")
    return out


def analyze_code(v, plan: dict, dd: dict, d: Path, pass_: str) -> dict:
    tl = timeline(d)
    applied, restored = stamp(tl, "APPLIED"), stamp(tl, "RESTORED")
    pre = f"pass {pass_} {dd['id']}"
    exp = dd["expect"]
    out: dict = {"drill": dd["id"], "kind": dd["kind"], "model": dd["model"], "key_model": dd["key_model"]}
    df = per_pod(jlines(d / "default.log"), exp["default"], since=applied)
    msgs = sorted({x["message"] or "-" for x in df.values()})
    rel = lambda t, z: None if t is None or z is None else round(t - z, 1)  # noqa: E731
    late = [p for p, x in df.items() if x["first"] is None]
    out["default"] = {p: {"after_s": rel(x["first"], applied), "message": x["message"]} for p, x in df.items()}
    when = ", ".join(f"{p} {rel(x['first'], applied)} s" for p, x in sorted(df.items()))
    never = ", ".join(f"{p} {','.join(map(str, df[p]['statuses']))}" for p in late)
    v.check(f"{pre}: {dd['model']}'s route without rejected_code: a {dd['key_model']} key answered HTTP {exp['default']} at every API gateway pod "
            f"({when} after the change), the plugin's own message: {'; '.join(msgs)}", bool(df) and not late,
            f"never at {never}" if late else "no probe round")
    dv = curl_res(d / "default-vip-result.txt")
    v.check(f"{pre}: ... and through the VIP: HTTP {dv['status']}", dv["status"] == exp["default"], f"HTTP {dv['status']}")
    rd = per_pod(jlines(d / "rendered.log"), exp["rendered"], since=restored)
    rlate = [p for p, x in rd.items() if x["first"] is None]
    rmsgs = sorted({x["message"] or "-" for x in rd.values()})
    out["rendered"] = {p: {"after_s": rel(x["first"], restored), "message": x["message"]} for p, x in rd.items()}
    v.check(f"{pre}: the rendered routes back: HTTP {exp['rendered']} at every pod again, with the unknown key's message "
            f"({'; '.join(rmsgs)})", bool(rd) and not rlate and rmsgs == [exp["rendered_message"]],
            f"never at {', '.join(rlate)}" if rlate else f"message {rmsgs}")
    rv = curl_res(d / "rendered-vip-result.txt")
    ov = curl_res(d / "own-vip-result.txt")
    v.check(f"{pre}: ... through the VIP HTTP {rv['status']}, and {dd['model']}'s own key there HTTP {ov['status']}",
            rv["status"] == exp["rendered"] and ov["status"] == 200, f"cross {rv['status']}, own {ov['status']}")
    out["probe"] = probe_counts(v, d, plan, pre)
    v.check(f"{pre}: the routes ConfigMap is the render's again", read(d / "configmap-after.txt").strip() == "same",
            read(d / "configmap-after.txt").strip() or "not read")
    return out


def analyze_idle(v, plan: dict, dd: dict, d: Path, pass_: str) -> dict:
    pre = f"pass {pass_} {dd['id']}"
    out: dict = {"drill": dd["id"], "kind": dd["kind"], "silent_s": dd["silent_s"], "halves": {}}
    for half in ("rendered", "corrected"):
        h = d / half
        tl = timeline(h)
        sent, cont = stamp(tl, "SENT"), stamp(tl, "CONTINUED")
        res = curl_res(h / "result.txt")
        hd = headers(h / "headers.txt")
        idle = read(h / "idle.txt").strip() or "absent"
        srv = hd.get("server", "")
        body = read(h / "body.txt").strip()
        caps = [frames(read(p)) for p in sorted(h.glob("captures/echo-*.txt"))]
        frs = [f for c in caps for f in c]
        backend_port = dd["test_backend"]["port"]
        # the Gateway's proxy's connection is the one that carried the request (the kubelet's TCP
        # probes of the same port carry no data); only its segments are read
        req = sorted((f for f in frs if f["dport"] == backend_port and f["length"] > 0 and (sent is None or f["t"] >= sent - 1)),
                     key=lambda f: f["t"])
        conn = {(req[0]["src"], req[0]["sport"])} if req else set()
        early = [f for f in frs if f["sport"] == backend_port and (f["dst"], f["dport"]) in conn and f["length"] > 0 and cont is not None
                 and f["t"] < cont - 0.5]
        closes = sorted((f for f in frs if f["dport"] == backend_port and (f["src"], f["sport"]) in conn and ("F" in f["flags"] or "R" in f["flags"])),
                        key=lambda f: f["t"])
        close = closes[0] if closes else None
        rec = {"status": res["status"], "total_s": res["total"], "server": srv, "idle": idle, "backend_bytes_before_continue": len(early),
               "upstream_closed_s": None if not close or sent is None else round(close["t"] - sent, 1),
               "closed_by": None if not close else f"{close['src']}:{close['sport']}"}
        out["halves"][half] = rec
        if half == "rendered":
            want = _seconds(idle) or dd["default_idle_s"]
            v.check(f"{pre}, as rendered (the listener's stream idle timeout {idle}): the request silent for {dd['silent_s']} s ended "
                    f"HTTP {res['status']} after {res['total']} s, answered by {srv or 'none'}: the Gateway ended it, the backend having sent "
                    f"{len(early)} bytes' segments before it was continued",
                    res["status"] not in (0, 200) and "envoy" in srv.lower() and res["total"] is not None
                    and abs(res["total"] - want) <= max(10.0, 0.05 * want) and not early,
                    f"HTTP {res['status']} after {res['total']} s from {srv or 'none'}, want a cut near {want} s")
            v.check(f"{pre}, as rendered: the Gateway's proxy closed its connection to the test backend {rec['upstream_closed_s']} s after the "
                    f"request was sent ({rec['closed_by'] or 'no close seen'})", close is not None and rec["upstream_closed_s"] is not None
                    and rec["upstream_closed_s"] <= dd["silent_s"], "no FIN or RST toward the backend before it was continued")
        else:
            c = dd["corrected"]
            v.check(f"{pre}, corrected (the listener's stream idle timeout {idle}, the route's request {c['request_s']} s and backendRequest "
                    f"{c['backend_request_s']} s): the same silence answered HTTP {res['status']} after {res['total']} s",
                    res["status"] == 200 and res["total"] is not None and res["total"] >= dd["silent_s"] - 2 and "sfab-drill-idle" in body
                    and _seconds(idle) == c["stream_idle_s"], f"HTTP {res['status']} after {res['total']} s, idle {idle}")
    out["helm"] = helm_times(timeline(d))
    out["leases"] = lease_reads(d, dd)
    back = read(d / "restored.txt").strip()
    v.check(f"{pre}: the rendered chain back: {back}", back.startswith("idle ") and "route timeouts none" in back and "helm values rendered" in back,
            back or "not read")
    return out


def helm_times(tl: list) -> dict:
    """{values: {"upgrade_s": helm's upgrade, "<rollout>_s": each rollout}} from the timeline's stamps."""
    out: dict = {}
    start = {}
    for t, e, rest in tl:
        if e in ("HELM", "ROLL"):
            start[(e, rest)] = t
        elif e == "HELMED" and ("HELM", rest) in start:
            out.setdefault(rest, {})["upgrade_s"] = round(t - start[("HELM", rest)], 1)
        elif e == "ROLLED" and ("ROLL", rest) in start:
            which, _, what = rest.partition(" ")
            out.setdefault(which, {})[f"{what.split('/')[-1]}_s"] = round(t - start[("ROLL", rest)], 1)
    return out


def lease_reads(d: Path, dd: dict) -> dict:
    """{read: {gateway: "holder, N transitions"}} for each leases-<read>.json the drill saved."""
    names = {g: f"cilium-l2announce-{dd['cec'].split('/')[0]}-cilium-gateway-{g}" for g in sorted(dd.get("gateways") or {})}
    out: dict = {}
    for p in sorted(d.glob("leases-*.json")):
        try:
            items = load(p).get("items") or []
        except (OSError, ValueError):
            continue
        by = {i["metadata"]["name"]: i.get("spec") or {} for i in items}
        out[p.stem[len("leases-"):]] = {g: f"{(by.get(n) or {}).get('holderIdentity')}, {(by.get(n) or {}).get('leaseTransitions', 0)} transitions"
                                       for g, n in names.items()}
    return out


def _seconds(v):
    m = re.match(r"^(\d+(?:\.\d+)?)s$", str(v or "").split(",")[0])
    return float(m.group(1)) if m else None


def cmd_analyze(a) -> int:
    plan = load(a.plan)
    dd = drill(plan, a.drill)
    d = Path(a.dir)
    v = vocab.Vocab()
    fn = {"key-lifecycle": analyze_keys, "rejected-code": analyze_code, "idle-timeout": analyze_idle}[dd["kind"]]
    out = fn(v, plan, dd, d, a.pass_)
    (d / "analysis.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [f"{dd['id']}, pass {a.pass_}: {dd['title']}"] + [f"  {k}: {json.dumps(x, sort_keys=True)}" for k, x in sorted(out.items())
                                                            if k not in ("drill", "kind")]
    (d / "analysis.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 1 if v.counts()["fail"] else 0


def cmd_summarize(a) -> int:
    rs = Path(a.set)
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    try:
        plan = load(rs / "drills.json")
    except (OSError, ValueError):
        plan = {"list": []}
    repo = run.get("labs_repo") or {}
    unc = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    L = ["# Gateway drills", "", f"- Lab: `{run.get('lab', '?')}`; labs repo commit `{repo.get('commit') or 'none'}`{unc}; UTC "
         f"{run.get('utc_start') or 'unknown'}"]
    if a.stamp:
        L.append(f"- {a.stamp}")
    for dd in plan.get("list") or []:
        passes = sorted(rs.glob(f"pass*/{dd['id']}/analysis.json"))
        L += ["", f"## {dd['id']}: {dd['title']}", ""]
        if not passes:
            L.append("Not run.")
            continue
        for p in passes:
            try:
                an = load(p)
            except (OSError, ValueError):
                continue
            L.append(f"### {p.parent.parent.name}")
            L.append("")
            for k, x in sorted(an.items()):
                if k in ("drill", "kind"):
                    continue
                L.append(f"- {k}: `{json.dumps(x, sort_keys=True)}`")
            L.append("")
    verdict = read(rs / "verdict.txt")
    L += ["## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", "",
                                                                                     vocab.result_line(vocab.counts_of(str(rs / "verdict.txt"))), ""]
    (rs / "DRILLS.md").write_text("\n".join(L), encoding="utf-8")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="gwdrill")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("kid")
    s.add_argument("--plan", required=True)
    s.add_argument("--drill", required=True)
    s.add_argument("--pass", dest="pass_", required=True)
    s = sub.add_parser("whole")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s = sub.add_parser("idle")
    s.add_argument("--cec", required=True)
    s.add_argument("--name", required=True)
    s = sub.add_parser("analyze")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--drill", required=True)
    s.add_argument("--pass", dest="pass_", required=True)
    s = sub.add_parser("summarize")
    s.add_argument("--set", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"get": cmd_get, "kid": cmd_kid, "whole": cmd_whole, "idle": cmd_idle, "analyze": cmd_analyze,
            "summarize": cmd_summarize}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
