#!/usr/bin/env python3
"""servedrill.py: chapter 6's serving drills, their plan, the serving layer's whole check and the
analysis (common/drill/lib-servedrill.sh).

    servedrill.py get       --plan gen/drills.json PATH        a value of the plan
    servedrill.py epline    --t0 T --t1 T < ENDPOINTSLICES      one read of the EndpointSlices as one JSON
                                                               line: when it began and ended, and each
                                                               Service's ready addresses
    servedrill.py whole     --plan gen/drills.json --dir DIR    one poll of the serving layer whole, from
                                                               its saved files
    servedrill.py returned  --plan gen/drills.json --log FILE --pods FILE --since T
                                                               the time of the first read at or after T
                                                               in which every Service holds all its servers
    servedrill.py moved-env --plan gen/drills.json --drill ID --env serving.env
                                                               the table with the drill's row moved
    servedrill.py analyze   --plan gen/drills.json --dir DIR --drill ID --pass N
    servedrill.py summarize --set DIR [--stamp TEXT]            DRILLS.md

Every time is the lab host's clock: the moments lib-servedrill.sh stamped (timeline.txt: the
fault's KLISH session started and returned, the restore's session started and returned, every
Service whole again), the EndpointSlices read with the harness's kubectl every interval (each read stamped
when it began and when it ended), and the gateway probe's requests, stamped in the client container,
whose clock is the host's.

For each Service the analysis finds, from the reads, when a server the fault takes out left its
ready endpoints (the first read after the fault's session began that no longer lists it, bracketed
by the read before it) and when it came back after the restore, and checks that no server the fault
leaves alone ever left. Those times are events against the readiness bound the plan states (the
probe's period times its failures, each probe up to its timeout, then the removal's propagation),
never a carrier figure: a KLISH shutdown drops no carrier at the node. For each model it counts the
gateway probe's requests by when they were sent and how they ended, and the answers the router had
to try again for. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import evfile  # noqa: E402
import judge as J  # noqa: E402
import vocab  # noqa: E402

PHASES = ("before", "at the cut", "down", "at the restore", "returning", "after")


def load(p):
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def cmd_get(a) -> int:
    cur = load(a.plan)
    for part in a.path.split("."):
        if isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
        elif isinstance(cur, list):
            cur = next((x for x in cur if isinstance(x, dict) and (x.get("id") == part or x.get("name") == part)), None)
        elif isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = None
        if cur is None:
            return 1
    if isinstance(cur, list):
        print("\n".join(json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x) for x in cur))
    elif isinstance(cur, dict):
        print(json.dumps(cur, sort_keys=True))
    elif isinstance(cur, bool):
        print("1" if cur else "0")
    else:
        print(cur)
    return 0


# --------------------------------------------------------------------------------------------
# endpoints


def ready_by_service(doc: dict) -> dict:
    """Service -> sorted ready addresses, from kubectl get endpointslices -o json."""
    out: dict = {}
    for sl in (doc or {}).get("items") or []:
        svc = ((sl.get("metadata") or {}).get("labels") or {}).get("kubernetes.io/service-name")
        if not svc:
            continue
        have = out.setdefault(svc, set())
        for e in sl.get("endpoints") or []:
            if (e.get("conditions") or {}).get("ready"):
                have.update(e.get("addresses") or [])
    return {k: sorted(v) for k, v in sorted(out.items())}


def cmd_epline(a) -> int:
    try:
        doc = json.load(sys.stdin)
    except ValueError:
        doc = None
    rec = {"t": round(float(a.t0), 6), "t_done": round(float(a.t1), 6)}
    if doc is None:
        rec["error"] = "unreadable"
    else:
        rec["services"] = ready_by_service(doc)
    print(json.dumps(rec, sort_keys=True))
    return 0


def pod_ips(path) -> dict:
    try:
        doc = load(path)
    except (OSError, ValueError):
        return {}
    return {i["metadata"]["name"]: (i.get("status") or {}).get("podIP") for i in doc.get("items") or []}


def ep_reads(path) -> list:
    out = []
    for line in read(path).splitlines():
        try:
            x = json.loads(line)
        except ValueError:
            continue
        if "services" in x:
            out.append(x)
    return out


def whole_services(plan: dict, ips: dict, services: dict) -> list:
    """Problems: each Service's ready endpoints against its servers' addresses."""
    probs = []
    for s in plan["serving"]["services"]:
        want = sorted(ips.get(p) or f"{p}?" for p in s["servers"])
        have = services.get(s["name"]) or []
        if have != want:
            probs.append(f"Service {s['name']}: {' '.join(have) or 'none'} (servers {' '.join(want)})")
    return probs


def cmd_whole(a) -> int:
    plan = load(a.plan)
    d = Path(a.dir)
    probs = []
    try:
        pods = load(d / "pods.json")
    except (OSError, ValueError):
        pods = {}
    items = {i["metadata"]["name"]: i for i in pods.get("items") or []}
    rows = [p for c in plan["serving"]["copies"] for p in [c["server"]] + c["workers"]]
    for p in rows:
        i = items.get(p["pod"])
        if i is None:
            probs.append(f"{p['pod']}: no such pod")
        elif not J.pod_ready(i):
            probs.append(f"{p['pod']}: not Ready")
    ips = {n: (i.get("status") or {}).get("podIP") for n, i in items.items()}
    try:
        eps = ready_by_service(load(d / "endpointslices.json"))
    except (OSError, ValueError):
        eps = {}
        probs.append("the EndpointSlices were not read")
    probs += whole_services(plan, ips, eps)
    for sw, x in sorted((plan.get("rail_switches") or {}).items()):
        st = read(d / f"{sw}-status.txt")
        rows_ = J.p_interface_status(st) if st else {}
        down = [n for n in x["natives"] if (rows_.get(n) or {}).get("oper") != "up"]
        if not rows_:
            probs.append(f"{sw}: show interface status not read")
        elif down:
            probs.append(f"{sw}: {','.join(down)} not up")
    print("; ".join(probs) if probs else "whole: every pod of the table Ready, every Service holding its servers, every rail port up")
    return 1 if probs else 0


def cmd_returned(a) -> int:
    plan = load(a.plan)
    ips = pod_ips(a.pods)
    for x in ep_reads(a.log):
        if x["t"] >= float(a.since) and not whole_services(plan, ips, x["services"]):
            print(f"{x['t']:.6f}")
            return 0
    return 1


def cmd_moved_env(a) -> int:
    plan = load(a.plan)
    d = next((x for x in plan["list"] if x["id"] == a.drill), None)
    if d is None or d.get("kind") != "rail-move":
        print(f"servedrill: no rail-move drill {a.drill}", file=sys.stderr)
        return 2
    row, mv = d["row"], d["moved"]
    text = Path(a.env).read_text(encoding="utf-8")
    cols = next((line.partition("=")[2].strip("'\"").split() for line in text.splitlines() if line.startswith("SERVING_POD_COLUMNS=")),
                ["pod", "model", "copy", "role", "index", "node", "rail", "nad", "address", "decision"])
    old = " ".join(str(row.get(c, "-")) for c in cols)
    new = " ".join(str(mv.get(c, "-")) for c in cols)
    out, hit = [], 0
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.startswith("SERVING_POD_") and v.strip("'\"") == old:
            line = f"{k}='{new}'"
            hit += 1
        out.append(line)
    if hit != 1:
        print(f"servedrill: {row['pod']}'s row was not found once in {a.env}", file=sys.stderr)
        return 1
    print("\n".join(out))
    return 0


# --------------------------------------------------------------------------------------------
# the analysis


def timeline(d: Path) -> dict:
    out: dict = {}
    for line in read(d / "timeline.txt").splitlines():
        parts = line.split(" ", 2)
        if len(parts) >= 2:
            try:
                out.setdefault(parts[1], float(parts[0]))
            except ValueError:
                continue
    return out


def phase(t: float, tl: dict) -> str:
    edges = [("INJECT", "at the cut"), ("INJECTED", "down"), ("RESTORE", "at the restore"), ("RESTORED", "returning"), ("RETURNED", "after")]
    cur = "before"
    for ev, ph in edges:
        if ev in tl and t >= tl[ev]:
            cur = ph
    return cur


def records(d: Path, model: str) -> list:
    out = []
    for line in read(d / f"records-{model}.jsonl").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return sorted(out, key=lambda r: r.get("sent") or 0)


def service_events(plan: dict, drill: dict, reads: list, ips: dict, tl: dict) -> list:
    out = []
    t_cut, t_restore = tl.get("INJECT"), tl.get("RESTORE")
    t_end = tl.get("RETURNED") or tl.get("STOP") or (reads[-1]["t"] if reads else None)
    for name, sx in drill["expect"]["services"].items():
        servers = sx["servers"]
        dead = [p for p in servers if p not in sx["while_down"]]
        rec = {"service": name, "kind": sx["kind"], "servers": servers, "dead": dead, "reads": len(reads), "left": {}, "back": {},
               "lost_live": [], "whole_before": None}
        before = [x for x in reads if t_cut is not None and x["t"] < t_cut]
        if before:
            rec["whole_before"] = sorted(before[-1]["services"].get(name) or []) == sorted(ips.get(p) or "" for p in servers)
        for p in servers:
            ip = ips.get(p)
            if p in dead:
                prev = None
                for x in reads:
                    if t_cut is not None and x["t"] >= t_cut and ip not in (x["services"].get(name) or []):
                        rec["left"][p] = {"t": x["t"], "after_cut_s": round(x["t"] - t_cut, 3),
                                          "prev_after_cut_s": round(prev["t"] - t_cut, 3) if prev else None}
                        break
                    if t_cut is not None and x["t"] >= t_cut:
                        prev = x
                prev = None
                for x in reads:
                    if t_restore is not None and x["t"] >= t_restore and ip in (x["services"].get(name) or []):
                        rec["back"][p] = {"t": x["t"], "after_restore_s": round(x["t"] - t_restore, 3),
                                          "prev_after_restore_s": round(prev["t"] - t_restore, 3) if prev else None}
                        break
                    if t_restore is not None and x["t"] >= t_restore:
                        prev = x
            else:
                gone = [x["t"] for x in reads if t_cut is not None and t_cut <= x["t"] <= (t_end or x["t"])
                        and ip not in (x["services"].get(name) or [])]
                if gone:
                    rec["lost_live"].append({"pod": p, "reads": len(gone), "first_after_cut_s": round(gone[0] - t_cut, 3)})
        out.append(rec)
    return out


def model_summary(d: Path, model: str, tl: dict) -> dict:
    rs = records(d, model)
    by: dict = {ph: {"sent": 0, "answered": 0, "failed": 0} for ph in PHASES}
    fails, retried = [], []
    for r in rs:
        ph = phase(r.get("sent") or 0, tl)
        by[ph]["sent"] += 1
        by[ph][r.get("outcome") if r.get("outcome") in ("answered", "failed") else "failed"] += 1
        if r.get("outcome") != "answered":
            fails.append({"n": r.get("n"), "phase": ph, "why": r.get("why"), "status": r.get("status")})
        if (r.get("retries") or 0) > 0:
            retried.append({"n": r.get("n"), "phase": ph, "retries": r.get("retries"),
                            "took_s": round((r.get("done") or 0) - (r.get("sent") or 0), 3)})
    slow = max(rs, key=lambda r: (r.get("done") or 0) - (r.get("sent") or 0)) if rs else None
    return {"model": model, "sent": len(rs), "answered": sum(1 for r in rs if r.get("outcome") == "answered"),
            "failed": len(fails), "by_phase": by, "fails": fails[:20], "retried": retried,
            "slowest": {"n": slow.get("n"), "phase": phase(slow.get("sent") or 0, tl), "took_s": round((slow.get("done") or 0) - (slow.get("sent") or 0), 3),
                        "retries": slow.get("retries")} if slow else None}


def _range(a, b) -> str:
    """When an event fell between two reads: 'b to a s' (the read before it, the read that showed
    it), 'by a s' with no read before it, 'never' with none that showed it."""
    if a is None:
        return "never"
    if b is None:
        return f"by {a:.1f} s"
    return f"{b:.1f} to {a:.1f} s"


def _span(a, b, what: str) -> str:
    r = _range(a, b)
    return r if r == "never" else f"{r} after {what}"


def cmd_analyze(a) -> int:
    plan = load(a.plan)
    d = Path(a.dir)
    drill = next(x for x in plan["list"] if x["id"] == a.drill)
    tl = timeline(d)
    ips = pod_ips(d / "pods-before.json")
    reads = ep_reads(d / "endpoints.jsonl")
    v = vocab.Vocab(known=vocab.known_ids_default() or None)
    tag = f"pass {a.pass_} {a.drill}"
    rd = plan["serving"]["readiness"]
    bound = f"the readiness bound: a probe every {rd['period_s']} s, out after {rd['failure_threshold']} failures, each up to {rd['timeout_s']} s"
    events = service_events(plan, drill, reads, ips, tl)
    gw = plan["probes"]["gateway"]
    models = [model_summary(d, m["model"], tl) for m in gw["models"]]
    fault = f"{drill['switch']} dark" if drill["kind"] == "serve-dark" else f"{drill['switch']} {drill['natives'][0]} shut"
    for e in events:
        if e["whole_before"] is False:
            v.bad(f"{tag}: Service {e['service']} held all its servers before the fault", "it did not in the last read before the cut")
        if e["dead"]:
            for p in e["dead"]:
                lf, bk = e["left"].get(p), e["back"].get(p)
                v.check(f"{tag}: Service {e['service']}: {p} left it {_span(lf and lf['after_cut_s'], lf and lf['prev_after_cut_s'], 'the shut session began')}"
                        f" ({bound}, then the removal's propagation)", lf is not None and (tl.get("RESTORE") is None or lf["t"] < tl["RESTORE"]),
                        "it never left while the fault held")
                v.check(f"{tag}: ... and came back {_span(bk and bk['after_restore_s'], bk and bk['prev_after_restore_s'], 'the restore session began')}",
                        bk is not None, f"not back within the {len(reads)} reads")
        live = [p for p in e["servers"] if p not in e["dead"]]
        if live:
            v.check(f"{tag}: Service {e['service']}: {', '.join(live)} stayed in it throughout ({e['reads']} reads, one every "
                    f"{plan['probes']['endpoints']['interval_s']} s)", not e["lost_live"],
                    "; ".join(f"{x['pod']} missing from {x['reads']} reads, first {x['first_after_cut_s']} s after the cut" for x in e["lost_live"]))
    stayed = (drill.get("expect") or {}).get("in_node") or []
    if stayed:
        v.known("L9", f"{tag}: {', '.join(stayed)} on {drill['switch']}'s rails stayed in their Services: each copy's RPC runs inside its "
                      "node through the rail NIC's macvlan bridge, and a KLISH shutdown drops no carrier at the rail NICs (on hardware "
                      "the NICs would lose carrier and these copies would leave too; each model's copies on the other rail switch's "
                      "rails would answer)")
    for m in models:
        down = m["by_phase"]["down"]
        v.check(f"{tag}: {m['model']} through {gw['gateway']}: {m['failed']} of {m['sent']} requests failed ({m['answered']} answered; "
                f"{down['answered']} of {down['sent']} sent while {fault} answered)", m["sent"] > 0 and m["failed"] == 0,
                "; ".join(f"#{f['n']} {f['phase']} {f['why']}" for f in m["fails"][:4]) or "no request sent")
        if m["retried"]:
            sl = m["slowest"]
            v.ok(f"{tag}: ... the router tried {len(m['retried'])} of them again ("
                 + ", ".join(f"#{x['n']} {x['phase']}, {x['retries']} retr{'y' if x['retries'] == 1 else 'ies'}, {x['took_s']} s" for x in m["retried"][:4])
                 + (f"; the slowest answer took {sl['took_s']} s" if sl else "") + ")")
        else:
            v.ok(f"{tag}: ... none needed a router retry" + (f" (the slowest answer took {m['slowest']['took_s']} s)" if m["slowest"] else ""))
    out = {"drill": a.drill, "pass": a.pass_, "kind": drill["kind"], "switch": drill.get("switch"), "natives": drill.get("natives"),
           "timeline": tl, "services": events, "models": models, "readiness": rd,
           "dead_copies": drill["expect"]["dead_copies"], "live_copies": drill["expect"]["live_copies"], "in_node": stayed}
    if tl.get("INJECT") and tl.get("INJECTED"):
        out["shut_session_s"] = round(tl["INJECTED"] - tl["INJECT"], 3)
    if tl.get("RESTORE") and tl.get("RESTORED"):
        out["restore_session_s"] = round(tl["RESTORED"] - tl["RESTORE"], 3)
    if tl.get("RESTORE") and tl.get("RETURNED"):
        out["whole_after_restore_s"] = round(tl["RETURNED"] - tl["RESTORE"], 3)
    (d / "analysis.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (d / "analysis.txt").write_text(text(out), encoding="utf-8")
    return 1 if v.counts()["fail"] else 0


def text(a: dict) -> str:
    L = [f"{a['drill']}, pass {a['pass']}: {a['kind']} on {a.get('switch')} ({', '.join(a.get('natives') or [])}); "
         f"shut session {a.get('shut_session_s', '?')} s, restore session {a.get('restore_session_s', '?')} s, every Service whole "
         f"{a.get('whole_after_restore_s', '?')} s after the restore's session began",
         f"copies out: {', '.join(a['dead_copies'])}; copies left: {', '.join(a['live_copies'])}"
         + (f" (on the dark rails but inside one node: {', '.join(a['in_node'])})" if a.get("in_node") else "")]
    for e in a["services"]:
        parts = []
        for p in e["dead"]:
            lf, bk = e["left"].get(p), e["back"].get(p)
            parts.append(f"{p} left {_span(lf and lf['after_cut_s'], lf and lf['prev_after_cut_s'], 'the cut')}, back "
                         f"{_span(bk and bk['after_restore_s'], bk and bk['prev_after_restore_s'], 'the restore')}")
        live = [p for p in e["servers"] if p not in e["dead"]]
        if live:
            parts.append(f"{', '.join(live)} stayed" + ("" if not e["lost_live"] else " (NOT: " + ", ".join(x["pod"] for x in e["lost_live"]) + ")"))
        L.append(f"  Service {e['service']}: " + "; ".join(parts))
    for m in a["models"]:
        ph = ", ".join(f"{k} {v['answered']}/{v['sent']}" for k, v in m["by_phase"].items() if v["sent"])
        L.append(f"  {m['model']}: {m['answered']} of {m['sent']} answered, {m['failed']} failed ({ph}); router retries: {len(m['retried'])}")
    L.append("  (times in seconds on the lab host's clock; a Service's change is bracketed by the read before it)")
    return "\n".join(L) + "\n"


def cmd_summarize(a) -> int:
    rs = Path(a.set)
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    passes = sorted((int(p.name[4:]) for p in rs.glob("pass*") if p.name[4:].isdigit()))
    L = ["# Serving drills", "",
         f"- Lab: `{run.get('lab')}`; labs repo commit `{commit}`{uncommitted}; UTC {run.get('utc_start') or 'unknown'}",
         f"- Every time is the lab host's clock; passes: {len(passes)}"]
    if a.stamp:
        L.append(f"- {a.stamp}")
    drills: dict = {}
    for p in passes:
        for d in sorted((rs / f"pass{p}").iterdir()):
            if d.is_dir():
                drills.setdefault(d.name, []).append((p, d))
    for did, runs in drills.items():
        first = None
        for _, d in runs:
            try:
                first = load(d / "analysis.json")
                break
            except (OSError, ValueError):
                continue
        if first is None:
            mv = read(runs[0][1] / "result.txt")
            L += ["", f"## {did}", "", "```"] + mv.strip("\n").splitlines() + ["```"]
            continue
        L += ["", f"## {did}: {first['kind']} on {first.get('switch')}, copies out {', '.join(first['dead_copies'])}", "",
              "| Pass | Shut session | Restore session | Whole after restore | Service | Server left (after the cut) | Back (after the restore) |",
              "|---|---|---|---|---|---|---|"]
        agree = set()
        for p, d in runs:
            try:
                x = load(d / "analysis.json")
            except (OSError, ValueError):
                continue
            agree.add(tuple(sorted((e["service"], tuple(sorted(e["left"]))) for e in x["services"])))
            for e in x["services"]:
                for srv in e["dead"]:
                    lf, bk = e["left"].get(srv), e["back"].get(srv)
                    L.append(f"| {p} | {x.get('shut_session_s', '?')} s | {x.get('restore_session_s', '?')} s | {x.get('whole_after_restore_s', '?')} s "
                             f"| {e['service']} ({srv}) | {_range(lf and lf['after_cut_s'], lf and lf['prev_after_cut_s'])} "
                             f"| {_range(bk and bk['after_restore_s'], bk and bk['prev_after_restore_s'])} |")
        L += ["", "| Pass | Model | Sent | Answered | Failed | Sent while down, answered | Router retries | Slowest answer |", "|---|---|---|---|---|---|---|---|"]
        for p, d in runs:
            try:
                x = load(d / "analysis.json")
            except (OSError, ValueError):
                continue
            for m in x["models"]:
                dn = m["by_phase"]["down"]
                sl = m.get("slowest") or {}
                L.append(f"| {p} | {m['model']} | {m['sent']} | {m['answered']} | {m['failed']} | {dn['answered']} of {dn['sent']} | "
                         f"{len(m['retried'])} | {sl.get('took_s', '-')} s |")
        L += ["", "Every pass agrees on which servers left which Services." if len(agree) == 1 else
              "The passes disagree on which servers left which Services: see each pass's analysis.txt."]
    L += ["", "## Files", "",
          "- `pass<N>/<drill>/`: `timeline.txt` (the host-clock moments), `endpoints.jsonl` (each read of the EndpointSlices), "
          "`records-<model>.jsonl` (each request of the gateway probe), `klish/` (the switch before, during and after), the pods "
          "and events read, `analysis.json` and `analysis.txt`",
          "- `pass<N>/rail-move/`: the moved table, the recipe's refusal of it, and the audits against it and against the table as rendered",
          ""]
    (rs / "DRILLS.md").write_text("\n".join(L), encoding="utf-8")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="servedrill")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("epline")
    s.add_argument("--t0", required=True)
    s.add_argument("--t1", required=True)
    s = sub.add_parser("whole")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s = sub.add_parser("returned")
    s.add_argument("--plan", required=True)
    s.add_argument("--log", required=True)
    s.add_argument("--pods", required=True)
    s.add_argument("--since", required=True)
    s = sub.add_parser("moved-env")
    s.add_argument("--plan", required=True)
    s.add_argument("--drill", required=True)
    s.add_argument("--env", required=True)
    s = sub.add_parser("analyze")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--drill", required=True)
    s.add_argument("--pass", dest="pass_", type=int, required=True)
    s = sub.add_parser("summarize")
    s.add_argument("--set", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"get": cmd_get, "epline": cmd_epline, "whole": cmd_whole, "returned": cmd_returned, "moved-env": cmd_moved_env,
            "analyze": cmd_analyze, "summarize": cmd_summarize}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
