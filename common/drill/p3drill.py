#!/usr/bin/env python3
"""p3drill.py: Part III's drills, the plan read and the evidence judged (common/drill/lib-p3drill.sh).

    p3drill.py get --plan gen/drills.json PATH         a value of the plan (list.<id> names a drill)
    p3drill.py whole --plan P --tenancy T --dir D [--explain]
                                                       yes when both ingress nodes' bonds are up on
                                                       both legs and every Gateway's lease is on an
                                                       ingress node (the reads in D)
    p3drill.py holder --plan P --drill ID --leases FILE
                                                       the ingress node holding the most leases
    p3drill.py iso-plan --plan P --drill ID --row N    the isolation drill's plan for one client
    p3drill.py analyze-lease --plan P --dir D --drill ID --pass N
    p3drill.py analyze-isolation --plan P --dir D --drill ID --pass N
    p3drill.py analyze-leak --plan P --dir D --drill ID --pass N
    p3drill.py summarize --set DIR [--stamp TEXT]      DRILLS.md

analyze-lease (chapter 8) reads the drill's timeline, the leases read every 0.5 s, the probes' logs,
the firewall's ARP tables and the EndpointSlices, and prints:

  the move      each lease the cut node held taken by the other ingress node, and when (the first
                read after the cut naming it, against the moment both pair ports were shut and
                against the cut's start, all on the lab host)
  the gap       for each echo probe and connect loop through a Gateway the cut node held: the
                requests lost, and the gap from the last request answered before both ports were
                shut (the timeline's SHUT) to the first sent after it that was answered, by the
                requests' sent times, so a gap is a multiple of the probe's interval; the slowest
                answer and connect sent while the node was cut, a stall the counts do not show;
                recovered before the ports came back, so the lease moved, not the
                restore; the prediction (2 to 4 s at the tuned timers, plus the firewall acting on
                the new holder's gratuitous ARP) said beside the measured gap, which it never fails
  the ARP       the firewall's entry for each moved VIP naming the new holder's bond MAC while the
                cut node is still cut
  apart         the model probe's answered and failed requests over the drill, reported beside the
                gap, never folded into it (the API gateway, the router and the identity provider
                run on the ingress nodes too); and when the cut node's endpoints left each Service
                (the EndpointSlices), as recorded

analyze-isolation (chapter 11) prints, for each load factor, the held connections judged as chapter
10's measurement judges them (common/audit/tenancy.py judge_hold) and one line a population: its own
Gateway's answers, its allowed cells' and the forbidden cells' attempts that got through, which must
be zero.

analyze-leak (chapter 11) judges the one cell no network layer holds: the new key of another
audience's caller minted, answered 200 from the internet client through its own Gateway and named
under that caller in the API gateway's access log, then refused after its revoke, and the key Secret
the same after the drill as before. Every time is the lab host's clock. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import tenancy as T  # noqa: E402
import vocab  # noqa: E402

MAC = re.compile(r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})", re.I)


def load(p):
    return json.loads(Path(p).read_text(encoding="utf-8"))


def read(p) -> str:
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def drill(plan: dict, did: str) -> dict:
    return next(d for d in plan["list"] if d["id"] == did)


def cmd_get(a) -> int:
    cur = load(a.plan)
    parts = a.path.split(".")
    if parts[0] == "list" and len(parts) > 1:
        cur = drill(cur, parts[1])
        parts = parts[2:]
    for part in parts:
        if isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
        else:
            cur = cur.get(part) if isinstance(cur, dict) else None
    if isinstance(cur, list):
        for x in cur:
            print(json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else x)
    elif isinstance(cur, dict):
        print(json.dumps(cur, sort_keys=True))
    elif cur is not None:
        print(cur)
    return 0


def lease_holders(doc) -> dict:
    return {i["metadata"]["name"]: (i.get("spec") or {}).get("holderIdentity") for i in (doc or {}).get("items") or []}


def bond_legs(text: str) -> int:
    """How many of a bond's slaves report MII Status up (/proc/net/bonding/bond0)."""
    n, in_slave = 0, False
    for line in (text or "").splitlines():
        if line.startswith("Slave Interface:"):
            in_slave = True
            continue
        if in_slave and line.strip().startswith("MII Status:"):
            n += line.strip().endswith("up")
            in_slave = False
    return n


def cmd_whole(a) -> int:
    d = Path(a.dir)
    tp = load(a.tenancy) if Path(a.tenancy).is_file() else {}
    au = tp.get("audiences") or {}
    ingress = au.get("ingress_nodes") or []
    legs = {n: bond_legs(read(d / f"bond-{n}.txt")) for n in ingress}
    try:
        h = lease_holders(json.loads(read(d / "leases.json")))
    except ValueError:
        h = {}
    leases = {g: h.get((x.get("lease") or "").split("/", 1)[-1]) for g, x in (au.get("gateways") or {}).items()}
    good = bool(ingress) and all(v == 2 for v in legs.values()) and all(x in ingress for x in leases.values())
    if a.explain:
        print("; ".join(f"{n} on {v} leg(s)" for n, v in legs.items()) + "; leases " + ", ".join(f"{g} {x}" for g, x in sorted(leases.items())))
    else:
        print("yes" if good else "no")
    return 0


def cmd_holder(a) -> int:
    dr = drill(load(a.plan), a.drill)
    try:
        h = lease_holders(load(a.leases))
    except (OSError, ValueError):
        h = {}
    count = {}
    for g, ln in dr["leases"].items():
        x = h.get(ln.split("/", 1)[-1])
        if x in dr["ingress"]:
            count[x] = count.get(x, 0) + 1
    if count:
        print(sorted(count.items(), key=lambda kv: (-kv[1], kv[0]))[0][0])
    return 0


def cmd_iso_plan(a) -> int:
    dr = drill(load(a.plan), a.drill)
    r = dr["rows"][int(a.row)]
    print(json.dumps({"own": r["own"], "tries": r["tries"], "rounds": dr["rounds"], "interval_s": dr["interval_s"],
                      "timeout_s": dr["timeout_s"], "ca_root": dr["hold"].get("ca_root")}, sort_keys=True))
    return 0


# --------------------------------------------------------------------------------------------
# the lease drill


def timeline(d: Path) -> dict:
    out = {}
    for line in read(d / "timeline.txt").splitlines():
        x = line.split(" ", 2)
        if len(x) >= 2:
            try:
                out.setdefault(x[1], (float(x[0]), x[2] if len(x) > 2 else ""))
            except ValueError:
                pass
    return out


def jsonl(p) -> list:
    out = []
    for line in read(p).splitlines():
        if line.strip().startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def gap(records: list, tc: float, ok_key, t_key) -> dict:
    """The outage around tc: the last answered attempt before it, the first after, and how many
    failed between."""
    rs = sorted(records, key=lambda r: r[t_key])
    before = [r[t_key] for r in rs if r[t_key] < tc and ok_key(r)]
    after = [r[t_key] for r in rs if r[t_key] >= tc and ok_key(r)]
    last_ok = before[-1] if before else None
    first_ok = after[0] if after else None
    lost = [r for r in rs if not ok_key(r) and (last_ok is None or r[t_key] > last_ok) and (first_ok is None or r[t_key] < first_ok)]
    return {"last_ok": last_ok, "first_ok": first_ok, "lost": len(lost), "sent": len(rs),
            "gap_s": round(first_ok - last_ok, 3) if last_ok is not None and first_ok is not None else None}


def tcp_records(text: str) -> list:
    out = []
    for line in (text or "").splitlines():
        x = line.split()
        if len(x) >= 5:
            try:
                out.append({"t": float(x[0]), "ok": x[2] == "1", "ms": float(x[4])})
            except ValueError:
                pass
    return out


def arp_mac(text: str, ip: str):
    for line in (text or "").splitlines():
        if re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", line):
            m = MAC.search(line)
            if m:
                return m.group(1).lower()
    return None


def analyze_lease(v, dr: dict, d: Path, pas: str) -> dict:
    tl = timeline(d)
    lab = f"pass {pas} {dr['id']}"
    cut = read(d / "cut-node.txt").strip()
    out = {"cut": cut, "gateways": {}, "probes": {}, "connects": {}}
    if "CUT" not in tl or not cut:
        v.bad(f"{lab}: the cut", "the drill never cut a node (see timeline.txt)")
        return out
    tc = tl["CUT"][0]
    # the node is cut once both of its pair ports are shut: the KLISH sessions run one switch after
    # the other between CUT and SHUT, and the bond keeps a leg until the second. The probes' gaps and
    # the leases' moves are timed from SHUT, the first moment the node is surely cut (from CUT where
    # a timeline has no SHUT)
    ts = (tl.get("SHUT") or (tc,))[0]
    tr = (tl.get("RESTORE") or (None,))[0]
    other = [n for n in dr["ingress"] if n != cut]
    reads = jsonl(d / "leases.jsonl")
    held_by_cut = []
    for g, ln in sorted(dr["leases"].items()):
        name = ln.split("/", 1)[-1]
        before = [r for r in reads if r["t1"] <= tc and r.get("doc")]
        h0 = lease_holders(before[-1]["doc"]).get(name) if before else None
        if h0 != cut:
            out["gateways"][g] = {"holder": h0, "moved": False}
            v.ok(f"{lab}: {g}'s lease held by {h0} before the cut, not the cut node {cut}")
            continue
        held_by_cut.append(g)
        moved = next((r for r in reads if r["t0"] >= tc and r.get("doc") and lease_holders(r["doc"]).get(name) in other), None)
        took = round(moved["t1"] - tc, 3) if moved else None
        took_s = round(moved["t1"] - ts, 3) if moved else None
        new = lease_holders(moved["doc"]).get(name) if moved else None
        out["gateways"][g] = {"holder": h0, "moved": bool(moved), "new": new, "took_s": took, "after_shut_s": took_s}
        v.check(f"{lab}: {g}'s lease, held by {cut} at the cut, taken by {new or 'nobody'}"
                + (f" within {took_s} s of both ports shut, {took} s of the cut's start (the first lease read naming it)"
                   if took is not None else ""),
                bool(moved) and (tr is None or moved["t0"] <= tr), "the lease never moved before the restore" if not moved else "moved after the restore")
    pr = dr.get("prediction") or {}
    lo, hi = (pr.get("min_ms") or 0) / 1000, (pr.get("max_ms") or 0) / 1000
    for i, e in enumerate(dr["echo"]):
        c = e["client"]
        recs = jsonl(d / "probes" / f"echo-{c}.jsonl")
        gp = gap(recs, ts, lambda r: r.get("outcome") == "answered", "sent")
        trecs = tcp_records(read(d / "probes" / f"tcp-{c}.log"))
        tcp = gap(trecs, ts, lambda r: r["ok"], "t")
        # the slowest answer and connect sent while the node was cut (from the cut's start to the
        # restore): an answer that waited out a retransmission is a stall the counts do not show
        win = [r for r in recs if r.get("outcome") == "answered" and r["sent"] >= tc and (tr is None or r["sent"] <= tr)]
        gp["slowest_s"] = round(max(r["done"] - r["sent"] for r in win), 3) if win else None
        twin = [r for r in trecs if r["ok"] and r["t"] >= tc and (tr is None or r["t"] <= tr)]
        tcp["slowest_ms"] = max(r["ms"] for r in twin) if twin else None
        out["probes"][c], out["connects"][c] = gp, tcp
        mine = e["gateway"] in held_by_cut
        if not recs:
            v.bad(f"{lab}: the echo probe from {c} through {e['gateway']}", "no record")
            continue
        if mine:
            rec_ok = gp["first_ok"] is not None and (tr is None or gp["first_ok"] < tr)
            v.check(f"{lab}: {c} through {e['gateway']}: {gp['lost']} of {gp['sent']} echo requests lost, the gap {gp['gap_s']} s from the "
                    f"last request answered before both ports were shut to the first sent after it that was answered (sent times, "
                    f"every {dr['interval_s']} s), the slowest answer while cut {gp['slowest_s']} s; answered again before the ports came back",
                    rec_ok,
                    "no answer after the cut" if gp["first_ok"] is None else "answered only after the restore")
            v.check(f"{lab}: {c}'s connects to {e['address']}:443: {tcp['lost']} of {tcp['sent']} failed, the gap {tcp['gap_s']} s "
                    f"(every {dr['connect_interval_s']} s), the slowest connect while cut {tcp['slowest_ms']} ms; connecting again before "
                    "the ports came back", tcp["first_ok"] is not None and (tr is None or tcp["first_ok"] < tr),
                    "no connect after the cut" if tcp["first_ok"] is None else "only after the restore")
            if gp["gap_s"] is not None:
                inside = lo <= gp["gap_s"] <= hi + float(dr["interval_s"])
                v.ok(f"{lab}: the prediction, {lo:g} to {hi:g} s at the timers {pr.get('duration')}, {pr.get('renew_deadline')}, "
                     f"{pr.get('retry_period')} plus the firewall's ARP update, against the measured {gp['gap_s']} s (the probe's own "
                     f"interval {dr['interval_s']} s): {'within it' if inside else 'outside it'}")
        else:
            v.ok(f"{lab}: {c} through {e['gateway']}, a lease the cut node did not hold: {gp['lost']} of {gp['sent']} echo requests lost, "
                 f"{tcp['lost']} of {tcp['sent']} connects failed")
    during = read(d / "arp-during.txt")
    # the firewall learns a VIP's MAC only from traffic it forwards to it: the entry is judged for a
    # Gateway an echo probe drives through the firewall, and recorded for any other (the internet
    # Gateway in chapter 8, which no population reaches yet)
    driven = {e["gateway"] for e in dr["echo"]}
    for g in held_by_cut:
        new = out["gateways"][g].get("new")
        want = ((dr["candidates"].get(new) or {}).get("mac") or "").lower() if new else ""
        got = arp_mac(during, dr["vips"][g])
        if g not in driven:
            v.ok(f"{lab}: the firewall's ARP entry for {g}'s VIP {dr['vips'][g]} while {cut} is cut names {got or 'nothing'} (recorded, not "
                 f"judged: no probe of the drill reaches {g} through the firewall)")
            continue
        v.check(f"{lab}: the firewall's ARP entry for {g}'s VIP {dr['vips'][g]} names {new or 'the new holder'}'s bond MAC {want or '?'} while "
                f"{cut} is cut (arp-during.txt)", bool(want) and got == want, f"names {got or 'nothing'}")
    m = jsonl(d / "probes" / "model.jsonl")
    if dr.get("model"):
        ans = sum(1 for r in m if r.get("outcome") == "answered")
        v.ok(f"{lab}: apart from the gap, the model probe ({dr['model']['model']} through {dr['model']['gateway']}): {ans} of {len(m)} "
             "answered over the drill, the API gateway, router and identity provider pods on the cut node among what it lost")
        out["model"] = {"sent": len(m), "answered": ans}
    out["endpoints"] = {}
    for ns in dr.get("endpoints") or []:
        rows = jsonl(d / f"endpointslices-{ns}.jsonl")
        left = {}
        for r in rows:
            if r["t0"] < tc or not r.get("doc"):
                continue
            for it in r["doc"].get("items") or []:
                svc = (it["metadata"].get("labels") or {}).get("kubernetes.io/service-name", it["metadata"]["name"])
                here = any((ep.get("nodeName") == cut) for ep in it.get("endpoints") or [])
                if not here and svc not in left:
                    left[svc] = round(r["t1"] - tc, 3)
        out["endpoints"][ns] = left
        v.ok(f"{lab}: {ns}'s Services without an endpoint on {cut} after the cut: "
             + (", ".join(f"{s} from {t} s" for s, t in sorted(left.items())) or "none read"))
    (d / "analysis.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


# --------------------------------------------------------------------------------------------
# the isolation drill


def through(rec: dict) -> bool:
    """A forbidden attempt that got past where the matrix says it dies."""
    o = rec.get("outcome") or ""
    if rec.get("kind") == "connect":
        return o == "CONNECTED"
    return o.startswith("HTTP ") and o != "HTTP 404"


def analyze_isolation(v, dr: dict, d: Path, pas: str) -> dict:
    lab = f"pass {pas} {dr['id']}"
    out = {}
    hp = dr["hold"]
    for f in dr["factors"]:
        sub = d / f"x{f}"
        v.sec(f"{lab}: {hp['n'] * f} held connection(s) a population")
        T.judge_hold(v, sub, hp, "held", f, label=f"{lab} x{f} ")
        res = {}
        for r in dr["rows"]:
            recs = [x for x in jsonl(sub / f"iso-{r['population']}.jsonl") if "what" in x]
            own = [x for x in recs if x["what"] == "own"]
            own_ok = sum(1 for x in own if x["outcome"] == "HTTP 200")
            parts, zeros, allowed_bad = [], [], []
            for t in r["tries"]:
                xs = [x for x in recs if x["what"] == t["cell"]]
                if t["mode"] == "allowed":
                    good = sum(1 for x in xs if x["outcome"] in ("CONNECTED", "HTTP 200"))
                    parts.append(f"{t['column']} {good}/{len(xs)} allowed")
                    if good != len(xs) or not xs:
                        allowed_bad.append(t["column"])
                else:
                    n = sum(1 for x in xs if through(x))
                    parts.append(f"{t['column']} {n}/{len(xs)} through")
                    if n or not xs:
                        zeros.append(t["column"])
            res[r["population"]] = {"own": [own_ok, len(own)], "cells": parts}
            v.check(f"{lab} x{f} {r['population']} ({r['client']}): its own Gateway {own_ok} of {len(own)} answered 200; "
                    + "; ".join(parts), own and own_ok == len(own) == dr["rounds"] and not zeros and not allowed_bad,
                    ("forbidden through: " + ", ".join(zeros) if zeros else "") + (" allowed short: " + ", ".join(allowed_bad) if allowed_bad else "")
                    or f"own {own_ok} of {len(own)}")
        out[f"x{f}"] = res
    (d / "analysis.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def asked(text: str) -> list:
    out = []
    for line in (text or "").splitlines():
        x = line.split()
        if len(x) >= 2:
            try:
                out.append((float(x[0]), x[1]))
            except ValueError:
                pass
    return out


def analyze_leak(v, dr: dict, d: Path, pas: str) -> dict:
    lab = f"pass {pas} {dr['id']}"
    tl = timeline(d)
    field = read(d / "field.txt").strip()
    out = {"field": field}
    v.check(f"{lab}: the key Job minted {field}, a key of {dr['caller']}, a caller of the {dr['caller_audience']} audience",
            "MINTED" in tl and f"minted {field}" in read(d / "mint.log"), (read(d / "mint.log").strip().splitlines() or ["no log"])[-1][:120])
    tm = (tl.get("MINTED") or (None,))[0]
    got = asked(read(d / "requests-minted.txt"))
    ok = next((t for t, st in got if st == "200"), None)
    out["answered_s"] = round(ok - tm, 3) if ok and tm else None
    when = f" {out['answered_s']} s after the mint" if out["answered_s"] is not None else ""
    v.check(f"{lab}: {dr['client']}, a client of the {dr['client_audience']} audience, through {dr['gateway']} to {dr['model']} with {field}: "
            f"HTTP 200{when}: no network layer refuses it, the caller's key is not bound to a Gateway", ok is not None,
            f"{len(got)} request(s), the last {got[-1][1] if got else 'none'}")
    log = read(d / "api-gateway-access.txt")
    hit = [l for l in log.splitlines() if f'"caller":"{dr["caller"]}"' in l.replace(" ", "") and '"status":"200"' in l.replace(" ", "")]
    v.check(f"{lab}: the API gateway's access log names caller {dr['caller']} for it ({len(hit)} answered line(s)): the log says who, the "
            "Gateway says from where", bool(hit), "no answered line names the caller")
    tr = (tl.get("REVOKED") or (None,))[0]
    after = asked(read(d / "requests-revoked.txt"))
    code = str((dr.get("rejected") or {}).get("code", 401))
    rf = next((t for t, st in after if st == code), None)
    out["refused_s"] = round(rf - tr, 3) if rf and tr else None
    v.check(f"{lab}: after the revoke the same key refused HTTP {code}" + (f", {out['refused_s']} s after it" if out["refused_s"] is not None else ""),
            "REVOKED" in tl and rf is not None, f"{len(after)} request(s), the last {after[-1][1] if after else 'none'}")
    b = {x.split()[0]: x.split()[1] for x in read(d / "keys-before.txt").splitlines() if len(x.split()) == 2}
    a = {x.split()[0]: x.split()[1] for x in read(d / "keys-after.txt").splitlines() if len(x.split()) == 2}
    v.check(f"{lab}: the key Secret holds the same {len(b)} fields and fingerprints after the drill as before, and no {field}",
            bool(b) and a == b and field not in a, f"before {len(b)}, after {len(a)}")
    (d / "analysis.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return out


def cmd_analyze(a, which) -> int:
    plan = load(a.plan)
    dr = drill(plan, a.drill)
    v = vocab.Vocab()
    {"lease": analyze_lease, "isolation": analyze_isolation, "leak": analyze_leak}[which](v, dr, Path(a.dir), a.pass_)
    return 1 if v.counts()["fail"] else 0


def cmd_summarize(a) -> int:
    rs = Path(a.set)
    try:
        run = json.loads(read(rs / "RUN.json"))
    except ValueError:
        run = {}
    repo = run.get("labs_repo") or {}
    L = ["# Drills", "", f"- Lab: `{run.get('lab') or '-'}`; labs repo commit `{repo.get('commit') or 'none'}`"
         + (" (with uncommitted changes)" if repo.get("dirty") is True else "") + f"; UTC {run.get('utc_start') or 'unknown'}"]
    if a.stamp:
        L.append(f"- {a.stamp}")
    L.append("")
    for pd in sorted(rs.glob("pass*")):
        for dd in sorted(x for x in pd.iterdir() if x.is_dir()):
            L += [f"## {dd.name}: {pd.name}", ""]
            an = read(dd / "analyze.out").splitlines()
            L += ["```"] + [x for x in an if x.startswith(("  PASS", "  FAIL", "  SKIP", "  KNOWN", "=="))] + ["```", ""]
    L += ["## Verdict", "", "```"] + [x for x in read(rs / "verdict.txt").splitlines() if x.strip()] + ["```", ""]
    (rs / "DRILLS.md").write_text("\n".join(L), encoding="utf-8")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="p3drill")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("whole")
    s.add_argument("--plan", required=True)
    s.add_argument("--tenancy", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--explain", action="store_true")
    s = sub.add_parser("holder")
    s.add_argument("--plan", required=True)
    s.add_argument("--drill", required=True)
    s.add_argument("--leases", required=True)
    s = sub.add_parser("iso-plan")
    s.add_argument("--plan", required=True)
    s.add_argument("--drill", required=True)
    s.add_argument("--row", required=True)
    for name in ("analyze-lease", "analyze-isolation", "analyze-leak"):
        s = sub.add_parser(name)
        s.add_argument("--plan", required=True)
        s.add_argument("--dir", required=True)
        s.add_argument("--drill", required=True)
        s.add_argument("--pass", dest="pass_", required=True)
    s = sub.add_parser("summarize")
    s.add_argument("--set", required=True)
    s.add_argument("--stamp")
    a = ap.parse_args(argv)
    if a.cmd == "analyze-lease":
        return cmd_analyze(a, "lease")
    if a.cmd == "analyze-isolation":
        return cmd_analyze(a, "isolation")
    if a.cmd == "analyze-leak":
        return cmd_analyze(a, "leak")
    return {"get": cmd_get, "whole": cmd_whole, "holder": cmd_holder, "iso-plan": cmd_iso_plan, "summarize": cmd_summarize}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
