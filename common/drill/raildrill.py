#!/usr/bin/env python3
"""raildrill.py: chapter 5's dark-switch drill, its plan, the rails' whole check and the analysis
(common/drill/lib-raildrill.sh).

    raildrill.py get       --plan gen/drills.json PATH         a value of the plan
    raildrill.py rows      --plan gen/drills.json              the probe's rows: id, ns, dst, ICMP id (TSV)
    raildrill.py caps      --plan gen/drills.json              the capture points: node, eth, rail (TSV)
    raildrill.py split     --dir DIR                           the guest's ping logs, fetched as one stream, into logs/
    raildrill.py whole     --plan gen/drills.json --dir DIR    one poll of the rails whole, from its saved files
    raildrill.py analyze   --plan gen/drills.json --dir DIR --drill ID --pass N
    raildrill.py summarize --set DIR [--stamp TEXT]            DRILLS.md

Every time is the lab host's clock: the requests and replies as tcpdump on the host saw them in
the nodes' container ports (tcpdump -nn -tt -e, host epoch seconds), against the moments drills.sh
stamped on the host clock (timeline.txt: the shut's session started and returned, the restore's
session started and returned). The guest's own ping log is the second witness of each row's count
of replies; a disagreement is printed, never resolved.

For each row the analysis follows the request out of the source's container port on the rail it
rides (the destination's rail), into the destination's port on that rail, the reply out of the
destination's port on the rail it rides (the source's rail) and into the source's port. Requests
are grouped by when they were sent: before the cut, at the cut (while the shut's session ran),
dark (from the session's return to the restore's start), at the restore, after it. A reply later
than late_ms counts as lost. A dark row is judged silent where the plan says: with its request's
rail dead, the requests leave the source and none reach the destination; with only its reply's
rail dead, the destination answers and no reply reaches the source. After the restore, the first
answered request is an event, timed from the restore's session start. Beside the counts it records,
for each dark row, the ARP requests the node whose next frame rides the dead rail sent for the far
address while dark (a KLISH shutdown drops no carrier, so the node keeps asking), and the guest
log's Destination Host Unreachable lines (its kernel's own, once that neighbor entry failed).
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "audit"))
import analyze_ping as AP  # noqa: E402
import evfile  # noqa: E402
import judge as J  # noqa: E402
import vocab  # noqa: E402

WARM_S = 1.0     # requests sent in the probes' first second are warm-up (a new flow's first packet can be lost to ARP)


def load(p):
    """A JSON file, stored plain or compressed (NAME.gz, evfile.py)."""
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
            cur = next((x for x in cur if isinstance(x, dict) and x.get("id") == part), None)
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


def cmd_rows(a) -> int:
    for r in load(a.plan)["probes"]["rails"]["rows"]:
        print("\t".join(str(x) for x in (r["id"], r["ns"], r["dst_addr"], r["icmp_id"])))
    return 0


def cmd_caps(a) -> int:
    for c in load(a.plan)["probes"]["rails"]["capture"]:
        print("\t".join(str(x) for x in (c["node"], c["eth"], c["rail"])))
    return 0


def cmd_split(a) -> int:
    """'==> /tmp/sfab-drill/ping-<row>.log' headers, each followed by that log, into logs/ping-<row>.log."""
    d = Path(a.dir) / "logs"
    d.mkdir(parents=True, exist_ok=True)
    cur, buf = None, []

    def flush():
        if cur:
            (d / f"ping-{cur}.log").write_text("\n".join(buf) + "\n", encoding="utf-8")
    for line in sys.stdin.read().splitlines():
        m = re.match(r"^==> .*/ping-([A-Za-z0-9-]+)\.log$", line)
        if m:
            flush()
            cur, buf = m.group(1), []
        elif cur:
            buf.append(line)
    flush()
    return 0


# --------------------------------------------------------------------------------------------
# the rails whole


def whole(plan: dict, d: Path) -> tuple:
    """(whole?, problems) for one poll: every same-rail row answered, every rail switch's rendered
    ports up and oper-up."""
    probs = []
    for r in plan["probes"]["rails"]["rows"]:
        if r["kind"] != "same":
            continue
        res = AP.GUEST_STATS.search(read(d / f"{r['id']}.txt"))
        if not res or int(res.group(2)) < 1:
            probs.append(f"{r['id']} not answered")
    for sw, x in (plan.get("rail_switches") or {}).items():
        st = J.p_interface_status(read(d / f"{sw}-status.txt"))
        down = [n for n in x["natives"] if (st.get(n) or {}).get("oper") != "up"]
        if not st:
            probs.append(f"{sw}: show interface status not read")
        elif down:
            probs.append(f"{sw}: {','.join(down)} not up")
    return not probs, probs


def cmd_whole(a) -> int:
    ok, probs = whole(load(a.plan), Path(a.dir))
    print("whole" if ok else "; ".join(probs))
    return 0 if ok else 1


# --------------------------------------------------------------------------------------------
# the analysis


def timeline(d: Path) -> dict:
    t = {}
    for line in read(d / "timeline.txt").splitlines():
        x = line.split(" ", 2)
        if len(x) >= 2:
            try:
                t.setdefault(x[1], float(x[0]))
            except ValueError:
                pass
    return t


def port_frames(d: Path, node: str, eth: str) -> list:
    return AP.frames(read(d / "captures" / f"{node}-{eth}.txt"), f"{node}:{eth}")


def phase(t, tl) -> str:
    if t < tl["T0"]:
        return "before"
    if t < tl["T0e"]:
        return "cut"
    if t < tl["T1"]:
        return "dark"
    if t < tl["T1e"]:
        return "restore"
    return "after"


ARP_REQ = re.compile(r"^(\d+\.\d+) \S+ > \S+, ethertype ARP \(0x0806\), length \d+: Request who-has (\S+) tell (\S+),")
UNREACH = re.compile(r"Destination Host Unreachable")


def arp_asks(d: Path, node: str, eth: str, target: str, t0: float, t1: float) -> int:
    """ARP requests for target that left node's container port eth between t0 and t1 (host clock)."""
    n = 0
    for line in read(d / "captures" / f"{node}-{eth}.txt").splitlines():
        m = ARP_REQ.match(line.strip())
        if m and m.group(2) == target and t0 <= float(m.group(1)) < t1:
            n += 1
    return n


def row_record(plan: dict, row: dict, d: Path, tl: dict, late_ms: float, dead=()) -> dict:
    caps = {(c["node"], c["rail"]): c["eth"] for c in plan["probes"]["rails"]["capture"]}
    pid = row["icmp_id"]
    sel = lambda fs, kind: {f["seq"]: f["t"] for f in fs if f.get("proto") == "icmp" and f.get("id") == pid and f["kind"] == kind}  # noqa: E731
    req_out = sel(port_frames(d, row["src"], caps[(row["src"], row["request_rail"])]), "request")
    req_in = sel(port_frames(d, row["dst"], caps[(row["dst"], row["request_rail"])]), "request")
    rep_out = sel(port_frames(d, row["dst"], caps[(row["dst"], row["reply_rail"])]), "reply")
    rep_in = sel(port_frames(d, row["src"], caps[(row["src"], row["reply_rail"])]), "reply")
    start = min(req_out.values()) if req_out else None
    ph = {k: {"sent": 0, "arrived": 0, "replied": 0, "answered": 0, "late": 0} for k in ("before", "cut", "dark", "restore", "after")}
    first_after = None
    oks = {}
    for seq, t in sorted(req_out.items()):
        if start is not None and t < start + WARM_S:
            continue
        p = ph[phase(t, tl)]
        p["sent"] += 1
        p["arrived"] += seq in req_in
        p["replied"] += seq in rep_out
        got = rep_in.get(seq)
        ok = got is not None and (got - t) * 1000.0 <= late_ms
        p["answered"] += ok
        p["late"] += got is not None and not ok
        if ok and t >= tl["T1"] and (first_after is None or t < first_after):
            first_after = t
        oks[seq] = (t, ok)
    # steady: from the first answered request after the restore began (or the restore's return, on a
    # row that never went dark) to the end, every request must be answered
    since = first_after if first_after is not None else tl["T1e"]
    steady = [ok for t, ok in oks.values() if t >= since and t >= tl["T1"]]
    tail = {"sent": len(steady), "answered": sum(steady)}
    glog = read(d / "logs" / f"ping-{row['id']}.log")
    g = AP.guest_log(glog)
    # while dark, the node whose next frame rides a dead rail asks ARP for the far address there:
    # the source on a dead request rail, the destination on a dead reply rail
    arp = None
    if row["request_rail"] in dead:
        arp = arp_asks(d, row["src"], caps[(row["src"], row["request_rail"])], row["dst_addr"], tl["T0e"], tl["T1"])
    elif row["reply_rail"] in dead:
        arp = arp_asks(d, row["dst"], caps[(row["dst"], row["reply_rail"])], row["src_addr"], tl["T0e"], tl["T1"])
    answered_all = sum(1 for seq, t in req_out.items() if seq in rep_in and (rep_in[seq] - t) * 1000.0 <= late_ms)
    return {"id": row["id"], "kind": row["kind"], "rail": row["rail"], "to_rail": row["to_rail"], "icmp_id": pid,
            "request_rail": row["request_rail"], "reply_rail": row["reply_rail"], "request_switch": row["request_switch"],
            "reply_switch": row["reply_switch"], "phases": ph, "tail": tail,
            "return_s": None if first_after is None else round(first_after - tl["T1"], 3),
            "return_after_session_s": None if first_after is None else round(first_after - tl["T1e"], 3),
            "captured_answered": answered_all, "guest_received": g["received"], "guest_transmitted": g["transmitted"],
            "dark_arp": arp, "guest_unreachable": len(UNREACH.findall(glog))}


def _rows_label(row: dict) -> str:
    if row["kind"] == "same":
        return f"{row['id']} (rail {row['rail']}, {row['request_switch']})"
    return (f"{row['id']} (rail {row['rail']} to rail {row['to_rail']}: request on {row['request_switch']}, "
            f"reply on {row['reply_switch']})")


def cmd_analyze(a) -> int:
    plan = load(a.plan)
    dr = next((x for x in plan["list"] if x["id"] == a.drill), None)
    if dr is None or dr.get("kind") != "dark":
        print(f"raildrill: no dark drill {a.drill}", file=sys.stderr)
        return 2
    d = Path(a.dir)
    v = vocab.Vocab(known=set(os.environ.get("SFAB_KNOWN_IDS", "").split()) or None)
    tag = f"pass {a.pass_} {a.drill}"
    tl = timeline(d)
    need = {"T0": "INJECT", "T0e": "INJECTED", "T1": "RESTORE", "T1e": "RESTORED"}
    tl = {k: tl.get(x) for k, x in need.items()}
    if None in tl.values():
        v.bad(f"{tag}: the timeline", "missing " + ", ".join(need[k] for k, x in tl.items() if x is None))
        return 1
    late = float(plan["timing"].get("late_ms", 1000))
    sw, dead = dr["switch"], dr["dead_rails"]
    recs = []
    for row in plan["probes"]["rails"]["rows"]:
        r = row_record(plan, row, d, tl, late, dead)
        r["expect"] = dr["expect"][row["id"]]
        recs.append(r)
        b, k, af = r["phases"]["before"], r["phases"]["dark"], r["phases"]["after"]
        lab = _rows_label(row)
        v.check(f"{tag}: {lab}: before the cut, {b['answered']} of {b['sent']} answered", b["sent"] > 0 and b["answered"] == b["sent"],
                f"{b['sent'] - b['answered']} lost" if b["sent"] else "no request captured")
        if r["expect"] == "dark":
            v.check(f"{tag}: {lab}: while {sw} was dark, {k['answered']} of {k['sent']} answered (dark, as planned: nothing routes around it)",
                    k["sent"] > 0 and k["answered"] == 0, f"{k['answered']} answered" if k["sent"] else "no request captured while dark")
            if row["request_rail"] in dead:
                v.check(f"{tag}: ... its requests left {row['src']} on rail {row['request_rail']} ({k['sent']}) and none reached {row['dst']} "
                        f"({k['arrived']}): the dead rail is silent", k["sent"] > 0 and k["arrived"] == 0,
                        f"{k['arrived']} reached {row['dst']}")
            else:
                v.check(f"{tag}: ... its requests reached {row['dst']} on rail {row['request_rail']} ({k['arrived']} of {k['sent']}), "
                        f"{row['dst']}'s replies left on rail {row['reply_rail']} ({k['replied']}) and none reached {row['src']}: "
                        "the reply rides the dead rail", k["arrived"] > 0 and k["replied"] > 0 and k["answered"] == 0,
                        f"arrived {k['arrived']}, replied {k['replied']}, answered {k['answered']}")
            v.check(f"{tag}: ... after the no shutdown it answered again: the first answered request sent "
                    f"{r['return_s'] if r['return_s'] is not None else '?'} s after the restore's session began "
                    f"({r['return_after_session_s'] if r['return_after_session_s'] is not None else '?'} s after it returned; an event, host clock)",
                    r["return_s"] is not None, "no answered request after the restore")
        else:
            v.check(f"{tag}: {lab}: while {sw} was dark, {k['answered']} of {k['sent']} answered", k["sent"] > 0 and k["answered"] == k["sent"],
                    f"{k['sent'] - k['answered']} lost" if k["sent"] else "no request captured while dark")
        v.check(f"{tag}: ... after the restore, from its first answered request on, {r['tail']['answered']} of {r['tail']['sent']} answered",
                r["tail"]["sent"] > 0 and r["tail"]["answered"] == r["tail"]["sent"], f"{r['tail']['sent'] - r['tail']['answered']} lost")
        if r["guest_received"] is not None and r["guest_received"] != r["captured_answered"]:
            v.ok(f"{tag}: ... DISAGREE: the guest's ping log counts {r['guest_received']} replies, the host's captures "
                 f"{r['captured_answered']} answered in time (recorded, not resolved)")
    out = {"drill": a.drill, "pass": int(a.pass_), "switch": sw, "dead_rails": dead, "live_rails": dr["live_rails"], "timeline": tl,
           "late_ms": late, "rows": recs}
    (d / "analysis.json").write_text(json.dumps(out, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    (d / "analysis.txt").write_text(text(out), encoding="utf-8")
    return 1 if v.counts()["fail"] else 0


def text(a: dict) -> str:
    tl = a["timeline"]
    L = [f"pass {a['pass']} {a['drill']}: {a['switch']} dark (rails {', '.join(map(str, a['dead_rails']))}); "
         f"shut session {tl['T0e'] - tl['T0']:.2f} s, dark {tl['T1'] - tl['T0e']:.2f} s, restore session {tl['T1e'] - tl['T1']:.2f} s (host clock)"]
    L.append(f"{'row':<12} {'expect':<9} {'before':>9} {'dark':>9} {'arrived':>8} {'replied':>8} {'arp':>5} {'after':>9} {'return s':>9} "
             f"{'guest rx':>9} {'unreach':>8}")
    for r in a["rows"]:
        b, k, af = r["phases"]["before"], r["phases"]["dark"], r["phases"]["after"]
        L.append(f"{r['id']:<12} {r['expect']:<9} {b['answered']:>4}/{b['sent']:<4} {k['answered']:>4}/{k['sent']:<4} {k['arrived']:>8} "
                 f"{k['replied']:>8} {str(r['dark_arp'] if r.get('dark_arp') is not None else '-'):>5} {af['answered']:>4}/{af['sent']:<4} "
                 f"{str(r['return_s'] if r['return_s'] is not None else '-'):>9} "
                 f"{str(r['guest_received'] if r['guest_received'] is not None else '?'):>9} {r.get('guest_unreachable', 0):>8}")
    L += ["", "before, dark, after: answered of the requests that left the source's container port (host clock; a reply over "
          f"{a['late_ms']:g} ms counts as lost); arrived, replied: dark requests seen at the far node's port and its replies leaving it; "
          "arp: ARP requests for the far address on the dead rail while dark (from the source on a dead request rail, from the far "
          "node on a dead reply rail); guest rx: replies the guest's ping counted; unreach: its Destination Host Unreachable lines"]
    return "\n".join(L) + "\n"


def cmd_summarize(a) -> int:
    rs = Path(a.set)
    found = {evfile.plain_name(p): p for p in [*rs.glob("pass*/*/analysis.json.gz"), *rs.glob("pass*/*/analysis.json")]}
    sets = sorted(found.values(), key=lambda p: (int(p.parent.parent.name[4:]), p.parent.name))
    runs = [load(p) for p in sets]
    res = vocab.counts_of(str(rs / "verdict.txt"))
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    L = ["# Rail drills", "",
         f"- Lab: `{run.get('lab')}`; labs repo commit `{repo.get('commit') or 'none'}`{uncommitted}; "
         f"UTC {run.get('utc_start') or 'unknown'}; host tick {run.get('host_tick')}; passes: {len({x['pass'] for x in runs})}"]
    if a.stamp:
        L.append(f"- {a.stamp}")
    L.append("")
    for drill in sorted({x["drill"] for x in runs}):
        rr = [x for x in runs if x["drill"] == drill]
        L += [f"## {drill}: {rr[0]['switch']} dark, rails {', '.join(map(str, rr[0]['dead_rails']))}", "",
              "Answered of sent, by when each request was sent (host clock; the cut and the restore are the KLISH sessions). "
              "Return: seconds from the restore's session start to the first answered request.", "",
              "| Pass | Row | Expect | Before | Dark | Reached the far node | Far node replied | ARP while dark | After | Return (s) | "
              "Guest log replies | Guest log unreachable |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for x in rr:
            for r in x["rows"]:
                b, k, af = r["phases"]["before"], r["phases"]["dark"], r["phases"]["after"]
                L.append(f"| {x['pass']} | `{r['id']}` | {r['expect']} | {b['answered']} of {b['sent']} | {k['answered']} of {k['sent']} | "
                         f"{k['arrived']} | {k['replied']} | {r['dark_arp'] if r.get('dark_arp') is not None else '-'} | "
                         f"{af['answered']} of {af['sent']} | "
                         f"{r['return_s'] if r['return_s'] is not None else '-'} | {r['guest_received'] if r['guest_received'] is not None else '?'} | "
                         f"{r.get('guest_unreachable', 0)} |")
        L.append("")
        agree = all(len({(r["expect"], r["phases"]["dark"]["answered"] == 0) for x2 in rr for r in x2["rows"] if r["id"] == rid}) == 1
                    for rid in {r["id"] for r in rr[0]["rows"]})
        L += [f"Every pass {'agrees' if agree else 'does not agree'} on which rows went dark.", ""]
        for x in rr:
            L += [f"Pass {x['pass']} (`pass{x['pass']}/{drill}/analysis.txt`):", "", "```"] + text(x).rstrip().splitlines() + ["```", ""]
    L += ["The verdict so far (`verdict.txt`; the run's own RESULT line follows it there):", "", vocab.result_line(res), ""]
    (rs / "DRILLS.md").write_text("\n".join(L), encoding="utf-8")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="raildrill")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    for name in ("rows", "caps"):
        s = sub.add_parser(name)
        s.add_argument("--plan", required=True)
    s = sub.add_parser("split")
    s.add_argument("--dir", required=True)
    s = sub.add_parser("whole")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s = sub.add_parser("analyze")
    for k in ("--plan", "--dir", "--drill"):
        s.add_argument(k, required=True)
    s.add_argument("--pass", dest="pass_", required=True)
    s = sub.add_parser("summarize")
    s.add_argument("--set", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"get": cmd_get, "rows": cmd_rows, "caps": cmd_caps, "split": cmd_split, "whole": cmd_whole, "analyze": cmd_analyze,
            "summarize": cmd_summarize}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
