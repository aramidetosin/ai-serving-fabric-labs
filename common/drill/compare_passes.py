#!/usr/bin/env python3
"""compare_passes.py --set DIR: the passes of one drills result set, side by side (FRAMEWORK.md 4.6).

The method: independent passes of the same drills are combined
into the ranges that get published, so no figure depends on someone picking a representative run by
eye. For each drill and each measure it prints the values across every pass and every probe
instance: one value when they agree, a range when they do not. A row whose passes disagree about
whether there was loss at all (some lost nothing, others lost five or more) is a contradiction, not
a range, and is printed on its own line starting DISAGREE, as is a drill placed in some passes and
not in others, and any pass where the guest's ping log and the host's captures disagree. Reads
DIR/pass*/<drill>/analysis.json only. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "audit"))
import evfile  # noqa: E402

MATERIAL = 5   # a spread from 0 to at least this many probes is a contradiction, not noise


def span(values, fmt="{:g}"):
    vals = sorted({v for v in values if v is not None})
    if not vals:
        return "no data"
    if len(vals) == 1:
        return fmt.format(vals[0])
    return f"{fmt.format(vals[0])} to {fmt.format(vals[-1])}"


def conflict(values) -> bool:
    vals = [v for v in values if v is not None]
    return bool(vals) and min(vals) == 0 and max(vals) >= MATERIAL


def load_set(rs: Path) -> dict:
    """{drill: {pass: analysis}}, passes in order."""
    out = {}
    found = {evfile.plain_name(p): p for p in [*rs.glob("pass*/*/analysis.json.gz"), *rs.glob("pass*/*/analysis.json")]}
    for p in sorted(found.values(), key=lambda x: (int(re.sub(r"\D", "", x.parent.parent.name) or 0), x.parent.name)):
        try:
            a = json.loads(evfile.read_text(p, "strict"))
        except (OSError, ValueError):
            continue
        out.setdefault(a["drill"], {})[int(a["pass"])] = a
    return out


def plan_order(rs: Path, drills: dict) -> list:
    try:
        plan = json.loads(evfile.read_text(rs / "drills.json", "strict"))
        order = [d["id"] for d in plan.get("list") or []]
    except (OSError, ValueError):
        order = []
    return [d for d in order if d in drills] + sorted(d for d in drills if d not in order)


def rows_for(did: str, passes: dict) -> tuple:
    rows, dis = [], []
    ps = sorted(passes)
    placed = {p: bool((passes[p].get("placement") or {}).get("placed")) for p in ps}
    rows.append(("placed before the fault", ", ".join(f"pass {p} {'yes' if placed[p] else 'no'}" for p in ps), len(set(placed.values())) == 1))
    if len(set(placed.values())) > 1:
        dis.append(f"DISAGREE {did}: placed in passes {[p for p in ps if placed[p]]}, not in {[p for p in ps if not placed[p]]}")
    for p in ps:
        for prob in passes[p].get("problems") or []:
            if "disagree" in prob:
                dis.append(f"DISAGREE {did}: pass {p}: {prob}")

    def add(label, values, fmt="{:g}", loss=True):
        """A loss row is judged (some passes lost nothing, others five or more); a rate or a time
        is printed as its range only."""
        ok = not (loss and conflict(values))
        rows.append((label, span(values, fmt), ok if loss else None))
        if not ok:
            dis.append(f"DISAGREE {did}: {label}: passes conflict about whether there was loss at all ({span(values, fmt)})")

    pg = [passes[p].get("ping") for p in ps if passes[p].get("ping")]
    if pg:
        tgt = passes[ps[0]].get("target")
        add(f"ping round trips lost, ids crossing {tgt}", [x for g in pg for x in g["lost_on_target"]])
        add("  of them at the cut", [x for g in pg for x in g["lost_at_cut_on_target"]])
        add("  of them at the restore", [x for g in pg for x in g["lost_at_restore_on_target"]])
        add(f"ping round trips lost, ids not crossing {tgt}", [x for g in pg for x in g["lost_spared"]])
        add(f"longest stretch with no reply at the cut, ids crossing {tgt} (s)", [x for g in pg for x in g["gap_cut_on_target"]], "{:.2f}", loss=False)
        rows.append(("ping ids crossing the target, per pass", ", ".join(f"pass {p} {len(passes[p]['ping']['on_target'])} of "
                                                                      f"{len(passes[p]['ping']['ids'])}" for p in ps if passes[p].get("ping")), None))
    tc = [passes[p].get("tcp") for p in ps if passes[p].get("tcp")]
    if tc:
        add("TCP connects failed at the cut", [c["failed_at_cut"] for c in tc])
        add("TCP connects failed at the restore", [c["failed_at_restore"] for c in tc])
        add("TCP connects failed elsewhere", [c["failed_elsewhere"] for c in tc])
    oc = [passes[p].get("orphan") for p in ps if passes[p].get("orphan")]
    if oc:
        add("orphan connects failed at the cut", [c["failed_at_cut"] for c in oc])
        add("orphan connects failed at the restore", [c["failed_at_restore"] for c in oc])
    ev = [passes[p].get("events") for p in ps if passes[p].get("events")]
    if ev:
        add("every bond on one leg, seconds after the fault began (the reboot or the shut)", [e.get("bonds_on_one_leg") for e in ev], "{:.1f}", loss=False)
        back = {p: (passes[p].get("events") or {}).get("return") is not None for p in ps if passes[p].get("events")}
        rows.append(("the standby returned (every bond back on two legs)",
                     ", ".join(f"pass {p} {'yes' if b else 'no'}" for p, b in back.items()), len(set(back.values())) == 1))
        if len(set(back.values())) > 1:
            dis.append(f"DISAGREE {did}: the standby returned in passes {[p for p, b in back.items() if b]}, not in {[p for p, b in back.items() if not b]}")
    pl = [passes[p].get("peer_link") for p in ps if passes[p].get("peer_link")]
    if pl:
        for ph in ("before", "during", "after"):
            for sw in sorted({s for x in pl for s in (x.get(ph) or {})}):
                add(f"peer link tx packets per second on {sw}, {ph}", [(x.get(ph) or {}).get(sw, {}).get("tx_pps") for x in pl], "{:g}", loss=False)
    return rows, dis


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="compare_passes")
    ap.add_argument("--set", required=True)
    a = ap.parse_args(argv)
    rs = Path(a.set)
    data = load_set(rs)
    if not data:
        print("compare_passes: no analysis.json in this set")
        return 1
    alldis = []
    out = [f"Passes compared: {', '.join(sorted({f'pass{p}' for d in data.values() for p in d}))} in {rs.name}", ""]
    for did in plan_order(rs, data):
        rows, dis = rows_for(did, data[did])
        alldis += dis
        out += [f"## {did}", "", "| measure | across every pass and probe | agrees? |", "|---|---|---|"]
        out += [f"| {lab} | {val} | {'-' if ok is None else 'yes' if ok else 'no, passes conflict'} |" for lab, val, ok in rows]
        out.append("")
    out.append("Ranges span every probe instance of every pass. A ping lost is a round trip lost, on either leg.")
    out.append("")
    out += alldis or ["no disagreement between the passes"]
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
