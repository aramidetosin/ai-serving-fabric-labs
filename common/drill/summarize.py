#!/usr/bin/env python3
"""summarize.py --set DIR [--stamp TEXT]: DRILLS.md for one drills result set (FRAMEWORK.md 4.6).

The method: report four things apart, per drill and per pass,
never one word such as "no loss" for all of them: round trips never answered at the cut, at the
restore and elsewhere; replies that came back later than a second (counted as lost, reported apart);
the longest stretch with nothing arriving; and where each probe ran. Nothing here decides loss from
a gap threshold. A reboot's return is reported as an event, with the probes lost around it, never as
a span from the departure. Every time is the lab host's clock (RUN.json records its tick). Reads
DIR/RUN.json, DIR/verdict.txt, DIR/compare.txt and DIR/pass*/<drill>/analysis.json only. Standard
library only.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "audit"))
import compare_passes as CP  # noqa: E402
import drill as DR  # noqa: E402
import vocab  # noqa: E402


def utc(epoch) -> str:
    import datetime as _dt  # noqa: PLC0415

    return _dt.datetime.fromtimestamp(float(epoch), _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-4] + "Z"


def nums(xs):
    return ", ".join(str(x) for x in xs) if xs else "none"


def drill_table(did: str, passes: dict) -> list:
    L = []
    first = passes[sorted(passes)[0]]
    L += [f"## {did}: {first['title']}", ""]
    tgt = first.get("target")
    head = ["Pass", "Placed", f"Ping ids crossing {tgt}: lost at the cut", "at the restore", "Other ids: lost",
            "Longest no-reply stretch at the cut (s)", "TCP failed at the cut", "at the restore"]
    has_orphan = any(passes[p].get("orphan") for p in passes)
    if has_orphan:
        head += ["Orphan failed at the cut", "at the restore"]
    L += ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for p in sorted(passes):
        a = passes[p]
        pg, tc, oc = a.get("ping") or {}, a.get("tcp") or {}, a.get("orphan") or {}
        row = [str(p), "yes" if (a.get("placement") or {}).get("placed") else "no",
               nums(pg.get("lost_at_cut_on_target")), nums(pg.get("lost_at_restore_on_target")), nums(pg.get("lost_spared")),
               nums(pg.get("gap_cut_on_target")), str(tc.get("failed_at_cut", "-")), str(tc.get("failed_at_restore", "-"))]
        if has_orphan:
            row += [str(oc.get("failed_at_cut", "-")), str(oc.get("failed_at_restore", "-"))]
        L.append("| " + " | ".join(row) + " |")
    L.append("")
    for p in sorted(passes):
        a = passes[p]
        if a.get("events"):
            # the standby is the drill's target only in standby-reboot; a keepalive drill cuts the active's link
            L.append(f"Pass {p}, the standby {a.get('standby') or a.get('target')}: departure, then its return as an event (host clock):")
            L.append("")
            names = dict(DR.EVENT_TEXT)
            for k, v in sorted(((k, v) for k, v in (a.get("events_utc") or {}).items() if k in names), key=lambda kv: kv[1]):
                L.append(f"- {utc(v)}: {names[k]}")
            L.append("")
        if a.get("peer_link"):
            parts = []
            for ph in ("before", "during", "after"):
                for sw, r in sorted((a["peer_link"].get(ph) or {}).items()):
                    parts.append(f"{ph} {sw} tx {r['tx_pps']}/s rx {r['rx_pps']}/s")
            L.append(f"Pass {p}, peer link packets per second (host-side counters of its member ports): " + "; ".join(parts))
            L.append("")
        for prob in a.get("problems") or []:
            L.append(f"Pass {p}: {prob}")
    if any(passes[p].get("problems") for p in passes):
        L.append("")
    L.append(f"Per pass: `pass<N>/{did}/analysis.txt` (every probe instance), `placement.txt`, `timeline.txt`, `captures/`, `logs/`, `klish/`.")
    L.append("")
    return L


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="summarize")
    ap.add_argument("--set", required=True)
    ap.add_argument("--stamp")
    a = ap.parse_args(argv)
    rs = Path(a.set)
    data = CP.load_set(rs)
    try:
        run = json.loads((rs / "RUN.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    L = [f"# Drills {rs.name}", "",
         f"- Lab: `{run.get('lab')}`; labs repo commit `{commit}`{uncommitted}; UTC {run.get('utc_start') or 'unknown'}; "
         f"host tick {run.get('host_tick')}"]
    if a.stamp:
        L.append(f"- {a.stamp}")
    L += ["- Probes: a ping from the source guest to the far guest, one ICMP id per process, each placed on a bond leg by the guests' hash; "
          "a TCP connect loop from the enterprise client to the users' VIP, a new source port per attempt, placed by the firewall's hash. "
          "Captures on the lab host locate every probe before the fault and timestamp it; the guest's own ping log is the second witness.",
          "- A lost ping is a round trip lost, on either leg. A reply later than a second counts as lost. Every shut is a KLISH shutdown "
          "from the switch side, which drops no carrier at the far end, so every member figure is an LACP-timeout figure.",
          ""]
    for did in CP.plan_order(rs, data):
        L += drill_table(did, data[did])
    try:
        L += ["## The passes compared", "", (rs / "compare.txt").read_text(encoding="utf-8").strip(), ""]
    except OSError:
        pass
    try:
        ver = (rs / "verdict.txt").read_text(encoding="utf-8")
    except OSError:
        ver = ""
    L += ["## Verdict", "", "```"] + [x for x in ver.splitlines() if x.strip() and not x.startswith("== RESULT")] + ["```", ""]
    L += [vocab.result_line(vocab.counts_of(str(rs / "verdict.txt"))), ""]
    (rs / "DRILLS.md").write_text("\n".join(L), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
