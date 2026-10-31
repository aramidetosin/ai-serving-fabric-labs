#!/usr/bin/env python3
"""analyze_ping.py: what a ping probe did during a drill, as round trips (FRAMEWORK.md 4.6).

    analyze_ping.py --decode FILE [FILE ...] --src ADDR --dst ADDR --id N [--t0 EPOCH] [--restore EPOCH]
                    [--guest-log FILE] [--late-ms 1000]

The method: loss is read from the sequence numbers, never
inferred from a gap threshold; each lost probe is placed against the cut and the restore, so loss
during the failure is never mixed with loss during recovery; replies that arrive later than a second
count as lost and are reported apart, because ping counts a very late reply as received; and the
longest stretch with nothing arriving is computed over arrival order, not sequence order. A lost
probe is a round trip lost, on either leg: a ping needs a request and a reply, and nothing here says
which of the two went missing.

What this version adds for the book's lab is where the times come from. The probe runs inside a
VM guest, whose clock is the guest's own, so every time here is the lab host's: the requests and
replies as tcpdump on the host saw them on the guests' container ports (tcpdump -nn -tt -e -r,
host epoch seconds), against the cut and the restore, which drills.sh also stamps on the host
clock. The guest's own ping log (ping -D -O) is the second witness: its count of unanswered
sequence numbers must agree with the captures', and a disagreement is printed, never resolved.

As a module (common/drill/drill.py imports it): frames(text, nic) reads a decode; probe(...) builds
one probe's record from the frames and the guest log. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

HEAD = re.compile(r"^(\d+\.\d+) ([0-9a-f:]{17}) > ([0-9a-f:]{17}), (.*)$")
ICMP = re.compile(r"(\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): ICMP echo (request|reply), id (\d+), seq (\d+)")
TCP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]")
VLAN = re.compile(r"\bvlan (\d+), p \d+")
GUEST_REPLY = re.compile(r"^\[(\d+\.\d+)\].*icmp_seq=(\d+).*time=([\d.]+) ms")
GUEST_NOANS = re.compile(r"^\[(\d+\.\d+)\] no answer yet for icmp_seq=(\d+)")
GUEST_STATS = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received(?:, \+(\d+) duplicates)?")


def frames(text: str, nic: str = "") -> list:
    """One dict per frame of a tcpdump -nn -tt -e decode: t, src_mac, dst_mac, vlan, nic, and for
    ICMP echo kind/src/dst/id/seq, for TCP src/sport/dst/dport/flags."""
    out = []
    for line in (text or "").splitlines():
        m = HEAD.match(line.strip())
        if not m:
            continue
        rest = m.group(4)
        f = {"t": float(m.group(1)), "src_mac": m.group(2), "dst_mac": m.group(3), "nic": nic, "vlan": None}
        v = VLAN.search(rest)
        if v:
            f["vlan"] = int(v.group(1))
        i = ICMP.search(rest)
        if i:
            f.update(proto="icmp", src=i.group(1), dst=i.group(2), kind=i.group(3), id=int(i.group(4)), seq=int(i.group(5)))
        else:
            t = TCP.search(rest)
            if t:
                f.update(proto="tcp", src=t.group(1), sport=int(t.group(2)), dst=t.group(3), dport=int(t.group(4)), flags=t.group(5))
            else:
                f["proto"] = "other"
        out.append(f)
    return out


def guest_log(text: str) -> dict:
    """The guest's ping -D -O log: replies {seq: (t, rtt_ms)}, duplicates, no-answer lines, the
    statistics line."""
    rep, dups, noans = {}, 0, set()
    tx = rx = None
    for line in (text or "").splitlines():
        m = GUEST_REPLY.match(line)
        if m:
            seq = int(m.group(2))
            if seq in rep:
                dups += 1
            else:
                rep[seq] = (float(m.group(1)), float(m.group(3)))
            continue
        m = GUEST_NOANS.match(line)
        if m:
            noans.add(int(m.group(2)))
            continue
        m = GUEST_STATS.search(line)
        if m:
            tx, rx = int(m.group(1)), int(m.group(2))
    return {"replies": rep, "dups": dups, "no_answer": noans, "transmitted": tx, "received": rx}


def mode(nics: list):
    c = Counter(x for x in nics if x)
    return c.most_common(1)[0][0] if c else None


def probe(src_frames: list, dst_frames: list, src: str, dst: str, pid: int, t0=None, restore=None,
          guest=None, late_ms=1000.0, cut_w=15.0, rec_w=25.0, place=None, windows=None) -> dict:
    """One ping probe (one ICMP id) as round trips, on the host's clock.

    src_frames: the frames on the source guest's container ports (requests leaving, replies
    arriving); dst_frames: on the destination's (requests arriving, replies leaving). place is
    (start, end) on the host clock for the placement read; windows overrides the cut and restore
    windows ({"cut": (a, b), "restore": (a, b)}) for a drill whose events set them (a reboot)."""
    req, rep = {}, {}
    for f in src_frames:
        if f.get("proto") != "icmp" or f.get("id") != pid:
            continue
        if f["kind"] == "request" and f["src"] == src and f["dst"] == dst:
            req.setdefault(f["seq"], (f["t"], f["nic"]))
        elif f["kind"] == "reply" and f["src"] == dst and f["dst"] == src:
            rep.setdefault(f["seq"], []).append((f["t"], f["nic"]))
    req_in, rep_out = {}, {}
    for f in dst_frames:
        if f.get("proto") != "icmp" or f.get("id") != pid:
            continue
        if f["kind"] == "request" and f["src"] == src and f["dst"] == dst:
            req_in.setdefault(f["seq"], (f["t"], f["nic"]))
        elif f["kind"] == "reply" and f["src"] == dst and f["dst"] == src:
            rep_out.setdefault(f["seq"], (f["t"], f["nic"]))
    late_s = late_ms / 1000.0
    win = dict(windows or {})
    if "cut" not in win and t0 is not None:
        win["cut"] = (t0 - 0.5, t0 + cut_w)
    if "restore" not in win and restore is not None:
        win["restore"] = (restore - 0.5, restore + rec_w)

    def where(t):
        # the cut and the restore first, then any window a drill's events add (a standby's own shut)
        for k in ("cut", "restore", *sorted(x for x in win if x not in ("cut", "restore"))):
            a = win.get(k)
            if a and a[0] <= t <= a[1]:
                return k
        return "elsewhere"

    lost, late, dup = [], [], 0
    arrivals = []
    for seq, (ts, _nic) in sorted(req.items()):
        got = rep.get(seq) or []
        dup += max(0, len(got) - 1)
        if got:
            ta = min(t for t, _ in got)
            arrivals.append(ta)
            if ta - ts > late_s:
                late.append(seq)
                lost.append(seq)
        else:
            lost.append(seq)
    by_win = Counter(where(req[s][0]) for s in lost)
    arrivals.sort()

    def widest(window=None):
        w, at = 0.0, None
        for a, b in zip(arrivals, arrivals[1:]):
            if window and not (window[0] <= a <= window[1] or window[0] <= b <= window[1]):
                continue
            if b - a > w:
                w, at = b - a, (a, b)
        return round(w, 3), at

    rel = (lambda t: round(t - t0, 3)) if t0 is not None else (lambda t: round(t, 3))
    gap_all, gap_at = widest()
    gap_cut, _ = widest(win.get("cut"))
    gap_rec, _ = widest(win.get("restore"))

    def legs(a, b):
        sel = lambda d: [v[1] for s, v in d.items() if a <= v[0] < b]  # noqa: E731
        return {"req_out": mode(sel(req)), "req_in": mode(sel(req_in)), "rep_out": mode(sel(rep_out)),
                "rep_in": mode([x[1] for s, v in rep.items() for x in v[:1] if a <= x[0] < b])}

    out = {"id": pid, "sent": len(req), "answered": len(req) - len(lost), "lost": len(lost), "late": len(late), "dup": dup,
           "lost_at_cut": by_win.get("cut", 0), "lost_at_restore": by_win.get("restore", 0), "lost_elsewhere": by_win.get("elsewhere", 0),
           "lost_by_window": dict(sorted(by_win.items())), "lost_seqs": lost, "late_seqs": late,
           "first_lost_s": rel(req[lost[0]][0]) if lost else None, "last_lost_s": rel(req[lost[-1]][0]) if lost else None,
           "gap_s": gap_all, "gap_from_s": rel(gap_at[0]) if gap_at else None, "gap_to_s": rel(gap_at[1]) if gap_at else None,
           "gap_cut_s": gap_cut, "gap_restore_s": gap_rec,
           "windows": {k: [rel(a), rel(b)] for k, (a, b) in win.items()}}
    if place:
        out["placement"] = legs(*place)
    if t0 is not None:
        out["during"] = legs(t0 + 5, (restore if restore is not None else t0 + 30))
    if guest is not None:
        g = guest
        # compare only what both saw: sequence numbers whose request left at least a second
        # before the last one (the last ones may be in flight when ping stops)
        if req:
            last_t = max(t for t, _ in req.values())
            cmp = {s for s, (t, _) in req.items() if t <= last_t - 1.0}
        else:
            cmp = set()
        tx = g.get("transmitted") or 0
        glost = {s for s in range(1, tx + 1) if s not in g["replies"] or g["replies"][s][1] > late_ms}
        glost_cmp = glost & cmp
        clost_cmp = set(lost) & cmp
        out["guest"] = {"transmitted": g.get("transmitted"), "received": g.get("received"), "dups": g.get("dups"),
                        "lost": len(glost), "no_answer_lines": len(g.get("no_answer") or ())}
        out["witness_agree"] = glost_cmp == clost_cmp
        if glost_cmp != clost_cmp:
            out["witness_diff"] = {"guest_only": sorted(glost_cmp - clost_cmp), "capture_only": sorted(clost_cmp - glost_cmp)}
    return out


def text(p: dict, label: str = "") -> str:
    """The report lines for one probe."""
    L = [f"{label or 'ping id ' + str(p['id'])}: sent {p['sent']}, answered {p['answered']}, round trips lost {p['lost']}"
         + (f" ({p['late']} of them late replies, over a second)" if p["late"] else "")]
    if p["lost"]:
        for k, name in (("lost_at_cut", "at the cut"), ("lost_at_restore", "at the restore")):
            if p.get(k):
                L.append(f"  {p[k]} lost {name}")
        for k, v in sorted((p.get("lost_by_window") or {}).items()):
            if k not in ("cut", "restore", "elsewhere") and v:
                L.append(f"  {v} lost in the {k} window")
        if p.get("lost_elsewhere"):
            L.append(f"  {p['lost_elsewhere']} lost elsewhere")
        L.append(f"  first lost sent at {p['first_lost_s']:+.2f} s, last at {p['last_lost_s']:+.2f} s (host clock, relative to the cut)"
                 if p.get("first_lost_s") is not None else "")
    else:
        L.append("  no round trip lost")
    if p.get("gap_s"):
        L.append(f"  longest stretch with no reply arriving: {p['gap_s']:.2f} s, from {p['gap_from_s']:+.2f} s to {p['gap_to_s']:+.2f} s")
    if p.get("dup"):
        L.append(f"  {p['dup']} duplicate replies")
    g = p.get("guest")
    if g:
        L.append(f"  the guest's ping: {g['transmitted']} transmitted, {g['received']} received"
                 + ("; the two witnesses agree on every round trip both saw" if p.get("witness_agree")
                    else f"; DISAGREE: lost only per the guest {p['witness_diff']['guest_only']}, only per the captures {p['witness_diff']['capture_only']}"))
    return "\n".join(x for x in L if x)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="analyze_ping")
    ap.add_argument("--decode", nargs="+", required=True, help="NIC=FILE decodes of the source's ports (and --dst-decode for the far end)")
    ap.add_argument("--dst-decode", nargs="*", default=[])
    ap.add_argument("--src", required=True)
    ap.add_argument("--dst", required=True)
    ap.add_argument("--id", type=int, required=True)
    ap.add_argument("--t0", type=float)
    ap.add_argument("--restore", type=float)
    ap.add_argument("--guest-log")
    ap.add_argument("--late-ms", type=float, default=1000.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    def read(specs):
        out = []
        for s in specs:
            nic, _, f = s.rpartition("=")
            out += frames(Path(f).read_text(encoding="utf-8", errors="replace"), nic or Path(f).stem)
        return out

    g = guest_log(Path(a.guest_log).read_text(encoding="utf-8", errors="replace")) if a.guest_log else None
    p = probe(read(a.decode), read(a.dst_decode), a.src, a.dst, a.id, a.t0, a.restore, g, a.late_ms)
    print(json.dumps(p, indent=2, sort_keys=True) if a.json else text(p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
