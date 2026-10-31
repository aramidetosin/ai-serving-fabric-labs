#!/usr/bin/env python3
"""drill.py: the Python half of the drill harness (common/drill/lib-drill.sh; FRAMEWORK.md 4.6).

    drill.py get     --plan gen/drills.json PATH           a value of the plan (lists space-joined)
    drill.py ids     --plan P --attempt N                  the ICMP ids of placement try N
    drill.py place   --plan P --drill ID --dir D --end EPOCH --target SW --attempt N [--ids "..."]
    drill.py bonds   --plan P --dir DIR                    every bond on its legs under the system MAC
    drill.py legs                                          (stdin: a bonding file) the active legs
    drill.py ipstats                                       (stdin: ip -s -j link) rx and tx per link
    drill.py events  --plan P --monitor FILE --t0 EPOCH --standby SW --active SW
    drill.py analyze --plan P --dir D --drill ID --pass N
    drill.py split   --dir D                               (stdin: the guest's ping logs, one after another)

place reads the decodes under D/captures/place/ (the captures so far) for the last place_s seconds
before END and says whether the drill's probes sit where it needs them (the plan's place:): target,
at least one probe instance whose round trip crosses the target switch and at least one that does
not; both, instances leaving the source on both of its legs. It writes D/placement-N.json and
prints the per-probe legs; exit 0 placed, 1 not placed, 2 nothing to read.

analyze builds D/analysis.json and D/analysis.txt from what lib-drill.sh saved in D: timeline.txt
(host epoch, event), the decodes under captures/, the probe logs under logs/, the counter samples
under counters/ and, for a reboot, monitor.log. Every time in it is the lab host's clock; every
duration is relative to the cut (T0). Loss is counted in round trips. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "audit"))
import analyze_ping as AP  # noqa: E402
import evfile  # noqa: E402
import judge  # noqa: E402


def load(p):
    """A JSON file, stored plain or compressed (NAME.gz, evfile.py)."""
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def drill_of(plan: dict, did: str) -> dict:
    d = next((x for x in plan.get("list") or [] if x["id"] == did), None)
    if d is None:
        raise SystemExit(f"drill: no drill {did} in the plan")
    return d


def ids_of(plan: dict, attempt: int) -> list:
    p = plan["probes"]["ping"]
    base = int(p["id_base"]) + (int(attempt) - 1) * int(p["count"]) * 2
    return [base + i for i in range(int(p["count"]))]


def nic_switch(plan: dict) -> dict:
    """'k8s-gpu1:eth1' -> 'fe-sw1', for every captured port."""
    out = {}
    for k in ("ping", "tcp"):
        for c in (plan.get("probes") or {}).get(k, {}).get("capture") or []:
            out[f"{c['node']}:{c['eth']}"] = c["switch"]
    return out


def capture_name(probe: str, node: str, eth: str) -> str:
    return f"{probe}-{node}-{eth}"


def decodes(d: Path, probe: str, plan: dict, sub: str = "") -> tuple:
    """The frames of a probe's captures: (source-side frames, far-side frames)."""
    src_f, dst_f = [], []
    p = plan["probes"][probe]
    base = d / "captures" / sub if sub else d / "captures"
    for c in p.get("capture") or []:
        name = capture_name(probe, c["node"], c["eth"])
        fr = AP.frames(read(base / f"{name}.txt"), f"{c['node']}:{c['eth']}")
        if probe == "ping" and c["node"] == p["dst"]:
            dst_f += fr
        else:
            src_f += fr
    return src_f, dst_f


def timeline(d: Path) -> dict:
    ev = {}
    for line in read(d / "timeline.txt").splitlines():
        f = line.split(None, 2)
        if len(f) >= 2:
            try:
                t = float(f[0])
            except ValueError:
                continue
            ev.setdefault(f[1], []).append((t, f[2] if len(f) > 2 else ""))
    return ev


def first(ev: dict, key: str):
    v = ev.get(key)
    return v[0][0] if v else None


def last_detail(ev: dict, key: str):
    v = ev.get(key)
    return v[-1][1] if v else ""


# --------------------------------------------------------------------------------------------
# placement


def ping_legs(plan, src_f, dst_f, ids, a, b) -> dict:
    p = plan["probes"]["ping"]
    sw = nic_switch(plan)
    out = {}
    for i in ids:
        r = AP.probe(src_f, dst_f, p["src_addr"], p["dst_addr"], i, place=(a, b))
        lg = r.get("placement") or {}
        via = sorted({sw.get(lg.get("req_out")), sw.get(lg.get("rep_in"))} - {None})
        out[str(i)] = {"legs": lg, "via": via, "req_switch": sw.get(lg.get("req_out")), "rep_switch": sw.get(lg.get("rep_in")),
                       "frames": r["sent"]}
    return out


def tcp_attempts(plan, frames_, a=None, b=None) -> dict:
    """Per client port, from the firewall's bundle legs: the leg its first SYN left on and the leg
    its first SYN-ACK came back on, and when."""
    p = plan["probes"]["tcp"]
    sw = nic_switch(plan)
    out = {}
    for f in sorted(frames_, key=lambda x: x["t"]):
        if f.get("proto") != "tcp":
            continue
        if f["src"] == p["client_addr"] and f["dst"] == p["dst_addr"] and f["dport"] == p["port"] and f["flags"] == "S":
            if a is not None and not (a <= f["t"] < b):
                continue
            e = out.setdefault(f["sport"], {"t": f["t"], "syn_nic": f["nic"], "syn_switch": sw.get(f["nic"]), "synack_nic": None,
                                            "synack_switch": None, "syns": 0})
            e["syns"] += 1
        elif f["src"] == p["dst_addr"] and f["dst"] == p["client_addr"] and f["sport"] == p["port"] and f["flags"] == "S.":
            e = out.get(f["dport"])
            if e is not None and e["synack_nic"] is None:
                e["synack_nic"], e["synack_switch"] = f["nic"], sw.get(f["nic"])
    return out


def judge_place(plan: dict, drill: dict, target: str, ping: dict, tcp: dict) -> tuple:
    """(placed, reasons): the drill's place: requirements against what the captures show."""
    members = (plan.get("pair") or {}).get("members") or []
    ok, why = True, []
    for probe, want in sorted((drill.get("place") or {}).items()):
        if probe == "ping":
            if want == "target":
                on = [i for i, r in ping.items() if target in r["via"]]
                off = [i for i, r in ping.items() if r["via"] and target not in r["via"]]
                good = bool(on) and bool(off)
                why.append(f"ping: {len(on)} of {len(ping)} ids cross {target}, {len(off)} do not" + ("" if good else " (want at least one of each)"))
            else:
                seen = {r["req_switch"] for r in ping.values()} - {None}
                good = all(m in seen for m in members)
                why.append(f"ping: requests leave {', '.join(sorted(seen)) or 'nowhere'}" + ("" if good else f" (want both of {', '.join(members)})"))
        else:
            legs = Counter(r["syn_switch"] for r in tcp.values() if r["syn_switch"])
            if want == "target":
                on, off = legs.get(target, 0), sum(v for k, v in legs.items() if k != target)
                good = on > 0 and off > 0
                why.append(f"tcp: {on} connects leave the firewall toward {target}, {off} toward the other switch" + ("" if good else " (want both)"))
            else:
                good = all(legs.get(m, 0) for m in members)
                why.append(f"tcp: connects per firewall leg {dict(sorted(legs.items()))}" + ("" if good else " (want both legs)"))
        ok = ok and good
    return ok, why


def cmd_place(a) -> int:
    plan = load(a.plan)
    drill = drill_of(plan, a.drill)
    d = Path(a.dir)
    end = float(a.end)
    start = end - float(plan["timing"]["place_s"])
    ping, tcp = {}, {}
    ids = [int(x) for x in (a.ids or "").split()] or ids_of(plan, a.attempt)
    if "ping" in drill["probes"]:
        s, t = decodes(d, "ping", plan, "place")
        ping = ping_legs(plan, s, t, ids, start, end)
    if "tcp" in drill["probes"]:
        s, _ = decodes(d, "tcp", plan, "place")
        tcp = tcp_attempts(plan, s, start, end)
    placed, why = judge_place(plan, drill, a.target, ping, tcp)
    rec = {"attempt": int(a.attempt), "window": [start, end], "target": a.target, "placed": placed, "why": why,
           "ping": ping, "tcp": {str(k): v for k, v in sorted(tcp.items())}}
    (d / f"placement-{a.attempt}.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    lines = [f"placement try {a.attempt}, the {plan['timing']['place_s']} s before {end:.3f} (host clock), target {a.target}: "
             + ("placed" if placed else "not placed")]
    for i, r in sorted(ping.items()):
        lg = r["legs"]
        lines.append(f"  ping id {i}: request {lg.get('req_out') or '-'} -> {lg.get('req_in') or '-'}, reply {lg.get('rep_out') or '-'} -> {lg.get('rep_in') or '-'}"
                     f"  (crosses {', '.join(r['via']) or 'nothing seen'}; {r['frames']} requests)")
    if tcp:
        c = Counter((r["syn_switch"], r["synack_switch"]) for r in tcp.values())
        for (s1, s2), n in sorted(c.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
            lines.append(f"  tcp: {n} connects, SYN to {s1 or '-'}, SYN-ACK from {s2 or '-'}")
    lines += [f"  {w}" for w in why]
    txt = "\n".join(lines) + "\n"
    with open(d / "placement.txt", "a", encoding="utf-8") as f:
        f.write(txt)
    sys.stdout.write(txt)
    if not ping and not tcp:
        return 2
    return 0 if placed else 1


# --------------------------------------------------------------------------------------------
# whole: every bond on its legs; the monitor's leg reads


def bond_problems(text: str, members: list, sysmac: str) -> list:
    b = judge.p_bond_legs(text)
    probs = []
    for m in members:
        leg = b["legs"].get(m)
        if leg is None:
            probs.append(f"{m} absent")
            continue
        if leg["agg"] != b["active_agg"]:
            probs.append(f"{m} outside the active aggregator")
        if leg["mii"] != "up":
            probs.append(f"{m} MII {leg['mii']}")
        if (leg["partner_mac"] or "").lower() != (sysmac or "").lower():
            probs.append(f"{m} partner {leg['partner_mac']}")
    return probs


def cmd_bonds(a) -> int:
    plan = load(a.plan)
    sysmac = (plan.get("pair") or {}).get("system_mac") or ""
    bad = 0
    for b in plan.get("bonded") or []:
        text = read(Path(a.dir) / f"{b['node']}.bonding.txt")
        probs = bond_problems(text, [m["eth"] for m in b["members"]], sysmac) if text.strip() else ["not read"]
        if probs:
            bad += 1
            print(f"{b['node']} {b['bond']}: " + "; ".join(probs))
    if not bad:
        print(f"every bond on its {', '.join(str(len(b['members'])) for b in plan.get('bonded') or [])} legs under {sysmac}")
    return 1 if bad else 0


def cmd_legs(a) -> int:
    b = judge.p_bond_legs(sys.stdin.read())
    up = [s for s, leg in sorted(b["legs"].items()) if leg["agg"] == b["active_agg"] and leg["mii"] == "up"]
    print(",".join(up) or "none")
    return 0


def cmd_ipstats(a) -> int:
    try:
        data = json.loads(sys.stdin.read() or "[]")
    except ValueError:
        data = []
    out = {}
    for link in data if isinstance(data, list) else []:
        st = link.get("stats64") or link.get("stats") or {}
        rx, tx = st.get("rx") or {}, st.get("tx") or {}
        if link.get("ifname"):
            out[link["ifname"]] = {"rx": rx.get("packets"), "tx": tx.get("packets")}
    print(json.dumps(out, sort_keys=True))
    return 0


def cmd_split(a) -> int:
    """The guest's ping logs, catted one after another with '==> PATH' headers, into D/logs/."""
    d = Path(a.dir) / "logs"
    d.mkdir(parents=True, exist_ok=True)
    cur, buf = None, []

    def flush():
        if cur:
            (d / cur).write_text("".join(buf), encoding="utf-8")

    for line in sys.stdin:
        m = re.match(r"^==> .*/(ping-\d+\.log)\s*$", line)
        if m:
            flush()
            cur, buf = m.group(1), []
            continue
        if cur:
            buf.append(line)
    flush()
    return 0


# --------------------------------------------------------------------------------------------
# the reboot monitor


def monitor_rows(text: str) -> list:
    """monitor.log lines: '<epoch> | bonds n=eth1,eth2 ... | <sw> mgmt=up <switch read> | ... | fw ae1=...'."""
    rows = []
    for line in (text or "").splitlines():
        parts = [p.strip() for p in line.split("|")]
        try:
            t = float(parts[0])
        except (ValueError, IndexError):
            continue
        r = {"t": t, "bonds": {}, "sw": {}, "fw": None}
        for p in parts[1:]:
            if p.startswith("bonds"):
                for kv in p.split()[1:]:
                    k, _, v = kv.partition("=")
                    r["bonds"][k] = [x for x in v.split(",") if x and x not in ("none", "?")] if v != "?" else None
            elif p.startswith("fw "):
                m = re.search(r"=(\S+)", p)
                v = m.group(1) if m else "?"
                r["fw"] = None if v == "?" else [x for x in v.split(",") if x and x != "none"]
            elif p:
                f = p.split(None, 1)
                name, rest = f[0], (f[1] if len(f) > 1 else "")
                s = {"mgmt": "up" if "mgmt=up" in rest else "down"}
                m = re.search(r"keepalive is:\s*(\S+)", rest)
                s["ka"] = m.group(1) if m else None
                m = re.search(r"Role:\s*(\S+)", rest)
                s["role"] = m.group(1).lower() if m else None
                s["pcs"] = {pc: (st, td) for pc, st, td in re.findall(r"(PortChannel\d+)=(\S*?)/td=(\S*)", rest)}
                r["sw"][name] = s
        rows.append(r)
    return rows


def events(plan: dict, rows: list, t0: float, standby: str, active: str) -> dict:
    """The standby's departure and its return, from the monitor's rows (host clock). Each event is
    the first row after the reboot command (T0) that shows it; an event that says something came
    back (the peer link, the keepalive, the firewall's legs, every bond's legs) is the first row
    showing it after a row showing it gone, and is absent when the monitor never saw it gone."""
    pair = plan.get("pair") or {}
    pl = (pair.get("peer_link") or {}).get(active, {}).get("portchannel") or "PortChannel1"
    ev = {}
    after = [r for r in rows if r["t"] >= t0]

    def bonds_n(r, n):
        vals = [v for v in r["bonds"].values() if v is not None]
        return bool(vals) and len(vals) == len(r["bonds"]) and all(len(v) == n for v in vals)

    def first(pred, rows_):
        return next((r["t"] for r in rows_ if pred(r)), None)

    def mark(key, pred, rows_=None):
        t = first(pred, after if rows_ is None else rows_)
        if t is not None:
            ev[key] = t
        return t

    def back(key, gone, here):
        """KEY: the first row after T0 where HERE holds, after a row where GONE held."""
        g = first(gone, after)
        if g is not None:
            mark(key, here, [r for r in after if r["t"] > g])

    sb = lambda r: r["sw"].get(standby) or {}  # noqa: E731
    ac = lambda r: r["sw"].get(active) or {}  # noqa: E731
    sb_pcs = lambda r: {pc: v for pc, v in (sb(r).get("pcs") or {}).items() if pc != pl}  # noqa: E731
    mark("standby_portchannels_down", lambda r: sb(r).get("mgmt") == "up" and any(
        st == "down" or td == "true" for st, td in sb_pcs(r).values()))
    one = mark("bonds_on_one_leg", lambda r: bonds_n(r, 1))
    mark("active_keepalive_not_ok", lambda r: ac(r).get("ka") not in (None, "OK"))
    down = mark("standby_mgmt_down", lambda r: sb(r).get("mgmt") == "down")
    if down is not None:
        mark("standby_mgmt_up", lambda r: sb(r).get("mgmt") == "up", [r for r in after if r["t"] > down])
    back("peer_link_up", lambda r: (ac(r).get("pcs") or {}).get(pl, ("", ""))[0] not in ("up", ""),
         lambda r: (ac(r).get("pcs") or {}).get(pl, ("", ""))[0] == "up")
    back("session_up", lambda r: ac(r).get("ka") not in (None, "OK"), lambda r: ac(r).get("ka") == "OK" and sb(r).get("ka") == "OK")
    back("standby_portchannels_up", lambda r: sb(r).get("mgmt") == "down" or any(st == "down" or td == "true" for st, td in sb_pcs(r).values()),
         lambda r: sb(r).get("mgmt") == "up" and bool(sb_pcs(r)) and all(st == "up" and td != "true" for st, td in sb_pcs(r).values()))
    back("fw_both_legs", lambda r: r["fw"] is not None and len(r["fw"]) < 2, lambda r: r["fw"] is not None and len(r["fw"]) >= 2)
    if one is not None:
        mark("bonds_on_two_legs", lambda r: bonds_n(r, 2), [r for r in after if r["t"] > max(one, down or one)])
    ev["return"] = ev.get("bonds_on_two_legs")
    return ev


EVENT_TEXT = [
    ("standby_portchannels_down", "the standby's own MCLAG PortChannels read down or traffic-disabled, the standby still answering"),
    ("bonds_on_one_leg", "every bond toward the pair on one leg"),
    ("active_keepalive_not_ok", "the active's iccpd no longer reports the keepalive OK"),
    ("standby_mgmt_down", "the standby's management address stops answering"),
    ("standby_mgmt_up", "the standby's management address answers again"),
    ("peer_link_up", "the peer link up on the active"),
    ("session_up", "the keepalive OK on both switches"),
    ("standby_portchannels_up", "every MCLAG PortChannel up on the standby"),
    ("fw_both_legs", "the firewall's ae1 on both legs"),
    ("bonds_on_two_legs", "every bond toward the pair back on two legs: the return"),
]


def cmd_events(a) -> int:
    plan = load(a.plan)
    ev = events(plan, monitor_rows(read(a.monitor)), float(a.t0), a.standby, a.active)
    print(json.dumps(ev, sort_keys=True))
    return 0 if ev.get("return") else 1


# --------------------------------------------------------------------------------------------
# analysis


def tcp_rows(text: str) -> list:
    rows = []
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) >= 3:
            try:
                rows.append({"t": float(f[0]), "seq": int(f[1]), "ok": f[2] == "1",
                             "lport": int(f[3]) if len(f) > 3 and f[3].isdigit() else None,
                             "ms": float(f[4]) if len(f) > 4 else None})
            except ValueError:
                continue
    return rows


def outages(rows: list, t0: float, legs: dict | None = None) -> list:
    """Runs of failed attempts: (last ok before, first failed, first ok after, count, the legs of
    the failed attempts' SYNs where the captures saw them)."""
    out, last_ok, run = [], None, []
    for r in rows:
        if r["ok"]:
            if run:
                out.append((last_ok, run, r["t"]))
                run = []
            last_ok = r["t"]
        else:
            run.append(r)
    if run:
        out.append((last_ok, run, None))
    res = []
    for lo, run, nxt in out:
        lg = Counter((legs or {}).get(x["lport"], {}).get("syn_switch") or "not seen" for x in run) if legs is not None else None
        res.append({"last_ok_s": round(lo - t0, 3) if lo else None, "first_failed_s": round(run[0]["t"] - t0, 3),
                    "first_ok_after_s": round(nxt - t0, 3) if nxt else None, "failed": len(run),
                    "gap_s": round(nxt - lo, 3) if (lo and nxt) else None, "syn_legs": dict(lg) if lg is not None else None})
    return res


def connect_probe(rows: list, t0, windows: dict, legs=None) -> dict:
    def where(t):
        for k, (a, b) in windows.items():
            if a <= t <= b:
                return k
        return "elsewhere"
    failed = [r for r in rows if not r["ok"]]
    byw = Counter(where(r["t"]) for r in failed)
    return {"attempts": len(rows), "failed": len(failed), "failed_at_cut": byw.get("cut", 0),
            "failed_at_restore": byw.get("restore", 0), "failed_elsewhere": byw.get("elsewhere", 0),
            "failed_by_window": dict(sorted(byw.items())), "outages": outages(rows, t0, legs)}


def counters(d: Path, plan: dict, sw_list: list) -> dict:
    """Peer-link packets per second on each switch, from the host-side veth samples, per window."""
    pl = (plan.get("pair") or {}).get("peer_link") or {}
    samples = {}
    for f in sorted((d / "counters").glob("*.json")) if (d / "counters").is_dir() else []:
        m = re.match(r"^(before|during|after)-(\d)-(.+)\.json$", f.name)
        if not m:
            continue
        try:
            rec = load(f)
        except (OSError, ValueError):
            continue
        samples.setdefault(m.group(1), {}).setdefault(m.group(3), {})[int(m.group(2))] = rec
    out = {}
    for ph, by_sw in samples.items():
        for sw in sw_list:
            s = by_sw.get(sw) or {}
            if 1 not in s or 2 not in s:
                continue
            dt = s[2]["t"] - s[1]["t"]
            if dt <= 0:
                continue
            eths = (pl.get(sw) or {}).get("eths") or []
            tx = sum((s[2]["links"].get(e, {}).get("tx") or 0) - (s[1]["links"].get(e, {}).get("tx") or 0) for e in eths)
            rx = sum((s[2]["links"].get(e, {}).get("rx") or 0) - (s[1]["links"].get(e, {}).get("rx") or 0) for e in eths)
            out.setdefault(ph, {})[sw] = {"tx_pps": round(tx / dt, 1), "rx_pps": round(rx / dt, 1), "tx": tx, "rx": rx,
                                          "seconds": round(dt, 2), "eths": eths}
    return out


def klish_counters(text: str) -> dict:
    rows = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*((?:Ethernet|PortChannel)\d+)\s+(\S+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)", line)
        if m:
            n = lambda x: int(x.replace(",", ""))  # noqa: E731
            rows[m.group(1)] = {"state": m.group(2), "rx_ok": n(m.group(3)), "tx_ok": n(m.group(7))}
    return rows


def analyze(plan: dict, d: Path, did: str, pas: int) -> dict:
    drill = drill_of(plan, did)
    t = plan["timing"]
    ev = timeline(d)
    t0, t1 = first(ev, "INJECT"), first(ev, "INJECTED")
    restore = first(ev, "RESTORE")
    target = last_detail(ev, "TARGET") or drill.get("switch")
    ids = [int(x) for x in last_detail(ev, "PING_IDS").split()] if ev.get("PING_IDS") else []
    out = {"drill": did, "pass": pas, "title": drill["title"], "kind": drill["kind"], "target": target, "t0": t0, "t1": t1,
           "restore": restore, "late_ms": t["late_ms"], "valid": True, "problems": []}
    pl = sorted(d.glob("placement-*.json"), key=lambda p: int(re.sub(r"\D", "", p.stem) or 0))
    out["placement"] = load(pl[-1]) if pl else None
    if not out["placement"] or not out["placement"].get("placed"):
        out["problems"].append("the probes were not placed as the drill needs before the cut")
    if t0 is None:
        out["valid"] = False
        out["problems"].append("no cut in the timeline")
        return out
    windows = {"cut": (t0 - 0.5, t0 + t["cut_window_s"])}
    if restore is not None:
        windows["restore"] = (restore - 0.5, restore + t["restore_window_s"])
    if drill["kind"] == "reboot":
        mon = monitor_rows(read(d / "monitor.log"))
        active = last_detail(ev, "ACTIVE")
        e = events(plan, mon, t0, target, active)
        out["events"] = {k: (round(v - t0, 2) if v is not None else None) for k, v in e.items()}
        out["events_utc"] = {k: v for k, v in e.items() if v is not None}
        dep_end = max(t0 + t["cut_window_s"], (e.get("bonds_on_one_leg") or t0) + 5)
        windows = {"cut": (t0 - 0.5, dep_end)}
        if e.get("return"):
            start = e.get("standby_mgmt_up") or e.get("standby_portchannels_up") or e["return"]
            windows["restore"] = (start - 5, e["return"] + 15)
            restore = e["return"]
            out["restore"] = restore
        else:
            out["problems"].append("the standby's return (every bond on two legs) is not in the monitor")
    elif drill.get("await_return"):
        # a shut the standby answers by shutting its own MCLAG ports (a keepalive cut): the monitor's
        # events, and the return the drill waited for (the RETURN line), both on the host's clock
        mon = monitor_rows(read(d / "monitor.log"))
        e = events(plan, mon, t0, last_detail(ev, "STANDBY"), last_detail(ev, "ACTIVE"))
        out["standby"] = last_detail(ev, "STANDBY")
        out["events"] = {k: (round(v - t0, 2) if v is not None else None) for k, v in e.items()}
        out["events_utc"] = {k: v for k, v in e.items() if v is not None}
        ret = first(ev, "RETURN")
        out["return_s"] = round(ret - t0, 2) if ret is not None else None
        if ret is None:
            out["problems"].append("the drill saw no return (the pair whole and every bond on its legs) after the restore")
        if e.get("standby_portchannels_down"):
            windows["standby"] = (e["standby_portchannels_down"] - 5, e["standby_portchannels_down"] + t["cut_window_s"])
        if e.get("standby_portchannels_up"):
            windows["return"] = (e["standby_portchannels_up"] - 5, e["standby_portchannels_up"] + t["restore_window_s"])
    out["windows"] = {k: [round(a - t0, 2), round(b - t0, 2)] for k, (a, b) in windows.items()}
    sw = nic_switch(plan)
    if "ping" in drill["probes"]:
        p = plan["probes"]["ping"]
        s, dfr = decodes(d, "ping", plan)
        place = tuple(out["placement"]["window"]) if out["placement"] else (t0 - t["place_s"], t0)
        per = {}
        for i in ids:
            g = AP.guest_log(read(d / "logs" / f"ping-{i}.log"))
            r = AP.probe(s, dfr, p["src_addr"], p["dst_addr"], i, t0, restore, g, t["late_ms"],
                         t["cut_window_s"], t["restore_window_s"], place=place, windows=windows)
            lg = r.get("placement") or {}
            r["via"] = sorted({sw.get(lg.get("req_out")), sw.get(lg.get("rep_in"))} - {None})
            r["on_target"] = target in r["via"]
            per[str(i)] = r
            if not r.get("witness_agree", True):
                out["problems"].append(f"ping id {i}: the guest's log and the host's captures disagree")
        on = [k for k, r in per.items() if r["on_target"]]
        off = [k for k, r in per.items() if not r["on_target"]]
        agg = lambda ks, f: [per[k][f] for k in ks]  # noqa: E731
        out["ping"] = {"ids": per, "on_target": on, "spared": off,
                       "lost_on_target": agg(on, "lost"), "lost_spared": agg(off, "lost"),
                       "lost_at_cut_on_target": agg(on, "lost_at_cut"), "lost_at_restore_on_target": agg(on, "lost_at_restore"),
                       "lost_at_cut_spared": agg(off, "lost_at_cut"), "lost_at_restore_spared": agg(off, "lost_at_restore"),
                       "gap_cut_on_target": agg(on, "gap_cut_s"), "late": sum(r["late"] for r in per.values()),
                       "dup": sum(r["dup"] for r in per.values())}
        if not per or not any(r["sent"] for r in per.values()):
            out["valid"] = False
            out["problems"].append("no ping request in the captures")
    if "tcp" in drill["probes"]:
        rows = tcp_rows(read(d / "logs" / "tcp.log"))
        s, _ = decodes(d, "tcp", plan)
        legs = tcp_attempts(plan, s)
        c = connect_probe(rows, t0, windows, legs)
        on_cut = [r for r in rows if windows["cut"][0] <= r["t"] <= windows["cut"][1]]
        c["at_cut_by_leg"] = dict(Counter((legs.get(r["lport"]) or {}).get("syn_switch") or "not seen" for r in on_cut))
        c["failed_by_leg"] = dict(Counter((legs.get(r["lport"]) or {}).get("syn_switch") or "not seen" for r in rows if not r["ok"]))
        out["tcp"] = c
        if not rows:
            out["valid"] = False
            out["problems"].append("no TCP connect in the client's log")
    if "orphan" in drill["probes"]:
        rows = tcp_rows(read(d / "logs" / "orphan.log"))
        out["orphan"] = connect_probe(rows, t0, windows)
        if not rows:
            out["problems"].append("no orphan connect in the bastion's log")
    if drill.get("peer_link_counters"):
        out["peer_link"] = counters(d, plan, (plan.get("pair") or {}).get("members") or [])
        kl = {}
        for f in sorted((d / "klish").glob("*-counters.txt")) if (d / "klish").is_dir() else []:
            m = re.match(r"^(before|during|after)-(.+)-counters\.txt$", f.name)
            if m:
                kl.setdefault(m.group(2), {})[m.group(1)] = klish_counters(read(f))
        out["peer_link_klish"] = kl
    out["valid"] = out["valid"] and bool(out["placement"] and out["placement"].get("placed"))
    return out


def report(a: dict) -> str:
    L = [f"drill {a['drill']}, pass {a['pass']}: {a['title']}", f"  target switch {a.get('target')}; every time on the lab host's clock, relative to the cut (T0)"]
    if a.get("t1") and a.get("t0"):
        L.append(f"  the fault's session took {a['t1'] - a['t0']:.2f} s (T0 is when it started)")
    if a.get("placement"):
        L.append(f"  placement: {'; '.join(a['placement'].get('why') or [])}")
    for p in a.get("problems") or []:
        L.append(f"  PROBLEM: {p}")
    if a.get("events") and a.get("kind") == "shut":
        L.append(f"  the standby ({a.get('standby')}) as the monitor saw it (reads every few seconds; each is an event, not a measured gap):")
        names = dict(EVENT_TEXT)
        for k, v in sorted(((k, v) for k, v in a["events"].items() if k in names and v is not None), key=lambda kv: kv[1]):
            L.append(f"    T0{v:+8.1f} s  {names[k]}")
        if a.get("return_s") is not None:
            L.append(f"    T0{a['return_s']:+8.1f} s  the drill's own polls: the pair whole and every bond on its legs again")
        for k, txt in EVENT_TEXT:
            if a["events"].get(k) is None and k not in ("standby_mgmt_down", "standby_mgmt_up"):
                L.append(f"    not seen: {txt}")
    elif a.get("events"):
        L.append("  the standby's departure and return (monitor reads every few seconds; the return is an event, not a redundancy gap):")
        names = dict(EVENT_TEXT)
        for k, v in sorted(((k, v) for k, v in a["events"].items() if k in names and v is not None), key=lambda kv: kv[1]):
            L.append(f"    T0{v:+8.1f} s  {names[k]}")
        for k, txt in EVENT_TEXT:
            if a["events"].get(k) is None:
                L.append(f"    not seen: {txt}")
    pg = a.get("ping")
    if pg:
        L.append(f"  ping {', '.join(pg['on_target'])} cross {a.get('target')}; {', '.join(pg['spared']) or 'none'} do not")
        for k, r in sorted(pg["ids"].items()):
            L.append("  " + AP.text(r, f"ping id {k} (via {', '.join(r['via']) or 'nothing seen'})").replace("\n", "\n  "))
    tc = a.get("tcp")
    if tc:
        extra = "".join(f", {v} in the {k} window" for k, v in sorted((tc.get("failed_by_window") or {}).items())
                        if k not in ("cut", "restore", "elsewhere") and v)
        L.append(f"  tcp connects to the users' VIP: {tc['attempts']} attempts, {tc['failed']} failed "
                 f"({tc['failed_at_cut']} at the cut, {tc['failed_at_restore']} at the restore{extra}, {tc['failed_elsewhere']} elsewhere)")
        L.append(f"    attempts in the cut window by the firewall leg their SYN took: {tc.get('at_cut_by_leg')}")
        for o in tc["outages"]:
            L.append(f"    failed run: last ok {o['last_ok_s']}, first failed {o['first_failed_s']:+.2f} s, first ok after {o['first_ok_after_s']}, "
                     f"{o['failed']} failed, SYN legs {o['syn_legs']}")
    oc = a.get("orphan")
    if oc:
        L.append(f"  orphan connects (the bastion to the single-attached storage management address): {oc['attempts']} attempts, {oc['failed']} failed "
                 f"({oc['failed_at_cut']} at the cut, {oc['failed_at_restore']} at the restore, {oc['failed_elsewhere']} elsewhere)")
        for o in oc["outages"]:
            L.append(f"    failed run: last ok {o['last_ok_s']}, first failed {o['first_failed_s']:+.2f} s, first ok after {o['first_ok_after_s']}, {o['failed']} failed")
    if a.get("peer_link"):
        L.append("  peer link, packets per second from the host-side counters of its member ports:")
        for ph in ("before", "during", "after"):
            for sw, r in sorted((a["peer_link"].get(ph) or {}).items()):
                L.append(f"    {ph:<6} {sw}: tx {r['tx_pps']} rx {r['rx_pps']} over {r['seconds']} s")
    return "\n".join(L) + "\n"


def cmd_analyze(a) -> int:
    plan = load(a.plan)
    d = Path(a.dir)
    res = analyze(plan, d, a.drill, int(a.pass_))
    (d / "analysis.json").write_text(json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    txt = report(res)
    (d / "analysis.txt").write_text(txt, encoding="utf-8")
    sys.stdout.write(txt)
    return 0 if res["valid"] else 1


def cmd_get(a) -> int:
    cur = load(a.plan)
    for part in a.path.split("."):
        if isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)]
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


def cmd_ids(a) -> int:
    print(" ".join(map(str, ids_of(load(a.plan), a.attempt))))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="drill")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("ids")
    s.add_argument("--plan", required=True)
    s.add_argument("--attempt", type=int, default=1)
    s = sub.add_parser("place")
    for k in ("--plan", "--drill", "--dir", "--end", "--target"):
        s.add_argument(k, required=True)
    s.add_argument("--attempt", type=int, default=1)
    s.add_argument("--ids", default="")
    s = sub.add_parser("bonds")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    sub.add_parser("legs")
    sub.add_parser("ipstats")
    s = sub.add_parser("split")
    s.add_argument("--dir", required=True)
    s = sub.add_parser("events")
    for k in ("--plan", "--monitor", "--t0", "--standby", "--active"):
        s.add_argument(k, required=True)
    s = sub.add_parser("analyze")
    for k in ("--plan", "--dir", "--drill"):
        s.add_argument(k, required=True)
    s.add_argument("--pass", dest="pass_", required=True)
    a = ap.parse_args(argv)
    return {"get": cmd_get, "ids": cmd_ids, "place": cmd_place, "bonds": cmd_bonds, "legs": cmd_legs, "ipstats": cmd_ipstats,
            "split": cmd_split, "events": cmd_events, "analyze": cmd_analyze}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
