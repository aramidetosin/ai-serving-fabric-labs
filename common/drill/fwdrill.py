#!/usr/bin/env python3
"""fwdrill.py: chapter 4's firewall drills, the Python half (common/drill/lib-fwdrill.sh).

    fwdrill.py env       --plan gen/drills.json --id ID            shell assignments for one drill
    fwdrill.py newlog    --before FILE --after FILE --src A --dst B --dport N
                                                                    traffic log entries in AFTER only
    fwdrill.py analyze   --plan gen/drills.json --dir DIR --drill ID --pass N
    fwdrill.py summarize --set DIR [--stamp TEXT]                   DRILLS.md

analyze reads one pass of one drill from its directory (the files lib-fwdrill.sh saved), writes
analysis.json and analysis.txt there and prints the result vocabulary, appending each line to
$SFAB_VERDICT.

  land        the counter's name in the firewall's own counter table (else nothing here relies on
              it, and the line says so); with the rule in place the node's requests answered and
              the counter unmoved; without it none answered, the counter risen, and every drop
              counter that moved listed; the packet-diag captures (each stage's frames from the
              probe's source to its destination); the host-side captures (the requests arriving on
              the bundle, no reply, nothing on the uplink); with the rule back, the rulebase in the
              render's order, the requests answered and the counter unmoved
  ntp-uplink  the first traffic log entry, new since the route moved, from the new source to the
              NTP server: its rule (the drill's expect_rule), action and zones as logged; the same
              for each service that moved with it (DNS, after a name looked up through the
              firewall); the host-side captures (frames from the new source on the bundle and on
              the uplink); after the routes went back, an entry from the rendered source allowed by
              the rule the render admits it with, for NTP and for each service with it

Every count is what the saved files hold; a file the shell could not fill is a FAIL that names it.
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import evfile  # noqa: E402
import panos_parse as PP  # noqa: E402
import vocab  # noqa: E402

RULE_WIDTH = 19
DENY = ("deny", "drop", "reset-both", "reset-client", "reset-server")


def load(p):
    """A JSON file, stored plain or compressed (NAME.gz, evfile.py)."""
    return json.loads(evfile.read_text(p, "strict"))


def q(v) -> str:
    return shlex.quote("" if v is None else str(v))


def drill_of(plan: dict, did: str) -> dict:
    d = next((x for x in plan.get("list") or [] if x.get("id") == did), None)
    if d is None:
        raise SystemExit(f"fwdrill: no drill {did}")
    return d


def cmd_env(a) -> int:
    plan = load(a.plan)
    d = drill_of(plan, a.id)
    t = plan.get("timing") or {}
    out = {"KIND": d.get("kind"), "TITLE": d.get("title"), "FWN": d.get("fw"),
           "SETTLE_S": t.get("settle_s", 5), "NTP_WAIT_S": t.get("ntp_wait_s", 300), "LOG_PAUSE_S": t.get("log_pause_s", 10),
           "CAP_ETHS": " ".join((d.get("capture") or {}).get("eths") or []), "CAP_FILTER": (d.get("capture") or {}).get("filter")}
    if d.get("kind") == "fw_nat_removed":
        n, pr = d["nat"], (plan.get("probes") or {}).get(d["probe"]) or {}
        out.update({"RULE": n["rule"], "XPATH": n["xpath"], "RULES_XPATH": n["rules_xpath"], "ELEMENT": n["element"],
                    "WHERE": n["place"]["where"], "DST": n["place"].get("dst") or "", "COUNTER": d["counter"],
                    "PSRC": pr.get("src"), "PSRC_KIND": pr.get("src_kind"), "PSRC_ADDR": pr.get("src_addr"), "PDST": pr.get("dst_addr"),
                    "PCOUNT": pr.get("count", 5), "PIV": pr.get("interval_s", 0.5), "PTO": pr.get("timeout_s", 1),
                    "DIAG_SRC": d["diag"]["source"], "DIAG_DST": d["diag"]["destination"], "STAGES": " ".join(d["diag"]["stages"])})
    else:
        out.update({"SVC": d["service"], "XPATH": d["xpath"], "ELEMENT": d["element"], "RESTORE_ELEMENT": d["restore_element"],
                    "SERVER": d["server"], "PORT": d["port"], "NEW_IF": d["to"]["interface"], "NEW_SRC": d["to"]["address"],
                    "OLD_IF": d["from"]["interface"], "OLD_SRC": d["from"]["address"], "EXPECT_RULE": d["expect_rule"],
                    "RESTORE_RULE": d["restore_rule"], "DOMAIN": d.get("domain") or "", "WITH_N": len(d.get("with") or [])})
        for i, w in enumerate(d.get("with") or [], 1):
            out.update({f"WITH_{i}_SVC": w["service"], f"WITH_{i}_PORT": w["port"], f"WITH_{i}_XPATH": w["xpath"],
                        f"WITH_{i}_ELEMENT": w["element"], f"WITH_{i}_RESTORE": w["restore_element"],
                        f"WITH_{i}_RULE": w["restore_rule"]})
    for k, v in out.items():
        print(f"D_{k.upper()}={q(v)}")
    return 0


def cmd_newlog(a) -> int:
    before = {PP.tlog_key(e) for e in PP.tlog(PP.read(a.before))}
    new = [e for e in PP.tlog_find(PP.read(a.after), src=a.src, dst=a.dst, dport=a.dport) if PP.tlog_key(e) not in before]
    print(json.dumps(new, sort_keys=True))
    return 0 if new else 1


# --------------------------------------------------------------------------------------------
# the analysis

# a frame's addresses (with -v they open the line after the IP header; _joined puts them back on one)
FRAME = re.compile(r"(?:^|[\s)])(\d+\.\d+\.\d+\.\d+)(?:\.\d+)? > (\d+\.\d+\.\d+\.\d+)(?:\.\d+)?: (.*)$")


def frames(text: str) -> list:
    """Every frame of a tcpdump decode as {src, dst, what, vlan, line}."""
    out = []
    for i, line in enumerate((text or "").splitlines(), 1):
        m = FRAME.search(line)
        if not m:
            continue
        v = re.search(r"\bvlan (\d+), p \d+", line)
        out.append({"src": m.group(1), "dst": m.group(2), "what": m.group(3), "vlan": int(v.group(1)) if v else None, "line": i})
    return out


def _joined(text: str) -> str:
    """tcpdump -v prints the IP header on the frame's line and the addresses on the next: join them."""
    out, cur = [], ""
    for line in (text or "").splitlines():
        if line[:1] in (" ", "\t") and cur:
            cur += " " + line.strip()
        else:
            if cur:
                out.append(cur)
            cur = line
    if cur:
        out.append(cur)
    return "\n".join(out)


def _counters(d: Path, tag: str) -> dict:
    return PP.counters(PP.read(d / f"counters-{tag}.txt"), PP.read(d / f"counters-{tag}.xml"))


def analyze_land(v, plan: dict, dr: dict, d: Path, pas: int) -> dict:
    name = dr["counter"]
    pr = (plan.get("probes") or {}).get(dr["probe"]) or {}
    who = f"{pr.get('src')} ({pr.get('src_addr')})"
    pub = pr.get("dst_addr")
    pre = f"pass {pas} {dr['id']}"
    a = {"drill": dr["id"], "pass": pas, "title": dr["title"], "counter": name, "problems": []}
    c = {t: _counters(d, t) for t in ("base0", "base1", "before", "after", "restored0", "restored1")}
    seen = any(name in c[t] for t in c)
    a["counter_seen"] = seen
    v.check(f"{pre}: {name} is in this firewall's own show counter global table ({len(c['before'])} counters read)", seen,
            f"not among the {len(c['before'])} counters read: every figure below that names it is unproven")
    probes = {t: PP.ping(PP.read(d / f"ping-{t}.txt")) for t in ("baseline", "broken", "restored")}
    a["pings"] = probes
    deltas = {t: PP.delta(c[x], c[y], name).get(name) for t, (x, y) in
              (("baseline", ("base0", "base1")), ("broken", ("before", "after")), ("restored", ("restored0", "restored1")))}
    a["deltas"] = deltas
    moved = {k: x for k, x in PP.delta(c["before"], c["after"]).items() if (c["after"].get(k) or c["before"].get(k) or {}).get("severity") == "drop"}
    a["drops_moved"] = moved
    pb, pk, pr2 = probes["baseline"], probes["broken"], probes["restored"]
    v.check(f"{pre}: with {dr['nat']['rule']} in place, {who} reaches {pub}: {pb['received']} of {pb['sent']} answered",
            bool(pb["sent"]) and pb["received"] == pb["sent"], "no ping statistics" if pb["sent"] is None else "")
    if seen:
        v.check(f"{pre}: ... and {name} did not rise", deltas["baseline"] == 0, f"rose by {deltas['baseline']}")
    v.check(f"{pre}: without it, {pk['received']} of {pk['sent']} answered: the firewall discards every request", pk["sent"] and pk["received"] == 0,
            "no ping statistics" if pk["sent"] is None else f"{pk['received']} answered")
    if seen:
        v.check(f"{pre}: ... and {name} rose by {deltas['broken']} while {pk['sent']} requests were sent", (deltas["broken"] or 0) > 0,
                "it did not rise")
    v.ok(f"{pre}: drop counters that moved during it: " + (", ".join(f"{k} +{x}" for k, x in sorted(moved.items())) or "none")
         + " (recorded; not judged)")
    # the delta view read right after the probe (its baseline read right before it)
    dv = PP.counters_cli(PP.read(d / "drop-delta-after.txt"))
    a["delta_view"] = {k: x.get("value") for k, x in dv.items()}
    if seen:
        got = (dv.get(name) or {}).get("value")
        v.check(f"{pre}: show counter global filter delta yes severity drop, read after the probe, lists {name} +{got if got is not None else '?'}"
                " (drop-delta-after.txt)", bool(got), f"not in the delta view ({', '.join(sorted(dv)) or 'no counter listed'})")
    diag = {}
    for st in dr["diag"]["stages"]:
        fr = [f for f in frames(_joined(PP.read(d / "diag" / f"{st}.decode.txt")))
              if f["src"] == dr["diag"]["source"] and f["dst"] == dr["diag"]["destination"]]
        diag[st] = len(fr)
        if st == "drop":
            v.check(f"{pre}: the drop stage captured {len(fr)} frame(s) from {dr['diag']['source']} to {dr['diag']['destination']} "
                    "(diag/drop.decode.txt)", len(fr) > 0, "none: see diag/drop.view.txt for what the firewall printed")
        else:
            v.ok(f"{pre}: the {st} stage captured {len(fr)} frame(s) from {dr['diag']['source']} to {dr['diag']['destination']} (recorded)")
    a["diag"] = diag
    host = {}
    for eth in (dr.get("capture") or {}).get("eths") or []:
        fr = frames(_joined(PP.read(d / "captures" / f"{eth}.txt")))
        host[eth] = {"requests": sum(1 for f in fr if f["src"] == pr.get("src_addr") and f["dst"] == pub and "echo request" in f["what"]),
                     "replies": sum(1 for f in fr if f["src"] == pub and f["dst"] == pr.get("src_addr") and "echo reply" in f["what"]),
                     "frames": len(fr)}
    a["host"] = host
    req = sum(x["requests"] for x in host.values())
    rep = sum(x["replies"] for x in host.values())
    legs = ", ".join(f"{e} {x['requests']}" for e, x in host.items() if x["requests"])
    v.check(f"{pre}: the host-side captures saw {req} requests arrive at the firewall ({legs or 'none'}) and {rep} replies leave it",
            req > 0 and rep == 0, f"{req} requests, {rep} replies")
    pub_eth = (dr.get("capture") or {}).get("eths", [])[-1:]
    if pub_eth:
        x = host.get(pub_eth[0]) or {}
        v.check(f"{pre}: nothing of it left on the uplink ({pub_eth[0]}: {x.get('frames', 0)} frames)", x.get("frames", 0) == 0,
                f"{x.get('frames')} frames")
    order = PP.read(d / "order-after.txt")
    v.check(f"{pre}: {dr['nat']['rule']} back where the render puts it ({dr['nat']['place']['where']} {dr['nat']['place'].get('dst') or ''}): "
            "the running rulebase in the render's order", "differs" not in order and "nat " in order and order.strip() != "",
            (order.strip().splitlines() or ["no order read"])[-1][:120])
    v.check(f"{pre}: with it back, {pr2['received']} of {pr2['sent']} answered", bool(pr2["sent"]) and pr2["received"] == pr2["sent"],
            "no ping statistics" if pr2["sent"] is None else "")
    if seen:
        v.check(f"{pre}: ... and {name} did not rise", deltas["restored"] == 0, f"rose by {deltas['restored']}")
    return a


def analyze_ntp(v, plan: dict, dr: dict, d: Path, pas: int) -> dict:
    pre = f"pass {pas} {dr['id']}"
    a = {"drill": dr["id"], "pass": pas, "title": dr["title"], "problems": []}
    try:
        new = json.loads(PP.read(d / "new-entries.json") or "[]")
    except ValueError:
        new = []
    e = new[0] if new else None
    a["entry"] = e
    v.check(f"{pre}: the firewall's own NTP from {dr['to']['address']} ({dr['to']['interface']}) to {dr['server']}:{dr['port']} "
            f"logged under {dr['expect_rule']}, {e['action'] if e else '?'}, zone {e['from'] if e else '?'} to zone {e['to'] if e else '?'}",
            bool(e) and e["rule"] == dr["expect_rule"][:RULE_WIDTH] and e["action"] in DENY,
            "no new entry from that source within the wait" if not e else f"rule {e['rule']}, {e['action']}")
    host = {}
    for eth in (dr.get("capture") or {}).get("eths") or []:
        fr = [f for f in frames(_joined(PP.read(d / "captures" / f"{eth}.txt"))) if f["src"] == dr["to"]["address"]]
        host[eth] = len(fr)
    a["host"] = host
    eths = (dr.get("capture") or {}).get("eths") or []
    inside = sum(host.get(x, 0) for x in eths[:-1])
    # each service that moved with it (the DNS route, whose server is the same address): a lookup
    # through the firewall made at once, logged from the new source, and allowed again after
    a["with"] = []
    for w in dr.get("with") or []:
        x = w["service"]
        try:
            nw = json.loads(PP.read(d / f"{x}-new-entries.json") or "[]")
        except ValueError:
            nw = []
        try:
            bk = json.loads(PP.read(d / f"{x}-restored-entries.json") or "[]")
        except ValueError:
            bk = []
        e2, b2 = (nw[0] if nw else None), (bk[0] if bk else None)
        a["with"].append({"service": x, "entry": e2, "restored_entry": b2})
        v.check(f"{pre}: the firewall's own {x.upper()} from {dr['to']['address']} to {w['server']}:{w['port']} (a name looked up "
                f"through it) logged under {dr['expect_rule']}, {e2['action'] if e2 else '?'}, zone {e2['from'] if e2 else '?'} to zone "
                f"{e2['to'] if e2 else '?'}",
                bool(e2) and e2["rule"] == dr["expect_rule"][:RULE_WIDTH] and e2["action"] in DENY,
                "no new entry from that source after the lookup" if not e2 else f"rule {e2['rule']}, {e2['action']}")
        v.check(f"{pre}: with the route back, the firewall's {x.upper()} from {dr['from']['address']} allowed again by {w['restore_rule']}",
                bool(b2) and b2["rule"] == w["restore_rule"][:RULE_WIDTH] and b2["action"] == "allow",
                "no new allowed entry from that source after the lookup" if not b2 else f"rule {b2['rule']}, {b2['action']}")
    what = "/".join(["NTP"] + [w["service"].upper() for w in dr.get("with") or []])
    v.check(f"{pre}: no {what} frame from {dr['to']['address']} reached the server's side (the bundle: {inside} frames)", inside == 0,
            f"{inside} frames")
    if eths:
        v.ok(f"{pre}: {what} frames from {dr['to']['address']} on the uplink ({eths[-1]}): {host.get(eths[-1], 0)} (recorded; not judged)")
    try:
        back = json.loads(PP.read(d / "restored-entries.json") or "[]")
    except ValueError:
        back = []
    b = back[0] if back else None
    a["restored_entry"] = b
    v.check(f"{pre}: with the route back, the firewall's NTP from {dr['from']['address']} allowed again by {dr['restore_rule']}",
            bool(b) and b["rule"] == dr["restore_rule"][:RULE_WIDTH] and b["action"] == "allow",
            "no new allowed entry from that source within the wait" if not b else f"rule {b['rule']}, {b['action']}")
    rb = PP.read(d / "route-after.xml")
    v.check(f"{pre}: the {dr['service']} service route reads {dr['from']['interface']} again", dr["from"]["interface"] in rb,
            "the running configuration does not show it")
    for w in dr.get("with") or []:
        rw = PP.read(d / f"route-after-{w['service']}.xml")
        v.check(f"{pre}: the {w['service']} service route reads {dr['from']['interface']} again", dr["from"]["interface"] in rw,
                "the running configuration does not show it")
    return a


class _Tee:
    """stdout, and the lines kept for analysis.txt."""

    def __init__(self):
        self.lines = []

    def write(self, s):
        sys.stdout.write(s)
        self.lines.append(s)

    def flush(self):
        sys.stdout.flush()


def cmd_analyze(a) -> int:
    plan = load(a.plan)
    dr = drill_of(plan, a.drill)
    d = Path(a.dir)
    tee = _Tee()
    v = vocab.Vocab(known=None, out=tee)
    before = v.counts()["fail"]
    res = analyze_land(v, plan, dr, d, a.pass_) if dr["kind"] == "fw_nat_removed" else analyze_ntp(v, plan, dr, d, a.pass_)
    res["fails"] = v.counts()["fail"] - before
    (d / "analysis.json").write_text(json.dumps(res, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (d / "analysis.txt").write_text("".join(tee.lines), encoding="utf-8")
    return 1 if res["fails"] else 0


# --------------------------------------------------------------------------------------------
# DRILLS.md


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
    passes = sorted(int(p.name[4:]) for p in rs.glob("pass*") if p.name[4:].isdigit())
    repo = run.get("labs_repo") or {}
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    L = ["# Firewall drills", "",
         f"- Lab: `{run.get('lab')}`; labs repo commit `{repo.get('commit') or 'none'}`{uncommitted}; "
         f"UTC {run.get('utc_start') or 'unknown'}; host tick {run.get('host_tick')}; passes: {len(passes)}"]
    if a.stamp:
        L.append(f"- {a.stamp}")
    L.append("")
    for dr in plan.get("list") or []:
        rows = {}
        for p in passes:
            try:
                rows[p] = load(rs / f"pass{p}" / dr["id"] / "analysis.json")
            except (OSError, ValueError):
                pass
        L += [f"## {dr['id']}: {dr['title']}", ""]
        if dr.get("kind") == "fw_nat_removed":
            n = dr["counter"]
            L += [f"| Pass | {n} in the table | Answered, rule in place | {n} rise | Answered, rule removed | {n} rise | "
                  "Drop-stage frames | Answered, rule back | {n} rise |".replace("{n}", n), "|" + "---|" * 9]
            for p, r in sorted(rows.items()):
                pg, dl = r.get("pings") or {}, r.get("deltas") or {}
                f = lambda t: f"{(pg.get(t) or {}).get('received')} of {(pg.get(t) or {}).get('sent')}"  # noqa: E731
                L.append(f"| {p} | {'yes' if r.get('counter_seen') else 'no'} | {f('baseline')} | {dl.get('baseline')} | {f('broken')} | "
                         f"{dl.get('broken')} | {(r.get('diag') or {}).get('drop')} | {f('restored')} | {dl.get('restored')} |")
            L.append("")
            for p, r in sorted(rows.items()):
                mv = r.get("drops_moved") or {}
                L.append(f"- pass {p}, drop counters that moved with the rule removed: "
                         + (", ".join(f"`{k}` +{x}" for k, x in sorted(mv.items())) or "none"))
        else:
            L += ["| Pass | Service | Logged rule | Action | From zone | To zone | Frames on the bundle | Restored: rule |", "|" + "---|" * 8]
            for p, r in sorted(rows.items()):
                eths = (dr.get("capture") or {}).get("eths") or []
                inside = sum((r.get("host") or {}).get(x, 0) for x in eths[:-1])
                for svc, e, b in [("ntp", r.get("entry") or {}, r.get("restored_entry") or {})] + [
                        (w.get("service"), w.get("entry") or {}, w.get("restored_entry") or {}) for w in r.get("with") or []]:
                    L.append(f"| {p} | {svc} | {e.get('rule', '-')} | {e.get('action', '-')} | {e.get('from', '-')} | {e.get('to', '-')} | "
                             f"{inside} | {b.get('rule', '-')} |")
        L.append("")
    verdict = PP.read(rs / "verdict.txt")
    L += ["## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", ""]
    counts = vocab.counts_of(str(rs / "verdict.txt"))
    L += [vocab.result_line(counts), ""]
    (rs / "DRILLS.md").write_text("\n".join(L), encoding="utf-8")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="fwdrill")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("env")
    s.add_argument("--plan", required=True)
    s.add_argument("--id", required=True)
    s = sub.add_parser("newlog")
    s.add_argument("--before", required=True)
    s.add_argument("--after", required=True)
    s.add_argument("--src")
    s.add_argument("--dst")
    s.add_argument("--dport")
    s = sub.add_parser("analyze")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--drill", required=True)
    s.add_argument("--pass", dest="pass_", type=int, required=True)
    s = sub.add_parser("summarize")
    s.add_argument("--set", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"env": cmd_env, "newlog": cmd_newlog, "analyze": cmd_analyze, "summarize": cmd_summarize}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
