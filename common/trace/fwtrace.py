#!/usr/bin/env python3
"""fwtrace.py: chapter 4's firewall trace, its plan and its judgment (common/trace/lib-fwtrace.sh).

    fwtrace.py session-env --plan gen/trace.json --id ID     shell assignments for one session
    fwtrace.py pull-env    --plan gen/trace.json             shell assignments for the pull
    fwtrace.py points      --plan gen/trace.json             the pull's capture points, one per line
    fwtrace.py session-id  --file FILE --src A --sport N     the session's id in show session all
    fwtrace.py judge       --set DIR --plan gen/trace.json --inv INV [--stamp TEXT]

The plan is gen/trace.json (sfab.render.trace). judge reads the saved files only and prints the
result vocabulary, appending each line to $SFAB_VERDICT, then writes TRACE.md:

  each session  the reply (status and echoed message, the connection held after it), the session
                as show session all lists it (found by the client's address and pinned source port:
                its zones, its destination before and after translation, state ACTIVE while held)
                and as show session id prints it (the security rule and the NAT rule), and the
                traffic log line PAN-OS wrote when the session ended (rule, action and zones);
  the pull      crictl's own result, the node's first SYN to the registry on an inside point, the
                same sequence number on the uplink with the source rewritten to the address of the
                source NAT rule's interface and the destination unchanged, the bytes the registry
                sent back on each side, and the traffic log's line for the pull.

Rule names in the CLI's traffic log are cut to 19 characters, and compared that way. The session
formats are the CLI's documented shapes, unproven until a deploy records them (ch04/README.md):
every field the judge could not read is named in its FAIL line. Standard library only.
"""

from __future__ import annotations

import argparse
import importlib.util
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

_spec = importlib.util.spec_from_file_location("trace_md", HERE / "trace-md.py")
TMD = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(TMD)

RULE_WIDTH = 19


def load(p):
    """A JSON file, stored plain or compressed (NAME.gz, evfile.py)."""
    return json.loads(evfile.read_text(p, "strict"))


def read(p: Path) -> str:
    return PP.read(p)


def q(v) -> str:
    return shlex.quote("" if v is None else str(v))


def cmd_session_env(a) -> int:
    plan = load(a.plan)
    s = next((x for x in plan.get("sessions") or [] if x["id"] == a.id), None)
    if s is None:
        print(f"fwtrace: no session {a.id}", file=sys.stderr)
        return 2
    # method, body and header: chapter 1's walk sends the model's request (a POST, its body and the
    # key's header file in the client) where chapter 4's sessions send a GET; empty for those
    for k in ("id", "client", "client_addr", "dst_addr", "fqdn", "path", "sport", "hold_s", "ca_root", "pin", "translated_addr",
              "method", "body", "header"):
        print(f"S_{k.upper()}={q(s.get(k))}")
    return 0


def cmd_pull_env(a) -> int:
    p = load(a.plan).get("pull") or {}
    if not p:
        return 1
    for k in ("node", "node_addr", "image", "cri", "registry", "registry_addr", "registry_port", "translated_src"):
        print(f"P_{k.upper()}={q(p.get(k))}")
    return 0


def cmd_points(a) -> int:
    for pt in (load(a.plan).get("pull") or {}).get("points") or []:
        print("\t".join(str(x) for x in (pt["id"], pt["node"], pt["eth"], pt["vlan"] if pt["vlan"] is not None else "none",
                                          pt["group"] or "-", pt["side"], pt["depth"])))
    return 0


def find_session(text: str, src: str, sport) -> dict | None:
    for r in PP.sessions(text):
        if r.get("src") == src and str(r.get("sport")) == str(sport):
            return r
    return None


def cmd_session_id(a) -> int:
    r = find_session(read(Path(a.file)), a.src, a.sport)
    if r is None:
        return 1
    print(r["id"])
    return 0


# --------------------------------------------------------------------------------------------
# judgment


def judge_session(v, rs: Path, s: dict, plan: dict) -> dict:
    d = rs / "sessions" / s["id"]
    ex = s.get("expect") or {}
    v.sec(f"session {s['id']}: {s['client']} ({s['client_addr']}) to https://{s['fqdn']}{s['path']} at {s['dst_addr']}:443"
          + (f", translated to {s['translated_addr']}" if s.get("translated_addr") else ""))
    req = read(d / "request.txt")
    code, body = TMD.http_reply(req)
    v.check(f"the reply: HTTP {ex.get('status', 200)}" + (f" with the echoed message {s['msg']}" if s.get("msg") else ""),
            code == ex.get("status", 200) and (not s.get("msg") or s["msg"] in body), f"HTTP {code}" if code else "no HTTP reply")
    held = re.search(r"^HELD ([0-9.]+)$", req, re.M)
    v.check(f"the connection held {s['hold_s']} s after the reply, so the session table still lists it", bool(held),
            "the client never reached its hold")
    lst = read(d / "session-all.txt")
    row = find_session(lst, s["client_addr"], s["sport"])
    xrows = PP.sessions_xml(read(d / "session-all.xml"))
    xrow = next((r for r in xrows if r.get("source") == s["client_addr"] and r.get("sport") == str(s["sport"])), None)
    v.check(f"show session all lists it: {s['client_addr']}[{s['sport']}] to {s['dst_addr']}[443]" + (f" (id {row['id']})" if row else ""),
            row is not None and row.get("dst") == s["dst_addr"] and row.get("dport") == 443,
            "no row for the client's address and source port" if row is None else f"destination {row.get('dst')}[{row.get('dport')}]")
    out = {"id": s["id"], "code": code, "row": row, "xml_row": xrow}
    if row is not None:
        want_x = s.get("translated_addr") or s["dst_addr"]
        v.check(f"... zone {ex.get('from_zone')} to zone {ex.get('to_zone')}, state ACTIVE", row.get("from") == ex.get("from_zone")
                and row.get("to") == ex.get("to_zone") and row.get("state") == "ACTIVE",
                f"zone {row.get('from')} to {row.get('to')}, state {row.get('state')}")
        v.check(f"... destination after translation {want_x}" + (" (the destination NAT)" if s.get("translated_addr") else " (none)")
                + f", source unchanged {s['client_addr']}",
                row.get("xdst") == want_x and row.get("xsrc") == s["client_addr"],
                f"translated destination {row.get('xdst')}, source {row.get('xsrc')}")
    det = PP.session(read(d / "session-detail.txt"))
    out["detail"] = det
    v.check(f"show session id names the security rule {ex.get('rule')}", det.get("rule") == ex.get("rule"),
            f"rule {det.get('rule') or 'not read'}")
    if ex.get("nat_rule"):
        v.check(f"... and the NAT rule {ex['nat_rule']}", det.get("nat_rule") == ex["nat_rule"],
                f"nat-rule {det.get('nat_rule') or 'not read'}")
    else:
        v.check("... and no NAT rule", not det.get("nat_rule") or det.get("nat_rule") in ("None", "none"),
                f"nat-rule {det.get('nat_rule')}")
    tl = read(d / "traffic-log.txt")
    es = PP.tlog_find(tl, src=s["client_addr"], sport=s["sport"], dst=s["dst_addr"], dport=443)
    e = es[0] if es else None
    out["tlog"] = e
    want_rule = (ex.get("rule") or "")[:RULE_WIDTH]
    v.check(f"the traffic log line: {ex.get('rule')} (shown as {want_rule}), allow, zone {ex.get('from_zone')} to zone {ex.get('to_zone')}, "
            f"the pre-NAT destination {s['dst_addr']}",
            bool(e) and e["rule"] == want_rule and e["action"] == "allow" and e["from"] == ex.get("from_zone") and e["to"] == ex.get("to_zone"),
            "no entry for the connection" if not e else f"rule {e['rule']}, {e['action']}, {e['from']} to {e['to']}")
    return out


def _bytes_from(pkts: list, src: str, dst: str) -> int:
    n = 0
    for p in pkts:
        if p.get("src") == src and p.get("dst") == dst:
            m = re.search(r"\blength (\d+)\)", p.get("raw") or "")
            n += int(m.group(1)) if m else 0
    return n


def _first_inside_syn(pts: list, dec: dict, p: dict):
    """The node's first SYN to the registry among the inside points, and the point it was seen at."""
    reg, port = p["registry_addr"], int(p["registry_port"])
    syn0, at0 = None, None
    for x in [x for x in pts if x["side"] == "inside"]:
        for pk in dec.get(x["id"]) or []:
            if pk.get("flags") == "S" and pk.get("src") == p["node_addr"] and pk.get("dst") == reg and pk.get("dport") == port:
                if syn0 is None or pk["ts"] < syn0["ts"]:
                    syn0, at0 = pk, x
    return syn0, at0


def _pull_points(d: Path) -> list:
    return [dict(zip(("id", "node", "eth", "vlan", "group", "side", "depth"), line.split("\t")))
            for line in read(d / "points.tsv").splitlines() if line.strip()]


def cmd_pull_sport(a) -> int:
    """The source port of the node's first SYN to the registry, from the decoded captures, so the
    traffic log is read for that session's own line."""
    p = load(a.plan).get("pull") or {}
    d = Path(a.set) / "pull"
    pts = _pull_points(d)
    dec = {x["id"]: TMD.packets(read(d / "captures" / f"{x['id']}.txt")) for x in pts if x["side"] == "inside"}
    syn0, _ = _first_inside_syn(pts, dec, p) if p else (None, None)
    if syn0 is None:
        return 1
    print(syn0["sport"])
    return 0


def judge_pull(v, rs: Path, p: dict) -> dict:
    d = rs / "pull"
    ex = p.get("expect") or {}
    v.sec(f"pull: {p['node']} ({p['node_addr']}) pulls {p['image']} from the registry {p['registry_addr']}:{p['registry_port']}")
    res = read(d / "pull.txt")
    v.check(f"crictl pulled it through {p['node']}'s CRI", bool(re.search(r"Image is up to date for |sha256:[0-9a-f]{64}", res)),
            (res.strip().splitlines() or ["no output"])[-1][:100])
    pts = _pull_points(d)
    dec = {x["id"]: TMD.packets(read(d / "captures" / f"{x['id']}.txt")) for x in pts}
    reg, port = p["registry_addr"], int(p["registry_port"])
    syn0, at0 = _first_inside_syn(pts, dec, p)
    v.check(f"the node's first SYN to {reg}:{port} seen inside, from {p['node_addr']}" + (f" at {at0['id']} (seq {syn0['seq']}, source port {syn0['sport']})" if syn0 else ""),
            syn0 is not None, "no SYN from the node to the registry at any inside point")
    out = {"syn": syn0, "inside_at": at0["id"] if at0 else None}
    if syn0 is not None:
        want_tag = at0.get("vlan")
        v.check(f"... tagged {want_tag}" if want_tag not in (None, "none") else "... untagged",
                str(syn0.get("vlan")) == str(want_tag) if want_tag not in (None, "none") else syn0.get("vlan") is None,
                f"vlan {syn0.get('vlan')}")
        outside = [x for x in pts if x["side"] == "outside"]
        s1, at1 = None, None
        for x in outside:
            s = TMD.first_syn(dec.get(x["id"]) or [], seq=syn0["seq"])
            if s is not None:
                s1, at1 = s, x
                break
        v.check(f"the same SYN (seq {syn0['seq']}) seen on the uplink" + (f" at {at1['id']}" if at1 else ""), s1 is not None,
                "not at " + ", ".join(x["id"] for x in outside))
        out.update(outside_syn=s1, outside_at=at1["id"] if at1 else None)
        if s1 is not None:
            v.check(f"... its source rewritten to {p['translated_src']} (port {syn0['sport']} became {s1.get('sport')}), "
                    f"its destination {reg}:{port} unchanged",
                    s1.get("src") == p["translated_src"] and s1.get("dst") == reg and s1.get("dport") == port,
                    f"{s1.get('src')}.{s1.get('sport')} > {s1.get('dst')}.{s1.get('dport')}")
            b_in = sum(_bytes_from(dec.get(x["id"]) or [], reg, p["node_addr"]) for x in pts if x["side"] == "inside")
            b_out = sum(_bytes_from(dec.get(x["id"]) or [], reg, p["translated_src"]) for x in outside)
            out.update(bytes_inside=b_in, bytes_outside=b_out)
            v.check(f"the registry's replies: {b_out} bytes to {p['translated_src']} on the uplink, {b_in} bytes to {p['node_addr']} inside "
                    "(IP lengths summed over the captures, snaplen 256)", b_out > 0 and b_in > 0, "no reply bytes on one side")
    tl = read(d / "traffic-log.txt")
    # the pull's own session: the entry from the first SYN's source port, not any earlier pull's
    sport = syn0["sport"] if syn0 else None
    es = [e for e in PP.tlog_find(tl, src=p["node_addr"], sport=sport, dst=reg, dport=port)] if sport is not None else []
    e = es[0] if es else None
    want_rule = (ex.get("rule") or "")[:RULE_WIDTH]
    v.check(f"the traffic log has the pull's session (source port {sport if sport is not None else 'unknown'}) under {ex.get('rule')}, allow, "
            f"zone {ex.get('from_zone')} to zone {ex.get('to_zone')}",
            bool(e) and e["rule"] == want_rule and e["action"] == "allow" and e["from"] == ex.get("from_zone") and e["to"] == ex.get("to_zone"),
            ("no SYN to take the source port from" if sport is None else f"no entry from {p['node_addr']}[{sport}] to the registry")
            if not e else f"rule {e['rule']}, {e['action']}, {e['from']} to {e['to']}")
    out["tlog"] = e
    rmi = read(d / "rmi.txt")
    v.ok(f"the image removed from {p['node']} again, so the next trace pulls it whole ({(rmi.strip().splitlines() or ['no output'])[-1][:80]}; not judged)")
    out["points"] = pts
    out["frames"] = {k: len(x) for k, x in dec.items()}
    return out


def judge(a) -> int:
    rs = Path(a.set)
    plan = load(a.plan)
    inv = load(a.inv)
    v = vocab.Vocab(known=set(inv.get("known") or []) or None)
    sessions = [judge_session(v, rs, s, plan) for s in plan.get("sessions") or []]
    pull = judge_pull(v, rs, plan["pull"]) if plan.get("pull") else None
    counts = vocab.counts_of(os.environ["SFAB_VERDICT"]) if os.environ.get("SFAB_VERDICT") else v.counts()
    write_md(rs, inv, plan, sessions, pull, counts, a.stamp)
    return 1 if v.counts()["fail"] else 0


def _excerpt(path: Path, pattern: str, before=0, after=12) -> tuple[int, list]:
    lines = read(path).splitlines()
    for i, l in enumerate(lines):
        if re.search(pattern, l):
            return i + 1, lines[max(0, i - before):i + after]
    return 0, []


def write_md(rs: Path, inv: dict, plan: dict, sessions: list, pull, counts: dict, stamp) -> None:
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    verdict = read(rs / "verdict.txt")
    L = ["# Firewall trace", "",
         f"- Lab: `{inv.get('lab')}`; labs repo commit `{commit}`{uncommitted}; UTC {run.get('utc_start') or 'unknown'}",
         f"- Firewall `{plan.get('fw')}`, public address {plan.get('public')}; {len(plan.get('sessions') or [])} sessions"
         + (f", one image pull at {len((plan.get('pull') or {}).get('points') or [])} capture points" if plan.get("pull") else "")]
    if stamp:
        L.append(f"- {stamp}")
    L += ["", "## Sessions", "", "| Session | Client | To | Translated to | Rule expected | NAT rule expected | Hold (s) |", "|---|---|---|---|---|---|---|"]
    for s in plan.get("sessions") or []:
        ex = s.get("expect") or {}
        L.append(f"| `{s['id']}` | {s['client']} {s['client_addr']}[{s['sport']}] | {s['dst_addr']}:443 | {s.get('translated_addr') or 'none'} | "
                 f"`{ex.get('rule')}` | {('`' + ex['nat_rule'] + '`') if ex.get('nat_rule') else 'none'} | {s['hold_s']} |")
    L += ["", "## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", ""]
    for s in sessions:
        d = rs / "sessions" / s["id"]
        L += [f"## Session {s['id']}", ""]
        for f, pat, what in (("session-all.txt", r"^\d+\s", "show session all, the session's row"),
                             ("session-detail.txt", r"c2s flow", "show session id"),
                             ("traffic-log.txt", r"^\d{4}/\d\d/\d\d ", "the traffic log")):
            n, ex = _excerpt(d / f, pat, after=2 if f != "session-detail.txt" else 40)
            if f == "traffic-log.txt" and s.get("tlog"):
                n = s["tlog"].get("line") or n
                lines = read(d / f).splitlines()
                ex = lines[n - 1:n + 3] if n else ex
            L += [f"{what} (`sessions/{s['id']}/{f}:{n}`)" if n else f"{what}: not read", ""]
            if ex:
                L += ["```"] + ex + ["```", ""]
    if pull:
        L += ["## The image pull", "", "| Point | Side | Frames |", "|---|---|---|"]
        for x in pull.get("points") or []:
            L.append(f"| `{x['id']}` | {x['side']} | {pull['frames'].get(x['id'], 0)} |")
        L.append("")
        for key, at in (("syn", "inside_at"), ("outside_syn", "outside_at")):
            pk = pull.get(key)
            if pk:
                L += [f"- `{pull.get(at)}` (`pull/captures/{pull.get(at)}.txt:{pk['line']}`)", "", "  ```", f"  {pk['head']}", "  ```", ""]
    L += ["## Files", "",
          "- `verdict.txt`, `commands.txt`; per session `sessions/<id>/`: `request.txt`, `session-all.txt` and `.xml`, `session-detail.txt` and `.xml`, `traffic-log.txt`",
          "- `pull/`: `pull.txt`, `rmi.txt`, `points.tsv`, `traffic-log.txt`, `captures/<point>.pcap` and `.txt` (decoded with `tcpdump -nn -e -tttt -v -S -r`); "
          f"each point keeps the pull's first {os.environ.get('SFAB_TRACE_CAP_FRAMES') or 5000} frames on the registry's port (`tcpdump -c`), so the frame counts and the reply bytes are of those frames",
          "", vocab.result_line(counts), ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="fwtrace")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("session-env")
    s.add_argument("--plan", required=True)
    s.add_argument("--id", required=True)
    s = sub.add_parser("pull-env")
    s.add_argument("--plan", required=True)
    s = sub.add_parser("points")
    s.add_argument("--plan", required=True)
    s = sub.add_parser("session-id")
    s.add_argument("--file", required=True)
    s.add_argument("--src", required=True)
    s.add_argument("--sport", required=True)
    s = sub.add_parser("pull-sport")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s = sub.add_parser("judge")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--inv", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"session-env": cmd_session_env, "pull-env": cmd_pull_env, "points": cmd_points, "session-id": cmd_session_id,
            "pull-sport": cmd_pull_sport, "judge": judge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
