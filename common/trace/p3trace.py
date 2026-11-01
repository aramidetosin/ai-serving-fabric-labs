#!/usr/bin/env python3
"""p3trace.py: Part III's traces (common/trace/lib-p3trace.sh), their capture points and their
judgment: the per-population DNS trace (chapter 9), the zone-keyed NAT trace (chapter 10) and the
capture ladder (chapter 11).

    p3trace.py get    --plan gen/trace.json PATH        a value of the plan (a list one item a line)
    p3trace.py points --plan gen/trace.json [--session ID]
                                                        the capture points, TSV: id, host or guest, node,
                                                        port or interface, filter
    p3trace.py flows  --plan gen/trace.json             the ladder's connects, TSV: id, client, kind,
                                                        address, port, first source port, tries, allowed
    p3trace.py tlog-missing --set DIR --plan gen/trace.json
                                                        the DNS trace's connects through the firewall the
                                                        traffic log in DIR does not hold yet
    p3trace.py judge  --set DIR --plan gen/trace.json --inv INV [--stamp TEXT]

The plan is gen/trace.json (sfab.render.trace: dns, nat or ladder). judge reads the saved files only
and prints the result vocabulary, appending each line to $SFAB_VERDICT, then writes TRACE.md:

  dns      for each population: its resolver received its client's query for the name and answered
           the view's address; the resolver's own query to its authorities, and their answer, or
           that it answered from its cache (no query of its in the window); the client's lookup as
           it printed it; then its connect toward the answer from its pinned source port, with the
           SYN at the rungs the firewall's render says it reaches and at none past it (a node's,
           at none of its own ports: the node answers its own Gateways' VIPs), and its traffic log
           line (rule, action, zones)
  nat      for each population, chapter 4's held session (fwtrace.py: the reply, the session's
           zones and translation, show session id's rules, the traffic log line), then its SYN by
           sequence number: at the point outside the firewall (destination the address the
           population's resolver answered), and on exactly one leg of the bundle, tagged with the
           Gateway's VLAN, source address and sequence number kept, destination the Gateway's VIP
           (the internet users' translated, the staff's and the operator's as sent)
  ladder   every flow's SYNs per rung by distinct sequence number: an allowed flow at every rung on
           its path, on exactly one leg, on the pair's ports facing its Gateway's lease holder (read
           from the pair's MAC tables by the holder's bond MAC, never by name) and on that holder's
           VLAN 110 unit, and on no port facing the other ingress node; a node's flows at no rung;
           a forbidden flow at the rungs before the device that refuses it and at none past it,
           its tally there zero

Decodes are tcpdump -nn -tt -e -v -S -r. Standard library only.
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
import evfile  # noqa: E402
import panos_parse as PP  # noqa: E402
import vocab  # noqa: E402

PKT = re.compile(r"^(\d{9,11}\.\d{6}) ([0-9a-f:]{17}) > ([0-9a-f:]{17}), (.*)$")
TCP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]")
UDP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): (.*)$")
DNSQ = re.compile(r"(?:^|\s)(\d+)\+?%?\s*(?:\[[^\]]*\]\s*)*(A|AAAA)\?\s+(\S+?)\.?\s")
DNSR = re.compile(r"(?:^|\s)(\d+)[*\-|$]*\s+(?:q:\s+(?:A|AAAA)\?\s+(\S+?)\.?\s+)?(\d+)/(\d+)/(\d+)")
ANS_A = re.compile(r"\sA (\d+\.\d+\.\d+\.\d+)")
DIG_A = re.compile(r"^(\S+)\s+(\d+)\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)\s*$")
GETENT = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(STREAM|DGRAM|RAW)")
MAC_ROW = re.compile(r"^\s*(\d+)\s+([0-9a-fA-F:]{17})\s+(\S+)\s+(\S+)")
RULE_WIDTH = 19


def load(p):
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def packets(text: str) -> list:
    """tcpdump -nn -tt -e -v -S: one dict per frame (t, MACs, vlan, addresses, ports, flags, seq,
    and its DNS query or answer) with the 1-based line its header is on."""
    out, cur = [], None
    for i, line in enumerate((text or "").splitlines(), 1):
        if line[:1] in (" ", "\t") and cur is not None:
            cur["raw"] += " " + line.strip()
            continue
        m = PKT.match(line)
        if not m:
            cur = None
            continue
        cur = {"t": float(m.group(1)), "src_mac": m.group(2), "dst_mac": m.group(3), "raw": m.group(4), "line": i}
        out.append(cur)
    for p in out:
        r = p["raw"]
        v = re.search(r"\bvlan (\d+), p \d+", r)
        p["vlan"] = int(v.group(1)) if v else None
        m = TCP.search(r)
        if m:
            p.update(src=m.group(1), sport=int(m.group(2)), dst=m.group(3), dport=int(m.group(4)), flags=m.group(5), proto="tcp")
            s = re.search(r"\bseq (\d+)\b", r)
            p["seq"] = int(s.group(1)) if s else None
            continue
        m = UDP.search(r)
        if m:
            p.update(src=m.group(1), sport=int(m.group(2)), dst=m.group(3), dport=int(m.group(4)), proto="udp", flags=None, seq=None)
            body = " " + m.group(5)
            if p["dport"] == 53:
                q = DNSQ.search(body)
                if q:
                    p["dns"] = {"query": True, "id": int(q.group(1)), "type": q.group(2), "name": q.group(3).rstrip(".")}
            elif p["sport"] == 53:
                a = DNSR.search(body)
                if a:
                    p["dns"] = {"query": False, "id": int(a.group(1)), "name": (a.group(2) or "").rstrip("."), "answers": int(a.group(3)),
                                "a": ANS_A.findall(body)}
    return out


def syns(pk: list, src=None, sport=None, dst=None, dport=None, seq=None) -> list:
    out = []
    for p in pk:
        if p.get("proto") != "tcp" or p.get("flags") != "S":
            continue
        if src is not None and p.get("src") != src:
            continue
        if sport is not None and p.get("sport") not in (sport if isinstance(sport, (set, list, tuple, range)) else {sport}):
            continue
        if dst is not None and p.get("dst") != dst:
            continue
        if dport is not None and p.get("dport") != dport:
            continue
        if seq is not None and p.get("seq") != seq:
            continue
        out.append(p)
    return out


def distinct(pk: list) -> int:
    return len({(p.get("sport"), p.get("seq")) for p in pk})


def connect_lines(text: str) -> list:
    out = []
    for i, line in enumerate((text or "").splitlines(), 1):
        x = line.split()
        if len(x) >= 6 and x[2] in ("0", "1"):
            out.append({"sport": int(x[3]), "outcome": x[4], "line": i})
    return out


def lookup_answer(text: str, name: str) -> list:
    out = []
    for line in (text or "").splitlines():
        m = DIG_A.match(line.strip())
        if m and m.group(1).rstrip(".") == name:
            out.append(m.group(3))
    if not out:
        for line in (text or "").splitlines():
            m = GETENT.match(line.strip())
            if m and m.group(1) not in out:
                out.append(m.group(1))
    return out


def cite(path: str, line) -> str:
    return f"`{path}:{line}`" if line else f"`{path}`"


def run_header(rs: Path, plan: dict, stamp) -> list:
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    unc = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    L = [f"- Lab: `{plan.get('lab')}`; labs repo commit `{repo.get('commit') or 'none'}`{unc}; UTC {run.get('utc_start') or 'unknown'}"]
    if stamp:
        L.append(f"- {stamp}")
    return L


def verdict_block(rs: Path) -> list:
    return ["## Verdict", "", "```"] + [x for x in read(rs / "verdict.txt").splitlines() if x.strip()] + ["```", ""]


# --------------------------------------------------------------------------------------------
# commands


def cmd_get(a) -> int:
    cur = load(a.plan)
    for part in a.path.split("."):
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


def plan_points(plan: dict, session: str | None = None) -> list:
    pts = plan.get("points") or []
    if session:
        s = next(x for x in plan["sessions"] if x["id"] == session)
        pts = [p for p in pts if p["id"] in s["points"]]
    return pts


def cmd_points(a) -> int:
    for p in plan_points(load(a.plan), a.session):
        kind = "guest" if p.get("guest") else "host"
        print("\t".join((p["id"], kind, p["node"], p.get("iface") or p["eth"], p["filter"])))
    return 0


def cmd_flows(a) -> int:
    for f in load(a.plan).get("flows") or []:
        print("\t".join(str(x) for x in (f["id"], f["client"], f["kind"], f["address"], f["port"], f["sport"], f["tries"],
                                          1 if f["allowed"] else 0)))
    return 0


def dns_tlog_wanted(plan: dict, rs: Path) -> list:
    out = []
    for r in plan.get("rows") or []:
        s = r["syn"]
        if not s["local"] and (s["outcome"] in ("reached", "log-line")):
            out.append((r["client_addr"], s["sport"]))
    return out


def cmd_tlog_missing(a) -> int:
    rs, plan = Path(a.set), load(a.plan)
    tl = read(rs / "fw" / "traffic-log-443.txt")
    print(sum(1 for src, sp in dns_tlog_wanted(plan, rs) if not PP.tlog_find(tl, src=src, sport=sp)))
    return 0


# --------------------------------------------------------------------------------------------
# the DNS trace


def judge_dns(v, rs: Path, plan: dict) -> list:
    decs = {p["id"]: packets(read(rs / "captures" / f"{p['id']}.txt")) for p in plan["points"]}
    tl = read(rs / "fw" / "traffic-log-443.txt")
    out = []
    for r in plan["rows"]:
        v.sec(f"{r['population']}: {r['client']} ({r['client_addr']}) looks up {r['name']} through {r['resolver']} ({r['resolver_addr']}), "
              f"view {r['view']}")
        pk = decs.get(r["dns_point"]) or []
        q = [p for p in pk if (p.get("dns") or {}).get("query") and p["src"] == r["client_addr"] and p["dst"] == r["resolver_addr"]
             and p["dns"]["name"] == r["name"] and p["dns"]["type"] == "A"]
        ids = {p["dns"]["id"] for p in q}
        ans = [p for p in pk if (p.get("dns") or {}) and not p["dns"]["query"] and p["src"] == r["resolver_addr"] and p["dst"] == r["client_addr"]
               and p["dns"]["id"] in ids]
        got = sorted({x for p in ans for x in p["dns"]["a"]})
        pt = f"captures/{r['dns_point']}.txt"
        v.check(f"{r['resolver']} received {r['client']}'s query for {r['name']} A ({len(q)}) and answered {', '.join(got) or 'nothing'}, the "
                f"view's {r['answer']} ({cite(pt, q[0]['line'] if q else None)})", bool(q) and got == [r["answer"]],
                f"{len(q)} queries, answered {got}")
        fw_q = [p for p in pk if (p.get("dns") or {}).get("query") and p["src"] == r["resolver_addr"] and p["dst"] in r["authorities"]
                and p["dns"]["name"] == r["name"]]
        if fw_q:
            fids = {p["dns"]["id"] for p in fw_q}
            back = [p for p in pk if (p.get("dns") or {}) and not p["dns"]["query"] and p["dst"] == r["resolver_addr"]
                    and p["src"] in r["authorities"] and p["dns"]["id"] in fids]
            fa = sorted({x for p in back for x in p["dns"]["a"]})
            v.check(f"... which it asked of its authority {fw_q[0]['dst']}, which answered {', '.join(fa) or 'nothing'}"
                    f" ({cite(pt, fw_q[0]['line'])})", r["answer"] in fa, f"{len(back)} answer(s) from it: {fa}")
        else:
            v.ok(f"... from its cache: no query of its to {', '.join(r['authorities'])} in the window (the name's answer still held)")
        la = lookup_answer(read(rs / "lookups" / f"{r['population']}.txt"), r["name"])
        v.check(f"{r['client']}'s own lookup printed {', '.join(la) or 'nothing'}", la == [r["answer"]], f"{la}")
        s = r["syn"]
        cl = connect_lines(read(rs / "connects" / f"{r['population']}.txt"))
        c = cl[0] if cl else {"outcome": "none", "line": None}
        want_conn = s["outcome"] == "reached"
        v.check(f"{r['client']}'s connect to {s['address']}:443 from port {s['sport']}: {c['outcome']}"
                + (" (answered on the node)" if s["local"] else ""), (c["outcome"] == "CONNECTED") == want_conn,
                f"want {'a connection' if want_conn else 'no connection'}")
        seen = {}
        for pid in s["seen"] + s["seen_any"] + s["unseen"]:
            fr = decs.get(pid) or []
            if s["local"]:
                seen[pid] = syns(fr, dst=s["address"], dport=443)
            else:
                seen[pid] = syns(fr, src=r["client_addr"], sport=s["sport"], dport=443)
        for pid in s["seen"]:
            x = seen[pid]
            sc = cite(f"captures/{pid}.txt", x[0]["line"] if x else None)
            v.check(f"... its SYN at {pid} ({sc})", bool(x), "no SYN there")
        if s["seen_any"]:
            on = [pid for pid in s["seen_any"] if seen[pid]]
            v.check(f"... on exactly one leg of the bundle ({', '.join(on) or 'none'}), its destination {s['at']}",
                    len(on) == 1 and all(p["dst"] == s["at"] for p in seen[on[0]]), f"on {len(on)} legs")
        if s["unseen"]:
            leak = [pid for pid in s["unseen"] if seen[pid]]
            what = "no SYN to it left the node" if s["local"] else "nothing of it past the device that refuses it"
            v.check(f"... {what}: none at {', '.join(s['unseen'])}", not leak, f"SYNs at {', '.join(leak)}")
        if not s["local"] and s["outcome"] in ("reached", "log-line"):
            hits = PP.tlog_find(tl, src=r["client_addr"], sport=s["sport"])
            e = hits[0] if hits else {}
            act = "allow" if s["outcome"] == "reached" else s.get("action") or "deny"
            v.check(f"... the traffic log: {s['rule']} ({act}), zone {s['from_zone']} to {s['to_zone']}"
                    + (f" ({cite('fw/traffic-log-443.txt', e.get('line'))})" if e else ""),
                    bool(e) and e.get("rule") == str(s["rule"])[:RULE_WIDTH] and e.get("from") == s["from_zone"] and e.get("to") == s["to_zone"]
                    and (e.get("action") == act or (act != "allow" and e.get("action") in ("deny", "drop", "reset-both"))),
                    f"{e.get('rule')} {e.get('action')} {e.get('from')} to {e.get('to')}" if e else "no line")
        out.append({"row": r, "query": q[0] if q else None, "answer": got, "forwarded": bool(fw_q), "connect": c["outcome"]})
    return out


def md_dns(rs: Path, plan: dict, res: list, stamp) -> None:
    L = ["# Split-horizon trace", ""] + run_header(rs, plan, stamp)
    L += [f"- Each population looks up `{plan['name']}` through its own resolver, then connects toward the answer; "
          f"{len(plan['points'])} capture points", "",
          "| Population | Client | Resolver | View | Answer | Resolver asked its authority | The connect | Where the SYN went |",
          "|---|---|---|---|---|---|---|---|"]
    for x in res:
        r, s = x["row"], x["row"]["syn"]
        where = ("answered on the node" if s["local"] else
                 f"{s['rule']} ({'allowed' if s['outcome'] == 'reached' else 'refused'}), {s['from_zone']} to {s['to_zone']}")
        L.append(f"| {r['population']} | {r['client']} | {r['resolver']} | {r['view']} | {', '.join(x['answer']) or '-'} | "
                 f"{'yes' if x['forwarded'] else 'no, from its cache'} | {x['connect']} | {where} |")
    L += [""] + verdict_block(rs)
    L += ["## Files", "", "- `captures/<point>.pcap` and `.txt`: each resolver's port (port 53) and each rung the connects cross (tcp 443)",
          "- `lookups/<population>.txt`: the client's own lookup; `connects/<population>.txt`: its connect (syn_connect.py)",
          "- `fw/traffic-log-443.txt`: the firewall's traffic log after the connects", ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------------------------
# the NAT trace


def judge_nat(v, rs: Path, plan: dict) -> list:
    import fwtrace as FT  # noqa: PLC0415

    out = []
    for s in plan["sessions"]:
        j = FT.judge_session(v, rs, s, plan)
        d = rs / "captures" / s["id"]
        decs = {pid: packets(read(d / f"{pid}.txt")) for pid in s["points"]}
        want_dst = s.get("translated_addr") or s["dst_addr"]
        seq = None
        if s.get("entry"):
            x = syns(decs.get(s["entry"]) or [], src=s["client_addr"], sport=s["sport"], dst=s["dst_addr"], dport=443)
            seq = x[0]["seq"] if x else None
            ec = cite(f"captures/{s['id']}/{s['entry']}.txt", x[0]["line"] if x else None)
            v.check(f"{s['id']}: the SYN at {s['entry']}, {s['client_addr']}:{s['sport']} to {s['dst_addr']}:443, sequence number "
                    f"{seq if seq is not None else '?'} ({ec})", bool(x) and seq is not None, "no SYN there")
        legs = {pid: syns(decs.get(pid) or [], src=s["client_addr"], sport=s["sport"], dport=443, seq=seq) for pid in s["legs"]}
        on = [pid for pid, x in legs.items() if x]
        f = legs[on[0]][0] if len(on) == 1 else None
        good = f is not None and f["dst"] == want_dst and f.get("vlan") == s["vlan"]
        what = ("destination rewritten to " + want_dst + ", source and sequence number kept") if s.get("translated_addr") else \
               ("destination " + want_dst + " as sent, untranslated" + (", sequence number kept" if seq is not None else ""))
        lc = cite(f"captures/{s['id']}/{on[0]}.txt", f["line"]) if f else "-"
        v.check(f"{s['id']}: the same SYN on exactly one leg ({', '.join(on) or 'none'}), tagged {s['vlan']}: {what} ({lc})", good,
                f"on {len(on)} legs" + (f", destination {f['dst']}, VLAN {f.get('vlan')}" if f else ""))
        out.append({"session": s, "seq": seq, "leg": on[0] if len(on) == 1 else None, "leg_frame": f, "judged": j})
    return out


def md_nat(rs: Path, plan: dict, res: list, stamp) -> None:
    L = ["# Zone-keyed NAT trace", ""] + run_header(rs, plan, stamp)
    L += ["- One held HTTPS request per population to its own Gateway, at its resolver's answer; the firewall's session table read "
          "while it is held; each SYN followed by its sequence number from outside the firewall to the leg that carried it", "",
          "| Population | Client | Sent to | After the firewall | Zones | Rule | NAT rule | Sequence number | Leg |",
          "|---|---|---|---|---|---|---|---|---|"]
    for x in res:
        s = x["session"]
        ex = s["expect"]
        L.append(f"| {s['id']} | {s['client']} ({s['client_addr']}) | {s['dst_addr']} | {s.get('translated_addr') or s['dst_addr']} | "
                 f"{ex['from_zone']} to {ex['to_zone']} | {ex['rule']} | {ex.get('nat_rule') or 'none'} | {x['seq'] if x['seq'] is not None else '-'} | "
                 f"{x['leg'] or '-'} |")
    L += [""] + verdict_block(rs)
    L += ["## Files", "", "- `sessions/<population>/`: the held request, show session all (CLI and XML), show session id, the traffic log",
          "- `captures/<population>/<point>.pcap` and `.txt`: the outside point and both legs, captured while that request ran", ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------------------------
# the ladder


def holders(rs: Path, plan: dict) -> dict:
    try:
        doc = load(rs / "cluster" / "leases.json")
    except (OSError, ValueError):
        return {}
    by = {i["metadata"]["name"]: (i.get("spec") or {}).get("holderIdentity") for i in doc.get("items") or []}
    return {f["gateway"]: by.get(f["lease"].split("/", 1)[-1]) for f in plan["flows"]}


def mac_ports(rs: Path, plan: dict, inv: dict) -> dict:
    """{ingress node: {pair port id}} from the pair's MAC tables: each ingress node's bond MAC in
    VLAN 110 on a PortChannel, that PortChannel's members (the inventory's) as the ladder's ids."""
    out = {x["node"]: set() for x in plan["ingress"]}
    bymac = {str(x["mac"]).lower(): x["node"] for x in plan["ingress"] if x.get("mac")}
    for sw in plan["pair"]:
        pcs = (inv["nodes"].get(sw) or {}).get("portchannels") or {}
        for line in read(rs / "pair" / f"{sw}-mac.txt").splitlines():
            m = MAC_ROW.match(line)
            if not m or int(m.group(1)) != plan["vlan"]:
                continue
            node = bymac.get(m.group(2).lower())
            port = m.group(4)
            if node is None:
                continue
            members = (pcs.get(port) or {}).get("members") or [port]
            for e in members:
                out[node].add(f"4-{sw}-{e}")
    return out


def judge_ladder(v, rs: Path, plan: dict, inv: dict) -> dict:
    pts = plan["points"]
    decs = {p["id"]: packets(read(rs / "captures" / f"{p['id']}.txt")) for p in pts}
    hold = holders(rs, plan)
    macp = mac_ports(rs, plan, inv)
    legs = [p["id"] for p in pts if p["role"] == "leg"]
    pair = [p["id"] for p in pts if p["role"] == "pair-port"]
    units = {p["node"]: p["id"] for p in pts if p["role"] == "holder"}
    v.sec("the ladder's rungs and the lease holders")
    for g in sorted({f["gateway"] for f in plan["flows"]}):
        h = hold.get(g)
        v.check(f"{g}'s lease held by {h or 'nobody read'}; the pair's ports facing it by its MAC: {', '.join(sorted(macp.get(h) or [])) or 'none'}",
                bool(h) and bool(macp.get(h)), "no holder, or its MAC in no PortChannel of the pair")
    table, tally = [], {p["id"]: 0 for p in pts}
    for f in plan["flows"]:
        sp = range(f["sport"], f["sport"] + f["tries"])
        counts = {pid: distinct(syns(decs.get(pid) or [], src=f["client_addr"], sport=sp, dport=f["port"])) for pid in decs}
        if f["local"]:
            counts = {pid: distinct(syns(decs.get(pid) or [], sport=sp, dport=f["port"], dst=f["address"])) for pid in decs}
        h = hold.get(f["gateway"])
        cl = connect_lines(read(rs / "connects" / f"{slug(f['id'])}.txt"))
        outcomes = sorted({c["outcome"] for c in cl}) or ["none"]
        if f["local"]:
            nz = [pid for pid, n in counts.items() if n]
            v.check(f"{f['id']}: answered on {f['client']} itself ({', '.join(outcomes)}): no SYN at any rung", not nz and outcomes == ["CONNECTED"],
                    f"SYNs at {', '.join(nz)}" if nz else f"the connect {', '.join(outcomes)}")
        elif f["allowed"]:
            on_legs = [x for x in legs if counts.get(x)]
            facing = sorted(macp.get(h) or [])
            on_pair = [x for x in pair if counts.get(x)]
            other = [x for x in on_pair if x not in facing]
            unit = units.get(h)
            other_units = [u for n, u in units.items() if n != h and counts.get(u)]
            entry_ok = not f["entry"] or counts.get(f["entry"], 0) >= 1
            v.check(f"{f['id']}: allowed ({', '.join(outcomes)}), its SYN" + (f" at {f['entry']}," if f["entry"] else "")
                    + f" on one leg ({', '.join(on_legs) or 'none'}), on the pair's port facing {h} ({', '.join(x for x in on_pair if x in facing) or 'none'}) "
                    f"and on {unit or 'its unit'}", entry_ok and len(on_legs) == 1 and bool(on_pair) and not other and bool(unit and counts.get(unit))
                    and not other_units and outcomes == ["CONNECTED"],
                    f"entry {counts.get(f['entry']) if f['entry'] else '-'}, legs {len(on_legs)}, pair {on_pair}, other ports {other}, "
                    f"unit {counts.get(unit) if unit else '-'}, other units {other_units}, connect {outcomes}")
        else:
            may = [x for x in f["may"] if x in counts]
            past = {pid: n for pid, n in counts.items() if pid not in may and n}
            for pid, n in past.items():
                tally[pid] += n
            reach = ", ".join(f"{x} {counts.get(x, 0)}" for x in may) or "no rung"
            v.check(f"{f['id']}: {f['mode']} at {f['refused_at']} ({', '.join(outcomes)}): {f['tries']} SYNs by distinct sequence number "
                    f"reached {reach}, and none past it", all(counts.get(x, 0) >= 1 for x in may) and not past and "CONNECTED" not in outcomes,
                    "past it: " + ", ".join(f"{k} {n}" for k, n in past.items()) if past else f"{reach}; connect {outcomes}")
        table.append((f, counts))
    v.sec("the forbidden tallies")
    v.check(f"every rung's forbidden tally is zero ({len(pts)} rungs, {sum(1 for f in plan['flows'] if not f['allowed'] and not f['local'])} "
            "forbidden flows)", not any(tally.values()), ", ".join(f"{k} {n}" for k, n in tally.items() if n))
    return {"table": table, "tally": tally, "holders": hold, "macp": macp}


def slug(s: str) -> str:
    return re.sub(r"^-|-$", "", re.sub(r"[^a-z0-9]+", "-", str(s).lower()))


def md_ladder(rs: Path, plan: dict, res: dict, stamp) -> None:
    pts = [p["id"] for p in plan["points"]]
    L = ["# The capture ladder", ""] + run_header(rs, plan, stamp)
    L += [f"- {len(plan['flows'])} flows (every population of the matrix to each Gateway's VIP), {len(pts)} rungs; each forbidden "
          "flow tried from its own source ports, its SYNs counted by distinct sequence number", "",
          "| Flow | Mode | " + " | ".join(f"`{p}`" for p in pts) + " |", "|---|---|" + "---|" * len(pts)]
    for f, counts in res["table"]:
        cells = []
        for p in pts:
            n = counts.get(p, 0)
            past = not f["allowed"] and not f["local"] and p not in f["may"]
            cells.append(f"{n}{' (forbidden)' if past and n else ''}")
        L.append(f"| `{f['id']}` | {f['mode']}{', on the node' if f['local'] else ''} | " + " | ".join(cells) + " |")
    L += ["", "Forbidden tally per rung: " + ", ".join(f"`{k}` {n}" for k, n in res["tally"].items()), "",
          "Lease holders: " + ", ".join(f"{g} {h}" for g, h in sorted(res["holders"].items())) + "; the pair's ports facing each, by its MAC: "
          + "; ".join(f"{n}: {', '.join(sorted(x)) or 'none'}" for n, x in sorted(res["macp"].items())), ""]
    L += verdict_block(rs)
    L += ["## Files", "", "- `captures/<rung>.pcap` and `.txt`: every rung, captured over the whole run",
          "- `connects/<flow>.txt`: each flow's connects (syn_connect.py, one line a source port); `warmup/`: the warm-up connects",
          "- `pair/<switch>-mac.txt`: the pair's MAC tables after the warm-up; `cluster/leases.json`: the Gateways' leases", ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


# --------------------------------------------------------------------------------------------


def cmd_judge(a) -> int:
    rs, plan, inv = Path(a.set), load(a.plan), load(a.inv)
    v = vocab.Vocab(known=set(inv.get("known") or []) or None)
    kind = plan.get("kind")
    if kind == "dns":
        md_dns(rs, plan, judge_dns(v, rs, plan), a.stamp)
    elif kind == "nat":
        md_nat(rs, plan, judge_nat(v, rs, plan), a.stamp)
    elif kind == "ladder":
        md_ladder(rs, plan, judge_ladder(v, rs, plan, inv), a.stamp)
    else:
        v.bad("the trace's plan", f"kind {kind!r} is none of dns, nat, ladder")
    return 1 if v.counts()["fail"] else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="p3trace")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("points")
    s.add_argument("--plan", required=True)
    s.add_argument("--session")
    s = sub.add_parser("flows")
    s.add_argument("--plan", required=True)
    s = sub.add_parser("tlog-missing")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s = sub.add_parser("judge")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--inv", required=True)
    s.add_argument("--stamp")
    a = ap.parse_args(argv)
    return {"get": cmd_get, "points": cmd_points, "flows": cmd_flows, "tlog-missing": cmd_tlog_missing, "judge": cmd_judge}[a.cmd](a)


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    sys.exit(main())
