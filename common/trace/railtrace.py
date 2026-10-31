#!/usr/bin/env python3
"""railtrace.py: chapter 5's rail trace, its plan and its judgment (common/trace/lib-railtrace.sh).

    railtrace.py get    --plan gen/trace.json PATH     a value of the plan (a list one item per line)
    railtrace.py rails  --plan gen/trace.json          every rail: r, switch, src ns, src and dst address (TSV)
    railtrace.py points --plan gen/trace.json          the capture points: id, where, node, iface or eth (TSV)
    railtrace.py flows  --plan gen/trace.json          the flows: id, node, ns, dst address, ICMP id (TSV)
    railtrace.py df     --plan gen/trace.json          the DF matrix: id, node, ns, dst address, payload, ICMP id (TSV)
    railtrace.py judge  --set DIR --plan gen/trace.json --inv INV [--stamp TEXT]

The plan is gen/trace.json (sfab.render.trace, rails form). judge reads the saved files only and
prints the result vocabulary, appending each line to $SFAB_VERDICT, then writes TRACE.md:

  health     the same rail on every rail: each of the source's GPU namespaces pings the far node's
             address on its own rail (health/rail<r>.txt)
  each flow  its ping (every request answered, every reply at the TTL the plan names: 64 on one rail,
             63 across); at every capture point, the flow's requests and replies by its ICMP id, each
             present exactly where the plan says and absent everywhere else, at the plan's TTL, so the
             request is seen crossing the destination rail's switch and the reply the source rail's;
             the request with the first sequence number carrying one IP id at every point that saw it
             (the same packet, forwarded once in a relay namespace across rails); and traceroute's
             hops as the plan names them (flows/<id>/)
  the DF     each flow forward and reversed at every size, the don't-fragment bit set: a size up to
  matrix     the relay's MTU answered, a size above it refused, with where the refusal came from
             (the sender's own interface, a hop's fragmentation-needed message, or silence); the
             answered sizes' frames at the capture points with their frame and IP lengths, and no
             frame of a refused size anywhere (df/ and captures-df/)

Decodes are tcpdump -nn -e -tttt -v -r, the guests' made and read inside the guest. Standard
library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Build A revision 2: the relay is labeled wherever it is shown.
RELAY_LABEL = ("the cross-rail flow rides the lab's IP relay, its stand-in that lets captures show PXN's path: production GPU hosts "
               "do not IP-forward between rails (NCCL moves cross-rail collective data over NVLink with PXN, and its IP control "
               "traffic uses the frontend), and rp_filter 2 belongs to the relay; production keeps 1 with per-rail policy routing")

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import evfile  # noqa: E402
import vocab  # noqa: E402

HEAD = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) ([0-9a-f:]{17}) > ([0-9a-f:]{17}), (.*)$")
ICMP = re.compile(r"(\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): ICMP echo (request|reply), id (\d+), seq (\d+)")
PING_REPLY = re.compile(r"bytes from (\S+): icmp_seq=(\d+) ttl=(\d+)")
PING_STATS = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
LOCAL_ERR = re.compile(r"local error: message too long, mtu[= ](\d+)", re.I)
SEND_ERR = re.compile(r"(sendmsg|sendto): message too long", re.I)
FRAG = re.compile(r"Frag needed and DF set \(mtu = (\d+)\)|frag needed.*?mtu[ =]+(\d+)", re.I)
HOP = re.compile(r"^\s*(\d+)\s+(\S+)")


def load(p):
    """A JSON file, stored plain or compressed (NAME.gz, evfile.py)."""
    return json.loads(evfile.read_text(p, "strict"))


def read(p: Path) -> str:
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
    else:
        print(cur)
    return 0


def _tsv(rows) -> None:
    for r in rows:
        print("\t".join("" if x is None else str(x) for x in r))


def cmd_rails(a) -> int:
    p = load(a.plan)
    _tsv((r["r"], r["switch"], r["src_ns"], r["src_addr"], r["dst_addr"]) for r in p["rails"])
    return 0


def cmd_points(a) -> int:
    _tsv((x["id"], x["where"], x["node"], x["iface"] or x["eth"]) for x in load(a.plan)["points"])
    return 0


def cmd_flows(a) -> int:
    _tsv((f["id"], f["src_node"], f["src_ns"], f["dst_addr"], f["icmp_id"]) for f in load(a.plan)["flows"])
    return 0


def cmd_df(a) -> int:
    _tsv((d["id"], d["node"], d["ns"], d["dst_addr"], d["payload"], d["icmp_id"]) for d in load(a.plan)["df"])
    return 0


# --------------------------------------------------------------------------------------------
# reading the evidence


def frames(text: str) -> list:
    """tcpdump -nn -e -tttt -v -r: one dict per ICMP echo frame, with the line its header is on."""
    out, cur = [], None
    for i, line in enumerate((text or "").splitlines(), 1):
        m = HEAD.match(line)
        if m:
            rest = m.group(4)
            fl = re.search(r", length (\d+): ", rest)
            ttl = re.search(r"\bttl (\d+)\b", rest)
            ipid = re.search(r"\bttl \d+, id (\d+)\b", rest)
            iplen = re.search(r"proto \S+ \(\d+\), length (\d+)\)", rest)
            cur = {"ts": m.group(1), "src_mac": m.group(2), "dst_mac": m.group(3), "line": i, "head": line,
                   "frame_len": int(fl.group(1)) if fl else None, "ttl": int(ttl.group(1)) if ttl else None,
                   "ipid": int(ipid.group(1)) if ipid else None, "ip_len": int(iplen.group(1)) if iplen else None,
                   "df": "flags [DF]" in rest, "vlan": bool(re.search(r"\bvlan \d+, p \d+", rest))}
            out.append(cur)
            i_ = ICMP.search(rest)
            if i_:
                cur.update(src=i_.group(1), dst=i_.group(2), kind=i_.group(3), id=int(i_.group(4)), seq=int(i_.group(5)))
            continue
        if cur is not None and line[:1] in (" ", "\t"):
            cur["head"] += "\n" + line
            i_ = ICMP.search(line)
            if i_ and "kind" not in cur:
                cur.update(src=i_.group(1), dst=i_.group(2), kind=i_.group(3), id=int(i_.group(4)), seq=int(i_.group(5)))
    return [f for f in out if f.get("kind")]


def ping_result(text: str) -> dict:
    tx = rx = None
    m = PING_STATS.search(text or "")
    if m:
        tx, rx = int(m.group(1)), int(m.group(2))
    ttls = [int(x.group(3)) for x in PING_REPLY.finditer(text or "")]
    le, fr = LOCAL_ERR.search(text or ""), FRAG.search(text or "")
    se = SEND_ERR.search(text or "")
    return {"tx": tx, "rx": rx, "ttls": ttls, "local_mtu": int(le.group(1)) if le else None, "local_err": se.group(0) if se else None,
            "frag_mtu": int(next(g for g in fr.groups() if g)) if fr else None,
            "frag_from": (re.search(r"From (\S+) .*Frag needed", text or "", re.I) or [None, None])[1] if fr else None}


def hops(text: str) -> list:
    out = []
    for line in (text or "").splitlines():
        if line.lower().startswith("traceroute to"):
            continue
        m = HOP.match(line)
        if m:
            addr = next((t for t in line.split()[1:] if re.match(r"^\d+\.\d+\.\d+\.\d+$", t)), None)
            out.append((int(m.group(1)), addr or "*"))
    return out


# --------------------------------------------------------------------------------------------
# judgment


def _where(pt: dict) -> str:
    if pt["where"] == "guest":
        return f"{pt['node']}'s relay bridge {pt['iface']}"
    return f"{pt['node']} {pt['native']}, facing {pt['faces']} on rail {pt['rail']}"


def judge_health(v, rs: Path, plan: dict) -> list:
    src, dst = plan["src"]["node"], plan["dst"]["node"]
    v.sec(f"health: the same rail on every rail, {src}'s GPU namespaces to {dst}")
    out = []
    for r in plan["rails"]:
        res = ping_result(read(rs / "health" / f"rail{r['r']}.txt"))
        good = bool(res["rx"])
        out.append({"r": r["r"], "rx": res["rx"], "tx": res["tx"]})
        v.check(f"rail {r['r']} ({r['switch']}): {src} ({r['src_ns']}, {r['src_addr']}) to {r['dst_addr']}: "
                f"{res['rx'] if res['rx'] is not None else '?'} of {res['tx'] if res['tx'] is not None else '?'} answered", good,
                "no reply" if res["tx"] else "no ping statistics in the output")
    return out


def judge_flow(v, rs: Path, plan: dict, f: dict, decs: dict) -> dict:
    d = rs / "flows" / f["id"]
    rails = f"rail {f['rail']} to rail {f['to_rail']}"
    v.sec(f"flow {f['id']}: {f['src_node']} namespace {f['src_ns']} ({f['src_addr']}) to {f['dst_node']} {f['dst_addr']}, {rails}")
    res = ping_result(read(d / "ping.txt"))
    want_ttl = f["expect"]["ttl"]
    v.check(f"the ping: {res['rx'] if res['rx'] is not None else '?'} of {plan['count']} answered, every reply at TTL {want_ttl}",
            res["rx"] == plan["count"] and res["ttls"] and all(t == want_ttl for t in res["ttls"]),
            f"replies {res['rx']}, TTLs {sorted(set(res['ttls'])) or 'none'}")
    out = {"id": f["id"], "ping": res, "points": {}}
    seen_req, seen_rep = {}, {}
    for pt in plan["points"]:
        fs = [x for x in decs.get(pt["id"], []) if x.get("id") == f["icmp_id"]]
        req = [x for x in fs if x["kind"] == "request"]
        rep = [x for x in fs if x["kind"] == "reply"]
        e = pt["expect"][f["id"]]
        out["points"][pt["id"]] = {"requests": len(req), "replies": len(rep), "req_ttl": sorted({x["ttl"] for x in req}),
                                   "rep_ttl": sorted({x["ttl"] for x in rep}), "first_req": req[0] if req else None,
                                   "first_rep": rep[0] if rep else None}
        if req:
            seen_req[pt["id"]] = req
        if rep:
            seen_rep[pt["id"]] = rep

        def part(kind, got, want):
            if want is None:
                return f"no {kind}" if not got else None, f"no {kind}", not got
            ok = len({x["seq"] for x in got}) == plan["count"] and all(x["ttl"] == want for x in got)
            return None, f"{plan['count']} {'requests' if kind == 'request' else 'replies'} at TTL {want}", ok
        _, lr, okr = part("request", req, e["request"])
        _, lp, okp = part("reply", rep, e["reply"])
        got_s = (f"{len(req)} requests (TTL {','.join(map(str, out['points'][pt['id']]['req_ttl'])) or '-'}), "
                 f"{len(rep)} replies (TTL {','.join(map(str, out['points'][pt['id']]['rep_ttl'])) or '-'})")
        v.check(f"{pt['id']} ({_where(pt)}): {lr}, {lp}", okr and okp, got_s)
    req_sw = sorted({p["node"] for p in plan["points"] if p["where"] == "switch" and p["id"] in seen_req})
    rep_sw = sorted({p["node"] for p in plan["points"] if p["where"] == "switch" and p["id"] in seen_rep})
    v.check(f"the request crossed {f['request_switch']} (rail {f['request_rail']}, the destination's rail) and the reply "
            f"{f['reply_switch']} (rail {f['reply_rail']}, the source's)", req_sw == [f["request_switch"]] and rep_sw == [f["reply_switch"]],
            f"requests on {','.join(req_sw) or 'no switch'}, replies on {','.join(rep_sw) or 'no switch'}")
    firsts = {pid: next((x for x in fr if x["seq"] == 1), None) for pid, fr in seen_req.items()}
    firsts = {k: x for k, x in firsts.items() if x}
    ids = {x["ipid"] for x in firsts.values()}
    ttl_s = ", ".join(f"{x['ttl']} at {k}" for k, x in sorted(firsts.items()))
    v.check(f"the request with seq 1 carries one IP id at every point that saw it ({len(firsts)} points; TTL {ttl_s or 'none'})",
            len(firsts) >= 2 and len(ids) == 1 and None not in ids, f"IP ids {sorted(i for i in ids if i is not None) or 'none'}")
    out["ipid"] = next(iter(ids)) if len(ids) == 1 else None
    hp = hops(read(d / "traceroute.txt"))
    out["hops"] = hp
    want = f["expect"]["hops"]
    label = ", then ".join(want)
    if f["kind"] == "cross":
        label = (f"{want[0]} ({f['src_node']}'s own address on rail {f['request_rail']}: its namespace on that rail forwarded the probe "
                 f"and answers from its route's pinned source), then {want[1]}")
    v.check(f"traceroute: {len(want)} hop{'s' if len(want) > 1 else ''}, {label}", [h[1] for h in hp] == want,
            "hops " + (", ".join(f"{n} {a}" for n, a in hp) or "none"))
    return out


def judge_df(v, rs: Path, plan: dict, decs: dict) -> list:
    ceiling = min(plan["src"]["mtu"], plan["dst"]["mtu"])
    sizes = sorted({d["size"] for d in plan["df"]})
    v.sec(f"the DF probe matrix: {len(plan['flows'])} paths, both directions, at {', '.join(map(str, sizes))} bytes, "
          "the don't-fragment bit set")
    flows = {f["id"]: f for f in plan["flows"]}
    out = []
    for row in plan["df"]:
        res = ping_result(read(rs / "df" / f"{row['id']}.txt"))
        f = flows[row["flow"]]
        label = f"{row['flow']} {row['direction']}, {row['size']} bytes: {row['node']} ({row['ns']}, {row['src_addr']}) to {row['dst_addr']}"
        rec = {"id": row["id"], "size": row["size"], "rx": res["rx"], "tx": res["tx"], "local_mtu": res["local_mtu"], "local_err": res["local_err"],
               "frag_mtu": res["frag_mtu"], "points": {}}
        if row["size"] <= ceiling:
            v.check(f"{label}: {res['rx'] if res['rx'] is not None else '?'} of {res['tx'] or '?'} answered", bool(res["rx"]),
                    "no reply" + (f" (local error, mtu {res['local_mtu']})" if res["local_mtu"] else ""))
        else:
            if res["local_mtu"]:
                how = f"refused at the sender's own interface: message too long, mtu {res['local_mtu']}"
            elif res["local_err"]:
                how = f"refused at the sender's own interface: {res['local_err']}"
            elif res["frag_mtu"]:
                how = f"refused by a hop: fragmentation needed, mtu {res['frag_mtu']}" + (f" (from {res['frag_from']})" if res["frag_from"] else "")
            else:
                how = "refused silently: no reply and no error"
            rec["refusal"] = how
            v.check(f"{label}: {how}", res["tx"] is not None and not res["rx"],
                    "no ping statistics in the output" if res["tx"] is None else f"{res['rx']} answered: the path carries {row['size']} bytes")
        for pt in plan["points"]:
            e = pt["expect"][row["flow"]]
            want_req, want_rep = (e["request"], e["reply"]) if row["direction"] == "forward" else (e["reply"], e["request"])
            fs = [x for x in decs.get(pt["id"], []) if x.get("id") == row["icmp_id"]]
            rec["points"][pt["id"]] = {"requests": sum(1 for x in fs if x["kind"] == "request"), "replies": sum(1 for x in fs if x["kind"] == "reply"),
                                       "frame_len": sorted({x["frame_len"] for x in fs if x["frame_len"]}),
                                       "ip_len": sorted({x["ip_len"] for x in fs if x["ip_len"]}),
                                       "df_req": all(x["df"] for x in fs if x["kind"] == "request") if any(x["kind"] == "request" for x in fs) else None,
                                       "df_rep": all(x["df"] for x in fs if x["kind"] == "reply") if any(x["kind"] == "reply" for x in fs) else None,
                                       "want_request": want_req is not None, "want_reply": want_rep is not None}
        out.append(rec)
        pts = rec["points"]
        if row["size"] <= ceiling:
            where = [k for k, x in pts.items() if x["want_request"] or x["want_reply"]]
            frame = row["size"] + 14
            bad = [f"{k}: {x['requests']} requests, {x['replies']} replies, frames {x['frame_len']}" for k, x in pts.items()
                   if (x["want_request"] and not x["requests"]) or (x["want_reply"] and not x["replies"])
                   or any(n != frame for n in x["frame_len"]) or x["df_req"] is False]
            stray = [k for k, x in pts.items() if not (x["want_request"] or x["want_reply"]) and (x["requests"] or x["replies"])]
            v.check(f"... its requests and replies at {', '.join(where)} as {frame}-byte frames (IP {row['size']}), every request with DF set, "
                    "and at no other point", not bad and not stray, "; ".join(bad[:2] + [f"stray at {k}" for k in stray[:2]]))
            rdf = sorted({x["df_rep"] for x in pts.values() if x["df_rep"] is not None}, key=str)
            rec["reply_df"] = rdf[0] if len(rdf) == 1 else None
            if rdf:
                v.ok(f"... the far node's echo replies carry {'DF' if rdf == [True] else 'no DF' if rdf == [False] else 'DF at some points only'} "
                     "(recorded: ping sets DF on its requests; the reply is the far kernel's own)")
        else:
            seen = [k for k, x in pts.items() if x["requests"] or x["replies"]]
            v.check("... and no frame of it at any capture point", not seen, f"seen at {', '.join(seen)}")
    answered = [r for r in out if r["size"] <= ceiling]
    refused = [r for r in out if r["size"] > ceiling]
    if refused:
        first = min(r["size"] for r in refused)
        v.check(f"the paths' ceiling: {max(r['size'] for r in answered) if answered else '?'} bytes answered on every path both ways, "
                f"{first} the first size refused on every one (the relay's and the rail NICs' MTU is {ceiling})",
                all(r["rx"] for r in answered) and all(r["tx"] is not None and not r["rx"] for r in refused), "a row disagrees (above)")
    return out


def judge(a) -> int:
    rs = Path(a.set)
    plan = load(a.plan)
    inv = load(a.inv)
    v = vocab.Vocab(known=set(inv.get("known") or []) or None)
    decs = {pt["id"]: frames(read(rs / "captures" / f"{pt['id']}.txt")) for pt in plan["points"]}
    ddecs = {pt["id"]: frames(read(rs / "captures-df" / f"{pt['id']}.txt")) for pt in plan["points"]}
    health = judge_health(v, rs, plan)
    flows = [judge_flow(v, rs, plan, f, decs) for f in plan["flows"]]
    df = judge_df(v, rs, plan, ddecs)
    counts = vocab.counts_of(os.environ["SFAB_VERDICT"]) if os.environ.get("SFAB_VERDICT") else v.counts()
    write_md(rs, inv, plan, health, flows, df, decs, counts, a.stamp)
    return 1 if v.counts()["fail"] else 0


def write_md(rs: Path, inv: dict, plan: dict, health: list, flows: list, df: list, decs: dict, counts: dict, stamp) -> None:
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    verdict = read(rs / "verdict.txt")
    L = ["# Rail trace", "",
         f"- Lab: `{inv.get('lab')}`; labs repo commit `{commit}`{uncommitted}; UTC {run.get('utc_start') or 'unknown'}",
         f"- From {plan['src']['node']} to {plan['dst']['node']}: {len(plan['flows'])} flows at {len(plan['points'])} capture points, "
         f"{plan['count']} requests each; the DF matrix {len(plan['df'])} pings",
         f"- Label: {RELAY_LABEL}"]
    if stamp:
        L.append(f"- {stamp}")
    L += ["", "## Flows", "", "| Flow | From | To | Request rides | Reply rides | TTL | Hops |", "|---|---|---|---|---|---|---|"]
    for f in plan["flows"]:
        L.append(f"| `{f['id']}` | {f['src_node']} `{f['src_ns']}` {f['src_addr']} | {f['dst_node']} {f['dst_addr']} | rail {f['request_rail']} "
                 f"({f['request_switch']}) | rail {f['reply_rail']} ({f['reply_switch']}) | {f['expect']['ttl']} | {', '.join(f['expect']['hops'])} |")
    L += ["", "## Capture points", "", "| Point | Where |", "|---|---|"]
    for pt in plan["points"]:
        L.append(f"| `{pt['id']}` | {_where(pt)} |")
    L += ["", "## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", ""]
    L += ["## Frames per point", "", "| Point | " + " | ".join(f"`{f['id']}` requests (TTL) | replies (TTL)" for f in flows) + " |",
          "|---|" + "---|---|" * len(flows)]
    for pt in plan["points"]:
        cells = []
        for f in flows:
            x = f["points"].get(pt["id"]) or {}
            cells.append(f"{x.get('requests', 0)} ({','.join(map(str, x.get('req_ttl') or [])) or '-'})")
            cells.append(f"{x.get('replies', 0)} ({','.join(map(str, x.get('rep_ttl') or [])) or '-'})")
        L.append(f"| `{pt['id']}` | " + " | ".join(cells) + " |")
    L.append("")
    for f in flows:
        L += [f"## Flow {f['id']}", ""]
        for pt in plan["points"]:
            x = f["points"].get(pt["id"]) or {}
            for key in ("first_req", "first_rep"):
                fr = x.get(key)
                if fr:
                    L += [f"- `{pt['id']}`, first {'request' if key == 'first_req' else 'reply'} (`captures/{pt['id']}.txt:{fr['line']}`)", "",
                          "  ```"] + [f"  {l}" for l in fr["head"].splitlines()] + ["  ```", ""]
        tr = read(rs / "flows" / f["id"] / "traceroute.txt").strip().splitlines()
        L += [f"traceroute (`flows/{f['id']}/traceroute.txt`)", "", "```"] + tr + ["```", ""]
    L += ["## The DF probe matrix", "", "| Row | Size | Answered | Refusal | Frames at the points | Replies' DF |", "|---|---|---|---|---|---|"]
    for r in df:
        fr = sorted({n for x in r["points"].values() for n in x["frame_len"]})
        rd = r.get("reply_df")
        L.append(f"| `{r['id']}` | {r['size']} | {r['rx'] if r['rx'] is not None else '?'} of {r['tx'] or '?'} | {r.get('refusal') or '-'} | "
                 f"{', '.join(map(str, fr)) or 'none'} | {'set' if rd is True else 'not set' if rd is False else '-'} |")
    L += ["", "## Files", "",
          "- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`",
          "- `health/rail<r>.txt`; `flows/<flow>/ping.txt` and `traceroute.txt`; `df/<row>.txt`",
          "- `captures/<point>.pcap` and `.txt` (the flows), `captures-df/<point>.pcap` and `.txt` (the DF matrix), decoded with "
          "`tcpdump -nn -e -tttt -v -r` (a guest's in the guest)",
          "", vocab.result_line(counts), ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="railtrace")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    for name in ("rails", "points", "flows", "df"):
        s = sub.add_parser(name)
        s.add_argument("--plan", required=True)
    s = sub.add_parser("judge")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--inv", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"get": cmd_get, "rails": cmd_rails, "points": cmd_points, "flows": cmd_flows, "df": cmd_df, "judge": judge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
