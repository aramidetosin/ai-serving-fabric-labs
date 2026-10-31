#!/usr/bin/env python3
"""walktrace.py: chapter 1's walk, its capture points and its judgment (common/trace/lib-walktrace.sh).

    walktrace.py get         --plan gen/trace.json PATH        a value of the plan (servetrace.py get)
    walktrace.py points      --plan gen/trace.json --set DIR --inv INV
                                                               every capture point, TSV as servetrace.py
                                                               prints them: the frontend's first, then
                                                               the serving trace's
    walktrace.py cmdata      --key KEY                         the file KEY a ConfigMap (its JSON on stdin)
                                                               holds, as is
    walktrace.py split-reply --set DIR                         the held request's reply (sessions/walk/
                                                               request.txt) as request/result.txt,
                                                               headers.txt and body.json
    walktrace.py tlog-has    --file F --src A SPORT...         exit 0 when the saved traffic log holds a
                                                               line from A for every SPORT
    walktrace.py judge       --set DIR --plan gen/trace.json --inv INV [--stamp TEXT]

The plan is gen/trace.json (sfab.render.trace, walk form). The frontend's points are the plan's (the
client's port, the firewall's interface facing it, both legs of the bundle, the pair's ports facing
the legs) and the pair's ports facing the lease holder's bond, found from the lease the set saved; the
serving trace's follow, numbered after them (servetrace.py point_rows with the plan's depth_base).

judge reads the saved files only and prints the result vocabulary, appending each line to
$SFAB_VERDICT, then writes TRACE.md. It walks the request inward, each device with the table it
consults:

  the names     the client's resolver answering the users' hostname with the Gateway's VIP (the view the
                platform's authoritative servers answer that resolver from), and another of the lab's
                resolvers, asking itself, getting another (a view decides, not the name)
  the firewall  the connected route toward the VIP and its egress interface (show routing route), no
                NAT rule from the client's zone (show running nat-policy), the rule that admits the
                request (show running security-policy), and chapter 4's held session: the session table
                (zones, no translation, the rule) and the traffic log line
  the wire      the walked SYN on the client's port, the same frame on the firewall's interface, then
                with its addresses, ports and sequence number kept and its TTL one lower on exactly one
                leg of the bundle, tagged with the Gateway VLAN; the same frame on the pair port that leg
                lands on and on that switch's port facing the lease holder (tagged where the holder's unit
                in the Gateway VLAN is a tagged one, an ingress node's bond0.110, else untagged), and on the lease
                holder's bond0 with the lease holder's bond MAC as its destination, its MACs, IP id and
                TTL as the leg carried them: nothing between the firewall and the Gateway routed it
  the pair      its MAC table holding the lease holder's bond MAC in the VLAN on the holder's PortChannel
  the cluster   chapter 6's and 7's hops (servetrace.py: the VIP, the API gateway pod, the router pod,
                the server and its workers on the rail, the rail switch ports, the other copies, the
                keys' marks at each hop), the lease holder one of the nodes the L2 announcement policy
                selects (inventory k8s.l2_announce.nodes: the control nodes by default, the ingress
                nodes in build A revision 2), the HTTPRoute that matched the hostname and path, the API
                gateway's route for the model (its consumer groups, the walked key's caller among them), the
                router's model list (the model's Service), and the server among that Service's ready
                endpoints
  the rail      the rail switch's interface counters on the port facing the remote worker's node, at
                least the frames the capture there counted between the two reads, and its MAC table
                holding the worker's rail MAC on that port
  the refusals  the admin hostname: the Gateway's 404, and no API gateway pod saw it; another model's
                key: the API gateway's 401 with the unknown key's message, the API gateway pod saw the
                request with that key's mark, and no router pod received any request but the walked
                one; a node's port: the client's view recorded, the SYN on the client's port and the
                firewall's interface and on no leg or point past it, and the traffic log naming the
                last rule with its action

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
import fwtrace as FT  # noqa: E402
import judge as J  # noqa: E402
import panos_parse as PP  # noqa: E402
import servetrace as ST  # noqa: E402
import vocab  # noqa: E402

PKT = re.compile(r"^(\d{9,11}\.\d{6}) ([0-9a-f:]{17}) > ([0-9a-f:]{17}), (.*)$")
TCP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]")
DIG_A = re.compile(r"^(\S+)\s+(\d+)\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)\s*$")
DIG_SERVER = re.compile(r"^;; SERVER: (\d+\.\d+\.\d+\.\d+)#(\d+)")
RULE_WIDTH = 19


def load(p):
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def line_of(text: str, rx) -> int | None:
    """The 1-based number of the first line matching rx (a pattern or a compiled one)."""
    r = re.compile(rx) if isinstance(rx, str) else rx
    for i, line in enumerate((text or "").splitlines(), 1):
        if r.search(line):
            return i
    return None


def cite(path: str, line) -> str:
    return f"`{path}:{line}`" if line else f"`{path}`"


# --------------------------------------------------------------------------------------------
# the points


def holder_tag(plan: dict, inv: dict, holder):
    """The VLAN the frames toward the lease holder carry on its bond: the Gateway's VLAN when the
    holder has a tagged unit in it (an ingress node's bond0.110), else None (untagged)."""
    h = ((inv.get("nodes") or {}).get(holder or "") or {}).get("bond") or {}
    v = plan["frontend"].get("vlan")
    return v if any(int(u.get("vlan") or 0) == v for u in h.get("vlan_ifs") or []) else None


def server_ports(plan: dict, inv: dict, holder) -> list:
    """The pair's ports facing the lease holder's bond: its members' peers in the inventory."""
    nodes = inv.get("nodes") or {}
    h = nodes.get(holder or "") or {}
    tag = holder_tag(plan, inv, holder)
    out = []
    for m in (h.get("bond") or {}).get("members") or []:
        peer = ((h.get("nics") or {}).get(m) or {}).get("peer")
        if not peer:
            continue
        sw, eth = peer.split(":", 1)
        native = (((nodes.get(sw) or {}).get("nics") or {}).get(eth) or {}).get("native") or eth
        out.append({"id": f"{plan['frontend']['server_depth']}-{sw}-{native}", "node": sw, "eth": eth, "native": native,
                    "role": "server", "faces": holder, "member": m, "vlan": tag})
    return out


def frontend_points(plan: dict, rs: Path, inv: dict) -> list:
    return list(plan["frontend"]["points"]) + server_ports(plan, inv, ST.lease_holder(rs))


def frontend_rows(plan: dict, rs: Path, inv: dict) -> list:
    fe = plan["frontend"]
    f = fe["filter"]
    filt = f"({f}) or (vlan and ({f}))"
    return [(p["id"], "host", p["node"], "-", "-", p["eth"], filt, fe["snaplen"], 0) for p in frontend_points(plan, rs, inv)]


def cmd_points(a) -> int:
    plan, inv, rs = load(a.plan), load(a.inv), Path(a.set)
    for r in frontend_rows(plan, rs, inv) + ST.point_rows(plan, rs):
        print("\t".join(str(x) for x in r))
    return 0


def cmd_get(a) -> int:
    return ST.cmd_get(a)


def cmd_cmdata(a) -> int:
    try:
        doc = json.load(sys.stdin)
    except ValueError:
        return 1
    v = (doc.get("data") or {}).get(a.key)
    if v is None:
        return 1
    sys.stdout.write(v if v.endswith("\n") else v + "\n")
    return 0


def dechunk(body: str) -> str:
    """A chunked body's data, its chunk sizes removed; any other body as it is."""
    out, rest = [], body
    while True:
        m = re.match(r"^([0-9a-fA-F]+)\r?\n", rest)
        if not m:
            return body if not out else "".join(out)
        n = int(m.group(1), 16)
        if n == 0:
            return "".join(out)
        rest = rest[m.end():]
        out.append(rest[:n])
        rest = rest[n:].lstrip("\r\n")


def cmd_tlog_has(a) -> int:
    text = read(a.file)
    return 0 if all(PP.tlog_find(text, src=a.src, sport=x) for x in a.sports) else 1


def cmd_split_reply(a) -> int:
    rs = Path(a.set)
    text = read(rs / "sessions" / "walk" / "request.txt").replace("\r", "")
    req = rs / "request"
    req.mkdir(parents=True, exist_ok=True)
    head, _, rest = text.partition("\n\n")
    first = head.splitlines()[0] if head else ""
    m = re.match(r"^HTTP/[0-9.]+ (\d{3})\b", first)
    body = rest.split("\nHELD ", 1)[0]
    sport = load(rs / "trace.json")["sport"] if (rs / "trace.json").is_file() else ""
    (req / "result.txt").write_text(f"{m.group(1) if m else 0} {sport}\n", encoding="utf-8")
    (req / "headers.txt").write_text(head + "\n" if m else "", encoding="utf-8")
    (req / "body.json").write_text(dechunk(body).strip() + "\n" if m else "", encoding="utf-8")
    return 0 if m else 1


# --------------------------------------------------------------------------------------------
# reading the saved files


def packets(text: str) -> list:
    """tcpdump -nn -tt -e -v -S: one dict per frame (t, MACs, vlan, ttl, ipid, addresses, ports,
    flags, seq) with the 1-based line its header is on."""
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
        t = re.search(r"\bttl (\d+)\b", r)
        p["ttl"] = int(t.group(1)) if t else None
        d = re.search(r"\bttl \d+, id (\d+)\b", r)
        p["ipid"] = int(d.group(1)) if d else None
        m = TCP.search(r)
        if m:
            p.update(src=m.group(1), sport=int(m.group(2)), dst=m.group(3), dport=int(m.group(4)), flags=m.group(5))
        s = re.search(r"\bseq (\d+)\b", r)
        p["seq"] = int(s.group(1)) if s else None
    return out


def syns(pk: list, src=None, sport=None, dst=None, dport=None, seq=None) -> list:
    out = []
    for p in pk:
        if p.get("flags") != "S":
            continue
        if seq is not None and p.get("seq") != seq:
            continue
        if src is not None and p.get("src") != src:
            continue
        if sport is not None and p.get("sport") not in (sport if isinstance(sport, (set, list, tuple)) else {sport}):
            continue
        if dst is not None and p.get("dst") != dst:
            continue
        if dport is not None and p.get("dport") != dport:
            continue
        out.append(p)
    return out


def dig(text: str) -> dict:
    ans = []
    server, sline = None, None
    for i, line in enumerate((text or "").splitlines(), 1):
        m = DIG_A.match(line.strip())
        if m:
            ans.append({"name": m.group(1).rstrip("."), "address": m.group(3), "line": i})
        m = DIG_SERVER.match(line.strip())
        if m:
            server, sline = m.group(1), i
    return {"answers": ans, "server": server, "server_line": sline}


def fw_routes(text: str) -> list:
    """show routing route: {dest, nexthop, metric, flags, iface, line} for each row."""
    out = []
    for i, line in enumerate((text or "").splitlines(), 1):
        t = line.split()
        if len(t) < 3 or not re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", t[0]):
            continue
        flags, iface = [], None
        for x in t[3:]:
            if re.match(r"^(?:[A-Z][a-z0-9]?|~|\?)$", x):
                flags.append(x)
            elif iface is None:
                iface = x
        out.append({"dest": t[0], "nexthop": t[1], "metric": t[2], "flags": flags, "iface": iface, "line": i})
    return out


def longest(routes: list, address: str):
    import ipaddress  # noqa: PLC0415
    a = ipaddress.ip_address(address)
    best = None
    for r in routes:
        n = ipaddress.ip_network(r["dest"], strict=False)
        if a in n and (best is None or n.prefixlen > ipaddress.ip_network(best["dest"], strict=False).prefixlen):
            best = r
    return best


def policy_blocks(text: str) -> dict:
    """show running security-policy or nat-policy: name -> {index, line, the block's key value lines}."""
    out, cur = {}, None
    for i, line in enumerate((text or "").splitlines(), 1):
        m = PP.POLICY_HEAD.match(line.strip())
        if m:
            cur = {"index": int(m.group(2)), "line": i, "fields": {}}
            out[m.group(1)] = cur
            continue
        if line.strip() == "}":
            cur = None
            continue
        if cur is not None:
            k = re.match(r"^\s*([A-Za-z][A-Za-z0-9 /_-]*?)\s+(.*?);?\s*$", line)
            if k and k.group(1) not in cur["fields"]:
                cur["fields"][k.group(1)] = (k.group(2).rstrip(";").strip(), i)
    return out


def counters_table(text: str) -> dict:
    """show interface counters: native -> {rx_ok, tx_ok, line}, read by the header's column names."""
    out, cols = {}, None
    for i, line in enumerate((text or "").splitlines(), 1):
        t = line.split()
        if t[:1] == ["Interface"] and "RX_OK" in t and "TX_OK" in t:
            cols = t
            continue
        if cols and t and re.match(r"^Ethernet\d+$", t[0]) and len(t) >= len(cols):
            def num(name):
                try:
                    return int(t[cols.index(name)].replace(",", ""))
                except (ValueError, IndexError):
                    return None
            out[t[0]] = {"rx_ok": num("RX_OK"), "tx_ok": num("TX_OK"), "line": i}
    return out


def stamps(rs: Path) -> dict:
    out = {}
    for line in read(rs / "rail" / "stamps.tsv").splitlines():
        f = line.split("\t")
        if len(f) == 4:
            try:
                out[(f[0], f[1])] = (float(f[2]), float(f[3]))
            except ValueError:
                pass
    return out


def yaml_block(text: str, head_rx: str, next_rx: str = r"^\s*- ") -> tuple:
    """The lines of a YAML list item, from the line matching head_rx to the next item: (first line, lines)."""
    lines = (text or "").splitlines()
    start = next((i for i, l in enumerate(lines) if re.search(head_rx, l)), None)
    if start is None:
        return None, []
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = start + 1
    while end < len(lines):
        l = lines[end]
        if l.strip() and len(l) - len(l.lstrip()) <= indent and re.match(next_rx, l):
            break
        if l.strip() and len(l) - len(l.lstrip()) < indent:
            break
        end += 1
    return start + 1, lines[start:end]


# --------------------------------------------------------------------------------------------
# judgment


def judge_names(v, rs: Path, plan: dict) -> dict:
    d = plan["dns"]
    v.sec(f"the names: {plan['client']['node']} asks for {d['hostname']}")
    c = dig(read(rs / "dns" / "client-dig.txt"))
    got = [x["address"] for x in c["answers"] if x["name"] == d["hostname"]]
    v.check(f"{plan['client']['node']}'s resolver {d['server']} ({d['resolver']}, the {d['view']} view) answers {d['hostname']} with "
            f"{d['answer']}, {plan['gateway']['name']}'s VIP", c["server"] == d["server"] and got == [d["answer"]],
            f"server {c['server'] or 'none'}, answers {', '.join(got) or 'none'}")
    out = {"client": c, "contrast": None}
    if d.get("contrast"):
        k = d["contrast"]
        r = dig(read(rs / "dns" / "resolver-dig.txt"))
        got2 = [x["address"] for x in r["answers"] if x["name"] == d["hostname"]]
        v.check(f"... while {k['node']}, another resolver of the lab asking itself from {k['source']}, gets {k['answer']} (the {k['view']} view): "
                "the view, not the name, picks the Gateway", got2 == [k["answer"]], f"answers {', '.join(got2) or 'none'}")
        out["contrast"] = r
    return out


def judge_firewall(v, rs: Path, plan: dict) -> dict:
    f = plan["firewall"]
    vip = plan["gateway"]["vip"]
    v.sec(f"the firewall's tables: {f['ingress']} (zone {f['ingress_zone']}) toward {vip}")
    rt = fw_routes(read(rs / "fw" / "routing-route.txt"))
    best = longest(rt, vip)
    v.check(f"show routing route: {vip} falls in {f['route']}, connected (flag C) on {f['egress']}, zone {f['egress_zone']}",
            bool(best) and best["dest"] == f["route"] and "C" in best["flags"] and best["iface"] == f["egress"],
            f"{best['dest']} {' '.join(best['flags'])} {best['iface']}" if best else "no route holds it")
    nat = policy_blocks(read(rs / "fw" / "running-nat-policy.txt"))
    from_z = {n: (b["fields"].get("from") or ("", 0))[0] for n, b in nat.items()}
    hit = [n for n, z in from_z.items() if f["ingress_zone"] in z.split() or z.strip() == "any"]
    v.check(f"show running nat-policy: {len(nat)} NAT rules, none from zone {f['ingress_zone']}: no translation", bool(nat) and not hit,
            ", ".join(hit) if hit else "no NAT rulebase read")
    sec = policy_blocks(read(rs / "fw" / "running-security-policy.txt"))
    r = sec.get(f["rule"])
    fields = (r or {}).get("fields") or {}
    dst = (fields.get("destination") or ("", 0))[0]
    first = sorted((b["index"], n) for n, b in sec.items()
                   if set((b["fields"].get("from") or ("", 0))[0].split()) & {f["ingress_zone"], "any"}
                   and set((b["fields"].get("to") or ("", 0))[0].split()) & {f["egress_zone"], "any"})
    v.check(f"show running security-policy: {f['rule']}, the first rule from {f['ingress_zone']} to {f['egress_zone']}, allows TCP 443 to "
            f"{vip} alone", bool(r) and dst.split() == [vip] and (fields.get("action") or ("", 0))[0] == "allow"
            and "443" in (fields.get("application/service") or ("", 0))[0] and bool(first) and first[0][1] == f["rule"],
            f"destination {dst or 'none'}, action {(fields.get('action') or ('none', 0))[0]}, first rule {first[0][1] if first else 'none'}")
    s = plan["sessions"][0]
    sess = FT.judge_session(v, rs, s, plan)
    return {"route": best, "nat": nat, "rule": r, "session": sess}


def judge_wire(v, rs: Path, plan: dict, inv: dict, pk: dict, holder) -> dict:
    """The walked SYN from the client's port to the lease holder's bond."""
    fe = plan["frontend"]
    caddr, vip, sport = plan["client"]["address"], plan["gateway"]["vip"], plan["sport"]
    pts = frontend_points(plan, rs, inv)
    by = {}
    for p in pts:
        by.setdefault(p["role"], []).append(p)
    v.sec(f"the wire: the walked SYN from {caddr} port {sport} to {vip}:443")
    out = {"points": pts, "seen": {}}
    cp = by["client"][0]
    s0 = (syns(pk.get(cp["id"]) or [], src=caddr, sport=sport, dst=vip, dport=443) or [None])[0]
    v.check(f"{cp['id']}, {plan['client']['node']}'s own port: the SYN leaves untagged" + (f", TTL {s0['ttl']}, seq {s0['seq']}" if s0 else ""),
            bool(s0) and s0.get("vlan") is None and s0.get("seq") is not None, "no SYN from the pinned port" if not s0 else f"vlan {s0.get('vlan')}")
    if not s0:
        return out
    out["seen"][cp["id"]] = s0
    seq = s0["seq"]
    same = lambda a, b: (a["src_mac"], a["dst_mac"], a["ttl"], a["ipid"]) == (b["src_mac"], b["dst_mac"], b["ttl"], b["ipid"])  # noqa: E731
    ip_ = by["ingress"][0]
    s1 = (syns(pk.get(ip_["id"]) or [], seq=seq) or [None])[0]
    v.check(f"{ip_['id']}, the firewall's {ip_['ifname']}: the same frame (MACs, TTL {s0['ttl']}, IP id {s0['ipid']})",
            bool(s1) and same(s0, s1) and s1.get("vlan") is None, "not seen" if not s1 else f"TTL {s1['ttl']}, IP id {s1['ipid']}")
    if s1:
        out["seen"][ip_["id"]] = s1
    on_legs = [(p, (syns(pk.get(p["id"]) or [], seq=seq) or [None])[0]) for p in by["leg"]]
    hits = [(p, s) for p, s in on_legs if s]
    leg, sl = hits[0] if len(hits) == 1 else (None, None)
    v.check(f"the same SYN (seq {seq}) on exactly one leg of {plan['firewall']['bundle']}" + (f": {leg['id']} ({leg['ifname']})" if leg else "")
            + f", captured on both", len(hits) == 1, f"on {len(hits)} legs ({', '.join(p['id'] for p, _ in hits) or 'none'})")
    out["leg"] = leg
    if not leg:
        return out
    out["seen"][leg["id"]] = sl
    v.check(f"... tagged {fe['vlan']}, its addresses and ports kept ({caddr}.{sport} > {vip}.443), TTL {s0['ttl'] - 1}: one lower, the firewall's "
            "routed hop", sl.get("vlan") == fe["vlan"] and (sl["src"], sl["sport"], sl["dst"], sl["dport"]) == (caddr, sport, vip, 443)
            and sl.get("ttl") == s0["ttl"] - 1, f"vlan {sl.get('vlan')}, {sl['src']}.{sl['sport']} > {sl['dst']}.{sl['dport']}, TTL {sl.get('ttl')}")
    tr = next((p for p in by["trunk"] if p["leg"] == leg["leg"]), None)
    other_tr = [p for p in by["trunk"] if p is not tr and syns(pk.get(p["id"]) or [], seq=seq)]
    st = (syns(pk.get(tr["id"]) or [], seq=seq) or [None])[0] if tr else None
    v.check(f"{tr['id'] if tr else 'the pair port the leg lands on'}: the same frame, tagged {fe['vlan']}, as the leg put it on the wire; "
            "the other pair member's port saw none", bool(st) and same(sl, st) and st.get("vlan") == fe["vlan"] and not other_tr,
            "not seen" if not st else (f"also at {', '.join(p['id'] for p in other_tr)}" if other_tr else f"vlan {st.get('vlan')}, TTL {st['ttl']}"))
    if st:
        out["seen"][tr["id"]] = st
    sw = tr["node"] if tr else None
    tag = holder_tag(plan, inv, holder)
    tagw = f"tagged {tag}" if tag else "untagged"
    sv = [(p, (syns(pk.get(p["id"]) or [], seq=seq) or [None])[0]) for p in by.get("server") or []]
    shits = [(p, s) for p, s in sv if s]
    sp, ss = shits[0] if len(shits) == 1 else (None, None)
    v.check(f"one pair port facing {holder}'s bond carried it, on {sw}, the switch the leg lands on" + (f": {sp['id']}" if sp else "")
            + f", {tagw}, the same frame", bool(sp) and sp["node"] == sw and ss.get("vlan") == tag and same(sl, ss),
            f"on {len(shits)} ports ({', '.join(p['id'] for p, _ in shits) or 'none'})" if not sp else f"on {sp['node']}, vlan {ss.get('vlan')}")
    if sp:
        out["seen"][sp["id"]] = ss
        out["server_port"] = sp
    bid = ST.pid(plan, 1, f"{holder}-bond0") if holder else None
    sb = (syns(pk.get(bid) or [], seq=seq) or [None])[0] if bid else None
    hmac = ((inv.get("nodes") or {}).get(holder or "") or {}).get("bond", {}).get("mac")
    v.check(f"{bid or 'the lease holder bond0'}: the same frame, {tagw}, to {holder}'s bond MAC {hmac}, with the MACs, TTL {sl['ttl']} and IP id "
            "the leg carried: no routed hop between the firewall and the Gateway",
            bool(sb) and sb.get("vlan") == tag and sb.get("dst_mac") == hmac and same(sl, sb),
            "not seen" if not sb else f"dst MAC {sb.get('dst_mac')}, TTL {sb.get('ttl')}, IP id {sb.get('ipid')}")
    if sb:
        out["seen"][bid] = sb
        out["bond"] = bid
    return out


def judge_pair(v, rs: Path, plan: dict, inv: dict, holder, wire: dict) -> dict:
    fe = plan["frontend"]
    h = ((inv.get("nodes") or {}).get(holder or "") or {}).get("bond") or {}
    mac, pc = (h.get("mac") or "").lower(), h.get("pc")
    v.sec(f"the pair: the MAC table each member bridges by, VLAN {fe['vlan']}")
    out = {}
    for sw in fe["pair"]:
        text = read(rs / "pair" / f"{sw}-mac-table.txt")
        rows = [r for r in J.p_mac_table(text) if r[0] == fe["vlan"] and r[1] == mac]
        ln = line_of(text, re.compile(rf"^\s*{fe['vlan']}\s+{re.escape(mac)}\s", re.I)) if mac else None
        v.check(f"{sw}: {holder}'s bond MAC {mac} in VLAN {fe['vlan']} on PortChannel{pc}", bool(rows) and rows[0][3] == f"PortChannel{pc}",
                f"{rows[0][3]}" if rows else "not in the table")
        out[sw] = {"line": ln, "iface": rows[0][3] if rows else None}
    return out


def judge_cluster(v, rs: Path, plan: dict, inv: dict, holder, j: dict) -> dict:
    gw = plan["gateway"]
    out = {}
    v.sec("the tables the cluster's hops consult")
    role = str(((inv.get("k8s") or {}).get("l2_announce") or {}).get("nodes") or "control")
    if role == "control":
        announcers = (inv.get("k8s") or {}).get("control") or []
    else:
        announcers = [n for n, x in (inv.get("nodes") or {}).items() if (x or {}).get("group") == role]
    art = "an" if role[:1] in "aeiou" else "a"
    lt = read(rs / "cluster" / "lease.txt")
    v.check(f"{gw['lease']}: held by {holder or 'none'}, {art} {role} node, which answers for {gw['vip']}", bool(holder) and holder in announcers,
            f"holder {holder or 'unknown'}")
    out["lease_line"] = line_of(lt, re.escape(holder)) if holder else None
    try:
        routes = load(rs / "cluster" / "httproutes.json").get("items") or []
    except (OSError, ValueError):
        routes = []
    best = None
    for r in routes:
        if not any((p.get("name") == gw["name"]) for p in (r.get("spec") or {}).get("parentRefs") or []):
            continue
        if plan["hostname"] not in ((r.get("spec") or {}).get("hostnames") or []):
            continue
        for k, rule in enumerate((r.get("spec") or {}).get("rules") or []):
            for m in rule.get("matches") or []:
                pv = ((m.get("path") or {}).get("value")) or "/"
                if plan["path"] == pv or plan["path"].startswith(pv.rstrip("/") + "/"):
                    if best is None or len(pv) > len(best["path"]):
                        be = (rule.get("backendRefs") or [{}])[0]
                        acc = any(c.get("type") == "Accepted" and c.get("status") == "True"
                                  for p in ((r.get("status") or {}).get("parents") or []) if (p.get("parentRef") or {}).get("name") == gw["name"]
                                  for c in p.get("conditions") or [])
                        best = {"route": f"{r['metadata'].get('namespace')}/{r['metadata']['name']}", "rule": k, "path": pv,
                                "backend": f"{be.get('name')}:{be.get('port')}", "accepted": acc}
    ag = plan["api_gateway"]
    v.check(f"the HTTPRoute {gw['name']} matched: {best['route'] if best else '-'}, rule {best['rule'] if best else '-'}, {plan['hostname']} "
            f"with path prefix {best['path'] if best else '-'}, to Service {best['backend'] if best else '-'}, Accepted",
            bool(best) and best["accepted"] and best["backend"] == f"{ag['name']}:{ag['port']}",
            "no route of the Gateway carries the hostname and path" if not best else f"backend {best['backend']}, accepted {best['accepted']}")
    out["route"] = best
    m = plan["model"]
    at, block = yaml_block(read(rs / "cluster" / "api-gateway-routes.yaml"), rf"^\s*- id: {re.escape(m)}\s*$")
    txt = "\n".join(block)
    wl = re.search(r"whitelist:\s*\n((?:\s*- \S+\s*\n?)+)", txt)
    groups = re.findall(r"- (\S+)", wl.group(1)) if wl else []
    # the walked key's caller: its field in the keys Secret is <caller>.<id>, or the model's own
    # name in a lab with no callers (one consumer group per model)
    kf = (read(rs / "request" / "key.txt").split() or [""])[0]
    caller = kf.split(".", 1)[0] if kf else m
    v.check(f"the API gateway's route for {m}: {plan['path']} by key authentication, the consumer groups {', '.join(groups) or '-'}, "
            f"the walked key's caller {caller} among them",
            plan["path"] in txt and "key-auth" in txt and caller in groups,
            "no route for the model" if not block else f"consumer groups {', '.join(groups) or 'none'}, caller {caller}")
    out["routes_line"] = at
    out["caller"] = caller
    rat, rblock = yaml_block(read(rs / "cluster" / "router-config.yaml"), rf"^\s*- model_name: {re.escape(m)}\s*$")
    api = re.search(r"api_base:\s*(\S+)", "\n".join(rblock))
    v.check(f"the router's model list: {m} on {plan['expect']['api_base']}, the model's Service", bool(api) and api.group(1) == plan["expect"]["api_base"],
            f"api_base {api.group(1) if api else 'none'}")
    out["router_line"] = rat
    svc = re.match(r"^https?://([^.]+)\.", plan["expect"]["api_base"]).group(1)
    try:
        sl = load(rs / "cluster" / f"endpointslices-{plan['serving']['namespace']}.json").get("items") or []
    except (OSError, ValueError):
        sl = []
    ready = sorted({a for x in sl if (x.get("metadata") or {}).get("labels", {}).get("kubernetes.io/service-name") == svc
                    for e in x.get("endpoints") or [] if (e.get("conditions") or {}).get("ready") for a in e.get("addresses") or []})
    srv = j.get("srv_ip")
    v.check(f"the Service {svc}: the server that answered ({srv or 'none'}) among its ready endpoints ({', '.join(ready) or 'none'}): the router "
            "names only the Service, and the Service's load balancing picked the copy", bool(srv) and srv in ready, f"ready {', '.join(ready) or 'none'}")
    out["service"] = svc
    return out


def judge_rail(v, rs: Path, plan: dict, j: dict, decs: dict) -> dict:
    copy = j.get("copy")
    v.sec("the rail switch: its counters and its MAC table")
    if not copy:
        v.bad("the copy that served the request", "none (above)")
        return {}
    sw = copy["switch"]
    out = {"switch": sw}
    st = stamps(rs)
    b, a = counters_table(read(rs / "rail" / f"{sw}-counters-before.txt")), counters_table(read(rs / "rail" / f"{sw}-counters-after.txt"))
    t0, t1 = (st.get((sw, "before")) or (None, None))[1], (st.get((sw, "after")) or (None, None))[0]
    mt = read(rs / "rail" / f"{sw}-mac-table.txt")
    macs = J.p_mac_table(mt)
    if not any(x["remote"] for x in copy["workers"]):
        # a node-local copy (build A revision 2: a copy that fits one node): its RPC never leaves the node
        port = next((p for p in copy["switch_ports"] if p["faces"] == copy["server"]["node"]), None)
        rpc = (plan.get("serving") or {}).get("rpc_port")
        fr = [f for f in decs.get(port["id"]) or [] if rpc in (f.get("sport"), f.get("dport"))] if port else []
        v.check(f"copy {copy['copy']} sits inside {copy['server']['node']}: its RPC to {', '.join(w['pod'] for w in copy['workers'])} stays in the "
                f"node's rail {copy['rail']} macvlan bridge, and {sw} {port['native'] if port else '?'} (facing {copy['server']['node']}) carried none "
                "of it", port is not None and not fr, f"{len(fr)} RPC frames on the port" if port else "no port facing the server's node in the plan")
        out.update(port=port["native"] if port else None, local=True, frames=len(fr))
        return out
    for w in [x for x in copy["workers"] if x["remote"]]:
        port = next((p for p in copy["switch_ports"] if p["faces"] == w["node"]), None)
        if port is None:
            v.bad(f"{sw}'s port facing {w['node']}", "not in the plan")
            continue
        nat = port["native"]
        fr = [f for f in decs.get(port["id"]) or [] if t0 is not None and t1 is not None and t0 <= f["t"] <= t1]
        rb, ra = b.get(nat) or {}, a.get(nat) or {}
        drx = (ra.get("rx_ok") or 0) - (rb.get("rx_ok") or 0) if ra and rb else None
        dtx = (ra.get("tx_ok") or 0) - (rb.get("tx_ok") or 0) if ra and rb else None
        v.check(f"{sw} {nat}, facing {w['node']} where {w['pod']} runs: show interface counters after the request reads RX_OK {ra.get('rx_ok')}, "
                f"TX_OK {ra.get('tx_ok')}, up from {rb.get('rx_ok')} and {rb.get('tx_ok')} after the clear: at least the {len(fr)} RPC frames "
                "its capture counted between the two reads",
                drx is not None and dtx is not None and drx > 0 and dtx > 0 and drx + dtx >= len(fr) and len(fr) > 0,
                "a counter table was not read" if drx is None else f"RX +{drx}, TX +{dtx}, {len(fr)} frames captured")
        out.update(port=nat, before_line=rb.get("line"), after_line=ra.get("line"), rx=drx, tx=dtx, frames=len(fr), worker=w)
        row = [r for r in macs if r[1] == (w.get("mac") or "").lower()]
        v.check(f"{sw}'s MAC table: {w['pod']}'s rail MAC {w.get('mac')} in VLAN {copy['vlan']} on {nat}: the table the rail bridges by",
                bool(row) and row[0][0] == copy["vlan"] and row[0][3] == nat, f"{row[0][0]} {row[0][3]}" if row else "not in the table")
        out["mac_line"] = line_of(mt, re.compile(re.escape(w.get("mac") or "-"), re.I))
    return out


def judge_refusals(v, rs: Path, plan: dict, inv: dict, pk: dict, j: dict, rows: list) -> dict:
    rf = plan["refusals"]
    caddr, gw = plan["client"]["address"], plan["gateway"]
    holder = ST.lease_holder(rs)
    pts = frontend_points(plan, rs, inv)
    legs = [p for p in pts if p["role"] == "leg"]
    out = {}
    keyed = {r[0]: ST.http_requests(read(rs / "captures" / f"{r[0]}-payload.txt")) for r in rows if len(r) > 8 and r[8]}
    ag_ids = [r[0] for r in rows if r[0].startswith(ST.pid(plan, 2, "")) and len(r) > 8 and r[8]]
    ro_ids = [r[0] for r in rows if r[0].startswith(ST.pid(plan, 3, "")) and len(r) > 8 and r[8]]
    pi = j.get("pi") or {}
    ag_ips = {pi[n]["ip"] for n in pi if pi[n].get("ip") and any(i.endswith(f"-{n}-eth0") for i in ag_ids)}
    tl443 = read(rs / "fw" / "traffic-log-443.txt")

    h = rf["hostname"]
    v.sec(f"refused at {h['layer']}: {h['hostname']} sent to {gw['name']}, which carries no route for it")
    res = read(rs / "request" / "refuse-result.txt").split()
    status = int(res[0]) if res and res[0].isdigit() else 0
    srv = ST.headers(read(rs / "request" / "refuse-headers.txt")).get("server", "")
    v.check(f"GET {h['url']} from port {h['sport']}: HTTP {h['expect']} from the Gateway (server {srv or 'none'}), no key sent",
            status == h["expect"] and "envoy" in srv.lower(), f"HTTP {status or 'none'}, server {srv or 'none'}")
    bid = ST.pid(plan, 1, f"{holder}-bond0") if holder else None
    sb = syns(pk.get(bid) or [], src=caddr, sport=h["sport"], dst=gw["vip"], dport=443) if bid else []
    e = PP.tlog_find(tl443, src=caddr, sport=h["sport"])
    v.check(f"... it crossed the firewall (the traffic log: {e[0]['rule'] if e else 'no line'}, {e[0]['action'] if e else '-'}) and reached the "
            f"Gateway's VIP on {holder or 'the lease holder'} (its SYN on bond0)", bool(sb) and bool(e) and e[0]["action"] == "allow",
            f"{len(sb)} SYNs at the lease holder, traffic log {'none' if not e else e[0]['rule']}")
    seen = [(pid_, r) for pid_ in ag_ids for r in keyed.get(pid_) or [] if (r["host"] or "").split(":")[0] == h["hostname"]
            or "sfab-trace-refused" in r["path"]]
    v.check(f"nothing past {h['layer']}: no request for {h['hostname']} at any of {len(ag_ids)} API gateway pods", not seen and bool(ag_ids),
            f"{len(seen)} requests" if ag_ids else "no API gateway pod captured")
    out["hostname"] = {"status": status, "server": srv, "tlog": e[0] if e else None, "syn": sb[0] if sb else None}

    k = rf["key"]
    v.sec(f"refused at {k['layer']}: {k['route_model']}'s route with {k['model']}'s key")
    res = read(rs / "request" / "refuse-key-result.txt").split()
    status = int(res[0]) if res and res[0].isdigit() else 0
    body = read(rs / "request" / "refuse-key-body.txt")
    try:
        msg = (json.loads(body) or {}).get("message")
    except ValueError:
        msg = None
    v.check(f"POST {k['url']} from port {k['sport']} with {k['model']}'s key: HTTP {k['expect']} with the unknown key's message ({k['message']})",
            status == k["expect"] and msg == k["message"], f"HTTP {status or 'none'}, message {msg!r}")
    km = ST.key_line(rs / "request" / f"key-{k['model']}.txt")
    got = [(pid_, r) for pid_ in ag_ids for r in keyed.get(pid_) or [] if r["method"] == "POST" and r["path"] == k["path"]
           and r["sport"] != 0 and ST.mark_in(r["authorization"]) == km["mark"] and km["mark"]]
    v.check(f"... read by {k['device']}: a POST on {k['path']} with Authorization {km['mark'] or '-'}, {k['model']}'s key "
            f"({km['field']} {km['fingerprint']})" + (f", at {got[0][0]}" if got else ""), bool(got), "no API gateway pod received it")
    to_router = [(pid_, r) for pid_ in ro_ids for r in keyed.get(pid_) or [] if r["src"] in ag_ips and r["method"] == "POST"]
    v.check(f"nothing past {k['layer']}: the router pods received {len(to_router)} request(s) from the API gateway in all, the walked one",
            len(to_router) == 1, ", ".join(f"{p} line {r['line']}" for p, r in to_router[:4]) or "none")
    out["key"] = {"status": status, "message": msg, "at": got[0] if got else None, "router": len(to_router)}

    p = rf["port"]
    v.sec(f"refused at {p['layer']}: {p['to']}'s port {p['port']} from {plan['client']['node']}")
    pr = read(rs / "refuse" / "port-result.txt").split()
    outcome = pr[4] if len(pr) > 4 else "none"
    v.check(f"the client's view: {outcome} after {pr[5] if len(pr) > 5 else '-'} s, from port {p['sport']} to {p['address']}:{p['port']} "
            "(recorded, not assumed)", bool(pr) and outcome != "CONNECTED" and outcome != "none", f"outcome {outcome}")
    cp = next(x for x in pts if x["role"] == "client")
    ip_ = next(x for x in pts if x["role"] == "ingress")
    at = {x["id"]: syns(pk.get(x["id"]) or [], src=caddr, sport=p["sport"], dst=p["address"], dport=p["port"])
          for x in pts + ([{"id": bid}] if bid else [])}
    v.check(f"its SYN on {cp['id']} and on the firewall's {ip_['ifname']} ({len(at[cp['id']])} and {len(at[ip_['id']])}, its retransmissions "
            "with it)", bool(at[cp["id"]]) and bool(at[ip_["id"]]), f"{len(at[cp['id']])} and {len(at[ip_['id']])}")
    past = [x for x, s in at.items() if s and x not in (cp["id"], ip_["id"])]
    v.check(f"nothing past {p['layer']}: no SYN on either leg ({', '.join(x['id'] for x in legs)}), at the pair or at the lease holder",
            not past, ", ".join(past))
    tl = read(rs / "fw" / f"traffic-log-{p['port']}.txt")
    e = PP.tlog_find(tl, src=caddr, sport=p["sport"], dst=p["address"], dport=p["port"])
    ex = p["expect"]
    v.check(f"the traffic log names {ex['rule']} (shown as {ex['rule'][:RULE_WIDTH]}), {ex['action']}, zone {ex['from_zone']} to zone {ex['to_zone']}",
            bool(e) and e[0]["rule"] == ex["rule"][:RULE_WIDTH] and e[0]["action"] == ex["action"] and e[0]["from"] == ex["from_zone"]
            and e[0]["to"] == ex["to_zone"], "no entry for the connect" if not e else f"{e[0]['rule']}, {e[0]['action']}, {e[0]['from']} to {e[0]['to']}")
    out["port"] = {"outcome": outcome, "took": pr[5] if len(pr) > 5 else None, "client_syns": len(at[cp["id"]]),
                   "fw_syns": len(at[ip_["id"]]), "tlog": e[0] if e else None, "client_point": cp["id"], "ingress_point": ip_["id"],
                   "first": (at[ip_["id"]] or [None])[0]}
    return out


def judge(a) -> int:
    rs = Path(a.set)
    plan = load(a.plan)
    inv = load(a.inv)
    v = vocab.Vocab(known=set(inv.get("known") or []) or None)
    holder = ST.lease_holder(rs)
    fe_rows = frontend_rows(plan, rs, inv)
    sv_rows = ST.point_rows(plan, rs)
    rows = fe_rows + sv_rows
    texts = {r[0]: read(rs / "captures" / f"{r[0]}.txt") for r in rows}
    decs = {k: ST.frames(t) for k, t in texts.items()}
    pk = {k: packets(t) for k, t in texts.items()}
    names = judge_names(v, rs, plan)
    fw = judge_firewall(v, rs, plan)
    wire = judge_wire(v, rs, plan, inv, pk, holder)
    pair = judge_pair(v, rs, plan, inv, holder, wire)
    j = ST.judge_serving(v, rs, plan, sv_rows, decs)
    keyhops = ST.judge_keys(v, rs, plan, sv_rows, j["pi"], j["agp"], j["rop"], j["srv_ip"])
    cl = judge_cluster(v, rs, plan, inv, holder, j)
    rail = judge_rail(v, rs, plan, j, decs)
    ref = judge_refusals(v, rs, plan, inv, pk, j, rows)
    counts = vocab.counts_of(os.environ["SFAB_VERDICT"]) if os.environ.get("SFAB_VERDICT") else v.counts()
    write_md(rs, inv, plan, rows, decs, holder, names, fw, wire, pair, j, keyhops, cl, rail, ref, counts, a.stamp)
    return 1 if v.counts()["fail"] else 0


# --------------------------------------------------------------------------------------------
# TRACE.md


def _frame_cite(point, f) -> str:
    return f"`captures/{point}.txt:{f['line']}`" if point and f else "-"


def hop_table(rs: Path, plan: dict, holder, names, fw, wire, pair, j, keyhops, cl, rail) -> list:
    d, f, gw = plan["dns"], plan["firewall"], plan["gateway"]
    c = plan["client"]["node"]
    rows = []
    cd = names["client"]
    ans = next((x for x in cd["answers"] if x["name"] == d["hostname"]), None)
    rows.append(("1", c, "its resolver (resolv.conf)", f"asks {d['server']} ({d['resolver']}) for {d['hostname']}",
                 cite("dns/client-dig.txt", cd["server_line"])))
    rows.append(("2", f"{d['resolver']}, the resolver, and {d.get('authority') or 'the authoritative server'}",
                 f"view {d['view']} (the resolver's source address)", f"A {ans['address'] if ans else '-'}, "
                 f"{gw['name']}'s VIP", cite("dns/client-dig.txt", ans["line"] if ans else None)))
    rt = fw.get("route")
    rows.append(("3", f"{f['node']}, in on {f['ingress']} (zone {f['ingress_zone']})", f"routing table, virtual router {f['vr']}",
                 f"{rt['dest'] if rt else '-'} connected on {f['egress']}: zone {f['egress_zone']}", cite("fw/routing-route.txt", rt["line"] if rt else None)))
    rows.append(("4", f["node"], "NAT rulebase", f"no rule from zone {f['ingress_zone']}: no translation", cite("fw/running-nat-policy.txt", None)))
    sess = fw.get("session") or {}
    det = read(rs / "sessions" / "walk" / "session-detail.txt")
    tlog = sess.get("tlog")
    rows.append(("5", f["node"], "security rulebase", f"{f['rule']}: allow TCP 443 to {gw['vip']}",
                 cite("sessions/walk/session-detail.txt", line_of(det, rf"^\s*rule\s+:\s+{re.escape(f['rule'])}")) + ", "
                 + cite("sessions/walk/traffic-log.txt", tlog["line"] if tlog else None)))
    leg = wire.get("leg")
    if leg:
        sl = wire["seen"].get(leg["id"])
        rows.append(("6", f"{f['node']}, out on {f['egress']} over {leg['ifname']}", f"{f['bundle']}'s LACP hash",
                     f"leg {leg['leg']}, tagged {f['tag']}, TTL {sl['ttl']}", _frame_cite(leg["id"], sl)))
    sp = wire.get("server_port")
    if sp:
        sw = sp["node"]
        pl = (pair.get(sw) or {})
        rows.append(("7", f"{sw}, a pair member", f"MAC table, VLAN {f['tag']}", f"{holder}'s bond MAC on {pl.get('iface') or '-'}: bridged out "
                     f"{sp['native']} {'tagged ' + str(sp['vlan']) if sp.get('vlan') else 'untagged'}, no address, no route", cite(f"pair/{sw}-mac-table.txt", pl.get("line")) + ", "
                     + _frame_cite(sp["id"], wire["seen"].get(sp["id"]))))
    bid = wire.get("bond")
    rows.append(("8", f"{holder}, the lease holder", f"the lease {gw['lease']}", f"answers for {gw['vip']} on its unit in the Gateway VLAN",
                 cite("cluster/lease.txt", cl.get("lease_line")) + (", " + _frame_cite(bid, wire["seen"].get(bid)) if bid else "")))
    rt_ = cl.get("route") or {}
    rows.append(("9", f"{gw['name']}, the Gateway", f"HTTPRoute {rt_.get('route', '-')}, rule {rt_.get('rule', '-')}",
                 f"{plan['hostname']} and {rt_.get('path', '-')}: to Service {rt_.get('backend', '-')}", "`cluster/httproutes.json`"))
    k1 = next((x for x in keyhops if x["hop"].startswith("1:")), None)
    k2 = next((x for x in keyhops if x["hop"].startswith("2:")), None)
    hp = {x["hop"]: x for x in j.get("hops") or []}
    ag = hp.get("API gateway")
    rows.append(("10", f"{ag['pod'] if ag else '-'}, the API gateway", f"its route for {plan['model']}: key authentication, consumer group "
                 f"{cl.get('caller') or plan['model']}", f"the caller's key accepted ({k1['mark'] if k1 else '-'}); the router's master key set in its place",
                 cite("cluster/api-gateway-routes.yaml", cl.get("routes_line")) + (f", `captures/{k1['point']}-payload.txt:{k1['request'].get('auth_line') or k1['request']['line']}`" if k1 else "")
                 + (f", `captures/{k2['point']}-payload.txt:{k2['request'].get('auth_line') or k2['request']['line']}`" if k2 else "")))
    ro = hp.get("router")
    hd = read(rs / "request" / "headers.txt")
    rows.append(("11", f"{ro['pod'] if ro else '-'}, the router", "its model list", f"{plan['model']} on the Service {cl.get('service', '-')}",
                 cite("cluster/router-config.yaml", cl.get("router_line")) + ", " + cite("request/headers.txt", line_of(hd, r"(?i)^x-litellm-model-api-base:"))))
    cp = j.get("copy")
    sv = hp.get("server")
    if cp:
        rows.append(("12", f"the Service {cl.get('service', '-')}", "its EndpointSlices (the ready servers)",
                     f"{cp['server']['pod']}, {plan['model']}'s copy {cp['copy']}", f"`cluster/endpointslices-{plan['serving']['namespace']}.json`"))
        rows.append(("13", f"{cp['server']['pod']} on {cp['server']['node']}", f"the placement table: {plan['model']}-{cp['copy']} on rail {cp['rail']}",
                     f"RPC to its workers over {cp['nad']}, fixed before the request", _frame_cite(sv["point"], sv.get("first")) if sv else "-"))
    if rail.get("port") and rail.get("local") and cp:
        # a node-local copy: the rail switch port facing its node carried none of its RPC
        rows.append(("14", f"{rail['switch']}, a rail switch", f"its port {rail['port']}, facing {cp['server']['node']}",
                     f"no RPC frame: copy {cp['copy']}'s RPC stays in the node's rail {cp['rail']} macvlan bridge",
                     cite(f"rail/{rail['switch']}-counters-after.txt", None)))
    elif rail.get("port"):
        w = rail["worker"]
        rows.append(("14", f"{rail['switch']}, a rail switch", f"MAC table, VLAN {cp['vlan']}", f"{w['pod']}'s MAC on {rail['port']}: bridged, "
                     "no address, no route", cite(f"rail/{rail['switch']}-mac-table.txt", rail.get("mac_line")) + ", "
                     + cite(f"rail/{rail['switch']}-counters-after.txt", rail.get("after_line"))))
    return rows


def write_md(rs: Path, inv: dict, plan: dict, rows: list, decs: dict, holder, names, fw, wire, pair, j, keyhops, cl, rail, ref, counts, stamp):
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    verdict = read(rs / "verdict.txt")
    gw, rf = plan["gateway"], plan["refusals"]
    h = j.get("headers") or {}
    L = ["# Request walk", "",
         f"- Lab: `{inv.get('lab')}`; labs repo commit `{commit}`{uncommitted}; UTC {run.get('utc_start') or 'unknown'}",
         f"- One chat completion from {plan['client']['node']} ({plan['client']['address']}, source port {plan['sport']}) to `{plan['url']}` "
         f"through {gw['name']} ({gw['vip']}), with {plan['model']}'s key, held {plan['sessions'][0]['hold_s']} s after its answer; "
         f"{len(rows)} capture points",
         f"- Answer: HTTP {j.get('status') or 'none'}; the router's deployment `{h.get('x-litellm-model-name', '-')}` on "
         f"`{h.get('x-litellm-model-api-base', '-')}`, retries {h.get('x-litellm-attempted-retries', '-')}"]
    if stamp:
        L.append(f"- {stamp}")
    # chapter 2 on: each hop and refusal tagged with the row of the decision table that decides there
    tags = plan.get("rows") or {}
    layers, hrow = tags.get("layers") or {}, tags.get("hops") or {}
    rrow = tags.get("refusals") or {}

    def row(rid):
        return layers.get(rid, "-") if rid and rid != "-" else "-"

    if tags:
        L += ["", "## Hops, devices, tables and decisions", "", "| Hop | Row | Device | Table it consults | Decision | Evidence |",
              "|---|---|---|---|---|---|"]
    else:
        L += ["", "## Hops, devices, tables and decisions", "", "| Hop | Device | Table it consults | Decision | Evidence |", "|---|---|---|---|---|"]
    for r in hop_table(rs, plan, holder, names, fw, wire, pair, j, keyhops, cl, rail):
        L.append("| " + " | ".join((r[0], row(hrow.get(r[0]))) + tuple(r[1:]) if tags else r) + " |")
    if tags:
        L += ["", "## Three refused requests", "", "| Request | Row | Where it died | What the client got | Evidence | Nothing past it |",
              "|---|---|---|---|---|---|"]
    else:
        L += ["", "## Three refused requests", "", "| Request | Where it died | What the client got | Evidence | Nothing past it |", "|---|---|---|---|---|"]
    first_refusal = len(L)
    hn, ky, pt = ref.get("hostname") or {}, ref.get("key") or {}, ref.get("port") or {}
    L.append(f"| `{rf['hostname']['url']}`, no key, port {rf['hostname']['sport']} | {rf['hostname']['layer']}, {gw['name']} | HTTP "
             f"{hn.get('status') or 'none'}, server {hn.get('server') or 'none'} | `request/refuse-headers.txt`, "
             f"{cite('fw/traffic-log-443.txt', (hn.get('tlog') or {}).get('line'))} | no API gateway pod received it |")
    at = ky.get("at")
    L.append(f"| {plan['model']}'s route with {rf['key']['model']}'s key, port {rf['key']['sport']} | {rf['key']['layer']}, "
             f"{at[0].split('-', 1)[1].rsplit('-eth0', 1)[0] if at else rf['key']['device']} | HTTP {ky.get('status') or 'none'}, `{ky.get('message')}` | "
             f"`request/refuse-key-body.txt`" + (f", `captures/{at[0]}-payload.txt:{at[1].get('auth_line') or at[1]['line']}`" if at else "")
             + f" | the router pods received {ky.get('router', '-')} request in all, the walked one |")
    L.append(f"| {rf['port']['to']} ({rf['port']['address']}) TCP {rf['port']['port']}, port {rf['port']['sport']} | {rf['port']['layer']}, "
             f"{rf['port']['expect']['rule']} | {pt.get('outcome', 'none')} after {pt.get('took') or '-'} s | "
             f"{_frame_cite(pt.get('ingress_point'), pt.get('first'))}, {cite('fw/traffic-log-' + str(rf['port']['port']) + '.txt', (pt.get('tlog') or {}).get('line'))} | "
             "no SYN on either bundle leg |")
    if tags:
        for k, rid in zip(range(first_refusal, len(L)), ("hostname", "key", "port")):
            head, rest = L[k].split(" | ", 1)
            L[k] = f"{head} | {row(rrow.get(rid))} | {rest}"
    L += ["", "## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", ""]
    L += ["## Frames per point", "", "| Point | Kind | Node | Interface | Filter | Frames | Data segments |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        fr = decs.get(r[0]) or []
        L.append(f"| `{r[0]}` | {r[1]} | {r[2]} | {r[5]} | `{r[6]}` | {len(fr)} | {sum(1 for f in fr if f['length'] > 0)} |")
    L += ["", "## Files", "",
          "- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`",
          "- `dns/`: the client's lookup through its resolver, and the resolver's own from its address",
          "- `fw/`: the routing table, the security and NAT rulebases (one CLI session), and the traffic log read for the refused requests",
          "- `sessions/walk/`: the held request's reply and its session as `show session all` and `show session id` print it (CLI and XML), "
          "and its traffic log line",
          "- `pair/`, `rail/`: the MAC tables, the rail switches' counters cleared, read before and after the request, and the times of each read",
          "- `cluster/`: the pods, the lease, the EndpointSlices, every HTTPRoute, the API gateway's routes and the router's model list",
          "- `request/`: the warm-up's and the request's status, response headers and body, the refused requests' answers, and each key "
          "named by field, fingerprint and mark; no request header is saved",
          "- `refuse/`: the refused connect, as the client saw it",
          "- `captures/<point>.pcap` and `.txt`, decoded with `tcpdump -nn -tt -e -v -S -r` (a guest's and a pod's in the guest); the API "
          "gateway's and the router's pods captured whole, each pcap scrubbed of its keys on its way out of the guest and decoded on the lab "
          "host, with `-A` as `<point>-payload.txt`",
          "", vocab.result_line(counts), ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="walktrace")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("points")
    s.add_argument("--plan", required=True)
    s.add_argument("--set", required=True)
    s.add_argument("--inv", required=True)
    s = sub.add_parser("cmdata")
    s.add_argument("--key", required=True)
    s = sub.add_parser("split-reply")
    s.add_argument("--set", required=True)
    s = sub.add_parser("tlog-has")
    s.add_argument("--file", required=True)
    s.add_argument("--src", required=True)
    s.add_argument("sports", nargs="+")
    s = sub.add_parser("judge")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--inv", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"get": cmd_get, "points": cmd_points, "cmdata": cmd_cmdata, "split-reply": cmd_split_reply, "tlog-has": cmd_tlog_has,
            "judge": judge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
