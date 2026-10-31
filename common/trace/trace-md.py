#!/usr/bin/env python3
"""trace-md.py: a chapter trace's planning and judgment (common/trace/lib-trace.sh; FRAMEWORK.md 4.5).

    trace-md.py flow   --inv INV [--k8s gen/k8s.json] [--flow ID]   shell assignments for one flow
    trace-md.py holder --leases FILE --namespace NS --gateway GW [--lease NS/NAME]
    trace-md.py points --inv INV --holder NODE               the capture points, one per line
    trace-md.py syn    --decode FILE --sport N --vip ADDR    the first matching SYN's seq, or nothing
    trace-md.py judge  --set DIR --inv INV --points FILE --env FILE [--stamp TEXT]

Promoted from milestone M2's trace (dev/m2/trace-md.py, which keeps its own copy as recorded) and
generalized for chapter traces: the client need not be a capture point, and a flow with
same_frame: true is also judged as one frame at every point that carries it.

flow resolves a flow of the chapter's trace block (inventory "trace") against the inventory: the
client and its address, the Gateway, its VIP and namespace, the URL and the expected verdict. points
expands the points, a point with "at: lease-holder" for the control node that holds the Gateway's
L2 announcement lease: "side: pair" for the pair ports facing that node's bond, "iface:" for an
interface inside it (captured and decoded in the guest). Each output line is tab-separated:

    id  where (container or guest)  node  interface  vlan (none or a tag)  group  depth

judge reads the decodes (captures/<id>.txt, tcpdump -nn -e -tttt -v -S -r) and the other saved
files, prints the result vocabulary (appending to $SFAB_VERDICT), and writes TRACE.md. The recorded
SYN is the client's SYN from the pinned source port, found at the client's own point when the trace
has one, else at the first point (in depth order) that saw it; at every other point the SYN with
the same sequence number is that SYN, whatever its addresses, so a translation would show as a
changed address and never as a missing frame. With same_frame, the frame must also carry the same
source and destination MACs, addresses, IP id and TTL at every point that saw it, and its
destination MAC must be the lease holder's bond MAC from the inventory: nothing on the way
rewrote it, so nothing on the way routed it. Standard library only; it reads no device.
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
import vocab  # noqa: E402

FW_RULE_WIDTH = 19      # PAN-OS cuts rule names to 19 characters in the CLI traffic log


def natural(s: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"([0-9]+)", s)]


def bare(a):
    return None if a is None else str(a).split("/")[0]


def load(p):
    """A JSON file, stored plain or compressed (NAME.gz, evfile.py)."""
    return json.loads(evfile.read_text(p, "strict"))


# --------------------------------------------------------------------------------------------
# the flow and the points


def flow_of(inv: dict, fid: str | None, names: dict | None = None) -> dict:
    tr = inv.get("trace") or {}
    flows = tr.get("flows") or []
    if not flows:
        raise SystemExit("trace-md: the chapter's trace block names no flow")
    f = next((x for x in flows if x.get("id") == fid), None) if fid else flows[0]
    if f is None:
        raise SystemExit(f"trace-md: no flow {fid}")
    nodes = inv.get("nodes") or {}
    c = nodes.get(f["client"])
    if c is None:
        raise SystemExit(f"trace-md: the flow's client {f['client']} is not in this lab")
    gw = (inv.get("gateways") or {}).get(f["gateway"])
    if not gw:
        raise SystemExit(f"trace-md: the inventory has no Gateway {f['gateway']} (its gateways block)")
    dom = (inv.get("org") or {}).get("zone") or (inv.get("org") or {}).get("domain")
    ex = f.get("expect") or {}
    path = f.get("path") or "/"
    m = re.search(r"[?&]msg=([^&]+)", path)
    return {
        "FLOW": f["id"], "CLIENT": f["client"], "CLIENT_ADDR": bare(c.get("address")),
        "GATEWAY": f["gateway"], "VIP": gw["vip"], "GW_NS": (inv.get("k8s") or {}).get("gateway_namespace") or "",
        "FQDN": f"{f['hostname']}.{dom}", "PORT": str(f.get("port") or 443), "URLPATH": path,
        "MSG": m.group(1) if m else "", "SPORT": str(f.get("sport") or 41443), "WARM_SPORT": str(f.get("warm_sport") or 41442),
        "WANT_STATUS": str(ex.get("status") or 200), "RULE": ex.get("rule") or "", "FROM_ZONE": ex.get("from_zone") or "",
        "TO_ZONE": ex.get("to_zone") or "", "TTL_DROP_AFTER": str(f.get("ttl_drop_after") or 0),
        "SAME_FRAME": "1" if f.get("same_frame") else "0",
        # the Gateway Service's L2 announcement lease, by gen/k8s.json's name when it is rendered
        "L2_LEASE": (((names or {}).get("gateways") or {}).get(f["gateway"]) or {}).get("l2_lease") or "",
    }


def cmd_flow(a) -> int:
    names = {}
    if a.k8s:
        try:
            names = load(a.k8s)
        except (OSError, ValueError):
            names = {}
    for k, v in flow_of(load(a.inv), a.flow, names).items():
        print(f"{k}={shlex.quote(str(v))}")
    return 0


def holder_of(leases: dict, ns: str, gw: str, lease: str = ""):
    """The node holding the Cilium L2 announcement lease of the Gateway's Service: the lease
    gen/k8s.json names (<namespace>/<name>), else cilium-l2announce-<namespace>-cilium-gateway-<gateway>."""
    want = lease.split("/", 1)[-1] if lease else (f"cilium-l2announce-{ns}-cilium-gateway-{gw}" if ns else None)
    for item in leases.get("items") or []:
        name = (item.get("metadata") or {}).get("name") or ""
        if (want and name == want) or (not want and name.startswith("cilium-l2announce-") and name.endswith(f"-cilium-gateway-{gw}")):
            return (item.get("spec") or {}).get("holderIdentity")
    return None


def cmd_holder(a) -> int:
    try:
        h = holder_of(load(a.leases), a.namespace, a.gateway, a.lease)
    except (OSError, ValueError):
        h = None
    if h:
        print(h)
    return 0 if h else 1


def points_of(inv: dict, holder: str | None) -> list:
    nodes = inv.get("nodes") or {}
    out = []
    for p in (inv.get("trace") or {}).get("points") or []:
        pid = str(p["id"])
        depth = int(re.match(r"^(\d+)", pid).group(1)) if re.match(r"^(\d+)", pid) else 0
        vlan = str(p.get("vlan", "none"))
        group = p.get("group") or "-"
        if p.get("at") == "lease-holder":
            if not holder or holder not in nodes:
                raise SystemExit(f"trace-md: point {pid} needs the lease holder, and none is known")
            h = nodes[holder]
            if p.get("side") == "pair":
                bond = h.get("bond") or {}
                for m in bond.get("members") or []:
                    peer = (h.get("nics") or {}).get(m, {}).get("peer")
                    if not peer:
                        continue
                    sw, eth = peer.split(":", 1)
                    native = ((nodes.get(sw) or {}).get("nics") or {}).get(eth, {}).get("native") or eth
                    out.append((pid.format(switch=sw, native=native, holder=holder), "container", sw, eth, vlan, group, depth))
            elif p.get("iface"):
                where = "guest" if h.get("kind") == "vm-node" else "container"
                out.append((pid.format(holder=holder), where, holder, p["iface"], vlan, group, depth))
            continue
        n = nodes.get(p["node"])
        if n is None:
            raise SystemExit(f"trace-md: point {pid}: no node {p['node']} in this lab")
        where = "guest" if n.get("kind") == "vm-node" else "container"
        out.append((pid, where, p["node"], p.get("iface") or p["eth"], vlan, group, depth))
    return out


def cmd_points(a) -> int:
    for row in points_of(load(a.inv), a.holder or None):
        print("\t".join(map(str, row)))
    return 0


# --------------------------------------------------------------------------------------------
# reading the decodes

PKT = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+) ([0-9a-f:]{17}) > ([0-9a-f:]{17}), (.*)$")
TCP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]")


def packets(text: str) -> list:
    """tcpdump -nn -e -tttt -v -S -r: one dict per frame, with the 1-based line its header is on."""
    out, cur = [], None
    for i, line in enumerate((text or "").splitlines(), 1):
        if line[:1] in (" ", "\t") and cur is not None:
            cur["raw"] += " " + line.strip()
            continue
        m = PKT.match(line)
        if not m:
            continue
        cur = {"ts": m.group(1), "src_mac": m.group(2), "dst_mac": m.group(3), "raw": m.group(4), "line": i, "head": line}
        out.append(cur)
    for p in out:
        r = p["raw"]
        v = re.search(r"\bvlan (\d+), p \d+", r)
        p["vlan"] = int(v.group(1)) if v else None
        t = re.search(r"\bttl (\d+)\b", r)
        p["ttl"] = int(t.group(1)) if t else None
        i = re.search(r"\bttl \d+, id (\d+)\b", r)
        p["ipid"] = int(i.group(1)) if i else None
        m = TCP.search(r)
        if m:
            p.update(src=m.group(1), sport=int(m.group(2)), dst=m.group(3), dport=int(m.group(4)), flags=m.group(5))
        s = re.search(r"\bseq (\d+)\b", r)
        p["seq"] = int(s.group(1)) if s else None
        ck = re.search(r"\bcksum 0x[0-9a-f]+ \(([^)]*)\)", r)
        p["cksum"] = ck.group(1) if ck else None
    return out


def first_syn(pkts: list, sport=None, vip=None, seq=None):
    for p in pkts:
        if p.get("flags") != "S":
            continue
        if seq is not None and p.get("seq") == seq:
            return p
        if seq is None and p.get("sport") == sport and (vip is None or p.get("dst") == vip):
            return p
    return None


def cmd_syn(a) -> int:
    try:
        text = Path(a.decode).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 1
    p = first_syn(packets(text), sport=int(a.sport), vip=a.vip)
    if p is None or p.get("seq") is None:
        return 1
    print(p["seq"])
    return 0


def http_reply(text: str):
    lines = (text or "").replace("\r", "").split("\n")
    starts = [i for i, l in enumerate(lines) if re.match(r"^HTTP/[0-9.]+ \d{3}\b", l)]
    if not starts:
        return None, ""
    i = starts[-1]
    j = i + 1
    while j < len(lines) and lines[j].strip():
        j += 1
    return int(lines[i].split()[1]), "\n".join(lines[j + 1:])


def tlog_entries(text: str) -> list:
    """The PAN-OS CLI traffic log: one token list per entry (an entry starts with its date)."""
    out, cur = [], None
    for line in (text or "").splitlines():
        if re.match(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\b", line):
            cur = line.split()
            out.append(cur)
        elif cur is not None and not re.match(r"^(Time|Rule|Src User|Rule_UUid|=+|admin@)", line.strip()):
            cur.extend(line.split())
    return out


def tlog_find(text: str, src, sport, dst, dport):
    """The entry of that connection, as {from, rule, action, to, tokens}, or None. An entry reads
    <date> <time> <app> <from zone> <sport> <source> <rule> <action> <to zone> <dport> <destination>
    and then the users, the end reason and the rule's uuid; it is found by its source port and
    source address, so an application name of any length is read the same."""
    for t in tlog_entries(text):
        for k in range(1, len(t) - 6):
            if t[k] == str(sport) and t[k + 1] == src and t[k + 5] == str(dport) and t[k + 6] == dst:
                return {"from": t[k - 1], "rule": t[k + 2], "action": t[k + 3], "to": t[k + 4], "tokens": t}
    return None


# --------------------------------------------------------------------------------------------
# judgment and TRACE.md


def read(p: Path) -> str | None:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return None


def judge(a) -> int:
    rs = Path(a.set)
    inv = load(a.inv)
    env = {}
    for line in Path(a.env).read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k] = shlex.split(v)[0] if v else ""
    pts = []
    for line in Path(a.points).read_text(encoding="utf-8").splitlines():
        f = line.split("\t")
        if len(f) >= 7:
            pts.append({"id": f[0], "where": f[1], "node": f[2], "iface": f[3], "vlan": f[4], "group": f[5], "depth": int(f[6])})
    v = vocab.Vocab(known=set(inv.get("known") or []) or None)
    nodes = inv.get("nodes") or {}
    client, caddr, vip = env["CLIENT"], env["CLIENT_ADDR"], env["VIP"]
    sport, port = int(env["SPORT"]), int(env["PORT"])
    holder = env.get("HOLDER") or ""

    v.sec(f"trace {env['FLOW']}: {client} ({caddr}) to {env['FQDN']} on {vip}:{port}")
    dns = read(rs / "dns.txt")
    answers = [l.strip() for l in (dns or "").splitlines() if re.match(r"^\d+\.\d+\.\d+\.\d+$", l.strip())]
    resolver = bare((nodes.get(client) or {}).get("resolver_address"))
    v.chk(f"{client} resolves {env['FQDN']} through {resolver or 'its resolver'} to the users' VIP {vip}", vip, ",".join(answers) or "no answer")
    # the nodes the L2 announcement policy selects: its role (k8s.l2_announce.nodes), the control
    # nodes by default, the ingress nodes in revision 2
    k8s_ = inv.get("k8s") or {}
    role = str((k8s_.get("l2_announce") or {}).get("nodes") or "control")
    announcers = list(k8s_.get("control") or []) if role == "control" else \
        [n for n in list(k8s_.get("control") or []) + list(k8s_.get("workers") or []) if (nodes.get(n) or {}).get("group") == role]
    art = "an" if role[:1] in "aeiou" else "a"
    v.check(f"the {env['GATEWAY']} Service's L2 announcement lease holder is {art} {role} node ({holder or 'none'})",
            holder in announcers, f"holder {holder or 'unknown'}")
    warm = read(rs / "warmup.txt")
    wc, _ = http_reply(warm or "")
    v.ok(f"warm-up attempt from source port {env['WARM_SPORT']} made first (HTTP {wc if wc else 'no reply'}; not judged)")

    # the recorded SYN at the client, then the same sequence number everywhere
    decodes = {p["id"]: packets(read(rs / "captures" / f"{p['id']}.txt") or "") for p in pts}
    # the recorded SYN: at the client's own point when the trace has one, else at the first point
    # (in depth order) that saw a SYN from the pinned source port to the VIP
    order = [p for p in pts if p["node"] == client] + sorted((p for p in pts if p["node"] != client), key=lambda p: p["depth"])
    first, syn0 = None, None
    for p in order:
        s0 = first_syn(decodes.get(p["id"], []), sport=sport, vip=vip)
        if s0 is not None:
            first, syn0 = p, s0
            break
        if p["node"] == client:
            first = p
            break
    seq = syn0.get("seq") if syn0 else None
    where0 = client if first is not None and first["node"] == client else (first["id"] if first else "any point")
    v.check(f"the recorded SYN from {client}'s pinned source port {sport} found at {where0} (seq {seq})",
            syn0 is not None and seq is not None, f"no SYN from port {sport} at {first['id'] if first else 'any point'}")
    rows = []
    for p in pts:
        pk = decodes.get(p["id"], [])
        s = first_syn(pk, seq=seq) if seq is not None else None
        n_syn = sum(1 for x in pk if x.get("flags") == "S" and x.get("seq") == seq) if seq is not None else 0
        rows.append(dict(p, frames=len(pk), syns=n_syn, syn=s, decoded=(rs / "captures" / f"{p['id']}.txt").is_file()))
    v.ok(f"{len(rows)} capture points decoded ({sum(1 for r in rows if r['decoded'])} with a decode)")

    v.sec("the SYN at each point")
    groups: dict = {}
    for r in rows:
        if r["group"] != "-":
            groups.setdefault(r["group"], []).append(r)
            continue
        v.check(f"{r['id']}: the recorded SYN seen (seq {seq})", r["syn"] is not None,
                f"{r['frames']} frames, none with seq {seq}" if r["decoded"] else "no decode")
    for g, members in groups.items():
        seen = [r["id"] for r in members if r["syn"] is not None]
        v.check(f"exactly one of the {g} points carries the SYN ({', '.join(r['id'] for r in members)})", len(seen) == 1,
                f"seen at {', '.join(seen) or 'none'}")
    # the trunk port the SYN crossed is the one its ae1 leg lands on
    by_group = {g: next((r for r in m if r["syn"] is not None), None) for g, m in groups.items()}
    leg, trunk = by_group.get("ae1"), by_group.get("trunk")
    if leg and trunk:
        peer = ((nodes.get(leg["node"]) or {}).get("nics") or {}).get(leg["iface"], {}).get("peer")
        v.chk(f"the SYN's trunk port is the pair port its ae1 leg lands on ({leg['id']} to {peer})", peer, f"{trunk['node']}:{trunk['iface']}")
    srv = by_group.get("server")
    if srv and trunk:
        v.chk(f"the SYN leaves the pair on the switch that received it ({trunk['node']})", trunk["node"], srv["node"])

    v.sec("tags, TTL and addresses")
    for r in rows:
        s = r["syn"]
        if s is None:
            continue
        want = None if r["vlan"] in ("none", "", "None") else int(r["vlan"])
        v.check(f"{r['id']}: " + ("untagged" if want is None else f"tagged 802.1Q {want}"), s.get("vlan") == want,
                f"vlan {s.get('vlan')}" if s.get("vlan") is not None else "untagged")
    drop = int(env.get("TTL_DROP_AFTER") or 0)
    seen_rows = [r for r in rows if r["syn"] is not None and r["syn"].get("ttl") is not None]
    if seen_rows and drop:
        t0 = seen_rows[0]["syn"]["ttl"]
        before = [r for r in seen_rows if r["depth"] <= drop]
        after = [r for r in seen_rows if r["depth"] > drop]
        bad_b = [f"{r['id']} {r['syn']['ttl']}" for r in before if r["syn"]["ttl"] != t0]
        bad_a = [f"{r['id']} {r['syn']['ttl']}" for r in after if r["syn"]["ttl"] != t0 - 1]
        v.check(f"TTL {t0} up to the firewall, {t0 - 1} after it: one routed hop", bool(after) and not bad_b and not bad_a,
                "; ".join(bad_b + bad_a) or "no point after the firewall saw the SYN")
    changed = [f"{r['id']} {r['syn'].get('src')} > {r['syn'].get('dst')}" for r in seen_rows
               if (r["syn"].get("src"), r["syn"].get("dst"), r["syn"].get("dport")) != (caddr, vip, port)]
    v.check(f"source {caddr} and destination {vip}:{port} unchanged at every point (no translation)", bool(seen_rows) and not changed,
            "; ".join(changed))

    if env.get("SAME_FRAME") == "1":
        same_frame(v, inv, holder, seen_rows)

    v.sec("the reply and the firewall's witness")
    code, body = http_reply(read(rs / "request.txt") or "")
    want_code = int(env.get("WANT_STATUS") or 200)
    v.check(f"https://{env['FQDN']}{env['URLPATH']} answers {want_code}" + (f" with the echoed message {env['MSG']}" if env.get("MSG") else ""),
            code == want_code and (not env.get("MSG") or env["MSG"] in body), f"HTTP {code}" if code else "no HTTP reply")
    tl = read(rs / "fw-traffic-log.txt")
    rule = env.get("RULE") or ""
    if rule:
        e = tlog_find(tl or "", caddr, sport, vip, port)
        want_rule = rule[:FW_RULE_WIDTH]
        ok_ = bool(e) and e["rule"] == want_rule and e["action"] == "allow" and e["from"] == env.get("FROM_ZONE") and e["to"] == env.get("TO_ZONE")
        v.check(f"the firewall's traffic log has the session allowed by {rule} (shown as {want_rule}), zone {env.get('FROM_ZONE')} to zone {env.get('TO_ZONE')}",
                ok_, "no entry for the connection" if not e else f"rule {e['rule']}, {e['action']}, {e['from']} to {e['to']}")

    counts = vocab.counts_of(os.environ["SFAB_VERDICT"]) if os.environ.get("SFAB_VERDICT") else v.counts()
    write_md(rs, inv, env, rows, seq, code, counts, a.stamp)
    return 1 if v.counts()["fail"] else 0


def same_frame(v, inv: dict, holder: str, seen_rows: list) -> None:
    """One frame at every point that saw the SYN: the same MACs, addresses, IP id and TTL, and the
    lease holder's bond MAC as its destination (common to every chapter trace with same_frame)."""
    v.sec("one frame at every point")
    if not seen_rows:
        v.bad("one frame at every point", "no point saw the SYN")
        return
    fields = (("source MAC", "src_mac"), ("destination MAC", "dst_mac"), ("source address", "src"),
              ("destination address", "dst"), ("IP id", "ipid"), ("TTL", "ttl"))
    for label, key in fields:
        vals = {r["syn"].get(key) for r in seen_rows}
        got = ", ".join(f"{r['id']} {r['syn'].get(key)}" for r in seen_rows)
        val = seen_rows[0]["syn"].get(key)    # as the first point that saw it (the firewall's leg)
        v.check(f"{label} {val} the same at all {len(seen_rows)} points that saw the SYN",
                len(vals) == 1 and None not in vals, got)
    want = (((inv.get("nodes") or {}).get(holder) or {}).get("bond") or {}).get("mac")
    if want:
        got = seen_rows[0]["syn"].get("dst_mac")
        v.chk(f"destination MAC is {holder}'s bond0 MAC {want.lower()} (the frame is addressed to the node, not to a router)",
              want.lower(), got or "absent")
    else:
        v.bad("destination MAC is the lease holder's bond MAC", f"the inventory names no bond MAC for {holder or 'the holder'}")


def write_md(rs: Path, inv: dict, env: dict, rows: list, seq, code, counts: dict, stamp: str | None) -> None:
    run = {}
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        pass
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    verdict = read(rs / "verdict.txt") or ""
    L = [f"# Trace {env['FLOW']}", "",
         f"- Lab: `{inv.get('lab')}`; labs repo commit `{commit}`{uncommitted}; UTC {run.get('utc_start') or 'unknown'}",
         f"- Flow: `{env['CLIENT']}` ({env['CLIENT_ADDR']}) to `https://{env['FQDN']}{env['URLPATH']}` on {env['VIP']}:{env['PORT']} "
         f"(Gateway `{env['GATEWAY']}`), source port {env['SPORT']} pinned, after a warm-up from {env['WARM_SPORT']}",
         f"- Lease holder: `{env.get('HOLDER') or 'unknown'}`; capture points: {len(rows)}"]
    if stamp:
        L.append(f"- {stamp}")
    L += ["", "## Path", "", "| Depth | Point | Where | Node | Interface | Expected tag |", "|---|---|---|---|---|---|"]
    for r in rows:
        L.append(f"| {r['depth']} | `{r['id']}` | {r['where']} | {r['node']} | {r['iface']} | {r['vlan']} |")
    L += ["", "## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", "",
          "## Frames per point", "", f"| Point | Frames | SYNs with seq {seq} | Source MAC | Destination MAC | IP id | TTL | Tag | Checksum |",
          "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        s = r["syn"] or {}
        L.append(f"| `{r['id']}` | {r['frames']} | {r['syns']} | {s.get('src_mac', '-')} | {s.get('dst_mac', '-')} | {s.get('ipid') if s.get('ipid') is not None else '-'} | "
                 f"{s.get('ttl', '-')} | {s.get('vlan') or 'none' if s else '-'} | {s.get('cksum') or '-'} |")
    L += ["", "## The first SYN at each point", ""]
    for r in rows:
        s = r["syn"]
        L.append(f"- `{r['id']}` (`captures/{r['id']}.txt:{s['line']}`)" if s else f"- `{r['id']}`: not seen")
        if s:
            L += ["", "  ```", f"  {s['head']}", "  ```", ""]
    L += ["## Files", "", "- `verdict.txt`, `commands.txt`, `dns.txt`, `warmup.txt`, `request.txt`, `fw-traffic-log.txt`, `points.tsv`",
          "- `captures/<point>.pcap` and `captures/<point>.txt` (decoded with `tcpdump -nn -e -tttt -v -S -r`; guest points decoded in the guest)",
          "", vocab.result_line(counts), ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="trace-md")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("flow")
    s.add_argument("--inv", required=True)
    s.add_argument("--k8s", help="gen/k8s.json, for the cluster's own names")
    s.add_argument("--flow")
    s = sub.add_parser("holder")
    s.add_argument("--leases", required=True)
    s.add_argument("--namespace", default="")
    s.add_argument("--gateway", required=True)
    s.add_argument("--lease", default="", help="<namespace>/<name> of the lease, from gen/k8s.json")
    s = sub.add_parser("points")
    s.add_argument("--inv", required=True)
    s.add_argument("--holder", default="")
    s = sub.add_parser("syn")
    s.add_argument("--decode", required=True)
    s.add_argument("--sport", required=True)
    s.add_argument("--vip")
    s = sub.add_parser("judge")
    s.add_argument("--set", required=True)
    s.add_argument("--inv", required=True)
    s.add_argument("--points", required=True)
    s.add_argument("--env", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"flow": cmd_flow, "holder": cmd_holder, "points": cmd_points, "syn": cmd_syn, "judge": judge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
