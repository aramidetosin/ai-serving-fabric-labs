#!/usr/bin/env python3
"""Stand-ins for Part III's harness (chapters 8 to 11), for common/tests/test_part3_labs.py.

They extend chapter 7's stand-in world (shims-ch07/_ch07.py, on chapter 6's) with what Part III's
tools ask of the lab, and hand everything else to it. The world lives in the same JSON file; times
are the host clock. The facts the model needs (each client's first capture point, every connect's
outcome as render/decisions.py's path computes it, the bundle's legs, the pair's ports facing the
ingress nodes, the firewall's rulebases, the routers' routes) come from $SHIM_P3_FACTS, written by
common/tests/p3_world.py from the lab's model. Deliberately simple and deterministic, made-up values
only (never the book's or a lab's figures):

- DNS: every server answers from the inventory's views and resolvers: an authoritative server from
  the view matching the asking address, NXDOMAIN for a name it does not hold, REFUSED for a name
  outside its zone; a resolver only for its clients (REFUSED otherwise), from the view matching its
  own address, its first query for a name forwarded to its first authority and then cached; AAAA is
  NOERROR with no record wherever A is answered. The corporate resolver, once its pins are loaded
  from a copy of its render (sfab-dns reload of a break's directory), answers A for the pinned
  names itself and AAAA REFUSED;
- connects (syn_connect.py, hold_request.py, hold_conns.py, the probes, curl) end as the facts say:
  CONNECTED when reached (on the node itself for a cluster node asking its own Gateway's VIP),
  TIMEOUT otherwise, and every SYN is a frame at the capture points it crosses: the client's first
  point (the firewall's port or the router's uplink) when the firewall or a later device refuses
  it, one leg of the bundle by its source port's parity tagged with the VIP's VLAN, the pair port
  on that leg's switch facing the Gateway's lease holder, and the holder's VLAN 110 unit; a DNS
  lookup is frames at its resolver's port. The firewall logs every connect it decided (allow or
  deny-all-log) and lists held connections in its session table while they are held;
- the leases: the users' Gateway on k8s-ingress1, the others on k8s-ingress2 (chapter 7's); once
  both pair ports of an ingress node are shut, its leases move to the other one SHIM_FAILOVER_S
  later, and the firewall's ARP entry for each moved VIP names the new holder's MAC; the probes'
  requests through a moved Gateway fail from the cut until then;
- a security rule edited through the XML API (break-10a) changes that rule's destination, and a
  connect it no longer admits meets deny-all-log; a merge patch of a model route (break-11a) adds
  its paths to the Gateway, whose requests then reach the API gateway; a patch of an announcement
  policy (break-8a) is kept and read back;
- the refused mint: a key Job asked for a model outside its caller's audience fails with the key
  tool's refusal and changes nothing.
"""

import hashlib
import json
import os
import re
import shlex
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "shims-ch07"))
import _ch07 as W7  # noqa: E402

W = W7.W
INV, NODES, PREFIX = W.INV, W.NODES, W.PREFIX
RENDER = W.RENDER
F = json.load(open(os.environ["SHIM_P3_FACTS"]))
FAILOVER_S = float(os.environ.get("SHIM_FAILOVER_S", "1.5"))
DNS = INV.get("dns") or {}
ZONE = DNS.get("zone") or ""
BY_ADDR = {(x.get("address") or "").split("/")[0]: n for n, x in NODES.items() if x.get("address")}
VLAN = 110


def _json(p):
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return {}


TEN = _json(RENDER / "gen" / "tenancy.json")
K8S = W.K8S


def p3(s):
    W7.init7(s)
    c = s.setdefault("p3", {})
    if not c.get("ready"):
        c.update(ready=True, events=[], cuts=[], shut={}, holds={}, pinned=None, cache={}, rule_dst={}, route_add={}, policy={},
                 files={}, probes={}, iso={}, held={}, sid=0)
    return c


def ip_in(a, cidr):
    import ipaddress  # noqa: PLC0415

    try:
        return ipaddress.ip_address(a) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def addr_of(n):
    return (NODES.get(n) or {}).get("address", "").split("/")[0]


def node_of_ctr(ctr):
    return ctr[len(PREFIX):] if ctr.startswith(PREFIX) else ctr


# ---------------------------------------------------------------------------- the leases

def base_holder(g):
    return "k8s-ingress1" if g == "gw-users" else "k8s-ingress2"


def cut_windows(c):
    """[(node, since, until)] for every ingress node whose pair ports were all shut together."""
    out = []
    for n, by in F["pair_ports"].items():
        wins = []
        for sw, eth in by.items():
            nat = (NODES[sw].get("nics") or {}).get(eth, {}).get("native") or eth
            wins.append(c["shut"].get(f"{sw}|{nat}") or [])
        if not wins or not all(wins):
            continue
        # the intersection of every port's shut windows (one window each in these drills)
        a = max(w[-1][0] for w in wins)
        ends = [w[-1][1] for w in wins]
        b = None if any(e is None for e in ends) else min(ends)
        if b is None or a < b:
            out.append((n, a, b))
    return out


def holder(s, g, t):
    c = p3(s)
    h = base_holder(g)
    for n, a, _b in cut_windows(c):
        if h == n and t >= a + FAILOVER_S:
            h = next(x for x in F["pair_ports"] if x != n)
    return h


def leases_doc(s, t):
    items = []
    for g, ln in sorted(F["leases"].items()):
        items.append({"metadata": {"name": ln, "namespace": "kube-system"},
                      "spec": {"holderIdentity": holder(s, g, t), "leaseDurationSeconds": 3, "leaseTransitions": 0,
                               "renewTime": "2026-10-31T09:00:00.000000Z"}})
    return {"items": items}


# ---------------------------------------------------------------------------- the network

def gateway_of_vip(a):
    return F["vips"].get(a)


def connect_fact(s, client, addr, port):
    c = p3(s)
    f = dict(F["connects"].get(f"{client}|{addr}|{port}") or {"outcome": "silence", "device": "nowhere", "local": False})
    rd = c["rule_dst"].get(f.get("rule") or "")
    if f.get("outcome") == "reached" and rd is not None and addr not in rd:
        # break-10a: the rule no longer names the address the client asked for
        f.update(outcome="log-line", rule="deny-all-log", action="deny", device=F["fw"])
    return f


def seq_of(client, sport, t):
    return int(hashlib.sha256(f"{client}|{sport}|{t:.3f}".encode()).hexdigest()[:8], 16)


def syn_points(s, client, sport, f, t):
    """[{node, eth|iface, dst, vlan}] where one SYN shows."""
    if f.get("local"):
        return []
    cl = F["clients"].get(client) or {}
    out = []
    entry = cl.get("entry")
    reached = f["outcome"] == "reached"
    if entry and (reached or f["outcome"] == "log-line" or f.get("device") == F["fw"]):
        out.append({"node": entry[0], "eth": entry[1], "dst": None, "vlan": None})
    if reached and gateway_of_vip(f.get("at")):
        leg = F["legs"][sport % len(F["legs"])]
        out.append({"node": F["fw"], "eth": leg["eth"], "dst": f["at"], "vlan": VLAN})
        h = holder(s, gateway_of_vip(f["at"]), t)
        sw_eth = (F["pair_ports"].get(h) or {}).get(leg["switch"])
        if sw_eth:
            out.append({"node": leg["switch"], "eth": sw_eth, "dst": f["at"], "vlan": VLAN})
        out.append({"node": h, "iface": "bond0.110", "dst": f["at"], "vlan": None})
    return out


def add_syn(s, client, sport, addr, port, t):
    c = p3(s)
    f = connect_fact(s, client, addr, port)
    ev = {"type": "syn", "t": t, "client": client, "src": F["clients"].get(client, {}).get("addr") or addr_of(client), "sport": sport,
          "dst": addr, "dport": port, "seq": seq_of(client, sport, t), "fact": f, "points": syn_points(s, client, sport, f, t)}
    c["events"].append(ev)
    if not f.get("local") and f["outcome"] in ("reached", "log-line") and f.get("rule"):
        c.setdefault("log", []).append({"t": t, "src": ev["src"], "sport": sport, "dst": addr, "dport": port, "rule": f["rule"],
                                        "action": "allow" if f["outcome"] == "reached" else (f.get("action") or "deny"),
                                        "from": f.get("from_zone"), "to": f.get("to_zone")})
    return f


def connect_lines(s, client, addr, port, sport, count, now):
    out = []
    for k in range(count):
        t = now + 0.01 * k
        f = add_syn(s, client, sport + k, addr, port, t)
        ok = f["outcome"] == "reached"
        out.append(f"{t:.6f} {k} {1 if ok else 0} {sport + k} {'CONNECTED' if ok else 'TIMEOUT'} {0.002 if ok else 4.0}")
    return "\n".join(out)


# ---------------------------------------------------------------------------- DNS

def node_by_addr(a):
    return BY_ADDR.get(a)


def views_on(server):
    return [(vid, v) for vid, v in (DNS.get("views") or {}).items() if server in (v.get("servers") or [v.get("server")])]


def resolver_entry(server):
    return next((r for r in (DNS.get("resolvers") or {}).values() if server in (r.get("servers") or [])), None)


def view_for_addr(a):
    for vid, v in (DNS.get("views") or {}).items():
        if any(ip_in(a, cidr) for cidr in v.get("match_cidrs") or []):
            return vid, v
    return None, None


def dns_answer(s, client, server_addr, name, qtype, rd=True):
    """(status, [answers], flags, forwarded_to)"""
    c = p3(s)
    name = name.rstrip(".")
    caddr = addr_of(client)
    server = node_by_addr(server_addr) if server_addr else (NODES.get(client) or {}).get("resolver")
    role = (NODES.get(server) or {}).get("dns_role")
    r = resolver_entry(server) if server else None
    if r is not None:
        if not any(ip_in(caddr, x) for x in r.get("clients") or []):
            return "REFUSED", [], ["qr", "rd", "ra"], None
        pin = c.get("pinned") if server == (c.get("pinned") or {}).get("node") else None
        if pin and name in pin["names"]:
            if qtype == "A":
                return "NOERROR", [pin["names"][name]], ["qr", "aa", "rd", "ra"], None
            return ("NOERROR", [], ["qr", "aa", "rd", "ra"], None) if pin.get("local") else ("REFUSED", [], ["qr", "rd", "ra"], None)
        _vid, v = view_for_addr(addr_of(server))
        fwd = None
        key = f"{server}|{name}"
        if key not in c["cache"] and r.get("to"):
            fwd = addr_of(r["to"][0])
            c["cache"][key] = True
        if v is None or not name.endswith(ZONE):
            return "NXDOMAIN", [], ["qr", "rd", "ra"], fwd
        if name in (v.get("names") or []):
            return ("NOERROR", [v["answer_address"]] if qtype == "A" else [], ["qr", "rd", "ra"], fwd)
        return "NXDOMAIN", [], ["qr", "rd", "ra"], fwd
    if role in ("bind-auth", "bind-views"):
        if not name.endswith(ZONE):
            return "REFUSED", [], ["qr", "rd"] if rd else ["qr"], None
        v = next((v for _vid, v in views_on(server) if any(ip_in(caddr, x) for x in v.get("match_cidrs") or [])), None)
        if v is None:
            return "REFUSED", [], ["qr"], None
        fl = ["qr", "aa"] + (["rd"] if rd else [])
        if name in (v.get("names") or []):
            return "NOERROR", ([v["answer_address"]] if qtype == "A" else []), fl, None
        return "NXDOMAIN", [], fl, None
    return "timeout", [], [], None


def dig_text(status, answers, flags, server_addr, name, qtype):
    if status == "timeout":
        return f"; <<>> DiG 9.18 <<>> {name} {qtype}\n;; connection timed out; no servers could be reached"
    lines = [f"; <<>> DiG 9.18 <<>> {name} {qtype}", ";; Got answer:", f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 4242",
             f";; flags: {' '.join(flags)}; QUERY: 1, ANSWER: {len(answers)}, AUTHORITY: 0, ADDITIONAL: 1", ""]
    if answers:
        lines += [";; ANSWER SECTION:"] + [f"{name}.\t\t300\tIN\t{qtype}\t{a}" for a in answers] + [""]
    lines.append(f";; SERVER: {server_addr}#53({server_addr}) (UDP)")
    return "\n".join(lines)


def dig(s, client, args, now):
    a = [x for x in args if not x.startswith("+")]
    server = next((x[1:] for x in a if x.startswith("@")), None)
    rest = [x for x in a if not x.startswith("@") and x not in ("-b",)]
    name = rest[0] if rest else ""
    qtype = rest[1] if len(rest) > 1 else "A"
    rd = "+norecurse" not in args
    srv_node = node_by_addr(server) if server else (NODES.get(client) or {}).get("resolver")
    server = server or addr_of(srv_node)
    st, ans, fl, fwd = dns_answer(s, client, server, name, qtype, rd)
    p3(s)["events"].append({"type": "dns", "t": now, "client": client, "src": addr_of(client), "server": server, "resolver": srv_node,
                            "name": name.rstrip("."), "qtype": qtype, "status": st, "answers": ans, "fwd": fwd})
    return dig_text(st, ans, fl, server, name.rstrip("."), qtype)


# ---------------------------------------------------------------------------- frames at the capture points

def mac_of(n):
    return (F["ingress"].get(n) or {}).get("mac") or "02:00:00:00:00:02"


def syn_frame(t, src, sport, dst, dport, seq, vlan):
    eth = (f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan else
           "ethertype IPv4 (0x0800), length 74: ")
    return (f"{t:.6f} 0c:00:aa:bb:cc:02 > 02:00:00:00:00:02, {eth}(tos 0x0, ttl 63, id 999, offset 0, flags [DF], proto TCP (6), length 60)\n"
            f"    {src}.{sport} > {dst}.{dport}: Flags [S], cksum 0x1a2b (correct), seq {seq}, win 64240, length 0")


def udp_frame(t, src, sport, dst, dport, body):
    return (f"{t:.6f} 0c:00:aa:bb:cc:04 > 02:00:00:00:00:03, ethertype IPv4 (0x0800), length 90: (tos 0x0, ttl 64, id 77, offset 0, flags [none], "
            f"proto UDP (17), length 76)\n    {src}.{sport} > {dst}.{dport}: [udp sum ok] {body}")


def frames_at(s, node, eth=None, iface=None, start=0.0, stop=None):
    c = p3(s)
    out = []
    for e in c["events"]:
        if e["t"] < start or (stop is not None and e["t"] > stop):
            continue
        if e["type"] == "syn":
            for p in e["points"]:
                if p["node"] == node and (p.get("eth") == eth if eth else p.get("iface") == iface):
                    out.append((e["t"], syn_frame(e["t"], e["src"], e["sport"], p["dst"] or e["dst"], e["dport"], e["seq"], p["vlan"])))
        elif e["type"] == "dns" and e.get("resolver") == node and eth == F["resolver_ifaces"].get(node):
            q = f"{e['name']}."
            out.append((e["t"], udp_frame(e["t"], e["src"], 40000, e["server"], 53, f"4242+ {e['qtype']}? {q} (41)")))
            if e.get("fwd"):
                out.append((e["t"] + 0.001, udp_frame(e["t"] + 0.001, e["server"], 41000, e["fwd"], 53, f"5151+ {e['qtype']}? {q} (52)")))
                a = " ".join(f"{q} [5m] A {x}" for x in e["answers"])
                out.append((e["t"] + 0.002, udp_frame(e["t"] + 0.002, e["fwd"], 53, e["server"], 41000,
                                                      f"5151* q: {e['qtype']}? {q} {len(e['answers'])}/0/0 {a} (68)")))
            a = " ".join(f"{q} [5m] A {x}" for x in e["answers"])
            out.append((e["t"] + 0.003, udp_frame(e["t"] + 0.003, e["server"], 53, e["src"], 40000,
                                                  f"4242 q: {e['qtype']}? {q} {len(e['answers'])}/0/0 {a} (57)")))
    return "\n".join(x for _t, x in sorted(out, key=lambda y: y[0]))


def p3_point(node, eth=None, iface=None):
    """Whether a capture point is one Part III's tools capture (the stand-in answers its decode)."""
    if iface:
        return iface == "bond0.110"
    if node == F["fw"] and eth in [x["eth"] for x in F["legs"]] + [c["entry"][1] for c in F["clients"].values() if c.get("entry")
                                                                    and c["entry"][0] == F["fw"]]:
        return True
    if any(c.get("entry") == [node, eth] for c in F["clients"].values()):
        return True
    if any((F["pair_ports"].get(n) or {}).get(node) == eth for n in F["pair_ports"]):
        return True
    if F["resolver_ifaces"].get(node) == eth:
        return True
    return node in F["clients"] and F["clients"][node]["kind"] == "vm-node"


# ---------------------------------------------------------------------------- the firewall CLI

def running_policy(kind):
    out = ["", "Nat policy configured on vsys1:"] if kind == "nat" else [""]
    rows = F["nat"] if kind == "nat" else F["rules"]
    c = None
    for i, r in enumerate(rows, 1):
        def mem(x):
            x = [y.split("/")[0] if y.endswith("/32") else y for y in x]
            return x[0] if len(x) == 1 else "[ " + " ".join(x) + " ]"
        out.append(f'"{r["name"]}; index: {i}" {{')
        if kind == "nat":
            out += [f"        from {mem(r['from'])};", "        source any;", f"        to {mem(r['to'])};",
                    f"        destination {mem(r['dst'])};",
                    f"        service 0:tcp/any/{r['service'].split('-')[-1]};" if r["service"].startswith("tcp-") else "        service 0:any/any/any;"]
            if r.get("dnat"):
                out.append(f'        translate-to "dst: {r["dnat"]}";')
            elif r.get("snat"):
                out.append(f'        translate-to "src: {r["snat"]} (dynamic-ip-and-port)";')
        else:
            dst = p3c_rule_dst(c, r)
            apps = r["apps"] or ["any"]
            svc = "443" if "ssl" in apps else "any"
            out += [f"        from {mem(r['from'])};", f"        source {mem(r['src'])};", f"        to {mem(r['to'])};",
                    f"        destination {mem(dst)};",
                    f"        application/service {mem([f'{i_}:{a}/tcp/any/{svc}' for i_, a in enumerate(apps)])};", f"        action {r['action']};"]
        out += ["}", ""]
    return "\n".join(out)


_RULE_DST = {}


def p3c_rule_dst(_c, r):
    return _RULE_DST.get(r["name"]) or r["dst"]


def tlog_text(s, dport):
    import importlib.util  # noqa: PLC0415

    spec = importlib.util.spec_from_file_location("ch04_world", HERE.parent / "ch04_world.py")
    cw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cw)
    es = [e for e in sorted(p3(s).get("log") or [], key=lambda e: -e["t"]) if str(e["dport"]) == str(dport)]
    rows = [(time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(e["t"])), "ssl" if e["action"] == "allow" else "not-applicable", e["from"],
             e["sport"], e["src"], e["rule"], e["action"], e["to"], e["dport"], e["dst"]) for e in es]
    return cw.tlog(rows)


def session_count_text(s, flt, now):
    m = re.match(r"^from (\S+) destination (\S+) destination-port (\d+)$", flt)
    n = 0
    if m:
        for h in p3(s)["holds"].values():
            if h["zone"] == m.group(1) and h["address"] == m.group(2) and h["start"] <= now and (h["stop"] is None or h["stop"] > now):
                n += h["n"]
    return f"Number of sessions that match filter: {n}"


SESSION_INFO = """target-dp:                                       *.dp0
--------------------------------------------------------------------------------
Number of sessions supported:                    65534
Number of allocated sessions:                    {n}
Session timeout
  TCP default timeout:                           3600 secs
  TCP session timeout before SYN-ACK received:      5 secs
  TCP session timeout before 3-way handshaking:    10 secs
  TCP half-closed session timeout:                 30 secs
  TCP session timeout in TIME_WAIT:                15 secs
  TCP session timeout for unverified RST:          30 secs
  TCP session delayed ack timeout:                 25 millisecs
  UDP default timeout:                             30 secs
  ICMP default timeout:                             6 secs
  SCTP default timeout:                          3600 secs
  other IP default timeout:                        30 secs
  Captive Portal session timeout:                  30 secs
  Session timeout in discard state:
    TCP: 90 secs, UDP: 60 secs, SCTP: 60 secs, other IP protocols: 60 secs"""


def arp_text(s, now):
    rows = ["maximum of entries supported :      2500", "default timeout:                    1800 seconds", "total ARP entries in table :        3", "",
            "interface         ip address      hw address        port         status   ttl", "-" * 80]
    for vip, g in sorted(F["vips"].items()):
        if vip in (p3(s).get("arp_omit") or []):
            continue  # a VIP no traffic through the firewall has reached: no entry learned
        rows.append(f"ae1.110           {vip:<16}{mac_of(holder(s, g, now)):<18}ae1          c        1782")
    return "\n".join(rows)


def held_session(s, line):
    c = p3(s)
    m = re.match(r"^show session all filter source (\S+) source-port (\d+)$", line)
    if m:
        h = c["held"].get(m.group(2))
        if not h or h.get("stop"):
            return "No Active Sessions"
        import importlib.util  # noqa: PLC0415

        spec = importlib.util.spec_from_file_location("ch04_world", HERE.parent / "ch04_world.py")
        cw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cw)
        f = h["fact"]
        return cw.session_all(h["sid"], "ssl", h["src"], int(h["sport"]), f["from_zone"], h["src"], int(h["sport"]), h["dst"], 443, f["to_zone"],
                              f["at"], 443, "ND" if f["at"] != h["dst"] else "")
    m = re.match(r"^show session id (\d+)$", line)
    if m:
        h = next((x for x in c["held"].values() if str(x["sid"]) == m.group(1)), None)
        if not h:
            return "Session not found"
        import importlib.util  # noqa: PLC0415

        spec = importlib.util.spec_from_file_location("ch04_world", HERE.parent / "ch04_world.py")
        cw = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cw)
        f = h["fact"]
        return cw.session_detail(h["sid"], h["src"], int(h["sport"]), f["from_zone"], h["dst"], 443, f["at"], f["to_zone"], f["rule"],
                                 f.get("nat_rule"), "ethernet1/6", "ae1.110")
    return None


def fw_line(s, line, now):
    if line == "show running nat-policy":
        return running_policy("nat")
    if line == "show running security-policy":
        return running_policy("security")
    m = re.match(r"^show log traffic .*dport equal (\d+)$", line)
    if m:
        return tlog_text(s, m.group(1))
    m = re.match(r"^show session all filter (.*) count yes$", line)
    if m:
        return session_count_text(s, m.group(1), now)
    if line == "show session info":
        n = sum(h["n"] for h in p3(s)["holds"].values() if h["stop"] is None)
        return SESSION_INFO.format(n=n)
    if line == "show arp all":
        return arp_text(s, now)
    return held_session(s, line)


def fw_cli(data):
    out = []
    with W.locked():
        s = W.load()
        p3(s)
        _RULE_DST.update(p3(s)["rule_dst"])
        now = time.time()
        for line in data.splitlines():
            out.append(f"admin@{F['fw']}> {line}")
            if line == "exit":
                break
            got = fw_line(s, line, now)
            out.append(got if got is not None else "ok")
        W.save(s)
    return "\n".join(out)


# ---------------------------------------------------------------------------- the switches

def mac_rows(s, sw, now):
    rows = ["-" * 60, "VLAN     MAC Address         Type          Interface", "-" * 60]
    for n, x in sorted(F["ingress"].items()):
        pc = next((p for p, v in (NODES[sw].get("portchannels") or {}).items() if v.get("peer_node") == n), None)
        if pc:
            rows.append(f"{VLAN:<9}{x['mac']}   DYNAMIC       {pc}")
    return "\n".join(rows)


def switch_cli(sw, data):
    if NODES[sw].get("role") == "rail_vlan":
        return None
    lines = data.splitlines()
    if not any(l.strip() in ("show mac address-table", "shutdown", "no shutdown") for l in lines):
        return None
    out, ctx, mode = [], None, "#"
    with W.locked():
        s = W.load()
        c = p3(s)
        now = time.time()
        for line in lines:
            out.append(f"{sw}{mode} {line}")
            l = line.strip()
            if l == "exit" and mode == "#":
                break
            if l == "configure terminal":
                mode = "(config)#"
            elif l == "end":
                mode, ctx = "#", None
            elif l == "exit":
                ctx, mode = None, "(config)#"
            elif l.startswith("interface "):
                ctx, mode = W.expand(l.split()[-1]), "(config-if)#"
            elif l in ("shutdown", "no shutdown") and ctx:
                for nat in ctx:
                    w = c["shut"].setdefault(f"{sw}|{nat}", [])
                    if l == "shutdown":
                        w.append([now, None])
                    elif w and w[-1][1] is None:
                        w[-1][1] = now
            elif l == "show mac address-table":
                out.append(mac_rows(s, sw, now))
        W.save(s)
    return "\n".join(out)


# ---------------------------------------------------------------------------- the clients

def file_store(s, ctr):
    return W.client_files(s, ctr)


def hold_events(h, until):
    """hold_conns.py's lines for a held run up to `until`."""
    lines = []
    t0 = h["start"]
    for i in range(h["n"]):
        lines.append(json.dumps({"t": round(t0 + 0.01 * i, 6), "event": "open", "conn": i, "sport": h["sport"] + i}, sort_keys=True))
        lines.append(json.dumps({"t": round(t0 + 0.01 * i + 0.005, 6), "event": "reply", "conn": i, "k": 0, "status": 200}, sort_keys=True))
    lines.append(json.dumps({"t": round(t0 + 0.01 * h["n"], 6), "event": "held", "open": h["n"]}, sort_keys=True))
    end = h["stop"] or until
    k, t = 1, t0 + h["every"]
    while t < min(end, t0 + h["hold"]):
        for i in range(h["n"]):
            lines.append(json.dumps({"t": round(t + 0.001 * i, 6), "event": "reply", "conn": i, "k": k, "status": 200}, sort_keys=True))
        k += 1
        t += h["every"]
    if h["stop"] is not None or until >= t0 + h["hold"]:
        for i in range(h["n"]):
            lines.append(json.dumps({"t": round(min(end, t0 + h["hold"]), 6), "event": "closed", "conn": i}, sort_keys=True))
        lines.append(json.dumps({"t": round(min(end, t0 + h["hold"]), 6), "event": "done", "open": h["n"], "replies": h["n"] * k, "errors": 0},
                                sort_keys=True))
    return "\n".join(lines)


def run_python(s, ctr, args, script, now):
    """A repository script fed to the node's python3 (docker exec -i ... python3 - ARGS, or a guest's
    sudo python3 -), by its docstring's first words."""
    c = p3(s)
    client = node_of_ctr(ctr)
    head = (script or "")[:400]
    if "syn_connect.py" in head:
        a, port, sport, count = args[0], int(args[1]), int(args[2]), int(args[3])
        return 0, connect_lines(s, client, a, port, sport, count, now)
    if "dnsq.py" in head:
        srv, name, qt = args[0], args[1], args[2]
        src = args[3] if len(args) > 3 else None
        st, ans, fl, _ = dns_answer(s, client, srv, name, qt)
        if src and src != addr_of(client):
            # the router's own link address, outside the resolver's clients
            r = resolver_entry(node_by_addr(srv))
            if r and not any(ip_in(src, x) for x in r.get("clients") or []):
                st, ans, fl = "REFUSED", [], ["qr", "rd", "ra"]
        return 0, dig_text(st, ans, fl, srv, name, qt).replace("DiG 9.18", "dnsq.py")
    return None


def blocking(ctr, args, script):
    """hold_conns.py and hold_request.py: they hold their connections for a while, so the stand-in
    sets them up under the world's lock, then waits outside it (the harness's other calls go on)."""
    client = node_of_ctr(ctr)
    head = (script or "")[:400]
    now = time.time()
    if "hold_conns.py" in head:
        addr, _host, _path, n, hold, every, sport, _ca, tag = args[:9]
        stop = args[9] if len(args) > 9 else None
        key = f"{client}|{tag}"
        with W.locked():
            s = W.load()
            c = p3(s)
            f = connect_fact(s, client, addr, 443)
            c["holds"][key] = {"client": client, "address": addr, "n": int(n), "hold": float(hold), "every": float(every), "sport": int(sport),
                               "start": now, "stop": None, "zone": f.get("from_zone"), "stopfile": stop, "tag": tag}
            for i in range(int(n)):
                add_syn(s, client, int(sport) + i, addr, 443, now + 0.01 * i)
            W.save(s)
        first = hold_events(dict(c["holds"][key], stop=None), now).split("\n")
        upto = next(i for i, x in enumerate(first) if '"event": "held"' in x)
        sys.stdout.write("\n".join(first[:upto + 1]) + "\n")
        sys.stdout.flush()
        while True:
            time.sleep(0.2)
            with W.locked():
                s = W.load()
                h = p3(s)["holds"][key]
                if (stop and stop in file_store(s, ctr)) or time.time() >= h["start"] + h["hold"]:
                    h["stop"] = time.time()
                    W.save(s)
                    break
        rest = hold_events(h, time.time()).split("\n")
        held_at = next(i for i, x in enumerate(rest) if '"event": "held"' in x)
        sys.stdout.write("\n".join(rest[held_at + 1:]) + "\n")
        return 0
    if "hold_request.py" in head:
        addr, _fqdn, path, sport, hold = args[0], args[1], args[2], int(args[3]), float(args[4])
        with W.locked():
            s = W.load()
            c = p3(s)
            f = add_syn(s, client, sport, addr, 443, now)
            if f["outcome"] == "reached":
                c["sid"] += 1
                c["held"][str(sport)] = {"sid": 30000 + c["sid"], "src": addr_of(client), "sport": sport, "dst": addr, "fact": f, "start": now,
                                         "stop": None}
            W.save(s)
        if f["outcome"] != "reached":
            print("no reply: timed out")
            return 1
        msg = path.split("msg=", 1)[-1] if "msg=" in path else ""
        sys.stdout.write(f"HTTP/1.1 200 OK\nserver: envoy\ncontent-type: text/plain\n\n{msg}\nHELD {now:.6f}\n")
        sys.stdout.flush()
        time.sleep(hold)
        with W.locked():
            s = W.load()
            h = p3(s)["held"].get(str(sport))
            if h:
                h["stop"] = time.time()
            p3(s).setdefault("log", []).append({"t": time.time(), "src": addr_of(client), "sport": sport, "dst": addr, "dport": 443,
                                                "rule": f["rule"], "action": "allow", "from": f["from_zone"], "to": f["to_zone"]})
            W.save(s)
        print(f"CLOSED {time.time():.6f}")
        return 0
    return None


def curl_p3(s, ctr, argv, now):
    """Part III's requests: the also request (a model path on a Gateway whose route set does not carry
    it: 404 from envoy), break-11a's patched route, requests through the firewall (the facts decide),
    break-9a's stub; None hands it to chapter 7's stand-in."""
    files = file_store(s, ctr)
    client = node_of_ctr(ctr)
    url = next((a for a in argv if a.startswith("https://")), "")
    if not url:
        return None
    host = url.split("/")[2]
    path = "/" + url.split("/", 3)[3] if url.count("/") >= 3 else "/"
    out, hdr, fmt, lp = W.opt(argv, "-o"), W.opt(argv, "-D"), W.opt(argv, "-w") or "", W.opt(argv, "--local-port")
    res = W.opt(argv, "--resolve")
    addr = res.split(":", 2)[2] if res and res.split(":")[0] == host else None
    if addr is None:
        st, ans, _fl, _ = dns_answer(s, client, None, host, "A")
        addr = ans[0] if ans else None
        if addr is None:
            return 6, "curl: (6) Could not resolve host: " + host
    cl = F["clients"].get(client) or {}
    sport = int(lp) if lp else 51000 + int(now * 1000) % 1000
    f = connect_fact(s, client, addr, 443)
    if not f.get("local"):
        f = add_syn(s, client, sport, addr, 443, now)
        if f["outcome"] != "reached":
            return 28, f"curl: (28) Failed to connect to {host} port 443 after 4000 ms: Timeout was reached\n" + \
                fmt.replace("%{http_code}", "000").replace("%{remote_ip}", "").replace("%{local_port}", str(sport)).replace("\\n", "\n")
    gw = gateway_of_vip(f.get("at") or addr)
    model = W7.model_of_url(url)
    rt = next((r for r in K8S["inference"]["routes"] if r["gateway"] == gw), None)
    carried = rt is not None and model is not None and (any(x["model"] in (None, model) for x in rt["rules"]) or model in p3(s)["route_add"].get(rt["name"], []))
    if model is not None and gw and not carried:
        if hdr:
            files[hdr] = "HTTP/1.1 404 Not Found\r\nserver: envoy\r\ncontent-length: 0\r\n\r\n"
        if out and out != "/dev/null":
            files[out] = ""
        return 0, fmt.replace("%{http_code}", "404").replace("%{remote_ip}", addr).replace("%{local_port}", str(sport)).replace("\\n", "\n")
    if cl.get("kind") == "client" and not f.get("local") and (cl.get("entry") or client == "ops-client") and model is None and "/echo" in url:
        if out and out != "/dev/null":
            files[out] = url.split("msg=", 1)[-1]
        if hdr:
            files[hdr] = "HTTP/1.1 200 OK\r\nserver: envoy\r\n\r\n"
        return 0, fmt.replace("%{http_code}", "200").replace("%{remote_ip}", addr).replace("%{local_port}", str(sport)).replace("\\n", "\n")
    if model is not None and (lp is None or cl.get("kind") == "client"):
        # a model request with a caller's key at the API gateway (chapter 7's stand-in decides the
        # answer), logged under the key's caller
        key = W7.client_key(files, argv)
        if key and key.count(".") == 2:
            return None  # a person's token, reached through the firewall: chapter 7's stand-in answers it
        st, msg = W7.answer_at(s, W7.pick(s), now, model, key)
        fld = W7.field_of(s, key) if key else None
        W7.log_access(s, now, model, st, f"{fld.split('.')[0]}_key_{fld.split('.')[1]}" if fld and st == 200 else "",
                      fld.split(".")[0] if fld and st == 200 else "")
        if hdr:
            files[hdr] = (f"HTTP/1.1 {st} {'OK' if st == 200 else 'Unauthorized'}\r\nserver: envoy\r\n"
                          + (f"x-litellm-model-name: openai/{model}\r\n" if st == 200 else "")
                          + (f"www-authenticate: {K8S['inference']['www_authenticate']}\r\n" if st == 401 and K8S["inference"].get("www_authenticate") else "")
                          + "\r\n")
        if out and out != "/dev/null":
            files[out] = json.dumps({"message": msg}) if st != 200 else json.dumps({"choices": [{"message": {"content": "yes"}}]})
        return 0, fmt.replace("%{http_code}", str(st)).replace("%{remote_ip}", addr).replace("%{local_port}", str(sport)).replace("\\n", "\n")
    if model is None and host.split(".")[0] == "admin" and gw:
        # an admin hostname on a Gateway that does not carry it (the route set's 404)
        carried_h = host in (K8S["gateways"].get(gw) or {}).get("hostnames", []) and gw == "gw-internal"
        st = 200 if carried_h else 404
        if hdr:
            files[hdr] = f"HTTP/1.1 {st} {'OK' if st == 200 else 'Not Found'}\r\nserver: envoy\r\n\r\n"
        if out and out != "/dev/null":
            files[out] = ""
        return 0, fmt.replace("%{http_code}", str(st)).replace("%{remote_ip}", addr).replace("%{local_port}", str(sport)).replace("\\n", "\n")
    return None


CHAIN = ("depth=2 CN = Tarnwick Lab Root CA\ndepth=1 CN = Tarnwick Platform CA\ndepth=0 \n 0 s:\n   i:CN = Tarnwick Platform CA\n"
         " 1 s:CN = Tarnwick Platform CA\n   i:CN = Tarnwick Lab Root CA\nVerify return code: 0 (ok)")


def tls_text(s, node, sc):
    """The gateway layer's chain read: the chain when the facts let the node reach the address it
    connects to, else nothing (the grep keeps no line of a connect that timed out)."""
    m = re.search(r"openssl s_client -connect (\S+):443 ", sc)
    if not m:
        return None
    f = connect_fact(s, node, m.group(1), 443)
    p3(s).setdefault("tls", []).append({"node": node, "address": m.group(1), "outcome": f["outcome"]})
    return CHAIN if f["outcome"] == "reached" else ""


def p3_client(s, ctr, argv, stdin, now):
    c = p3(s)
    files = file_store(s, ctr)
    node = node_of_ctr(ctr)
    if argv[:1] == ["python3"] and argv[1:2] == ["-"]:
        return run_python(s, ctr, argv[2:], stdin, now)
    if argv[:1] == ["dig"]:
        return 0, dig(s, node, argv[1:], now)
    if argv[:1] == ["curl"]:
        return curl_p3(s, ctr, argv, now)
    if argv[:1] == ["sfab-dns"] and argv[1:2] == ["reload"]:
        d = argv[2] if len(argv) > 2 else "/sfab/bootstrap"
        if c.get("reload_busy", 0) > 0:
            # the restart met the listening address still held: sfab-dns puts the previous one back
            c["reload_busy"] -= 1
            return 1, ("[sfab-dns] put the previous configuration back\n[sfab-dns] FAIL: the reload failed; the previous configuration serves\n\n"
                       "dnsmasq: failed to create listening socket for 10.24.10.53: Address in use")
        if d.startswith("/tmp/sfab-break"):
            conf = files.get(f"{d}/dnsmasq.conf") or ""
            names = {f"{m.group(1)}": m.group(2) for m in re.finditer(r"(?m)^address=/([^/]+)/(\S+)$", conf)}
            # a local= over the platform's zone answers the pinned names' other types from the server
            local = any(ZONE == d or ZONE.endswith("." + d) for d in re.findall(r"(?m)^local=/([^/]+)/$", conf))
            c["pinned"] = {"node": node, "names": names, "local": local}
        else:
            c["pinned"] = None
        c["cache"] = {}
        return 0, f"sfab-dns: {node}: reloaded from {d}"
    if argv[:1] == ["touch"]:
        files[argv[1]] = ""
        return None if argv[1].endswith("/stop") and any(argv[1].startswith(p) for p in s.get("ch07", {}).get("probes", {})) else (0, "")
    if argv[:1] == ["cat"] and len(argv) == 2:
        f = argv[1]
        if f.endswith("/echo.jsonl") or f.endswith("/tcp.log"):
            return 0, probe_text(s, ctr, f, now)
        if f.endswith("/iso.jsonl"):
            return 0, iso_text(s, ctr, now)
        if f == "/etc/resolv.conf":
            return 0, f"nameserver {addr_of((NODES.get(node) or {}).get('resolver'))}\noptions timeout:2 attempts:2"
        return None
    if argv[:2] == ["bash", "-c"] and "curl -s -o /dev/null -w '%{http_code}'" in argv[2]:
        # breakheal.sh's probe_http loop: count requests, one a line "<t> <i> <ok> <code>"
        sc = argv[2]
        n = int(re.search(r"seq 0 (\d+)", sc).group(1)) + 1
        iv = float(re.search(r"sleep ([\d.]+)", sc).group(1))
        url = re.search(r"'(https://[^']+)'", sc).group(1)
        lines = []
        for i in range(n):
            t = now + i * iv
            r = curl_p3(s, ctr, ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--local-port", str(53000 + i + int(now) % 500), url], t)
            code = (r[1].strip().split() or ["000"])[0] if r and r[0] == 0 else "000"
            lines.append(f"{t:.6f} {i} {1 if code == '200' else 0} {code}")
        return 0, "\n".join(lines)
    if argv[:2] == ["sh", "-c"]:
        sc = argv[2]
        if "openssl s_client -connect " in sc:
            return 0, tls_text(s, node, sc)
        if " -w '%{http_code} %{remote_ip}" in sc and "curl " in sc:
            # matrix.sh's request: curl from a pinned port, the pin taken when the client's resolver has no answer
            pin = None
            m = re.match(r"^if getent hosts (\S+) >/dev/null 2>&1; then p=; else p='--resolve (\S+)'; fi; (.*)$", sc)
            if m:
                st_, ans_, _f, _ = dns_answer(s, node, None, m.group(1), "A")
                pin = None if ans_ else m.group(2)
                sc = m.group(3).replace(" $p", f" --resolve {pin}" if pin else "")
            cmd = sc.split('; echo "exit')[0]
            r = curl_p3(s, ctr, shlex.split(cmd), now)
            if r is None:
                return 0, "000 \nexit 7"
            rc, text = r
            return 0, f"{text.rstrip()}\nexit {rc}"
        m = re.match(r"^cat (\S+) 2>/dev/null$", sc)
        if m:
            return 0, files.get(m.group(1), "")
        if sc.startswith("dig ") or re.search(r";\s*dig ", sc):
            m = re.search(r"dig ([^;]*?)(;|$)", sc)
            out = dig(s, node, shlex.split(m.group(1)), now)
            if "echo \"exit" in sc:
                out += f"\nexit 0 start {now:.6f} end {now + 0.01:.6f}"
            return 0, out
        if "python3 /tmp/sfab-gai.py" in sc:
            name = sc.split("sfab-gai.py ", 1)[1].split(";")[0].strip()
            st, ans, _fl, _ = dns_answer(s, node, None, name, "A")
            st6, _a6, _f6, _ = dns_answer(s, node, None, name, "AAAA")
            if ans and st6 == "NOERROR":
                return 0, f"{sorted(ans)}\nexit 0 start {now:.6f} end {now + 0.02:.6f}"
            return 0, f"gaierror -3 [Errno -3] Try again\nexit 2 start {now:.6f} end {now + 10.0:.6f}"
        if "timeout" in sc and " curl " in sc and "http %{http_code}" in sc:
            url = re.search(r"'(https://[^']+)'", sc).group(1)
            host = url.split("/")[2]
            st, ans, _fl, _ = dns_answer(s, node, None, host, "A")
            if not ans or (c.get("pinned") and host in c["pinned"]["names"] and node in ("ent-client",)):
                if not ans:
                    return 0, f"curl: (6) Could not resolve host: {host}\nexit 6 start {now:.6f} end {now + 0.1:.6f}"
            f = add_syn(s, node, 52000 + int(now * 100) % 1000, ans[0], 443, now)
            ok = f["outcome"] == "reached"
            return 0, (f"http {200 if ok else 0} remote {ans[0]}\nexit {0 if ok else 28} start {now:.6f} end {now + 0.1:.6f}")
        if "python3 -" in sc and stdin is not None and ("dnsq.py" in stdin[:400]):
            a = shlex.split(sc)
            return run_python(s, ctr, argv[3:][1:] if len(argv) > 3 else [], stdin, now)
        m = re.search(r"cat >(\S+)$", sc)
        if m and "rm -rf" not in sc:
            files[m.group(1)] = stdin or ""
            return 0, ""
        m = re.match(r"^rm -rf (\S+) && mkdir -p (\S+) && cp -R /sfab/bootstrap/\. (\S+)/$", sc)
        if m:
            files[f"{m.group(2)}/dnsmasq.conf"] = ""
            return 0, ""
        if "probe_echo.py" in sc and "nohup" in sc:
            a = shlex.split(sc.split(";", 1)[-1].replace("nohup ", "").replace(" &", "").split(">")[0])
            c["probes"][ctr] = {"kind": "echo", "start": now, "interval": float(a[a.index("--interval") + 1]), "url": a[a.index("--url") + 1],
                                "stop": None, "dir": os.path.dirname(a[a.index("--log") + 1])}
            return 0, ""
        if "probe_tcp.py" in sc and "nohup" in sc:
            a = shlex.split(sc.replace("nohup ", "").replace(" &", "").split(">")[0])
            i = next(k for k, x in enumerate(a) if x.endswith("probe_tcp.py"))
            c["probes"][ctr + "|tcp"] = {"kind": "tcp", "start": now, "address": a[i + 1], "interval": float(a[i + 4]), "stop": None}
            return 0, ""
        if "probe_isolation.py" in sc and "nohup" in sc:
            a = shlex.split(sc.replace("nohup ", "").replace(" &", "").split(">")[0])
            plan = json.loads(files.get(a[a.index("--plan") + 1]) or "{}")
            c["iso"][ctr] = {"start": now, "plan": plan}
            return 0, ""
        if "touch" in sc and "/stop" in sc:
            for m_ in re.finditer(r"touch (\S+/stop)", sc):
                files[m_.group(1)] = ""
                for k, p in c["probes"].items():
                    if k.startswith(ctr) and p.get("stop") is None and (p.get("dir") and m_.group(1).startswith(p["dir"])):
                        p["stop"] = now
            for k, p in c["probes"].items():
                if k.startswith(ctr) and p["kind"] == "tcp" and "pkill" in sc:
                    p["stop"] = now
            return 0, ""
        if "grep -q '\"done\"'" in sc:
            r = c["iso"].get(ctr)
            if r and now >= r["start"] + (r["plan"].get("rounds", 1) * r["plan"].get("interval_s", 1)):
                return 0, ""
            return 1, ""
        if sc.startswith("cat ") and "records-" in sc:
            return None
    return None


def probe_text(s, ctr, f, now):
    c = p3(s)
    if f.endswith("/echo.jsonl"):
        p = c["probes"].get(ctr)
        if not p:
            return ""
        gw = None
        client = node_of_ctr(ctr)
        dr = next((d for d in _drills()["list"] if d.get("kind") == "lease-loss"), None)
        if dr:
            gw = next((e["gateway"] for e in dr["echo"] if e["client"] == client), None)
        out, n, t = [], 0, p["start"]
        end = p.get("stop") or now
        while t <= end:
            ok = not gw_down(s, gw, t)
            out.append(json.dumps({"n": n, "sent": round(t, 6), "done": round(t + 0.05, 6), "status": 200 if ok else None,
                                   "outcome": "answered" if ok else "failed", **({} if ok else {"why": "timeout"})}, sort_keys=True))
            n += 1
            t += p["interval"]
        return "\n".join(out)
    p = c["probes"].get(ctr + "|tcp")
    if not p:
        return ""
    client = node_of_ctr(ctr)
    gw = gateway_of_vip(p["address"])
    out, n, t = [], 0, p["start"]
    end = p.get("stop") or now
    while t <= end:
        ok = not gw_down(s, gw, t)
        out.append(f"{t:.6f} {n} {1 if ok else 0} {50000 + n} {1.2 if ok else 1000.0}")
        n += 1
        t += p["interval"]
    _ = client
    return "\n".join(out)


def gw_down(s, gw, t):
    """A Gateway whose lease holder is cut and has not been replaced yet."""
    if not gw:
        return False
    for n, a, b in cut_windows(p3(s)):
        if base_holder(gw) == n and a <= t < a + FAILOVER_S and (b is None or t < b):
            return True
    return False


def iso_text(s, ctr, now):
    r = p3(s)["iso"].get(ctr)
    if not r:
        return ""
    p = r["plan"]
    out = []
    for k in range(int(p.get("rounds", 1))):
        t = r["start"] + k * float(p.get("interval_s", 1))
        out.append(json.dumps({"round": k, "t": round(t, 6), "what": "own", "mode": "allowed", "kind": "http", "outcome": "HTTP 200"}, sort_keys=True))
        for x in p.get("tries") or []:
            if x["mode"] == "allowed":
                o = "CONNECTED" if x["kind"] == "connect" else "HTTP 200"
            elif x["mode"] == "404":
                o = "HTTP 404"
            else:
                o = "TIMEOUT"
            out.append(json.dumps({"round": k, "t": round(t, 6), "what": x["cell"], "mode": x["mode"], "kind": x["kind"], "outcome": o}, sort_keys=True))
    out.append(json.dumps({"done": True, "t": round(now, 6)}))
    return "\n".join(out)


def _drills():
    return _json(RENDER / "gen" / "drills.json") or {"list": []}


# ---------------------------------------------------------------------------- the cluster

def l2_policies(s):
    c = p3(s)
    items = []
    for g, x in sorted(K8S["gateways"].items()):
        name = x["l2_policy"]
        items.append({"metadata": {"name": name}, "spec": {"serviceSelector": {"matchLabels": {F["audience_label"]: x["audience"]}},
                                                         "interfaces": c["policy"].get(name) or list(F["l2_interfaces"]),
                                                         "loadBalancerIPs": True}})
    return {"items": items}


def kube_p3(s, cmd, stdin, now):
    c = p3(s)
    if cmd[:2] == ["bash", "-c"] and "openssl x509" in cmd[2] and "spki sha256" in cmd[2]:
        m = re.search(r"get secret (\S+) ", cmd[2])
        sec = m.group(1) if m else "x"
        # the serial as openssl x509 -serial prints it: upper-case hex, the value Envoy's /certs lists
        ser = hashlib.sha256(sec.encode()).hexdigest()[:16].upper()
        return 0, (f"subject=CN={sec}\nissuer=CN=Tarnwick Platform CA\nserial={ser}\nspki sha256 {hashlib.sha256(sec.encode()).hexdigest()}")
    if cmd[:1] != ["kubectl"]:
        return None
    args = cmd[1:]
    words, o, ns = W.strip(args), W.opt(args, "-o"), W.ns_of(args) or "default"
    if words[:1] == ["logs"] and W.opt(args, "-l") and W.opt(args, "-c") == "apisix":
        # the API gateway's access lines (file-logger) on every pod, as kubectl logs -l --prefix prints them
        pods = W7.api_pods(s)
        paths = {m["name"]: m["path"] for m in K8S["inference"]["models"]}
        lines = []
        for a in s["ch07"].get("access") or []:
            for p_ in pods[:1]:
                lines.append(f"[pod/{p_}/apisix] " + json.dumps({"time": a["time"], "client": "10.22.9.7", "host": f"llm.{W7.DOMAIN}",
                                                                 "route": a["route"], "request": f"POST {paths.get(a['route'], '/models')}/v1/chat/completions",
                                                                 "status": int(a["status"]), "consumer": a["consumer"], "caller": a["caller"]}))
        return 0, "\n".join(lines)
    if words[:2] == ["get", "pods"] and ns == "kube-system" and W.opt(args, "-l") == "k8s-app=cilium":
        # one Cilium agent pod a node of the cluster
        vms = [n for n in NODES if NODES[n]["kind"] == "vm-node"]
        return 0, json.dumps({"items": [{"metadata": {"name": f"cilium-{i:05x}"}, "spec": {"nodeName": n}} for i, n in enumerate(vms, 0x1a2b)]})
    if words[:1] == ["exec"] and ns == "kube-system" and "--" in args and args[args.index("--") + 1:][:4] == ["cilium-dbg", "envoy", "admin", "certs"]:
        # Envoy's admin /certs as the stand-in lists it: each Gateway certificate's name and serial, no key
        rows = [{"ca_cert": [], "cert_chain": [{"path": f"<inline:{K8S['gateway_namespace']}/{x['listener']['secret']}>",
                                                "serial_number": hashlib.sha256(x['listener']['secret'].encode()).hexdigest()[:16]}]}
                for g, x in sorted(K8S["gateways"].items())]
        return 0, json.dumps({"certificates": rows}, indent=1)
    if words[:2] == ["get", "ciliuml2announcementpolicies"]:
        d = l2_policies(s)
        return (0, json.dumps(d)) if o == "json" else (0, "NAME   AGE\n" + "\n".join(f"{i['metadata']['name']}   9m" for i in d["items"]))
    if words[:2] == ["get", "ciliuml2announcementpolicies.cilium.io"] and len(words) > 2:
        it = next((i for i in l2_policies(s)["items"] if i["metadata"]["name"] == words[2]), None)
        return (0, json.dumps(it, indent=1)) if it else (1, "not found")
    if words[:1] == ["patch"] and len(words) > 2:
        p = json.loads(W.opt(args, "-p") or "{}")
        if words[1].startswith("ciliuml2announcementpolicies"):
            c["policy"][words[2]] = (p.get("spec") or {}).get("interfaces")
            return 0, f"{words[1]}/{words[2]} patched"
        if words[1].startswith("httproutes"):
            rt = next((r for r in K8S["inference"]["routes"] if r["name"] == words[2]), None)
            paths = [r_["matches"][0]["path"]["value"] for r_ in ((p.get("spec") or {}).get("rules") or []) if r_.get("matches")]
            c["route_add"][words[2]] = [m["name"] for m in K8S["inference"]["models"] if m["path"] in paths
                                        and not any(x["model"] == m["name"] for x in (rt or {}).get("rules") or [])]
            return 0, f"{words[1]}/{words[2]} patched"
        return None
    if words[:2] == ["get", "leases"] and ns == "kube-system":
        d = leases_doc(s, now)
        return (0, json.dumps(d)) if o == "json" else (0, "NAME   HOLDER   AGE\n" + "\n".join(
            f"{i['metadata']['name']}   {i['spec']['holderIdentity']}   9m" for i in d["items"]))
    if words[:2] == ["get", "lease"] and len(words) > 2:
        it = next((i for i in leases_doc(s, now)["items"] if i["metadata"]["name"] == words[2]), None)
        if it is None:
            return 1, ""
        if o and o.startswith("jsonpath"):
            return 0, it["spec"]["holderIdentity"]
        return 0, json.dumps(it, indent=1)
    if words[:2] == ["get", "configmap"] and len(words) > 2 and words[2] == "cilium-config":
        r = W7.kubectl7(s, args, stdin, now)
        d = json.loads(r[1])
        lease = (TEN.get("audiences") or {}).get("lease") or {}
        d["data"].update(lease.get("config") or {})
        return 0, json.dumps(d)
    if words[:2] == ["get", "endpointslices"] and ns in ("echo", K8S["inference"]["namespace"]) and o == "json":
        cut = [n for n, a, b in cut_windows(c) if a + 1.0 <= now and (b is None or now < b)]
        items = []
        for svc, nodes in (("api-gateway", ["k8s-ingress1", "k8s-ingress2"]), ("echo", ["k8s-gpu1", "k8s-gpu2"])):
            items.append({"metadata": {"name": f"{svc}-abcde", "labels": {"kubernetes.io/service-name": svc}},
                          "endpoints": [{"nodeName": n, "conditions": {"ready": True}} for n in nodes if n not in cut]})
        return 0, json.dumps({"items": items})
    if words[:2] == ["get", "pods"] and "-A" in args and o == "wide":
        return 0, "NAMESPACE   NAME   READY   STATUS   NODE\n" + "\n".join(
            f"{p['metadata'].get('namespace', '-')}   {n}   1/1   Running   {p['spec']['nodeName']}" for n, p in sorted(s["pods"].items()))
    if words[:2] == ["get", "secrets"] and ns == "cilium-secrets":
        # Cilium 1.19's copies: each named by a hash and labelled with the Secret it copies, the labels
        # printed as columns when -L names them
        labels = [args[i + 1] for i, a in enumerate(args[:-1]) if a == "-L"]
        cols = {"secretsync.cilium.io/owning-secret-name": lambda g: g["listener"]["secret"],
                "secretsync.cilium.io/owning-secret-namespace": lambda g: K8S["gateway_namespace"]}
        head = "NAME   TYPE   DATA   AGE" + "".join(f"   {lb.rsplit('/', 1)[-1].upper()}" for lb in labels)
        return 0, head + "\n" + "\n".join(
            f"cilium-sync-secret-{hashlib.sha256(g['listener']['secret'].encode()).hexdigest()}   kubernetes.io/tls   3   9m"
            + "".join(f"   {(cols.get(lb) or (lambda _g: '<none>'))(g)}" for lb in labels)
            for g in K8S["gateways"].values())
    if words[:2] in (["get", "gateway"], ["get", "gateways.gateway.networking.k8s.io"]) and len(words) > 2 and o == "yaml":
        return 0, json.dumps({"metadata": {"name": words[2]}, "status": {"conditions": [{"type": "Programmed", "status": "True"}]}}, indent=1)
    if words[:2] in (["get", "httproute"], ["get", "httproutes.gateway.networking.k8s.io"]) and len(words) > 2 and o == "yaml":
        r = next((x for x in routes_patched(s) if x["metadata"]["name"] == words[2]), None)
        return (0, json.dumps(r, indent=1)) if r else (1, "not found")
    if words[:1] in (["create"], ["apply"]) and stdin and stdin.lstrip().startswith("{"):
        doc = json.loads(stdin)
        if doc.get("kind") == "Job":
            cmd_ = doc["spec"]["template"]["spec"]["containers"][0]["command"]
            if "--audience" in cmd_:
                fm = cmd_[cmd_.index("--for") + 1].split(",")
                am = cmd_[cmd_.index("--audience-models") + 1].split(",")
                aud = cmd_[cmd_.index("--audience") + 1]
                slug = cmd_[cmd_.index("--model") + 1]
                out = [m for m in fm if m not in am]
                if out:
                    s["ch07"]["kpods"][doc["metadata"]["name"]] = {
                        "kind": "job", "t": now, "ok": False,
                        "log": (f"sfab-keys: refused: caller {slug} is in audience {aud}, which may call {', '.join(am)}; {', '.join(out)} is "
                                "outside it, so no key is minted and the Secret is left as it was")}
                    return 0, f"job/{doc['metadata']['name']} created"
    return None


ORIG_ROUTES = W7.routes


def routes_patched(s):
    """chapter 7's HTTPRoutes, with break-11a's added rules on its route."""
    out = ORIG_ROUTES(s)
    c = p3(s)
    for r in out:
        add = c["route_add"].get(r["metadata"]["name"])
        if add:
            for m in K8S["inference"]["models"]:
                if m["name"] in add:
                    r["spec"]["rules"].append({"matches": [{"path": {"type": "PathPrefix", "value": m["path"]}}],
                                               "backendRefs": r["spec"]["rules"][0].get("backendRefs") or []})
    return out


# ---------------------------------------------------------------------------- the guests

def guest_p3(s, node, script, now):
    c = p3(s)
    sc = script.strip()
    ctr = PREFIX + node
    if sc.startswith("dig "):
        return dig(s, node, shlex.split(sc)[1:], now)
    if sc == "cat /proc/net/bonding/bond0" and node in F["ingress"]:
        return ("Ethernet Channel Bonding Driver: v[stand-in]\n\nBonding Mode: IEEE 802.3ad Dynamic link aggregation\nMII Status: up\n\n"
                "Slave Interface: eth1\nMII Status: up\n\nSlave Interface: eth2\nMII Status: up\n")
    if "sfab-rail-p3-" in sc:
        m = re.search(r"sfab-rail-(p3-\S+?)\.(pcap|txt)", sc)
        tag = m.group(1) if m else ""
        g = c.setdefault("gcaps", {})
        if "tcpdump -i" in sc and "-w" in sc:
            iface = re.search(r"tcpdump -i (\S+)", sc).group(1)
            g[tag] = {"node": node, "iface": iface, "start": now, "stop": None}
            return ""
        if sc.startswith("pkill"):
            if tag in g:
                g[tag]["stop"] = now
            return ""
        if sc.startswith("pgrep"):
            return ("", 1)
        if sc.startswith("cat "):
            x = g.get(tag)
            return frames_at(s, node, iface=x["iface"], start=x["start"], stop=x.get("stop")) if x else ""
        return ""
    m = re.match(r"^ip neigh flush to (\S+) dev (\S+) 2>/dev/null; ping -c \d+ -W 1 \S+ >/dev/null 2>&1; ip neigh show to \S+ dev \S+$", sc)
    if m and node in F["ingress"]:
        # break-8a's ARP check: the lease holder answers when its audience's policy names the unit
        vip, iface = m.group(1), m.group(2)
        g = gateway_of_vip(vip)
        pol = (K8S["gateways"].get(g) or {}).get("l2_policy")
        pats = c["policy"].get(pol) or list(F["l2_interfaces"])
        h = holder(s, g, now)
        if h != node and any(re.search(x, iface) for x in pats):
            return f"{vip} dev {iface} lladdr {mac_of(h)} REACHABLE"
        return f"{vip} dev {iface} FAILED"
    if node not in F["clients"]:
        return None
    if "openssl s_client -connect " in sc:
        return tls_text(s, node, sc)
    files = file_store(s, ctr)
    if "read -r k; read -r h" in sc:
        return None
    try:
        argv = shlex.split(sc)
    except ValueError:
        return None
    if argv[:1] == ["curl"]:
        r = curl_p3(s, ctr, argv, now)
        if r is None:
            r7 = W7.client7(s, ctr, argv, None, now)
            if r7 is None:
                out = W.curl(s, ctr, argv, now)
                lp = W.opt(argv, "--local-port")
                if lp:
                    # the keyed trace's request from a node of the cluster: the frames chapter 6 and 7's
                    # stand-ins write at the API gateway and router pods follow it
                    model = W.model_of_url(next((a for a in argv if a.startswith("https://")), ""))
                    cp = next(x for x in K8S["serving"]["models"] if x["name"] == model)["copies"]
                    s["trace_req"] = {"t": now, "model": model, "copy": cp[s.get("trace_n", 0) % len(cp)], "sport": int(lp)}
                    s["trace_client"] = ctr
                    s["trace_n"] = s.get("trace_n", 0) + 1
                    W7.log_access(s, now, model, 200, None, None)
                r7 = (0, out)
            return r7[1] if r7[0] == 0 else (r7[1], r7[0])
        return r[1] if r[0] == 0 else (r[1], r[0])
    if argv[:1] == ["cat"] and len(argv) >= 2:
        f = argv[1]
        return files.get(f, "")
    if argv[:2] == ["test", "-s"]:
        return "" if files.get(argv[2]) else ("", 1)
    if argv[:2] == ["rm", "-rf"]:
        for k in [k for k in files if k == argv[2] or k.startswith(argv[2] + "/")]:
            del files[k]
        return ""
    return None


ORIG_KEYED = W7.keyed_frames


def keyed_frames_p3(s, pod, iface):
    """chapter 7's keyed frames, the caller's key read from the trace's own client (a node of the
    cluster in chapter 8) and its model's header file."""
    r = s.get("trace_req")
    ctr = s.get("trace_client")
    if not r or not ctr:
        return ORIG_KEYED(s, pod, iface)
    files = W.client_files(s, ctr)
    ck = next(((v.strip().split("Bearer ", 1)[1]) for k, v in files.items() if k.endswith(f"/hdr-{r['model']}") and "Bearer " in v), "")
    saved = W.client_files(s, f"{PREFIX}ent-client")
    shadow = dict(saved)
    try:
        saved.clear()
        saved["/tmp/sfab-trace/hdr-chat"] = f"Authorization: Bearer {ck}\n"
        return ORIG_KEYED(s, pod, iface)
    finally:
        saved.clear()
        saved.update(shadow)


W7.keyed_frames = keyed_frames_p3


def guest_hook(s, node, script, now):
    r = guest_p3(s, node, script, now)
    if r is not None:
        return r
    return ORIG_GUEST(s, node, script, now)


ORIG_GUEST = W._guest
W._guest = guest_hook


def knode(s, cmd, stdin, now):
    p3(s)
    r = kube_p3(s, cmd, stdin, now)
    if r is not None:
        return r
    if cmd[:1] == ["kubectl"] and W.strip(cmd[1:])[:2] in (["get", "httproutes"], ["get", "httproute"]):
        old = W7.routes
        try:
            W7.routes = lambda s_: routes_patched(s_)  # noqa: E731
            return W7.knode7(s, cmd, stdin, now)
        finally:
            W7.routes = old
    return W7.knode7(s, cmd, stdin, now)


# ---------------------------------------------------------------------------- the tools

def guest_stdin(remote):
    """ssh's remote command for a guest's python3 or file write fed on standard input."""
    if remote.startswith("sudo python3 - "):
        return "python", shlex.split(remote)[3:]
    m = re.match(r"^sudo bash -c '(.*)'$", remote)
    if m and "read -r k; read -r h" in m.group(1):
        return "key", m.group(1)
    if remote.startswith("sudo bash -c ") and "cat >" in remote:
        return "file", remote
    return None, None


def ssh_tool(argv):
    target, rest = W.target_of(argv)
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = W.BY_IP.get(host)
    if node and NODES[node]["kind"] == "vm-node":
        kind, x = guest_stdin(" ".join(rest))
        if kind:
            stdin = sys.stdin.read()
            with W.locked():
                s = W.load()
                p3(s)
                now = time.time()
                files = file_store(s, PREFIX + node)
                rc, out = 0, ""
                if kind == "python":
                    r = run_python(s, PREFIX + node, x, stdin, now)
                    rc, out = r if r else (0, "")
                elif kind == "key":
                    lines = stdin.splitlines()
                    mk = re.search(r">(\S+/key-[\w.]+);", x)
                    mh = re.search(r">(\S+/hdr-[\w.]+)$", x)
                    if len(lines) >= 2 and mk and mh:
                        files[mk.group(1)] = lines[0] + "\n"
                        files[mh.group(1)] = lines[1] + "\n"
                else:
                    script = W.guest_script(" ".join(rest)) or ""
                    m = re.search(r"cat >(\S+)", script)
                    if m:
                        files[m.group(1)] = stdin
                W.save(s)
            W.log("ssh", argv)
            if out:
                sys.stdout.write(out if out.endswith("\n") else out + "\n")
            return rc
    return W.ssh_tool(argv)


def sshpass(argv):
    target, rest = W.target_of(argv[2:])
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = W.BY_IP.get(host)
    if node and node == F["fw"] and not rest:
        data = sys.stdin.read()
        W.log("sshpass", argv)
        print(fw_cli(data))
        return 0
    if node and NODES[node]["kind"] == "dell_sonic" and " ".join(rest) == "sonic-cli":
        data = sys.stdin.read()
        out = switch_cli(node, data)
        if out is not None:
            W.log("sshpass", argv)
            print(out)
            return 0
        return W.delegate("sshpass", argv, data)
    return W.sshpass(argv)


def docker_tool(argv):
    if argv[:1] != ["exec"]:
        return W.delegate("docker", argv)
    rest = argv[1:]
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in ("-e", "-u", "-w") else rest[1:]
    ctr, cmd = rest[0], rest[1:]
    interactive = "-i" in argv[1:argv.index(ctr)]
    node = node_of_ctr(ctr)
    kind = (NODES.get(node) or {}).get("kind")
    if kind in ("client", "resolver", "frr"):
        stdin = sys.stdin.read() if interactive else None
        if cmd[:2] == ["python3", "-"] and stdin and ("hold_conns.py" in stdin[:400] or "hold_request.py" in stdin[:400]):
            W.log("docker", argv)
            return blocking(ctr, cmd[2:], stdin)
        if kind == "frr" and cmd[:2] == ["vtysh", "-c"] and cmd[2] == "show ip route" and node in F["routers"]:
            W.log("docker", argv)
            print(frr_text(node))
            return 0
        if kind == "frr" and cmd[:2] == ["sh", "-c"] and stdin is not None and "dnsq.py" in stdin[:400]:
            with W.locked():
                s = W.load()
                r = run_python(s, ctr, cmd[4:], stdin, time.time())
                W.save(s)
            W.log("docker", argv)
            print(r[1])
            return r[0]
        with W.locked():
            s = W.load()
            p3(s)
            r = p3_client(s, ctr, cmd, stdin, time.time())
            W.save(s)
        if r is not None:
            W.log("docker", argv)
            rc, out = r
            if out:
                sys.stdout.write(out if out.endswith("\n") else out + "\n")
            return rc
        if kind == "client":
            # chapter 7's and 6's stand-ins read standard input themselves
            import io  # noqa: PLC0415

            sys.stdin = io.StringIO(stdin or "")
            return W7.docker7(argv)
        if kind == "resolver" and cmd[:1] == ["rm"]:
            return 0
        return 0 if kind in ("resolver",) else W.delegate("docker", argv, stdin)
    return W7.docker7(argv)


def frr_text(node):
    rows = ["Codes: K - kernel route, C - connected, S - static", ""]
    for r in F["routers"][node]:
        if r["type"] == "C":
            rows.append(f"C>* {r['dest']} is directly connected, eth1, 00:09:00")
        else:
            rows.append(f"S>* {r['dest']} [1/0] via {r['via']}, eth1, weight 1, 00:09:00")
    return "\n".join(rows)


def tcpdump_tool(argv):
    if "-r" in argv and "-w" not in argv:
        f = os.path.abspath(argv[argv.index("-r") + 1])
        s = W.load()
        cap = (s.get("hcaps") or {}).get(f)
        if cap and p3_point(cap["node"], eth=cap["eth"]):
            print(frames_at(s, cap["node"], eth=cap["eth"], start=cap["start"]))
            return 0
    return W7.tcpdump7(argv)


def api_params(argv):
    """The XML API's form fields and URL, as fw-api.sh sends them (--data-urlencode k=v, k@file)."""
    import urllib.parse  # noqa: PLC0415

    params, url, i = {}, None, 0
    while i < len(argv):
        a = argv[i]
        if a in ("--data-urlencode", "--data"):
            k, _, v = argv[i + 1].partition("=")
            if "@" in k and not v:
                k, _, f = k.partition("@")
                params[k] = sys.stdin.read() if f == "-" else open(f).read()
            else:
                params[k] = v
            i += 2
            continue
        if a in ("-H", "-o", "-m", "--max-time"):
            i += 2
            continue
        if not a.startswith("-"):
            url = a
        i += 1
    if url:
        for k, v in urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query):
            params.setdefault(k, v)
    return params, url


def curl_tool(argv):
    """The firewall's XML API: keygen, break-10a's edit of a security rule's destination, commits."""
    params, url = api_params(argv)
    host = (url or "").split("/")[2] if url and url.count("/") >= 2 else ""
    if W.BY_IP.get(host) == F["fw"]:
        t = params.get("type")
        W.log("curl", argv)
        if t == "keygen":
            print("<response status='success'><result><key>LUFRPTshimkey0123456789abcdef==</key></result></response>")
            return 0
        if t == "config" and params.get("action") == "edit" and "/security/rules/entry" in params.get("xpath", ""):
            names = re.findall(r"entry\[@name='([^']+)'\]", params["xpath"])
            mem = re.findall(r"<member>([^<]+)</member>", params.get("element", ""))
            with W.locked():
                s = W.load()
                c = p3(s)
                rule = next((r for r in F["rules"] if names and r["name"] == names[-1]), None)
                if rule and mem and sorted(x.split("/")[0] for x in rule["dst"]) != sorted(mem):
                    c["rule_dst"][rule["name"]] = mem
                elif rule:
                    c["rule_dst"].pop(rule["name"], None)
                W.save(s)
            print("<response status='success' code='20'><msg>command succeeded</msg></response>")
            return 0
        if t == "commit":
            print("<response status='success' code='19'><result><msg><line>Commit job enqueued with jobid 7</line></msg><job>7</job></result></response>")
            return 0
        if t == "op" and "<jobs>" in params.get("cmd", ""):
            print("<response status='success'><result><job><id>7</id><status>FIN</status><result>OK</result><details></details></job></result></response>")
            return 0
        if t == "config" and params.get("action") == "show":
            print("<response status='success'><result></result></response>")
            return 0
    import subprocess  # noqa: PLC0415

    r = subprocess.run([sys.executable, str(W.SHARED / "_devices.py"), "curl"] + argv, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    return r.returncode


if __name__ == "__main__":
    tool = sys.argv[1]
    W.KUBE_HOOK = knode
    if tool == "docker":
        sys.exit(docker_tool(sys.argv[2:]))
    if tool == "tcpdump":
        sys.exit(tcpdump_tool(sys.argv[2:]))
    if tool == "ssh":
        sys.exit(ssh_tool(sys.argv[2:]))
    if tool == "sshpass":
        sys.exit(sshpass(sys.argv[2:]))
    if tool == "curl":
        sys.exit(curl_tool(sys.argv[2:]))
    sys.exit({"nsenter": W.nsenter}[tool](sys.argv[2:]))
