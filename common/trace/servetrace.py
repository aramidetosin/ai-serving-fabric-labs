#!/usr/bin/env python3
"""servetrace.py: chapter 6's serving trace, its capture points and its judgment
(common/trace/lib-servetrace.sh).

    servetrace.py get    --plan gen/trace.json PATH          a value of the plan (a list one item a line)
    servetrace.py points --plan gen/trace.json --set DIR     the capture points, from the pods and the
                                                             lease the set saved (cluster/): TSV, one a line,
                                                             id, kind, node, namespace, pod, interface,
                                                             filter, capture length, keyed (1 or 0)
    servetrace.py judge  --set DIR --plan gen/trace.json --inv INV [--stamp TEXT]

The plan is gen/trace.json (sfab.render.trace, serving form). The points are found when the trace
runs: the node the users' VIP's lease names (its bond0, port 443 to the VIP), every API gateway pod
and every router pod on its cluster interface (eth0), every server of the model on eth0 and on its
rail attachment, every worker on its rail attachment, and the rail switch ports facing each copy's
nodes on its rail (each a container port on the lab host). A pod's capture runs inside its network
namespace in its node's guest and is decoded there.

judge reads the saved files only and prints the result vocabulary, appending each line to
$SFAB_VERDICT, then writes TRACE.md. It follows the request hop by hop, by the addresses each hop
sends to and the segments that carry data (a segment with a TCP payload; the kubelet's probes of the
API gateway carry none, and its probes of the router come from no API gateway pod):

  the client  HTTP 200, the router naming the model's deployment and the model's Service, no retry
  the VIP     the client's SYN from its pinned source port reaching the lease holder's bond0, and
              data both ways
  API gateway one API gateway pod receiving data on its port from the Gateway and sending it on to a
              router pod; the other API gateway pods none
  router      that router pod receiving data from that API gateway pod and sending it to one server
              of the model; the other router pods none
  server      that server receiving it on eth0 from that router pod and answering
  the rail    the server's RPC on its rail attachment to every worker of its copy, both ways, and
              every worker seeing it on its own attachment, at the addresses the table names
  the switch  the rail switch ports facing the server's node and the other node carrying the RPC to
              the worker on the other node, and no frame of the RPC to a worker beside its server
              (macvlan's bridge mode keeps that inside the node)
  the other   the model's other copies: no data to their servers, no RPC on their rail; a router's
              connection to one of them set aside when a keyed capture shows it is GET /v1/models
              (the router reads each model's list now and then), or when all its data falls more
              than a second outside the request's life at the router

Every capture holds headers only on a pod's cluster interface (66 bytes a frame), so no capture
holds an HTTP header; the key travels in the client's 0600 header file and is never printed.
Decodes are tcpdump -nn -tt -e -v -r. Standard library only.

Chapter 7's keyed trace (the plan's keys.capture) captures the API gateway's and the router's
cluster interfaces whole instead, each pcap scrubbed on its way out of the guest
(common/trace/keyscrub.py: every Authorization value replaced by its keyed mark) and decoded twice,
<point>.txt as above and <point>-payload.txt with -A. The judge then reads the HTTP requests each
hop carried, from the payload decodes:

  hop 1       the request from the Gateway's proxy to the API gateway pod: POST on the model's path,
              its Authorization the caller's key (its mark the one request/key.txt names)
  hop 2       the API gateway pod to the router pod: POST on the router's path for the model, its
              Authorization the router's master key, and the caller's key nowhere on it
  hop 3       the router pod to the server: its Authorization the backend key
  the marks   every Authorization value in the payload decodes a mark, none a value

and with the plan's refuse, the request to a hostname the Gateway does not carry: the Gateway's 404
(server envoy), the client's SYN at the lease holder, and no request for that hostname at any API
gateway pod, which received exactly the keyed request.

Part III (chapter 8) adds a node of the cluster as the client (the plan's client.local): its request
names the VIP with curl --resolve, the node's own datapath answers the VIP, so the node's own ports
are captured to show no SYN to the VIP leaves it, in place of the lease holder's bond0; and the
plan's also, the same key and path sent to another Gateway (refuse.gateway, a hostname there): that
Gateway's 404 with no request for it at any API gateway pod.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import evfile  # noqa: E402
import vocab  # noqa: E402

TCP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]")
FRAME_START = re.compile(r"^(\d{9,11}\.\d{6}) ")
REQ = re.compile(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (/\S*) HTTP/1\.[01]")
AUTHZ = re.compile(r"(?i)^[^\S\r\n]*authorization[ \t]*:[ \t]*(?:(?:bearer|basic|token)[ \t]+)?([^\r\n]+)")
HOST = re.compile(r"(?i)^[^\S\r\n]*host[ \t]*:[ \t]*(\S+)")
MARK = re.compile(r"<redacted hmac:([0-9a-f]{12})>")
# the TCP payload length: the first ", length N" after the flags (tcpdump may follow it with the
# protocol it recognises on the port, as in "length 742: HTTP" on 8080)
LEN = re.compile(r"Flags \[[^\]]*\].*?, length (\d+)")
TS = re.compile(r"^(\d+\.\d+) ")


def load(p):
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def cmd_get(a) -> int:
    cur = load(a.plan)
    for part in a.path.split("."):
        if isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)] if int(part) < len(cur) else None
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


# --------------------------------------------------------------------------------------------
# the cluster as the set saved it


def pods(rs: Path, ns: str) -> dict:
    """name -> {ip, node, labels, phase} from cluster/pods-<ns>.json."""
    try:
        doc = load(rs / "cluster" / f"pods-{ns}.json")
    except (OSError, ValueError):
        return {}
    out = {}
    for i in doc.get("items") or []:
        md, st, sp = i.get("metadata") or {}, i.get("status") or {}, i.get("spec") or {}
        out[md.get("name")] = {"ip": st.get("podIP"), "node": sp.get("nodeName"), "labels": md.get("labels") or {},
                               "phase": st.get("phase")}
    return out


def selected(ps: dict, selector: str) -> list:
    k, _, v = selector.partition("=")
    return sorted(n for n, p in ps.items() if p["labels"].get(k) == v and p.get("phase") == "Running")


def lease_holder(rs: Path) -> str | None:
    try:
        doc = load(rs / "cluster" / "lease.json")
    except (OSError, ValueError):
        return None
    return (doc.get("spec") or {}).get("holderIdentity")


def pid(plan: dict, depth: int, name: str) -> str:
    """A capture point's id, <depth>-<name>, its depth counted after the plan's depth_base (chapter
    1's walk puts the frontend's depths first; chapters 6 and 7 have none)."""
    return f"{depth + int(plan.get('depth_base') or 0)}-{name}"


def point_rows(plan: dict, rs: Path) -> list:
    """Every capture point: (id, kind, node, ns, pod, iface, filter, snaplen, keyed)."""
    sn = plan["snaplen"]
    keyed = bool((plan.get("keys") or {}).get("capture"))
    ksn = sn.get("keyed", 2048) if keyed else sn["http"]
    rows = []
    holder = lease_holder(rs)
    gw = plan["gateway"]
    if (plan["client"] or {}).get("local"):
        # a node of the cluster answers its own Gateways' VIPs (Part III, chapter 8): its own ports are
        # captured, as the wire carries them, to show no SYN to a VIP leaves it
        vips = " or ".join(f"host {x}" for x in [gw["vip"]] + [a["vip"] for a in plan.get("also") or []]
                           + ([plan["refuse"]["vip"]] if (plan.get("refuse") or {}).get("vip") else []))
        filt = f"tcp port {gw['port']} and ({vips})"
        for x in plan["client"]["ports"]:
            rows.append((x["id"], "host", x["node"], "-", "-", x["eth"], f"({filt}) or (vlan and ({filt}))", sn["vip"], 0))
    elif holder:
        rows.append((pid(plan, 1, f"{holder}-bond0"), "guest", holder, "-", "-", "bond0", f"tcp port {gw['port']} and host {gw['vip']}",
                     sn["vip"], 0))
    pi = pods(rs, plan["api_gateway"]["namespace"])
    ag, ro = plan["api_gateway"], plan["router"]
    for n in selected(pi, ag["selector"]):
        rows.append((pid(plan, 2, f"{n}-eth0"), "pod", pi[n]["node"], ag["namespace"], n, "eth0", f"tcp port {ag['port']} or tcp port {ro['port']}",
                     ksn, int(keyed)))
    for n in selected(pi, ro["selector"]):
        rows.append((pid(plan, 3, f"{n}-eth0"), "pod", pi[n]["node"], ro["namespace"], n, "eth0",
                     f"tcp port {ro['port']} or tcp port {plan['serving']['http_port']}", ksn, int(keyed)))
    sv = plan["serving"]
    for c in plan["copies"]:
        s = c["server"]
        rows.append((pid(plan, 4, f"{s['pod']}-eth0"), "pod", s["node"], sv["namespace"], s["pod"], "eth0", f"tcp port {sv['http_port']}",
                     sn["http"], 0))
        rows.append((pid(plan, 4, f"{s['pod']}-{c['nad']}"), "pod", s["node"], sv["namespace"], s["pod"], c["nad"], f"tcp port {sv['rpc_port']}",
                     sn["rail"], 0))
        for w in c["workers"]:
            rows.append((pid(plan, 5, f"{w['pod']}-{c['nad']}"), "pod", w["node"], sv["namespace"], w["pod"], c["nad"],
                         f"tcp port {sv['rpc_port']}", sn["rail"], 0))
        for p in c["switch_ports"]:
            rows.append((p["id"], "host", p["node"], "-", "-", p["eth"], f"tcp port {sv['rpc_port']}", sn["rail"], 0))
    return rows


def cmd_points(a) -> int:
    for r in point_rows(load(a.plan), Path(a.set)):
        print("\t".join(str(x) for x in r))
    return 0


# --------------------------------------------------------------------------------------------
# decodes


def frames(text: str) -> list:
    """Every TCP segment of a tcpdump -nn -tt -e [-v] decode: t, src, sport, dst, dport, flags,
    length (the TCP payload), line (the decode line it starts on)."""
    out = []
    lines = (text or "").splitlines()
    i = 0
    while i < len(lines):
        head = lines[i]
        m0 = TS.match(head)
        if not m0:
            i += 1
            continue
        start = i + 1
        body = head
        while i + 1 < len(lines) and lines[i + 1][:1].isspace():
            i += 1
            body += " " + lines[i].strip()
        i += 1
        m = TCP.search(body)
        if not m:
            continue
        lm = LEN.search(body)
        out.append({"t": float(m0.group(1)), "src": m.group(1), "sport": int(m.group(2)), "dst": m.group(3),
                    "dport": int(m.group(4)), "flags": m.group(5), "length": int(lm.group(1)) if lm else 0, "line": start})
    return out


def data(fr: list, src=None, dst=None, sport=None, dport=None) -> list:
    """The segments carrying data, optionally from src or to dst (an address or a set), ports given."""
    def has(v, want):
        return want is None or (v in want if isinstance(want, (set, list, tuple)) else v == want)
    return [f for f in fr if f["length"] > 0 and has(f["src"], src) and has(f["dst"], dst) and has(f["sport"], sport)
            and has(f["dport"], dport)]


def http_requests(text: str) -> list:
    """The HTTP requests of a -A payload decode: one a frame whose payload holds a request line,
    with the frame's t, src, sport, dst, dport, the method, path, Host, the Authorization value as
    the decode holds it (a mark, after keyscrub.py), the decode line the frame starts on and the
    line of its Authorization header."""
    out = []
    lines = (text or "").splitlines()
    starts = [i for i, l in enumerate(lines) if FRAME_START.match(l)] + [len(lines)]
    for a, b in zip(starts, starts[1:]):
        block = lines[a:b]
        m = TCP.search(" ".join(block[:3]))
        ri = next((i for i, l in enumerate(block) if REQ.search(l)), None)
        if not m or ri is None:
            continue
        r = REQ.search(block[ri])
        auth = host = None
        auth_line = None
        for j in range(ri + 1, len(block)):
            l = block[j]
            if auth is None:
                am = AUTHZ.match(l)
                if am:
                    auth, auth_line = am.group(1), a + j + 1
            if host is None:
                hm = HOST.match(l)
                if hm:
                    host = hm.group(1)
        out.append({"t": float(FRAME_START.match(lines[a]).group(1)), "src": m.group(1), "sport": int(m.group(2)), "dst": m.group(3),
                    "dport": int(m.group(4)), "method": r.group(1), "path": r.group(2), "host": host, "authorization": auth,
                    "line": a + 1, "auth_line": auth_line})
    return out


def model_list_polls(rs: Path, plan: dict, rows: list) -> set:
    """The (address, port) of each connection a keyed router capture shows carrying GET /v1/models:
    the router reads each model's list from its Service on its own now and then (chapter 1's walk
    met one at a copy that did not serve the request), so such a connection is not the request."""
    return {(r["src"], r["sport"]) for row in rows if len(row) > 8 and row[8] and row[0].startswith(pid(plan, 3, ""))
            for r in http_requests(read(rs / "captures" / f"{row[0]}-payload.txt"))
            if r["method"] == "GET" and r["path"].rstrip("/").endswith("/v1/models")}


LIFE_SLACK_S = 1.0  # the guests' clocks agree within milliseconds (chrony); a second of slack


def request_life(fr: list, agp_ip: str, rop_ip: str, port: int):
    """(first, last): the request's data arriving at the router pod from the API gateway pod and the
    router's last data back to it, from the router's capture; None when either is missing."""
    i_ = data(fr, src=agp_ip, dst=rop_ip, dport=port)
    o_ = data(fr, src=rop_ip, dst=agp_ip, sport=port)
    if not i_ or not o_:
        return None
    return min(f["t"] for f in i_), max(f["t"] for f in o_)


def outside_life(got: list, life, routers: set) -> set:
    """The (address, port) of each connection from a router pod whose every data segment lies more than
    LIFE_SLACK_S outside life."""
    if life is None:
        return set()
    conns: dict = {}
    for f in got:
        if f["src"] in routers:
            conns.setdefault((f["src"], f["sport"]), []).append(f["t"])
    return {k for k, ts in conns.items()
            if all(t < life[0] - LIFE_SLACK_S or t > life[1] + LIFE_SLACK_S for t in ts)}


def in_life(segs: list, life) -> list:
    """The segments of segs inside life, both ends included: the router's data to a server that can
    carry the request (it comes after the request reached the router and before the router answered;
    both are read from the router's own capture, so no slack). A router's own read of a model's list
    a few seconds before the request, at another copy, is not the request's upstream. With no life,
    every segment."""
    if life is None:
        return list(segs)
    return [f for f in segs if life[0] <= f["t"] <= life[1]]


def mark_in(value) -> str | None:
    m = MARK.search(value or "")
    return m.group(0) if m else None


def key_line(path: Path) -> dict:
    """The last line of a key file the trace wrote: field, fingerprint and mark."""
    parts = (read(path).strip().splitlines() or [""])[-1].split()
    return {"field": parts[0] if parts else None, "fingerprint": parts[1] if len(parts) > 1 else None,
            "mark": mark_in(" ".join(parts[2:])) if len(parts) > 2 else None}


def headers(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition(":")
        if sep and k.strip() and " " not in k.strip():
            out[k.strip().lower()] = v.strip()
    return out


# --------------------------------------------------------------------------------------------
# judgment


def judge(a) -> int:
    rs = Path(a.set)
    plan = load(a.plan)
    inv = load(a.inv)
    # a pinned trace's request took the source port of the try that landed on the pinned copy
    sp = read(rs / "request" / "sport.txt").strip()
    if plan.get("pin") and sp.isdigit():
        plan["sport"] = int(sp)
    v = vocab.Vocab(known=set(inv.get("known") or []) or None)
    rows = point_rows(plan, rs)
    decs = {r[0]: frames(read(rs / "captures" / f"{r[0]}.txt")) for r in rows}
    j = judge_serving(v, rs, plan, rows, decs)
    keyhops = judge_keys(v, rs, plan, rows, j["pi"], j["agp"], j["rop"], j["srv_ip"]) if (plan.get("keys") or {}).get("capture") else []
    also = judge_also(v, rs, plan, rows) if plan.get("also") else []
    refused = judge_refuse(v, rs, plan, rows, decs, j["pi"]) if plan.get("refuse") else None
    counts = vocab.counts_of(os.environ["SFAB_VERDICT"]) if os.environ.get("SFAB_VERDICT") else v.counts()
    write_md(rs, inv, plan, rows, decs, j["hops"], j["copy"], j["status"], j["headers"], counts, a.stamp, keyhops, refused, also)
    return 1 if v.counts()["fail"] else 0


def judge_serving(v, rs: Path, plan: dict, rows: list, decs: dict) -> dict:
    """The serving form's judgment from the client's answer to the model's other copies: the hops,
    the copy that served, the answer's status and headers, and the pods that took the request
    (chapter 1's walk reuses it with its own points before these)."""
    pi = pods(rs, plan["api_gateway"]["namespace"])
    psv = pods(rs, plan["serving"]["namespace"])
    ag, ro, sv, gw = plan["api_gateway"], plan["router"], plan["serving"], plan["gateway"]
    hops: list = []

    v.sec(f"the request: {plan['client']['node']} to {plan['model']} through {gw['name']}")
    res = read(rs / "request" / "result.txt").split()
    status = int(res[0]) if res and res[0].isdigit() else 0
    h = headers(read(rs / "request" / "headers.txt"))
    ex = plan["expect"]
    retries = h.get("x-litellm-attempted-retries")
    v.check(f"HTTP {ex['status']} for POST {plan['url']} with {plan['model']}'s key", status == ex["status"], f"HTTP {status or 'none'}")
    v.check(f"answered by the router's {ex['model_name']} deployment, on the model's Service {ex['api_base']}, with no retry",
            h.get("x-litellm-model-name") == ex["model_name"] and h.get("x-litellm-model-api-base") == ex["api_base"] and retries == "0",
            f"model {h.get('x-litellm-model-name')}, API base {h.get('x-litellm-model-api-base')}, retries {retries}")

    v.sec("the users' VIP")
    holder = lease_holder(rs)
    vip_id = pid(plan, 1, f"{holder}-bond0") if holder else None
    if (plan["client"] or {}).get("local"):
        ports = [r[0] for r in rows if r[0].startswith("0-")]
        out_ = [f for r in ports for f in decs.get(r) or [] if f["dst"] == gw["vip"] and f["dport"] == gw["port"] and "S" in f["flags"]]
        v.check(f"{plan['client']['node']} answers {gw['name']}'s VIP {gw['vip']} itself: no SYN to it left the node on its "
                f"{len(ports)} port(s) ({', '.join(ports)}), so the lease holder ({holder or 'unread'}) never saw the request",
                bool(ports) and not out_, f"{len(out_)} SYN(s) on the node's ports")
        hops.append({"hop": "Gateway VIP (answered on the node)", "point": ports[0] if ports else "-", "node": plan["client"]["node"],
                     "address": f"{gw['vip']}:{gw['port']}", "first": None})
    elif vip_id is None:
        v.bad(f"the node holding {gw['lease']}", "the lease was not read")
    else:
        fr = decs.get(vip_id) or []
        syn = [f for f in fr if f["src"] == plan["client"]["address"] and f["sport"] == plan["sport"] and f["dst"] == gw["vip"]
               and f["dport"] == gw["port"] and "S" in f["flags"] and "." not in f["flags"]]
        up = data(fr, src=plan["client"]["address"], dst=gw["vip"], sport=plan["sport"], dport=gw["port"])
        down = data(fr, src=gw["vip"], dst=plan["client"]["address"], sport=gw["port"], dport=plan["sport"])
        v.check(f"{holder}, which holds {gw['name']}'s lease: the client's SYN from {plan['client']['address']} port {plan['sport']} to "
                f"{gw['vip']}:{gw['port']} on bond0, and data both ways ({len(up)} segments in, {len(down)} out)",
                bool(syn) and bool(up) and bool(down), f"SYN {len(syn)}, in {len(up)}, out {len(down)}")
        hops.append({"hop": "Gateway VIP", "point": vip_id, "node": holder, "address": f"{gw['vip']}:{gw['port']}",
                     "first": (syn or up or [None])[0]})

    v.sec("the API gateway and the router")
    ag_pods = selected(pi, ag["selector"])
    ro_pods = selected(pi, ro["selector"])
    ro_ips = {pi[n]["ip"]: n for n in ro_pods if pi[n].get("ip")}
    took = []
    for n in ag_pods:
        fr = decs.get(pid(plan, 2, f"{n}-eth0")) or []
        ip = pi[n]["ip"]
        i_ = data(fr, dst=ip, dport=ag["port"])
        o_ = data(fr, src=ip, dst=set(ro_ips), dport=ro["port"])
        if i_ and o_:
            took.append((n, i_, o_))
    others = [n for n in ag_pods if n not in [t[0] for t in took]]
    agp = None
    if len(took) == 1:
        agp, i_, o_ = took[0]
        rp = ro_ips.get(o_[0]["dst"])
        v.ok(f"one API gateway pod took it: {agp} on {pi[agp]['node']} ({pi[agp]['ip']}:{ag['port']}), data from the Gateway's proxy at "
             f"{i_[0]['src']}, sent on to the router pod {rp} ({o_[0]['dst']}:{ro['port']})"
             + (f"; {', '.join(others)} took none" if others else ""))
        hops.append({"hop": "API gateway", "point": pid(plan, 2, f"{agp}-eth0"), "node": pi[agp]["node"], "address": f"{pi[agp]['ip']}:{ag['port']}",
                     "first": i_[0], "pod": agp})
    else:
        v.bad("one API gateway pod took it and sent it to a router pod", f"{len(took)} of {len(ag_pods)} did ({', '.join(t[0] for t in took) or 'none'})")
    rop, srv_ip = None, None
    server_ips = {psv[c["server"]["pod"]]["ip"]: c for c in plan["copies"] if (psv.get(c["server"]["pod"]) or {}).get("ip")}
    if agp:
        rp = ro_ips.get(took[0][2][0]["dst"])
        fr = decs.get(pid(plan, 3, f"{rp}-eth0")) or []
        ip = pi[rp]["ip"]
        i_ = data(fr, src=pi[agp]["ip"], dst=ip, dport=ro["port"])
        o_ = in_life(data(fr, src=ip, dst=set(server_ips), dport=sv["http_port"]), request_life(fr, pi[agp]["ip"], ip, ro["port"]))
        other_ro = [n for n in ro_pods if n != rp and data(decs.get(pid(plan, 3, f"{n}-eth0")) or [], src=pi[agp]["ip"], dport=ro["port"])]
        if i_ and o_:
            rop, srv_ip = rp, o_[0]["dst"]
            c = server_ips[srv_ip]
            v.ok(f"the router pod {rp} on {pi[rp]['node']} received it from {agp} and sent it to {c['server']['pod']} ({srv_ip}:{sv['http_port']}), "
                 f"{plan['model']}'s copy {c['copy']} on rail {c['rail']}" + (f"; also seen at {', '.join(other_ro)}" if other_ro else ""))
            hops.append({"hop": "router", "point": pid(plan, 3, f"{rp}-eth0"), "node": pi[rp]["node"], "address": f"{ip}:{ro['port']}", "first": i_[0], "pod": rp})
        else:
            v.bad(f"the router pod {rp} received it from {agp} and sent it to a server of {plan['model']}",
                  f"in {len(i_)}, out to a server {len(o_)}")
        if other_ro:
            v.bad("no other router pod received it", ", ".join(other_ro))
    copy = server_ips.get(srv_ip) if srv_ip else None
    v.sec("the server and its workers on the rail")
    pin = plan.get("pin")
    if pin:
        tries = [x for x in read(rs / "request" / "attempts.txt").splitlines() if x.strip()]
        v.check(f"the request landed on copy {pin['copy']}, the one the plan pins (try {len(tries)} of at most {pin['tries']}; "
                "the captures of each miss discarded)", copy is not None and copy["copy"] == pin["copy"],
                f"copy {copy['copy'] if copy else 'none'} served it")
    if copy is None:
        v.bad("the copy that served it", "no server of the model received it")
    else:
        s = copy["server"]
        fr = decs.get(pid(plan, 4, f"{s['pod']}-eth0")) or []
        i_ = data(fr, src=pi[rop]["ip"], dst=srv_ip, dport=sv["http_port"])
        o_ = data(fr, src=srv_ip, dst=pi[rop]["ip"], sport=sv["http_port"])
        v.check(f"{s['pod']} on {s['node']} received it on eth0 from {rop} and answered ({len(i_)} data segments in, {len(o_)} out)",
                bool(i_) and bool(o_), f"in {len(i_)}, out {len(o_)}")
        hops.append({"hop": "server", "point": pid(plan, 4, f"{s['pod']}-eth0"), "node": s["node"], "address": f"{srv_ip}:{sv['http_port']}",
                     "first": (i_ or [None])[0], "pod": s["pod"]})
        rfr = decs.get(pid(plan, 4, f"{s['pod']}-{copy['nad']}")) or []
        for w in copy["workers"]:
            out_ = data(rfr, src=s["address"], dst=w["address"], dport=sv["rpc_port"])
            back = data(rfr, src=w["address"], dst=s["address"], sport=sv["rpc_port"])
            v.check(f"{s['pod']}'s RPC on {copy['nad']} ({s['address']}) to {w['pod']} at {w['address']}:{sv['rpc_port']}, the table's "
                    f"rail {copy['rail']}: {len(out_)} data segments out, {len(back)} back", bool(out_) and bool(back),
                    f"out {len(out_)}, back {len(back)}")
            wfr = decs.get(pid(plan, 5, f"{w['pod']}-{copy['nad']}")) or []
            got = data(wfr, src=s["address"], dst=w["address"], dport=sv["rpc_port"])
            v.check(f"{w['pod']} on {w['node']} saw it on its own {copy['nad']} ({len(got)} data segments from {s['address']})", bool(got),
                    f"{len(got)} segments")
            hops.append({"hop": f"worker{' (other node)' if w['remote'] else ' (same node)'}", "point": pid(plan, 5, f"{w['pod']}-{copy['nad']}"),
                         "node": w["node"], "address": f"{w['address']}:{sv['rpc_port']}", "first": (got or [None])[0], "pod": w["pod"]})
        v.sec(f"{copy['switch']}: the rail switch of rail {copy['rail']}")
        remote = [w for w in copy["workers"] if w["remote"]]
        local = [w for w in copy["workers"] if not w["remote"]]
        for p in copy["switch_ports"]:
            pf = decs.get(p["id"]) or []
            for w in remote:
                got = data(pf, src={s["address"], w["address"]}, dst={s["address"], w["address"]})
                v.check(f"{p['node']} {p['native']} (facing {p['faces']}) carried the RPC between {s['address']} and {w['address']}, the worker on "
                        f"the other node ({len(got)} data segments)", bool(got), f"{len(got)} segments")
                hops.append({"hop": f"{p['node']} {p['native']}", "point": p["id"], "node": p["node"], "address": f"faces {p['faces']}",
                             "first": (got or [None])[0]})
            for w in local:
                got = [f for f in pf if {f["src"], f["dst"]} == {s["address"], w["address"]}]
                v.check(f"... and no frame of the RPC to {w['pod']} ({w['address']}), beside its server on {w['node']}: macvlan's bridge mode "
                        "keeps it inside the node", not got, f"{len(got)} frames")
        v.sec(f"{plan['model']}'s other copies")
        polls = model_list_polls(rs, plan, rows)
        life = request_life(decs.get(pid(plan, 3, f"{rop}-eth0")) or [], pi[agp]["ip"], pi[rop]["ip"], ro["port"])
        for c in plan["copies"]:
            if c["copy"] == copy["copy"]:
                continue
            seen = []
            fr = decs.get(pid(plan, 4, f"{c['server']['pod']}-eth0")) or []
            got = data(fr, dport=sv["http_port"])
            aside = [f for f in got if (f["src"], f["sport"]) in polls]
            # unkeyed captures hold no request line: a router connection whose data all falls outside
            # the request's life at the router (more than LIFE_SLACK_S before it arrived or after the
            # router answered) cannot carry the request or its retry, so it is set aside as well
            later = outside_life(got, life, {pi[n]["ip"] for n in ro_pods if pi[n].get("ip")}) - polls
            aside += [f for f in got if (f["src"], f["sport"]) in later]
            if len(got) > len(aside):
                seen.append(f"{c['server']['pod']} eth0")
            pts = ([pid(plan, 4, f"{c['server']['pod']}-{c['nad']}")] + [pid(plan, 5, f"{w['pod']}-{c['nad']}") for w in c["workers"]]
                   + [p["id"] for p in c["switch_ports"]])
            for pt in pts:
                if data(decs.get(pt) or [], dport=sv["rpc_port"]) or data(decs.get(pt) or [], sport=sv["rpc_port"]):
                    seen.append(pt)
            conns = sorted({f"{f['src']}:{f['sport']}" for f in aside if (f["src"], f["sport"]) in polls})
            outs = sorted({f"{f['src']}:{f['sport']}" for f in aside if (f["src"], f["sport"]) in later})
            notes = ([f"a router's GET /v1/models from {', '.join(conns)}"] if conns else []) + (
                [f"a router's connection from {', '.join(outs)} outside the request's life at the router "
                 f"({life[0]:.3f} to {life[1]:.3f})"] if outs else [])
            v.check(f"copy {c['copy']} on rail {c['rail']} carried none of it: no data to {c['server']['pod']}, no RPC on {c['nad']} at its server, "
                    f"its workers or {c['switch']}'s ports" + (f" (set aside: {'; '.join(notes)})" if notes else ""),
                    not seen, ", ".join(seen))
    return {"hops": hops, "copy": copy, "status": status, "headers": h, "pi": pi, "agp": agp, "rop": rop, "srv_ip": srv_ip}


def judge_keys(v, rs: Path, plan: dict, rows: list, pi: dict, agp, rop, srv_ip) -> list:
    """The keys at the in-cluster hops, from the scrubbed payload decodes."""
    k = plan["keys"]
    caller, master, backend = (key_line(rs / "request" / f) for f in ("key.txt", "master-key.txt", "backend-key.txt"))
    ag, ro, sv = plan["api_gateway"], plan["router"], plan["serving"]
    reqs = {r[0]: http_requests(read(rs / "captures" / f"{r[0]}-payload.txt")) for r in rows if len(r) > 8 and r[8]}
    out: list = []
    v.sec("the keys at the in-cluster hops (the captures' Authorization values replaced by their marks)")
    for who, kl in (("the caller's", caller), ("the router's master", master), ("the backend", backend)):
        if not kl["mark"]:
            v.bad(f"{who} key's mark read from its Secret", "no mark (the key or the redaction key was not read)")
    if not agp:
        v.bad("hop 1: the API gateway pod that took the request", "no API gateway pod took it (above)")
        return out
    aip = pi[agp]["ip"]
    a_reqs = reqs.get(pid(plan, 2, f"{agp}-eth0")) or []
    h1 = [r for r in a_reqs if r["dst"] == aip and r["dport"] == ag["port"] and r["method"] == "POST" and r["path"] == plan["path"]]
    m1 = mark_in(h1[0]["authorization"]) if h1 else None
    v.check(f"hop 1, the Gateway's proxy to {agp}: POST {plan['path']} with Authorization {caller['mark'] or '-'}, the caller's {plan['model']} key "
            f"({caller['field']} {caller['fingerprint']})", bool(h1) and m1 is not None and m1 == caller["mark"],
            f"{len(h1)} such requests" + (f", Authorization {h1[0]['authorization'][:40]}" if h1 else ""))
    if h1:
        out.append({"hop": "1: Gateway to API gateway", "point": pid(plan, 2, f"{agp}-eth0"), "request": h1[0], "mark": m1, "key": "the caller's key"})
    rip = pi[rop]["ip"] if rop else None
    h2 = [r for r in a_reqs if r["src"] == aip and r["dport"] == ro["port"] and r["method"] == "POST" and r["path"] == k["router_path"]]
    m2 = mark_in(h2[0]["authorization"]) if h2 else None
    leaked = [r for r in a_reqs if r["src"] == aip and r["dport"] == ro["port"] and caller["mark"] and mark_in(r["authorization"]) == caller["mark"]]
    v.check(f"hop 2, {agp} to the router{' pod ' + rop if rop else ''}: POST {k['router_path']} with Authorization {master['mark'] or '-'}, the "
            f"router's master key ({master['fingerprint']}), set in place of the caller's", bool(h2) and m2 is not None and m2 == master["mark"],
            f"{len(h2)} such requests" + (f", Authorization {h2[0]['authorization'][:40]}" if h2 else ""))
    v.check(f"... and the caller's key nowhere on hop 2 ({len(leaked)} requests to the router carry its mark)", not leaked,
            ", ".join(f"line {r['line']}" for r in leaked[:3]))
    if h2:
        out.append({"hop": "2: API gateway to router", "point": pid(plan, 2, f"{agp}-eth0"), "request": h2[0], "mark": m2, "key": "the router's master key"})
    if rop and rip:
        r_reqs = reqs.get(pid(plan, 3, f"{rop}-eth0")) or []
        got2 = [r for r in r_reqs if r["src"] == aip and r["dst"] == rip and r["dport"] == ro["port"] and mark_in(r["authorization"]) == master["mark"]]
        v.check(f"... which {rop} received with the same mark", bool(got2), f"{len(got2)} requests")
        h3 = [r for r in r_reqs if r["src"] == rip and r["dport"] == sv["http_port"] and (srv_ip is None or r["dst"] == srv_ip)]
        m3 = mark_in(h3[0]["authorization"]) if h3 else None
        others = [r for r in h3 if mark_in(r["authorization"]) in (caller["mark"], master["mark"])]
        v.check(f"hop 3, {rop} to the server{' at ' + srv_ip if srv_ip else ''}: Authorization {backend['mark'] or '-'}, the backend key "
                f"({backend['fingerprint']}), neither the caller's nor the master key", bool(h3) and m3 == backend["mark"] and not others,
                f"{len(h3)} requests" + (f", Authorization {h3[0]['authorization'][:40]}" if h3 else ""))
        if h3:
            out.append({"hop": "3: router to server", "point": pid(plan, 3, f"{rop}-eth0"), "request": h3[0], "mark": m3, "key": "the backend key"})
    every = [r for rr in reqs.values() for r in rr if r["authorization"] is not None]
    plain = [r for r in every if not mark_in(r["authorization"])]
    v.check(f"every Authorization value in the keyed captures is a mark, none a value ({len(every)} requests with one, "
            f"{sum(1 for _ in reqs)} keyed points)", not plain, ", ".join(f"{r['dst']}:{r['dport']} line {r['line']}" for r in plain[:3]))
    return out


def judge_refuse(v, rs: Path, plan: dict, rows: list, decs: dict, pi: dict) -> dict:
    rf, gw, ag = plan["refuse"], plan["gateway"], plan["api_gateway"]
    v.sec(f"the refusal: {rf['hostname']} sent to {rf.get('gateway') or gw['name']}, which does not carry it")
    res = read(rs / "request" / "refuse-result.txt").split()
    status = int(res[0]) if res and res[0].isdigit() else 0
    h = headers(read(rs / "request" / "refuse-headers.txt"))
    srv = h.get("server", "")
    v.check(f"GET {rf['url']} from {plan['client']['node']}: HTTP {rf['expect']} from the Gateway (server {srv or 'none'})",
            status == rf["expect"] and "envoy" in srv.lower(), f"HTTP {status or 'none'}, server {srv or 'none'}")
    holder = lease_holder(rs)
    rvip = rf.get("vip") or gw["vip"]
    syn = []
    if (plan["client"] or {}).get("local"):
        ports = [r[0] for r in rows if r[0].startswith("0-")]
        out_ = [f for r in ports for f in decs.get(r) or [] if f["dst"] == rvip and f["sport"] == rf["sport"] and "S" in f["flags"]]
        v.check(f"{plan['client']['node']} answered it itself: no SYN from port {rf['sport']} to {rvip} left the node", not out_,
                f"{len(out_)} SYN(s) on the node's ports")
    else:
        fr = decs.get(pid(plan, 1, f"{holder}-bond0")) or [] if holder else []
        syn = [f for f in fr if f["src"] == plan["client"]["address"] and f["sport"] == rf["sport"] and f["dst"] == gw["vip"] and "S" in f["flags"]
               and "." not in f["flags"]]
        v.check(f"{holder or 'the lease holder'}: the client's SYN from port {rf['sport']} to {gw['vip']}:{gw['port']}", bool(syn), f"{len(syn)} SYNs")
    reqs = {r[0]: http_requests(read(rs / "captures" / f"{r[0]}-payload.txt")) for r in rows if r[0].startswith(pid(plan, 2, "")) and len(r) > 8 and r[8]}
    seen = [(pid, r) for pid, rr in reqs.items() for r in rr if (r["host"] or "").split(":")[0] == rf["hostname"] or "sfab-trace-refused" in r["path"]]
    inbound = [(pid, r) for pid, rr in reqs.items() for r in rr if r["dport"] == ag["port"]]
    v.check(f"no API gateway pod saw it: no request for {rf['hostname']} at {len(reqs)} API gateway pods, which received "
            f"{len(inbound)} request(s) in all, the keyed one", not seen and len(inbound) == 1,
            f"{len(seen)} for the name, {len(inbound)} in all")
    return {"status": status, "server": srv, "syn": (syn or [None])[0], "holder": holder}


def judge_also(v, rs: Path, plan: dict, rows: list) -> list:
    """Part III (chapter 8): the same key on the same path sent to another Gateway, whose route set
    does not carry the model: that Gateway's 404, and no request with its marker at any API gateway
    pod (the keyed captures hold every request they received)."""
    out = []
    reqs = {r[0]: http_requests(read(rs / "captures" / f"{r[0]}-payload.txt")) for r in rows if r[0].startswith(pid(plan, 2, "")) and len(r) > 8 and r[8]}
    for a in plan.get("also") or []:
        v.sec(f"the same key and path through {a['gateway']}, whose route set does not carry {plan['model']}")
        tag = f"also-{a['gateway']}"
        res = read(rs / "request" / f"{tag}-result.txt").split()
        status = int(res[0]) if res and res[0].isdigit() else 0
        h = headers(read(rs / "request" / f"{tag}-headers.txt"))
        srv = h.get("server", "")
        v.check(f"POST {a['url']} from {plan['client']['node']} through {a['gateway']} ({a['vip']}) with {plan['model']}'s key: HTTP "
                f"{a['expect']} from the Gateway (server {srv or 'none'})", status == a["expect"] and "envoy" in srv.lower(),
                f"HTTP {status or 'none'}, server {srv or 'none'}")
        seen = [(p_, r) for p_, rr in reqs.items() for r in rr if a["marker"] in r["path"]]
        v.check(f"no API gateway pod saw it: no request carrying {a['marker']} at {len(reqs)} API gateway pods (so no API gateway "
                "line names it)", bool(reqs) and not seen, f"{len(seen)} request(s)" if reqs else "no keyed capture read")
        out.append({"gateway": a["gateway"], "status": status, "server": srv})
    return out


def write_md(rs: Path, inv: dict, plan: dict, rows: list, decs: dict, hops: list, copy, status: int, h: dict, counts: dict, stamp,
             keyhops: list | None = None, refused: dict | None = None, also: list | None = None) -> None:
    try:
        run = load(rs / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    uncommitted = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    verdict = read(rs / "verdict.txt")
    gw = plan["gateway"]
    L = ["# Serving trace", "",
         f"- Lab: `{inv.get('lab')}`; labs repo commit `{commit}`{uncommitted}; UTC {run.get('utc_start') or 'unknown'}",
         f"- One chat completion from {plan['client']['node']} ({plan['client']['address']}, source port {plan['sport']}) to "
         f"`{plan['url']}` through {gw['name']} ({gw['vip']}), with {plan['model']}'s key; {len(rows)} capture points",
         f"- Answer: HTTP {status or 'none'}; the router's deployment `{h.get('x-litellm-model-name', '-')}` on "
         f"`{h.get('x-litellm-model-api-base', '-')}`, retries {h.get('x-litellm-attempted-retries', '-')}"]
    if stamp:
        L.append(f"- {stamp}")
    L += ["", "## The path", "", "| Hop | Point | Node | Address | First data (decode line) |", "|---|---|---|---|---|"]
    for x in hops:
        f = x.get("first")
        cell = f"`captures/{x['point']}.txt:{f['line']}`" if f else "-"
        L.append(f"| {x['hop']} | `{x['point']}` | {x['node']} | {x['address']} | {cell} |")
    if copy:
        L += ["", f"The copy that served it: {plan['model']}-{copy['copy']}, rail {copy['rail']} ({copy['nad']}) on {copy['switch']}: server "
              f"{copy['server']['pod']} on {copy['server']['node']} at {copy['server']['address']}, workers "
              + ", ".join(f"{w['pod']} on {w['node']} at {w['address']}" for w in copy["workers"]) + "."]
    if keyhops:
        L += ["", "## The keys at the in-cluster hops", "",
              "Each value in the captures is its keyed mark (`captures/scrub.log` counts the values replaced); the key files under "
              "`request/` name each key by its field, fingerprint and mark.", "",
              "| Hop | Point | Request | Authorization | Key | Decode line |", "|---|---|---|---|---|---|"]
        for x in keyhops:
            r = x["request"]
            L.append(f"| {x['hop']} | `{x['point']}` | {r['method']} `{r['path']}` | `{x['mark']}` | {x['key']} | "
                     f"`captures/{x['point']}-payload.txt:{r.get('auth_line') or r['line']}` |")
    for x, a in zip(also or [], plan.get("also") or []):
        L += ["", f"## The same key through {a['gateway']}", "",
              f"`{a['url']}` from {plan['client']['node']} (source port {a['sport']}) to {a['gateway']} ({a['vip']}), with "
              f"{plan['model']}'s key: HTTP {x['status'] or 'none'}, server {x['server'] or 'none'}; no API gateway pod saw it."]
    if refused:
        rf = plan["refuse"]
        L += ["", "## The refusal", "",
              f"`{rf['url']}` from {plan['client']['node']} (source port {rf['sport']}) to {rf.get('gateway') or plan['gateway']['name']}: "
              f"HTTP {refused['status'] or 'none'}, server {refused['server'] or 'none'}; no API gateway pod saw it."]
    L += ["", "## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", ""]
    L += ["## Frames per point", "", "| Point | Kind | Node | Interface | Filter | Frames | Data segments |", "|---|---|---|---|---|---|---|"]
    for r in rows:
        fr = decs.get(r[0]) or []
        L.append(f"| `{r[0]}` | {r[1]} | {r[2]} | {r[5]} | `{r[6]}` | {len(fr)} | {sum(1 for f in fr if f['length'] > 0)} |")
    L += ["", "## Files", "",
          "- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`",
          "- `cluster/`: the pods of both namespaces, the users' VIP's lease and the serving EndpointSlices, read before the captures",
          "- `request/`: the warm-up's and the request's status (`result.txt`), response headers and body; no request header is saved",
          "- `captures/<point>.pcap` and `.txt`, decoded with `tcpdump -nn -tt -e -v -r` (a guest's and a pod's in the guest); a pod's "
          "cluster interface captured at 66 bytes a frame, so no capture holds an HTTP header"
          + ("; the API gateway's and the router's captured whole, each pcap scrubbed of its keys on its way out of the guest and "
             "decoded on the lab host, with `-A` as `<point>-payload.txt`" if (plan.get("keys") or {}).get("capture") else ""),
          "", vocab.result_line(counts), ""]
    (rs / "TRACE.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="servetrace")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("points")
    s.add_argument("--plan", required=True)
    s.add_argument("--set", required=True)
    s = sub.add_parser("judge")
    s.add_argument("--set", required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--inv", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"get": cmd_get, "points": cmd_points, "judge": judge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
