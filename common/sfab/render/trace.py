"""gen/trace.json: a chapter's firewall trace (chapter 4's form of chapter.yaml's trace block),
resolved against the lab's model (FRAMEWORK.md section 4.5).

Chapter 3's trace (flows and points) is read by common/trace/ straight from the inventory, as the
chapter wrote it. Chapter 4's trace reads the firewall's state rather than following one frame, and
names things only the model can resolve (the Gateway behind a DNAT, the image a node pulls, the
rule a session must name), so its block is rendered here, and `sfab check` reports a changed trace
as drift. A lab whose trace block holds neither sessions: nor pull: renders no gen/trace.json.

    trace:
      sessions:                       one HTTPS request per side of the firewall, its connection held
        - id: enterprise              open hold_s after the reply so the session table still lists it
          client: ent-client          a client container (its python3 makes the request)
          gateway: gw-users           the Gateway whose route answers
          via: public                 optional: the request goes to the firewall's public address
          hostname: llm               a name under the org domain (the TLS name and the Host header)
          path: /echo?msg=...
          sport: 42443                the client's source port, pinned
          hold_s: 20
          expect: {status, rule, nat_rule, from_zone, to_zone}
      pull:                           a node's image pull through the source NAT
        node: k8s-gpu2                    a VM guest with a Kubernetes role (crictl pulls through its CRI)
        image: node_helm              a spec/versions.yaml kubernetes key whose image the node lacks
        points: [{id, node, eth, vlan, group}]    container ports captured on the lab host
        expect: {rule, nat_rule, from_zone, to_zone}

What is resolved: each session's client address, the address it connects to (the Gateway's VIP,
or the public address with the DNAT rule's translated address beside it), whether the client's
own resolver is in the lab (if not, the request pins the name to the address, as the audit's
population probes do), the pull's node address, image reference (pulled by digest, as the init node
pulls it), the registry's address and port, and the translated source (the source NAT rule's
interface address). Every name and address is checked against the model.

Chapter 5's trace follows pings on the rails rather than a session, and its block is rendered here
too (a third form, under rails:):

    trace:
      rails:
        from: k8s-gpu1                    two VM guests with the in-node relay; the flows start in from's
        to: k8s-gpu2                      GPU namespaces and end at to's rail addresses
        flows:                        each a ping of count requests under one ICMP id
          - {id: same-rail, rail: 1}                  rail 1 to to's address on rail 1
          - {id: cross-rail, rail: 1, to_rail: 2}     rail 1's namespace to to's address on rail 2
        count: 3
        interval_s: 0.5
        df_sizes: [9000, 9001]        IP sizes for the DF probe matrix, each flow both ways
        points:                       {id, node, eth}: a rail switch's container port, captured on
          - {id: 1-k8s-gpu1-relay0, node: k8s-gpu1, iface: relay0}      the lab host; {id, node, iface}: a
          - {id: 2-rail-sw1-Ethernet0, node: rail-sw1, eth: eth1}   guest's relay bridge, captured
                                                                    and decoded in the guest

What is resolved: every rail both nodes hold, with each node's address, namespace and container
port on it and the switch ports it lands on (the health check reads them); each flow's source
namespace and addresses, the rail its request rides (the destination's) and the rail its reply rides
(the source's: the far node answers through its own relay), the switch each crosses, the TTL the
reply arrives with (64 on one rail, 63 across: one forward in a relay namespace each way), the hops
traceroute must print (across rails, the source node's own address on the destination rail, as the
relay namespace that forwards the request answers from the pinned source of its route back, then
the destination), and at every point which of the flow's requests and replies must appear and with
which TTL. The DF matrix's rows: each flow forward and reversed (the far node's namespace on the
flow's request rail pinging back), each size with its payload, every ping under its own ICMP id.

Chapter 6's trace follows one request to a model, from a client through a Gateway, the API
gateway and the router to a copy's server and its workers over their rail (a fourth form, under
serving:):

    trace:
      serving:
        client: ent-client            a client container (curl, the lab root CA in its bundle)
        gateway: gw-users             the Gateway whose model route the request takes
        model: chat                   a model that Gateway's audience may call
        max_tokens: 16
        sport: 42606                  the client's source port, pinned (the Gateway's capture finds it)
        copy: c                       optional: the copy the request must land on. The router picks
        tries: 12                     the copy, so the trace sends the request again, its source port
                                      one higher each time and the captures of a miss discarded,
                                      until that copy's server took it, at most tries times

What is resolved: the client's address and whether its resolver is in the lab (if not, the name is
pinned to the Gateway's VIP); the Gateway's VIP and the lease that names the node announcing it; the
model's URL (its route under the inference path) and the answer the router must name (its
deployment, on the model's Service); the API gateway's and the router's Deployments, selectors and
ports, and the key Secret the request's key comes from; and every copy of the model from the
placement table: its rail and attachment, its server and workers with their nodes and rail
addresses, which worker sits on another node than its server (only that worker's RPC crosses the
rail switch), and the rail switch's ports facing those nodes. The pods themselves are found when the
trace runs (common/trace/lib-servetrace.sh), and so is the node holding the Gateway's lease.

Chapter 7 adds two settings to the serving form:

        keys: true                    the API gateway's and the router's cluster interfaces captured
                                      whole, every Authorization value replaced by its keyed mark
                                      (common/trace/keyscrub.py) before the pcap or its decode is
                                      written, so the judge can name the key each hop carried
        refuse: {hostname: admin, path: /echo, sport: 42707}
                                      after the request, one more from the same client to a hostname
                                      the Gateway does not carry: the Gateway's 404, and no API
                                      gateway pod sees it (it needs keys: true, whose whole captures
                                      show every request the API gateway received)

The plan then also names the router's master key and the backend key (their Secrets and fields:
the marks the second and third hops must carry) and the router's per-model path.

Chapter 1 walks one request from the client to the model, every device on the way with the table it
consults, and sends three requests that must be refused (a fifth form, under walk:):

    trace:
      walk:
        client: ent-client            a client container wired to the firewall
        gateway: gw-users             the Gateway its population's resolver answers with
        model: chat
        max_tokens: 16
        sport: 42106                  the walked request's source port
        hold_s: 30                    its connection held this long after the answer (the session table)
        refuse:
          hostname: {hostname: admin, path: /echo, sport: 42107}   a hostname the Gateway does not carry: 404
          key: {model: staff, sport: 42108}                        another model's key on this model's route: 401
          port: {to: k8s-gpu1, port: 22, sport: 42109, timeout_s: 5}   a port no rule allows: the last rule's deny

The plan is chapter 7's keyed serving plan for the in-cluster hops, its capture points numbered after
the frontend's five depths (depth_base), plus: the frontend's points (the client's port, the
firewall's interface facing it, both legs of the bundle the Gateway's VLAN rides, and the pair ports
those legs land on; the pair's ports facing the lease holder are found when the trace runs), the
filter they share, and the VLAN tag the legs carry; chapter 4's session form for the walked request
(lib-fwtrace.sh holds it open while the firewall's session table is read), with the POST, its body
and the key's header file in the client; the firewall's tables as the render resolves them (the
ingress zone, the connected route and egress interface toward the VIP, the first security rule that
matches the request, and no NAT rule: a walk the render would translate is refused); the resolver's
view that answers the client and, for contrast, the view that answers the resolver itself; the rail
switches whose counters the trace reads; each copy's VLAN and pods' rail MACs; and the three refusals,
each with the device and layer that must refuse it (the port's first matching rule must be a deny,
and its destination must sit behind the same bundle, so the legs' captures can show nothing passed).
"""

from __future__ import annotations

import json
import re

from .. import addr
from ..model import Host, Model
from . import RenderError

SCHEMA = 1
CA_ROOT = "/shared/ca/root.crt"


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _err(where: str, msg: str):
    raise RenderError(f"{where}: {msg}")


def _num(v, where: str):
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
        _err(where, f"must be a number above 0, got {v!r}")
    return v


def _bare(a):
    return None if a is None else str(a).split("/")[0]


def _host(model: Model, name, where: str) -> Host:
    n = model.nodes.get(str(name or ""))
    if not isinstance(n, Host):
        _err(where, f"{name!r} is not a host of {model.lab}")
    return n


def _expect(raw, where: str, keys=("status", "rule", "nat_rule", "from_zone", "to_zone")) -> dict:
    raw = raw or {}
    extra = set(raw) - set(keys)
    if extra:
        _err(where, f"unknown keys {sorted(extra)} (have {', '.join(keys)})")
    return {k: raw.get(k) for k in keys}


def _rule_names(model: Model):
    from .panos import view  # noqa: PLC0415

    v = view(model)
    if v is None:
        return None, set(), {}
    return v, {r.name for r in v.rules}, {n.name: n for n in v.nat}


def session(model: Model, s: dict, seen: set) -> dict:
    sid = str(s.get("id") or "")
    where = f"chapter.yaml trace.sessions[{sid or '?'}]"
    if not re.match(r"^[a-z][a-z0-9-]*$", sid) or sid in seen:
        _err(where, "id must be a new name of lower case letters, digits and hyphens")
    seen.add(sid)
    extra = set(s) - {"id", "client", "gateway", "via", "hostname", "path", "sport", "hold_s", "expect"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    c = _host(model, s.get("client"), f"{where}.client")
    if c.kind != "client":
        _err(f"{where}.client", f"{c.name} must be a client container (the request runs its python3)")
    g = model.gateways.get(str(s.get("gateway") or ""))
    if g is None:
        _err(f"{where}.gateway", f"{s.get('gateway')!r} is not a Gateway of {model.lab}")
    fw = model.firewall
    if fw is None:
        _err(where, "the lab has no firewall whose session table to read")
    v, rules, nats = _rule_names(model)
    ex = _expect(s.get("expect"), f"{where}.expect")
    via = s.get("via")
    translated = None
    if via is None:
        dst = g.vip
    elif via == "public":
        if not fw.public:
            _err(f"{where}.via", "the firewall has no public address")
        dst = fw.public
        nr = nats.get(str(ex.get("nat_rule") or ""))
        if nr is None or not nr.dnat:
            _err(f"{where}.expect.nat_rule", "a request to the public address names the destination NAT rule that translates it")
        if nr.dnat != g.vip:
            _err(f"{where}.expect.nat_rule", f"{nr.name} translates to {nr.dnat}, not {g.name}'s VIP {g.vip}")
        translated = nr.dnat
    else:
        _err(f"{where}.via", "must be public, or left out (the Gateway's VIP)")
    if ex.get("rule") and ex["rule"] not in rules:
        _err(f"{where}.expect.rule", f"{ex['rule']!r} is not a security rule this lab's firewall carries")
    if ex.get("nat_rule") and ex["nat_rule"] not in nats:
        _err(f"{where}.expect.nat_rule", f"{ex['nat_rule']!r} is not a NAT rule this lab's firewall carries")
    zones = {z.name for z in v.zones}
    for k in ("from_zone", "to_zone"):
        if ex.get(k) and ex[k] not in zones:
            _err(f"{where}.expect.{k}", f"{ex[k]!r} is not a zone of this lab's firewall")
    host = str(s.get("hostname") or "")
    if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", host):
        _err(f"{where}.hostname", "a single DNS label under the org domain")
    path = str(s.get("path") or "/")
    if not path.startswith("/") or " " in path:
        _err(f"{where}.path", "must start with / and hold no space")
    m = re.search(r"[?&]msg=([^&]+)", path)
    sport = int(_num(s.get("sport"), f"{where}.sport"))
    if not 1024 < sport < 65536:
        _err(f"{where}.sport", "must be an unprivileged port")
    resolver_in = bool(c.resolver and c.resolver in model.nodes)
    return {
        "id": sid, "client": c.name, "client_addr": _bare(c.address), "gateway": g.name, "vip": g.vip,
        "dst_addr": dst, "port": 443, "translated_addr": translated, "fqdn": model.org.fqdn(host), "path": path,
        "msg": m.group(1) if m else None, "sport": sport, "hold_s": _num(s.get("hold_s", 20), f"{where}.hold_s"),
        "pin": not resolver_in, "resolver": c.resolver if resolver_in else None, "ca_root": CA_ROOT,
        "expect": dict(ex, status=int(ex.get("status") or 200)),
    }


def pull(model: Model, p: dict) -> dict:
    where = "chapter.yaml trace.pull"
    extra = set(p) - {"node", "image", "points", "expect"}
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    h = _host(model, p.get("node"), f"{where}.node")
    if h.kind != "vm-node" or not h.k8s:
        _err(f"{where}.node", f"{h.name} must be a VM guest with a Kubernetes role (crictl pulls through its CRI)")
    reg = model.registry
    if reg is None:
        _err(where, "the lab has no in-lab registry to pull from")
    key = str(p.get("image") or "")
    from . import k8s  # noqa: PLC0415

    if key == "node_helm":
        ref = k8s.helm_image(model)["ref"]
        holders = [model.k8s.init] if model.k8s and model.k8s.init else []
    else:
        _err(f"{where}.image", "node_helm is the image the trace pulls: only the init node holds it, so another node pulls it whole")
    if h.name in holders:
        _err(f"{where}.node", f"{h.name} already holds the image (the init node pulls it at bootstrap)")
    fw = model.firewall
    if fw is None:
        _err(where, "the lab has no firewall")
    v, rules, nats = _rule_names(model)
    ex = _expect(p.get("expect"), f"{where}.expect", keys=("rule", "nat_rule", "from_zone", "to_zone"))
    nr = nats.get(str(ex.get("nat_rule") or ""))
    if nr is None or not nr.snat_interface:
        _err(f"{where}.expect.nat_rule", "names the source NAT rule the pull crosses")
    sif = fw.interface(nr.snat_interface)
    if sif is None or not sif.address:
        _err(f"{where}.expect.nat_rule", f"{nr.name}'s interface {nr.snat_interface} has no address")
    if ex.get("rule") and ex["rule"] not in rules:
        _err(f"{where}.expect.rule", f"{ex['rule']!r} is not a security rule this lab's firewall carries")
    # the two ends of the wire the source NAT interface sits on: a capture there sees the rewritten source
    snat_eth = f"eth{nr.snat_interface.rsplit('/', 1)[-1]}" if re.match(r"^ethernet1/\d+$", nr.snat_interface) else None
    far = model.peer(fw.name, snat_eth) if snat_eth else None
    outside = {(fw.name, snat_eth)} | ({(far.node, far.eth)} if far else set())
    points = []
    seen = set()
    for i, pt in enumerate(p.get("points") or []):
        w = f"{where}.points[{i}]"
        pid = str(pt.get("id") or "")
        if not re.match(r"^[0-9]+-[A-Za-z0-9-]+$", pid) or pid in seen:
            _err(w, "id is <depth>-<name>, once")
        seen.add(pid)
        n = model.nodes.get(str(pt.get("node") or ""))
        if n is None or n.kind == "vm-node":
            _err(f"{w}.node", "a container port captured on the lab host (not a VM guest)")
        eth = str(pt.get("eth") or "")
        if not n.nic(eth):
            _err(f"{w}.eth", f"{n.name} has no wired {eth}")
        vlan = pt.get("vlan", "none")
        points.append({"id": pid, "node": n.name, "eth": eth, "vlan": None if vlan in (None, "none") else int(vlan),
                       "group": pt.get("group") or None, "depth": int(pid.split("-", 1)[0]),
                       "side": "outside" if (n.name, n.nic(eth).eth) in outside else "inside"})
    if not any(x["side"] == "outside" for x in points) or not any(x["side"] == "inside" for x in points):
        _err(f"{where}.points", f"captures the pull on both sides: inside, and on {nr.snat_interface} where its source is rewritten")
    return {
        "node": h.name, "node_addr": _bare(h.address), "image": ref, "image_key": key, "cri": k8s.CRI_SOCKET,
        "registry": reg.node, "registry_addr": _bare(reg.address), "registry_port": int(reg.port),
        "translated_src": _bare(sif.address), "points": points, "expect": ex,
    }


def plan(model: Model, raw: dict) -> dict:
    if not isinstance(raw, dict):
        _err("chapter.yaml trace", "must be a mapping")
    seen: set = set()
    out = {"schema": SCHEMA, "lab": model.lab, "fw": model.firewall.name if model.firewall else None,
           "public": model.firewall.public if model.firewall else None,
           "sessions": [session(model, s, seen) for s in raw.get("sessions") or []],
           "pull": pull(model, raw["pull"]) if raw.get("pull") else None}
    if not out["sessions"] and not out["pull"]:
        _err("chapter.yaml trace", "sessions: and pull: name nothing")
    return out


# --------------------------------------------------------------------------------------------
# chapter 5: the rails

RAIL_IDS = {"flow": 5101, "df": 5201}
RAIL_KEYS = {"from", "to", "flows", "count", "interval_s", "df_sizes", "points"}


def _relay_host(model: Model, name, where: str) -> Host:
    h = _host(model, name, where)
    if h.kind != "vm-node" or h.relay is None or not h.rails:
        _err(where, f"{h.name} must be a VM guest with rails and the in-node relay")
    return h


def _rail_of(h: Host, r: int):
    return next((x for x in h.rails if x.rail == r), None)


def _ns_of(h: Host, r: int):
    return next((x for x in h.relay.namespaces if x.rail == r), None)


def _switch_port(model: Model, sw: str, native: str):
    n = model.nodes.get(sw)
    return next((x for x in (n.nics if n else ()) if x.native == native), None)


def rails_plan(model: Model, raw: dict) -> dict:
    where = "chapter.yaml trace.rails"
    if not isinstance(raw, dict):
        _err(where, "must be a mapping")
    extra = set(raw) - RAIL_KEYS
    if extra:
        _err(where, f"unknown keys {sorted(extra)} (have {', '.join(sorted(RAIL_KEYS))})")
    src = _relay_host(model, raw.get("from"), f"{where}.from")
    dst = _relay_host(model, raw.get("to"), f"{where}.to")
    if src.name == dst.name:
        _err(f"{where}.to", "names another node than from")
    common = sorted({x.rail for x in src.rails} & {x.rail for x in dst.rails})
    if not common:
        _err(where, f"{src.name} and {dst.name} share no rail")
    rails = []
    for r in common:
        a, b = _rail_of(src, r), _rail_of(dst, r)
        rails.append({"r": r, "vlan": a.vlan, "switch": a.switch, "src_addr": _bare(a.address), "dst_addr": _bare(b.address),
                      "src_ns": _ns_of(src, r).ns, "dst_ns": _ns_of(dst, r).ns, "src_ifname": a.ifname, "dst_ifname": b.ifname,
                      "src_eth": a.eth, "dst_eth": b.eth, "src_switch_eth": a.switch_eth, "src_native": a.switch_native,
                      "dst_switch_eth": b.switch_eth, "dst_native": b.switch_native})
    by_r = {x["r"]: x for x in rails}
    count = int(_num(raw.get("count", 3), f"{where}.count"))
    interval = _num(raw.get("interval_s", 0.5), f"{where}.interval_s")
    flows, seen = [], set()
    for i, f in enumerate(raw.get("flows") or []):
        w = f"{where}.flows[{i}]"
        fid = str((f or {}).get("id") or "")
        if not re.match(r"^[a-z][a-z0-9-]*$", fid) or fid in seen:
            _err(w, "id must be a new name of lower case letters, digits and hyphens")
        seen.add(fid)
        if set(f) - {"id", "rail", "to_rail"}:
            _err(w, f"unknown keys {sorted(set(f) - {'id', 'rail', 'to_rail'})}")
        r = int(_num(f.get("rail"), f"{w}.rail"))
        t = int(_num(f.get("to_rail", r), f"{w}.to_rail"))
        for k, v in (("rail", r), ("to_rail", t)):
            if v not in by_r:
                _err(f"{w}.{k}", f"rail {v} is not a rail both {src.name} and {dst.name} hold (have {common})")
        cross = t != r
        req, rep = by_r[t], by_r[r]
        ns = _ns_of(src, r)
        route = next((x for x in ns.routes if x.dest == model.rails[t].prefix), None) if cross else None
        if cross and route is None:
            _err(w, f"{src.name}'s namespace {ns.ns} holds no relay route to rail {t}")
        hop1 = _bare(_rail_of(src, t).address) if cross else req["dst_addr"]
        flows.append({"id": fid, "kind": "cross" if cross else "same", "rail": r, "to_rail": t, "icmp_id": RAIL_IDS["flow"] + i,
                      "src_node": src.name, "src_ns": ns.ns, "src_addr": rep["src_addr"], "dst_node": dst.name, "dst_addr": req["dst_addr"],
                      "via": route.via if route else None, "via_src": route.src if route else None,
                      "request_rail": t, "request_switch": req["switch"], "reply_rail": r, "reply_switch": rep["switch"],
                      "expect": {"ttl": 63 if cross else 64, "hops": [hop1, req["dst_addr"]] if cross else [req["dst_addr"]]}})
    if not flows:
        _err(f"{where}.flows", "names no flow")
    sizes = [int(_num(x, f"{where}.df_sizes")) for x in raw.get("df_sizes") or []]
    if sizes != sorted(set(sizes)) or any(x < 29 or x > 9216 for x in sizes):
        _err(f"{where}.df_sizes", "IP sizes, ascending, each from 29 to 9216")
    df, k = [], 0
    for f in flows:
        back_ns = _ns_of(dst, f["request_rail"]).ns
        for direction, node, nsn, a, b in (("forward", src.name, f["src_ns"], f["src_addr"], f["dst_addr"]),
                                           ("reverse", dst.name, back_ns, f["dst_addr"], f["src_addr"])):
            for size in sizes:
                df.append({"id": f"{f['id']}-{direction}-{size}", "flow": f["id"], "direction": direction, "node": node, "ns": nsn,
                           "src_addr": a, "dst_addr": b, "size": size, "payload": size - 28, "icmp_id": RAIL_IDS["df"] + k})
                k += 1
    points, pseen = [], set()
    for i, pt in enumerate(raw.get("points") or []):
        w = f"{where}.points[{i}]"
        pid = str((pt or {}).get("id") or "")
        if not re.match(r"^[0-9]+-[A-Za-z0-9-]+$", pid) or pid in pseen:
            _err(w, "id is <depth>-<name>, once")
        pseen.add(pid)
        if set(pt) - {"id", "node", "eth", "iface"} or (("eth" in pt) == ("iface" in pt)):
            _err(w, "a point is {id, node, eth} (a switch port) or {id, node, iface} (a guest's relay bridge)")
        n = model.nodes.get(str(pt.get("node") or ""))
        if n is None:
            _err(f"{w}.node", f"{pt.get('node')!r} is not a node of {model.lab}")
        out = {"id": pid, "node": n.name, "depth": int(pid.split("-", 1)[0])}
        if "iface" in pt:
            if n.name not in (src.name, dst.name) or str(pt["iface"]) != n.relay.bridge:
                _err(w, f"a guest point is the relay bridge ({src.relay.bridge}) of {src.name} or {dst.name}")
            out.update(where="guest", iface=n.relay.bridge, eth=None, native=None, faces=None, rail=None)
        else:
            nic = n.nic(str(pt["eth"]))
            if n.role != "rail_vlan" or nic is None or nic.rail is None or nic.peer.node not in (src.name, dst.name):
                _err(w, f"a switch point is a rail switch's port facing {src.name} or {dst.name}")
            out.update(where="switch", iface=None, eth=nic.eth, native=nic.native, faces=nic.peer.node, rail=nic.rail)
        exp = {}
        for f in flows:
            e = {"request": None, "reply": None}
            if out["where"] == "guest":
                if f["kind"] == "cross" and n.name == src.name:
                    e["request"] = 64
                if f["kind"] == "cross" and n.name == dst.name:
                    e["reply"] = 64
            else:
                if out["rail"] == f["request_rail"]:
                    e["request"] = f["expect"]["ttl"]
                if out["rail"] == f["reply_rail"]:
                    e["reply"] = f["expect"]["ttl"]
            exp[f["id"]] = e
        out["expect"] = exp
        points.append(out)
    if not points:
        _err(f"{where}.points", "names no capture point")
    for f in flows:
        if not any(p["expect"][f["id"]]["request"] for p in points) or not any(p["expect"][f["id"]]["reply"] for p in points):
            _err(f"{where}.points", f"no point sees both the request and the reply of {f['id']}")
    return {
        "schema": SCHEMA, "lab": model.lab, "kind": "rails",
        "src": {"node": src.name, "bridge": src.relay.bridge, "relay_prefix": src.relay.prefix, "mtu": src.relay.mtu},
        "dst": {"node": dst.name, "bridge": dst.relay.bridge, "relay_prefix": dst.relay.prefix, "mtu": dst.relay.mtu},
        "rails": rails, "flows": flows, "count": count, "interval_s": interval, "df": df, "points": points, "filter": "icmp",
    }


# --------------------------------------------------------------------------------------------
# chapter 6: one request to a model

SERVE_KEYS = {"client", "gateway", "model", "max_tokens", "sport", "keys", "refuse", "copy", "tries", "pin", "also"}
REFUSE_KEYS = {"hostname", "path", "sport", "gateway"}
ALSO_KEYS = {"gateway", "sport"}
# Capture lengths: on the pods' cluster interfaces only the headers (Ethernet, IP and a TCP header
# with its timestamps, 66 bytes), so no capture holds an HTTP header and with it a key; on the rails
# a little of the RPC payload, which holds no key. With keys: true (chapter 7) the API gateway's and
# the router's cluster interfaces are captured whole ("keyed"), and every Authorization value in the
# pcap and its decode is replaced by its keyed mark before either leaves the guest's pipe.
SNAPLEN = {"http": 66, "rail": 128, "vip": 96, "keyed": 2048}


def serving_plan(model: Model, raw: dict, base: int = 0, where: str = "chapter.yaml trace.serving") -> dict:
    """The serving form. base numbers its capture points after base depths of another form's (the
    walk, chapter 1, puts the frontend's five depths first): a plan with a base names it as
    depth_base, and one without is the plan chapters 6 and 7 recorded with."""
    if not isinstance(raw, dict):
        _err(where, "must be a mapping")
    extra = set(raw) - SERVE_KEYS
    if extra:
        _err(where, f"unknown keys {sorted(extra)} (have {', '.join(sorted(SERVE_KEYS))})")
    from . import inference, k8s  # noqa: PLC0415

    if not inference.enabled(model):
        _err(where, "the lab serves no model through the API gateway (serving off, or no inference block)")
    sv, inf = k8s.serving_summary(model), inference.settings(model)
    c = _host(model, raw.get("client"), f"{where}.client")
    pinned = raw.get("pin", False)
    if not isinstance(pinned, bool):
        _err(f"{where}.pin", "true (the request names the Gateway's VIP with curl --resolve) or false")
    # Part III (chapter 8): a node of the cluster as the client, its request pinned to a Gateway's VIP,
    # which the node's own datapath answers (render/decisions.py path: nothing to the VIP leaves it)
    local = bool(pinned and c.kind == "vm-node" and getattr(c, "k8s", None))
    if c.kind != "client" and not local:
        _err(f"{where}.client", f"{c.name} must be a client container (the request is curl's), or a node of the cluster with pin: true")
    g = model.gateways.get(str(raw.get("gateway") or ""))
    if g is None:
        _err(f"{where}.gateway", f"{raw.get('gateway')!r} is not a Gateway of {model.lab}")
    pop = next((x for x in model.populations.values() if c.name in x.clients), None)
    if not pinned and (pop is None or pop.answer_address != g.vip):
        _err(f"{where}.client", f"{c.name}'s population is not answered with {g.name}'s VIP {g.vip}")
    mname = str(raw.get("model") or "")
    mi = next((m for m in inf["models"] if m["name"] == mname), None)
    if mi is None:
        _err(f"{where}.model", f"{mname!r} is not a model the lab serves ({', '.join(m['name'] for m in inf['models'])})")
    rt = next((r for r in inf["routes"] if r["gateway"] == g.name), None)
    if rt is None or not any(x["model"] in (None, mname) for x in rt["rules"]):
        _err(f"{where}.model", f"{g.name}'s model route does not carry {mname}")
    sport = int(_num(raw.get("sport"), f"{where}.sport"))
    if not 1024 < sport < 65536:
        _err(f"{where}.sport", "must be an unprivileged port")
    host = rt["hostnames"][0]
    resolver_in = bool(c.resolver and c.resolver in model.nodes) and not pinned
    keyed = raw.get("keys", False)
    if not isinstance(keyed, bool):
        _err(f"{where}.keys", "true (the API gateway's and the router's cluster interfaces captured whole, the keys marked) or false")
    refuse = None
    if raw.get("refuse") is not None:
        rf = raw["refuse"]
        if not isinstance(rf, dict) or set(rf) - REFUSE_KEYS:
            _err(f"{where}.refuse", f"a mapping of {', '.join(sorted(REFUSE_KEYS))}")
        if not keyed:
            _err(f"{where}.refuse", "needs keys: true (the API gateway's whole captures show it never saw the request)")
        label = str(rf.get("hostname") or "")
        if not re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", label):
            _err(f"{where}.refuse.hostname", "a single DNS label under the org domain")
        rhost = model.org.fqdn(label)
        rg = g
        if rf.get("gateway") is not None:
            rg = model.gateways.get(str(rf["gateway"]))
            if rg is None or not pinned:
                _err(f"{where}.refuse.gateway", "another Gateway of the lab, with pin: true (the refusal is pinned to its VIP)")
        if rhost in rg.hostnames and rf.get("gateway") is None:
            _err(f"{where}.refuse.hostname", f"{g.name} carries {rhost}: it would answer it")
        if rf.get("gateway") is not None and any(rhost in r["hostnames"] for r in inf["routes"] if r["gateway"] == rg.name):
            _err(f"{where}.refuse.hostname", f"{rg.name}'s model route carries {rhost}: it would answer it")
        rpath = str(rf.get("path") or "/")
        if not rpath.startswith("/") or any(ch in rpath for ch in " '\"?#"):
            _err(f"{where}.refuse.path", "a path starting with /, with no space, quote or query")
        rsport = int(_num(rf.get("sport"), f"{where}.refuse.sport"))
        if not 1024 < rsport < 65536 or rsport == sport:
            _err(f"{where}.refuse.sport", "an unprivileged port other than the request's")
        # pinned to the Gateway when the client's resolver is not in the lab, or when the view that
        # answers it publishes no record for the name (the enterprise view holds no admin name: the
        # request still reaches the users' Gateway, which answers it 404)
        pin_refuse = not resolver_in or not _published(model, c.resolver, rhost)
        refuse = {"hostname": rhost, "path": rpath, "url": f"https://{rhost}{rpath}?msg=sfab-trace-refused", "sport": rsport,
                  "resolve": f"{rhost}:443:{rg.vip}" if pin_refuse else None, "expect": 404}
        if rf.get("gateway") is not None:
            refuse.update(gateway=rg.name, vip=rg.vip)
    pin = None
    if raw.get("copy") is not None:
        names = [x.name for x in model.models[mname].copies]
        if str(raw["copy"]) not in names:
            _err(f"{where}.copy", f"{raw['copy']!r} is not a copy of {mname} ({', '.join(names)})")
        tries = int(_num(raw.get("tries", 12), f"{where}.tries"))
        if not 1 <= tries <= 50 or sport + tries > 65535:
            _err(f"{where}.tries", "1 to 50, the source ports sport to sport + tries - 1 unprivileged")
        if refuse and sport <= refuse["sport"] < sport + tries:
            _err(f"{where}.refuse.sport", f"inside the request's source ports {sport} to {sport + tries - 1}")
        srv_row = next(r for r in sv["placement"] if r["model"] == mname and r["copy"] == str(raw["copy"]) and r["role"] == "server")
        pin = {"copy": str(raw["copy"]), "tries": tries, "server": srv_row["pod"], "container": "server"}
    elif raw.get("tries") is not None:
        _err(f"{where}.tries", "needs copy: the copy the request must land on")
    copies = []
    for cp in [x for x in model.models[mname].copies]:
        rows = [r for r in sv["placement"] if r["model"] == mname and r["copy"] == cp.name]
        srv = next(r for r in rows if r["role"] == "server")
        wks = [r for r in rows if r["role"] == "worker"]

        def rail_of(node: str, r: int):
            h = model.nodes[node]
            ri = next((x for x in h.rails if x.rail == r), None)
            if ri is None:
                _err(where, f"{node} holds no rail {r}")
            return ri

        sri = rail_of(srv["node"], srv["rail"])
        nodes = [srv["node"]] + [w["node"] for w in wks if w["node"] != srv["node"]]
        ports = []
        for n in dict.fromkeys(nodes):
            ri = rail_of(n, srv["rail"])
            ports.append({"id": f"{6 + base}-{ri.switch}-{ri.switch_native}", "node": ri.switch, "eth": ri.switch_eth,
                          "native": ri.switch_native, "faces": n})
        copies.append({
            "copy": cp.name, "rail": srv["rail"], "nad": srv["nad"], "switch": sri.switch, "service": f"{mname}-{cp.name}",
            "spans": bool(cp.spans),
            "server": {"pod": srv["pod"], "node": srv["node"], "address": _bare(srv["address"])},
            "workers": [{"pod": w["pod"], "node": w["node"], "address": _bare(w["address"]), "remote": w["node"] != srv["node"]}
                        for w in wks],
            "switch_ports": ports,
        })
    also = []
    for i, x in enumerate(raw.get("also") or []):
        w = f"{where}.also[{i}]"
        if not isinstance(x, dict) or set(x) - ALSO_KEYS or not pinned:
            _err(w, "a mapping of gateway and sport, with pin: true (the request is pinned to that Gateway's VIP)")
        og = model.gateways.get(str(x.get("gateway") or ""))
        if og is None or og.name == g.name:
            _err(f"{w}.gateway", "another Gateway of the lab")
        ort = next((r for r in inf["routes"] if r["gateway"] == og.name), None)
        if ort is not None and any(r["model"] in (None, mname) for r in ort["rules"]):
            _err(f"{w}.gateway", f"{og.name}'s route carries {mname}: it would answer the request")
        osport = int(_num(x.get("sport"), f"{w}.sport"))
        if not 1024 < osport < 65536 or osport in (sport, (refuse or {}).get("sport")) or osport in [a["sport"] for a in also]:
            _err(f"{w}.sport", "an unprivileged port of its own")
        marker = f"sfab-trace-also-{og.name}"
        also.append({"gateway": og.name, "vip": og.vip, "sport": osport, "marker": marker, "expect": 404,
                     "url": f"https://{host}{mi['path']}/v1/chat/completions?msg={marker}", "resolve": f"{host}:443:{og.vip}"})
    if (also or (refuse or {}).get("gateway")) and not keyed:
        _err(where, "also: and refuse.gateway need keys: true (the API gateway's whole captures show it never saw them)")
    client = {"node": c.name, "address": _bare(c.address), "pin": not resolver_in, "resolver": c.resolver if resolver_in else None,
              "resolve": f"{host}:443:{g.vip}" if not resolver_in else None, "ca_root": CA_ROOT}
    if local:
        # the node answers every VIP of its own Gateways itself: its own ports are captured to show
        # no SYN to the VIP leaves it (the lease holder sees none)
        client.update(kind=c.kind, local=True,
                      ports=[{"id": f"0-{c.name}-{n.eth}", "node": c.name, "eth": n.eth} for n in c.nics if n.role == "bond-member"])
    out = {
        "schema": SCHEMA, "lab": model.lab, "kind": "serving",
        "client": client,
        "gateway": {"name": g.name, "vip": g.vip, "port": 443, "service": k8s.gateway_service(g),
                    "lease": f"{k8s.SYSTEM_NS}/{k8s.l2_lease(model, g)}", "route": rt["name"]},
        "hostname": host, "path": f"{mi['path']}/v1/chat/completions", "url": f"https://{host}{mi['path']}/v1/chat/completions",
        "model": mname, "route_id": mi["route_id"], "max_tokens": int(_num(raw.get("max_tokens", 16), f"{where}.max_tokens")),
        "sport": sport,
        "keys": {"namespace": inf["namespace"], "secret": inf["keys"]["models"]["secret"], "model": mname, "capture": keyed,
                 "master": {"secret": inf["keys"]["master"]["secret"], "field": inf["keys"]["master"]["field"]},
                 "backend": {"secret": inf["keys"]["backend"]["secret"], "field": inf["keys"]["backend"]["field"]},
                 "router_path": f"/engines/{mname}/chat/completions"},
        "refuse": refuse,
        "api_gateway": {"namespace": inf["namespace"], "name": inf["gateway"]["name"],
                        "selector": f"app.kubernetes.io/name={inf['gateway']['name']}", "port": inf["gateway"]["port"]},
        "router": {"namespace": inf["namespace"], "name": inf["router"]["name"],
                   "selector": f"app.kubernetes.io/name={inf['router']['name']}", "port": inf["router"]["port"]},
        "serving": {"namespace": sv["namespace"], "http_port": int(sv["ports"]["http"]), "rpc_port": int(sv["ports"]["rpc"]),
                    "rail_probe_port": int(sv["ports"]["rail_probe"])},
        "copies": copies, "pin": pin, "snaplen": dict(SNAPLEN),
        "expect": {"status": 200, "model_name": f"openai/{mname}", "api_base": mi["api_base"]},
    }
    if also:
        out["also"] = also
    if base:
        out["depth_base"] = base
    return out


# --------------------------------------------------------------------------------------------
def _published(model, resolver: str | None, fqdn: str) -> bool:
    """Whether a view that answers this resolver (it matches the resolver, or the resolver serves it)
    holds a record for the name."""
    if model.dns is None or not resolver:
        return False
    for v in model.dns.views:
        if f"node:{resolver}" in v.match or resolver in v.servers:
            if fqdn in model.dns.names_of(v):
                return True
    return False


# chapter 1: one request walked from the client to the model, and three refused

WALK_KEYS = {"client", "gateway", "model", "max_tokens", "sport", "hold_s", "refuse"}
WALK_REFUSE_KEYS = {"hostname", "key", "port"}
# the frontend's depths, before the serving form's points: the client's port, the firewall's
# interface to it, the bundle's legs, the pair's ports facing the legs, the pair's server ports
WALK_BASE = 5
# where the key's header file and the request's body sit in the client: lib-servetrace.sh's ST_DIR
WALK_DIR = "/tmp/sfab-trace"


def _fw_iface_holding(fw, address: str):
    """The firewall interface whose connected prefix holds address."""
    for i in fw.interfaces:
        if i.address and i.zone and addr.contains(addr.prefix_of(i.address), address):
            return i
    return None


def _svc_ok(v, names, proto: str, port: int, apps=()) -> bool:
    """Whether a flow's protocol and port match a rule's services: any; application-default, the
    default ports of the rule's App-IDs (panos.app_default); or a named service."""
    if "any" in names:
        return True
    if "application-default" in names:
        table = getattr(v.fw, "app_default", None) or {}
        for a in apps:
            for d in table.get(a, ()):
                pr, _, ports = str(d).partition("/")
                if pr == proto and str(port) in ports.split(","):
                    return True
        return False
    svcs = {x.name: x for x in v.services}
    return any(svcs.get(s) and svcs[s].protocol == proto and str(port) in svcs[s].port.split(",") for s in names)


def _cidr_ok(cidrs, address: str) -> bool:
    return any(c == "any" or addr.contains(c, address) for c in cidrs)


def first_rule(v, src_zone: str, dst_zone: str, src: str, dst: str, port: int, proto: str = "tcp"):
    """The render's first security rule that matches the flow, allow or deny: the one PAN-OS applies."""
    for r in v.rules:
        if not ({src_zone, "any"} & set(r.from_zones)) or not ({dst_zone, "any"} & set(r.to_zones)):
            continue
        if _cidr_ok(r.src_cidrs, src) and _cidr_ok(r.dst_cidrs, dst) and _svc_ok(v, r.services, proto, port, r.applications):
            return r
    return None


def first_nat(v, src_zone: str, dst_zone: str, src: str, dst: str, port: int, proto: str = "tcp"):
    """The render's first NAT rule that matches the flow on its pre-NAT zones, or None."""
    for n in v.nat:
        if not ({src_zone, "any"} & set(n.from_zones)) or not ({dst_zone, "any"} & set(n.to_zones)):
            continue
        if _cidr_ok(n.src_cidrs, src) and _cidr_ok(n.dst_cidrs, dst) and _svc_ok(v, [n.service], proto, port):
            return n
    return None


def walk_plan(model: Model, raw: dict) -> dict:
    """Chapter 1's walk: chapter 7's keyed serving trace for the in-cluster hops (its points numbered
    after the frontend's), chapter 4's held session for the firewall, the frontend's capture points
    from the client's port to the pair's server ports, the tables each device consults, and three
    refused requests, each with the layer that must refuse it."""
    where = "chapter.yaml trace.walk"
    if not isinstance(raw, dict):
        _err(where, "must be a mapping")
    extra = set(raw) - WALK_KEYS
    if extra:
        _err(where, f"unknown keys {sorted(extra)} (have {', '.join(sorted(WALK_KEYS))})")
    rf = raw.get("refuse") or {}
    if not isinstance(rf, dict) or set(rf) != WALK_REFUSE_KEYS:
        _err(f"{where}.refuse", f"names all three refusals: {', '.join(sorted(WALK_REFUSE_KEYS))}")
    sv_raw = {k: raw[k] for k in ("client", "gateway", "model", "max_tokens", "sport") if k in raw}
    sv_raw.update(keys=True, refuse=rf["hostname"])
    plan = serving_plan(model, sv_raw, base=WALK_BASE, where=where)
    plan["kind"] = "walk"
    from . import inference, k8s  # noqa: PLC0415
    from .panos import view  # noqa: PLC0415

    inf = inference.settings(model)
    c = model.nodes[plan["client"]["node"]]
    g = model.gateways[plan["gateway"]["name"]]
    fw = model.firewall
    v = view(model) if fw is not None else None
    if fw is None or v is None:
        _err(where, "the walk crosses the firewall: the lab has none")
    # the client's port and the firewall interface it lands on
    ci = next((i for i in c.ifaces if i.address and _bare(i.address) == plan["client"]["address"]), None)
    if ci is None or ci.peer is None or ci.peer.node != fw.name:
        _err(f"{where}.client", f"{c.name}'s port must be wired to the firewall")
    fnic = fw.nic(ci.peer.eth)
    ing = fw.interface(fnic.ifname) if fnic is not None else None
    if ing is None or not ing.zone:
        _err(f"{where}.client", f"the firewall port {ci.peer} facing {c.name} is no zoned interface")
    # the egress toward the VIP: a subinterface of a bundle whose legs land on the pair
    eg = _fw_iface_holding(v, g.vip)
    if eg is None or eg.kind != "subinterface" or not eg.parent:
        _err(f"{where}.gateway", f"{g.name}'s VIP {g.vip} is not on a subinterface of the firewall's bundle")
    bundle = fw.interface(eg.parent)
    legs = []
    for k, m in enumerate(bundle.members, 1):
        mi = fw.interface(m)
        far = model.peer(fw.name, mi.eth) if mi is not None and mi.eth else None
        sw = model.nodes.get(far.node) if far else None
        if far is None or sw is None or sw.kind != "dell_sonic":
            _err(where, f"the bundle member {m} lands on no switch of this lab")
        legs.append({"leg": k, "ifname": m, "eth": mi.eth, "switch": far.node, "switch_eth": far.eth, "native": sw.nic(far.eth).native})
    caddr, vip = plan["client"]["address"], g.vip
    rule = first_rule(v, ing.zone, eg.zone, caddr, vip, 443)
    if rule is None or rule.action != "allow":
        _err(where, f"no rule of the render allows {c.name} ({ing.zone}) to {g.name}'s VIP {vip}:443 ({eg.zone})")
    nat = first_nat(v, ing.zone, eg.zone, caddr, vip, 443)
    if nat is not None:
        _err(where, f"the NAT rule {nat.name} would translate the walked request: the walk follows an untranslated one")
    pts = [{"id": f"1-{c.name}-{ci.eth}", "node": c.name, "eth": ci.eth, "role": "client", "vlan": None},
           {"id": f"2-{fw.name}-{ing.name.replace('/', '-')}", "node": fw.name, "eth": fnic.eth, "role": "ingress", "vlan": None,
            "ifname": ing.name}]
    pts += [{"id": f"3-{fw.name}-{bundle.name}-leg{x['leg']}", "node": fw.name, "eth": x["eth"], "role": "leg", "vlan": eg.tag,
             "leg": x["leg"], "ifname": x["ifname"]} for x in legs]
    pts += [{"id": f"4-{x['switch']}-{x['native']}", "node": x["switch"], "eth": x["switch_eth"], "role": "trunk", "vlan": eg.tag,
             "leg": x["leg"]} for x in legs]
    filt = f"host {caddr} and (tcp port 443 or tcp port 22)"
    # the resolver: the view that answers the client (the authoritative view its resolver is matched
    # to), and for contrast the view another of the lab's resolvers gets for the same name
    from .dns import client_view, view_for  # noqa: PLC0415

    dns = {"hostname": plan["hostname"], "server": c.resolver_address, "resolver": c.resolver, "answer": vip, "view": None,
           "authority": None, "contrast": None}
    _res, cv = client_view(model, c)
    if cv is None or cv.answer_address != vip:
        _err(f"{where}.client", f"no view answers {c.name}'s lookups through {c.resolver} with {g.name}'s VIP")
    dns["view"] = cv.name
    dns["authority"] = cv.server
    for r in (model.dns.resolvers if model.dns is not None else ()):
        for sname in r.servers:
            rn = model.nodes.get(sname)
            if sname == c.resolver or not isinstance(rn, Host) or not rn.primary or dns["contrast"]:
                continue
            ov = view_for(model, rn.primary)
            if ov is not None and ov.name != cv.name:
                dns["contrast"] = {"node": rn.name, "source": rn.primary, "server": rn.primary, "view": ov.name, "answer": ov.answer_address}
    # the refusals: the hostname's is the serving form's refuse; another model's key; a node's port
    kr = rf["key"]
    if not isinstance(kr, dict) or set(kr) - {"model", "sport"}:
        _err(f"{where}.refuse.key", "a mapping of model (another model the lab serves) and sport")
    km = str(kr.get("model") or "")
    if km == plan["model"] or km not in {m["name"] for m in inf["models"]}:
        _err(f"{where}.refuse.key.model", f"another model the lab serves than {plan['model']}")
    ksport = int(_num(kr.get("sport"), f"{where}.refuse.key.sport"))
    pr = rf["port"]
    if not isinstance(pr, dict) or set(pr) - {"to", "port", "sport", "timeout_s"}:
        _err(f"{where}.refuse.port", "a mapping of to (a host), port, sport and timeout_s")
    dh = _host(model, pr.get("to"), f"{where}.refuse.port.to")
    daddr = dh.primary
    din = _fw_iface_holding(v, daddr) if daddr else None
    if din is None or din.parent != bundle.name:
        _err(f"{where}.refuse.port.to", f"{dh.name} is not behind the bundle {bundle.name}, whose legs the walk captures")
    dport = int(_num(pr.get("port"), f"{where}.refuse.port.port"))
    pr_rule = first_rule(v, ing.zone, din.zone, caddr, daddr, dport)
    if pr_rule is None or pr_rule.action != "deny":
        _err(f"{where}.refuse.port", f"the render allows {c.name} to {dh.name} on tcp/{dport} ({pr_rule.name if pr_rule else 'no rule'})")
    psport = int(_num(pr.get("sport"), f"{where}.refuse.port.sport"))
    sports = [plan["sport"], plan["refuse"]["sport"], ksport, psport]
    if len(set(sports)) != 4 or not all(1024 < x < 65536 for x in sports):
        _err(f"{where}.refuse", "the request and the three refusals need four unprivileged source ports, each its own")
    plan["refusals"] = {
        "hostname": dict(plan["refuse"], layer="the Gateway", device=g.name),
        "key": {"model": km, "route_model": plan["model"], "url": plan["url"], "path": plan["path"], "sport": ksport,
                "expect": inf["rejected"]["code"], "message": inf["rejected"]["message"], "layer": "the API gateway",
                "device": inf["gateway"]["name"]},
        "port": {"to": dh.name, "address": daddr, "port": dport, "sport": psport,
                 "timeout_s": _num(pr.get("timeout_s", 5), f"{where}.refuse.port.timeout_s"),
                 "expect": {"rule": pr_rule.name, "action": pr_rule.action, "from_zone": ing.zone, "to_zone": din.zone},
                 "layer": "the firewall", "device": fw.name},
    }
    # chapter 4's held session, as lib-fwtrace.sh runs it, with the model's request in place of a GET
    hold = _num(raw.get("hold_s", 30), f"{where}.hold_s")
    plan["sessions"] = [{
        "id": "walk", "client": c.name, "client_addr": caddr, "gateway": g.name, "vip": vip, "dst_addr": vip, "port": 443,
        "translated_addr": None, "fqdn": plan["hostname"], "path": plan["path"], "msg": None, "sport": plan["sport"], "hold_s": hold,
        "pin": plan["client"]["pin"], "resolver": plan["client"]["resolver"], "ca_root": CA_ROOT,
        "method": "POST", "body": f"{WALK_DIR}/request.json", "header": f"{WALK_DIR}/hdr-{plan['model']}",
        "expect": {"status": 200, "rule": rule.name, "nat_rule": None, "from_zone": ing.zone, "to_zone": eg.zone},
    }]
    plan["firewall"] = {"node": fw.name, "vr": fw.vr, "ingress": ing.name, "ingress_zone": ing.zone, "egress": eg.name,
                        "egress_zone": eg.zone, "route": addr.prefix_of(eg.address), "rule": rule.name, "nat_rule": None,
                        "bundle": bundle.name, "tag": eg.tag}
    pair = sorted({x["switch"] for x in legs})
    plan["frontend"] = {"points": pts, "filter": filt, "snaplen": SNAPLEN["vip"], "server_depth": WALK_BASE, "vlan": eg.tag,
                        "pair": pair, "legs": legs}
    plan["dns"] = dns
    # the tables the in-cluster hops consult, as the cluster runs them: the API gateway's routes and
    # the router's model list (render/inference.py's ConfigMaps and the files they hold)
    plan["tables"] = {"routes": {"configmap": inf["configmaps"]["routes"], "key": "apisix.yaml"},
                      "router": {"configmap": inf["configmaps"]["router"], "key": "config.yaml"}}
    plan["rail_counters"] = {"switches": sorted({x["switch"] for x in plan["copies"]})}
    macs = {r["pod"]: r["mac"] for r in k8s.placement(model)}
    for cp in plan["copies"]:
        cp["server"]["mac"] = macs.get(cp["server"]["pod"])
        for w in cp["workers"]:
            w["mac"] = macs.get(w["pod"])
        cp["vlan"] = model.rails[cp["rail"]].vlan
    from . import decisions  # noqa: PLC0415

    if decisions.on(model):
        # chapter 2: each hop tagged with the row of the decision table that decides there (Table
        # 2-1), "forwarding" where a switch only forwards, "-" where no row decides
        layers = {r["id"]: r["layer"] for r in decisions.rows_spec(model)}
        layers["forwarding"] = "forwarding only"
        plan["rows"] = {"layers": layers,
                        "hops": dict(WALK_ROWS),
                        "refusals": {"hostname": "routeset", "key": "key", "port": "policy"}}
    return plan


# chapter 2's tags for the walk's hops (walktrace.py's hop numbers): the resolver's view, the
# firewall's route, NAT and rule, the bundle and the pair forwarding, the Gateway's route set, the
# API gateway's key, the Service and the copy the placement table fixed, the rail switch forwarding
WALK_ROWS = (("1", "-"), ("2", "view"), ("3", "routing"), ("4", "nat"), ("5", "policy"), ("6", "forwarding"), ("7", "forwarding"),
             ("8", "-"), ("9", "routeset"), ("10", "key"), ("11", "-"), ("12", "placement"), ("13", "placement"), ("14", "forwarding"))


# --------------------------------------------------------------------------------------------
# Part III (chapters 9 to 11): the per-population DNS trace, the zone-keyed NAT trace and the
# capture ladder. Each population's outcome is render/decisions.py's path, so a changed rule or route
# moves the plan and `sfab check` reports it.

P3_FILTER_TCP = "tcp port 443"


def _vlan_aware(f: str) -> str:
    return f"({f}) or (vlan and ({f}))"


def _p3_view(model: Model, where: str):
    from .panos import view  # noqa: PLC0415

    v = view(model) if model.firewall is not None else None
    if v is None:
        _err(where, "the trace crosses the firewall: the lab has none")
    return v


def _p3_path(model: Model, v, c: Host, dst: str, port: int, where: str) -> dict:
    from .decisions import path  # noqa: PLC0415

    return path(model, v, c, dst, port, where)


def _p3_entry(model: Model, c: Host) -> dict | None:
    """Where a client's request first meets a capture point on its way to the firewall: the
    firewall's own port when the client's gateway is the firewall, else its router's port facing the
    firewall; None for a client behind a VPN router (its uplink carries ESP) or a node of the
    cluster."""
    fw = model.firewall
    gw = c.gateway
    if fw is None or not gw:
        return None
    for i in fw.interfaces:
        if i.address and _bare(i.address) == gw and i.eth:
            return {"id": f"2-{fw.name}-{i.name.replace('/', '-')}", "node": fw.name, "eth": i.eth, "ifname": i.name, "role": "fw-ingress"}
    for n in model.nodes.values():
        if not isinstance(n, Host) or n.kind != "frr" or not any(x.address and _bare(x.address) == gw for x in n.ifaces):
            continue
        for x in n.ifaces:
            if x.peer is not None and x.peer.node == fw.name:
                return {"id": f"1-{n.name}-{x.eth}", "node": n.name, "eth": x.eth, "role": "router-uplink"}
    return None


def _p3_legs(model: Model, v, vip: str, where: str) -> tuple:
    eg = _fw_iface_holding(v, vip)
    if eg is None or eg.kind != "subinterface" or not eg.parent:
        _err(where, f"{vip} is not on a subinterface of the firewall's bundle")
    fw = model.firewall
    bundle = fw.interface(eg.parent)
    legs = []
    for k, m in enumerate(bundle.members, 1):
        mi = fw.interface(m)
        legs.append({"id": f"3-{fw.name}-{bundle.name}-leg{k}", "node": fw.name, "eth": mi.eth, "ifname": m, "leg": k, "role": "leg"})
    return legs, eg.tag


def _p3_local_ports(c: Host) -> list:
    return [{"id": f"0-{c.name}-{n.eth}", "node": c.name, "eth": n.eth, "role": "node"} for n in c.nics if n.role == "bond-member"]


def _p3_population(model: Model, pid: str, where: str):
    pop = model.populations.get(pid)
    if pop is None:
        _err(where, f"{pid!r} is not a population of {model.lab}")
    from .tenancy import matrix_clients  # noqa: PLC0415

    want = matrix_clients(model).get(pid)
    name = want if want in model.nodes else next((x for x in pop.clients if x in model.nodes), None)
    if name is None:
        _err(where, f"population {pid} has no client in this lab")
    return pop, model.nodes[name]


def _p3_flow(model: Model, v, c: Host, dst: str, port: int, sport: int, where: str) -> dict:
    """One connect's plan: the path's outcome, and the capture points it must and must not reach."""
    p = _p3_path(model, v, c, dst, port, where)
    local = any(h.get("row") is None and h.get("device") == c.name for h in p["hops"])
    out = {"address": dst, "port": port, "sport": sport, "outcome": p["outcome"], "local": local,
           "at": p.get("at"), "rule": p.get("rule"), "nat_rule": p.get("nat_rule"), "from_zone": p.get("from_zone"),
           "to_zone": p.get("to_zone"), "device": p.get("device"), "drop": p.get("drop"), "hops": [h.get("what") for h in p["hops"]]}
    if p["outcome"] == "log-line":
        out["action"] = p.get("action")
    return out


DNS_KEYS = {"populations", "name", "sport"}


def dns_plan(model: Model, raw: dict) -> dict:
    """Chapter 9: each population's lookup of one name captured at its own resolver, then its SYN
    toward the answer, where the firewall's render says it goes."""
    where = "chapter.yaml trace.dns"
    if not isinstance(raw, dict) or set(raw) - DNS_KEYS:
        _err(where, f"a mapping of {', '.join(sorted(DNS_KEYS))}")
    v = _p3_view(model, where)
    fqdn = model.org.fqdn(str(raw.get("name") or "llm"))
    base = int(_num(raw.get("sport", 42900), f"{where}.sport"))
    from .dns import client_view  # noqa: PLC0415

    rows, points = [], {}
    for k, pid in enumerate(raw.get("populations") or []):
        pop, c = _p3_population(model, str(pid), f"{where}.populations")
        res = model.nodes.get(c.resolver or "")
        if not isinstance(res, Host):
            _err(f"{where}.populations", f"{c.name}'s resolver {c.resolver} is not in this lab")
        _r, cv = client_view(model, c)
        if cv is None or fqdn not in model.dns.names_of(cv):
            _err(f"{where}.populations", f"no view answers {c.name} for {fqdn}")
        r = model.dns.resolver_of(res.name)
        auth = []
        for a in (r.to if r is not None else ()):
            an = model.nodes.get(a)
            if isinstance(an, Host) and an.primary:
                auth.append(an.primary)
        reth = "bond0" if res.bond is not None else next((x.eth for x in res.ifaces if x.address), "eth1")
        rp = {"id": f"0-{res.name}-{reth}", "node": res.name, "eth": reth, "role": "resolver"}
        points[rp["id"]] = dict(rp, filter=_vlan_aware("port 53"))
        f = _p3_flow(model, v, c, cv.answer_address, 443, base + k, f"{where}.populations[{pid}]")
        seen, unseen, seen_any = [], [], []
        if f["local"]:
            for x in _p3_local_ports(c):
                points[x["id"]] = dict(x, filter=_vlan_aware(P3_FILTER_TCP))
                unseen.append(x["id"])
        else:
            e = _p3_entry(model, c)
            if e is not None:
                points[e["id"]] = dict(e, filter=_vlan_aware(P3_FILTER_TCP))
                (seen if f["outcome"] != "silence" or f.get("device") == model.firewall.name else unseen).append(e["id"])
            legs, _tag = _p3_legs(model, v, _gw_vip(model), where)
            for x in legs:
                points[x["id"]] = dict(x, filter=_vlan_aware(P3_FILTER_TCP))
            if f["outcome"] == "reached":
                seen_any = [x["id"] for x in legs]
            else:
                unseen += [x["id"] for x in legs]
        rows.append({"population": pop.name, "client": c.name, "kind": c.kind, "client_addr": c.primary, "resolver": res.name,
                     "resolver_addr": res.primary, "view": cv.name, "name": fqdn, "answer": cv.answer_address, "authorities": auth,
                     "dns_point": rp["id"], "syn": dict(f, seen=seen, unseen=unseen, seen_any=seen_any)})
    if not rows:
        _err(f"{where}.populations", "names no population")
    return {"schema": SCHEMA, "lab": model.lab, "kind": "dns", "name": fqdn, "rows": rows,
            "points": [points[k] for k in sorted(points)], "snaplen": 256}


def _gw_vip(model: Model) -> str:
    return next(iter(model.gateways.values())).vip


NAT_KEYS = {"populations", "hold_s", "sport", "hostname", "path"}


def nat_plan(model: Model, raw: dict) -> dict:
    """Chapter 10: one held HTTPS request per population to its own Gateway, at the answer its
    resolver gives it, as chapter 4's sessions (lib-fwtrace.sh), each with its capture pair: the
    point outside the firewall (the ISP router's link, the staff's firewall port; none for the
    operator, whose uplink carries ESP) and both legs of the bundle, found by capturing both."""
    where = "chapter.yaml trace.nat"
    if not isinstance(raw, dict) or set(raw) - NAT_KEYS:
        _err(where, f"a mapping of {', '.join(sorted(NAT_KEYS))}")
    v = _p3_view(model, where)
    hold = _num(raw.get("hold_s", 20), f"{where}.hold_s")
    base = int(_num(raw.get("sport", 42950), f"{where}.sport"))
    label = str(raw.get("hostname") or "llm")
    from . import k8s  # noqa: PLC0415

    tb = k8s.test_backend_settings(model) or {}
    path = str(raw.get("path") or f"{tb.get('path') or '/echo'}?msg=sfab-trace-nat")
    sessions, points = [], {}
    for k, pid in enumerate(raw.get("populations") or []):
        pop, c = _p3_population(model, str(pid), f"{where}.populations")
        if c.kind != "client":
            _err(f"{where}.populations", f"{c.name} must be a client container (hold_request.py runs in its python3)")
        aud = model.audiences.get(pop.audience)
        g = model.gateways.get(aud.gateway if aud is not None else "")
        if g is None:
            _err(f"{where}.populations", f"population {pop.name} has no Gateway")
        dst = pop.answer_address
        f = _p3_flow(model, v, c, dst, 443, base + k, f"{where}.populations[{pid}]")
        if f["outcome"] != "reached" or f["at"] != g.vip:
            _err(f"{where}.populations", f"{c.name} does not reach {g.name} at {dst}: {f['outcome']}")
        legs, tag = _p3_legs(model, v, g.vip, where)
        pts = []
        e = _p3_entry(model, c)
        if e is not None:
            points[e["id"]] = dict(e, filter=_vlan_aware(P3_FILTER_TCP))
            pts.append(e["id"])
        for x in legs:
            points[x["id"]] = dict(x, filter=_vlan_aware(P3_FILTER_TCP))
            pts.append(x["id"])
        resolver_in = bool(c.resolver and c.resolver in model.nodes)
        m = re.search(r"[?&]msg=([^&]+)", path)
        sessions.append({
            "id": pop.name, "client": c.name, "client_addr": c.primary, "gateway": g.name, "vip": g.vip, "dst_addr": dst, "port": 443,
            "translated_addr": f["at"] if f["at"] != dst else None, "fqdn": model.org.fqdn(label), "path": path,
            "msg": m.group(1) if m else None, "sport": base + k, "hold_s": hold, "pin": not resolver_in,
            "resolver": c.resolver if resolver_in else None, "ca_root": CA_ROOT,
            "expect": {"status": 200, "rule": f["rule"], "nat_rule": f["nat_rule"], "from_zone": f["from_zone"], "to_zone": f["to_zone"]},
            "points": pts, "entry": e["id"] if e else None, "legs": [x["id"] for x in legs], "vlan": tag, "hops": f["hops"]})
    if not sessions:
        _err(f"{where}.populations", "names no population")
    return {"schema": SCHEMA, "lab": model.lab, "kind": "nat", "sessions": sessions, "points": [points[k] for k in sorted(points)],
            "snaplen": 256}


LADDER_KEYS = {"sport", "tries"}


def ladder_plan(model: Model, raw: dict) -> dict:
    """Chapter 11: the capture ladder. Every population of the matrix connects to each Gateway's VIP
    (at its own answer where that lands on the Gateway after translation), tries times from its own
    source ports, while every rung captures: the ISP router's link, the staff's firewall port, both
    legs of the bundle, the pair's ports facing the ingress nodes and each ingress node's VLAN 110
    unit. Each flow carries the matrix's mode for its cell and the rungs it may reach; a forbidden
    flow's SYNs past the device that refuses it are its tally, which must be zero."""
    where = "chapter.yaml trace.ladder"
    if not isinstance(raw, dict) or set(raw) - LADDER_KEYS:
        _err(where, f"a mapping of {', '.join(sorted(LADDER_KEYS))}")
    from . import decisions, k8s  # noqa: PLC0415

    if not decisions.on(model):
        _err(where, "the ladder runs the matrix's Gateway cells: chapter.yaml needs decisions: true")
    v = _p3_view(model, where)
    mx = decisions.matrix(model)
    tries = int(_num(raw.get("tries", 3), f"{where}.tries"))
    base = int(_num(raw.get("sport", 42970), f"{where}.sport"))
    gws = {g.name: g for g in model.gateways.values()}
    vips = {g.vip: g.name for g in gws.values()}
    legs, tag = _p3_legs(model, v, next(iter(gws.values())).vip, where)
    points = {}
    for x in legs:
        points[x["id"]] = dict(x, filter=_vlan_aware(P3_FILTER_TCP), rung=3)
    ingress = [h for h in model.by_group("ingress") if isinstance(h, Host)]
    if not ingress:
        ingress = [h for h in model.nodes.values() if isinstance(h, Host) and h.bond is not None
                   and any(u.vlan == tag for u in getattr(h.bond, "vlan_ifs", ()) or ())]
    for h in ingress:
        for n in h.nics:
            if n.role != "bond-member" or n.peer is None:
                continue
            sw = model.nodes.get(n.peer.node)
            nat_ = sw.nic(n.peer.eth).native if sw is not None and sw.nic(n.peer.eth) is not None else n.peer.eth
            pid = f"4-{n.peer.node}-{nat_}"
            points[pid] = {"id": pid, "node": n.peer.node, "eth": n.peer.eth, "native": nat_, "faces": h.name, "role": "pair-port",
                           "filter": _vlan_aware(P3_FILTER_TCP), "rung": 4}
        unit = next((u for u in getattr(h.bond, "vlan_ifs", ()) or () if u.vlan == tag), None)
        if unit is not None:
            pid = f"5-{h.name}-{unit.name}"
            points[pid] = {"id": pid, "node": h.name, "iface": unit.name, "role": "holder", "guest": True, "filter": P3_FILTER_TCP,
                           "rung": 5}
    rows = {r["id"]: r for r in mx["rows"]}
    flows, k = [], 0
    for cell in mx["cells"]:
        col = next(x for x in mx["columns"] if x["id"] == cell["column"])
        if col["kind"] != "connect" or not str(col.get("ref", "")).startswith("vip:"):
            continue
        r = rows[cell["row"]]
        c = model.nodes[r["client"]]
        if not isinstance(c, Host):
            continue
        g = gws[col["ref"].split(":", 1)[1]]
        f = _p3_flow(model, v, c, cell["address"], int(cell["port"]), base + k * tries, f"{where} {cell['id']}")
        e = None if f["local"] else _p3_entry(model, c)
        if e is not None:
            points[e["id"]] = dict(e, filter=_vlan_aware(P3_FILTER_TCP), rung=int(e["id"].split("-")[0]))
        # the rungs the flow may reach: up to its refusal; past it, its tally
        if f["local"]:
            may, refused_at = [], c.name
        elif f["outcome"] == "silence" and f.get("device") != model.firewall.name:
            may, refused_at = [], f.get("device")
        elif f["outcome"] in ("log-line", "silence"):
            may, refused_at = ([e["id"]] if e else []), model.firewall.name
        else:
            may, refused_at = ([e["id"]] if e else []) + ["legs", "pair", "holder"], None
        flows.append({"id": cell["id"], "population": r["id"], "client": c.name, "kind": c.kind, "client_addr": c.primary,
                      "gateway": g.name, "vip": g.vip, "address": cell["address"], "port": int(cell["port"]),
                      "post_nat": f["at"] if f["outcome"] == "reached" else None, "mode": cell["mode"], "allowed": cell["mode"] == "allowed",
                      "local": f["local"], "entry": e["id"] if e else None, "may": may, "refused_at": refused_at,
                      "sport": base + k * tries, "tries": 1 if cell["mode"] == "allowed" else tries,
                      "lease": f"{k8s.SYSTEM_NS}/{k8s.l2_lease(model, g)}"})
        k += 1
    if not flows:
        _err(where, "the matrix holds no Gateway connect cell")
    return {"schema": SCHEMA, "lab": model.lab, "kind": "ladder", "flows": flows, "points": [points[x] for x in sorted(points)],
            "vlan": tag, "pair": sorted({p["node"] for p in points.values() if p["role"] == "pair-port"}),
            "ingress": [{"node": h.name, "mac": h.bond.mac if h.bond else None} for h in ingress], "snaplen": 128,
            "vips": vips, "timeout_s": 4}


def render(model: Model, ctx) -> dict:
    ch = model.meta.chapter
    raw = getattr(ch, "trace", None) if ch is not None else None
    if raw and "walk" in raw:
        if set(raw) - {"walk"}:
            _err("chapter.yaml trace", "a walk trace holds walk: only")
        return {"gen/trace.json": dumps(walk_plan(model, raw["walk"]))}
    if raw and "serving" in raw:
        if set(raw) - {"serving"}:
            _err("chapter.yaml trace", "a serving trace holds serving: only")
        return {"gen/trace.json": dumps(serving_plan(model, raw["serving"]))}
    if raw and "rails" in raw:
        if set(raw) - {"rails"}:
            _err("chapter.yaml trace", "a rails trace holds rails: only")
        return {"gen/trace.json": dumps(rails_plan(model, raw["rails"]))}
    for form, fn in (("dns", dns_plan), ("nat", nat_plan), ("ladder", ladder_plan)):
        if raw and form in raw:
            if set(raw) - {form}:
                _err("chapter.yaml trace", f"a {form} trace holds {form}: only")
            return {"gen/trace.json": dumps(fn(model, raw[form]))}
    if not raw or not ("sessions" in raw or "pull" in raw):
        return {}
    return {"gen/trace.json": dumps(plan(model, raw))}
