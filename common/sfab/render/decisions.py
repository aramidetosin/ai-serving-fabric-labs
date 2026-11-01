"""gen/decisions.yaml and gen/matrix.yaml (chapter 2), with their runtime forms gen/decisions.json and
gen/matrix.json, in a lab whose chapter.yaml says decisions: true.

The decision table (Table 2-1) is the spec's decisions.rows, one row per layer a request meets, each
with the objects of the lab that implement it, found in the model:

    view       the DNS views, each with its server, the segments it answers and its answer
    routing    the firewall's connected gateway subnets and static routes, and each router's static
               routes as render/frr.py keeps them
    nat        the firewall's NAT rules, in order
    policy     the firewall's security rules, in order (deny-all-log last)
    routeset   every HTTPRoute on a Gateway: the model routes (render/inference.py), the test
               backend's (render/k8s.py) and the serving recipe's
    key        the API gateway's consumer groups, one per caller (one per model in a lab with no callers)
    placement  the placement table's copies and the rail attachments they use

Each object carries its decision id: the element's own decision:, else dec-<row prefix>-<object
name>, and says where the id is stamped on the device (a rule's description, an HTTPRoute's label,
a zone file's comments, a consumer group's desc, a pod's label and an attachment's annotation, a
router's comment line) or that it is not (the firewall's routes and connected subnets, which PAN-OS
holds no comment for in this render). Every switch is labeled forwarding only (decisions.forwarding),
with the decision ids its own ports carry; the ids the spec gives objects of no row are listed with
why (decisions.other). An explicit id under no row and not listed there is a render error.

The matrix (Table 2-2) is the spec's matrix.rows (a population and the client it tries from) by
matrix.columns. Each cell's mode is computed here, as the request meets the layers: the client's
resolver view answers its name; the client's gateway, or a router's static route, takes it to the
firewall, which looks up the route on ingress, matches a NAT rule on the pre-NAT zones and the first
security rule on the original addresses and the post-NAT zone; a Gateway's HTTPRoutes match the
hostname and path; the API gateway matches the key. A cell is one of

    allowed    a TCP connect that opens, or a model's route answered 200 with its own key
    log-line   a security rule that denies it, named, with its zones (the traffic log's evidence)
    404        no HTTPRoute of the Gateway it reaches matches the hostname and path
    401        a model route asked with a key that is not the model's (the second request of every
               model cell; the cell's own mode stays allowed)
    silence    a device on the path drops it without a word, named: a router with no route to the
               destination, the firewall's discard route, or zone protection's strict IP check on
               the firewall (a source the firewall routes out another interface, such as the
               operator's site prefix arriving on the uplink instead of through its tunnel)

A model cell holds two requests, the model's own key and another model's. A connect cell whose
population's answer lands on that same Gateway after translation is tried at the answer (the
operator's internal Gateway cell at the public address). Every request gets its source port from
matrix.sport (two a request: the attempt and one retry), and the cells that a lab cannot try (a
client or an endpoint outside its slice) are a render error, since the matrix proves the whole
table or nothing.
"""

from __future__ import annotations

import json
import re

from .. import addr
from ..model import Host, Model, Storage, Switch
from . import RenderError

SCHEMA = 1
ROW_IDS = ("view", "routing", "nat", "policy", "routeset", "key", "placement")
MODES = ("allowed", "log-line", "404", "401", "silence")
ID_RE = re.compile(r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$")
YAML_PATH, JSON_PATH = "gen/decisions.yaml", "gen/decisions.json"
MATRIX_YAML, MATRIX_JSON = "gen/matrix.yaml", "gen/matrix.json"
# what a client container and a VM guest are tried with
CLIENT_KINDS = ("client", "vm-node", "bastion")


def _err(where: str, msg: str):
    raise RenderError(f"{where}: {msg}")


def on(model: Model) -> bool:
    """True when the lab's chapter.yaml says decisions: true."""
    ch = model.meta.chapter
    return bool(getattr(ch, "decisions", False)) if ch is not None else False


def _block(model: Model) -> dict:
    d = (model.spec or {}).get("decisions")
    if not isinstance(d, dict) or not isinstance(d.get("rows"), list):
        _err("spec decisions", "a lab with decisions: true needs the spec's decisions.rows")
    return d


def rows_spec(model: Model) -> list:
    """The spec's rows, checked: the seven layers in order, each with its columns."""
    rows = _block(model)["rows"]
    ids = [str(r.get("id")) for r in rows if isinstance(r, dict)]
    if tuple(ids) != ROW_IDS:
        _err("spec decisions.rows", f"the rows are {', '.join(ROW_IDS)}, in that order (have {', '.join(ids)})")
    for r in rows:
        for k in ("prefix", "layer", "owner", "object", "decision", "evidence", "refusal"):
            if not r.get(k):
                _err(f"spec decisions.rows[{r['id']}]", f"{k}: is required")
    return rows


def _prefixes(model: Model) -> dict:
    return {str(r["id"]): str(r["prefix"]) for r in rows_spec(model)}


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")


def label_of(model: Model, row: str, name: str, explicit: str | None = None) -> str | None:
    """The decision id an object of ROW carries: its own, else (in a decisions lab) the derived
    dec-<prefix>-<name>; outside a decisions lab only its own."""
    if explicit:
        return explicit
    if not on(model):
        return None
    lid = f"dec-{_prefixes(model)[row]}-{_slug(name)}"
    if not ID_RE.match(lid):
        _err(f"decision label for {row} {name}", f"{lid!r} is no valid label value (63 characters, a-z 0-9 -)")
    return lid


def forwarding(model: Model) -> dict:
    f = dict(_block(model).get("forwarding") or {})
    if not f.get("decision") or not f.get("what"):
        _err("spec decisions.forwarding", "needs decision: and what:")
    return {"decision": str(f["decision"]), "what": str(f["what"])}


def forwarding_line(model: Model) -> str | None:
    """The KLISH comment every switch of a decisions lab carries (render/klish.py)."""
    if not on(model):
        return None
    f = forwarding(model)
    return f"! decision {f['decision']}: {f['what']}"


def consumer_desc(model: Model, name: str, desc: str) -> str:
    """A consumer group's desc in the API gateway's routes (render/inference.py)."""
    d = label_of(model, "key", name)
    return f"{d}: {desc}" if d else desc


# --------------------------------------------------------------------------------------------
# the objects of each row


def _bare(a):
    return str(a).split("/")[0] if a else None


def _dlabel(model: Model) -> str | None:
    return model.k8s.labels.get("decision") if model.k8s is not None else None


def route_sets(model: Model) -> list:
    """Every HTTPRoute on a Gateway of the lab: name, namespace, gateway, hostnames, path prefixes,
    what it leads to and its decision id."""
    out = _route_sets(model)
    lk = _dlabel(model)
    return [dict({"kind": "HTTPRoute"}, **r, device=r["gateway"],
                 stamped=f"the HTTPRoute's label {lk}" if lk and r.get("decision") else "not labelled") for r in out]


def _route_sets(model: Model) -> list:
    from . import k8s as K  # noqa: PLC0415

    out = []
    if model.k8s is None or not K.enabled(model):
        return out
    if K.serving_enabled(model):
        from . import inference  # noqa: PLC0415

        if inference.enabled(model):
            inf = inference.settings(model)
            for rt in inf["routes"]:
                g = model.gateways[rt["gateway"]]
                out.append({"name": rt["name"], "namespace": inf["namespace"], "gateway": rt["gateway"], "hostnames": list(rt["hostnames"]),
                            "paths": [x["path"] for x in rt["rules"]], "to": f"the API gateway ({inf['gateway']['name']})",
                            "models": [x["model"] or "all" for x in rt["rules"]],
                            "decision": label_of(model, "routeset", rt["name"], g.decision)})
        sv = K.serving_summary(model)
        r = sv["route"]
        g = model.gateways[r["gateway"]]
        out.append({"name": r["name"], "namespace": sv["namespace"], "gateway": r["gateway"], "hostnames": [r["hostname"]],
                    "paths": [f"/{m['name']}" for m in sv["models"]], "to": "the serving recipe's Services", "models": [m["name"] for m in sv["models"]],
                    "decision": label_of(model, "routeset", r["name"], g.decision)})
    tb = K.test_backend_settings(model)
    if tb:
        for gname in tb["gateways"]:
            g = model.gateways[gname]
            out.append({"name": K.route_name(tb, gname), "namespace": str(tb["namespace"]), "gateway": gname, "hostnames": list(g.hostnames),
                        "paths": [str(tb["path"])], "to": f"the test backend ({tb['name']})", "models": [],
                        "decision": label_of(model, "routeset", K.route_name(tb, gname), g.decision)})
    return out


def _views(model: Model) -> list:
    if model.dns is None:
        return []
    out = []
    for v in model.dns.views:
        if v.server not in model.nodes:
            continue
        z = model.dns.zone
        out.append({"kind": "DNS view", "name": v.name, "device": v.server, "server_kind": v.kind, "match": list(v.match),
                    "answer": v.answer_address, "decision": label_of(model, "view", v.name, v.decision),
                    "servers": list(v.servers or (v.server,)),
                    "stamped": f"zone file comments, bootstrap/{v.server}/zones/db.{v.name}.{z}, and the view's comment in named.conf"})
    return out


def _routing(model: Model, v) -> list:
    from . import frr  # noqa: PLC0415

    out = []
    fw = model.firewall
    if fw is not None and v is not None:
        for i in v.interfaces:
            if i.address and i.zone and i.kind in ("subinterface", "layer3"):
                out.append({"kind": "connected subnet", "name": i.name, "device": fw.name, "dest": addr.prefix_of(i.address),
                            "zone": i.zone, "decision": label_of(model, "routing", f"connected-{i.name}"),
                            "stamped": "not stamped on the firewall"})
        for r in v.routes:
            out.append({"kind": "static route", "name": r.name, "device": fw.name, "dest": r.dest, "nexthop": r.nexthop,
                        "interface": r.interface, "decision": label_of(model, "routing", r.name),
                        "stamped": "not stamped on the firewall"})
    for h in model.hosts.values():
        if h.kind != "frr":
            continue
        keep, _ = frr.kept_routes(model, h)
        for r in keep:
            out.append({"kind": "static route", "name": r.id or r.dest, "device": h.name, "dest": r.dest, "nexthop": r.via,
                        "decision": label_of(model, "routing", r.id or r.dest, r.decision),
                        "stamped": f"its comment line in bootstrap/{h.name}/frr.conf"})
    return out


def _nat(model: Model, v) -> list:
    if v is None:
        return []
    return [{"kind": "NAT rule", "name": n.name, "device": model.firewall.name, "from": list(n.from_zones), "to": list(n.to_zones),
             "translation": (f"destination {n.dnat}" if n.dnat else f"source, {n.snat_interface}'s address" if n.snat_interface else "none"),
             "decision": n.decision, "stamped": "the rule's description"} for n in v.nat]


def _policy(model: Model, v) -> list:
    if v is None:
        return []
    return [{"kind": "security rule", "name": r.name, "device": model.firewall.name, "from": list(r.from_zones), "to": list(r.to_zones),
             "action": r.action, "decision": r.decision, "stamped": "the rule's description"} for r in v.rules]


def _keys(model: Model) -> list:
    from . import inference  # noqa: PLC0415

    if not inference.enabled(model):
        return []
    inf = inference.settings(model)
    if inf.get("callers_on"):
        # one consumer group per caller; the routes it may call are those of its models
        paths = {m["name"]: m["path"] for m in inf["models"]}
        return [{"kind": "consumer group", "name": c["id"], "device": inf["gateway"]["name"],
                 "route": ", ".join(paths[x] for x in c["models"]), "models": list(c["models"]), "caller_kind": c["kind"],
                 "decision": label_of(model, "key", c["id"]),
                 "stamped": f"the consumer group's desc in the ConfigMap {inf['configmaps']['routes']}"} for c in inf["callers"]]
    return [{"kind": "consumer group", "name": m["name"], "device": inf["gateway"]["name"], "route": m["path"],
             "decision": label_of(model, "key", m["name"]),
             "stamped": f"the consumer group's desc in the ConfigMap {inf['configmaps']['routes']}"} for m in inf["models"]]


def nad_decisions(model: Model) -> dict:
    """{attachment name: the decision ids of the copies on its rail, joined by a comma}."""
    if model.k8s is None:
        return {}
    by: dict = {}
    for mod in model.models.values():
        for c in mod.copies:
            d = label_of(model, "placement", f"{mod.name}-{c.name}", c.decision)
            if d:
                by.setdefault(f"rail{c.rail}", [])
                if d not in by[f"rail{c.rail}"]:
                    by[f"rail{c.rail}"].append(d)
    return {k: ",".join(v) for k, v in sorted(by.items())}


def _placement(model: Model) -> list:
    if model.k8s is None:
        return []
    out = []
    for mod in model.models.values():
        for c in mod.copies:
            out.append({"kind": "model copy", "name": f"{mod.name}-{c.name}", "device": "cluster", "rail": c.rail, "attachment": f"rail{c.rail}",
                        "server": c.server, "workers": list(c.workers), "decision": label_of(model, "placement", f"{mod.name}-{c.name}", c.decision),
                        "stamped": "the placement table's decision column, each pod's label and the attachment's annotation"})
    return out


def _explicit_ids(model: Model) -> dict:
    """{decision id: [where]} for every id the spec gives an element of the lab."""
    out: dict = {}

    def add(d, where):
        if d:
            out.setdefault(d, []).append(where)

    for n in model.nodes.values():
        add(n.decision, f"node {n.name}")
        if isinstance(n, Switch):
            for pc in n.portchannels:
                add(pc.decision, f"{n.name} {pc.name}")
            for ap in n.access_ports:
                add(ap.decision, f"{n.name} {ap.native}")
        if isinstance(n, Host):
            for r in n.routes:
                add(r.decision, f"{n.name} route {r.id or r.dest}")
    for g in model.gateways.values():
        add(g.decision, f"gateway {g.name}")
    for mod in model.models.values():
        for c in mod.copies:
            add(c.decision, f"model {mod.name} copy {c.name}")
    fw = model.firewall
    if fw is not None:
        for r in fw.rules:
            add(r.decision, f"rule {r.name}")
        for r in fw.nat:
            add(r.decision, f"nat {r.name}")
    if model.dns is not None:
        for v in model.dns.views:
            add(v.decision, f"view {v.name}")
    return out


def _switch_ports(sw: Switch) -> list:
    out = []
    for pc in sw.portchannels:
        if pc.decision:
            out.append({"port": pc.name, "desc": pc.desc, "decision": pc.decision})
    for ap in sw.access_ports:
        if ap.decision:
            out.append({"port": ap.native, "desc": ap.desc, "decision": ap.decision})
    return out


def table(model: Model) -> dict:
    """The decision table with every row's objects (gen/decisions.yaml)."""
    from .panos import view  # noqa: PLC0415

    v = view(model)
    found = {"view": _views(model), "routing": _routing(model, v), "nat": _nat(model, v), "policy": _policy(model, v),
             "routeset": route_sets(model), "key": _keys(model), "placement": _placement(model)}
    rows = []
    for r in rows_spec(model):
        rid = str(r["id"])
        row = {k: str(r[k]) for k in ("id", "layer", "owner", "object", "decision", "evidence", "refusal")}
        if r.get("note"):
            row["note"] = str(r["note"])
        row["prefix"] = f"dec-{r['prefix']}-"
        row["objects"] = found[rid]
        rows.append(row)
    fwd = forwarding(model)
    switches = [{"name": s.name, "role": s.role, "decision": fwd["decision"], "ports": _switch_ports(s),
                 "stamped": f"the comment under the header of bootstrap/{s.name}/startup-config.cfg"}
                for s in model.switches.values()]
    carried = {o["decision"] for r in rows for o in r["objects"] if o.get("decision")}
    carried |= {p["decision"] for s in switches for p in s["ports"]} | {fwd["decision"]}
    other = []
    listed = {}
    for o in _block(model).get("other") or []:
        listed[str(o.get("decision"))] = str(o.get("why") or "")
    exp = _explicit_ids(model)
    for d, where in sorted(exp.items()):
        if d in carried:
            continue
        if d not in listed:
            _err("spec decisions.other", f"{d} labels {', '.join(where)}, which implement no row: list it with why, or put it on a row's object")
        other.append({"decision": d, "objects": sorted(set(where)), "why": listed[d]})
    for d in sorted(set(exp) | carried):
        if not ID_RE.match(d):
            _err("decision ids", f"{d!r} is no valid label value (63 characters, a-z 0-9 -)")
    return {"schema": SCHEMA, "lab": model.lab, "build": model.build, "org": model.org.name,
            "label": _dlabel(model), "rows": rows,
            "forwarding": {"decision": fwd["decision"], "what": fwd["what"], "switches": switches}, "other": other}


# --------------------------------------------------------------------------------------------
# the matrix


def _cidr_ok(cidrs, a: str) -> bool:
    return any(c == "any" or addr.contains(c, a) for c in cidrs)


def _fw_iface_of(v, a: str):
    for i in v.interfaces:
        if i.address and i.zone and i.kind in ("subinterface", "layer3") and addr.contains(addr.prefix_of(i.address), a):
            return i
    return None


def _fw_own(v, a: str):
    for i in v.interfaces:
        if i.address and _bare(i.address) == a:
            return i
    return None


def _fw_route(v, a: str):
    """(egress interface, zone, the route as text) for address a on the firewall, or None."""
    i = _fw_iface_of(v, a)
    if i is not None:
        return i, i.zone, f"{addr.prefix_of(i.address)} connected on {i.name}"
    best = None
    for r in v.routes:
        if addr.contains(r.dest, a) and (best is None or addr.net(r.dest).prefixlen > addr.net(best.dest).prefixlen):
            best = r
    if best is None:
        return None
    if best.kind == "discard":
        return None, None, f"{best.dest} discard ({best.name})"
    ei = next((x for x in v.interfaces if x.name == best.interface), None)
    if best.kind == "interface":
        return ei, (ei.zone if ei else None), f"{best.dest} out {best.interface} ({best.name})"
    return ei, (ei.zone if ei else None), f"{best.dest} via {best.nexthop} on {best.interface} ({best.name})"


def _router_holding(model: Model, a: str):
    for h in model.hosts.values():
        if h.kind == "frr":
            for i in h.ifaces:
                if i.address and _bare(i.address) == a:
                    return h
    return None


def _vpn_router_holding(model: Model, a: str):
    """The VPN router (kind vpngw) that holds address a, or None."""
    for h in model.hosts.values():
        if h.kind == "vpngw":
            for i in h.ifaces:
                if i.address and _bare(i.address) == a:
                    return h
    return None


def _tunnel_for(v, vr: Host, src: str, dst: str):
    """(the firewall's tunnel, proxy ID name, its tunnel interface) that carries src to dst from a
    VPN router, or None."""
    if v is None:
        return None
    for x in v.vpns:
        if x.peer != vr.primary:
            continue
        for name, local, remote in x.proxy_ids:
            if addr.contains(remote, src) and addr.contains(local, dst):
                tif = next((i for i in v.interfaces if i.name == x.tunnel_interface), None)
                if tif is not None:
                    return x, name, tif
    return None


def _router_route(model: Model, h: Host, a: str):
    from . import frr  # noqa: PLC0415

    for i in frr.wired(h):
        if addr.contains(addr.prefix_of(i.address), a):
            return None, f"{addr.prefix_of(i.address)} connected on {i.eth}"
    keep, _ = frr.kept_routes(model, h)
    best = None
    for r in keep:
        if "/" in str(r.dest) and addr.contains(r.dest, a) and (best is None or addr.net(r.dest).prefixlen > addr.net(best.dest).prefixlen):
            best = r
    if best is None:
        return False, None
    return best, f"{best.dest} via {best.via} ({best.id or 'static'})"


# The global counter PAN-OS 12.1.2 raises when zone protection's strict IP check drops a packet (build
# A revision 2: the operator's requests outside the tunnel's proxy IDs, flow_dos_pf_strictip 3 for
# three connects, and no traffic log line)
STRICT_IP_COUNTER = "flow_dos_pf_strictip"
# what a silent cell's expectation carries beside its device: how the firewall dropped it, when not
# by a route of its own (drop, the counter that counts it, the route the source takes back)
SILENCE_KEYS = ("drop", "counter", "source_route")


def _strict_ip_drop(v, ing, s_addr: str):
    """{route, profile} when the ingress zone's protection profile turns on the strict IP check and
    the firewall routes the source out another interface than the one it came in on (PAN-OS: the
    source must be routable over the ingress interface), else None."""
    z = next((x for x in v.zones if x.name == ing.zone), None)
    p = v.fw.profiles
    if z is None or not z.zone_protection or p is None or p.zone_protection != z.zone_protection:
        return None
    if "strict-ip-check" not in (p.zp_discard or ()):
        return None
    back = _fw_route(v, s_addr)
    if back is None:
        return {"route": "nowhere (no route back to it)", "profile": z.zone_protection}
    ei, _zone, text = back
    if ei is not None and ei.name == ing.name:
        return None
    return {"route": f"by {text}" if ei is not None else f"to a discard route ({text})", "profile": z.zone_protection}


def path(model: Model, v, src: Host, dst: str, port: int, where: str) -> dict:
    """The request from src to dst:port as the layers meet it: {hops: [...], outcome, at, ...}.
    outcome is reached (at the address the request reaches after translation), log-line or silence."""
    hops = []
    s_addr = src.primary
    ss, ds = model.segment_of(s_addr), model.segment_of(dst)
    if ss is not None and ds is not None and ss.id == ds.id:
        hops.append({"row": None, "device": None, "what": f"same segment ({ss.id}): no routed hop, no firewall"})
        return {"hops": hops, "outcome": "reached", "at": dst}
    if model.k8s is not None and getattr(src, "k8s", None) and any(g.vip == dst for g in model.gateways.values()):
        # a node of the cluster asking one of its own Gateways' VIPs: the VIP is a LoadBalancer
        # Service address, and Cilium (kubeProxyReplacement, render/k8s.py) translates it to a
        # Gateway pod at connect(), so no packet to the VIP leaves the node and no firewall sees it
        hops.append({"row": None, "device": src.name,
                     "what": f"{dst} is a LoadBalancer address of {src.name}'s own cluster: Cilium translates it to a Gateway pod "
                             "at connect(), so nothing to it leaves the node and no firewall sees it"})
        return {"hops": hops, "outcome": "reached", "at": dst}
    gw = src.gateway
    if not gw:
        _err(where, f"{src.name} has no default gateway")
    fw = model.firewall
    ing = None
    vr = _vpn_router_holding(model, gw)
    if vr is not None:
        t = _tunnel_for(v, vr, s_addr, dst)
        if t is not None:
            x, pid, tif = t
            hops.append({"row": "routing", "device": vr.name,
                         "what": f"into the IPsec tunnel to the firewall ({x.name}, proxy ID {pid}): {dst} is in its remote selector"})
            ing = tif
        else:
            hops.append({"row": "routing", "device": vr.name, "what": f"{dst} is in no tunnel selector: out via {vr.gateway}"})
            gw = vr.gateway
    if ing is not None:
        pass
    elif v is not None and _fw_own(v, gw) is not None:
        ing = _fw_own(v, gw)
    else:
        rtr = _router_holding(model, gw)
        if rtr is None:
            _err(where, f"{src.name}'s gateway {gw} is neither the firewall's nor a router's")
        r, text = _router_route(model, rtr, dst)
        if r is False:
            hops.append({"row": "routing", "device": rtr.name, "what": f"no route to {dst}"})
            return {"hops": hops, "outcome": "silence", "device": rtr.name, "layer": "routing"}
        hop = {"row": "routing", "device": rtr.name, "what": text}
        if r:
            hop.update(dest=str(r.dest), via=str(r.via))
        hops.append(hop)
        if r is None:
            # connected: the destination is on the router's own segment; the firewall's address
            # there takes the request in on that interface
            ing = _fw_own(v, dst) if v is not None else None
            if ing is None:
                return {"hops": hops, "outcome": "reached", "at": dst}
        else:
            ing = _fw_own(v, r.via) if v is not None else None
        if ing is None:
            _err(where, f"{rtr.name} routes {dst} via {r.via}, which is not the firewall")
    if fw is None or v is None:
        _err(where, "the path crosses no firewall the lab holds")
    sip = _strict_ip_drop(v, ing, s_addr)
    if sip is not None:
        hops.append({"row": "routing", "device": fw.name,
                     "what": f"in on {ing.name} (zone {ing.zone}): the source {s_addr} is routed {sip['route']}, not over {ing.name}, so "
                             f"zone protection's strict IP check ({sip['profile']}) drops it before any rule"})
        return {"hops": hops, "outcome": "silence", "device": fw.name, "layer": "routing", "drop": "strict-ip",
                "counter": STRICT_IP_COUNTER, "source_route": sip["route"]}
    own = _fw_own(v, dst)
    if own is not None:
        pre_zone, rtext = own.zone, f"{dst} is the firewall's own address on {own.name}"
    else:
        rt = _fw_route(v, dst)
        if rt is None:
            hops.append({"row": "routing", "device": fw.name, "what": f"in on {ing.name} (zone {ing.zone}): no route to {dst}"})
            return {"hops": hops, "outcome": "silence", "device": fw.name, "layer": "routing"}
        _ei, pre_zone, rtext = rt
        if _ei is None and pre_zone is None:
            hops.append({"row": "routing", "device": fw.name, "what": f"in on {ing.name} (zone {ing.zone}): {rtext}: dropped before policy"})
            return {"hops": hops, "outcome": "silence", "device": fw.name, "layer": "routing"}
    hops.append({"row": "routing", "device": fw.name, "what": f"in on {ing.name} (zone {ing.zone}): {rtext}, zone {pre_zone}"})
    from .trace import first_nat, first_rule  # noqa: PLC0415

    n = first_nat(v, ing.zone, pre_zone, s_addr, dst, port)
    post, post_zone = dst, pre_zone
    if n is not None and n.dnat:
        post = n.dnat
        pi = _fw_iface_of(v, post)
        if pi is None:
            _err(where, f"NAT rule {n.name} translates to {post}, on no zoned interface of the firewall")
        post_zone = pi.zone
        hops.append({"row": "nat", "device": fw.name, "what": f"{n.name}: destination {dst} translated to {post}, zone {post_zone}",
                     "rule": n.name})
    elif n is not None:
        hops.append({"row": "nat", "device": fw.name, "what": f"{n.name}: no translation", "rule": n.name})
    else:
        hops.append({"row": "nat", "device": fw.name, "what": f"no NAT rule from zone {ing.zone}: no translation", "rule": None})
    r = first_rule(v, ing.zone, post_zone, s_addr, dst, port)
    if r is None:
        _err(where, f"no security rule matches {src.name} ({ing.zone}) to {dst}:{port} ({post_zone}): the rulebase must end in a rule for any zone")
    if own is not None and post == dst and r.action == "allow":
        _err(where, f"{dst}:{port} is answered by the firewall itself, which the matrix does not try")
    hops.append({"row": "policy", "device": fw.name, "what": f"{r.name}: {r.action}, zone {ing.zone} to {post_zone}", "rule": r.name})
    if r.action != "allow":
        return {"hops": hops, "outcome": "log-line", "device": fw.name, "layer": "policy", "rule": r.name, "action": r.action,
                "from_zone": ing.zone, "to_zone": post_zone}
    return {"hops": hops, "outcome": "reached", "at": post, "rule": r.name, "nat_rule": n.name if n is not None else None,
            "from_zone": ing.zone, "to_zone": post_zone}


def _view_for(model: Model, pop, client: Host, where: str):
    """The view that answers a population's client: the authoritative view its resolver is matched
    to (render/dns.py client_view)."""
    from .dns import client_view  # noqa: PLC0415

    _res, v = client_view(model, client)
    if v is None or not v.answer_address:
        _err(where, f"no view answers {client.name}'s lookups through {pop.resolver}")
    return v


def _route_match(sets: list, gateway: str, host: str, upath: str):
    for rs in sets:
        if rs["gateway"] != gateway or host not in rs["hostnames"]:
            continue
        for p in rs["paths"]:
            if upath == p or upath.startswith(p.rstrip("/") + "/") or upath.startswith(p + "?"):
                return rs, p
    return None, None


def _target(model: Model, ref: str, where: str) -> tuple:
    """(address, what) for a connect column's reference."""
    kind, _, val = str(ref).partition(":")
    if kind == "vip":
        g = model.gateways.get(val)
        if g is None:
            _err(where, f"{ref}: no such Gateway in this lab")
        return g.vip, f"{g.name}'s VIP"
    if kind == "api" and not val:
        if model.k8s is None:
            _err(where, "api: the lab has no cluster")
        return _bare(model.k8s.api_vip), "the API server's VIP"
    n = model.nodes.get(val)
    if n is None:
        _err(where, f"{ref}: {val} is not a node of this lab")
    if kind == "node" and isinstance(n, Host) and n.primary:
        return n.primary, f"{n.name}'s address"
    if kind == "oob" and isinstance(n, Host) and n.oob is not None:
        return _bare(n.oob.address), f"{n.name}'s BMC address"
    if kind in ("data", "mgmt") and isinstance(n, Storage):
        si = n.data if kind == "data" else n.mgmt_if
        if si is not None:
            return _bare(si.address), f"{n.name}'s {'data' if kind == 'data' else 'management'} address"
    _err(where, f"{ref}: not an address reference this column can take (vip:, api, node:, oob:, data:, mgmt:)")
    return None, None


def _gw_iface_toward(v, rtr: Host):
    """The firewall's interface on a subnet it shares with a router: where the router would hand the
    firewall a request it held a route for."""
    for i in rtr.ifaces:
        if not i.address:
            continue
        for fi in v.interfaces:
            if fi.address and fi.zone and addr.contains(addr.prefix_of(fi.address), _bare(i.address)):
                return fi
    return None


def own_caller(model: Model, inf: dict, population, model_name: str) -> tuple:
    """(the caller whose key a population's model cell is asked with, the default one): the first
    application caller of the population's audience that may call the model, else the model's first
    application caller (Part II's rule: batch for chat). The default is the model's first."""
    apps = [c for c in inf["callers"] if c["kind"] == "application" and model_name in c["models"]]
    if not apps:
        return None, None
    default = apps[0]["id"]
    aud = {str(c.get("id")): c.get("audience") for c in ((model.spec or {}).get("inference") or {}).get("callers") or []}
    mine = next((c["id"] for c in apps if aud.get(c["id"]) == population.audience), None)
    return mine or default, default


def held_caller(model: Model, inf: dict, population) -> str | None:
    """The caller whose key a population holds, for the depth of a forbidden model cell: the first
    application caller of its audience; None when its audience has none (no key the API gateway
    admits anywhere)."""
    aud = {str(c.get("id")): c.get("audience") for c in ((model.spec or {}).get("inference") or {}).get("callers") or []}
    return next((c["id"] for c in inf["callers"] if c["kind"] == "application" and aud.get(c["id"]) == population.audience), None)


def depth_on(model: Model) -> bool:
    raw = (model.spec or {}).get("matrix") or {}
    return bool(raw.get("depth"))


def depth(model: Model, v, src: Host, dst: str, port: int, http: dict | None, where: str) -> list:
    """The layers that would refuse a request from src to dst:port if every earlier layer let it
    through (chapter 11's isolation depth), in the order the request meets them: each
    {row, device, why}. A router without a route refuses (and, let through, hands the request to the
    firewall on their shared subnet); the firewall's strict IP check, its own route, its first
    security rule after NAT; then, for an HTTP request (http: {host, path, caller, model}) that
    reaches a Gateway, its route set and the API gateway's consumer restriction for the caller's key.
    A layer that has no route onward ends the count: nothing behind it can be reached to refuse."""
    from .trace import first_nat, first_rule  # noqa: PLC0415

    out: list = []
    s_addr = src.primary
    ss, ds = model.segment_of(s_addr), model.segment_of(dst)
    reached = None
    if ss is not None and ds is not None and ss.id == ds.id:
        reached = dst
    elif model.k8s is not None and getattr(src, "k8s", None) and any(g.vip == dst for g in model.gateways.values()):
        reached = dst
    if reached is None:
        gw, ing = src.gateway, None
        vr = _vpn_router_holding(model, gw)
        if vr is not None:
            t = _tunnel_for(v, vr, s_addr, dst)
            if t is not None:
                ing = t[2]
            else:
                gw = vr.gateway
        if ing is None and v is not None and _fw_own(v, gw) is not None:
            ing = _fw_own(v, gw)
        elif ing is None:
            rtr = _router_holding(model, gw)
            if rtr is None:
                _err(where, f"{src.name}'s gateway {gw} is neither the firewall's nor a router's")
            r, _text = _router_route(model, rtr, dst)
            if r is False:
                out.append({"row": "routing", "device": rtr.name, "why": f"no route to {dst}"})
                ing = _gw_iface_toward(v, rtr) if v is not None else None
                if ing is None:
                    return out
            elif r is None:
                ing = _fw_own(v, dst) if v is not None else None
                if ing is None:
                    reached = dst
            else:
                ing = _fw_own(v, r.via) if v is not None else None
                if ing is None:
                    _err(where, f"{rtr.name} routes {dst} via {r.via}, which is not the firewall")
    if reached is None:
        sip = _strict_ip_drop(v, ing, s_addr)
        if sip is not None:
            out.append({"row": "routing", "device": model.firewall.name,
                        "why": f"strict IP check ({sip['profile']}): {s_addr} is routed {sip['route']}, not over {ing.name}"})
        own = _fw_own(v, dst)
        if own is not None:
            pre_zone = own.zone
        else:
            rt = _fw_route(v, dst)
            if rt is None or (rt[0] is None and rt[1] is None):
                out.append({"row": "routing", "device": model.firewall.name, "why": f"no route to {dst}"})
                return out
            pre_zone = rt[1]
        n = first_nat(v, ing.zone, pre_zone, s_addr, dst, port)
        post, post_zone = dst, pre_zone
        if n is not None and n.dnat:
            post = n.dnat
            post_zone = _fw_iface_of(v, post).zone
        r = first_rule(v, ing.zone, post_zone, s_addr, dst, port)
        if r is not None and r.action != "allow":
            out.append({"row": "policy", "device": model.firewall.name, "why": f"{r.name} ({ing.zone} to {post_zone})", "rule": r.name})
        if own is not None and post == dst:
            return out
        reached = post
    if http:
        gw = next((g for g in model.gateways.values() if g.vip == reached), None)
        if gw is None:
            return out
        rs, _rp = _route_match(route_sets(model), gw.name, http["host"], http["path"])
        if rs is None:
            out.append({"row": "routeset", "device": gw.name, "why": f"no HTTPRoute for {http['host']} and {http['path']}"})
        if http.get("model"):
            from . import inference  # noqa: PLC0415

            inf = inference.settings(model)
            m = next((x for x in inf["models"] if x["name"] == http["model"]), None)
            if m is not None and http.get("caller") not in m["callers"]:
                whose = f"{http['caller']}'s key" if http.get("caller") else "no key of the population's audience"
                out.append({"row": "key", "device": inf["gateway"]["name"],
                            "why": f"{whose}: {http['model']}'s route admits {', '.join(m['callers'])}"})
    return out


def matrix(model: Model) -> dict:
    """The matrix with every cell's mode, requests and evidence (gen/matrix.yaml)."""
    from . import inference  # noqa: PLC0415
    from .panos import view  # noqa: PLC0415

    raw = (model.spec or {}).get("matrix")
    if not isinstance(raw, dict) or not raw.get("rows") or not raw.get("columns"):
        _err("spec matrix", "a lab with decisions: true needs the spec's matrix.rows and matrix.columns")
    v = view(model)
    sets = route_sets(model)
    inf = inference.settings(model) if inference.enabled(model) else None
    users = list(model.dns.users) if model.dns is not None else []
    if not users:
        _err("spec matrix", "the lab has no hostname users type")
    timeout = int(raw.get("timeout_s") or 4)
    sport = int(raw.get("sport") or 43000)
    rows, cols, cells = [], [], []
    for i, r in enumerate(raw["rows"]):
        where = f"spec matrix.rows[{i}]"
        pop = model.populations.get(str(r.get("population")))
        if pop is None:
            _err(where, f"{r.get('population')!r} is not a population of this lab")
        c = model.nodes.get(str(r.get("client")))
        if not isinstance(c, Host) or c.kind not in CLIENT_KINDS or not c.primary:
            _err(where, f"{r.get('client')!r} is no client, bastion or VM guest with an address in this lab")
        if not _cidr_ok(pop.prefixes, c.primary):
            _err(where, f"{c.name} ({c.primary}) is not in population {pop.name}'s segments")
        vw = _view_for(model, pop, c, where)
        # a view that publishes no record for the users' hostname (the public server in state one)
        # leaves the population's own answer: the address its tools name directly
        ans = vw.answer_address if users[0] in model.dns.names_of(vw) else (pop.answer_address or vw.answer_address)
        rows.append({"id": pop.name, "label": str(r.get("label") or pop.name), "client": c.name, "kind": c.kind, "address": c.primary,
                     "resolver": pop.resolver, "resolver_address": c.resolver_address or pop.resolver_address, "view": vw.name,
                     "view_decision": label_of(model, "view", vw.name, vw.decision), "answer": ans,
                     "zones": list(pop.zones), "translated": pop.translated})
    seen = set()
    for j, col in enumerate(raw["columns"]):
        where = f"spec matrix.columns[{j}]"
        cid = str(col.get("id") or "")
        if not cid or cid in seen:
            _err(where, "every column has its own id")
        seen.add(cid)
        kinds = [k for k in ("connect", "model", "name") if k in col]
        if len(kinds) != 1:
            _err(where, "names one of connect:, model: or name:")
        k = kinds[0]
        out = {"id": cid, "label": str(col.get("label") or cid), "kind": k}
        if k == "connect":
            a, what = _target(model, col["connect"], where)
            out.update(ref=str(col["connect"]), address=a, what=what, port=int(col.get("port") or 0))
            if not out["port"]:
                _err(where, "a connect column needs port:")
        elif k == "model":
            if inf is None:
                _err(where, "a model column needs serving and the API gateway in the lab")
            m = next((x for x in inf["models"] if x["name"] == str(col["model"])), None)
            if m is None:
                _err(where, f"{col['model']!r} is not a model the lab serves")
            other = next((x["name"] for x in inf["models"] if x["name"] != m["name"]), None)
            if other is None:
                _err(where, "a model column needs another model, whose key it is asked with too")
            out.update(model=m["name"], other=other, hostname=users[0], path=f"{m['path']}/v1/chat/completions", port=443)
        else:
            h = model.org.fqdn(str(col["name"]))
            p = str(col.get("path") or "/")
            out.update(hostname=h, path=p, port=443)
        cols.append(out)
    n = 0
    for r in rows:
        c = model.nodes[r["client"]]
        for col in cols:
            where = f"spec matrix cell {r['id']}/{col['id']}"
            cell = {"id": f"{r['id']}/{col['id']}", "row": r["id"], "column": col["id"], "kind": col["kind"], "client": c.name,
                    "client_kind": c.kind, "client_addr": c.primary, "port": col["port"], "sport": sport + 4 * n}
            n += 1
            if col["kind"] == "connect":
                tried = col["address"]
                if col["ref"].startswith("vip:") and r["answer"] and r["answer"] != col["address"]:
                    via = path(model, v, c, r["answer"], col["port"], where)
                    if via["outcome"] == "reached" and via["at"] == col["address"]:
                        tried = r["answer"]
                        cell["note"] = f"tried at the population's answer, {tried}, which the firewall translates to {col['address']}"
                p = path(model, v, c, tried, col["port"], where)
                cell.update(address=tried, hops=p["hops"])
                if p["outcome"] == "reached":
                    cell.update(mode="allowed", layer=None, expect={"connect": "connected"})
                elif p["outcome"] == "log-line":
                    cell.update(mode="log-line", layer="policy", expect={"connect": "refused", "rule": p["rule"], "action": p["action"],
                                                                        "from_zone": p["from_zone"], "to_zone": p["to_zone"],
                                                                        "device": p["device"]})
                else:
                    cell.update(mode="silence", layer="routing", expect={"connect": "refused", "device": p["device"],
                                                                        **{k: p[k] for k in SILENCE_KEYS if k in p}})
                if p.get("from_zone") and p.get("rule"):
                    cell["fw"] = {"rule": p["rule"], "from_zone": p["from_zone"], "to_zone": p["to_zone"]}
                cell["requests"] = [{"id": "connect", "sport": cell["sport"]}]
            else:
                host, upath = col["hostname"], col["path"]
                ans = r["answer"]
                held = host in model.dns.names_of(next(x for x in model.dns.views if x.name == r["view"]))
                if held:
                    cell.update(hostname=host, address=ans, lookup={"name": host, "resolver": r["resolver"], "server": r["resolver_address"],
                                                                   "view": r["view"], "answer": ans})
                    what = f"view {r['view']}: {host} A {ans}"
                else:
                    # the view holds no record for the name (the enterprise view names no admin host):
                    # the lookup is answered NXDOMAIN, and the request is pinned to the address the view
                    # gives the users' hostname, so the cell still reads the layers behind it
                    cell.update(hostname=host, address=ans, pin=True,
                                lookup={"name": host, "resolver": r["resolver"], "server": r["resolver_address"],
                                        "view": r["view"], "answer": None, "expect": "nxdomain"},
                                note=f"view {r['view']} holds no record for {host}: the request is pinned to {ans}, the population's answer for the users' hostname")
                    what = f"view {r['view']}: no record for {host} (NXDOMAIN); the request pinned to {ans}"
                p = path(model, v, c, ans, 443, where)
                cell["hops"] = [{"row": "view", "device": r["resolver"], "what": what}] + p["hops"]
                if p["outcome"] != "reached":
                    md = "log-line" if p["outcome"] == "log-line" else "silence"
                    cell.update(mode=md, layer="policy" if md == "log-line" else "routing",
                                expect={"connect": "refused", **{k: p[k] for k in ("rule", "action", "from_zone", "to_zone", "device") + SILENCE_KEYS
                                                                     if k in p}})
                    cell["requests"] = [{"id": "connect", "sport": cell["sport"]}]
                else:
                    if p.get("from_zone") and p.get("rule"):
                        cell["fw"] = {"rule": p["rule"], "from_zone": p["from_zone"], "to_zone": p["to_zone"]}
                    gw = next((g for g in model.gateways.values() if g.vip == p["at"]), None)
                    if gw is None:
                        _err(where, f"{host} reaches {p['at']}, which is no Gateway's VIP")
                    rs, rp = _route_match(sets, gw.name, host, upath)
                    marker = f"sfab-matrix-{_slug(r['id'])}-{_slug(col['id'])}"
                    if rs is None:
                        cell["hops"].append({"row": "routeset", "device": gw.name, "what": f"no HTTPRoute for {host} and {upath}: 404"})
                        cell.update(mode="404", layer="routeset", gateway=gw.name,
                                    expect={"status": 404, "gateway": gw.name, "api_gateway_line": False})
                        cell["requests"] = [{"id": "request", "sport": cell["sport"], "method": "GET", "url": f"https://{host}{upath}?msg={marker}",
                                             "marker": marker, "expect": {"status": 404}}]
                    else:
                        cell["hops"].append({"row": "routeset", "device": gw.name, "what": f"HTTPRoute {rs['name']}, {rp}: {rs['to']}",
                                             "route": rs["name"]})
                        cell.update(gateway=gw.name, route=rs["name"])
                        if col["kind"] == "model":
                            mine, default = own_caller(model, inf, model.populations[r["id"]], col["model"])
                            whose = f"its own key ({mine}'s)" if mine != default else "its own key"
                            cell["hops"].append({"row": "key", "device": inf["gateway"]["name"],
                                                 "what": f"{col['model']}'s consumer group: {whose} 200, {col['other']}'s key {inf['rejected']['code']}"})
                            cell.update(mode="allowed", layer=None, expect={"status": 200})
                            body = {"model": col["model"], "max_tokens": 1, "messages": [{"role": "user", "content": "Say yes."}]}
                            own = {"id": "own", "sport": cell["sport"], "method": "POST", "url": f"https://{host}{upath}", "key": col["model"],
                                   "body": body, "expect": {"status": 200}}
                            if mine != default:
                                # the population's own caller (the internet users' inetapp), not the model's first
                                own["key_caller"] = mine
                            cell["requests"] = [
                                own,
                                {"id": "other", "sport": cell["sport"] + 2, "method": "POST", "url": f"https://{host}{upath}", "key": col["other"],
                                 "body": body, "expect": {"status": int(inf["rejected"]["code"]), "message": inf["rejected"]["message"],
                                                          "layer": "key"}},
                            ]
                        else:
                            cell.update(mode="allowed", layer=None, expect={"status": 200})
                            cell["requests"] = [{"id": "request", "sport": cell["sport"], "method": "GET",
                                                 "url": f"https://{host}{upath}?msg={marker}", "marker": marker, "expect": {"status": 200}}]
            if depth_on(model) and cell["mode"] != "allowed":
                http = None
                if col["kind"] != "connect":
                    caller = held_caller(model, inf, model.populations[r["id"]]) if col["kind"] == "model" else None
                    http = {"host": col["hostname"], "path": col["path"], "model": col.get("model"), "caller": caller}
                layers = depth(model, v, c, cell["address"], col["port"], http, where)
                cell["depth"] = len(layers)
                cell["depth_layers"] = layers
            elif depth_on(model):
                cell["depth"], cell["depth_layers"] = 0, []
            cells.append(cell)
    counts = {"cells": len(cells), "allowed": sum(1 for x in cells if x["mode"] == "allowed")}
    counts["forbidden"] = counts["cells"] - counts["allowed"]
    for md in MODES[1:]:
        counts[md] = sum(1 for x in cells if x["mode"] == md)
    counts["401"] = sum(1 for x in cells for q in x.get("requests") or [] if (q.get("expect") or {}).get("layer") == "key")
    if depth_on(model):
        counts["depth"] = {str(d): sum(1 for x in cells if x["mode"] != "allowed" and x["depth"] == d)
                           for d in sorted({x["depth"] for x in cells if x["mode"] != "allowed"})}
    if sport + 4 * n >= 65536:
        _err("spec matrix.sport", "the cells' source ports run past 65535")
    from . import k8s as K  # noqa: PLC0415

    ag = None
    if inf is not None:
        ag = {"namespace": inf["namespace"], "selector": inf["probe"]["selector"], "deployment": inf["gateway"]["name"],
              "secret": inf["keys"]["models"]["secret"], "rejected": inf["rejected"]}
    fw = model.firewall
    routers = sorted({h["device"] for x in cells for h in x["hops"] if h.get("row") == "routing" and h["device"] in model.hosts
                      and model.hosts[h["device"]].kind == "frr"})
    return {"schema": SCHEMA, "lab": model.lab, "rows": rows, "columns": cols, "cells": cells, "counts": counts,
            "silence": {"cells": [x["id"] for x in cells if x["mode"] == "silence"],
                        "evidence": "a capture at the hop, beside the route table or drop counter of the device without the route",
                        "strict_ip": [x["id"] for x in cells if (x.get("expect") or {}).get("drop") == "strict-ip"]},
            "timeout_s": timeout, "retries": 1, "firewall": fw.name if fw is not None else None, "routers": routers,
            "api_gateway": ag, "ca_root": "/shared/ca/root.crt",
            "labels": {"decision": _dlabel(model), "audience": model.k8s.labels.get("audience") if model.k8s else None},
            "gateway_namespace": K.gateway_namespace(model) if model.k8s is not None else None}


# --------------------------------------------------------------------------------------------
# label.sh's plan: one read per row, of the live object behind it


def label_plan(model: Model, t: dict, mx: dict) -> dict:
    """What label.sh reads for each row (gen/decisions.json holds it beside the table)."""
    from . import inference  # noqa: PLC0415
    from . import k8s as K  # noqa: PLC0415

    plan = {}
    # a view that publishes no record for the users' hostname (the public server in state one) is
    # read as an NXDOMAIN answer, and its zone file as labelled in its header with no entry for the name
    users = model.dns.users[0]
    holds = {vw.name: users in model.dns.names_of(vw) for vw in model.dns.views}
    plan["view"] = {"lookups": [{"population": r["id"], "client": r["client"], "kind": r["kind"], "name": users,
                                 "server": r["resolver_address"], "view": r["view"],
                                 "answer": r["answer"] if holds.get(r["view"], True) else None, "decision": r["view_decision"]}
                                for r in mx["rows"]],
                    "zones": [{"server": o["device"], "view": o["name"], "file": f"db.{o['name']}.{model.dns.zone}",
                               "name": users, "decision": o["decision"], "holds": holds.get(o["name"], True)}
                              for o in t["rows"][0]["objects"] if o["server_kind"] in ("bind-views", "bind-auth")]}
    fw = model.firewall
    plan["routing"] = {"firewall": fw.name if fw else None,
                       "routers": [{"node": h.name, "conf": "/sfab/bootstrap/frr.conf"} for h in model.hosts.values() if h.kind == "frr"]}
    plan["nat"] = {"firewall": fw.name if fw else None, "rules": [o["name"] for o in t["rows"][2]["objects"]],
                   "decisions": {o["name"]: o["decision"] for o in t["rows"][2]["objects"]}}
    plan["policy"] = {"firewall": fw.name if fw else None, "rules": [o["name"] for o in t["rows"][3]["objects"]],
                      "decisions": {o["name"]: o["decision"] for o in t["rows"][3]["objects"]}}
    plan["routeset"] = {"routes": [{"name": o["name"], "namespace": o["namespace"], "gateway": o["gateway"], "decision": o["decision"]}
                                   for o in t["rows"][4]["objects"]], "label": _dlabel(model),
                        "audience_label": model.k8s.labels.get("audience") if model.k8s else None}
    if inference.enabled(model):
        inf = inference.settings(model)
        plan["key"] = {"namespace": inf["namespace"], "configmap": inf["configmaps"]["routes"], "file": "apisix.yaml",
                       "selector": inf["probe"]["selector"], "groups": {o["name"]: o["decision"] for o in t["rows"][5]["objects"]}}
        sv = K.serving_summary(model)
        plan["placement"] = {"namespace": sv["namespace"], "label": _dlabel(model), "table": "bootstrap/k8s/serving.env",
                             "copies": {o["name"]: o["decision"] for o in t["rows"][6]["objects"]}, "nads": nad_decisions(model)}
    plan["forwarding"] = {"decision": t["forwarding"]["decision"], "switches": [s["name"] for s in t["forwarding"]["switches"]]}
    return plan


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True) + "\n"


def _yaml(head: list, obj) -> str:
    from .k8s import dump  # noqa: PLC0415

    return "".join(f"# {h}\n" for h in head) + dump(obj)


def render(model: Model, ctx) -> dict:
    if not on(model):
        return {}
    t = table(model)
    mx = matrix(model)
    plan = label_plan(model, t, mx)
    src = ctx.profile_file(model)
    th = [f"{model.lab} decisions: rendered from {src} by render/decisions.py; edit the spec and run make render",
          "The decision table (Table 2-1): one row per layer, in the order a request meets them, each with the objects of",
          "this lab that implement it and the decision id each carries. label.sh reads gen/decisions.json, the same data",
          "with its plan of reads, and prints the live object behind every row."]
    mh = [f"{model.lab} matrix: rendered from {src} by render/decisions.py; edit the spec and run make render",
          "The population and endpoint matrix (Table 2-2): every cell's mode as the request meets the layers, with the",
          "requests matrix.sh makes and the evidence each mode leaves. matrix.sh reads gen/matrix.json, the same data."]
    return {YAML_PATH: _yaml(th, t), JSON_PATH: dumps(dict(t, plan=plan)), MATRIX_YAML: _yaml(mh, mx), MATRIX_JSON: dumps(mx)}


__all__ = ["render", "on", "label_of", "forwarding_line", "consumer_desc", "nad_decisions", "table", "matrix", "path", "route_sets"]
