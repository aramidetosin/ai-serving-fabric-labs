"""Part III's stand-in world facts, for common/tests/test_part3_labs.py and the shims in
common/tests/shims-part3/.

facts(labdir) renders nothing: it reads the lab's model (sfab.spec, PyYAML) once and writes down, as
plain JSON, what the stand-ins need to answer the Part III harness without the model: every
client's address and first capture point, each connect's outcome as render/decisions.py's path
computes it (the firewall's zones, rule, translation, or the device that drops it), the bundle's
legs and the pair's ports facing the ingress nodes, the firewall's rulebases with the fields the
running policy prints, and each router's routes. The stand-ins model the lab from these facts; the
figures they print are the model's, never a lab's.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "common"))


def _bare(a):
    return str(a).split("/")[0] if a else None


def facts(labdir: Path) -> dict:
    from sfab.render import decisions  # noqa: PLC0415
    from sfab.render.inventory import inventory  # noqa: PLC0415
    from sfab.render.panos import view  # noqa: PLC0415
    from sfab.render.trace import _p3_entry  # noqa: PLC0415
    from sfab.spec import load, load_chapter, select  # noqa: PLC0415
    from sfab.model import Host  # noqa: PLC0415

    spec = load(ROOT)
    m = select(spec, load_chapter(labdir))
    inv = inventory(m)
    v = view(m)
    nodes = inv["nodes"]
    clients = {}
    for n, x in m.nodes.items():
        if isinstance(x, Host) and (x.kind == "client" or n in ("k8s-cp2",)) and x.primary:
            e = _p3_entry(m, x)
            clients[n] = {"addr": x.primary, "kind": x.kind, "entry": [e["node"], e["eth"]] if e else None}
    addrs = {g.vip for g in m.gateways.values()} | {p.answer_address for p in m.populations.values() if p.answer_address}
    if decisions.on(m):
        mx = decisions.matrix(m)
        addrs |= {c["address"] for c in mx["cells"] if c.get("address")}
        ports = {(c["address"], int(c["port"])) for c in mx["cells"] if c.get("address")}
    else:
        ports = set()
    ports |= {(a, 443) for a in addrs}
    connects = {}
    for c in clients:
        h = m.nodes[c]
        for a, p in sorted(ports):
            try:
                r = decisions.path(m, v, h, a, p, "facts")
            except Exception:  # noqa: BLE001 - a pair the render refuses is no fact
                continue
            local = any(x.get("row") is None and x.get("device") == c for x in r["hops"])
            connects[f"{c}|{a}|{p}"] = {k: r.get(k) for k in ("outcome", "device", "at", "rule", "action", "from_zone", "to_zone", "nat_rule",
                                                              "drop")} | {"local": local}
    fw = m.firewall
    legs = []
    eg = next((i for i in fw.interfaces if i.kind == "subinterface" and i.tag == 110), None)
    bundle = fw.interface(eg.parent) if eg else None
    for k, mm in enumerate(bundle.members if bundle else (), 1):
        mi = fw.interface(mm)
        far = m.peer(fw.name, mi.eth)
        legs.append({"leg": k, "eth": mi.eth, "switch": far.node, "switch_eth": far.eth})
    pair_ports, ingress = {}, {}
    for h in m.by_group("ingress"):
        ingress[h.name] = {"mac": h.bond.mac if h.bond else None}
        for n in h.nics:
            if n.role == "bond-member" and n.peer is not None:
                pair_ports.setdefault(h.name, {})[n.peer.node] = n.peer.eth
    rules = [{"name": r.name, "from": list(r.from_zones), "to": list(r.to_zones), "src": list(r.src_cidrs), "dst": list(r.dst_cidrs),
              "apps": list(r.applications), "services": list(r.services), "action": r.action} for r in v.rules]
    nat = [{"name": n.name, "from": list(n.from_zones), "to": list(n.to_zones), "dst": list(n.dst_cidrs), "service": n.service,
            "dnat": n.dnat, "snat": n.snat_interface} for n in v.nat]
    routers = {}
    for n, x in m.nodes.items():
        if isinstance(x, Host) and x.kind == "frr":
            rs = [{"dest": str(_cidr(i.address)), "via": None, "type": "C"} for i in x.ifaces if i.address]
            rs += [{"dest": str(r.dest), "via": str(r.via), "type": "S"} for r in x.routes]
            routers[n] = rs
    res_ifaces = {}
    for n, x in m.nodes.items():
        if isinstance(x, Host) and x.dns_role:
            res_ifaces[n] = "bond0" if x.bond is not None else next((i.eth for i in x.ifaces if i.address), "eth1")
    vips = {g.vip: g.name for g in m.gateways.values()}
    from sfab.render import k8s  # noqa: PLC0415

    leases = {g.name: k8s.l2_lease(m, g) for g in m.gateways.values()}
    pub = next((p for p in m.populations.values() if p.translated), None)
    return {"lab": m.lab, "fw": fw.name, "clients": clients, "connects": connects, "legs": legs, "pair_ports": pair_ports,
            "ingress": ingress, "rules": rules, "nat": nat, "routers": routers, "resolver_ifaces": res_ifaces, "vips": vips,
            "leases": leases, "published": {"address": pub.answer_address} if pub else None,
            "audience_label": (inv.get("k8s") or {}).get("labels", {}).get("audience"),
            "l2_interfaces": ((inv.get("k8s") or {}).get("l2_announce") or {}).get("interfaces") or [],
            "nodes_kind": {n: x["kind"] for n, x in nodes.items()}}


def _cidr(a):
    import ipaddress  # noqa: PLC0415

    return ipaddress.ip_interface(a).network


def write(labdir: Path, out: Path) -> Path:
    out.write_text(json.dumps(facts(labdir), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return out
