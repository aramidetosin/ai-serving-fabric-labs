"""gen/expect/<sw>.json: what each switch must show once it has taken its startup file
(FRAMEWORK.md 2.2), and gen/klish-normalize.json, the parity table in a form the lab host reads
without PyYAML.

The audit judges, boot parity and wait_fabric read these files. Build A switches hold VLANs,
PortChannels with their members, access ports and an MCLAG domain, and no address on any VLAN,
PortChannel or data port and no route; build B adds BGP, EVPN and Ethernet segments here.

The fields follow the KLISH show commands that read them:
- `show vlan`: vlans.<id>.tagged and .untagged (T and A in the member column);
- `show PortChannel summary`: portchannels.<name>, up, with every member selected (P);
- `show mclag brief`: mclag (session up, peer link up, the two roles across the pair);
- `show ip interfaces` and `show ip route`: addresses (Management0 in VRF mgmt and, on an MCLAG
  member, the two keepalive addresses in the keepalive VRF) and routes (nothing in the default
  table; the keepalive VRF holds its two connected /31s).
"""

from __future__ import annotations

import json

from ..model import Host, Model, Switch

try:  # the relay macvlan MAC is fixed by the host renderer; one formula, kept there
    from .host import relay_mac as _relay_mac
except ImportError:  # pragma: no cover
    _relay_mac = None

SCHEMA = 1

# Management0 inside a vrnetlab VM without passthrough: the QEMU user network.
SLIRP_MGMT = {"address": "10.0.0.15/24", "gateway": "10.0.0.2"}


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _mgmt(model: Model, sw: Switch) -> dict:
    if sw.passthrough:
        return {"interface": "Management0", "address": f"{sw.mgmt}/{model.mgmt.prefixlen}", "gateway": model.mgmt.gw,
                "vrf": sw.mgmt_vrf, "source": "passthrough"}
    return {"interface": "Management0", "address": SLIRP_MGMT["address"], "gateway": SLIRP_MGMT["gateway"],
            "vrf": sw.mgmt_vrf, "source": "slirp"}


def expect(model: Model, sw: Switch) -> dict:
    factory = int((model.common.get("switch") or {}).get("factory_mtu", 9100))
    vl: dict = {str(v): {"tagged": [], "untagged": []} for v in sw.vlans}
    pcs = {}
    for pc in sw.portchannels:
        for v in pc.vlans:
            vl.setdefault(str(v), {"tagged": [], "untagged": []})["tagged" if pc.mode == "trunk" else "untagged"].append(pc.name)
        pcs[pc.name] = {
            "id": pc.id,
            "desc": pc.desc,
            "kind": pc.kind,
            "mode": pc.mode,
            "vlans": list(pc.vlans),
            "mclag": pc.mclag,
            "fast_rate": pc.fast_rate,
            "mtu": pc.mtu or factory,
            "peer_node": pc.peer_node,
            "members": [mb.native for mb in pc.members],
            "member_peers": {mb.native: str(mb.peer) for mb in pc.members},
            "status": "up",
            "members_selected": True,
        }
    access = {}
    for ap in sw.access_ports:
        vl.setdefault(str(ap.vlan), {"tagged": [], "untagged": []})["untagged"].append(ap.native)
        access[ap.native] = {"eth": ap.ifname, "vlan": ap.vlan, "kind": ap.kind, "desc": ap.desc, "peer": str(ap.peer),
                             "rail": ap.rail}
    for v in vl.values():
        v["tagged"].sort()
        v["untagged"].sort()
    pc_of = {mb.native: pc.name for pc in sw.portchannels for mb in pc.members}
    port_mtu = {mb.native: (pc.mtu or factory) for pc in sw.portchannels for mb in pc.members}
    ports_ = {}
    for n in sw.nics:
        ports_[n.native] = {"eth": n.eth, "role": n.role, "peer": str(n.peer), "desc": n.desc, "admin": "up",
                            "mtu": port_mtu.get(n.native, factory), "portchannel": pc_of.get(n.native)}
    mclag = None
    if sw.mclag is not None:
        d = sw.mclag
        mclag = {
            "domain": d.domain,
            "source_ip": d.source_ip,
            "peer_ip": d.peer_ip,
            "peer": d.peer,
            "peer_link": d.peer_link,
            "system_mac": d.system_mac,
            "session_vrf": d.session_vrf,
            "backup": None if not d.backup_source_ip else {"source_ip": d.backup_source_ip, "peer_ip": d.backup_peer_ip,
                                                           "vrf": d.backup_vrf, "interval": d.backup_interval, "session": "up"},
            "session": "up",
            "peer_link_status": "up",
            "pair_roles": ["active", "standby"],
            "interfaces": [pc.name for pc in sw.portchannels if pc.mclag],
        }
    known_macs = _known_macs(model, sw)
    return {
        "schema": SCHEMA,
        "lab": model.lab,
        "switch": sw.name,
        "container": sw.container,
        "role": sw.role,
        "mgmt": sw.mgmt,
        "mgmt_vrf": sw.mgmt_vrf,
        "passthrough": sw.passthrough,
        "num_nics": sw.num_nics,
        "vm_data_nics": [f"eth{i}" for i in range(1, sw.num_nics + 1)],
        "used_ports": [n.native for n in sw.nics],
        "vlans": dict(sorted(vl.items(), key=lambda kv: int(kv[0]))),
        "portchannels": pcs,
        "access": access,
        "ports": ports_,
        "mclag": mclag,
        "addresses": {"ip_interfaces": [_mgmt(model, sw)] + _ka_ifaces(sw), "data": []},
        "routes": {"default": [], **({sw.keepalive.vrf: _ka_routes(sw)} if sw.keepalive else {})},
        "keepalive": None if sw.keepalive is None else {
            "vrf": sw.keepalive.vrf, "port": sw.keepalive.native, "address": sw.keepalive.address,
            "peer_address": sw.keepalive.peer_address, "backup_interface": f"Vlan{sw.keepalive.backup_vlan}" if sw.keepalive.backup_vlan else None,
            "backup_address": sw.keepalive.backup_address, "backup_peer": sw.keepalive.backup_peer},
        "router": False,
        "known_macs": known_macs,
        "bgp": None,
        "evpn": None,
        "es": None,
    }


def _ka_ifaces(sw: Switch) -> list:
    """The pair's only addresses: the keepalive link and the backup keepalive's VLAN interface, both
    in the keepalive VRF (build A revision 2: Chapter 2's forwarding-only pair owns exactly these)."""
    ka = sw.keepalive
    if ka is None:
        return []
    out = [{"interface": ka.native, "address": ka.address, "vrf": ka.vrf, "source": "keepalive"}]
    if ka.backup_vlan is not None:
        out.append({"interface": f"Vlan{ka.backup_vlan}", "address": ka.backup_address, "vrf": ka.vrf, "source": "backup-keepalive"})
    return out


def _ka_routes(sw: Switch) -> list:
    """The keepalive VRF's table: the connected /31s and nothing else."""
    import ipaddress  # noqa: PLC0415

    return [str(ipaddress.ip_interface(x["address"]).network) for x in _ka_ifaces(sw)]


def _known_macs(model: Model, sw: Switch) -> dict:
    """The host MACs this switch may learn, where the render fixes them (VM guests only): a
    bond takes its first member's guest MAC; an out-of-band or rail NIC has its guest MAC; a
    rail port also carries the relay namespace's macvlan when the node runs the relay (render/
    host.py fixes that MAC). Containers and appliances keep MACs the render does not fix, so
    they are not listed; a MAC table entry that is none of these and no appliance's is suspect
    (the vrnetlab containers' own veth MACs, for one)."""
    out = {}
    for pc in sw.portchannels:
        host = model.nodes.get(pc.peer_node) if pc.peer_node else None
        bond = getattr(host, "bond", None)
        if bond is not None and bond.mac:
            out[bond.mac] = {"node": host.name, "vlan": bond.vlan, "via": pc.name, "source": "bond"}
    prefix = (model.common.get("guest") or {}).get("mac_prefix")
    for ap in sw.access_ports:
        host = model.nodes.get(ap.peer.node)
        if not isinstance(host, Host) or host.kind != "vm-node":
            continue
        nic = host.nic(ap.peer.eth)
        if nic is None or not nic.mac:
            continue
        out[nic.mac] = {"node": host.name, "vlan": ap.vlan, "via": ap.native, "source": "nic"}
        if ap.kind == "rail" and host.relay is not None and _relay_mac is not None and prefix:
            out[_relay_mac(prefix, host.mgmt_octet, nic.index)] = {"node": host.name, "vlan": ap.vlan, "via": ap.native,
                                                                   "source": "relay-macvlan"}
    out.update(_pod_macs(model, sw))
    return out


def _pod_macs(model: Model, sw: Switch) -> dict:
    """With serving on, each placement row's rail MAC (render/k8s.py pod_mac, set through the
    pod's networks annotation), on the port facing the row's node on the row's rail."""
    from .k8s import placement, serving_enabled  # noqa: PLC0415

    if not serving_enabled(model):
        return {}
    out = {}
    for row in placement(model):
        host = model.nodes.get(row["node"])
        ri = next((x for x in getattr(host, "rails", ()) if x.rail == row["rail"]), None)
        if ri is None or ri.switch != sw.name:
            continue
        out[row["mac"]] = {"node": row["node"], "pod": row["pod"], "vlan": ri.vlan, "via": ri.switch_native, "source": "pod-macvlan"}
    return out


def normalize_table(model: Model) -> dict:
    rows = list((model.meta.normalize or {}).get("normalize") or [])
    return {"schema": SCHEMA, "source": "spec/klish-normalize.yaml", "normalize": rows}


def render(model: Model, ctx) -> dict:
    out = {f"gen/expect/{name}.json": dumps(expect(model, sw)) for name, sw in model.switches.items()}
    if model.switches:
        out["gen/klish-normalize.json"] = dumps(normalize_table(model))
    return out
