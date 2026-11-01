"""gen/inventory.json (what every stage script reads, through common/bin/inv.py) and
gen/RENDER.json (the sha256 of every output, the spec files and the versions behind them).

Both are byte-stable: sorted keys, two-space indent, a trailing newline, no timestamps.

Beside the nodes, links, stages and budgets, the inventory carries the services above the network
that finish, the audit and the trace read (services()): gateways, populations, dns, k8s, registry,
ca and ntp, each null when the lab has none (k8s with the cluster off, registry without the
registry node), and nodes.<storage>.csi for a storage node with CSI settings. stages.modules is host.modules plus the modules each node
kind in the lab needs (common.yaml kinds.<kind>.modules: vrf for the FRR routers).
"""

from __future__ import annotations

import json
import re

from ..model import Firewall, Host, Model, Storage, Switch

SCHEMA = 1


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def natural(name: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"([0-9]+)", name)]


def _nic(n) -> dict:
    d = {"peer": str(n.peer), "role": n.role, "link": n.link}
    for k in ("native", "ifname", "desc", "mac", "mtu", "vlan", "rail", "address", "gateway"):
        v = getattr(n, k)
        if v is not None:
            d[k] = v
    if n.vlans:
        d["vlans"] = list(n.vlans)
    return d


def _node(m: Model, n) -> dict:
    d = {
        "container": n.container,
        "kind": n.kind,
        "clab_kind": n.clab_kind,
        "section": n.section,
        "role": n.role,
        "group": n.group,
        "mgmt": n.mgmt,
        "image": n.image,
        "budget": {"mem_gib": n.budget.mem_gib, "vcpus": n.budget.vcpus, "state_gib": n.budget.state_gib,
                   "layer_gib": n.budget.layer_gib},
        "eths": list(n.eths),
        "nics": {x.eth: _nic(x) for x in n.nics},
        "requires": list(n.requires),
    }
    if n.pending:
        d["pending"] = n.pending
    if isinstance(n, Switch):
        d.update({
            "num_nics": n.num_nics,
            "pair": n.pair,
            "partner": n.partner,
            "passthrough": n.passthrough,
            "sflow": n.sflow,
            "vlans": list(n.vlans),
            "rails": list(n.rails),
            "portchannels": {
                p.name: {"id": p.id, "kind": p.kind, "mode": p.mode, "vlans": list(p.vlans), "mclag": p.mclag,
                         "mtu": p.mtu, "peer_node": p.peer_node, "members": [mb.native for mb in p.members],
                         "member_eths": [mb.ifname for mb in p.members], "tagged": list(p.tagged), "edge": p.edge}
                for p in n.portchannels
            },
            "access": {a.native: {"eth": a.ifname, "vlan": a.vlan, "kind": a.kind, "peer": str(a.peer), "mtu": a.mtu, "edge": a.edge}
                       for a in n.access_ports},
            "mclag": None if n.mclag is None else {
                "domain": n.mclag.domain, "source_ip": n.mclag.source_ip, "peer_ip": n.mclag.peer_ip, "peer": n.mclag.peer,
                "peer_link": n.mclag.peer_link, "system_mac": n.mclag.system_mac, "session_vrf": n.mclag.session_vrf,
                "backup": None if not n.mclag.backup_source_ip else {
                    "source_ip": n.mclag.backup_source_ip, "peer_ip": n.mclag.backup_peer_ip, "vrf": n.mclag.backup_vrf,
                    "interval": n.mclag.backup_interval},
            },
            "keepalive": None if n.keepalive is None else {
                "vrf": n.keepalive.vrf, "port": n.keepalive.native, "eth": n.keepalive.ifname, "address": n.keepalive.address,
                "peer_address": n.keepalive.peer_address, "mtu": n.keepalive.mtu,
                "backup_vlan": n.keepalive.backup_vlan, "backup_interface": f"Vlan{n.keepalive.backup_vlan}" if n.keepalive.backup_vlan else None,
                "backup_address": n.keepalive.backup_address, "backup_peer": n.keepalive.backup_peer},
            "stp": n.stp,
            "edge": sorted([p.name for p in n.portchannels if p.edge] + [a.native for a in n.access_ports if a.edge],
                           key=lambda x: (x[0], int(re.sub(r"\D", "", x) or 0))),
            "storm": {"kbps": dict(next((p.storm for p in n.portchannels if p.storm), ())
                                   or next((a.storm for a in n.access_ports if a.storm), ())),
                      "ports": sorted([mb.native for p in n.portchannels if p.storm for mb in p.members]
                                      + [a.native for a in n.access_ports if a.storm], key=lambda x: int(re.sub(r"\D", "", x) or 0))},
        })
    elif isinstance(n, Host):
        d.update({
            "address": n.address,
            "gateway": n.gateway,
            "vlan": n.vlan,
            "k8s": n.k8s,
            "resolver": n.resolver,
            "resolver_address": n.resolver_address,
            "resolvers": list(n.resolvers),
            "dns_role": n.dns_role,
            "bond": None if n.bond is None else {
                "name": n.bond.name, "members": list(n.bond.members), "pc": n.bond.pc, "vlan": n.bond.vlan,
                "address": n.bond.address, "gateway": n.bond.gateway, "mtu": n.bond.mtu, "mac": n.bond.mac,
                "vlan_ifs": [{"name": x.name, "vlan": x.vlan, "segment": x.segment, "address": x.address, "mtu": x.mtu,
                              "table": x.table} for x in n.bond.vlan_ifs],
            },
            "oob": None if n.oob is None else {"eth": n.oob.eth, "address": n.oob.address, "gateway": n.oob.gateway, "table": n.oob.table,
                                               "netns": n.oob.netns, "services": list(n.oob.services)},
            "rails": {str(r.rail): {"eth": r.eth, "ifname": r.ifname, "address": r.address, "switch": r.switch,
                                    "switch_eth": r.switch_eth, "switch_native": r.switch_native} for r in n.rails},
            "relay": None if n.relay is None else {
                "bridge": n.relay.bridge, "prefix": n.relay.prefix, "rp_filter": n.relay.rp_filter,
                "namespaces": [x.ns for x in n.relay.namespaces],
            },
            "ifaces": {i.eth: {"address": i.address, "gateway": i.gateway, "peer": str(i.peer) if i.peer else None} for i in n.ifaces},
        })
        if n.kind == "vm-node":
            d["guest_user"] = (m.common.get("guest") or {}).get("user", "admin")
            d["disk_gib"] = n.disk_gib
        if n.kind == "frr" and n.routes:
            # the routes the router's frr.conf carries (those to inside prefixes are left out where the
            # firewall does not gateway the segment in this lab, render/frr.py)
            from .frr import kept_routes  # noqa: PLC0415

            keep, _ = kept_routes(m, n)
            d["routes"] = [{k: v for k, v in (("id", r.id), ("dest", r.dest), ("via", r.via), ("dev", r.dev),
                                              ("decision", r.decision)) if v is not None} for r in keep]
    elif isinstance(n, Firewall):
        d.update({
            "public": n.public,
            "public_iface": n.public_iface,
            "interfaces": {i.name: {"kind": i.kind, "eth": i.eth, "address": i.address, "zone": i.zone, "connected": i.connected}
                           for i in n.interfaces},
        })
        d.update(_firewall_extra(m))
    elif isinstance(n, Storage):
        d.update({
            "product": n.product,
            "data": None if n.data is None else {"address": n.data.address, "nics": list(n.data.nics), "vlan": n.data.vlan},
            "mgmt_if": None if n.mgmt_if is None else {"address": n.mgmt_if.address, "nics": list(n.mgmt_if.nics), "vlan": n.mgmt_if.vlan},
        })
    return d


def _firewall_extra(m: Model) -> dict:
    """What the chapter 4 harness reads of the firewall as this lab renders it (render/panos.py's
    view): the security and NAT rule names in order, the system services with their service
    routes, and the administrative profile with its interface."""
    from .panos import view  # noqa: PLC0415

    from .. import addr  # noqa: PLC0415
    from .drills import _admitting_rule, _zone_of  # noqa: PLC0415

    v = view(m)
    if v is None:
        return {}
    ports = {"dns": 53, "ntp": 123}

    def fw_pub(v_):
        return f"{v_.fw.public}/32" if v_.fw.public else None

    def admits(s):
        srv = (list(v.dns) if s.service == "dns" else list(v.ntp) if s.service == "ntp" else [None])[0]
        if srv is None or s.service not in ports:
            return None
        src = addr.ip(s.address).compressed
        return _admitting_rule(v, _zone_of(v, src), _zone_of(v, srv), srv, ports[s.service], "udp")

    return {
        "rules": [r.name for r in v.rules],
        "nat": [n.name for n in v.nat],
        "system": {"dns": list(v.dns), "ntp": list(v.ntp),
                   "service_routes": {s.service: {"interface": s.interface, "address": s.address, "rule": admits(s)}
                                      for s in v.service_routes}},
        "admin": None if v.admin is None else {"interface": v.admin.interface, "profile": v.admin.profile,
                                               "allow": list(v.admin.allow), "permitted": list(v.admin.permitted_cidrs)},
        # the destination NATs on the public address: what the firewall publishes on the uplink
        "published": [{"name": n.name, "service": n.service, "to": n.dnat} for n in v.nat if n.dnat and fw_pub(v) in n.dst_cidrs],
        "vpns": [{"name": x.name, "peer": x.peer, "peer_node": x.peer_node, "tunnel_interface": x.tunnel_interface, "zone": x.zone,
                  "proxy_ids": [list(p) for p in x.proxy_ids]} for x in v.vpns],
    }


def _ip(cidr):
    return None if cidr is None else str(cidr).split("/")[0]


def services(m: Model) -> dict:
    """The blocks above the network. Where the model has no field yet, the value comes from
    m.spec, the merged profile tree (spec k8s.cilium_devices, gateway_namespace, test_backend;
    registry.scheme, upstreams, charts; ca.issuer, certificates; ntp)."""
    spec = m.spec or {}
    out: dict = {}
    out["gateways"] = {
        g.name: {"vip": g.vip, "pool": [g.pool_start, g.pool_end], "pool_cidrs": list(g.pool_cidrs),
                 "audience": g.audience, "hostnames": list(g.hostnames), "segment": g.segment, "decision": g.decision}
        for g in m.gateways.values()
    }
    aud_gw = {a.name: a.gateway for a in m.audiences.values()}
    out["populations"] = {
        p.name: {"segments": list(p.segments), "prefixes": list(p.prefixes), "zones": list(p.zones),
                 "audience": p.audience, "gateway": aud_gw.get(p.audience), "clients": list(p.clients),
                 "resolver": p.resolver, "resolver_address": p.resolver_address, "resolvers": list(p.resolvers), "answer": p.answer,
                 "answer_address": p.answer_address, "translated": p.translated}
        for p in m.populations.values()
    }
    if m.dns is None:
        out["dns"] = None
    else:
        from .dns import tsig_keys  # noqa: PLC0415

        out["dns"] = {
            "zone": m.dns.zone, "users": list(m.dns.users), "admin": list(m.dns.admin), "internal": list(m.dns.internal),
            "identity": list(m.dns.identity), "wildcard": m.dns.wildcard,
            "records": {r.name: r.address for r in m.dns.records},
            "views": {v.name: {"server": v.server, "servers": [x for x in v.servers if x in m.nodes], "kind": v.kind,
                               "match_cidrs": list(v.match_cidrs), "answer_address": v.answer_address, "recursion": v.recursion,
                               "infra": v.infra, "names": list(m.dns.names_of(v))}
                      for v in m.dns.views},
            "resolvers": {r.name: {"servers": [x for x in r.servers if x in m.nodes], "kind": r.kind, "clients": list(r.client_cidrs),
                                   "to": [x for x in r.to if x in m.nodes], "local": list(r.local)}
                          for r in m.dns.resolvers},
            "tsig": tsig_keys(m),
        }
    k = m.k8s
    if k is None:
        out["k8s"] = None
    else:
        ks = spec.get("k8s") or {}
        tb = dict(spec.get("test_backend") or {})
        if tb.get("gateways"):
            # the Gateways of this state only (gw-inet joins the list from chapter 8)
            tb["gateways"] = [g for g in tb["gateways"] if g in m.gateways]
        out["k8s"] = {
            "version": k.version, "api_vip": k.api_vip, "api_fqdn": k.api_fqdn, "pod_cidr": k.pod_cidr,
            "service_cidr": k.service_cidr, "init": k.init, "control": list(k.control), "workers": list(k.workers),
            "gateway_class": k.gateway_class, "labels": dict(k.labels), "l2_announce": dict(k.l2_announce),
            "cilium_devices": list(ks.get("cilium_devices") or []),
            "gateway_namespace": ks.get("gateway_namespace"),
            # the harness's kubectl: on this node, with the admin kubeconfig kubeadm wrote there (lib.sh K)
            "admin_node": k.init, "admin_kubeconfig": "/etc/kubernetes/admin.conf",
            "test_backend": {key: tb.get(key) for key in ("name", "namespace", "port", "path", "replicas", "gateways")} if tb else None,
        }
    r = m.registry
    if r is None:
        out["registry"] = None
    else:
        rs = spec.get("registry") or {}
        out["registry"] = {"node": r.node, "address": r.address, "port": r.port, "mirror": r.mirror, "fqdn": r.fqdn,
                           "scheme": rs.get("scheme", "http"), "upstreams": list(rs.get("upstreams") or []),
                           "charts": rs.get("charts", "charts")}
    c = m.ca
    from .ca import ca_on, lab_leaves  # noqa: PLC0415

    if c is None or not ca_on(m):
        out["ca"] = None
    else:
        cs = spec.get("ca") or {}
        out["ca"] = {"root_cn": c.root_cn,
                     "intermediates": {i.name: {"cn": i.cn, "key": i.key, "dns": list(i.dns), "ip": list(i.ip)} for i in c.intermediates},
                     "proof_inside": list(c.proof_inside), "proof_outside": list(c.proof_outside),
                     "issuer": cs.get("issuer"),
                     # a Gateway's own certificate exists only where the Gateway does (render/k8s.py certificates)
                     "certificates": [x for x in cs.get("certificates") or [] if x.get("gateway") is None or x.get("gateway") in m.gateways],
                     # made and kept on the lab host (common/ca/sfab-ca): the render it reads, where it keeps
                     # the keys, where it publishes the root, and each node leaf's directory
                     "conf": "bootstrap/ca", "state": "state/ca", "root": "state/shared/ca/root.crt",
                     "leaves": {lf.name: {"ca": lf.ca, "node": lf.node, "dns": list(lf.dns), "ip": list(lf.ip),
                                          "dir": f"state/tls/{lf.node}"} for lf in lab_leaves(m)}}
    from .dns import ntp_servers, ntp_upstream, nts_on  # noqa: PLC0415

    nt = spec.get("ntp") or {}
    servers = ntp_servers(m)
    up = ntp_upstream(m)
    out["ntp"] = None if not nt else {
        "servers": {x: _ip(m.nodes[x].address) for x in servers},
        "upstream": None if up is None else {"node": up.name, "address": up.primary},
        "nts": nts_on(m), "allow": list(nt.get("allow") or []), "local_stratum": nt.get("local_stratum"),
        "reference_stratum": nt.get("reference_stratum"),
    }
    return out


def storage_csi(m: Model) -> dict:
    """Per storage node: its CSI settings (spec storage.csi), for nodes.<name>.csi."""
    out = {}
    for s in m.storage.values():
        csi = (s.settings or {}).get("csi")
        if csi:
            out[s.name] = {"user": csi.get("user"), "api": csi.get("api"), "classes": list(csi.get("classes") or []),
                           "default_class": csi.get("default_class")}
    return out


def modules(m: Model) -> list:
    """host.modules, then the modules the lab's node kinds need (kinds.<kind>.modules), once each."""
    out = [str(x) for x in ((m.common.get("host") or {}).get("modules") or [])]
    kinds = m.common.get("kinds") or {}
    extra = sorted({str(x) for n in m.nodes.values() for x in ((kinds.get(n.kind) or {}).get("modules") or [])} - set(out))
    return out + extra


def inventory(m: Model) -> dict:
    ch = m.meta.chapter
    nodes = {n.name: _node(m, n) for n in m.nodes.values()}
    for name, csi in storage_csi(m).items():
        nodes[name]["csi"] = csi

    def index(attr):
        out: dict = {}
        for n in m.nodes.values():
            out.setdefault(getattr(n, attr), []).append(n.name)
        return {k: sorted(v, key=natural) for k, v in sorted(out.items())}

    guests = sorted(m.guests, key=natural)
    gpu = sorted((g for g in guests if m.nodes[g].group == "gpu"), key=natural, reverse=True)
    rest = sorted((g for g in guests if g not in gpu), key=natural, reverse=True)
    host_c = m.common.get("host") or {}
    floor = float(host_c.get("mem_floor_gib", 16))
    mem = round(sum(n.budget.mem_gib for n in m.nodes.values()), 2)
    state_base = float(host_c.get("state_base_gib", 0))
    from .ca import ca_on  # noqa: PLC0415

    fw = m.firewall
    bastion = next((n.name for n in m.nodes.values() if n.kind == "bastion"), None)
    images = {}
    for n in m.nodes.values():
        info = ((m.meta.versions or {}).get("images") or {}).get(n.image_key) or {}
        images[n.image] = {"key": n.image_key, "pulled": bool(info.get("pulled", False)), "digest": info.get("digest")}
    inv = {
        "schema": SCHEMA,
        "lab": m.lab,
        "prefix": m.prefix,
        "clabdir": m.clabdir,
        "build": m.build,
        "profile": m.profile,
        "state": m.state,
        "step": m.step,
        "variant": m.variant,
        "chapter": ch.chapter if ch else None,
        "extends": ch.extends if ch else None,
        "prints": list(ch.prints) if ch else [],
        "org": {"name": m.org.name, "domain": m.org.domain, "zone": m.org.names, "short": m.org.short, "label_domain": m.org.label_domain},
        "mgmt": {"network": m.mgmt.network, "subnet": m.mgmt.subnet, "gw": m.mgmt.gw, "bridge": m.mgmt.bridge},
        "features": dict(sorted(m.features.items())),
        "stages": {
            "switches": sorted(m.switches, key=natural),
            "pairs": sorted(m.pairs),
            "guests": guests,
            "fw": fw.name if fw else None,
            "storage": sorted(m.storage, key=natural),
            "bastion": bastion,
            # the node the harness's kubectl runs on (common/lib.sh K), with the admin kubeconfig
            # kubeadm wrote there: the init node, never the bastion
            "kubectl": m.k8s.init if m.k8s is not None else None,
            "fw_bootstrap": fw is not None,
            "wait_fabric": "mclag" if m.pairs else "none",
            "guest_hold": bool(guests),
            # the lab CA, made on the lab host before the deploy (common/ca/sfab-ca init, the up stage)
            "ca_init": ca_on(m),
            "cluster": bool(m.features.get("k8s")),
            "serving": bool(m.features.get("serving")),
            "storage_setup": bool(m.features.get("storage_setup")),
            "modules": modules(m),
        },
        "nodes": nodes,
        "order": list(m.nodes),
        "roles": index("role"),
        "groups": index("group"),
        "kinds": index("kind"),
        "links": [
            {"id": l.id, "a": str(l.a), "b": str(l.b), "kind": l.kind, "attachment": l.attachment, "pc": l.pc,
             "mode": l.mode, "vlans": list(l.vlans), "mtu": l.mtu, "rail": l.rail}
            for l in m.links
        ],
        "budget": {
            "mem_gib": mem,
            "floor_gib": floor,
            "need_gib": round(mem + floor, 2),
            "vcpus": round(sum(n.budget.vcpus for n in m.nodes.values()), 2),
            "vcpu_overcommit": host_c.get("vcpu_overcommit", 2),
            # The disk budget (FRAMEWORK.md 3.1): growth under state/ (the lab's own files plus
            # every node's state_gib) and in the container layers under Docker's data root.
            "state_base_gib": state_base,
            "state_gib": round(state_base + sum(n.budget.state_gib for n in m.nodes.values()), 2),
            "layer_gib": round(sum(n.budget.layer_gib for n in m.nodes.values()), 2),
        },
        "watchdog": {"order": gpu + rest, "floor_gib": floor},
        "images": dict(sorted(images.items())),
        "host": {"tick": host_c.get("tick", 10000), "boot_batch": host_c.get("boot_batch"), "startup_delay_s": host_c.get("startup_delay_s")},
        "timeouts": m.common.get("timeouts") or {},
        "harness": m.common.get("harness") or {},
        "naming": m.common.get("naming") or {},
        "switch": {k: v for k, v in (m.common.get("switch") or {}).items()},
        "guest": {"user": (m.common.get("guest") or {}).get("user", "admin"), "tables": (m.common.get("guest") or {}).get("tables") or {}},
        "trace": ch.trace if ch else {},
        "known": sorted(k["id"] for k in (m.meta.known or {}).get("known") or []),
        "warnings": list(m.warnings),
    }
    inv.update(services(m))
    return inv


def render(model: Model, ctx) -> dict:
    return {"gen/inventory.json": dumps(inventory(model))}


def render_json(model: Model, ctx, outputs: dict, present: list, skipped: list) -> str:
    """gen/RENDER.json: every output's sha256, the spec files and versions, the generator."""
    from . import generator_sha, sha256  # noqa: PLC0415
    from .. import GENERATOR_VERSION  # noqa: PLC0415

    ch = model.meta.chapter
    spec_files = dict(sorted(model.meta.spec_files.items()))
    combined = sha256("".join(f"{k}={v}\n" for k, v in spec_files.items()).encode())
    chapter = None
    if ch and ch.path:
        chapter = {"path": ctx.rel(ch.path), "sha256": ch.sha256}
    used = sorted({n.image_key for n in model.nodes.values()})
    versions = model.meta.versions or {}
    data = {
        "lab": model.lab,
        "profile": model.profile,
        "state": model.state,
        "step": model.step,
        "variant": model.variant,
        "chapter": chapter,
        "spec": {"files": spec_files, "sha256": combined},
        "versions": {
            "images": {k: (versions.get("images") or {}).get(k) for k in used},
            "tools": versions.get("tools") or {},
            "kubernetes": versions.get("kubernetes") or {},
        },
        "files": {p: sha256(b) for p, b in sorted(outputs.items())},
        # The generator block is left out of `sfab check`: a new generator commit, or a renderer
        # landing that writes nothing for this lab, is no drift. A renderer that does write files
        # for the lab shows as drift through "files".
        "generator": {"version": GENERATOR_VERSION, "sha256": generator_sha(ctx.root),
                      "renderers": {"present": list(present), "skipped": list(skipped)}},
    }
    return dumps(data)
