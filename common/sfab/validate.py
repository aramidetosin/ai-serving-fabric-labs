"""Model validation: every rejection of FRAMEWORK.md section 2.5, plus the structural checks the
renderers rely on. validate(model) raises ValidationError listing every problem found;
problems(model) returns the list without raising.
"""

from __future__ import annotations

import re
from collections import Counter

from . import addr, ports
from .model import Firewall, Host, Model, Storage, Switch

LABEL_MAX = 63
_DNS_LABEL = re.compile(r"^(\*|[a-z0-9]([a-z0-9-]*[a-z0-9])?)$")
_K8S_NAME = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


class ValidationError(Exception):
    """The model breaks one or more rules; .problems holds one message per problem."""

    def __init__(self, problems: list[str], lab: str = ""):
        self.problems = list(problems)
        head = f"{lab}: " if lab else ""
        super().__init__(head + f"{len(self.problems)} problem(s):\n  " + "\n  ".join(self.problems))


def validate(model: Model) -> None:
    p = problems(model)
    if p:
        raise ValidationError(p, model.lab)


def problems(model: Model) -> list[str]:
    out: list[str] = []
    for check in (check_segments, check_addresses, check_ports, check_num_nics, check_pairs, check_firewall,
                  check_audiences, check_placement, check_labels, check_domains, check_mtu, check_segment_mtu):
        out.extend(check(model))
    return out


# --------------------------------------------------------------------------------------------


def check_segments(m: Model) -> list[str]:
    """Each segment fits its scope, nothing overlaps (except declared children), nothing touches
    10.0.0.0/24."""
    out = []
    for s in m.segments.values():
        if s.scope not in ("internal", "external", "mgmt"):
            out.append(f"segment {s.id}: unknown scope {s.scope!r}")
            continue
        if not addr.scope_ok(s.scope, s.prefix):
            want = "RFC 1918" if s.scope in ("internal", "mgmt") else "RFC 5737 or RFC 3849"
            out.append(f"segment {s.id}: {s.prefix} is {s.scope} and must be {want}")
        if addr.in_slirp(s.prefix):
            out.append(f"segment {s.id}: {s.prefix} touches 10.0.0.0/24 (the vrnetlab slirp network)")
        if s.within:
            parent = m.segments.get(s.within)
            if parent is None:
                out.append(f"segment {s.id}: within: {s.within!r} is not a segment")
            elif not addr.contains(parent.prefix, s.prefix):
                out.append(f"segment {s.id}: {s.prefix} is not inside {parent.id} {parent.prefix}")
    top = [(s.id, s.prefix) for s in m.segments.values() if not s.within]
    for a, b in addr.overlaps(top):
        out.append(f"segments {a} and {b} overlap ({m.segments[a].prefix}, {m.segments[b].prefix})")
    if m.mgmt.subnet not in {s.prefix for s in m.segments.values() if s.scope == "mgmt"}:
        out.append(f"mgmt subnet {m.mgmt.subnet} is not declared as a segment with scope mgmt")
    return out


def _addresses(m: Model):
    """Yield (where, address-or-cidr) for every address the model assigns."""
    for n in m.nodes.values():
        yield f"{n.name} mgmt", n.mgmt
        if isinstance(n, Host):
            if n.address and not n.ifaces:
                yield f"{n.name} address", n.address
            if n.oob:
                yield f"{n.name} oob", n.oob.address
            if n.bond:
                for vi in n.bond.vlan_ifs:
                    yield f"{n.name} {vi.name}", vi.address
            for r in n.rails:
                yield f"{n.name} rail{r.rail}", r.address
            if n.relay:
                for ns in n.relay.namespaces:
                    yield f"{n.name} {ns.ns} relay", ns.relay_addr
            for i in n.ifaces:
                if i.address:
                    yield f"{n.name} {i.eth}", i.address
                if i.gateway:
                    yield f"{n.name} {i.eth} gw", i.gateway
            for r in n.routes:
                if r.via and _is_addr(r.via):
                    yield f"{n.name} route {r.dest} via", r.via
        if isinstance(n, Firewall):
            for i in n.interfaces:
                if i.address:
                    yield f"{n.name} {i.name}", i.address
            for r in n.routes:
                if r.kind == "ip" and r.nexthop:
                    yield f"{n.name} route {r.name} nexthop", r.nexthop
            for x in n.addresses:
                yield f"{n.name} address object {x.name}", x.prefix
            for v in n.vpns:
                yield f"{n.name} vpn {v.name} peer", v.peer
        if isinstance(n, Storage):
            for w, i in (("data", n.data), ("mgmt", n.mgmt_if)):
                if i:
                    yield f"{n.name} {w}", i.address
    for g in m.gateways.values():
        yield f"gateway {g.name} vip", g.vip
        yield f"gateway {g.name} pool", g.pool_start
        yield f"gateway {g.name} pool", g.pool_end
    if m.k8s:
        yield "k8s api vip", m.k8s.api_vip


def _is_addr(s: str) -> bool:
    try:
        addr.ip(s)
        return True
    except addr.AddrError:
        return False


def check_addresses(m: Model) -> list[str]:
    """Internal addresses must be RFC 1918, outside ones RFC 5737 or RFC 3849, every address
    inside a declared segment, and none in 10.0.0.0/24."""
    out = []
    for where, a in _addresses(m):
        try:
            seg = m.segment_of(addr.prefix_of(a) if "/" in str(a) else a)
        except addr.AddrError as e:
            out.append(f"{where}: {e}")
            continue
        if addr.in_slirp(a):
            out.append(f"{where}: {a} is in 10.0.0.0/24 (the vrnetlab slirp network)")
        if seg is None:
            out.append(f"{where}: {a} is outside every declared segment")
            continue
        if not addr.scope_ok(seg.scope, a):
            out.append(f"{where}: {a} sits in {seg.scope} segment {seg.id} but is {addr.classify(a)}")
        if "/" in str(a) and addr.iface(a).network.prefixlen < seg.prefixlen:
            out.append(f"{where}: {a} is wider than its segment {seg.id} {seg.prefix}")
    return out


def check_ports(m: Model) -> list[str]:
    """No port is used twice, and every switch port exists on the image."""
    out = []
    ends: dict = {}
    for l in m.links:
        for e in (l.a, l.b):
            ends.setdefault((e.node, e.eth), []).append(f"{l.a} -- {l.b}")
    for (node, eth), ls in sorted(ends.items()):
        if len(ls) > 1:
            out.append(f"{node}:{eth} is used by {len(ls)} links: {'; '.join(ls)}")
    ids = Counter(l.id for l in m.links)
    for i, c in sorted(ids.items()):
        if c > 1:
            out.append(f"link {i} is declared {c} times")
    for sw in m.switches.values():
        for n in sw.nics:
            try:
                ports.native(n.index)
            except ports.PortError as e:
                out.append(f"{sw.name}: {e}")
        pcs = Counter(p.id for p in sw.portchannels)
        for pc, c in pcs.items():
            if c > 1:
                out.append(f"{sw.name}: PortChannel {pc} is defined {c} times")
    for n in m.nodes.values():
        if n.section != "switches" and n.kind == "vm-node":
            seen = Counter(x.eth for x in n.nics)
            for e, c in seen.items():
                if c > 1:
                    out.append(f"{n.name}:{e} is used twice")
    return out


def check_num_nics(m: Model) -> list[str]:
    out = []
    for sw in m.switches.values():
        if sw.num_nics > ports.MAX_NICS:
            out.append(f"{sw.name}: NUM_NICS {sw.num_nics} is above {ports.MAX_NICS}")
        if sw.sflow and ports.MAX_NICS not in sw.used_ports:
            out.append(f"{sw.name}: exports sFlow, so eth{ports.MAX_NICS} must be cabled")
        if sw.used_ports and sw.num_nics < max(sw.used_ports):
            out.append(f"{sw.name}: NUM_NICS {sw.num_nics} is below its highest port eth{max(sw.used_ports)}")
    return out


def check_pairs(m: Model) -> list[str]:
    out = []
    for p in m.pairs.values():
        present = [x for x in p.members if x in m.nodes]
        if len(present) != len(p.members):
            out.append(f"pair {p.name}: only {present} of {list(p.members)} are in the lab")
            continue
        if not _MAC.match(p.system_mac) or not int(p.system_mac[:2], 16) & 0x02:
            out.append(f"pair {p.name}: system MAC {p.system_mac} must be a locally administered unicast MAC")
        for x in p.members:
            sw = m.nodes[x]
            if not isinstance(sw, Switch):
                out.append(f"pair {p.name}: {x} is not a switch")
                continue
            if sw.keepalive is None and not sw.passthrough:
                out.append(f"pair {p.name}: {x} lacks CLAB_MGMT_PASSTHROUGH; a keepalive in VRF mgmt needs the real management address")
            if sw.keepalive is not None:
                ka = sw.keepalive
                if sw.portchannel(p.peer_link_pc) is not None and ka.backup_vlan is not None:
                    if ka.backup_vlan not in sw.portchannel(p.peer_link_pc).vlans:
                        out.append(f"pair {p.name}: {x}'s peer link does not carry the backup keepalive's VLAN {ka.backup_vlan}")
                    for pc in sw.portchannels:
                        if pc.kind != "peer-link" and ka.backup_vlan in tuple(pc.vlans) + tuple(pc.tagged):
                            out.append(f"pair {p.name}: {x}'s {pc.name} carries the backup keepalive's VLAN {ka.backup_vlan}; it rides the peer link only")
                if any(n.index == ka.eth and n.role != "keepalive" for n in sw.nics):
                    out.append(f"pair {p.name}: {x}'s keepalive port eth{ka.eth} is used by something else")
            if sw.mclag is None:
                out.append(f"pair {p.name}: {x} has no MCLAG domain")
            if sw.portchannel(p.peer_link_pc) is None:
                out.append(f"pair {p.name}: {x} has no peer link PortChannel {p.peer_link_pc}")
    return out


def check_firewall(m: Model) -> list[str]:
    """Rules, NAT, interfaces and routes name only known zones, services and interfaces;
    deny-all-log, when present, is the last rule."""
    out = []
    fw = m.firewall
    if fw is None:
        return out
    zones = {z.name for z in fw.zones}
    ifs = {i.name for i in fw.interfaces}
    svcs = {s.name for s in fw.services} | {"any", "application-default", "service-http", "service-https"}
    for i in fw.interfaces:
        if i.zone and i.zone not in zones:
            out.append(f"firewall interface {i.name}: unknown zone {i.zone!r}")
        if i.parent and i.parent not in ifs:
            out.append(f"firewall interface {i.name}: unknown parent {i.parent!r}")
    for kind, items in (("rule", fw.rules), ("nat", fw.nat)):
        for r in items:
            for z in r.from_zones + r.to_zones:
                if z != "any" and z not in zones:
                    out.append(f"firewall {kind} {r.name}: unknown zone {z!r}")
            if not r.from_zones or not r.to_zones:
                out.append(f"firewall {kind} {r.name}: from: and to: are required")
    for r in fw.rules:
        for s in r.services:
            if s not in svcs:
                out.append(f"firewall rule {r.name}: unknown service {s!r}")
        if r.action not in ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both"):
            out.append(f"firewall rule {r.name}: unknown action {r.action!r}")
    for n in fw.nat:
        if n.service not in svcs:
            out.append(f"firewall nat {n.name}: unknown service {n.service!r}")
        if n.snat_interface and n.snat_interface not in ifs:
            out.append(f"firewall nat {n.name}: unknown interface {n.snat_interface!r}")
    names = [r.name for r in fw.rules]
    for kind, items in (("rule", names), ("nat", [n.name for n in fw.nat])):
        for x, c in Counter(items).items():
            if c > 1:
                out.append(f"firewall {kind} {x} is defined {c} times")
    if "deny-all-log" in names and names[-1] != "deny-all-log":
        out.append("firewall: deny-all-log must be the last security rule")
    for r in fw.routes:
        if r.kind == "discard":
            if r.interface or r.nexthop:
                out.append(f"firewall route {r.name}: a discard route names no interface and no next hop")
            continue
        if r.interface not in ifs:
            out.append(f"firewall route {r.name}: unknown interface {r.interface!r}")
        elif r.kind == "interface" and (fw.interface(r.interface) is None or fw.interface(r.interface).kind != "tunnel"):
            out.append(f"firewall route {r.name}: a route with no next hop goes out a tunnel interface")
    zps = {fw.profiles.zone_protection} if fw.profiles and fw.profiles.zone_protection else set()
    for z in fw.zones:
        if z.zone_protection and z.zone_protection not in zps:
            out.append(f"firewall zone {z.name}: unknown zone protection profile {z.zone_protection!r}")
    for r in fw.rules:
        if r.action == "allow" and r.applications == ("any",):
            out.append(f"firewall rule {r.name}: an allow rule names its App-IDs (application any allows anything on its ports)")
        if r.action == "allow" and "any" in r.services:
            out.append(f"firewall rule {r.name}: an allow rule takes application-default or an explicit service, never any")
        if r.action == "allow" and fw.profiles is not None and fw.profiles.group and not r.profile_group:
            out.append(f"firewall rule {r.name}: an allow rule carries the profile group {fw.profiles.group}")
    for k, v in fw.default_rules.items():
        if k not in ("intrazone-default", "interzone-default"):
            out.append(f"firewall default_rules: {k!r} is not a predefined rule")
        elif v.get("action") not in ("allow", "deny"):
            out.append(f"firewall default_rules {k}: action {v.get('action')!r}")
    for v in fw.vpns:
        if v.interface not in ifs:
            out.append(f"firewall vpn {v.name}: unknown interface {v.interface!r}")
        if not v.proxy_ids:
            out.append(f"firewall vpn {v.name}: no proxy ID")
    if fw.system and fw.system.service_route and fw.system.service_route not in ifs:
        out.append(f"firewall: service route interface {fw.system.service_route!r} is unknown")
    ad = fw.admin
    if ad is not None:
        i = fw.interface(ad.interface)
        if i is None or i.kind not in ("layer3", "subinterface") or not i.address:
            out.append(f"firewall admin: {ad.interface!r} is not an addressed layer 3 interface")
        bad = [s for s in ad.allow if s not in ADMIN_SERVICES]
        if bad:
            out.append(f"firewall admin: unknown service(s) {bad} (have {', '.join(sorted(ADMIN_SERVICES))})")
        if ad.profile == PING_PROFILE_NAME:
            out.append(f"firewall admin: the profile name {ad.profile!r} is the ping-only profile every other interface takes")
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$", ad.profile):
            out.append(f"firewall admin: profile name {ad.profile!r} is not a PAN-OS object name")
        for c in ad.permitted_cidrs:
            if c == "any" or not addr.scope_ok("internal", c):
                out.append(f"firewall admin: permitted {c} is not an inside (RFC 1918) prefix: nothing administrative is published")
    return out


# The services an interface management profile can turn on that render/panos.py writes, and the name
# of the profile every interface without administrative access takes (render/panos.py PING_PROFILE).
ADMIN_SERVICES = {"https", "ssh", "ping"}
PING_PROFILE_NAME = "ping-only"


def check_audiences(m: Model) -> list[str]:
    out = []
    for a in m.audiences.values():
        if a.gateway not in m.gateways:
            out.append(f"audience {a.name}: no Gateway {a.gateway!r}")
        for x in a.models:
            if x not in m.models:
                out.append(f"audience {a.name}: unknown model {x!r}")
    for g in m.gateways.values():
        if g.audience not in m.audiences:
            out.append(f"gateway {g.name}: unknown audience {g.audience!r}")
        if not (addr.ip(g.pool_start) <= addr.ip(g.vip) <= addr.ip(g.pool_end)):
            out.append(f"gateway {g.name}: VIP {g.vip} is outside its pool {g.pool_start} to {g.pool_end}")
    gs = sorted(m.gateways.values(), key=lambda g: addr.ip(g.pool_start))
    for a, b in zip(gs, gs[1:]):
        if addr.ip(b.pool_start) <= addr.ip(a.pool_end):
            out.append(f"gateways {a.name} and {b.name}: pools overlap")
    for p in m.populations.values():
        if p.audience not in m.audiences and p.audience != "none":
            out.append(f"population {p.name}: unknown audience {p.audience!r}")
    return out


def check_placement(m: Model) -> list[str]:
    """Rails exist, pods sit on GPU nodes, a copy that spans nodes says so, and every model keeps a
    copy through the loss of any one GPU node and of either rail switch (build A revision 2).

    A rail switch carries the rails of one parity in build A, and a copy is counted lost with a
    switch when its rail is one of that switch's: on hardware a dark switch drops the carrier of
    the rail NIC its in-node RPC rides too (the lab's virtual switch does not: known limit L9).
    A copy is lost with a node when any of its pods sits there."""
    out = []
    hosts = (m.spec.get("hosts") or {})
    gpu = sorted(n for n, h in hosts.items() if (h or {}).get("rails"))
    for mod in m.models.values():
        for c in mod.copies:
            if c.rail not in m.rails:
                out.append(f"model {mod.name} copy {c.name}: rail {c.rail} does not exist")
            for row in c.pods:
                h = hosts.get(row.node)
                if h is None or not h.get("rails"):
                    out.append(f"model {mod.name} copy {c.name}: {row.node} is not a GPU node with rails")
            if len(c.nodes) > 1 and not c.spans:
                out.append(f"model {mod.name} copy {c.name} sits on {', '.join(c.nodes)}: a copy across nodes must say spans: true")
            if c.spans and len(c.nodes) < 2:
                out.append(f"model {mod.name} copy {c.name} says spans: true but sits on {c.nodes[0] if c.nodes else 'no node'} alone")
        if not mod.copies:
            continue
        for par in ("odd", "even"):
            if all(c.parity == par for c in mod.copies):
                out.append(f"model {mod.name}: every copy sits on {par} rails; the loss of that rail switch leaves no copy")
        for node in gpu:
            if all(node in c.nodes for c in mod.copies):
                out.append(f"model {mod.name}: every copy has a pod on {node}; the loss of that node leaves no copy")
    return out


def _label_values(m: Model):
    for n in m.nodes.values():
        yield f"node {n.name}", n.name
        if n.decision:
            yield f"node {n.name} decision", n.decision
    for g in m.gateways.values():
        yield f"gateway {g.name}", g.name
        if g.decision:
            yield f"gateway {g.name} decision", g.decision
    for mod in m.models.values():
        yield f"model {mod.name}", mod.name
        for c in mod.copies:
            if c.decision:
                yield f"model {mod.name} decision", c.decision
            for r in c.pods:
                yield f"pod {r.pod}", r.pod
    for a in m.audiences.values():
        yield f"audience {a.name}", a.name
    fw = m.firewall
    if fw:
        for r in fw.rules:
            if r.decision:
                yield f"rule {r.name} decision", r.decision
        for r in fw.nat:
            if r.decision:
                yield f"nat {r.name} decision", r.decision
    if m.dns:
        for v in m.dns.views:
            if v.decision:
                yield f"view {v.name} decision", v.decision
    if m.k8s:
        for n in m.k8s.nads:
            yield f"nad {n.name}", n.name


def check_labels(m: Model) -> list[str]:
    """Kubernetes names, label values and keys, and DNS labels stay within 63 characters."""
    out = []
    for where, v in _label_values(m):
        if len(v) > LABEL_MAX:
            out.append(f"{where}: {v!r} is {len(v)} characters, more than {LABEL_MAX}")
        if not _K8S_NAME.match(v):
            out.append(f"{where}: {v!r} is not a valid lowercase name")
    if m.k8s:
        for role, key in m.k8s.labels.items():
            prefix, _, name = key.rpartition("/")
            if len(name) > LABEL_MAX:
                out.append(f"label {role}: name part {name!r} is longer than {LABEL_MAX}")
            if len(prefix) > 253:
                out.append(f"label {role}: prefix {prefix!r} is longer than 253")
    for where, fq in _fqdns(m):
        for lab in fq.split("."):
            if len(lab) > LABEL_MAX:
                out.append(f"{where}: DNS label {lab!r} in {fq} is longer than {LABEL_MAX}")
            elif not _DNS_LABEL.match(lab):
                out.append(f"{where}: DNS label {lab!r} in {fq} is not valid")
    return out


def _fqdns(m: Model):
    yield "org domain", m.org.domain
    yield "label domain", m.org.label_domain
    if m.org.zone:
        yield "org zone", m.org.zone
    if m.dns:
        for x in m.dns.users + m.dns.admin + m.dns.internal:
            yield "dns name", x
        if m.dns.wildcard:
            yield "dns wildcard", m.dns.wildcard
        for r in m.dns.records:
            yield "dns record", r.name
    for g in m.gateways.values():
        for h in g.hostnames:
            yield f"gateway {g.name} hostname", h
    if m.registry:
        yield "registry", m.registry.fqdn
    if m.ca:
        for lf in m.ca.leaves:
            for d in lf.dns:
                yield f"ca leaf {lf.name}", d


def check_domains(m: Model) -> list[str]:
    """Every domain the lab serves sits under .example (RFC 2606); the platform's zone sits under
    the org domain, and every name of the lab under the zone (a node leaf of the lab CA, which names
    an upstream stand-in, may sit anywhere under .example)."""
    out = []
    zone = m.org.names
    for where, fq in _fqdns(m):
        if not (fq == "example" or fq.endswith(".example")):
            out.append(f"{where}: {fq} is not under .example")
        elif where == "org zone":
            if not fq.endswith("." + m.org.domain):
                out.append(f"{where}: {fq} is not under {m.org.domain}")
        elif where not in ("org domain", "label domain") and not where.startswith("ca leaf") and not (fq == zone or fq.endswith("." + zone)):
            out.append(f"{where}: {fq} is not under {zone}")
    return out


def check_mtu(m: Model) -> list[str]:
    """A PortChannel facing the firewall runs an MTU no lower than the firewall's units on it."""
    out = []
    fw = m.firewall
    factory = int((m.common.get("switch") or {}).get("factory_mtu", 9100))
    maxmtu = int((m.common.get("switch") or {}).get("max_mtu", 9216))
    for sw in m.switches.values():
        for pc in sw.portchannels:
            if pc.mtu is not None and not 1312 <= pc.mtu <= maxmtu:
                out.append(f"{sw.name}: {pc.name} mtu {pc.mtu} is outside 1312 to {maxmtu}")
            if fw is None or pc.peer_node != fw.name:
                continue
            fw_eths = {mb.peer.eth for mb in pc.members}
            agg = [i for i in fw.interfaces if i.kind == "aggregate" and any(
                (fw.interface(x) and fw.interface(x).eth in fw_eths) for x in i.members)]
            need = 0
            for a in agg:
                need = max(need, a.mtu or 0)
                for u in fw.interfaces:
                    if u.parent == a.name and u.mtu:
                        need = max(need, u.mtu)
            have = pc.mtu or factory
            if need and have < need:
                out.append(f"{sw.name}: {pc.name} mtu {have} is below the firewall's {need} on {', '.join(a.name for a in agg)}")
    return out


def check_segment_mtu(m: Model) -> list[str]:
    """One IP MTU per segment: the firewall's unit and every host's address in a segment that
    declares an mtu use exactly it (Chapter 3's rule: every member of a VLAN equal)."""
    out = []
    fw = m.firewall
    if fw is not None:
        for i in fw.interfaces:
            if i.kind not in ("subinterface", "layer3") or not i.address:
                continue
            seg = m.segment_of(addr.prefix_of(i.address))
            if seg is not None and seg.mtu and seg.vlan is not None and i.kind == "subinterface" and (i.mtu or 1500) != seg.mtu:
                out.append(f"firewall {i.name}: mtu {i.mtu or 1500} differs from segment {seg.id}'s IP MTU {seg.mtu}")
    for h in m.hosts.values():
        if h.bond is not None:
            seg = m.segment_of(h.bond.address)
            if seg is not None and seg.mtu and h.bond.mtu != seg.mtu:
                out.append(f"{h.name}: bond0 mtu {h.bond.mtu} differs from segment {seg.id}'s IP MTU {seg.mtu}")
            for vi in h.bond.vlan_ifs:
                seg = m.segments.get(vi.segment)
                if seg is not None and seg.mtu and vi.mtu != seg.mtu:
                    out.append(f"{h.name}: {vi.name} mtu {vi.mtu} differs from segment {seg.id}'s IP MTU {seg.mtu}")
    for st in m.storage.values():
        for w, si in (("data", st.data), ("mgmt", st.mgmt_if)):
            if si is None:
                continue
            seg = m.segment_of(si.address)
            if seg is not None and seg.mtu and (si.mtu or 1500) != seg.mtu:
                out.append(f"{st.name} {w}: mtu {si.mtu or 1500} differs from segment {seg.id}'s IP MTU {seg.mtu}")
    return out
