"""The PA-VM: bootstrap/fw/startup-config.xml and bootstrap/fw/enforced.txt.

startup-config.xml is a whole PAN-OS <config> tree. containerlab delivers it to the firewall
container as /config/startup-config.cfg. The image's launcher treats the file as XML when
"<config" appears in its first 200 bytes; when the file holds a <jumbo-frame> element it first
turns jumbo-frame mode on and reboots (an interface MTU above 1500 does not validate until the
box has rebooted in that mode); then it imports the file, merges deviceconfig, network, vsys and
shared into the candidate, validates and commits. common/fw/fw-startup.py runs the same steps
when the launcher's commit did not take. So the file opens with <config> on its first line and
carries no XML declaration and no comments.

What the file holds, for the interfaces whose wires are in this lab:
  - ae1 over its members, LACP active and fast, with the tagged units that gateway the VLANs;
  - every other layer 3 interface, all with a management profile that answers ping only, except
    the one the spec's firewall.admin names (chapter 4: the out-of-band port), whose profile also
    answers HTTPS and SSH, to the permitted prefixes only;
  - one virtual router holding every layer 3 interface and the static routes;
  - one zone per interface, the services the rules name, the security rules in spec order
    (deny-all-log last, logging at session end) and the NAT rules in spec order;
  - the hostname, UTC, the DNS and NTP servers with their service routes when the node that
    serves them is in the lab, and jumbo frames at the largest MTU any interface asks for.
What it never holds: mgt-config (the launcher creates the login from the container's
environment, so no user, password hash or key is ever rendered) and the management address
(the launcher sets vrnetlab's own; containerlab forwards the lab's management address to it).

The slice (FRAMEWORK.md section 1.4): an interface whose wire is outside the lab is left out,
with the zone that only it held, the routes through it, and every rule or NAT rule that needs a
zone, an interface or a node the lab does not have. A rule whose zone or address list loses only
some members keeps the rest. Every omission is listed in enforced.txt's header.

enforced.txt is the same configuration as PAN-OS prints it in set format (one line per leaf,
`[ a b ]` for lists of more than one member, no vsys prefix on a single-vsys box), so the boot
stage can confirm every line in the running configuration.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from xml.sax.saxutils import escape, quoteattr

from .. import addr
from ..model import Firewall, FwAdmin, FwInterface, FwNat, FwRule, FwVpn, Host, Model, Storage, Zone

XML_PATH = "bootstrap/fw/startup-config.xml"
ENFORCED_PATH = "bootstrap/fw/enforced.txt"
# The tunnels' IKE gateways and IPsec tunnels, which boot sets through the API after the startup
# commit, each gateway with its pre-shared key put in from state/secrets/ipsec/<psk>.psk where the
# placeholder stands (the key is never rendered, so the startup file holds no gateway it could not
# commit).
VPN_PATH = "bootstrap/fw/vpn.json"
PSK_PLACEHOLDER = "@@SFAB_PSK@@"

DEVICE = "localhost.localdomain"
VSYS = "vsys1"
PING_PROFILE = "ping-only"
TIMEZONE = "UTC"
# No automatic logout for an idle administrator session (0), so a sampler's CLI session stays open.
IDLE_TIMEOUT = "0"
# Use the hypervisor-assigned MAC addresses: the dataplane ports keep the MACs QEMU gave the NICs.
AUTO_MAC_DETECT = "yes"
STD_MTU = 1500


# --------------------------------------------------------------------------------------------
# A small, byte-stable XML writer: one element per line, two-space indent, attributes in the
# order given, leaf text inline.


class El:
    __slots__ = ("tag", "attrs", "text", "kids")

    def __init__(self, tag: str, *kids: "El | None", text: str | None = None, attrs: tuple = ()):
        self.tag = tag
        self.attrs = tuple(attrs)
        self.text = text
        self.kids = [k for k in kids if k is not None]


def leaf(tag: str, value) -> El:
    return El(tag, text=str(value))


def entry(name: str, *kids: El | None) -> El:
    return El("entry", *kids, attrs=(("name", name),))


def members(tag: str, values) -> El:
    return El(tag, *(leaf("member", v) for v in values))


def xml(el: El, depth: int = 0) -> str:
    """Serialize one element (and its children) to text, without a trailing newline."""
    out: list[str] = []
    _ser(el, depth, out)
    return "\n".join(out)


def _ser(el: El, depth: int, out: list[str]) -> None:
    pad = "  " * depth
    attrs = "".join(f" {k}={quoteattr(str(v))}" for k, v in el.attrs)
    if el.kids:
        out.append(f"{pad}<{el.tag}{attrs}>")
        for k in el.kids:
            _ser(k, depth + 1, out)
        out.append(f"{pad}</{el.tag}>")
    elif el.text is not None:
        out.append(f"{pad}<{el.tag}{attrs}>{escape(el.text)}</{el.tag}>")
    else:
        out.append(f"{pad}<{el.tag}{attrs}/>")


# --------------------------------------------------------------------------------------------
# What this lab's firewall carries


@dataclass(frozen=True)
class ServiceRoute:
    service: str          # dns | ntp
    interface: str        # ethernet1/3
    address: str          # the interface's CIDR


@dataclass(frozen=True)
class FwView:
    fw: Firewall
    interfaces: tuple     # FwInterface, in spec order (each aggregate followed by its members)
    l3: tuple             # layer 3 interface names (units and layer3 ports), spec order
    zones: tuple          # Zone, with only the interfaces this lab carries
    routes: tuple
    services: tuple
    rules: tuple          # FwRule, pruned to this lab
    nat: tuple            # FwNat, pruned to this lab
    dns: tuple            # bare addresses
    ntp: tuple
    service_routes: tuple
    jumbo: int | None     # the global jumbo-frame MTU, or None
    omitted: tuple        # one line per element left out, with the reason
    admin: FwAdmin | None = None   # administrative access, when its interface is in this lab
    vpns: tuple = ()               # FwVpn, the tunnels whose interface and peer are in this lab

    def profile_of(self, ifname: str) -> str:
        """The interface management profile an interface takes."""
        return self.admin.profile if self.admin is not None and self.admin.interface == ifname else PING_PROFILE


def config_version(image: str) -> tuple[str, str]:
    """('12.1.0', '12.1.2') from 'vrnetlab/paloalto_pa-vm:12.1.2'."""
    tag = image.rsplit(":", 1)[-1] if ":" in image.rsplit("/", 1)[-1] else ""
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:[-.].*)?", tag)
    if not m:
        raise ValueError(f"firewall image {image!r}: the tag must be the PAN-OS release (for example 12.1.2)")
    return f"{m.group(1)}.{m.group(2)}.0", f"{m.group(1)}.{m.group(2)}.{m.group(3)}"


def _bare(cidr: str) -> str:
    """A host address without its /32 (or /128); a prefix or 'any' as it is."""
    if cidr == "any" or "/" not in cidr:
        return cidr
    net = addr.net(cidr)
    if net.prefixlen == net.max_prefixlen:
        return net.network_address.compressed
    return cidr


def _holders(m: Model) -> dict:
    """Primary address (bare) -> node name, for the nodes in this lab."""
    out = {}
    for n in m.nodes.values():
        a = None
        if isinstance(n, Host):
            a = n.primary
        elif isinstance(n, Storage):
            a = addr.ip(n.address).compressed if n.address else None
        if a:
            out.setdefault(a, n.name)
    return out


def _prune_refs(refs: tuple, cidrs: tuple, nodes: dict) -> tuple[tuple, tuple, list]:
    """Drop node:<x> references to nodes outside the lab. Returns (refs, cidrs, missing)."""
    if len(refs) != len(cidrs):
        return refs, cidrs, []
    keep_r, keep_c, missing = [], [], []
    for r, c in zip(refs, cidrs):
        kind, _, val = str(r).partition(":")
        if kind == "node" and val and val not in nodes:
            missing.append(val)
            continue
        keep_r.append(r)
        keep_c.append(c)
    return tuple(keep_r), tuple(keep_c), missing


def _prune_zones(zs: tuple, have: set) -> tuple[tuple, list]:
    keep = tuple(z for z in zs if z == "any" or z in have)
    return keep, [z for z in zs if z != "any" and z not in have]


def _rule_like(kind: str, name: str, frm, to, src, dst, nodes: dict, zones: set, omitted: list):
    """Shared pruning for security and NAT rules. Returns the kept lists, or None to drop."""
    f, f_gone = _prune_zones(frm, zones)
    t, t_gone = _prune_zones(to, zones)
    if not f or not t:
        gone = sorted(set(f_gone + t_gone))
        omitted.append(f"{kind} {name}: zone {', '.join(gone)} is not in this lab")
        return None
    s_r, s_c, s_gone = _prune_refs(*src, nodes)
    d_r, d_c, d_gone = _prune_refs(*dst, nodes)
    if (src[0] and not s_r) or (dst[0] and not d_r):
        gone = sorted(set(s_gone + d_gone))
        omitted.append(f"{kind} {name}: node {', '.join(gone)} is not in this lab")
        return None
    return f, t, (s_r, s_c), (d_r, d_c)


def view(m: Model) -> FwView | None:
    """The firewall configuration this lab carries, or None when the lab has no firewall."""
    fw = m.firewall
    if fw is None:
        return None
    omitted: list[str] = []
    nodes = m.nodes
    vpns = []
    for x in fw.vpns:
        if not any(i.name == x.interface and i.connected for i in fw.interfaces):
            omitted.append(f"vpn {x.name}: interface {x.interface} is not in this lab")
        elif x.peer_node and x.peer_node not in nodes:
            omitted.append(f"vpn {x.name}: its peer {x.peer_node} is not in this lab")
        else:
            vpns.append(x)
    vpn_tunnels = {x.tunnel_interface for x in vpns}
    ifs = []
    for i in fw.interfaces:
        if i.kind == "tunnel" and i.name not in vpn_tunnels:
            omitted.append(f"interface {i.name}: no tunnel of it is in this lab")
            continue
        if i.connected:
            ifs.append(i)
        elif i.kind != "aggregate-member" or any(a.name == i.parent and a.connected for a in fw.interfaces):
            omitted.append(f"interface {i.name}: its wire is not in this lab")
    have_if = {i.name for i in ifs}
    l3 = tuple(i.name for i in ifs if i.kind in ("subinterface", "layer3", "tunnel"))
    zones = []
    for z in fw.zones:
        zi = tuple(x for x in z.interfaces if x in have_if)
        if zi:
            zones.append(Zone(name=z.name, interfaces=zi, decision=z.decision, since=z.since, zone_protection=z.zone_protection))
        else:
            omitted.append(f"zone {z.name}: no interface of it is in this lab")
    have_zone = {z.name for z in zones}
    routes = []
    for r in fw.routes:
        if r.kind == "discard" or r.interface in have_if:
            routes.append(r)
        else:
            omitted.append(f"route {r.name}: interface {r.interface} is not in this lab")
    # a decisions lab (chapter 2 on) labels every rule: its own decision id, else the derived one
    from .decisions import label_of  # noqa: PLC0415

    rules = []
    for r in fw.rules:
        f, f_gone = _prune_zones(r.from_zones, have_zone)
        t, t_gone = _prune_zones(r.to_zones, have_zone)
        if not f or not t:
            omitted.append(f"rule {r.name}: zone {', '.join(sorted(set(f_gone + t_gone)))} is not in this lab")
            continue
        sp, s_gone = _prune_parts(r.src_parts, nodes)
        dp, d_gone = _prune_parts(r.dst_parts, nodes)
        if (r.src_parts and not sp) or (r.dst_parts and not dp):
            omitted.append(f"rule {r.name}: node {', '.join(sorted(set(s_gone + d_gone)))} is not in this lab")
            continue
        rules.append(FwRule(name=r.name, from_zones=f, to_zones=t, src=tuple(x[0] for x in sp), dst=tuple(x[0] for x in dp),
                            src_cidrs=tuple(c for x in sp for c in x[1]), dst_cidrs=tuple(c for x in dp for c in x[1]),
                            services=r.services, applications=r.applications, action=r.action, log_end=r.log_end,
                            decision=label_of(m, "policy", r.name, r.decision), since=r.since, desc=r.desc,
                            src_members=tuple(mm for x in sp for mm in x[2]), dst_members=tuple(mm for x in dp for mm in x[2]),
                            profile_group=r.profile_group, src_parts=sp, dst_parts=dp))
    nat = []
    for n in fw.nat:
        k = _rule_like("nat", n.name, n.from_zones, n.to_zones, (n.src, n.src_cidrs), (n.dst, n.dst_cidrs), nodes, have_zone, omitted)
        if k is None:
            continue
        if n.snat_interface and n.snat_interface not in have_if:
            omitted.append(f"nat {n.name}: interface {n.snat_interface} is not in this lab")
            continue
        kind, _, val = str(n.dnat_ref or "").partition(":")
        if kind == "node" and val not in nodes:
            omitted.append(f"nat {n.name}: node {val} is not in this lab")
            continue
        f, t, (sr, sc), (dr, dc) = k
        nat.append(FwNat(name=n.name, from_zones=f, to_zones=t, src=sr, dst=dr, src_cidrs=sc, dst_cidrs=dc, service=n.service,
                         dnat=n.dnat, dnat_ref=n.dnat_ref, dnat_port=n.dnat_port, snat_type=n.snat_type,
                         snat_interface=n.snat_interface, decision=label_of(m, "nat", n.name, n.decision), since=n.since))
    used = []
    for r in rules:
        used.extend(r.services)
    used.extend(n.service for n in nat)
    services = tuple(s for s in fw.services if s.name in set(used))
    holders = _holders(m)
    sysd = fw.system
    dns, ntp, sroutes = [], [], []
    if sysd is not None:
        for kind, servers, out in (("dns", sysd.dns, dns), ("ntp", sysd.ntp, ntp)):
            for a in servers:
                if a in holders:
                    out.append(a)
                else:
                    omitted.append(f"{kind} server {a}: no node in this lab holds that address")
        sr = sysd.service_route
        if sr and (dns or ntp):
            src_if = fw.interface(sr)
            if sr in have_if and src_if is not None and src_if.address:
                # PAN-OS service-route entries, one per service the firewall itself uses
                for svc, servers in (("dns", dns), ("ntp", ntp)):
                    if servers:
                        sroutes.append(ServiceRoute(service=svc, interface=sr, address=src_if.address))
            else:
                omitted.append(f"service route: interface {sr} is not in this lab")
    admin = fw.admin
    if admin is not None and admin.interface not in l3:
        omitted.append(f"admin profile {admin.profile}: interface {admin.interface} is not in this lab")
        admin = None
    mtus = [i.mtu for i in ifs if i.mtu]
    jumbo = max(mtus) if mtus and max(mtus) > STD_MTU else None
    return FwView(fw=fw, interfaces=tuple(ifs), l3=l3, zones=tuple(zones), routes=tuple(routes), services=services,
                  rules=tuple(rules), nat=tuple(nat), dns=tuple(dns), ntp=tuple(ntp), service_routes=tuple(sroutes),
                  jumbo=jumbo, omitted=tuple(omitted), admin=admin, vpns=tuple(vpns))


def _prune_parts(parts: tuple, nodes: dict) -> tuple[tuple, list]:
    """Drop the node:<x> references of a rule side whose node is outside the lab."""
    keep, gone = [], []
    for ref, cidrs, mem in parts:
        kind, _, val = str(ref).partition(":")
        if kind == "node" and val and val not in nodes:
            gone.append(val)
            continue
        keep.append((ref, cidrs, mem))
    return tuple(keep), gone


def vpn_psks(model: Model) -> list:
    """The pre-shared key names of the tunnels this lab's firewall terminates (state/secrets/ipsec)."""
    v = view(model)
    return sorted({x.psk for x in v.vpns}) if v is not None else []


# --------------------------------------------------------------------------------------------
# XML pieces. rule(), dnat() and snat() return the <entry> a live change sends through
# common/fw/fw-api.sh, so what a break or heal applies is what the next deploy boots.


def description(decision: str | None, desc: str | None) -> str | None:
    if decision and desc:
        return f"{decision}: {desc}"
    return decision or desc or None


def rule(r: FwRule) -> El:
    d = description(r.decision, r.desc)
    return entry(
        r.name,
        members("from", r.from_zones),
        members("to", r.to_zones),
        members("source", _side(r.src_members, r.src_cidrs)),
        members("destination", _side(r.dst_members, r.dst_cidrs)),
        members("application", r.applications),
        members("service", r.services),
        leaf("action", r.action),
        leaf("log-end", "yes" if r.log_end else "no"),
        El("profile-setting", El("group", leaf("member", r.profile_group))) if r.profile_group else None,
        leaf("description", d) if d else None,
    )


def _side(members_, cidrs) -> list:
    """What a rule's source or destination prints: its members (object names or bare prefixes)."""
    return list(members_) if members_ else [_bare(c) for c in cidrs]


def _nat_match(n: FwNat) -> list[El]:
    return [
        members("from", n.from_zones),
        members("to", n.to_zones),
        members("source", [_bare(c) for c in n.src_cidrs]),
        members("destination", [_bare(c) for c in n.dst_cidrs]),
        leaf("service", n.service),
    ]


def dnat(n: FwNat) -> El:
    tr = El("destination-translation", leaf("translated-address", n.dnat),
            leaf("translated-port", n.dnat_port) if n.dnat_port else None)
    d = description(n.decision, None)
    return entry(n.name, *_nat_match(n), tr, leaf("description", d) if d else None)


def snat(n: FwNat) -> El:
    st = n.snat_type or "dynamic-ip-and-port"
    if st != "dynamic-ip-and-port":
        raise ValueError(f"nat {n.name}: source translation {st!r} is not rendered (dynamic-ip-and-port only)")
    tr = El("source-translation", El(st, El("interface-address", leaf("interface", n.snat_interface))))
    d = description(n.decision, None)
    return entry(n.name, *_nat_match(n), tr, leaf("description", d) if d else None)


def nat_rule(n: FwNat) -> El:
    """A NAT rule: destination translation, source translation, or none (a no-translation rule)."""
    if n.dnat and n.snat_interface:
        raise ValueError(f"nat {n.name}: both translations in one rule are not rendered")
    if n.dnat:
        return dnat(n)
    if n.snat_interface:
        return snat(n)
    d = description(n.decision, None)
    return entry(n.name, *_nat_match(n), leaf("description", d) if d else None)


def _l3_kids(i: FwInterface, profile: str = PING_PROFILE) -> list[El | None]:
    return [
        El("ip", entry(i.address)) if i.address else None,
        leaf("mtu", i.mtu) if i.mtu else None,
        leaf("interface-management-profile", profile),
        El("adjust-tcp-mss", leaf("enable", "yes"), leaf("ipv4-mss-adjustment", i.mss_adjust)) if i.mss_adjust else None,
    ]


# The order an administrative profile's services are written in, and a permitted prefix as PAN-OS
# keeps it (an entry with no children).
ADMIN_ORDER = ("https", "ssh", "ping")


def profiles(v: FwView) -> El:
    """The interface management profiles: ping-only, then the administrative one when it is used."""
    out = [entry(PING_PROFILE, leaf("ping", "yes"))]
    a = v.admin
    if a is not None:
        kids = [leaf(s, "yes") for s in ADMIN_ORDER if s in a.allow]
        if a.permitted_cidrs:
            kids.append(El("permitted-ip", *(entry(c) for c in a.permitted_cidrs)))
        out.append(entry(a.profile, *kids))
    zp = zone_protection(v)
    return El("profiles", El("interface-management-profile", *out), El("zone-protection-profile", zp) if zp is not None else None)


# The zone protection flood types in PAN-OS's order, and the discard options the spec may name.
ZP_FLOODS = ("tcp-syn", "udp", "icmp", "icmpv6", "other-ip")
ZP_DISCARD = {"ip-spoof": "discard-ip-spoof", "malformed-option": "discard-malformed-option", "strict-ip-check": "strict-ip-check"}


def _zp_used(v: FwView) -> bool:
    return any(z.zone_protection for z in v.zones)


def zone_protection(v: FwView) -> El | None:
    """The zone protection profile, when a zone of this lab carries it."""
    p = v.fw.profiles
    if p is None or not p.zone_protection or not _zp_used(v):
        return None
    floods = []
    for kind in ZP_FLOODS:
        f = p.zp_flood.get(kind)
        if not f:
            continue
        act = "syn-cookies" if kind == "tcp-syn" and f.get("action", "red") == "syn-cookies" else "red"
        floods.append(El(kind, leaf("enable", "yes"),
                         El(act, leaf("alarm-rate", f["alarm"]), leaf("activate-rate", f["activate"]), leaf("maximal-rate", f["maximal"]))))
    disc = []
    for d in p.zp_discard:
        if d not in ZP_DISCARD:
            raise ValueError(f"zone protection: discard option {d!r} is not rendered (have {', '.join(sorted(ZP_DISCARD))})")
        disc.append(leaf(ZP_DISCARD[d], "yes"))
    return entry(p.zone_protection, El("flood", *floods) if floods else None, *disc)


def _zp_lines(v: FwView) -> list:
    p = v.fw.profiles
    if p is None or not p.zone_protection or not _zp_used(v):
        return []
    q = f"set network profiles zone-protection-profile {_val(p.zone_protection)}"
    out = []
    for kind in ZP_FLOODS:
        f = p.zp_flood.get(kind)
        if not f:
            continue
        act = "syn-cookies" if kind == "tcp-syn" and f.get("action", "red") == "syn-cookies" else "red"
        out.append(f"{q} flood {kind} enable yes")
        for k, n in (("alarm", "alarm-rate"), ("activate", "activate-rate"), ("maximal", "maximal-rate")):
            out.append(f"{q} flood {kind} {act} {n} {f[k]}")
    out.extend(f"{q} {ZP_DISCARD[d]} yes" for d in p.zp_discard)
    return out


def ike_crypto(v: FwView) -> El | None:
    """The IKE and IPsec crypto profiles the lab's tunnels use."""
    if not v.vpns:
        return None
    used = {x.ike_crypto for x in v.vpns} | {x.ipsec_crypto for x in v.vpns}
    ike, esp = [], []
    for c in v.fw.crypto:
        if c.name not in used:
            continue
        if c.kind == "ike":
            ike.append(entry(c.name, members("hash", c.hash), members("dh-group", [c.dh]), members("encryption", c.encryption),
                             El("lifetime", leaf("hours", c.lifetime_h))))
        else:
            esp.append(entry(c.name, El("esp", members("authentication", c.hash), members("encryption", c.encryption)),
                             leaf("dh-group", c.dh), El("lifetime", leaf("hours", c.lifetime_h))))
    return El("ike", El("crypto-profiles", El("ike-crypto-profiles", *ike) if ike else None,
                        El("ipsec-crypto-profiles", *esp) if esp else None))


def _crypto_lines(v: FwView) -> list:
    if not v.vpns:
        return []
    used = {x.ike_crypto for x in v.vpns} | {x.ipsec_crypto for x in v.vpns}
    out = []
    for c in v.fw.crypto:
        if c.name not in used:
            continue
        if c.kind == "ike":
            q = f"set network ike crypto-profiles ike-crypto-profiles {c.name}"
            out += [f"{q} hash {_list(c.hash)}", f"{q} dh-group {c.dh}", f"{q} encryption {_list(c.encryption)}", f"{q} lifetime hours {c.lifetime_h}"]
        else:
            q = f"set network ike crypto-profiles ipsec-crypto-profiles {c.name}"
            out += [f"{q} esp authentication {_list(c.hash)}", f"{q} esp encryption {_list(c.encryption)}", f"{q} dh-group {c.dh}",
                    f"{q} lifetime hours {c.lifetime_h}"]
    return out


GW_XPATH = "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
TUNNEL_XPATH = "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"


def ike_gateway(x: FwVpn, key: str = PSK_PLACEHOLDER) -> El:
    """An IKEv2 gateway; key is the placeholder unless boot fills it in at send time."""
    return entry(
        x.name,
        El("authentication", El("pre-shared-key", leaf("key", key))),
        El("protocol", El("ikev2", El("dpd", leaf("enable", "yes")), leaf("ike-crypto-profile", x.ike_crypto)), leaf("version", "ikev2")),
        El("local-address", leaf("interface", x.interface), leaf("ip", x.local)),
        El("peer-address", leaf("ip", x.peer)),
        El("local-id", leaf("id", _bare(x.local.split("/")[0] + "/32")), leaf("type", "ipaddr")),
        El("peer-id", leaf("id", x.peer), leaf("type", "ipaddr")),
    )


def ipsec_tunnel(x: FwVpn) -> El:
    pids = [entry(n, leaf("local", lo), leaf("remote", re_), El("protocol", El("any"))) for n, lo, re_ in x.proxy_ids]
    return entry(x.name, El("auto-key", El("ike-gateway", entry(x.name)), leaf("ipsec-crypto-profile", x.ipsec_crypto),
                            El("proxy-id", *pids)), leaf("tunnel-interface", x.tunnel_interface))


def _vpn_lines(v: FwView) -> list:
    """The gateways' and tunnels' set lines, as the running configuration prints them once boot has
    set them (the key line is left out: PAN-OS prints it encrypted)."""
    out = []
    for x in v.vpns:
        q = f"set network ike gateway {x.name}"
        out += [f"{q} protocol ikev2 dpd enable yes", f"{q} protocol ikev2 ike-crypto-profile {x.ike_crypto}", f"{q} protocol version ikev2",
                f"{q} local-address interface {x.interface}", f"{q} local-address ip {x.local}", f"{q} peer-address ip {x.peer}",
                f"{q} local-id id {x.local.split('/')[0]}", f"{q} local-id type ipaddr", f"{q} peer-id id {x.peer}", f"{q} peer-id type ipaddr"]
        t = f"set network tunnel ipsec {x.name}"
        out += [f"{t} auto-key ike-gateway {x.name}", f"{t} auto-key ipsec-crypto-profile {x.ipsec_crypto}"]
        for n, lo, re_ in x.proxy_ids:
            out += [f"{t} auto-key proxy-id {n} local {lo}", f"{t} auto-key proxy-id {n} remote {re_}", f"{t} auto-key proxy-id {n} protocol any"]
        out.append(f"{t} tunnel-interface {x.tunnel_interface}")
    return out


def vpn_plan(m: Model, v: FwView) -> str:
    """bootstrap/fw/vpn.json: what boot sets through the API, in order, then commits."""
    import json  # noqa: PLC0415

    steps = []
    for x in v.vpns:
        steps.append({"what": f"IKE gateway {x.name}", "xpath": GW_XPATH, "element": xml(ike_gateway(x)), "psk": x.psk,
                      "placeholder": PSK_PLACEHOLDER})
        steps.append({"what": f"IPsec tunnel {x.name}", "xpath": TUNNEL_XPATH, "element": xml(ipsec_tunnel(x))})
    doc = {"lab": m.lab, "firewall": v.fw.name, "steps": steps,
           "tunnels": [{"name": x.name, "gateway": x.name, "peer": x.peer, "peer_node": x.peer_node, "psk": x.psk,
                        "proxy_ids": [list(p) for p in x.proxy_ids]} for x in v.vpns]}
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def interfaces(v: FwView) -> El:
    eth, agg = [], []
    for i in sorted((i for i in v.interfaces if i.kind in ("aggregate-member", "layer3")), key=lambda i: _eth_order(i.name)):
        if i.kind == "aggregate-member":
            eth.append(entry(i.name, leaf("aggregate-group", i.parent)))
        else:
            eth.append(entry(i.name, El("layer3", *_l3_kids(i, v.profile_of(i.name)))))
    for a in (i for i in v.interfaces if i.kind == "aggregate"):
        lacp = a.lacp or {}
        units = [entry(u.name, leaf("tag", u.tag), *_l3_kids(u, v.profile_of(u.name)))
                 for u in v.interfaces if u.kind == "subinterface" and u.parent == a.name]
        layer3 = El(
            "layer3",
            leaf("mtu", a.mtu) if a.mtu else None,
            El("lacp", leaf("enable", "yes"), leaf("mode", lacp.get("mode", "active")),
               leaf("transmission-rate", lacp.get("rate", "fast"))) if lacp else None,
            El("units", *units) if units else None,
        )
        agg.append(entry(a.name, layer3))
    tun = [entry(i.name, leaf("interface-management-profile", v.profile_of(i.name)), leaf("mtu", i.mtu) if i.mtu else None)
           for i in v.interfaces if i.kind == "tunnel"]
    return El("interface", El("ethernet", *eth) if eth else None, El("aggregate-ethernet", *agg) if agg else None,
              El("tunnel", El("units", *tun)) if tun else None)


def _eth_order(name: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"([0-9]+)", name)]


def virtual_router(v: FwView) -> El:
    statics = []
    for r in v.routes:
        if r.kind == "discard":
            statics.append(entry(r.name, leaf("destination", r.dest), El("nexthop", El("discard")),
                                 leaf("metric", r.metric) if r.metric is not None else None))
        elif r.kind == "interface":
            statics.append(entry(r.name, leaf("destination", r.dest), leaf("interface", r.interface),
                                 leaf("metric", r.metric) if r.metric is not None else None))
        else:
            statics.append(entry(r.name, leaf("destination", r.dest), leaf("interface", r.interface),
                                 El("nexthop", leaf("ip-address", r.nexthop)), leaf("metric", r.metric) if r.metric is not None else None))
    rt = El("routing-table", El("ip", El("static-route", *statics))) if statics else None
    return El("virtual-router", entry(v.fw.vr, members("interface", v.l3), rt))


def deviceconfig(v: FwView) -> El:
    system = El(
        "system",
        leaf("hostname", v.fw.hostname),
        leaf("timezone", TIMEZONE),
        El("dns-setting", El("servers", leaf("primary", v.dns[0]), leaf("secondary", v.dns[1]) if len(v.dns) > 1 else None)) if v.dns else None,
        El("ntp-servers", *(El(slot, leaf("ntp-server-address", a)) for slot, a in zip(("primary-ntp-server", "secondary-ntp-server"), v.ntp))) if v.ntp else None,
        El("route", El("service", *(entry(s.service, El("source", leaf("interface", s.interface), leaf("address", s.address)))
                                    for s in v.service_routes))) if v.service_routes else None,
    )
    setting = El(
        "setting",
        El("management", leaf("idle-timeout", IDLE_TIMEOUT)),
        leaf("auto-mac-detect", AUTO_MAC_DETECT),
        El("jumbo-frame", leaf("mtu", v.jumbo)) if v.jumbo else None,
    )
    return El("deviceconfig", system, setting)


def _zp_of(v: FwView, z: Zone) -> str | None:
    p = v.fw.profiles
    return z.zone_protection if (z.zone_protection and p is not None and p.zone_protection == z.zone_protection) else None


def _used_objects(v: FwView) -> tuple[list, list]:
    """The address objects and groups this lab's rules name, and the objects the groups hold."""
    names = {mm for r in v.rules for mm in r.src_members + r.dst_members}
    groups = [g for g in v.fw.groups if g.name in names]
    held = names | {mm for g in groups for mm in g.members}
    return [a for a in v.fw.addresses if a.name in held], groups


def _profile_group(v: FwView):
    p = v.fw.profiles
    if p is None or not p.group or not any(r.profile_group == p.group for r in v.rules):
        return None
    return p


def vsys(v: FwView) -> El:
    zones = [entry(z.name, El("network", members("layer3", z.interfaces),
                              leaf("zone-protection-profile", _zp_of(v, z)) if _zp_of(v, z) else None)) for z in v.zones]
    svcs = [entry(s.name, El("protocol", El(s.protocol, leaf("port", s.port)))) for s in v.services]
    defaults = [entry(k, leaf("action", d.get("action", "deny")), leaf("log-start", "no"), leaf("log-end", "yes" if d.get("log_end", True) else "no"))
                for k, d in v.fw.default_rules.items()] if v.rules else []
    rb = El("rulebase",
            El("security", El("rules", *(rule(r) for r in v.rules))) if v.rules else None,
            El("nat", El("rules", *(nat_rule(n) for n in v.nat))) if v.nat else None,
            El("default-security-rules", El("rules", *defaults)) if defaults else None)
    addrs, groups = _used_objects(v)
    ao = [entry(a.name, leaf("ip-netmask", a.prefix), leaf("description", a.desc) if a.desc else None) for a in addrs]
    go = [entry(g.name, members("static", g.members), leaf("description", g.desc) if g.desc else None) for g in groups]
    pg = _profile_group(v)
    pge = None
    if pg is not None:
        pge = El("profile-group", entry(pg.group, members("virus", [pg.virus]) if pg.virus else None,
                                        members("spyware", [pg.spyware]) if pg.spyware else None,
                                        members("vulnerability", [pg.vulnerability]) if pg.vulnerability else None,
                                        members("file-blocking", [pg.file_blocking]) if pg.file_blocking else None))
    return El("vsys", entry(
        VSYS,
        El("import", El("network", members("interface", v.l3))) if v.l3 else None,
        El("zone", *zones) if zones else None,
        El("address", *ao) if ao else None,
        El("address-group", *go) if go else None,
        El("service", *svcs) if svcs else None,
        pge,
        rb if rb.kids else None,
    ))


def fw_xml(m: Model, v: FwView | None = None) -> str:
    v = v or view(m)
    if v is None:
        raise ValueError(f"{m.lab} has no firewall")
    version, detail = config_version(v.fw.image)
    network = El(
        "network",
        profiles(v),
        interfaces(v),
        ike_crypto(v),
        virtual_router(v),
    )
    root = El("config", El("devices", entry(DEVICE, deviceconfig(v), network, vsys(v))),
              attrs=(("version", version), ("urldb", "paloaltonetworks"), ("detail-version", detail)))
    return xml(root) + "\n"


# --------------------------------------------------------------------------------------------
# Set format, as PAN-OS prints `show` in configure mode after `set cli config-output-format set`


def _val(v) -> str:
    s = str(v)
    return f'"{s}"' if (" " in s or not s) else s


def _list(values) -> str:
    vals = [_val(x) for x in values]
    return vals[0] if len(vals) == 1 else "[ " + " ".join(vals) + " ]"


def set_lines(v: FwView) -> list[str]:
    fw = v.fw
    out: list[str] = []
    sysp = "set deviceconfig system"
    out.append(f"{sysp} hostname {_val(fw.hostname)}")
    out.append(f"{sysp} timezone {TIMEZONE}")
    for slot, a in zip(("primary", "secondary"), v.dns):
        out.append(f"{sysp} dns-setting servers {slot} {a}")
    for slot, a in zip(("primary-ntp-server", "secondary-ntp-server"), v.ntp):
        out.append(f"{sysp} ntp-servers {slot} ntp-server-address {a}")
    for s in v.service_routes:
        out.append(f"{sysp} route service {s.service} source interface {s.interface}")
        out.append(f"{sysp} route service {s.service} source address {s.address}")
    out.append(f"set deviceconfig setting management idle-timeout {IDLE_TIMEOUT}")
    out.append(f"set deviceconfig setting auto-mac-detect {AUTO_MAC_DETECT}")
    if v.jumbo:
        out.append(f"set deviceconfig setting jumbo-frame mtu {v.jumbo}")
    out.append(f"set network profiles interface-management-profile {PING_PROFILE} ping yes")
    if v.admin is not None:
        q = f"set network profiles interface-management-profile {v.admin.profile}"
        out.extend(f"{q} {s} yes" for s in ADMIN_ORDER if s in v.admin.allow)
        out.extend(f"{q} permitted-ip {c}" for c in v.admin.permitted_cidrs)
    out.extend(_zp_lines(v))
    eth = "set network interface ethernet"
    for i in sorted((i for i in v.interfaces if i.kind in ("aggregate-member", "layer3")), key=lambda i: _eth_order(i.name)):
        if i.kind == "aggregate-member":
            out.append(f"{eth} {i.name} aggregate-group {i.parent}")
        else:
            out.extend(_l3_lines(f"{eth} {i.name} layer3", i, v.profile_of(i.name)))
    for a in (i for i in v.interfaces if i.kind == "aggregate"):
        p = f"set network interface aggregate-ethernet {a.name} layer3"
        if a.mtu:
            out.append(f"{p} mtu {a.mtu}")
        if a.lacp:
            out.append(f"{p} lacp enable yes")
            out.append(f"{p} lacp mode {a.lacp.get('mode', 'active')}")
            out.append(f"{p} lacp transmission-rate {a.lacp.get('rate', 'fast')}")
        for u in v.interfaces:
            if u.kind == "subinterface" and u.parent == a.name:
                out.append(f"{p} units {u.name} tag {u.tag}")
                out.extend(_l3_lines(f"{p} units {u.name}", u, v.profile_of(u.name)))
    for i in v.interfaces:
        if i.kind == "tunnel":
            out.append(f"set network interface tunnel units {i.name} interface-management-profile {v.profile_of(i.name)}")
            if i.mtu:
                out.append(f"set network interface tunnel units {i.name} mtu {i.mtu}")
    out.extend(_crypto_lines(v))
    vr = f"set network virtual-router {fw.vr}"
    if v.l3:
        out.append(f"{vr} interface {_list(v.l3)}")
    for r in v.routes:
        q = f"{vr} routing-table ip static-route {r.name}"
        out.append(f"{q} destination {r.dest}")
        if r.kind == "discard":
            out.append(f"{q} nexthop discard")
        else:
            out.append(f"{q} interface {r.interface}")
            if r.kind == "ip":
                out.append(f"{q} nexthop ip-address {r.nexthop}")
        if r.metric is not None:
            out.append(f"{q} metric {r.metric}")
    for z in v.zones:
        out.append(f"set zone {z.name} network layer3 {_list(z.interfaces)}")
        if _zp_of(v, z):
            out.append(f"set zone {z.name} network zone-protection-profile {_zp_of(v, z)}")
    addrs, groups = _used_objects(v)
    for a in addrs:
        out.append(f"set address {a.name} ip-netmask {a.prefix}")
        if a.desc:
            out.append(f"set address {a.name} description {_val(a.desc)}")
    for g in groups:
        out.append(f"set address-group {g.name} static {_list(g.members)}")
        if g.desc:
            out.append(f"set address-group {g.name} description {_val(g.desc)}")
    pg = _profile_group(v)
    if pg is not None:
        for k, val in (("virus", pg.virus), ("spyware", pg.spyware), ("vulnerability", pg.vulnerability), ("file-blocking", pg.file_blocking)):
            if val:
                out.append(f"set profile-group {pg.group} {k} {_val(val)}")
    for s in v.services:
        out.append(f"set service {s.name} protocol {s.protocol} port {s.port}")
    for r in v.rules:
        q = f"set rulebase security rules {r.name}"
        out.append(f"{q} from {_list(r.from_zones)}")
        out.append(f"{q} to {_list(r.to_zones)}")
        out.append(f"{q} source {_list(_side(r.src_members, r.src_cidrs))}")
        out.append(f"{q} destination {_list(_side(r.dst_members, r.dst_cidrs))}")
        out.append(f"{q} application {_list(r.applications)}")
        out.append(f"{q} service {_list(r.services)}")
        out.append(f"{q} action {r.action}")
        out.append(f"{q} log-end {'yes' if r.log_end else 'no'}")
        if r.profile_group:
            out.append(f"{q} profile-setting group {r.profile_group}")
        d = description(r.decision, r.desc)
        if d:
            out.append(f"{q} description {_val(d)}")
    for n in v.nat:
        q = f"set rulebase nat rules {n.name}"
        out.append(f"{q} from {_list(n.from_zones)}")
        out.append(f"{q} to {_list(n.to_zones)}")
        out.append(f"{q} source {_list([_bare(c) for c in n.src_cidrs])}")
        out.append(f"{q} destination {_list([_bare(c) for c in n.dst_cidrs])}")
        out.append(f"{q} service {n.service}")
        if n.dnat:
            out.append(f"{q} destination-translation translated-address {n.dnat}")
            if n.dnat_port:
                out.append(f"{q} destination-translation translated-port {n.dnat_port}")
        if n.snat_interface:
            out.append(f"{q} source-translation {n.snat_type or 'dynamic-ip-and-port'} interface-address interface {n.snat_interface}")
        d = description(n.decision, None)
        if d:
            out.append(f"{q} description {_val(d)}")
    if v.rules:
        for k, d in v.fw.default_rules.items():
            q = f"set rulebase default-security-rules rules {k}"
            out += [f"{q} action {d.get('action', 'deny')}", f"{q} log-start no", f"{q} log-end {'yes' if d.get('log_end', True) else 'no'}"]
    if v.l3:
        out.append(f"set import network interface {_list(v.l3)}")
    out.extend(_vpn_lines(v))
    return out


def _l3_lines(p: str, i: FwInterface, profile: str = PING_PROFILE) -> list[str]:
    out = []
    if i.address:
        out.append(f"{p} ip {i.address}")
    if i.mtu:
        out.append(f"{p} mtu {i.mtu}")
    out.append(f"{p} interface-management-profile {profile}")
    if i.mss_adjust:
        out.append(f"{p} adjust-tcp-mss enable yes")
        out.append(f"{p} adjust-tcp-mss ipv4-mss-adjustment {i.mss_adjust}")
    return out


def normalize(line: str) -> str:
    """How a set line is compared: trailing spaces removed and runs of spaces folded. PAN-OS
    prints an address entry with a trailing space (`... ip 10.20.1.1/24 `)."""
    return " ".join(line.split())


def enforced(m: Model, ctx=None, v: FwView | None = None) -> str:
    v = v or view(m)
    if v is None:
        raise ValueError(f"{m.lab} has no firewall")
    src = ctx.profile_file(m) if ctx is not None else f"spec/profile-{m.profile}.yaml"
    head = [
        f"# {m.lab} {v.fw.name}: set-format lines the running configuration must hold after the startup commit.",
        f"# Rendered from {src} beside {XML_PATH}; edit the spec and run make render.",
        "# Compare each line after removing trailing spaces and folding runs of spaces into one;",
        "# lines starting with # and blank lines are comments. Rule order is not checked here.",
    ]
    if v.vpns:
        head.append(f"# The IKE gateway and IPsec tunnel lines at the end are set by boot from {VPN_PATH} after the startup commit,")
        head.append("# with the pre-shared key from state/secrets/ipsec (its line, printed encrypted, is not listed).")
    if v.omitted:
        head.append("# Not in this lab:")
        head.extend(f"#   {x}" for x in v.omitted)
    return "\n".join(head + set_lines(v)) + "\n"


def render(model: Model, ctx) -> dict:
    v = view(model)
    if v is None:
        return {}
    out = {XML_PATH: fw_xml(model, v), ENFORCED_PATH: enforced(model, ctx, v)}
    if v.vpns:
        out[VPN_PATH] = vpn_plan(model, v)
    return out
