"""bootstrap/<sw>/startup-config.cfg: the KLISH startup file of every SONiC switch (FRAMEWORK.md 2.3).

The patched launcher types the file into sonic-cli line by line, skipping blank lines and lines
that start with "!", then types `end` and `write memory` itself. So comments (the header, the
decision ids, the mtu floor) ride as "!" lines, and the file ends with `end`.

There is one function per role, so a chapter can print the tree as it stands: role_mclag_member,
role_rail_vlan and role_oob_access for build A. Each is built from the helpers head(), vlans(),
portchannel(), member(), access_port() and mclag_domain(), and every line they emit is a form
SONiC 4.6.0's KLISH accepted (the accepted forms are pinned in tests/test_switches.py). Interface
names are native: container ethN is ports.native(N).

Order for an MCLAG member: the head block (configure terminal, ip vrf mgmt, end) as its own
session; then the spanning-tree mode; the VLANs; the keepalive VRF and the backup keepalive's VLAN
interface with its address; the peer link PortChannel and its members; the dedicated keepalive
link, routed in the keepalive VRF; the MCLAG domain, after the VLAN interface its backup keepalive
names and before any `mclag <id>` line; mclag-separate-ip on the backup VLAN interface, which
SONiC 4.6.0 takes only once the domain exists; the firewall's PortChannel; the hosts' PortChannels, each followed by its members; the single-attached
access ports. Every used port gets `no shutdown`, since the factory profile leaves all 56 ports
admin down.

The l2 policy (spec l2:) adds, where the model sets it: an mtu on every PortChannel and member
(a member's before its channel-group) and on every access port; `spanning-tree portfast` and
`spanning-tree bpduguard port-shutdown` on each host-facing PortChannel and rail access port; and
storm control on each member of those PortChannels and on those access ports (SONiC 4.6.0 refuses
it on a PortChannel). Every form here was accepted on SONiC 4.6.0 in chapter 3's lab, and is
pinned in tests/test_switches.py.
"""

from __future__ import annotations

from .. import ports
from ..klish_lint import lint as _lint
from ..model import Model, Switch
from . import RenderError


def lint(lines) -> list:
    """The KLISH lint `sfab lint` runs on each rendered file (sfab.klish_lint.lint)."""
    return _lint(lines)


# --------------------------------------------------------------------------------------------
# Helpers. Each returns a list of lines.


def head(model: Model, sw: Switch, ctx) -> list:
    """The header comment and the management VRF block, typed first and on its own."""
    return [
        f"! {model.lab} {sw.name}: rendered from {ctx.profile_file(model)}; edit the spec and run make render",
        "configure terminal",
        f"ip vrf {sw.mgmt_vrf}",
        "end",
    ]


def vlans(ids) -> list:
    """`interface Vlan N` with no address creates the VLAN only (no VLAN interface entry)."""
    out = []
    for v in sorted(ids):
        out += [f"interface Vlan {int(v)}", "exit"]
    return out


def _desc(desc: str) -> str:
    d = str(desc or "").strip()
    if not d or any(c.isspace() for c in d) or "?" in d:
        raise RenderError(f"description {desc!r}: descriptions are one word with no space and no '?'")
    return f"description {d}"


def _vlan_list(vs) -> str:
    """The allowed list as SONiC 4.6.0's running configuration prints it: ascending, with every run
    of two or more consecutive VLANs folded into a range (100,130-131,200), so parity compares it
    line for line."""
    out, run = [], []
    for v in sorted({int(x) for x in vs}):
        if run and v == run[-1] + 1:
            run.append(v)
            continue
        if run:
            out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
        run = [v]
    if run:
        out.append(f"{run[0]}-{run[-1]}" if len(run) > 1 else str(run[0]))
    return ",".join(out)


def _edge() -> list:
    """An edge port under PVST: forwarding at once, and shut on the first BPDU it receives."""
    return ["spanning-tree portfast", "spanning-tree bpduguard port-shutdown"]


def _storm(storm) -> list:
    """Storm control lines, `storm-control <type> <kbps>` (the number follows the type directly)."""
    return [f"storm-control {t} {int(k)}" for t, k in storm]


def portchannel(id: int, desc: str, mode: str, vlans, mclag: int | None = None, mtu: int | None = None, tagged=(),
                edge: bool = False) -> list:
    """A PortChannel: fast LACP, optional `mclag <domain>`, an access VLAN or a trunk, admin up.

    mode is "access" (vlans holds the one VLAN) or "trunk" (the allowed list). An access PortChannel
    may carry tagged VLANs beside its untagged one (a host's VLAN units: SONiC 4.6.0 takes
    `switchport trunk allowed Vlan` on an access port, as the live switch showed). mtu None keeps the factory 9100
    and writes no mtu line.
    """
    vs = tuple(vlans)
    out = [f"interface PortChannel {int(id)}", _desc(desc)]
    if mtu is not None:
        out.append(f"mtu {int(mtu)}")
    out.append("fast_rate")
    if mclag is not None:
        out.append(f"mclag {int(mclag)}")
    if mode == "trunk":
        out.append(f"switchport trunk allowed Vlan {_vlan_list(vs)}")
    elif mode == "access":
        if len(vs) != 1:
            raise RenderError(f"PortChannel {id}: an access PortChannel carries one VLAN, not {vs}")
        out.append(f"switchport access Vlan {int(vs[0])}")
        if tagged:
            out.append(f"switchport trunk allowed Vlan {_vlan_list(tagged)}")
    else:
        raise RenderError(f"PortChannel {id}: mode {mode!r} is neither access nor trunk")
    if edge:
        out += _edge()
    out += ["no shutdown", "exit"]
    return out


def member(eth, pc: int, desc: str, mtu: int | None = None, storm=()) -> list:
    """A PortChannel member port. Its mtu, when the PortChannel sets one, goes before channel-group;
    storm control, which SONiC 4.6.0 takes on a member and not on the PortChannel, after it."""
    out = [f"interface {ports.native(eth)}", _desc(desc)]
    if mtu is not None:
        out.append(f"mtu {int(mtu)}")
    out.append(f"channel-group {int(pc)}")
    out += _storm(storm)
    out += ["no shutdown", "exit"]
    return out


def access_port(eth, vlan: int, desc: str, mtu: int | None = None, edge: bool = False, storm=()) -> list:
    """An untagged access port in one VLAN, admin up; mtu None keeps the factory 9100."""
    out = [f"interface {ports.native(eth)}", _desc(desc)]
    if mtu is not None:
        out.append(f"mtu {int(mtu)}")
    out.append(f"switchport access Vlan {int(vlan)}")
    if edge:
        out += _edge()
    out += _storm(storm)
    out += ["no shutdown", "exit"]
    return out


def keepalive_backup(ka) -> list:
    """The keepalive VRF and the backup keepalive's VLAN interface (a model Keepalive), carried on
    the peer link only: VRF before address, and both before the domain, whose backup-keepalive lines
    name the address."""
    out = [f"ip vrf {ka.vrf}"]
    if ka.backup_vlan is None:
        return out
    return out + [
        f"interface Vlan {int(ka.backup_vlan)}",
        "description mclag-backup-keepalive",
        f"ip vrf forwarding {ka.vrf}",
        f"ip address {ka.backup_address}",
        "exit",
    ]


def keepalive_separate_ip(ka) -> list:
    """mclag-separate-ip on the backup VLAN interface, so the standby's end keeps its own MAC
    (without it both ends carry the active's and never answer each other, the keepalive probe).
    SONiC 4.6.0 refuses it until the MCLAG domain exists ("%Error: mclag not configured", the first
    revision 2 boot), so it follows the domain."""
    if ka.backup_vlan is None:
        return []
    return [f"interface Vlan {int(ka.backup_vlan)}", "mclag-separate-ip", "exit"]


def keepalive_link(ka) -> list:
    """The dedicated keepalive link: a routed port in the keepalive VRF, VRF before address."""
    out = [f"interface {ka.native}", "description mclag-keepalive"]
    if ka.mtu is not None:
        out.append(f"mtu {int(ka.mtu)}")
    return out + [f"ip vrf forwarding {ka.vrf}", f"ip address {ka.address}", "no shutdown", "exit"]


def mclag_domain(dom) -> list:
    """The MCLAG domain (a model MclagDomain). It goes after the peer link exists and before any
    `mclag <id>` line. The session runs on the dedicated keepalive link in the keepalive VRF; the
    backup keepalive, when there is one, on the peer link's VLAN interface in the same VRF. It is
    never deleted and re-created."""
    out = [
        f"mclag domain {int(dom.domain)}",
        f"source-ip {dom.source_ip}",
        f"peer-ip {dom.peer_ip}",
        f"peer-link PortChannel {int(dom.peer_link_pc)}",
        f"mclag-system-mac {dom.system_mac}",
        f"session-vrf {dom.session_vrf}",
    ]
    if dom.backup_source_ip:
        out += [
            f"backup-keepalive source-ip {dom.backup_source_ip}",
            f"backup-keepalive peer-ip {dom.backup_peer_ip}",
            f"backup-keepalive session-vrf {dom.backup_vrf}",
            f"backup-keepalive interval {int(dom.backup_interval or 1)}",
        ]
    return out + ["exit"]


def _decision(decision: str | None, what: str) -> list:
    return [f"! decision {decision}: {what}"] if decision else []


def _fw_floor(model: Model, pc) -> int | None:
    """The highest MTU of the firewall units behind the aggregate a PortChannel faces."""
    fw = model.firewall
    if fw is None or pc.peer_node != fw.name:
        return None
    fw_eths = {mb.peer.eth for mb in pc.members}
    floor = 0
    for agg in fw.interfaces:
        if agg.kind != "aggregate":
            continue
        if not any((fw.interface(x) is not None and fw.interface(x).eth in fw_eths) for x in agg.members):
            continue
        floor = max(floor, agg.mtu or 0)
        for u in fw.interfaces:
            if u.parent == agg.name and u.mtu:
                floor = max(floor, u.mtu)
    return floor or None


def _fw_units(model: Model, pc) -> list:
    fw = model.firewall
    if fw is None:
        return []
    fw_eths = {mb.peer.eth for mb in pc.members}
    out = []
    for agg in fw.interfaces:
        if agg.kind == "aggregate" and any((fw.interface(x) is not None and fw.interface(x).eth in fw_eths) for x in agg.members):
            out += [u.name for u in fw.interfaces if u.parent == agg.name and u.kind == "subinterface"]
    return out


def _pc_block(model: Model, sw: Switch, pc) -> list:
    out = []
    what = f"{pc.name}, {pc.desc}"
    out += _decision(pc.decision, what)
    floor = _fw_floor(model, pc)
    if floor:
        units = " ".join(_fw_units(model, pc)) or pc.peer_node
        out.append(f"! mtu-floor {floor}: {pc.peer_node} {units}")
    dom = sw.mclag.domain if (pc.mclag and sw.mclag is not None) else None
    if pc.mclag and dom is None:
        raise RenderError(f"{sw.name}: {pc.name} is an MCLAG PortChannel but the switch has no MCLAG domain in this lab")
    out += portchannel(pc.id, pc.desc, pc.mode, pc.vlans, mclag=dom, mtu=pc.mtu, tagged=pc.tagged, edge=pc.edge)
    for mb in pc.members:
        out += member(mb.eth, pc.id, mb.desc, mtu=pc.mtu, storm=pc.storm)
    return out


def _stp(sw: Switch) -> list:
    return [f"spanning-tree mode {sw.stp}"] if sw.stp else []


def _access(sw: Switch) -> list:
    out = []
    for ap in sw.access_ports:
        out += _decision(ap.decision, f"{ap.native}, {ap.desc}")
        out += access_port(ap.eth, ap.vlan, ap.desc, mtu=ap.mtu, edge=ap.edge, storm=ap.storm)
    return out


# --------------------------------------------------------------------------------------------
# Roles, build A


def role_mclag_member(model: Model, sw: Switch, ctx) -> list:
    """An MCLAG pair member with no gateway: VLANs with no address, the peer link, the domain,
    then the MCLAG PortChannels (firewall trunk first, then the hosts) and the access ports."""
    out = head(model, sw, ctx)
    out.append(f"! role mclag_member: pair {sw.pair}, Layer 2 only, every gateway on the firewall")
    out.append("configure terminal")
    out += _stp(sw)
    out += vlans(sw.vlans)
    peer_links = [p for p in sw.portchannels if p.kind == "peer-link"]
    others = [p for p in sw.portchannels if p.kind != "peer-link"]
    if sw.keepalive is not None:
        out.append(f"! the keepalive VRF {sw.keepalive.vrf}; the backup keepalive on Vlan{sw.keepalive.backup_vlan}, peer link only")
        out += keepalive_backup(sw.keepalive)
    for pc in peer_links:
        out += _pc_block(model, sw, pc)
    if sw.keepalive is not None:
        out.append(f"! the dedicated keepalive link, routed in {sw.keepalive.vrf}, to {sw.keepalive.peer_address}")
        out += keepalive_link(sw.keepalive)
    if sw.mclag is not None:
        out.append("! the domain comes before any mclag line and is never deleted and re-created")
        out += mclag_domain(sw.mclag)
        if sw.keepalive is not None and sw.keepalive.backup_vlan is not None:
            out.append("! mclag-separate-ip once the domain exists")
            out += keepalive_separate_ip(sw.keepalive)
    # The firewall's trunk first, then the hosts, each in PortChannel order.
    fw = model.firewall
    fw_name = fw.name if fw else None
    for pc in sorted(others, key=lambda p: (p.peer_node != fw_name, p.id)):
        out += _pc_block(model, sw, pc)
    out += _access(sw)
    out.append("end")
    return out


def role_rail_vlan(model: Model, sw: Switch, ctx) -> list:
    """A standalone rail switch: one VLAN per rail it carries, no address, no router, no
    uplink; one access port per GPU node per rail (at 9216, an edge port with storm control, under
    the l2 policy)."""
    out = head(model, sw, ctx)
    rails = ", ".join(str(r) for r in sw.rails)
    out.append(f"! role rail_vlan: rails {rails} as plain VLANs, no address, no router, no uplink")
    out.append("configure terminal")
    out += _stp(sw)
    out += vlans(sw.vlans)
    out += _access(sw)
    out.append("end")
    return out


def role_oob_access(model: Model, sw: Switch, ctx) -> list:
    """The out-of-band access switch: one flat BMC VLAN, one access port per attached node."""
    out = head(model, sw, ctx)
    out.append(f"! role oob_access: VLAN {sw.oob_vlan}, one flat BMC VLAN, no address")
    out.append("configure terminal")
    out += vlans(sw.vlans)
    out += _access(sw)
    out.append("end")
    return out


ROLES = {
    "mclag_member": role_mclag_member,
    "rail_vlan": role_rail_vlan,
    "oob_access": role_oob_access,
}


def startup_config(model: Model, sw: Switch, ctx) -> str:
    fn = ROLES.get(sw.role)
    if fn is None:
        raise RenderError(f"{sw.name}: no KLISH renderer for role {sw.role!r} (have {', '.join(sorted(ROLES))})")
    lines = fn(model, sw, ctx)
    # a decisions lab (chapter 2 on) labels every switch forwarding only, under the header line
    from .decisions import forwarding_line  # noqa: PLC0415

    fl = forwarding_line(model)
    if fl:
        lines = lines[:1] + [fl] + lines[1:]
    problems = _lint(lines)
    if problems:
        raise RenderError(f"{sw.name}: the rendered KLISH fails its lint:\n  " + "\n  ".join(problems))
    return "\n".join(lines) + "\n"


def render(model: Model, ctx) -> dict:
    return {f"bootstrap/{name}/startup-config.cfg": startup_config(model, sw, ctx) for name, sw in model.switches.items()}
