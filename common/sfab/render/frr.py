"""FRR routers (kind frr): bootstrap/<router>/frr.conf, daemons, vtysh.conf and init.env
(FRAMEWORK.md sections 2.2 and 5).

Build A has two routers: the uplink router (uplink-rtr, every state) between the firewall's
public address and the operator segment, and the ISP router (isp-rtr, state many from step 9)
between the firewall's ISP link and the internet users. Build B's carrier routers are rendered
here too when chapter 17 lands.

The four files are bound read-only into sfab/frr at /sfab/bootstrap (render/clab.py), and the
image's frr-init.sh links the first three into /etc/frr:

- frr.conf: the router's whole configuration, in the order `show running-config` prints it: the
  global lines, the static routes, then one block per data port with its description and
  address. Only ports wired in this lab are configured. The management port eth0 is not in it:
  frr-init.sh puts eth0 in VRF mgmt with its own default route, so the default table holds only
  the lab's routes. A router therefore has no default route unless the spec gives it one, and a
  packet for an address outside the lab dies at the router instead of leaving through the
  management network.
  Static routes come from the spec (`routes:` on the router), one `ip route` (or `ipv6 route`)
  line each, after a `!` line naming the route's id and decision. The uplink router routes build
  A's inside prefixes to the firewall's public address (from the chapter 4
  lab on): the spec writes each as dest seg:<segment>, via public, so an operator request to an
  inside address reaches the firewall and its deny-all-log line instead of dying here. Such a
  route is rendered only while the firewall gateways that segment in the lab (an interface of it,
  wired here, holds an address in the prefix); otherwise the firewall would send the packet back
  on its default route, and the route is left out with a `!` line saying why. Every other prefix
  on the uplink side, the uplink and the operator /30s, is connected. The ISP router routes the
  public address inward from chapter 9 (198.51.100.2/32 via the firewall's ISP address).
  No port carries an `mtu` line: zebra has no MTU command for a kernel interface, so frr-init.sh
  sets each port's MTU from init.env instead.
- daemons: which FRR daemons watchfrr starts. zebra, mgmtd and staticd always run (FRR's
  frrcommon.sh starts them whatever the file says); every other daemon is off until the spec
  gives a router BGP, OSPF or LDP (build B's carrier, chapter 17).
- vtysh.conf: integrated configuration, so vtysh reads and shows the one frr.conf.
- init.env: what frr-init.sh needs before FRR starts: the data ports to wait for, the
  management address, gateway, VRF and table, forwarding and rp_filter, the MPLS core ports and
  customer VRFs (none in build A), TX checksum offload off on every data port, the lab's domain
  for resolv.conf's search line (SEARCH, render/host.py's dns_env), and the user sshd lets in
  (with the keys the topology binds at /sfab/authorized_keys). Same format as
  render/host.py's env files: one header comment line, then KEY=value lines sorted by key.

Nothing here is a secret. Prose in comments is plain English with no em or en dashes.
"""

from __future__ import annotations

from .. import addr, ports
from ..model import Host, Model
from .host import dns_env, env_file, words

# The daemons file lists every daemon FRR 10.5 knows besides the three it always starts.
ALWAYS = ("zebra", "mgmtd", "staticd")
OPTIONAL = ("bgpd", "ospfd", "ospf6d", "ripd", "ripngd", "isisd", "pimd", "pim6d", "ldpd", "nhrpd",
            "eigrpd", "babeld", "sharpd", "pbrd", "bfdd", "fabricd", "vrrpd", "pathd")
# Every daemon listens on loopback only for its vty; zebra gets a 90 MB netlink receive buffer.
OPTIONS = {
    "zebra": "  -A 127.0.0.1 -s 90000000",
    "mgmtd": "  -A 127.0.0.1",
    "staticd": "-A 127.0.0.1",
    "bgpd": "   -A 127.0.0.1",
    "ospfd": "  -A 127.0.0.1",
    "ospf6d": " -A ::1",
    "ripd": "   -A 127.0.0.1",
    "ripngd": " -A ::1",
    "isisd": "  -A 127.0.0.1",
    "pimd": "   -A 127.0.0.1",
    "pim6d": "  -A ::1",
    "ldpd": "   -A 127.0.0.1",
    "nhrpd": "  -A 127.0.0.1",
    "eigrpd": " -A 127.0.0.1",
    "babeld": " -A 127.0.0.1",
    "sharpd": " -A 127.0.0.1",
    "pbrd": "   -A 127.0.0.1",
    "bfdd": "   -A 127.0.0.1",
    "fabricd": "-A 127.0.0.1",
    "vrrpd": "  -A 127.0.0.1",
    "pathd": "  -A 127.0.0.1",
}

# frr-init.sh waits this long for containerlab to attach the links (FRAMEWORK.md section 5).
LINK_WAIT_S = 180
# The MPLS label space a carrier router opens (net.mpls.platform_labels).
MPLS_LABELS = 1048575
# Every router forwards; rp_filter is off, since a router's return path may use another port.
IP_FORWARD = 1
RP_FILTER = 0

FILES = ("frr.conf", "daemons", "vtysh.conf", "init.env")


class FrrRenderError(ValueError):
    """The model holds something a router's files cannot carry."""


def mgmt_vrf(model: Model) -> str:
    """The management VRF's name: the switches' (common.yaml switch.mgmt_vrf), mgmt."""
    return str((model.common.get("switch") or {}).get("mgmt_vrf") or "mgmt")


def mgmt_table(h: Host) -> int:
    """The management VRF's table: the hosts' management table (common.yaml guest.tables.mgmt)."""
    return int(h.tables.get("mgmt", 150))


def header(model: Model, h: Host, ctx, comment: str = "!") -> str:
    return (f"{comment} {model.lab} {h.name}: rendered from {ctx.profile_file(model)} by render/frr.py; "
            f"edit the spec and run make render")


def wired(h: Host) -> list:
    """The router's addressed data ports wired in this lab, by port number."""
    out = [i for i in h.ifaces if i.peer is not None and i.address]
    return sorted(out, key=lambda i: ports.eth_index(i.eth))


def description(model: Model, i) -> str:
    """The far end of a port, as the switches write theirs: '<node>-<port>' (fw-eth5)."""
    return f"{i.peer.node}-{i.peer.eth}"


def fw_gateways(model: Model, prefix: str) -> bool:
    """True when the lab's firewall holds an address in prefix on an interface wired in this lab:
    the firewall can deliver a packet routed to it for that prefix."""
    fw = model.firewall
    if fw is None:
        return False
    for i in fw.interfaces:
        if i.connected and i.address and i.kind in ("layer3", "subinterface"):
            if addr.contains(prefix, addr.ip(i.address).compressed):
                return True
    return False


def kept_routes(model: Model, h: Host) -> tuple[list, list]:
    """(routes rendered, [(route, reason)] left out). A route the spec wrote as dest seg:<segment>
    via public (a route to an inside prefix) is left out when the firewall does not gateway that
    segment here."""
    keep, out = [], []
    for r in h.routes:
        if r.dest_ref and r.via_ref == "public" and not fw_gateways(model, r.dest):
            out.append((r, f"the firewall gateways no {r.dest} in this lab"))
            continue
        keep.append(r)
    return keep, out


def route_comment(r, model: Model | None = None) -> str:
    """'! <id>: <decision>', or the one that is set. In a decisions lab a route without its own
    decision carries the one the decision table derives for it (render/decisions.py label_of)."""
    dec = r.decision
    if model is not None and not dec:
        from .decisions import label_of  # noqa: PLC0415

        dec = label_of(model, "routing", r.id or r.dest)
    return ": ".join(x for x in (r.id, dec) if x)


def static_routes(model: Model, h: Host, ctx=None, routes=None) -> list:
    """The spec's static routes as FRR lines: 'ip route <prefix> [<next hop>] [<port>]'.

    A next hop must be an address (a symbol such as qemu-user means nothing to FRR), a route
    takes no source address, and a next hop or a port on no wired port of this lab is kept but
    warned about: FRR holds such a route inactive until the port comes. routes defaults to every
    route of the router (kept_routes() narrows it to what the lab renders)."""
    lines = []
    nets = [addr.prefix_of(i.address) for i in wired(h)]
    ports_here = {i.eth for i in wired(h)}
    for r in (h.routes if routes is None else routes):
        dest = str(r.dest)
        name = r.id or dest
        if "/" not in dest:
            raise FrrRenderError(f"{h.name}: route {name}: the destination must be a prefix")
        try:
            family = addr.net(dest).version
        except ValueError as e:
            raise FrrRenderError(f"{h.name}: route {name}: {e}") from None
        if r.src:
            raise FrrRenderError(f"{h.name}: route {name}: FRR static routes take no source address")
        if not r.via and not r.dev:
            raise FrrRenderError(f"{h.name}: route {name}: needs a next hop or a port")
        parts = ["ip route" if family == 4 else "ipv6 route", dest]
        if r.via:
            try:
                hop = addr.ip(r.via)
            except ValueError:
                raise FrrRenderError(f"{h.name}: route {name}: next hop {r.via!r} is not an address") from None
            if hop.version != family:
                raise FrrRenderError(f"{h.name}: route {name}: next hop {r.via} is not in the destination's family")
            parts.append(hop.compressed)
            if ctx is not None and not r.dev and not any(addr.contains(n, r.via) for n in nets if addr.net(n).version == family):
                ctx.warn(f"frr: {h.name}: route {name} via {r.via} is on no port wired in this lab; FRR keeps it inactive")
        if r.dev:
            parts.append(str(r.dev))
            if ctx is not None and r.dev not in ports_here:
                ctx.warn(f"frr: {h.name}: route {name} names port {r.dev}, which is not wired in this lab; FRR keeps it inactive")
        lines.append(" ".join(parts))
    return lines


def frr_conf(model: Model, h: Host, ctx) -> str:
    lines = [
        header(model, h, ctx),
        f"! eth0 is in VRF {mgmt_vrf(model)} (frr-init.sh), so the default table holds only the lab's routes.",
        "! This file is bound read-only: change the spec and run make render, never write memory.",
        "frr defaults traditional",
        f"hostname {h.name}",
        "log stdout informational",
        "service integrated-vtysh-config",
        "!",
    ]
    keep, left = kept_routes(model, h)
    routes = static_routes(model, h, ctx, keep)
    if routes or left:
        for r, line in zip(keep, routes):
            c = route_comment(r, model)
            if c:
                lines.append(f"! {c}")
            lines.append(line)
        for r, why in left:
            lines.append(f"! {route_comment(r, model) or r.dest}: not rendered, {why}")
        lines.append("!")
    for i in wired(h):
        fam = "ip" if addr.iface(i.address).version == 4 else "ipv6"
        lines += [f"interface {i.eth}", f" description {description(model, i)}", f" {fam} address {i.address}", "exit", "!"]
    lines.append("end")
    return "\n".join(lines) + "\n"


def enabled_daemons(model: Model, h: Host) -> set:
    """The optional daemons this router runs. Build A's routers route statically, so none; the
    carrier's BGP, OSPF and LDP are added when chapter 17 puts them in the spec."""
    return set()


def daemons(model: Model, h: Host, ctx) -> str:
    on = enabled_daemons(model, h)
    unknown = on - set(OPTIONAL)
    if unknown:
        raise FrrRenderError(f"{h.name}: unknown FRR daemons {sorted(unknown)}")
    lines = [
        header(model, h, ctx, "#"),
        "# zebra, mgmtd and staticd always run (FRR's frrcommon.sh); every other daemon is listed here.",
    ]
    lines += [f"{d}={'yes' if d in on else 'no'}" for d in OPTIONAL]
    lines.append("vtysh_enable=yes")
    lines += [f'{d}_options="{OPTIONS[d]}"' for d in ALWAYS + OPTIONAL]
    return "\n".join(lines) + "\n"


def vtysh_conf(model: Model, h: Host, ctx) -> str:
    return "\n".join([header(model, h, ctx), "service integrated-vtysh-config"]) + "\n"


def init_env(model: Model, h: Host, ctx) -> str:
    guest = model.common.get("guest") or {}
    data = wired(h)
    env = {
        "LAB": model.lab,
        "NODE_NAME": h.name,
        "NODE_KIND": h.kind,
        "NODE_ROLE": h.role,
        "DOMAIN": model.org.names,
        "FQDN": model.org.fqdn(h.name),
        "MGMT_IF": "eth0",
        "MGMT_ADDR": f"{h.mgmt}/{model.mgmt.prefixlen}",
        "MGMT_GW": model.mgmt.gw,
        "MGMT_TABLE": mgmt_table(h),
        "MGMT_VRF": mgmt_vrf(model),
        "IFACES": words(i.eth for i in data),
        "IP_FORWARD": IP_FORWARD,
        "RP_FILTER": RP_FILTER,
        "LINK_WAIT_S": LINK_WAIT_S,
        "GUEST_USER": guest.get("user", "admin"),
    }
    for i in data:
        if i.mtu:
            env[f"{i.eth.upper()}_MTU"] = int(i.mtu)
    if guest.get("tx_offload_off", True):
        env["TX_OFF"] = words(sorted({n.eth for n in h.nics}, key=ports.eth_index))
    # SEARCH, so frr-init.sh replaces the search line Docker copied from the lab host's file.
    env.update(dns_env(model, h))
    # Build B's carrier sets these (chapter 17): CORE_IFS and MPLS_LABELS, and VRFS as
    # name,table,port+port items. Build A's routers have neither.
    return env_file(header(model, h, ctx, "#"), env)


def render(model: Model, ctx) -> dict:
    out = {}
    for h in model.routers.values():
        if h.pending:
            ctx.warn(f"frr: {h.name} is pending ({h.pending}); no files rendered")
            continue
        if not wired(h):
            ctx.warn(f"frr: {h.name} has no data port wired in this lab")
        base = f"bootstrap/{h.name}"
        out[f"{base}/frr.conf"] = frr_conf(model, h, ctx)
        out[f"{base}/daemons"] = daemons(model, h, ctx)
        out[f"{base}/vtysh.conf"] = vtysh_conf(model, h, ctx)
        out[f"{base}/init.env"] = init_env(model, h, ctx)
    return out
