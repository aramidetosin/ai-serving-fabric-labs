"""The lab's name and time services (FRAMEWORK.md sections 0, 2.2 and 5).

Names. Every name of the lab lives in the platform's zone (org.zone, ai.tarnwick.example), with no
record at the corporate apex and no wildcard. Three kinds of server answer for it:

- the authoritative servers (bind-auth): the spec's dns.views, each with its servers, the primary
  first. A view answers the resolvers its match names (by address, node:<host>, or by segment for a
  public server) and holds explicit records only: its name servers, the names its names: list
  picks (users, admin, internal) answering the view's answer, and with infra the infrastructure
  records and one reverse zone per lab /24 that holds one of them. Recursion is off everywhere. The
  primary writes bootstrap/<node>/named.conf and one zone file per zone of each view
  (zones/db.<view>.<zone>); a secondary writes named.conf only and takes each view's zones from the
  primary by transfer. A view with secondaries has its own TSIG key, <view>-xfr: the secondary's
  transfer requests and the primary's NOTIFY carry it, and each view's match-clients takes that key
  first and refuses every other view's, so a transfer always lands in the view it was asked from.
  The keys are made per lab (common/bin/secrets.py, state/secrets/tsig/, gen/clab-state.json
  "tsig") and installed by sfab-dns beside the render; they are never rendered.
- the recursive resolvers (bind-recursive, dns.resolvers): BIND recursing for its clients' segments
  only, with the platform's zone and the reverse zones of the view that answers it as static-stub
  zones on the authoritative servers, and an empty root of its own: the lab has no way out, so a
  name outside the platform's zone gets NXDOMAIN at once and no query leaves the lab.
- the enterprise's corporate resolver (dnsmasq): it answers the corporate names its local: list
  names under the org domain itself (local=, one host-record each), forwards the platform's zone,
  and only that, to the authoritative servers (server=/<zone>/<address>), and has no other
  upstream. A query for the platform's zone is answered by the platform's own servers, so an AAAA
  query there gets their NODATA.

Every server listens on its primary address and on 127.0.0.1, never on the management network.
On an authoritative server 127.0.0.1 also matches the first view that holds the infrastructure
records (else the first view), so the server can be asked locally.

The servers of public views with the same answer (the operator's and the internet's public servers)
are all named in each one's zones, in spec order, so their zones hold the same records, the same
SOA and the same serial, and a diff of their answers is empty. The authoritative pair's views name
their own servers.

Time. The spec's ntp block: its servers (dns-res1 and dns-res2) run chronyd beside their resolver, each
following the upstream reference (inet-ntp) over NTS when ntp.nts is on (its certificate from the
lab's internet intermediate, trusted through the lab root at /shared/ca/root.crt), serving the
allowed segments, and falling back to their own clock at local_stratum; the reference serves its
own clock (the lab host's) at reference_stratum to anyone, with its NTS key and chain installed from
/sfab/tls by the image. Every chronyd runs with -x, so none adjusts the clock of the host the
containers share. bootstrap/<node>/chrony.conf for each.

The images (images/resolver) install the render with sfab-dns, which checks every file
(named-checkconf, named-checkzone, dnsmasq --test) before it swaps the live copy at LIVE_DIR and
reloads. The files reference that live directory, the TSIG keys under LIVE_DIR/keys and the rndc
key the image makes at start.

Byte-stable: the SOA serial is derived from the zone's own data (its records and timers, not its
comments), and every list is written in a fixed order.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass

from .. import addr
from ..model import DnsResolver, DnsView, Host, Model

# Where the images keep the checked, live copy of a server's render (sfab-dns).
LIVE_DIR = "/etc/sfab/dns"
ZONE_DIR = f"{LIVE_DIR}/zones"
# The TSIG keys sfab-dns installs from the bound state/secrets/tsig/ (TSIG_BOUND) beside the render.
KEY_DIR = f"{LIVE_DIR}/keys"
TSIG_BOUND = "/sfab/tsig"
TSIG_ALGORITHM = "hmac-sha256"
# The rndc key each image makes at start; never rendered, never in an image.
RNDC_KEY = "/run/named/rndc.key"
RNDC_KEY_NAME = "rndc-key"
# BIND's working directory, pid file and logs; a secondary keeps its transferred zones under
# SECONDARY_DIR, relative to the working directory.
WORK_DIR = "/var/cache/bind"
SECONDARY_DIR = "secondary"
PID_FILE = "/run/named/named.pid"
LOG_DIR = "/var/log/named"
DNSMASQ_LOG = "/var/log/dnsmasq.log"

# The lab root the containers trust (state/shared/ca bound at /shared/ca, render/clab.py), and
# where an NTS server's key and chain are bound (state/tls/<node>) and installed for chronyd.
CA_ROOT = "/shared/ca/root.crt"
TLS_BOUND = "/sfab/tls"
TLS_LIVE = "/run/sfab/tls"
CHRONY_DUMP = "/var/lib/chrony"

# Zone timers.
TTL = 300
SOA_REFRESH = 3600
SOA_RETRY = 600
SOA_EXPIRE = 86400
SOA_NEGATIVE = 60

# chronyd's stratum while it serves its own clock, unless the ntp block says otherwise.
CHRONY_STRATUM = 10
REFERENCE_STRATUM = 2

AUTH_KINDS = ("bind-auth",)
RESOLVER_KINDS = ("bind-recursive", "dnsmasq")
# Every server role a host's dns_role may name.
ROLES = ("bind-auth", "bind-recursive", "dnsmasq")


class DnsRenderError(ValueError):
    """The model holds something a DNS server cannot serve."""


@dataclass(frozen=True)
class Rec:
    owner: str     # absolute name, no trailing dot ('' is the root)
    rtype: str     # SOA is written by the zone itself; A, NS or PTR here
    value: str
    note: str = ""


@dataclass(frozen=True)
class Zone:
    name: str      # 'ai.tarnwick.example', '1.20.10.in-addr.arpa', or '' for the root
    view: str
    kind: str      # forward | reverse | root
    ns: tuple      # name server names, the first is the SOA's primary
    records: tuple # tuple[Rec], NS first, in the order written

    @property
    def file(self) -> str:
        """zones/db.<view>.<zone>; the root zone is db.<view>.root."""
        return f"db.{self.view}.{self.name or 'root'}"


# --------------------------------------------------------------------------------------------
# helpers


def header(model: Model, node: str, what: str, ctx) -> str:
    return (f"{model.lab} {node}{what}: rendered from {ctx.profile_file(model)} by render/dns.py; "
            f"edit the spec and run make render")


def _internal(model: Model, a: str) -> bool:
    s = model.segment_of(a)
    return s is not None and s.scope == "internal"


def reverse_name(address: str) -> str:
    """The /24 reverse zone holding an IPv4 address: 10.20.1.11 -> 1.20.10.in-addr.arpa."""
    a = ipaddress.IPv4Address(address).exploded.split(".")
    return f"{a[2]}.{a[1]}.{a[0]}.in-addr.arpa"


def _rel(owner: str, origin: str) -> str:
    """owner written relative to origin: '@' at the apex, the leading labels below it, else the
    absolute name with its trailing dot."""
    if owner == origin:
        return "@"
    if origin and owner.endswith("." + origin):
        return owner[: -len(origin) - 1]
    if not origin and owner:
        return owner + "."
    return owner + "." if owner else "."


def _abs(name: str) -> str:
    return name + "." if name else "."


def serial(zone: "Zone", hostmaster: str) -> int:
    """The SOA serial, 1 to 2^31 - 1, from the zone's data: its name, name servers, hostmaster,
    timers and records. Comments, the view's name and the server's name are not part of it, so
    two servers holding the same records answer the same serial."""
    data = [zone.name, list(zone.ns), hostmaster, TTL, SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_NEGATIVE,
            [[r.owner, r.rtype, r.value] for r in zone.records]]
    text = json.dumps(data, separators=(",", ":"))
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16) % 2147483647 or 1


def server_node(model: Model, name: str) -> Host | None:
    n = model.nodes.get(name)
    return n if isinstance(n, Host) else None


def _live(model: Model, name: str) -> Host | None:
    """The host when it is in this lab and not pending."""
    h = server_node(model, name)
    return h if h is not None and not h.pending and h.primary else None


def views_of(model: Model, node: str) -> list:
    """Every view a server serves, primary or secondary, in spec order."""
    if model.dns is None:
        return []
    return [v for v in model.dns.views if node in (v.servers or (v.server,))]


def server_views(model: Model) -> dict:
    """{server: [views it serves, primary or secondary, in spec order]} for every authoritative
    server in this lab."""
    out: dict = {}
    if model.dns is None:
        return out
    for v in model.dns.views:
        if v.kind not in AUTH_KINDS:
            raise DnsRenderError(f"view {v.name}: unknown kind {v.kind!r} (a view is {', '.join(AUTH_KINDS)})")
        for s in v.servers or (v.server,):
            if s in model.nodes:
                out.setdefault(s, []).append(v)
    return out


def resolver_groups(model: Model) -> dict:
    """{server: its DnsResolver} for every resolver in this lab."""
    out: dict = {}
    if model.dns is None:
        return out
    for r in model.dns.resolvers:
        if r.kind not in RESOLVER_KINDS:
            raise DnsRenderError(f"resolver {r.name}: unknown kind {r.kind!r} (a resolver is {', '.join(RESOLVER_KINDS)})")
        for s in r.servers:
            if s in model.nodes:
                if s in out:
                    raise DnsRenderError(f"{s}: a resolver of both {out[s].name} and {r.name}")
                out[s] = r
    return out


def tsig_name(view: DnsView) -> str:
    return f"{view.name}-xfr"


def tsig_keys(model: Model) -> list:
    """The TSIG key names this lab needs: one per view with a secondary in the lab."""
    out = []
    if model.dns is None:
        return out
    for v in model.dns.views:
        if _live(model, v.server) and any(_live(model, s) for s in v.secondaries):
            out.append(tsig_name(v))
    return out


def tsig_servers(model: Model) -> list:
    """The servers that hold the TSIG keys: every server of a view with a secondary in the lab."""
    out: list = []
    if model.dns is None:
        return out
    for v in model.dns.views:
        if tsig_name(v) not in tsig_keys(model):
            continue
        for s in v.servers:
            if _live(model, s) and s not in out:
                out.append(s)
    return out


def name_servers(model: Model, view: DnsView) -> tuple:
    """The servers named as NS in a view's zones. A view with more than one server names its own
    servers, the primary first. A single-server view names every server in this lab that serves a
    single-server view of the same kind with the same answer, in spec order, so the two public
    servers' zones (and their SOA, whose primary is the first) are identical."""
    if len(view.servers) > 1:
        return tuple(s for s in view.servers if s == view.server or _live(model, s))
    out: list = []
    for v in model.dns.views:
        if len(v.servers) > 1 or v.kind != view.kind or v.answer_address != view.answer_address or v.server in out:
            continue
        if v.server == view.server or _live(model, v.server):
            out.append(v.server)
    return tuple(out)


def listen_addresses(h: Host) -> tuple:
    """127.0.0.1 and the server's primary address (the one the firewall's rules name)."""
    if not h.primary:
        raise DnsRenderError(f"{h.name}: a DNS server needs an address in this lab")
    return ("127.0.0.1", h.primary)


def _match_acl(view: DnsView) -> str:
    return f"{view.name}-clients"


def _local_view(views) -> str | None:
    """The view 127.0.0.1 matches on an authoritative server: the first with the infrastructure
    records, else the first."""
    for v in views:
        if v.infra:
            return v.name
    return views[0].name if views else None


def view_for(model: Model, address: str) -> DnsView | None:
    """The authoritative view a resolver at this address is answered from."""
    if model.dns is None or not address:
        return None
    for v in model.dns.views:
        if v.kind in AUTH_KINDS and any(addr.contains(c, address) for c in v.match_cidrs):
            return v
    return None


def client_view(model: Model, client: Host) -> tuple:
    """(the resolver a client asks, the view that answers the client's lookups): a client of a
    platform resolver is answered from the view that matches its resolver's address; a client of an
    authoritative server (the public servers) from the view that matches its own address."""
    if model.dns is None or not client.resolver:
        return None, None
    res = client.resolver
    rn = model.nodes.get(res)
    if model.dns.resolver_of(res) is not None:
        return res, view_for(model, getattr(rn, "primary", None) or "")
    for v in model.dns.views:
        if res in (v.servers or (v.server,)) and client.primary and any(addr.contains(c, client.primary) for c in v.match_cidrs):
            return res, v
    return res, None


# --------------------------------------------------------------------------------------------
# what a view answers


def answers(model: Model, view: DnsView) -> list:
    """The A records of a view's forward zone, as (fqdn, address, note), in the order written:
    the name servers, then (infra views) the infrastructure records sorted by name, then the
    names the view's names: list picks, all answering the view's answer."""
    d = model.dns
    out: list = []
    seen: set = set()

    def add(name, a, note):
        if name in seen:
            return
        seen.add(name)
        out.append((name, a, note))

    for s in name_servers(model, view):
        h = server_node(model, s)
        if h is not None and h.primary:
            add(model.org.fqdn(s), h.primary, "name server")
    if view.infra:
        # By label, so truenas1 comes before truenas1-mgmt.
        for r in sorted(d.records, key=lambda x: tuple(reversed(x.name.split(".")))):
            add(r.name, r.address, "the Kubernetes API VIP" if r.kind == "api" else "")
    if view.answer_address:
        # a decisions lab (chapter 2 on) labels each entry the view answers with its decision id
        from .decisions import label_of  # noqa: PLC0415

        dec = label_of(model, "view", view.name, view.decision) if _decisions_on(model) else None
        tag = f"decision {dec}: " if dec else ""
        notes = {**{n: "a name users type" for n in d.users}, **{n: "an admin name" for n in d.admin},
                 **{n: "an internal name" for n in d.internal}, **{n: "the identity provider" for n in d.identity}}
        for n in d.names_of(view):
            add(n, view.answer_address, f"{tag}{notes.get(n, 'a name')}")
        if d.wildcard:
            add(d.wildcard, view.answer_address, f"{tag}every other name in the zone")
    return out


def _decisions_on(model: Model) -> bool:
    from .decisions import on  # noqa: PLC0415

    return on(model)


def zone_model(model: Model, view: DnsView) -> tuple:
    """Every zone a view serves: the forward zone and, in a view with the infrastructure records,
    one reverse zone per lab /24 holding one of its internal addresses (the first name for an
    address wins)."""
    d = model.dns
    ns = tuple(model.org.fqdn(s) for s in name_servers(model, view))
    a_recs = answers(model, view)
    fwd = [Rec(d.zone, "NS", n) for n in ns]
    fwd += [Rec(name, "A", a, note) for name, a, note in a_recs]
    zones = [Zone(name=d.zone, view=view.name, kind="forward", ns=ns, records=tuple(fwd))]

    ptr: dict = {}
    for name, a, _note in a_recs:
        # only a view with the infrastructure records holds reverse zones: another view (the
        # enterprise's) names no infrastructure host beyond its own name servers
        if not view.infra or name.startswith("*.") or not _internal(model, a) or a in ptr:
            continue
        ptr[a] = name
    by_zone: dict = {}
    for a in sorted(ptr, key=lambda x: ipaddress.IPv4Address(x)):
        by_zone.setdefault(reverse_name(a), []).append(a)
    for rz in sorted(by_zone, key=lambda z: tuple(int(x) for x in reversed(z.split(".")[:3]))):
        recs = [Rec(rz, "NS", n) for n in ns]
        recs += [Rec(f"{a.split('.')[3]}.{rz}", "PTR", ptr[a]) for a in by_zone[rz]]
        zones.append(Zone(name=rz, view=view.name, kind="reverse", ns=ns, records=tuple(recs)))
    return tuple(zones)


def root_zone(model: Model, h: Host) -> Zone:
    """A resolver's own empty root: it is the root's one name server, with its address in the zone
    as named-checkzone wants for an in-zone NS."""
    me = model.org.fqdn(h.name)
    recs = (Rec("", "NS", me), Rec(me, "A", h.primary, "name server"))
    return Zone(name="", view=h.name, kind="root", ns=(me,), records=recs)


# --------------------------------------------------------------------------------------------
# BIND


def _view_note(model: Model, view: DnsView) -> str:
    who = ", ".join(view.match) or "nobody"
    names = model.dns.names_of(view)
    if view.answer_address and names:
        what = f"{', '.join(view.names)} names answer {view.answer_address} ({view.answer})"
    else:
        what = "no answer for the names users type"
    extra = "; the infrastructure records" if view.infra else ""
    dec = f"decision {view.decision}: " if view.decision else ""
    role = ""
    if len(view.servers) > 1:
        role = f"; primary {view.server}, secondary {', '.join(view.secondaries)} by transfer keyed with {tsig_name(view)}"
    return f"{dec}view {view.name} for {who}: {what}{extra}; recursion off{role}"


def bind_zone(model: Model, h: Host, view: DnsView | None, zone: Zone, ctx) -> str:
    """One zone file. The serial comes from the zone's data (serial())."""
    origin = zone.name
    label = "the root" if zone.kind == "root" else zone.name
    where = f", view {view.name}, zone {label}" if view is not None else f", zone {label}"
    lines = [f"; {header(model, h.name, where, ctx)}"]
    if view is not None and view.decision:
        lines.append(f"; decision {view.decision}")
    if zone.kind == "root":
        lines.append("; The lab has no way out: this resolver is authoritative for an empty root, so a name outside")
        lines.append("; the platform's zone gets NXDOMAIN at once and no query leaves the lab.")
    lines.append(f"$ORIGIN {_abs(origin)}")
    lines.append(f"$TTL {TTL}")
    hostmaster = f"hostmaster.{model.dns.zone}."
    soa = [
        f"@ IN SOA {_abs(zone.ns[0])} {hostmaster} (",
        f"    {serial(zone, hostmaster)} ; serial, from the zone's data",
        f"    {SOA_REFRESH} ; refresh",
        f"    {SOA_RETRY} ; retry",
        f"    {SOA_EXPIRE} ; expire",
        f"    {SOA_NEGATIVE} ) ; negative answers",
    ]
    body = []
    width = max([len(_rel(r.owner, origin)) for r in zone.records] + [1])
    for r in zone.records:
        own = _rel(r.owner, origin)
        val = _abs(r.value) if r.rtype in ("NS", "PTR") else r.value
        line = f"{own:<{width}} IN {r.rtype:<3} {val}"
        if r.note:
            line += f" ; {r.note}"
        body.append(line.rstrip())
    return "\n".join(lines + soa + body) + "\n"


def answered_zone(model: Model, h: Host, view: DnsView, override: dict, note: str, ctx) -> tuple:
    """(zones/<file>, text): the view's forward zone with the names in override (FQDN -> address)
    answering their own address, the rest as rendered, and note as a comment under the header.
    Chapter 2's break-2a installs it in place of the rendered file on the view's primary, whose
    secondaries take it by transfer; the reverse zones are left as rendered. Every overridden name
    is one the zone answers, or a name of the zone's lists (users, admin, internal) that the view does
    not hold, which is added."""
    fwd = next(z for z in zone_model(model, view) if z.kind == "forward")
    have = {r.owner for r in fwd.records if r.rtype == "A"}
    known = set(model.dns.users) | set(model.dns.admin) | set(model.dns.internal) | set(model.dns.identity)
    missing = sorted(set(override) - have - known)
    if missing:
        raise DnsRenderError(f"view {view.name}: no A record for {', '.join(missing)} to answer otherwise, and no name of the zone's lists")
    recs = tuple(Rec(r.owner, r.rtype, override[r.owner], r.note) if r.rtype == "A" and r.owner in override else r for r in fwd.records)
    # a name the view does not hold (the enterprise view's admin names) is added, answering the break's address
    recs += tuple(Rec(n, "A", override[n], "added by the break") for n in sorted(set(override) - have))
    z = Zone(name=fwd.name, view=fwd.view, kind=fwd.kind, ns=fwd.ns, records=recs)
    text = bind_zone(model, h, view, z, ctx)
    first, rest = text.split("\n", 1)
    return f"zones/{z.file}", f"{first}\n; {note}\n{rest}"


def zone_files(model: Model, h: Host, view: DnsView, ctx) -> dict:
    """{zones/<file>: text} for one view."""
    return {f"zones/{z.file}": bind_zone(model, h, view, z, ctx) for z in zone_model(model, view)}


def _options(listen, recursion_acl: list | None) -> list:
    out = [
        "options {",
        f'    directory "{WORK_DIR}";',
        f'    pid-file "{PID_FILE}";',
        f"    listen-on port 53 {{ {'; '.join(listen)}; }};",
        "    listen-on-v6 { none; };",
    ]
    if recursion_acl:
        acl = "; ".join(recursion_acl)
        out += ["    recursion yes;", f"    allow-recursion {{ {acl}; }};", f"    allow-query {{ {acl}; }};",
                f"    allow-query-cache {{ {acl}; }};"]
    else:
        out += ["    recursion no;", "    allow-recursion { none; };", "    allow-query-cache { none; };"]
    out += [
        "    allow-transfer { none; };",
        "    notify no;",
        "    dnssec-validation no;",
        "    querylog yes;",
        "    version none;",
        "    hostname none;",
        "    server-id none;",
        "};",
        "",
        "logging {",
        f'    channel general {{ file "{LOG_DIR}/named.log" versions 2 size 5m; print-time yes; severity info; }};',
        f'    channel queries {{ file "{LOG_DIR}/queries.log" versions 2 size 5m; print-time yes; }};',
        "    category default { general; };",
        "    category queries { queries; };",
        "    category lame-servers { null; };",
        "};",
        "",
        f'include "{RNDC_KEY}";',
        f'controls {{ inet 127.0.0.1 port 953 allow {{ 127.0.0.1; }} keys {{ "{RNDC_KEY_NAME}"; }}; }};',
    ]
    return out


def bind_auth(model: Model, h: Host, views, ctx) -> str:
    """named's whole configuration on an authoritative server: the options (recursion off), the
    logging and rndc control, the TSIG keys of the views that transfer, one client ACL per view,
    then the views in spec order, each with its zones as primary (files from the render) or as
    secondary (from its primary, by transfer)."""
    listen = listen_addresses(h)
    local = _local_view(views)
    keyed = [v for v in views if tsig_name(v) in tsig_keys(model)]
    out = [
        f"// {header(model, h.name, '', ctx)}",
        "// named.conf: named's whole configuration, an authoritative server (recursion off). sfab-dns checks it",
        f"// and its zones, installs them as {LIVE_DIR}/named.conf and {ZONE_DIR}/ with the TSIG keys in",
        f"// {KEY_DIR}/, and reloads. Views answer by the asking resolver's address, and a zone transfer or",
        "// NOTIFY by its view's TSIG key.",
        "",
    ]
    out += _options(listen, None)
    out.append("")
    for v in keyed:
        out.append(f'include "{KEY_DIR}/{tsig_name(v)}.key";  // view {v.name}\'s transfers; made per lab, never rendered')
    for v in views:
        if not v.match_cidrs:
            raise DnsRenderError(f"view {v.name}: no client matches it")
        out.append(f'acl {_match_acl(v)} {{ {"; ".join(v.match_cidrs)}; }};  // {", ".join(v.match)}')
    for v in views:
        others = [tsig_name(x) for x in keyed if x is not v]
        clients = ([f'key "{tsig_name(v)}"'] if v in keyed else []) + [f'!key "{k}"' for k in others]
        clients += (["127.0.0.1"] if v.name == local else []) + [_match_acl(v)]
        out += ["", f"// {_view_note(model, v)}", f'view "{v.name}" {{', f"    match-clients {{ {'; '.join(clients)}; }};",
                "    recursion no;"]
        zones = zone_model(model, v)
        if h.name == v.server:
            secs = [s for s in v.secondaries if _live(model, s)] if v in keyed else []
            for s in secs:
                out.append(f'    server {model.nodes[s].primary} {{ keys "{tsig_name(v)}"; }};  // {s}')
            for z in zones:
                extra = ""
                if secs:
                    extra = (f" notify explicit; also-notify {{ {'; '.join(model.nodes[s].primary for s in secs)}; }};"
                             f' allow-transfer {{ key "{tsig_name(v)}"; }};')
                out.append(f'    zone "{z.name or "."}" {{ type primary; file "{ZONE_DIR}/{z.file}";{extra} }};')
        else:
            p = _live(model, v.server)
            if p is None or v not in keyed:
                raise DnsRenderError(f"{h.name}: a secondary of view {v.name}, whose primary {v.server} is not in this lab")
            out.append(f'    server {p.primary} {{ keys "{tsig_name(v)}"; }};  // {p.name}, the primary')
            for z in zones:
                out.append(f'    zone "{z.name or "."}" {{ type secondary; primaries {{ {p.primary}; }}; '
                           f'file "{SECONDARY_DIR}/{z.file}"; allow-notify {{ {p.primary}; }}; }};')
        out.append("};")
    return "\n".join(out) + "\n"


def stub_zones(model: Model, h: Host) -> list:
    """The zones a recursive resolver sends to the authoritative servers: those of the view that
    answers it (the platform's zone and its reverse zones)."""
    v = view_for(model, h.primary)
    if v is None:
        raise DnsRenderError(f"{h.name}: no authoritative view answers its address {h.primary}")
    return [z.name for z in zone_model(model, v)]


def bind_recursive(model: Model, h: Host, r: DnsResolver, ctx) -> str:
    """named on a recursive resolver: recursion for its clients only, the platform's zones as
    static-stub zones on the authoritative servers, and its own empty root."""
    listen = listen_addresses(h)
    if not r.client_cidrs:
        raise DnsRenderError(f"resolver {r.name}: no client segment")
    to = [model.nodes[x].primary for x in r.to if _live(model, x)]
    if not to:
        raise DnsRenderError(f"resolver {r.name}: no authoritative server in this lab to send the platform's zone to")
    acl = f"{r.name}-clients"
    out = [
        f"// {header(model, h.name, '', ctx)}",
        "// named.conf: named's whole configuration, a recursive resolver for the inside segments. sfab-dns",
        f"// checks it and its zones, installs them as {LIVE_DIR}/named.conf and {ZONE_DIR}/, and reloads.",
        "// The platform's zone and its reverse zones go to the authoritative servers (static-stub); every",
        "// other name ends at this resolver's own empty root (NXDOMAIN), so no query leaves the lab.",
        "",
    ]
    out += _options(listen, ["127.0.0.1", acl])
    out += ["", f'acl {acl} {{ {"; ".join(r.client_cidrs)}; }};  // {", ".join(r.clients)}', ""]
    names = ", ".join(x for x in r.to if _live(model, x))
    for z in stub_zones(model, h):
        out.append(f'zone "{z}" {{ type static-stub; server-addresses {{ {"; ".join(to)}; }}; }};  // {names}')
    out.append(f'zone "." {{ type primary; file "{ZONE_DIR}/{root_zone(model, h).file}"; }};')
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------
# dnsmasq


def dnsmasq_conf(model: Model, h: Host, r: DnsResolver, ctx) -> str:
    """The enterprise's resolver: the corporate names under the org domain answered here (local=,
    one host-record each), the platform's zone forwarded to the authoritative servers, no other
    upstream (anything else is refused)."""
    listen = listen_addresses(h)
    to = [(x, model.nodes[x].primary) for x in r.to if _live(model, x)]
    if not to:
        raise DnsRenderError(f"resolver {r.name}: no authoritative server in this lab to forward the platform's zone to")
    out = [
        f"# {header(model, h.name, '', ctx)}",
        f"# resolver {r.name}: the corporate names of {model.org.domain} answered here; the platform's zone",
        f"# {model.dns.zone} forwarded to its authoritative servers ({', '.join(x for x, _ in to)}); no other upstream.",
        "port=53",
        f"listen-address={','.join(listen)}",
        "bind-interfaces",
        "no-resolv",
        "no-hosts",
        "no-poll",
        "domain-needed",
        "bogus-priv",
        "log-queries",
        f"log-facility={DNSMASQ_LOG}",
        f"local=/{model.org.domain}/",
    ]
    for _x, a in to:
        out.append(f"server=/{model.dns.zone}/{a}")
    for n in r.local:
        x = model.nodes.get(n)
        if x is not None and getattr(x, "primary", None):
            out.append(f"host-record={n}.{model.org.domain},{x.primary}")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------
# chrony


def ntp_block(model: Model) -> dict:
    t = (model.spec or {}).get("ntp")
    return t if isinstance(t, dict) else {}


def ntp_servers(model: Model) -> list:
    """The spec's ntp.servers in this lab."""
    return [str(s) for s in (ntp_block(model).get("servers") or []) if _live(model, str(s))]


def ntp_upstream(model: Model) -> Host | None:
    """The reference the time servers follow, when it and a time server are in this lab."""
    up = _live(model, str(ntp_block(model).get("upstream") or ""))
    return up if up is not None and ntp_servers(model) else None


def ntp_allow(model: Model) -> tuple:
    out: list = []
    for seg in ntp_block(model).get("allow") or []:
        s = model.segments.get(seg)
        if s is None:
            raise DnsRenderError(f"ntp.allow names {seg!r}, which is not a segment of this lab")
        if s.prefix not in out:
            out.append(s.prefix)
    return tuple(out)


def nts_on(model: Model) -> bool:
    return bool(ntp_block(model).get("nts", False)) and ntp_upstream(model) is not None


def chrony_server(model: Model, h: Host, ctx) -> str:
    """A time server of the inside segments: the upstream reference (over NTS when ntp.nts is on),
    its own clock at local_stratum when the reference is out of reach, the allowed segments, its
    primary address. No command port on the network."""
    t = ntp_block(model)
    allow = ntp_allow(model)
    if not allow:
        raise DnsRenderError(f"{h.name}: the time service allows no segment")
    up = ntp_upstream(model)
    nts = nts_on(model)
    how = " over NTS (RFC 8915; the reference's certificate chains to the lab root)" if nts else ""
    lines = [
        f"# {header(model, h.name, '', ctx)}",
        f"# A time server for the inside segments. It follows the upstream reference{how},",
        "# and serves its own clock as a local reference when the reference is out of reach. chronyd runs",
        "# with -x, so it never adjusts the clock of the host the container shares (the lab host's).",
    ]
    if up is not None:
        lines.append(f"server {up.primary} iburst{' nts' if nts else ''}")
        if nts:
            lines += [f"ntstrustedcerts {CA_ROOT}", f"ntsdumpdir {CHRONY_DUMP}"]
    lines += [f"local stratum {int(t.get('local_stratum', CHRONY_STRATUM))}", f"bindaddress {h.primary}"]
    lines += [f"allow {c}" for c in allow]
    lines.append("cmdport 0")
    return "\n".join(lines) + "\n"


def chrony_reference(model: Model, h: Host, ctx) -> str:
    """The upstream reference: its own clock (the lab host's) at reference_stratum, to anyone, with
    NTS when ntp.nts is on."""
    t = ntp_block(model)
    nts = nts_on(model)
    lines = [
        f"# {header(model, h.name, '', ctx)}",
        "# The upstream time reference, a stand-in for an internet NTP service: it serves the clock of the",
        "# host the container shares (the lab host's) as a local reference, to anyone, and with -x never",
        "# adjusts it.",
    ]
    if nts:
        lines.append(f"# NTS key exchange on TCP 4460, with the key and chain the image installs from {TLS_BOUND}.")
    lines += [f"local stratum {int(t.get('reference_stratum', REFERENCE_STRATUM))}", f"bindaddress {h.primary}", "allow all"]
    if nts:
        lines += [f"ntsserverkey {TLS_LIVE}/tls.key", f"ntsservercert {TLS_LIVE}/chain.crt"]
    lines.append("cmdport 0")
    return "\n".join(lines) + "\n"


def ntp_addresses(model: Model) -> list:
    """Every time server's address in this lab, in spec order: what clients name."""
    return [model.nodes[s].primary for s in ntp_servers(model)]


def ntp_address(model: Model) -> str | None:
    """The first time server's address, when one is in the lab."""
    a = ntp_addresses(model)
    return a[0] if a else None


# --------------------------------------------------------------------------------------------


def render(model: Model, ctx) -> dict:
    out: dict = {}
    for server, views in server_views(model).items():
        h = server_node(model, server)
        if h is None:
            raise DnsRenderError(f"view {views[0].name}: its server {server} is not a host")
        if h.pending:
            ctx.warn(f"dns: {server} is pending ({h.pending}); its views {', '.join(v.name for v in views)} were not rendered")
            continue
        if h.dns_role and h.dns_role != "bind-auth":
            raise DnsRenderError(f"{server}: dns_role {h.dns_role} but it serves views (bind-auth)")
        out[f"bootstrap/{server}/named.conf"] = bind_auth(model, h, views, ctx)
        for v in views:
            if v.server != server:
                continue
            for p, text in zone_files(model, h, v, ctx).items():
                out[f"bootstrap/{server}/{p}"] = text
    for server, r in resolver_groups(model).items():
        h = server_node(model, server)
        if h is None:
            raise DnsRenderError(f"resolver {r.name}: its server {server} is not a host")
        if h.pending:
            ctx.warn(f"dns: {server} is pending ({h.pending}); resolver {r.name} was not rendered")
            continue
        if f"bootstrap/{server}/named.conf" in out:
            raise DnsRenderError(f"{server}: both an authoritative server and a resolver")
        if h.dns_role and h.dns_role != r.kind:
            raise DnsRenderError(f"{server}: dns_role {h.dns_role} but resolver {r.name} is {r.kind}")
        if r.kind == "bind-recursive":
            out[f"bootstrap/{server}/named.conf"] = bind_recursive(model, h, r, ctx)
            rz = root_zone(model, h)
            out[f"bootstrap/{server}/zones/{rz.file}"] = bind_zone(model, h, None, rz, ctx)
        else:
            out[f"bootstrap/{server}/dnsmasq.conf"] = dnsmasq_conf(model, h, r, ctx)

    for s in ntp_servers(model):
        out[f"bootstrap/{s}/chrony.conf"] = chrony_server(model, model.nodes[s], ctx)
    up = ntp_upstream(model)
    if up is not None:
        out[f"bootstrap/{up.name}/chrony.conf"] = chrony_reference(model, up, ctx)

    for h in model.hosts.values():
        if h.dns_role and h.dns_role not in ROLES:
            raise DnsRenderError(f"{h.name}: dns_role {h.dns_role!r} is not one of {', '.join(ROLES)}")
        if h.dns_role and not h.pending and not any(p in out for p in (f"bootstrap/{h.name}/named.conf", f"bootstrap/{h.name}/dnsmasq.conf")):
            ctx.warn(f"dns: {h.name} has dns_role {h.dns_role} but serves nothing in this state")
    return out
