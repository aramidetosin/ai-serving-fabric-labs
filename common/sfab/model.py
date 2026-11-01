"""The selected model: every object a renderer, the inventory or a script needs for one lab.

sfab.spec.select() builds it from the merged, when-filtered profile and the chapter's slice.
Every dataclass is frozen; sequences are tuples and mappings are plain dicts that renderers
must treat as read-only. API.md beside this file documents every class and field.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from . import addr, ports
from .spec import SpecError

# --------------------------------------------------------------------------------------------
# Small value types


@dataclass(frozen=True)
class Meta:
    """How this model was selected."""

    lab: str
    profile: str
    variant: str | None
    variant_file: str | None
    state: str
    step: int
    chapter: Any  # sfab.spec.Chapter
    features: dict
    versions: dict
    known: dict
    normalize: dict
    spec_files: dict
    root: str


@dataclass(frozen=True)
class Org:
    name: str
    domain: str               # the enterprise's corporate domain (tarnwick.example)
    short: str
    label_domain: str
    zone: str = ""            # the platform's delegated zone (ai.tarnwick.example); the domain when unset

    def label_key(self, name: str, prefix: str | None = None) -> str:
        """label_key('control', 'node-role') == 'node-role.tarnwick.example/control';
        label_key('lb-pool') == 'tarnwick.example/lb-pool'."""
        dom = f"{prefix}.{self.label_domain}" if prefix else self.label_domain
        return f"{dom}/{name}"

    @property
    def names(self) -> str:
        """The zone every lab name lives under: the platform's zone, else the org domain."""
        return self.zone or self.domain

    def fqdn(self, label: str) -> str:
        """fqdn('llm') == 'llm.ai.tarnwick.example'; fqdn('*') == '*.ai.tarnwick.example' (a name
        under the platform's zone, org.zone; under the org domain when the profile sets no zone)."""
        return f"{label}.{self.names}"

    def route_id(self, model_name: str) -> str:
        """uuid5 (URL namespace) over https://<domain>/models/<name> (FRAMEWORK 1.2)."""
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://{self.domain}/models/{model_name}"))


@dataclass(frozen=True)
class Mgmt:
    network: str  # docker network name, e.g. sfab-a-mgmt
    subnet: str   # 172.21.40.0/24
    gw: str       # 172.21.40.1 (the docker bridge)
    bridge: str
    prefixlen: int

    def addr(self, octet: int) -> str:
        return addr.host(self.subnet, octet)


@dataclass(frozen=True)
class Segment:
    id: str
    prefix: str
    scope: str            # internal | external | mgmt
    vlan: int | None = None
    desc: str | None = None
    per_port: int | None = None   # prefix length of the per-router-port subnets, e.g. 30
    node_local: bool = False
    reserved: bool = False
    within: str | None = None     # id of the segment this one sits inside
    since: int | None = None
    mtu: int | None = None        # the IP MTU every member of the segment uses (one per VLAN)

    @property
    def prefixlen(self) -> int:
        return addr.net(self.prefix).prefixlen

    def host(self, n: int) -> str:
        return addr.host(self.prefix, n)

    def cidr(self, n: int) -> str:
        return addr.host_cidr(self.prefix, n)


@dataclass(frozen=True)
class Vlan:
    id: int
    name: str
    segment: str
    prefix: str
    gw_node: str | None    # 'fw'
    gw_iface: str | None   # 'ae1.100'
    gw: str | None         # gateway address, bare ('10.20.1.1'), or None (rails)
    decision: str | None = None
    since: int | None = None


@dataclass(frozen=True)
class Rail:
    r: int
    vlan: int
    segment: str
    prefix: str
    switch: str | None     # the rail switch carrying it (in the full state)
    parity: str            # 'odd' | 'even'


@dataclass(frozen=True, order=True)
class End:
    """One end of a link: a node and its container port name."""

    node: str
    eth: str

    @property
    def index(self) -> int:
        return int(self.eth[3:])

    def __str__(self) -> str:
        return f"{self.node}:{self.eth}"


@dataclass(frozen=True)
class Link:
    """One wire. a is the attaching node (host or appliance; the first member for a peer link),
    b the switch it lands on or the declared peer node."""

    id: str                    # str(a), e.g. 'k8s-gpu1:eth1' or 'fe-sw1:eth1'
    a: End
    b: End
    kind: str                  # peer-link | keepalive | bundle | access | rail | oob | p2p
    attachment: str            # '<owner>.<attach id>', e.g. 'k8s-gpu1.bond', 'fe.peer-link'
    pc: int | None = None      # PortChannel id on the switch side (peer-link, bundle)
    mode: str | None = None    # access | trunk, on the switch side
    vlans: tuple = ()          # VLANs on the switch side (access: one; trunk: the allowed list)
    mtu: int | None = None     # switch-side MTU when set (None: the factory 9100)
    rail: int | None = None
    decision: str | None = None
    since: int | None = None
    tagged: tuple = ()         # access bundles: VLANs also carried tagged (the host's VLAN units)

    def has(self, node: str) -> bool:
        return node in (self.a.node, self.b.node)

    def has_any(self, names) -> bool:
        return self.a.node in names or self.b.node in names

    def end(self, node: str) -> End:
        if self.a.node == node:
            return self.a
        if self.b.node == node:
            return self.b
        raise KeyError(f"{node} is not on link {self.id}")

    def other(self, node: str) -> End:
        return self.b if self.a.node == node else self.a


@dataclass(frozen=True)
class Nic:
    """One connected container port of a node."""

    node: str
    eth: str                     # 'eth4'
    index: int                   # 4
    role: str                    # peer-link | keepalive | bundle-member | access | rail | oob | bond-member | p2p
    attachment: str              # '<owner>.<attach id>'
    peer: End                    # the far end
    link: str                    # link id
    native: str | None = None    # switches: 'Ethernet3'
    ifname: str | None = None    # guest or appliance name: 'rail3' (VM guest), 'ethernet1/4' (PA-VM)
    desc: str | None = None      # switches: the port description the renderer types
    mac: str | None = None       # VM guests only: the guest NIC MAC
    mtu: int | None = None
    vlan: int | None = None      # access VLAN (switch side) or the VLAN the NIC sits in (host side)
    vlans: tuple = ()            # trunk VLANs
    rail: int | None = None
    address: str | None = None   # CIDR when the NIC itself holds an address
    gateway: str | None = None


@dataclass(frozen=True)
class Budget:
    """Preflight's planning figures for one node (FRAMEWORK.md 3.1). The disk budget is what a
    deploy writes, where it writes it: state_gib under the lab's state/, layer_gib in the node's
    container layer under Docker's data root. A VM guest's root disk size is Host.disk_gib, not a
    budget."""
    mem_gib: float
    vcpus: float
    state_gib: float
    layer_gib: float


@dataclass(frozen=True)
class Route:
    dest: str                    # prefix, or a symbol (see API.md)
    via: str | None = None       # next hop address, or a symbol such as 'qemu-user'
    dev: str | None = None
    src: str | None = None
    id: str | None = None
    first: bool = False
    dest_ref: str | None = None  # the spec's reference when dest was written as one (seg:<segment>)
    via_ref: str | None = None   # the spec's reference when via was written as one (public)
    decision: str | None = None
    since: int | None = None


# --------------------------------------------------------------------------------------------
# Nodes


@dataclass(frozen=True, kw_only=True)
class Node:
    name: str
    kind: str                 # spec kind: dell_sonic, paloalto_panos, truenas, vm-node, bastion, ...
    clab_kind: str            # containerlab kind: dell_sonic, paloalto_panos, generic_vm, linux
    image: str                # image reference from versions.yaml
    image_key: str            # key in versions.yaml images:
    section: str              # switches | appliances | hosts
    group: str
    role: str
    mgmt: str                 # management address, bare
    mgmt_octet: int
    container: str            # '<lab>-<name>'
    budget: Budget
    nics: tuple = ()          # tuple[Nic], sorted by index
    requires: tuple = ()
    decision: str | None = None
    since: int | None = None
    pending: str | None = None
    props: dict = field(default_factory=dict)  # the raw spec entry, read-only

    def nic(self, eth: str | int) -> Nic | None:
        e = ports.eth(eth)
        for n in self.nics:
            if n.eth == e:
                return n
        return None

    @property
    def eths(self) -> tuple:
        return tuple(n.eth for n in self.nics)


@dataclass(frozen=True)
class Member:
    eth: int
    ifname: str          # 'eth3'
    native: str          # 'Ethernet2'
    desc: str
    peer: End
    mtu: int | None = None


@dataclass(frozen=True)
class PortChannel:
    id: int
    name: str            # 'PortChannel10'
    desc: str
    kind: str            # peer-link | mclag
    mode: str            # trunk | access
    vlans: tuple         # trunk: allowed VLANs; access: (vlan,)
    vlan: int | None     # access VLAN, None on a trunk
    mclag: bool          # carries `mclag <domain>`
    fast_rate: bool
    mtu: int | None      # None: the factory 9100, no mtu line
    members: tuple       # tuple[Member], sorted by eth
    peer_node: str | None  # the far-end node, None for the peer link
    attachment: str
    decision: str | None = None
    tagged: tuple = ()   # an access PortChannel's tagged VLANs (switchport trunk allowed beside access)
    edge: bool = False   # host-facing: spanning-tree portfast and bpduguard port-shutdown (the l2 policy)
    storm: tuple = ()    # ((type, kbps), ...) storm control typed on every member (the l2 policy)


@dataclass(frozen=True)
class AccessPort:
    eth: int
    ifname: str
    native: str
    vlan: int
    desc: str
    kind: str            # access | rail | oob
    peer: End
    rail: int | None = None
    decision: str | None = None
    mtu: int | None = None   # None: the factory 9100, no mtu line
    edge: bool = False       # spanning-tree portfast and bpduguard port-shutdown (the l2 policy)
    storm: tuple = ()        # ((type, kbps), ...) storm control (the l2 policy)


@dataclass(frozen=True)
class MclagDomain:
    domain: int
    source_ip: str       # this switch's address on the dedicated keepalive link, bare
    peer_ip: str         # the partner's
    peer: str            # partner switch name
    peer_link: str       # 'PortChannel1'
    peer_link_pc: int
    system_mac: str
    session_vrf: str     # the keepalive VRF ('VrfMclagKa')
    backup_source_ip: str | None = None   # the backup keepalive over the peer-link VLAN interface, bare
    backup_peer_ip: str | None = None
    backup_vrf: str | None = None
    backup_interval: int | None = None


@dataclass(frozen=True)
class Keepalive:
    """A pair member's two keepalive paths, both in the keepalive VRF: the dedicated routed link
    (eth, native, address) and the backup VLAN interface carried on the peer link only."""
    vrf: str
    eth: int
    ifname: str          # 'eth13'
    native: str          # 'Ethernet12'
    address: str         # CIDR, '10.20.255.0/31'
    peer_address: str    # bare
    mtu: int | None
    backup_vlan: int | None = None
    backup_address: str | None = None   # CIDR
    backup_peer: str | None = None      # bare
    backup_interval: int | None = None
    segment: str | None = None


@dataclass(frozen=True, kw_only=True)
class Switch(Node):
    pair: str | None = None
    partner: str | None = None
    vlans: tuple = ()            # sorted VLAN ids the switch creates
    portchannels: tuple = ()     # tuple[PortChannel], sorted by id
    access_ports: tuple = ()     # tuple[AccessPort], sorted by eth
    mclag: MclagDomain | None = None
    keepalive: Keepalive | None = None
    stp: str | None = None       # spanning-tree mode (the l2 policy), None: spanning tree off
    rails: tuple = ()            # rail numbers (rail_vlan role)
    oob_vlan: int | None = None  # oob_access role
    num_nics: int = 1
    passthrough: bool = False    # CLAB_MGMT_PASSTHROUGH
    sflow: bool = False
    mgmt_vrf: str = "mgmt"

    @property
    def used_ports(self) -> tuple:
        return tuple(n.index for n in self.nics)

    def port(self, eth: int | str) -> Nic | None:
        return self.nic(eth)

    def portchannel(self, pc: int) -> PortChannel | None:
        for p in self.portchannels:
            if p.id == pc:
                return p
        return None


@dataclass(frozen=True)
class Bond:
    name: str            # 'bond0'
    members: tuple       # container port names, e.g. ('eth1', 'eth2')
    pc: int              # the switch-side PortChannel
    vlan: int
    address: str         # CIDR
    gateway: str | None
    mtu: int
    mode: str
    lacp_rate: str
    miimon: int
    xmit_hash_policy: str
    mac: str | None      # the bond MAC (its first member's guest MAC), VM guests only
    vlan_ifs: tuple = () # tuple[VlanIf]: the bond's tagged units


@dataclass(frozen=True)
class VlanIf:
    """A tagged unit on a host's bond (bond0.120): its own address in that VLAN's segment. With
    table set, traffic sourced from the segment leaves by the unit's gateway through that routing
    table (a policy rule `from <segment> lookup <table>`), so replies from addresses in the VLAN
    (the Gateway VIPs on an ingress node) go back the way they came."""
    name: str            # 'bond0.120'
    vlan: int
    segment: str
    address: str         # CIDR
    mtu: int
    gateway: str | None = None
    table: int | None = None
    prefix: str | None = None


@dataclass(frozen=True)
class OobIf:
    eth: str
    address: str         # CIDR (BMC address in the out-of-band VLAN)
    gateway: str | None
    table: int
    vlan: int
    netns: str | None = None   # the BMC stand-in's namespace: the NIC moves out of the host OS into it
    services: tuple = ()       # what the stand-in answers on: ssh, https


@dataclass(frozen=True)
class RailIf:
    rail: int
    vlan: int
    eth: str             # container port
    ifname: str          # guest name, 'rail3'
    address: str         # CIDR the node's namespace gpuR holds on this rail
    switch: str
    switch_eth: str
    switch_native: str
    mac: str | None = None


@dataclass(frozen=True)
class RelayNs:
    rail: int
    ns: str              # 'gpu3'
    rail_if: str         # macvlan in the namespace, on guest NIC rail_master
    rail_master: str     # 'rail3'
    rail_addr: str       # CIDR
    veth: str            # 'relay', inside the namespace
    bridge_port: str     # 'rl3', on the bridge
    relay_addr: str      # CIDR in the relay segment, .R
    routes: tuple        # tuple[Route]: other rails via the sibling namespace, src pinned


@dataclass(frozen=True)
class Relay:
    bridge: str
    prefix: str
    mtu: int
    rp_filter: int
    ip_forward: int
    namespaces: tuple    # tuple[RelayNs], by rail


@dataclass(frozen=True)
class Iface:
    eth: str
    address: str | None
    gateway: str | None
    segment: str | None
    peer: End | None
    mtu: int | None = None


@dataclass(frozen=True, kw_only=True)
class Host(Node):
    k8s: str | None = None        # init | join-control | join-worker
    index: int | None = None      # GPU node number n (rail address .(10+n))
    vlan: int | None = None
    address: str | None = None    # primary address, CIDR
    gateway: str | None = None    # default gateway, bare
    bond: Bond | None = None
    oob: OobIf | None = None
    rails: tuple = ()             # tuple[RailIf], by rail
    relay: Relay | None = None
    ifaces: tuple = ()            # tuple[Iface]: addressed ports outside a bond
    routes: tuple = ()            # tuple[Route]
    resolver: str | None = None   # resolver node name (the first of resolvers)
    resolver_address: str | None = None
    resolvers: tuple = ()         # every resolver node the host asks, in order
    resolver_addresses: tuple = ()  # their addresses, bare, for the ones that have one
    dns_role: str | None = None   # bind-views | bind-auth | bind-recursive | dnsmasq
    resolv_options: str | None = None  # resolv.conf options line, when the spec asks for one
    mgmt_mac: str | None = None   # VM guests: eth0's guest MAC
    disk_gib: int | None = None   # VM guests: the root disk's virtual size (VM_DISK_GIB), not a budget
    tables: dict = field(default_factory=dict)  # mgmt, oob, rail_base

    @property
    def primary(self) -> str | None:
        """The primary address, bare."""
        return addr.ip(self.address).compressed if self.address else None


@dataclass(frozen=True)
class FwInterface:
    name: str              # ae1, ae1.100, ethernet1/3
    kind: str              # aggregate | aggregate-member | subinterface | layer3
    eth: str | None        # container port for ethernet1/N: 'ethN'
    parent: str | None
    members: tuple
    tag: int | None
    address: str | None    # CIDR
    zone: str | None
    mtu: int | None
    lacp: dict | None
    vlan: int | None       # the VLAN a subinterface gateways
    connected: bool        # its wire (or a member's) is in this lab
    since: int | None = None
    mss_adjust: int | None = None  # adjust-tcp-mss: the SYNs through it get MSS = mtu - this


@dataclass(frozen=True)
class Zone:
    name: str
    interfaces: tuple
    decision: str | None = None
    since: int | None = None
    zone_protection: str | None = None


@dataclass(frozen=True)
class FwRoute:
    name: str
    dest: str
    nexthop: str | None        # an address, None for a tunnel interface route, 'discard'
    interface: str | None      # None for a discard route
    metric: int | None = None
    since: int | None = None
    kind: str = "ip"           # ip (via a next hop) | interface (out a tunnel) | discard
    dest_ref: str | None = None


@dataclass(frozen=True)
class FwAddress:
    """A named address object (set address <name> ip-netmask <prefix>)."""
    name: str
    prefix: str                # CIDR
    ref: str | None = None     # the spec's reference, when written as one
    desc: str | None = None


@dataclass(frozen=True)
class FwGroup:
    """A static address group of address objects."""
    name: str
    members: tuple             # address object names
    cidrs: tuple               # their prefixes
    desc: str | None = None


@dataclass(frozen=True)
class FwProfiles:
    """The security profile group every allow rule carries, and the zone protection profile."""
    group: str | None                  # bp-default
    virus: str | None = None
    spyware: str | None = None
    vulnerability: str | None = None
    file_blocking: str | None = None
    zone_protection: str | None = None # zp-internet
    zp_flood: dict = field(default_factory=dict)  # {syn: {alarm, activate, maximal}, udp: ..., icmp: ..., other-ip: ...}
    zp_discard: tuple = ()             # discard options turned on: ip-spoof, strict-ip, ...


@dataclass(frozen=True)
class FwCrypto:
    name: str
    kind: str                  # ike | ipsec
    encryption: tuple
    hash: tuple                # ike: hash; ipsec: esp authentication
    dh: str
    lifetime_h: int


@dataclass(frozen=True)
class FwVpn:
    """A site-to-site IPsec tunnel the firewall terminates (chapter 4, build A revision 2): one IKEv2
    gateway on an interface, one tunnel bound to a tunnel interface, a proxy ID per protected pair."""
    name: str                  # ops-gw
    interface: str             # ethernet1/5
    local: str                 # its CIDR on that interface
    peer: str                  # the peer's address, bare
    peer_node: str | None      # the node that holds it
    tunnel_interface: str      # tunnel.1
    ike_crypto: str
    ipsec_crypto: str
    psk: str                   # the pre-shared key's name under state/secrets/ipsec (never the key)
    proxy_ids: tuple           # tuple[(name, local prefix, remote prefix)]
    zone: str                  # the tunnel interface's zone
    since: int | None = None


@dataclass(frozen=True)
class FwService:
    name: str
    protocol: str
    port: str


@dataclass(frozen=True)
class FwRule:
    name: str
    from_zones: tuple
    to_zones: tuple
    src: tuple             # symbolic references as written
    dst: tuple
    src_cidrs: tuple       # resolved prefixes, or ('any',)
    dst_cidrs: tuple
    services: tuple        # service names, ('application-default',) or ('any',)
    applications: tuple
    action: str            # allow | deny
    log_end: bool
    decision: str | None = None
    since: int | None = None
    desc: str | None = None
    src_members: tuple = ()   # what the rule prints: an address object or group name, else a bare prefix
    dst_members: tuple = ()
    profile_group: str | None = None
    src_parts: tuple = ()     # per reference: (ref, its prefixes, its printed members), for slicing
    dst_parts: tuple = ()


@dataclass(frozen=True)
class FwNat:
    name: str
    from_zones: tuple
    to_zones: tuple
    src: tuple
    dst: tuple
    src_cidrs: tuple
    dst_cidrs: tuple
    service: str
    dnat: str | None           # translated destination address, bare
    dnat_ref: str | None       # as written, e.g. 'vip:gw-internal'
    dnat_port: int | None
    snat_type: str | None      # dynamic-ip-and-port
    snat_interface: str | None
    decision: str | None = None
    since: int | None = None


@dataclass(frozen=True)
class FwSystem:
    dns: tuple             # bare addresses
    ntp: tuple
    service_route: str | None


@dataclass(frozen=True)
class FwAdmin:
    """Administrative access on one interface (chapter 4): an interface management profile that
    allows the listed services, to the permitted prefixes only."""
    interface: str         # ethernet1/3
    profile: str           # oob-admin
    allow: tuple           # services the profile turns on: https, ssh, ping
    permitted: tuple       # references as written (seg:oob)
    permitted_cidrs: tuple # resolved prefixes
    since: int | None = None


@dataclass(frozen=True, kw_only=True)
class Firewall(Node):
    hostname: str = "fw"
    vr: str = "core"
    public: str | None = None          # the public address, bare
    public_iface: str | None = None
    interfaces: tuple = ()             # tuple[FwInterface], in spec order with members after ae
    zones: tuple = ()
    routes: tuple = ()
    services: tuple = ()
    rules: tuple = ()
    nat: tuple = ()
    system: FwSystem | None = None
    admin: FwAdmin | None = None
    addresses: tuple = ()              # tuple[FwAddress]
    groups: tuple = ()                 # tuple[FwGroup]
    profiles: FwProfiles | None = None
    default_rules: dict = field(default_factory=dict)  # intrazone-default / interzone-default: {action, log_end}
    crypto: tuple = ()                 # tuple[FwCrypto]
    vpns: tuple = ()                   # tuple[FwVpn]
    app_default: dict = field(default_factory=dict)    # App-ID -> ('tcp/443', ...), its default ports

    def interface(self, name: str) -> FwInterface | None:
        for i in self.interfaces:
            if i.name == name:
                return i
        return None

    def zone(self, name: str) -> Zone | None:
        for z in self.zones:
            if z.name == name:
                return z
        return None


@dataclass(frozen=True)
class StorageIf:
    address: str              # CIDR
    nics: tuple               # container ports
    vlan: int
    mtu: int | None = None
    lacp: dict | None = None


@dataclass(frozen=True, kw_only=True)
class Storage(Node):
    product: str = "truenas"
    data: StorageIf | None = None
    mgmt_if: StorageIf | None = None
    gateway: str | None = None
    routes: tuple = ()
    dns: tuple = ()
    ntp: tuple = ()
    settings: dict = field(default_factory=dict)  # pool, data_disks, datasets, services, csi, ...

    @property
    def address(self) -> str | None:
        return self.data.address if self.data else None


# --------------------------------------------------------------------------------------------
# Services above the network


@dataclass(frozen=True)
class Gateway:
    name: str
    audience: str
    vip: str                  # bare
    vip_cidr: str             # /32
    pool_start: str
    pool_end: str
    pool_cidrs: tuple         # the pool as prefixes
    segment: str
    hostnames: tuple          # listener hostnames (FQDNs)
    decision: str | None = None
    since: int | None = None


@dataclass(frozen=True)
class Audience:
    name: str
    gateway: str
    models: tuple
    admin: bool
    populations: tuple
    decision: str | None = None
    since: int | None = None


@dataclass(frozen=True)
class Population:
    name: str
    segments: tuple
    prefixes: tuple
    zones: tuple
    audience: str
    clients: tuple
    resolver: str | None      # the first resolver the population's clients ask
    resolver_address: str | None
    answer: str               # as written: 'public' or 'vip:<gateway>'
    answer_address: str | None
    translated: bool
    decision: str | None = None
    since: int | None = None
    resolvers: tuple = ()     # every resolver the clients ask, in order


@dataclass(frozen=True)
class PlacementRow:
    model: str
    copy: str
    role: str                 # server | worker
    index: int                # 0 for the server, 0.. for workers
    pod: str                  # the row's Pod: '<controller>-0', its StatefulSet's one replica
    node: str
    rail: int
    nad: str                  # 'rail<r>'
    decision: str | None = None
    controller: str = ""      # the row's StatefulSet: '<model>-<copy>-server' or '<model>-<copy>-worker<k>'


@dataclass(frozen=True)
class Copy:
    model: str
    name: str
    rail: int
    parity: str
    server: str
    workers: tuple
    pods: tuple               # tuple[PlacementRow]
    decision: str | None = None
    spans: bool = False       # spans GPU nodes: the labeled stand-in for a model larger than one node

    @property
    def nodes(self) -> tuple:
        """The GPU nodes the copy's pods sit on, in placement order."""
        out: list = []
        for r in self.pods:
            if r.node not in out:
                out.append(r.node)
        return tuple(out)


@dataclass(frozen=True)
class ServedModel:
    name: str
    weights: str | None
    route_id: str
    audiences: tuple
    copies: tuple
    since: int | None = None


@dataclass(frozen=True)
class DnsView:
    name: str
    server: str               # the view's primary server
    kind: str                 # bind-views | bind-auth | dnsmasq
    match: tuple              # segment ids or node:<host> references, as written
    match_cidrs: tuple
    answer: str               # as written
    answer_address: str | None
    recursion: bool
    infra: bool               # holds the infrastructure records
    decision: str | None = None
    since: int | None = None
    servers: tuple = ()       # every server of the view: the primary, then its secondaries
    names: tuple = ("users", "admin", "internal")  # which name lists answer the view's answer (identity too, when listed)

    @property
    def secondaries(self) -> tuple:
        return tuple(s for s in self.servers if s != self.server)


@dataclass(frozen=True)
class DnsResolver:
    """A group of resolvers clients ask (dns.resolvers): BIND recursing for its clients and sending
    the platform's zone to the authoritative servers (bind-recursive), or the enterprise's dnsmasq
    answering its local names and forwarding the platform's zone (dnsmasq)."""

    name: str
    servers: tuple            # node names
    kind: str                 # bind-recursive | dnsmasq
    clients: tuple            # segment ids
    client_cidrs: tuple
    to: tuple                 # the authoritative servers the platform's zone goes to
    to_addresses: tuple       # their addresses, bare
    local: tuple              # dnsmasq: the hosts it answers itself under the org domain
    since: int | None = None


@dataclass(frozen=True)
class DnsRecord:
    name: str                 # FQDN
    address: str              # bare
    kind: str                 # infra | api


@dataclass(frozen=True)
class Dns:
    zone: str
    users: tuple              # FQDNs users type
    admin: tuple              # admin FQDNs
    wildcard: str | None      # '*.<zone>' or None
    views: tuple
    records: tuple
    internal: tuple = ()      # internal-only FQDNs (the internal view answers them)
    resolvers: tuple = ()     # tuple[DnsResolver]
    identity: tuple = ()      # the identity provider's FQDNs (the views that list identity answer them)

    def names_of(self, view: "DnsView") -> tuple:
        """The FQDNs a view answers with its answer, in order: users, admin, internal, identity names."""
        out: list = []
        for key in view.names:
            for n in {"users": self.users, "admin": self.admin, "internal": self.internal, "identity": self.identity}.get(key, ()):
                if n not in out:
                    out.append(n)
        return tuple(out)

    def resolver_of(self, node: str) -> "DnsResolver | None":
        for r in self.resolvers:
            if node in r.servers:
                return r
        return None


@dataclass(frozen=True)
class CaIntermediate:
    name: str
    cn: str
    key: str
    dns: tuple
    ip: tuple
    proof_inside: tuple = ()   # this intermediate's own proof names, when the spec gives them
    proof_outside: tuple = ()


@dataclass(frozen=True)
class CaLeaf:
    """A certificate sfab-ca signs on the lab host for one node (ca.leaves)."""

    name: str
    ca: str                    # the intermediate that signs it
    node: str
    dns: tuple
    ip: tuple                  # addresses, bare


@dataclass(frozen=True)
class Ca:
    root_cn: str
    intermediates: tuple
    proof_inside: tuple
    proof_outside: tuple
    leaves: tuple = ()         # tuple[CaLeaf]


@dataclass(frozen=True)
class Nad:
    name: str                 # 'rail3'
    rail: int
    master: str               # guest NIC 'rail3'
    prefix: str
    range_start: str
    range_end: str
    decision: str | None = None


@dataclass(frozen=True)
class Registry:
    node: str
    address: str
    port: int
    name: str                 # short name
    fqdn: str
    mirror: str               # 'address:port'
    scheme: str = "http"      # http, or https with a certificate from the lab CA


@dataclass(frozen=True)
class K8s:
    version: str
    api_vip: str
    api_fqdn: str
    pod_cidr: str
    service_cidr: str
    init: str | None
    control: tuple
    workers: tuple
    gateway_class: str
    labels: dict              # role -> label key
    l2_announce: dict
    nads: tuple               # tuple[Nad]
    registry: Registry | None


@dataclass(frozen=True)
class Pair:
    name: str
    members: tuple
    domain: int
    system_mac: str
    peer_link_pc: int
    peer_link_eths: tuple
    trunk_vlans: tuple
    session_vrf: str
    passthrough: bool
    decision: str | None = None
    since: int | None = None
    keepalive_eth: str | None = None     # 'eth13', the dedicated keepalive link on both members
    backup_vlan: int | None = None       # the backup keepalive's VLAN, on the peer link only


# --------------------------------------------------------------------------------------------
# The model


@dataclass(frozen=True)
class Model:
    meta: Meta
    lab: str
    profile: str
    build: str
    state: str
    step: int
    variant: str | None
    features: dict
    org: Org
    mgmt: Mgmt
    segments: dict            # id -> Segment
    vlans: dict               # id -> Vlan
    rails: dict               # r -> Rail
    nodes: dict               # name -> Node (Switch, Firewall, Storage, Host), spec order
    pairs: dict               # name -> Pair
    links: tuple              # tuple[Link], sorted by (a node, a port number, b node, b port number)
    dropped: tuple            # links of kept nodes that this slice dropped, same order
    gateways: dict
    audiences: dict
    populations: dict
    models: dict
    placement: tuple
    dns: Dns | None
    ca: Ca | None
    k8s: K8s | None
    registry: Registry | None
    common: dict              # kinds, switch, host, guest, timeouts, harness, naming
    warnings: tuple
    spec: dict                # the merged, when-filtered profile tree (before slicing), read-only

    # typed views
    @property
    def switches(self) -> dict:
        return {k: v for k, v in self.nodes.items() if isinstance(v, Switch)}

    @property
    def hosts(self) -> dict:
        return {k: v for k, v in self.nodes.items() if isinstance(v, Host)}

    @property
    def appliances(self) -> dict:
        return {k: v for k, v in self.nodes.items() if v.section == "appliances"}

    @property
    def firewall(self) -> Firewall | None:
        for v in self.nodes.values():
            if isinstance(v, Firewall):
                return v
        return None

    @property
    def storage(self) -> dict:
        return {k: v for k, v in self.nodes.items() if isinstance(v, Storage)}

    @property
    def routers(self) -> dict:
        return {k: v for k, v in self.nodes.items() if isinstance(v, Host) and v.kind == "frr"}

    @property
    def guests(self) -> dict:
        """VM guests (kind vm-node)."""
        return {k: v for k, v in self.nodes.items() if isinstance(v, Host) and v.kind == "vm-node"}

    @property
    def prefix(self) -> str:
        return f"{self.lab}-"

    @property
    def clabdir(self) -> str:
        return f"clab-{self.lab}"

    # lookups
    def node(self, name: str) -> Node:
        try:
            return self.nodes[name]
        except KeyError:
            raise KeyError(f"no node {name!r} in lab {self.lab}") from None

    def container(self, name: str) -> str:
        return self.node(name).container

    def links_of(self, name: str) -> tuple:
        return tuple(l for l in self.links if l.has(name))

    def link_at(self, node: str, eth: str | int) -> Link | None:
        e = ports.eth(eth)
        for l in self.links:
            if (l.a.node == node and l.a.eth == e) or (l.b.node == node and l.b.eth == e):
                return l
        return None

    def peer(self, node: str, eth: str | int) -> End | None:
        l = self.link_at(node, eth)
        return l.other(node) if l else None

    def pair_members(self, name: str) -> tuple:
        sw = self.nodes.get(name)
        if isinstance(sw, Switch) and sw.pair and sw.pair in self.pairs:
            return tuple(m for m in self.pairs[sw.pair].members if m in self.nodes)
        return ()

    def by_role(self, role: str) -> tuple:
        return tuple(n for n in self.nodes.values() if n.role == role)

    def by_group(self, group: str) -> tuple:
        return tuple(n for n in self.nodes.values() if n.group == group)

    def by_kind(self, kind: str) -> tuple:
        return tuple(n for n in self.nodes.values() if n.kind == kind)

    def segment_of(self, address: str) -> Segment | None:
        """The most specific segment holding an address or prefix."""
        best = None
        for s in self.segments.values():
            try:
                if addr.contains(s.prefix, address):
                    if best is None or s.prefixlen > best.prefixlen:
                        best = s
            except addr.AddrError:
                continue
        return best

    def to_json(self) -> dict:
        """A JSON-ready dict of the model (meta's versions, known and normalize left out)."""
        out = {}
        for f in dataclasses.fields(self):
            if f.name in ("meta", "spec", "common"):
                continue
            out[f.name] = _jsonable(getattr(self, f.name))
        out["meta"] = {
            "lab": self.meta.lab, "profile": self.meta.profile, "variant": self.meta.variant,
            "variant_file": self.meta.variant_file, "state": self.meta.state, "step": self.meta.step,
            "chapter": self.meta.chapter.chapter if self.meta.chapter else None,
            "prints": list(self.meta.chapter.prints) if self.meta.chapter else [],
        }
        return out


def _jsonable(v: Any) -> Any:
    if isinstance(v, End):
        return str(v)
    if dataclasses.is_dataclass(v) and not isinstance(v, type):
        return {f.name: _jsonable(getattr(v, f.name)) for f in dataclasses.fields(v) if f.name != "props"}
    if isinstance(v, dict):
        return {str(k): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


# --------------------------------------------------------------------------------------------
# Building


_DEFAULT_ROLE = {
    "paloalto_panos": "firewall", "truenas": "storage", "ontap": "storage", "bastion": "bastion",
    "client": "client", "resolver": "resolver", "frr": "router", "registry": "registry", "vpngw": "vpn-gw",
}
_PANOS_ETH = re.compile(r"^ethernet1/([0-9]+)$")


def _need(d: dict, key: str, where: str) -> Any:
    if key not in d or d[key] is None:
        raise SpecError(f"{where}: {key}: is required")
    return d[key]


_KEYS = {
    "segments": {"id", "prefix", "scope", "vlan", "desc", "per_port", "node_local", "reserved", "within", "since", "decision", "mtu"},
    "vlans": {"id", "name", "segment", "gw", "decision", "since"},
    "rails": {"r", "vlan", "segment", "since"},
    "gateways": {"id", "vip", "pool", "audience", "segment", "decision", "since"},
    "audiences": {"id", "gateway", "models", "admin", "decision", "since"},
    "populations": {"id", "segments", "zones", "audience", "clients", "resolver", "answer", "translated", "decision", "since"},
    "dns.resolvers": {"id", "servers", "kind", "clients", "to", "local", "since"},
    "ca.leaves": {"id", "ca", "node", "dns", "ip"},
    "models": {"id", "weights", "copies", "decision", "since"},
    "copies": {"id", "rail", "server", "workers", "spans", "decision", "since"},
    "attach": {"id", "to", "pc", "eth", "nics", "nic", "peer_nic", "mode", "vlan", "vlans", "mtu", "kind", "rail", "decision", "since", "tagged"},
    "fw.interfaces": {"name", "kind", "members", "lacp", "mtu", "parent", "tag", "address", "zone", "decision", "since", "mss_adjust"},
    "fw.zones": {"name", "decision", "since", "zone_protection"},
    "fw.routes": {"name", "dest", "nexthop", "interface", "metric", "decision", "since", "discard"},
    "fw.addresses": {"name", "ref", "prefix", "desc"},
    "fw.groups": {"name", "members", "desc"},
    "fw.vpns": {"name", "interface", "peer", "tunnel_interface", "ike_crypto", "ipsec_crypto", "psk", "proxy_ids", "since", "decision"},
    "fw.crypto": {"name", "kind", "encryption", "hash", "dh", "lifetime_h"},
    "fw.services": {"name", "protocol", "port"},
    "fw.rules": {"name", "from", "to", "src", "dst", "service", "application", "action", "log_end", "decision", "since", "desc", "profile", "drill"},
    "fw.nat": {"name", "from", "to", "src", "dst", "service", "dnat", "dnat_port", "snat", "decision", "since"},
    "fw.admin": {"interface", "profile", "allow", "permitted", "decision", "since"},
    "dns.views": {"id", "server", "kind", "match", "answer", "recursion", "infra", "names", "decision", "since"},
}


def _keys(d: dict, kind: str, where: str) -> dict:
    """Refuse keys an element of this kind does not have (a typo would otherwise be ignored)."""
    extra = set(d) - _KEYS[kind]
    if extra:
        raise SpecError(f"{where}: unknown key(s) {sorted(extra)} (known: {sorted(_KEYS[kind])})")
    return d


def _bare_cidr(c: str) -> str:
    """A host prefix without its /32 (as PAN-OS prints a rule member); a wider prefix or any as it is."""
    if c == "any" or "/" not in c:
        return c
    n = addr.net(c)
    return n.network_address.compressed if n.prefixlen == n.max_prefixlen else c


def _tuple_str(v: Any) -> tuple:
    if v is None:
        return ()
    if isinstance(v, (list, tuple)):
        return tuple(str(x) for x in v)
    return (str(v),)


class _Builder:
    def __init__(self, tree: dict, meta: Meta):
        self.t = tree
        self.meta = meta
        self.warnings: list[str] = []
        self.kinds = tree.get("kinds") or {}
        self.guest = tree.get("guest") or {}
        self.switch_c = tree.get("switch") or {}

    # -- plan ----------------------------------------------------------------------------
    def plan(self) -> None:
        t = self.t
        o = _need(t, "org", "profile")
        self.org = Org(name=o["name"], domain=o["domain"], short=o["short"], label_domain=o.get("label_domain", o["domain"]),
                       zone=str(o.get("zone") or ""))
        m = _need(t, "mgmt", "profile")
        subnet = m["subnet"]
        self.mgmtnet = Mgmt(network=m["network"], subnet=subnet, gw=addr.host(subnet, int(m.get("gw", 1))),
                            bridge=m.get("bridge", m["network"]), prefixlen=addr.net(subnet).prefixlen)
        self.segments: dict[str, Segment] = {}
        for s in t.get("segments") or []:
            sid = _need(s, "id", "segments")
            _keys(s, "segments", f"segments.{sid}")
            if sid in self.segments:
                raise SpecError(f"segments: duplicate id {sid}")
            addr.net(s["prefix"])
            self.segments[sid] = Segment(id=sid, prefix=str(s["prefix"]), scope=s.get("scope", "internal"),
                                         vlan=s.get("vlan"), desc=s.get("desc"), per_port=s.get("per_port"),
                                         node_local=bool(s.get("node_local", False)), reserved=bool(s.get("reserved", False)),
                                         within=s.get("within"), since=s.get("since"),
                                         mtu=int(s["mtu"]) if s.get("mtu") is not None else None)
        self.seg_by_vlan = {s.vlan: s for s in self.segments.values() if s.vlan is not None}
        self.fw_raw = t.get("firewall") or {}
        fw_ifaces = {i["name"]: i for i in self.fw_raw.get("interfaces") or []}
        self.vlans: dict[int, Vlan] = {}
        for v in t.get("vlans") or []:
            vid = int(_need(v, "id", "vlans"))
            _keys(v, "vlans", f"vlans.{vid}")
            seg = self.segments.get(v.get("segment"))
            if seg is None:
                raise SpecError(f"vlans: VLAN {vid} names unknown segment {v.get('segment')!r}")
            gw_node = gw_iface = gw = None
            if v.get("gw"):
                gw_node, _, gw_iface = str(v["gw"]).partition("/")
                fi = fw_ifaces.get(gw_iface)
                if gw_node != self.fw_raw.get("node") or fi is None or not fi.get("address"):
                    raise SpecError(f"vlans: VLAN {vid} gw {v['gw']!r} is not an addressed firewall interface")
                gw = addr.ip(fi["address"]).compressed
            self.vlans[vid] = Vlan(id=vid, name=v.get("name", str(vid)), segment=seg.id, prefix=seg.prefix,
                                   gw_node=gw_node, gw_iface=gw_iface, gw=gw, decision=v.get("decision"), since=v.get("since"))
        # raw nodes, in spec order
        self.raw: dict[str, dict] = {}
        self.sect: dict[str, str] = {}
        for section in ("switches", "appliances", "hosts"):
            for name, r in (t.get(section) or {}).items():
                if name in self.raw:
                    raise SpecError(f"node {name} is defined twice")
                r = dict(r or {})
                if section == "switches":
                    r.setdefault("kind", "dell_sonic")
                kind = _need(r, "kind", f"{section}.{name}")
                kd = self.kinds.get(kind)
                if kd is None:
                    raise SpecError(f"{section}.{name}: unknown kind {kind!r} (common.yaml kinds: {sorted(self.kinds)})")
                if kd.get("section") != section:
                    raise SpecError(f"{section}.{name}: kind {kind} belongs under {kd.get('section')}:")
                self.raw[name] = r
                self.sect[name] = section
        self.pairs_raw = t.get("pairs") or {}
        self.rails: dict[int, Rail] = {}
        rail_sw = {}
        for name, r in self.raw.items():
            if self.sect[name] != "switches":
                continue
            for x in r.get("rails") or []:
                rail_sw[int(x)] = name
        for rr in t.get("rails") or []:
            r = int(_need(rr, "r", "rails"))
            _keys(rr, "rails", f"rails.{r}")
            seg = self.segments.get(rr.get("segment"))
            if seg is None:
                raise SpecError(f"rails: rail {r} names unknown segment {rr.get('segment')!r}")
            self.rails[r] = Rail(r=r, vlan=int(rr["vlan"]), segment=seg.id, prefix=seg.prefix,
                                 switch=rail_sw.get(r), parity="odd" if r % 2 else "even")
        self.primary = {n: self._primary(n) for n in self.raw}

    def _primary(self, name: str) -> str | None:
        r = self.raw[name]
        kind = r["kind"]
        if kind in ("vm-node", "bastion") or (r.get("bond") and kind in ("resolver", "client")):
            seg = self.seg_by_vlan.get(int(r.get("vlan", 100)))
            if seg is None:
                raise SpecError(f"hosts.{name}: no segment for VLAN {r.get('vlan', 100)}")
            return seg.cidr(int(_need(r, "octet", f"hosts.{name}")))
        if kind == "truenas":
            d = (r.get("storage") or {}).get("data") or {}
            seg = self.segments.get(d.get("segment"))
            return seg.cidr(int(d["octet"])) if seg and d.get("octet") is not None else None
        ifs = r.get("ifaces") or {}
        if ifs:
            first = sorted(ifs, key=ports.eth_index)[0]
            return ifs[first].get("address")
        return None

    # -- attachments ---------------------------------------------------------------------
    def _single(self, role: str) -> str | None:
        names = [n for n, r in self.raw.items() if self.sect[n] == "switches" and r.get("role") == role]
        return names[0] if len(names) == 1 else None

    def attachments(self, name: str) -> list[dict]:
        r = self.raw[name]
        where = f"{self.sect[name]}.{name}"
        out = [dict(_keys(a, "attach", f"{where}.attach[{a.get('id')}]")) for a in r.get("attach") or []]
        gn = self.guest.get("nics") or {}
        if "bond" in r:
            b = r["bond"]
            to = b.get("to") or (next(iter(self.pairs_raw)) if len(self.pairs_raw) == 1 else None)
            if not to:
                raise SpecError(f"{where}: bond: needs to: when the profile has more than one pair")
            vlan = int(r.get("vlan", 100))
            tagged = [int(x["vlan"]) for x in b.get("tagged") or []]
            out.append({"id": "bond", "to": to, "pc": b["pc"], "eth": b["eth"], "nics": b.get("nics") or gn.get("bond") or ["eth1", "eth2"],
                        "mode": "access", "vlan": vlan, "mtu": b.get("mtu"), "decision": b.get("decision"), "tagged": tagged})
        if "oob_eth" in r:
            sw = r.get("oob_to") or self._single("oob_access")
            if not sw:
                raise SpecError(f"{where}: oob_eth: needs oob_to: when there is not exactly one oob_access switch")
            out.append({"id": "oob", "to": sw, "eth": r["oob_eth"], "nic": r.get("oob_nic") or gn.get("oob", "eth3"),
                        "vlan": int(self.raw[sw].get("vlan", 0)) or None, "kind": "oob"})
        if r.get("rails"):
            rr = r["rails"]
            first_nic = int(rr.get("first_nic", gn.get("first_rail", 4)))
            base = int(_need(rr, "switch_eth", f"{where}.rails"))
            for rail in sorted(self.rails.values(), key=lambda x: x.r):
                if rail.switch is None:
                    continue
                order = sorted(int(x) for x in self.raw[rail.switch].get("rails") or [])
                k = order.index(rail.r)
                out.append({"id": f"rail{rail.r}", "to": rail.switch, "eth": base + k, "nic": f"eth{first_nic + rail.r - 1}",
                            "vlan": rail.vlan, "kind": "rail", "rail": rail.r})
        return out

    def expand_links(self) -> list[Link]:
        links: list[Link] = []
        # peer links
        for pname, p in self.pairs_raw.items():
            members = list(_need(p, "members", f"pairs.{pname}"))
            if len(members) != 2:
                raise SpecError(f"pairs.{pname}: members: must name two switches")
            for m in members:
                if self.sect.get(m) != "switches":
                    raise SpecError(f"pairs.{pname}: {m} is not a switch")
            pl = _need(p, "peer_link", f"pairs.{pname}")
            ka = self._keepalive_raw(pname, p)
            # the peer link carries the served VLANs and, only there, the backup keepalive's VLAN
            pl_vlans = tuple(int(x) for x in p.get("trunk_vlans") or [])
            if ka.get("backup"):
                pl_vlans = pl_vlans + (int(ka["backup"]["vlan"]),)
            for e in pl["eth"]:
                a = End(members[0], ports.eth(e))
                b = End(members[1], ports.eth(e))
                links.append(Link(id=str(a), a=a, b=b, kind="peer-link", attachment=f"{pname}.peer-link",
                                  pc=int(pl["pc"]), mode="trunk", vlans=pl_vlans,
                                  mtu=pl.get("mtu"), decision=p.get("decision"), since=p.get("since")))
            if ka.get("link"):
                e = ka["link"]["eth"]
                a = End(members[0], ports.eth(e))
                b = End(members[1], ports.eth(e))
                links.append(Link(id=str(a), a=a, b=b, kind="keepalive", attachment=f"{pname}.keepalive",
                                  mtu=ka["link"].get("mtu"), decision=p.get("decision"), since=p.get("since")))
        for owner in self.raw:
            if self.sect[owner] == "switches":
                if self.raw[owner].get("attach"):
                    raise SpecError(f"switches.{owner}: switches take no attach:; wires are declared on the attaching node")
                continue
            for a in self.attachments(owner):
                links.extend(self._links_for(owner, a))
        return links

    def _keepalive_raw(self, pname: str, p: dict) -> dict:
        """pairs.<p>.keepalive, checked: {vrf, segment, link: {eth, prefix, mtu}, backup: {vlan,
        prefix, interval}}. Each prefix is a /31 inside the segment; the first member takes its
        first address, the second the other. {} when the pair declares none."""
        ka = p.get("keepalive")
        if not ka:
            return {}
        where = f"pairs.{pname}.keepalive"
        extra = set(ka) - {"vrf", "segment", "link", "backup"}
        if extra:
            raise SpecError(f"{where}: unknown key(s) {sorted(extra)}")
        vrf = str(_need(ka, "vrf", where))
        if not re.match(r"^Vrf[A-Za-z0-9_-]+$", vrf):
            raise SpecError(f"{where}.vrf: SONiC VRF names start with Vrf, got {vrf!r}")
        seg = self.segments.get(str(_need(ka, "segment", where)))
        if seg is None:
            raise SpecError(f"{where}.segment: unknown segment {ka.get('segment')!r}")
        lk = _need(ka, "link", where)
        for k, sub in (("link", lk), ("backup", ka.get("backup"))):
            if sub is None:
                continue
            net = addr.net(str(_need(sub, "prefix", f"{where}.{k}")))
            if net.prefixlen != 31 or not net.subnet_of(addr.net(seg.prefix)):
                raise SpecError(f"{where}.{k}.prefix: {net} must be a /31 inside segment {seg.id} ({seg.prefix})")
        b = ka.get("backup")
        if b is not None and not 2 <= int(_need(b, "vlan", f"{where}.backup")) <= 3966:
            raise SpecError(f"{where}.backup.vlan: SONiC 4.6.0 reserves VLANs 3967 to 4094; pick one from 2 to 3966")
        return {"vrf": vrf, "segment": seg, "link": lk, "backup": b}

    def _links_for(self, owner: str, a: dict) -> list[Link]:
        where = f"{owner}.attach[{a.get('id')}]"
        aid = _need(a, "id", where)
        to = _need(a, "to", where)
        att = f"{owner}.{aid}"
        common = {"attachment": att, "decision": a.get("decision"), "since": a.get("since"),
                  "tagged": tuple(int(x["vlan"] if isinstance(x, dict) else x) for x in a.get("tagged") or [])}
        if to in self.pairs_raw:
            p = self.pairs_raw[to]
            eths = a["eth"] if isinstance(a["eth"], list) else [a["eth"]]
            nics = list(_need(a, "nics", where))
            k = len(eths)
            if len(nics) != 2 * k:
                raise SpecError(f"{where}: a bundle to pair {to} with {k} port(s) per switch needs {2 * k} nics, got {len(nics)}")
            mode = a.get("mode", "access")
            vlans = tuple(int(x) for x in a.get("vlans") or []) if mode == "trunk" else (int(_need(a, "vlan", where)),)
            out = []
            for mi, member in enumerate(p["members"]):
                for j, e in enumerate(eths):
                    nic = ports.eth(nics[mi * k + j])
                    ea = End(owner, nic)
                    out.append(Link(id=str(ea), a=ea, b=End(member, ports.eth(e)), kind="bundle", pc=int(_need(a, "pc", where)),
                                    mode=mode, vlans=vlans, mtu=a.get("mtu"), **common))
            return out
        if to not in self.raw:
            raise SpecError(f"{where}: to: {to!r} is not a node or pair in this state")
        if self.sect[to] == "switches":
            if "pc" in a:
                raise SpecError(f"{where}: a PortChannel to a single switch is not part of this design")
            nic = ports.eth(_need(a, "nic", where))
            role = self.raw[to].get("role")
            kind = a.get("kind") or ("rail" if role == "rail_vlan" else "oob" if role == "oob_access" else "access")
            vlan = a.get("vlan")
            if vlan is None:
                raise SpecError(f"{where}: vlan: is required on an access port")
            ea = End(owner, nic)
            return [Link(id=str(ea), a=ea, b=End(to, ports.eth(_need(a, "eth", where))), kind=kind, mode="access",
                         vlans=(int(vlan),), mtu=a.get("mtu"), rail=a.get("rail"), **common)]
        nic = ports.eth(_need(a, "nic", where))
        ea = End(owner, nic)
        return [Link(id=str(ea), a=ea, b=End(to, ports.eth(_need(a, "peer_nic", where))), kind="p2p", **common)]

    # -- nodes ---------------------------------------------------------------------------
    def base(self, name: str, nics: tuple) -> dict:
        r = self.raw[name]
        kind = r["kind"]
        kd = self.kinds[kind]
        img_key = kd["image"]
        images = (self.meta.versions or {}).get("images") or {}
        if img_key not in images:
            raise SpecError(f"{name}: image key {img_key!r} is not in versions.yaml images:")
        got = {}
        # a host that serves models holds them in memory: serving: {mem_gib, vcpus} sizes it in a lab
        # whose features turn serving on (build A revision 2: a GPU node holds a copy of each model)
        sv = (r.get("serving") or {}) if self.meta.features.get("serving") and self.meta.features.get("k8s") else {}
        for what in ("mem_gib", "vcpus", "state_gib", "layer_gib"):
            v = kd.get(what) if kd.get(what) is not None else sv.get(what, r.get(what))
            if v is None:
                raise SpecError(f"{name}: {what}: is required for kind {kind}")
            got[what] = float(v)
        role = r.get("role") or (r.get("group") if kind == "vm-node" else _DEFAULT_ROLE.get(kind, kind))
        octet = int(_need(r, "mgmt", name))
        return dict(name=name, kind=kind, clab_kind=kd["clab_kind"], image=images[img_key]["ref"], image_key=img_key,
                    section=self.sect[name], group=str(r.get("group") or role), role=str(role),
                    mgmt=self.mgmtnet.addr(octet), mgmt_octet=octet, container=f"{self.meta.lab}-{name}",
                    budget=Budget(**got), nics=nics,
                    requires=_tuple_str(r.get("requires")), decision=r.get("decision"), since=r.get("since"),
                    pending=r.get("pending"), props=r)

    def run(self, keep: set[str] | None) -> Model:
        self.plan()
        all_links = self.expand_links()
        names = list(self.raw) if keep is None else [n for n in self.raw if n in keep]
        kept = set(names)
        order = lambda l: (l.a.node, l.a.index, l.b.node, l.b.index)  # noqa: E731
        links = sorted((l for l in all_links if l.a.node in kept and l.b.node in kept), key=order)
        dropped = tuple(sorted((l for l in all_links if l.has_any(kept) and not (l.a.node in kept and l.b.node in kept)),
                               key=order)) if keep is not None else ()
        self.links = links
        self.kept = kept
        self.gateways = self._gateways()
        self.models = self._models()
        nodes: dict[str, Node] = {}
        for n in names:
            kind = self.raw[n]["kind"]
            if self.sect[n] == "switches":
                nodes[n] = self._switch(n)
            elif kind == "paloalto_panos":
                nodes[n] = self._firewall(n)
            elif kind in ("truenas", "ontap"):
                nodes[n] = self._storage(n)
            else:
                nodes[n] = self._host(n)
        pairs = {}
        for pname, p in self.pairs_raw.items():
            if not any(m in kept for m in p["members"]):
                continue
            ka = self._keepalive_raw(pname, p)
            pairs[pname] = Pair(name=pname, members=tuple(p["members"]), domain=int(p["domain"]), system_mac=str(p["system_mac"]),
                                peer_link_pc=int(p["peer_link"]["pc"]), peer_link_eths=tuple(ports.eth(e) for e in p["peer_link"]["eth"]),
                                trunk_vlans=tuple(int(x) for x in p.get("trunk_vlans") or []),
                                session_vrf=ka["vrf"] if ka else str(p.get("session_vrf", "mgmt")),
                                passthrough=bool(p.get("passthrough", False)), decision=p.get("decision"), since=p.get("since"),
                                keepalive_eth=ports.eth(ka["link"]["eth"]) if ka else None,
                                backup_vlan=int(ka["backup"]["vlan"]) if ka and ka.get("backup") else None)
        for n in names:
            if self.raw[n].get("pending"):
                self.warnings.append(f"{n}: pending: {self.raw[n]['pending']}")
        populations = self._populations(nodes)
        audiences = self._audiences(populations)
        reg = self._registry(nodes)
        common = {k: self.t.get(k) for k in ("kinds", "switch", "host", "guest", "timeouts", "harness", "naming") if k in self.t}
        return Model(
            meta=self.meta, lab=self.meta.lab, profile=self.meta.profile, build=str(self.t.get("build", self.meta.profile.upper())),
            state=self.meta.state, step=self.meta.step, variant=self.meta.variant, features=dict(self.meta.features),
            org=self.org, mgmt=self.mgmtnet, segments=self.segments, vlans=self.vlans, rails=self.rails, nodes=nodes,
            pairs=pairs, links=tuple(links), dropped=dropped, gateways=self.gateways, audiences=audiences,
            populations=populations, models=self.models, placement=tuple(r for m in self.models.values() for c in m.copies for r in c.pods),
            dns=self._dns(nodes), ca=self._ca(), k8s=self._k8s(nodes, reg), registry=reg, common=common,
            warnings=tuple(self.warnings), spec=self.t,
        )

    # links touching a node, with the node's own end first
    def _ends(self, name: str) -> list[tuple[End, End, Link]]:
        out = []
        for l in self.links:
            if l.a.node == name:
                out.append((l.a, l.b, l))
            if l.b.node == name:
                out.append((l.b, l.a, l))
        return sorted(out, key=lambda x: x[0].index)

    def _owner_eth(self, l: Link) -> str:
        return f"{l.a.node}-{l.a.eth}"

    def _l2(self, role: str) -> dict:
        """The profile's l2: policy for a switch role ({} when the role is not under it): port_mtu,
        stp (the spanning-tree mode), edge (host-facing ports get portfast and BPDU guard) and
        storm ((type, kbps) pairs, typed on every host-facing member and access port)."""
        l2 = self.t.get("l2") or {}
        if not l2 or role not in (l2.get("roles") or []):
            return {}
        extra = set(l2) - {"roles", "port_mtu", "stp", "edge", "storm_control_kbps"}
        if extra:
            raise SpecError(f"l2: unknown key(s) {sorted(extra)}")
        storm = tuple((str(k), int(v)) for k, v in (l2.get("storm_control_kbps") or {}).items())
        for k, v in storm:
            if k not in ("broadcast", "unknown-unicast", "unknown-multicast") or not 0 <= v <= 100000000:
                raise SpecError(f"l2.storm_control_kbps: {k} {v} (SONiC 4.6.0 takes broadcast, unknown-unicast or unknown-multicast, 0 to 100000000 kbps)")
        stp = l2.get("stp")
        if stp is not None and stp not in ("pvst", "rapid-pvst", "mst"):
            raise SpecError(f"l2.stp: {stp!r} is not a SONiC 4.6.0 spanning-tree mode")
        return {"port_mtu": int(l2["port_mtu"]) if l2.get("port_mtu") else None, "stp": stp,
                "edge": bool(l2.get("edge")), "storm": storm}

    def _switch(self, name: str) -> Switch:
        r = self.raw[name]
        role = _need(r, "role", f"switches.{name}")
        if role not in ("mclag_member", "rail_vlan", "oob_access"):
            self.warnings.append(f"switches.{name}: role {role} has no build A renderer")
        pair = r.get("pair")
        p = self.pairs_raw.get(pair) if pair else None
        if pair and p is None:
            raise SpecError(f"switches.{name}: pair {pair!r} is not in pairs:")
        if p and name not in p["members"]:
            raise SpecError(f"switches.{name}: not a member of pair {pair}")
        partner = next((m for m in p["members"] if m != name), None) if p else None
        ka = self._keepalive_raw(pair, p) if p else {}
        backup_vlan = int(ka["backup"]["vlan"]) if ka.get("backup") else None
        pol = self._l2(role)
        pmtu = pol.get("port_mtu")
        nics = []
        pcs: dict[int, list] = {}
        access = []
        vlans: set[int] = set()
        keepalive_end = None
        for own, far, l in self._ends(name):
            e = own.index
            nat = ports.native(e)
            if l.kind == "keepalive":
                keepalive_end = (own, far, l)
                nics.append(Nic(node=name, eth=own.eth, index=e, role="keepalive", attachment=l.attachment, peer=far, link=l.id,
                                native=nat, mtu=l.mtu or pmtu, desc="mclag-keepalive"))
                continue
            if l.kind in ("peer-link", "bundle"):
                role_n = "peer-link" if l.kind == "peer-link" else "bundle-member"
                pcs.setdefault(l.pc, []).append((own, far, l))
                if l.kind == "peer-link":
                    i = [ports.eth_index(x) for x in p["peer_link"]["eth"]].index(e) + 1 if p else 1
                    desc = f"peer-link-{i}"
                else:
                    desc = self._owner_eth(l)
                nics.append(Nic(node=name, eth=own.eth, index=e, role=role_n, attachment=l.attachment, peer=far, link=l.id,
                                native=nat, mtu=l.mtu, vlan=l.vlans[0] if l.mode == "access" else None,
                                vlans=l.vlans if l.mode == "trunk" else (), desc=desc))
                # the backup keepalive's VLAN rides the peer link only and is not a served VLAN
                vlans.update(v for v in l.vlans if v != backup_vlan or l.kind != "peer-link")
                vlans.update(l.tagged)
            else:
                v = l.vlans[0]
                desc = f"{l.a.node}-rail{l.rail}" if l.kind == "rail" else self._owner_eth(l)
                edge = bool(pol.get("edge")) and l.kind in ("access", "rail")
                access.append(AccessPort(eth=e, ifname=own.eth, native=nat, vlan=v, desc=desc, kind=l.kind, peer=far,
                                         rail=l.rail, decision=l.decision, mtu=max(l.mtu or 0, pmtu or 0) or None,
                                         edge=edge, storm=pol.get("storm", ()) if edge else ()))
                nics.append(Nic(node=name, eth=own.eth, index=e, role=l.kind, attachment=l.attachment, peer=far, link=l.id,
                                native=nat, mtu=l.mtu, vlan=v, rail=l.rail, desc=desc))
                vlans.add(v)
        fw_name = self.fw_raw.get("node")
        portchannels = []
        for pc, legs in sorted(pcs.items()):
            l0 = legs[0][2]
            kinds = {x[2].kind for x in legs}
            if len(kinds) > 1 or len({x[2].attachment for x in legs}) > 1:
                raise SpecError(f"switches.{name}: PortChannel {pc} is used by more than one attachment")
            desc_of = {n.eth: n.desc or "" for n in nics}
            mtu = max(l0.mtu or 0, pmtu or 0) or None
            members = tuple(Member(eth=o.index, ifname=o.eth, native=ports.native(o.index), desc=desc_of[o.eth], peer=f, mtu=mtu)
                            for o, f, x in sorted(legs, key=lambda q: q[0].index))
            if l0.kind == "peer-link":
                desc, mclag, peer_node = "peer-link", False, None
            else:
                owner, _, aid = l0.attachment.partition(".")
                desc, mclag, peer_node = f"{owner}-{aid}", p is not None, owner
            # host-facing: every bundle but the peer link and the firewall's trunk (which runs no STP)
            edge = bool(pol.get("edge")) and l0.kind == "bundle" and peer_node != fw_name
            portchannels.append(PortChannel(id=pc, name=f"PortChannel{pc}", desc=desc, kind="peer-link" if l0.kind == "peer-link" else "mclag",
                                            mode=l0.mode or "access", vlans=l0.vlans, vlan=l0.vlans[0] if l0.mode == "access" else None,
                                            mclag=mclag, fast_rate=True, mtu=mtu, members=members, peer_node=peer_node,
                                            attachment=l0.attachment, decision=l0.decision, tagged=tuple(sorted(l0.tagged)),
                                            edge=edge, storm=pol.get("storm", ()) if edge else ()))
        rails = tuple(sorted(int(x) for x in r.get("rails") or []))
        oob_vlan = int(r["vlan"]) if role == "oob_access" and r.get("vlan") is not None else None
        if role == "mclag_member" and p:
            vlans.update(int(x) for x in p.get("trunk_vlans") or [])
        if role == "rail_vlan":
            vlans.update(self.rails[x].vlan for x in rails if x in self.rails)
        if oob_vlan:
            vlans.add(oob_vlan)
        for v in vlans:
            if v not in self.vlans:
                raise SpecError(f"switches.{name}: VLAN {v} is not in vlans:")
        mclag = keepalive = None
        if role == "mclag_member" and p and partner in self.kept:
            idx = list(p["members"]).index(name)
            if ka:
                lk = ka["link"]
                ka_net = addr.net(str(lk["prefix"]))
                mine, theirs = (ka_net[idx], ka_net[1 - idx])
                bk = ka.get("backup")
                b_mine = b_theirs = None
                if bk:
                    b_net = addr.net(str(bk["prefix"]))
                    b_mine, b_theirs = b_net[idx], b_net[1 - idx]
                if keepalive_end is None:
                    raise SpecError(f"switches.{name}: pair {pair} declares a keepalive link on eth{lk['eth']} but the link is not in this lab")
                keepalive = Keepalive(vrf=ka["vrf"], eth=keepalive_end[0].index, ifname=keepalive_end[0].eth,
                                      native=ports.native(keepalive_end[0].index), address=f"{mine}/31", peer_address=str(theirs),
                                      mtu=keepalive_end[2].mtu or pmtu, backup_vlan=backup_vlan,
                                      backup_address=f"{b_mine}/31" if bk else None, backup_peer=str(b_theirs) if bk else None,
                                      backup_interval=int(bk.get("interval", 1)) if bk else None, segment=ka["segment"].id)
                mclag = MclagDomain(domain=int(p["domain"]), source_ip=str(mine), peer_ip=str(theirs), peer=partner,
                                    peer_link=f"PortChannel{int(p['peer_link']['pc'])}", peer_link_pc=int(p["peer_link"]["pc"]),
                                    system_mac=str(p["system_mac"]), session_vrf=ka["vrf"],
                                    backup_source_ip=str(b_mine) if bk else None, backup_peer_ip=str(b_theirs) if bk else None,
                                    backup_vrf=ka["vrf"] if bk else None, backup_interval=keepalive.backup_interval)
            else:
                mclag = MclagDomain(domain=int(p["domain"]), source_ip=self.mgmtnet.addr(int(r["mgmt"])),
                                    peer_ip=self.mgmtnet.addr(int(self.raw[partner]["mgmt"])), peer=partner,
                                    peer_link=f"PortChannel{int(p['peer_link']['pc'])}", peer_link_pc=int(p["peer_link"]["pc"]),
                                    system_mac=str(p["system_mac"]), session_vrf=str(p.get("session_vrf", "mgmt")))
        nics_t = tuple(sorted(nics, key=lambda n: n.index))
        sflow = bool(r.get("sflow", False))
        used = [n.index for n in nics_t]
        return Switch(**self.base(name, nics_t), pair=pair, partner=partner, vlans=tuple(sorted(vlans)),
                      portchannels=tuple(portchannels), access_ports=tuple(sorted(access, key=lambda a: a.eth)), mclag=mclag,
                      keepalive=keepalive, stp=pol.get("stp"),
                      rails=rails, oob_vlan=oob_vlan, num_nics=ports.num_nics(used, sflow=sflow),
                      passthrough=bool(r.get("passthrough", p.get("passthrough", False) if p else False)), sflow=sflow,
                      mgmt_vrf=str(self.switch_c.get("mgmt_vrf", "mgmt")))

    def _vlan_gw(self, vid) -> str | None:
        """A VLAN's gateway address, bare, while the node that holds it is in the lab. A slice
        without that node (chapter 5's rail slice holds no firewall) gives its hosts no gateway, so no
        guest is handed a default route toward an address nothing in the lab answers."""
        v = self.vlans.get(vid)
        if v is None or not v.gw:
            return None
        kept = getattr(self, "kept", None)
        if kept is not None and v.gw_node and v.gw_node not in kept:
            return None
        return v.gw

    def _gw_of(self, ref: str | None) -> str | None:
        """'fw/ae1.200' -> the interface's address, bare."""
        if not ref:
            return None
        node, _, ifn = str(ref).partition("/")
        for i in self.fw_raw.get("interfaces") or []:
            if node == self.fw_raw.get("node") and i["name"] == ifn and i.get("address"):
                return addr.ip(i["address"]).compressed
        raise SpecError(f"gateway reference {ref!r} is not an addressed firewall interface")

    def _host(self, name: str) -> Host:
        r = self.raw[name]
        kind = r["kind"]
        is_vm = kind == "vm-node"
        mac_prefix = str(self.guest.get("mac_prefix", "02:5a"))
        octet_m = int(r["mgmt"])
        tables = dict(self.guest.get("tables") or {})
        mtu = int(self.guest.get("data_mtu", 9000))
        nics = []
        bond_members = []
        bond_link = None
        oob = None
        rails = []
        ifaces_raw = {ports.eth(k): v for k, v in (r.get("ifaces") or {}).items()}
        for own, far, l in self._ends(name):
            mac = addr.mac(mac_prefix, octet_m, own.index) if is_vm else None
            if l.kind == "bundle" and l.a.node == name:
                bond_members.append(own.eth)
                bond_link = l
                nics.append(Nic(node=name, eth=own.eth, index=own.index, role="bond-member", attachment=l.attachment, peer=far,
                                link=l.id, mac=mac, mtu=mtu, vlan=l.vlans[0] if l.mode == "access" else None))
            elif l.kind == "oob" and l.a.node == name:
                seg = self.seg_by_vlan.get(l.vlans[0])
                octet = int(_need(r, "octet", f"hosts.{name}"))
                bmc = self.guest.get("bmc") or {}
                oob = OobIf(eth=own.eth, address=seg.cidr(octet), gateway=self._vlan_gw(l.vlans[0]), table=int(tables.get("oob", 100)),
                            vlan=l.vlans[0], netns=(str(bmc["netns"]) if is_vm and bmc.get("netns") else None),
                            services=_tuple_str(bmc.get("services")) if is_vm else ())
                nics.append(Nic(node=name, eth=own.eth, index=own.index, role="oob", attachment=l.attachment, peer=far, link=l.id,
                                mac=mac, vlan=l.vlans[0], address=oob.address, gateway=oob.gateway))
            elif l.kind == "rail" and l.a.node == name:
                idx = int(_need(r, "index", f"hosts.{name}"))
                rail = self.rails[l.rail]
                ri = RailIf(rail=rail.r, vlan=rail.vlan, eth=own.eth, ifname=f"rail{rail.r}",
                            address=addr.host_cidr(rail.prefix, 10 + idx), switch=far.node, switch_eth=far.eth,
                            switch_native=ports.native(far.index), mac=mac)
                rails.append(ri)
                nics.append(Nic(node=name, eth=own.eth, index=own.index, role="rail", attachment=l.attachment, peer=far, link=l.id,
                                ifname=ri.ifname, mac=mac, mtu=mtu, vlan=rail.vlan, rail=rail.r))
            else:
                ir = ifaces_raw.get(own.eth) or {}
                nics.append(Nic(node=name, eth=own.eth, index=own.index, role=l.kind, attachment=l.attachment,
                                peer=far, link=l.id, mac=mac, address=ir.get("address"), gateway=ir.get("gw")))
        bond = None
        address = gateway = None
        vlan = None
        if bond_link is not None:
            vlan = bond_link.vlans[0]
            seg = self.seg_by_vlan[vlan]
            address = seg.cidr(int(_need(r, "octet", f"hosts.{name}")))
            gateway = self._vlan_gw(vlan)
            bc = self.guest.get("bond") or {}
            members = tuple(sorted(bond_members, key=ports.eth_index))
            bmtu = int((r.get("bond") or {}).get("ip_mtu") or mtu)  # the host's IP MTU in its VLAN (bond.ip_mtu)
            vifs = []
            for tv in (r.get("bond") or {}).get("tagged") or []:
                tvid = int(_need(tv, "vlan", f"hosts.{name}.bond.tagged"))
                tseg = self.seg_by_vlan.get(tvid)
                if tseg is None:
                    raise SpecError(f"hosts.{name}.bond.tagged: VLAN {tvid} has no segment")
                toct = int(tv.get("octet", _need(r, "octet", f"hosts.{name}")))
                vifs.append(VlanIf(name=f"bond0.{tvid}", vlan=tvid, segment=tseg.id, address=tseg.cidr(toct),
                                   mtu=int(tv.get("ip_mtu") or tseg.mtu or mtu), gateway=self._vlan_gw(tvid) if tv.get("table") else None,
                                   table=int(tv["table"]) if tv.get("table") else None, prefix=tseg.prefix))
            bond = Bond(name="bond0", members=members, pc=int(bond_link.pc), vlan=vlan, address=address, gateway=gateway, mtu=bmtu,
                        mode=str(bc.get("mode", "802.3ad")), lacp_rate=str(bc.get("lacp_rate", "fast")), miimon=int(bc.get("miimon", 100)),
                        xmit_hash_policy=str(bc.get("xmit_hash_policy", "layer3+4")),
                        mac=addr.mac(mac_prefix, octet_m, ports.eth_index(members[0])) if is_vm else None, vlan_ifs=tuple(vifs))
        elif kind in ("vm-node", "bastion"):
            address = self.primary[name]
            vlan = int(r.get("vlan", 100))
            gateway = self._vlan_gw(vlan)
        ifaces = []
        links_by_eth = {own.eth: far for own, far, _ in self._ends(name)}
        for eth in sorted(ifaces_raw, key=ports.eth_index):
            ir = ifaces_raw[eth]
            a = ir.get("address")
            seg = None
            if a:
                addr.iface(a)
                seg = self._seg_id(a)
            smtu = self.segments[seg].mtu if seg else None
            ifaces.append(Iface(eth=eth, address=a, gateway=ir.get("gw"), segment=seg, peer=links_by_eth.get(eth), mtu=ir.get("mtu") or smtu))
            if address is None and a:
                address, gateway = a, ir.get("gw")
        routes = tuple(self._route(name, x) for x in r.get("routes") or [])
        relay = None
        if r.get("relay") and rails:
            relay = self._relay(rails)
        resolvers = self._resolvers_of(name, r, address)
        resolver = resolvers[0] if resolvers else None
        res_addrs = tuple(addr.ip(self.primary[x]).compressed for x in resolvers if self.primary.get(x))
        res_addr = None
        if resolver:
            p = self.primary.get(resolver)
            res_addr = addr.ip(p).compressed if p else None
        return Host(**self.base(name, tuple(sorted(nics, key=lambda n: n.index))), k8s=r.get("k8s"), index=r.get("index"), vlan=vlan,
                    address=address, gateway=gateway, bond=bond, oob=oob, rails=tuple(sorted(rails, key=lambda x: x.rail)),
                    relay=relay, ifaces=tuple(ifaces), routes=routes, resolver=resolver, resolver_address=res_addr,
                    resolvers=resolvers, resolver_addresses=res_addrs,
                    dns_role=r.get("dns_role"), resolv_options=r.get("resolv_options"), mgmt_mac=addr.mac(mac_prefix, octet_m, 0) if is_vm else None,
                    disk_gib=int(_need(r, "disk_gib", f"hosts.{name}")) if is_vm else None, tables=tables)

    _ROUTE_KEYS = {"id", "dest", "via", "dev", "src", "first", "decision", "since"}

    def _route(self, name: str, x: dict) -> Route:
        """A host's static route. dest may be written seg:<segment> (that segment's prefix) and via
        public (the firewall's public address); the reference is kept beside the resolved value, so
        a renderer can tell a route the spec wrote by reference (the routes to the inside prefixes)."""
        where = f"hosts.{name}.routes[{x.get('id') or x.get('dest')}]"
        extra = set(x) - self._ROUTE_KEYS
        if extra:
            raise SpecError(f"{where}: unknown key(s) {sorted(extra)} (known: {sorted(self._ROUTE_KEYS)})")
        dest, dest_ref = str(_need(x, "dest", where)), None
        kind, _, val = dest.partition(":")
        if kind == "seg" and val:
            seg = self.segments.get(val)
            if seg is None:
                raise SpecError(f"{where}: dest {dest!r}: no segment {val!r} in this state")
            dest, dest_ref = seg.prefix, dest
        via, via_ref = x.get("via"), None
        if via == "public":
            pub = self._public()
            if not pub:
                raise SpecError(f"{where}: via public, but the firewall has no public interface in this state")
            via, via_ref = pub, "public"
        return Route(dest=dest, via=via, dev=x.get("dev"), src=x.get("src"), id=x.get("id"), first=bool(x.get("first", False)),
                     dest_ref=dest_ref, via_ref=via_ref, decision=x.get("decision"), since=x.get("since"))

    def _seg_id(self, a: str) -> str | None:
        best = None
        for s in self.segments.values():
            if addr.contains(s.prefix, addr.prefix_of(a) if "/" in a else a):
                if best is None or s.prefixlen > best.prefixlen:
                    best = s
        return best.id if best else None

    @staticmethod
    def _resolver_list(v) -> tuple:
        """A resolver as the spec writes it: a node, a list of nodes, or (the older form) a list of
        {node, when} entries, which the when filter has already cut to the state's own."""
        if not v:
            return ()
        if isinstance(v, (list, tuple)):
            return tuple(str(x["node"]) if isinstance(x, dict) else str(x) for x in v)
        return (str(v),)

    def _resolvers_of(self, name: str, r: dict, address: str | None) -> tuple:
        v = self._resolver_list(r.get("resolver"))
        if v:
            for x in v:
                if x not in self.raw:
                    raise SpecError(f"hosts.{name}: resolver {x!r} is not a node in this state")
            return v
        if not address:
            return ()
        seg = self._seg_id(address)
        for p in self.t.get("populations") or []:
            if seg in (p.get("segments") or []):
                return self._resolver_list(p.get("resolver"))
        return ()

    def _resolver_of(self, name: str, r: dict, address: str | None) -> str | None:
        v = self._resolvers_of(name, r, address)
        return v[0] if v else None

    def _relay(self, rails: list[RailIf]) -> Relay:
        rc = self.t.get("relay") or {}
        seg = self.segments.get(rc.get("segment", "relay"))
        if seg is None:
            raise SpecError("relay: segment is not in segments:")
        out = []
        by_r = {x.rail: x for x in rails}
        for x in sorted(rails, key=lambda q: q.rail):
            src = addr.ip(x.address).compressed
            routes = tuple(Route(dest=self.rails[j].prefix, via=seg.host(j), dev="relay", src=src)
                           for j in sorted(by_r) if j != x.rail)
            out.append(RelayNs(rail=x.rail, ns=f"gpu{x.rail}", rail_if=f"rail{x.rail}", rail_master=x.ifname, rail_addr=x.address,
                               veth="relay", bridge_port=f"rl{x.rail}", relay_addr=seg.cidr(x.rail), routes=routes))
        return Relay(bridge=str(rc.get("bridge", "relay0")), prefix=seg.prefix, mtu=int(rc.get("mtu", 9000)),
                     rp_filter=int(rc.get("rp_filter", 2)), ip_forward=int(rc.get("ip_forward", 1)), namespaces=tuple(out))

    # -- firewall ------------------------------------------------------------------------
    def _ref(self, ref: str, where: str, public: str | None) -> tuple:
        s = str(ref)
        if s == "any":
            return ("any",)
        if s == "public":
            if not public:
                raise SpecError(f"{where}: 'public' used but the firewall has no public interface")
            return (addr.host32(public),)
        kind, _, val = s.partition(":")
        if kind == "vip" and val:
            g = self.gateways.get(val)
            if g is None:
                raise SpecError(f"{where}: {s!r}: no Gateway {val!r} in this state")
            return (g.vip_cidr,)
        if kind == "seg" and val:
            seg = self.segments.get(val)
            if seg is None:
                raise SpecError(f"{where}: {s!r}: no segment {val!r} in this state")
            return (seg.prefix,)
        if kind == "node" and val:
            p = self.primary.get(val)
            if not p:
                raise SpecError(f"{where}: {s!r}: node {val!r} has no primary address in this state")
            return (addr.host32(p),)
        if kind == "mgmt" and val:
            st = ((self.raw.get(val) or {}).get("storage") or {}).get("mgmt_if") or {}
            seg = self.segments.get(st.get("segment"))
            if seg is None or st.get("octet") is None:
                raise SpecError(f"{where}: {s!r}: {val!r} has no storage management address")
            return (addr.host32(seg.host(int(st["octet"]))),)
        if kind == "fw" and val:
            # one of the firewall's own interface addresses (the gateway a segment's hosts ping)
            fi = next((i for i in (getattr(self, "fw_raw", None) or {}).get("interfaces") or [] if str(i.get("name")) == val), None)
            if not fi or not fi.get("address"):
                raise SpecError(f"{where}: {s!r}: the firewall has no interface {val!r} with an address")
            return (addr.host32(str(fi["address"]).split("/")[0]),)
        if kind in ("addr", "group") and val:
            objs = getattr(self, "fw_objects", {}).get(kind, {})
            if val not in objs:
                raise SpecError(f"{where}: {s!r}: no firewall {'address object' if kind == 'addr' else 'address group'} {val!r}")
            return tuple(objs[val])
        try:
            if "/" in s:
                return (str(addr.net(s)),)
            return (addr.host32(s),)
        except addr.AddrError:
            raise SpecError(f"{where}: bad address reference {s!r}") from None

    def _firewall(self, name: str) -> Firewall:
        f = self.fw_raw
        if f.get("node") != name:
            raise SpecError(f"appliances.{name}: firewall: node: must name it")
        own = {o.eth: (o, far, l) for o, far, l in self._ends(name)}
        nics = []
        for o, far, l in self._ends(name):
            nics.append(Nic(node=name, eth=o.eth, index=o.index, role="bundle-member" if l.kind == "bundle" else l.kind,
                            attachment=l.attachment, peer=far, link=l.id, ifname=f"ethernet1/{o.index}",
                            mtu=l.mtu, vlans=l.vlans if l.mode == "trunk" else (), vlan=l.vlans[0] if l.mode == "access" else None))
        for sect in ("interfaces", "zones", "routes", "services", "rules", "nat", "addresses", "groups", "vpns", "crypto"):
            for x in f.get(sect) or []:
                _keys(x, f"fw.{sect}", f"firewall.{sect}[{x.get('name')}]")
        # address objects and groups first: a rule may name them (addr:<name>, group:<name>)
        addrs, groups = [], []
        self.fw_objects = {"addr": {}, "group": {}}
        for x in f.get("addresses") or []:
            an = str(_need(x, "name", "firewall.addresses"))
            if x.get("ref"):
                pre = self._ref(str(x["ref"]), f"firewall.addresses[{an}]", None)
                if len(pre) != 1:
                    raise SpecError(f"firewall.addresses[{an}]: {x['ref']!r} is not one prefix")
                pfx = pre[0]
            else:
                pfx = str(addr.net(str(_need(x, "prefix", f"firewall.addresses[{an}]"))))
            addrs.append(FwAddress(name=an, prefix=pfx, ref=x.get("ref"), desc=x.get("desc")))
            self.fw_objects["addr"][an] = (pfx,)
        for x in f.get("groups") or []:
            gn = str(_need(x, "name", "firewall.groups"))
            mem = _tuple_str(x.get("members"))
            for mname in mem:
                if mname not in self.fw_objects["addr"]:
                    raise SpecError(f"firewall.groups[{gn}]: member {mname!r} is not an address object")
            cidrs_g = tuple(self.fw_objects["addr"][mname][0] for mname in mem)
            if not mem:
                raise SpecError(f"firewall.groups[{gn}]: a static group needs at least one member")
            groups.append(FwGroup(name=gn, members=mem, cidrs=cidrs_g, desc=x.get("desc")))
            self.fw_objects["group"][gn] = cidrs_g
        raw_ifs = list(f.get("interfaces") or [])
        by_name = {i["name"]: i for i in raw_ifs}
        ifs = []

        def phys_eth(ifn: str) -> str | None:
            m = _PANOS_ETH.match(ifn)
            return f"eth{m.group(1)}" if m else None

        vlan_of_tag = {}
        for i in raw_ifs:
            n = i["name"]
            kind = i.get("kind") or ("subinterface" if "." in n else "layer3")
            members = tuple(i.get("members") or ())
            parent = i.get("parent")
            if kind == "aggregate":
                connected = any(phys_eth(m) in own for m in members)
            elif kind == "tunnel":
                # a tunnel interface is in the lab while the interface its VPN rides on is
                vpn_if = next((str(v.get("interface")) for v in f.get("vpns") or [] if v.get("tunnel_interface") == n), None)
                connected = bool(vpn_if) and phys_eth(vpn_if) in own
            elif kind == "subinterface":
                pi = by_name.get(parent) or {}
                legs = list(pi.get("members") or []) or [parent or ""]
                connected = any(phys_eth(m) in own for m in legs)
            else:
                connected = phys_eth(n) in own
            vlan = int(i["tag"]) if i.get("tag") is not None else None
            if vlan is not None:
                vlan_of_tag[n] = vlan
            ifs.append(FwInterface(name=n, kind=kind, eth=phys_eth(n), parent=parent, members=members,
                                   tag=int(i["tag"]) if i.get("tag") is not None else None, address=i.get("address"),
                                   zone=i.get("zone"), mtu=i.get("mtu"), lacp=i.get("lacp"), vlan=vlan, connected=connected,
                                   since=i.get("since"), mss_adjust=int(i["mss_adjust"]) if i.get("mss_adjust") is not None else None))
            for m in members:
                ifs.append(FwInterface(name=m, kind="aggregate-member", eth=phys_eth(m), parent=n, members=(), tag=None,
                                       address=None, zone=None, mtu=None, lacp=None, vlan=None, connected=phys_eth(m) in own))
        pub_if = f.get("public")
        public = None
        if pub_if:
            pi = by_name.get(pub_if)
            if not pi or not pi.get("address"):
                raise SpecError(f"firewall: public: {pub_if!r} is not an addressed interface")
            public = addr.ip(pi["address"]).compressed
        zones = []
        for z in f.get("zones") or []:
            zn = z["name"]
            zones.append(Zone(name=zn, interfaces=tuple(i.name for i in ifs if i.zone == zn), decision=z.get("decision"), since=z.get("since"),
                              zone_protection=z.get("zone_protection")))
        routes = []
        for x in f.get("routes") or []:
            w = f"firewall.routes[{x.get('name')}]"
            dref = str(_need(x, "dest", w))
            dest = dref if not dref.startswith("seg:") else self._ref(dref, w, public)[0]
            if x.get("discard"):
                routes.append(FwRoute(name=x["name"], dest=dest, nexthop=None, interface=None, metric=x.get("metric"), since=x.get("since"),
                                      kind="discard", dest_ref=dref if dref != dest else None))
            elif x.get("nexthop") is None:
                routes.append(FwRoute(name=x["name"], dest=dest, nexthop=None, interface=str(_need(x, "interface", w)), metric=x.get("metric"),
                                      since=x.get("since"), kind="interface", dest_ref=dref if dref != dest else None))
            else:
                routes.append(FwRoute(name=x["name"], dest=dest, nexthop=str(x["nexthop"]), interface=str(_need(x, "interface", w)),
                                      metric=x.get("metric"), since=x.get("since"), dest_ref=dref if dref != dest else None))
        routes = tuple(routes)
        pr = f.get("profiles") or {}
        profiles = None
        if pr:
            zp = pr.get("zone_protection") or {}
            profiles = FwProfiles(group=pr.get("group"), virus=pr.get("virus"), spyware=pr.get("spyware"),
                                  vulnerability=pr.get("vulnerability"), file_blocking=pr.get("file_blocking"),
                                  zone_protection=zp.get("name"), zp_flood=dict(zp.get("flood") or {}), zp_discard=_tuple_str(zp.get("discard")))
        app_default = {str(k): _tuple_str(v) for k, v in ((self.t.get("panos") or {}).get("app_default") or {}).items()}
        services = tuple(FwService(name=s["name"], protocol=str(s["protocol"]), port=str(s["port"])) for s in f.get("services") or [])
        def parts_of(refs, w):
            out_p = []
            for r_ in refs:
                kind_, _, val_ = str(r_).partition(":")
                cs = tuple(self._ref(r_, w, public))
                mem = (val_,) if kind_ in ("addr", "group") and val_ else tuple(_bare_cidr(c) for c in cs)
                out_p.append((str(r_), cs, mem))
            return tuple(out_p)

        def members_of(refs, w):
            return tuple(m_ for _r, _c, ms in parts_of(refs, w) for m_ in ms)

        # a rule with drill: exists only in a lab whose chapter.yaml drills plan runs that drill
        lab_drills = {str(d.get("id")) for d in ((getattr(self.meta.chapter, "drills", None) or {}).get("list") or [])
                      if isinstance(d, dict)} if self.meta.chapter else set()
        rules = []
        for x in f.get("rules") or []:
            w = f"firewall.rules[{x.get('name')}]"
            if x.get("drill") is not None and str(x["drill"]) not in lab_drills:
                continue
            src, dst = _tuple_str(x.get("src") or ["any"]), _tuple_str(x.get("dst") or ["any"])
            apps = _tuple_str(x.get("application") or ["any"])
            for a_ in apps:
                if a_ != "any" and app_default and a_ not in app_default:
                    raise SpecError(f"{w}: application {a_!r} is not in panos.app_default (the App-IDs the lab names)")
            svcs = _tuple_str(x.get("service") or (["application-default"] if apps != ("any",) else ["any"]))
            action = str(x.get("action", "allow"))
            pg = None
            if action == "allow" and profiles is not None and profiles.group and x.get("profile", True) is not False:
                pg = profiles.group
            rules.append(FwRule(name=x["name"], from_zones=_tuple_str(x.get("from")), to_zones=_tuple_str(x.get("to")), src=src, dst=dst,
                                src_cidrs=tuple(c for s in src for c in self._ref(s, w, public)),
                                dst_cidrs=tuple(c for s in dst for c in self._ref(s, w, public)),
                                services=svcs, applications=apps,
                                action=action, log_end=bool(x.get("log_end", True)),
                                decision=x.get("decision"), since=x.get("since"), desc=x.get("desc"),
                                src_members=members_of(src, w), dst_members=members_of(dst, w), profile_group=pg,
                                src_parts=parts_of(src, w), dst_parts=parts_of(dst, w)))
        nat = []
        for x in f.get("nat") or []:
            w = f"firewall.nat[{x.get('name')}]"
            src, dst = _tuple_str(x.get("src") or ["any"]), _tuple_str(x.get("dst") or ["any"])
            dnat = dnat_ref = None
            if x.get("dnat"):
                dnat_ref = str(x["dnat"])
                dnat = addr.ip(self._ref(dnat_ref, w, public)[0]).compressed
            sn = x.get("snat") or {}
            nat.append(FwNat(name=x["name"], from_zones=_tuple_str(x.get("from")), to_zones=_tuple_str(x.get("to")), src=src, dst=dst,
                             src_cidrs=tuple(c for s in src for c in self._ref(s, w, public)),
                             dst_cidrs=tuple(c for s in dst for c in self._ref(s, w, public)),
                             service=str(x.get("service", "any")), dnat=dnat, dnat_ref=dnat_ref, dnat_port=x.get("dnat_port"),
                             snat_type=sn.get("type"), snat_interface=sn.get("interface"), decision=x.get("decision"), since=x.get("since")))
        sysd = f.get("system") or {}
        system = FwSystem(dns=tuple(addr.ip(self._ref(s, "firewall.system", public)[0]).compressed for s in sysd.get("dns") or []),
                          ntp=tuple(addr.ip(self._ref(s, "firewall.system", public)[0]).compressed for s in sysd.get("ntp") or []),
                          service_route=sysd.get("service_route"))
        admin = None
        ad = f.get("admin")
        if ad:
            _keys(ad, "fw.admin", "firewall.admin")
            permitted = _tuple_str(ad.get("permitted") or [])
            admin = FwAdmin(interface=str(_need(ad, "interface", "firewall.admin")), profile=str(_need(ad, "profile", "firewall.admin")),
                            allow=_tuple_str(ad.get("allow") or ["ping"]), permitted=permitted,
                            permitted_cidrs=tuple(c for s in permitted for c in self._ref(s, "firewall.admin", public)),
                            since=ad.get("since"))
        crypto = []
        for x in f.get("crypto") or []:
            crypto.append(FwCrypto(name=str(x["name"]), kind=str(_need(x, "kind", "firewall.crypto")), encryption=_tuple_str(x.get("encryption")),
                                   hash=_tuple_str(x.get("hash")), dh=str(x.get("dh", "group14")), lifetime_h=int(x.get("lifetime_h", 8))))
        cnames = {c.name for c in crypto}
        vpns = []
        for x in f.get("vpns") or []:
            w = f"firewall.vpns[{x.get('name')}]"
            ifn = str(_need(x, "interface", w))
            ii = by_name.get(ifn) or {}
            if not ii.get("address"):
                raise SpecError(f"{w}: interface {ifn!r} is not an addressed firewall interface")
            pref = str(_need(x, "peer", w))
            peer = addr.ip(self._ref(pref, w, public)[0]).compressed
            pnode = pref.partition(":")[2] if pref.startswith("node:") else None
            tif = str(_need(x, "tunnel_interface", w))
            ti = by_name.get(tif)
            if ti is None or (ti.get("kind") != "tunnel"):
                raise SpecError(f"{w}: tunnel_interface {tif!r} is not a firewall interface of kind tunnel")
            for c in (x.get("ike_crypto"), x.get("ipsec_crypto")):
                if c not in cnames:
                    raise SpecError(f"{w}: crypto profile {c!r} is not in firewall.crypto")
            pids = []
            for pi in x.get("proxy_ids") or []:
                pids.append((str(pi["name"]), self._ref(str(pi["local"]), w, public)[0], self._ref(str(pi["remote"]), w, public)[0]))
            vpns.append(FwVpn(name=str(x["name"]), interface=ifn, local=str(ii["address"]), peer=peer, peer_node=pnode, tunnel_interface=tif,
                              ike_crypto=str(x["ike_crypto"]), ipsec_crypto=str(x["ipsec_crypto"]), psk=str(_need(x, "psk", w)),
                              proxy_ids=tuple(pids), zone=str(ti.get("zone")), since=x.get("since")))
        return Firewall(**self.base(name, tuple(sorted(nics, key=lambda n: n.index))), hostname=str(f.get("hostname", name)),
                        vr=str(f.get("vr", "core")), public=public, public_iface=pub_if, interfaces=tuple(ifs), zones=tuple(zones),
                        routes=routes, services=services, rules=tuple(rules), nat=tuple(nat), system=system, admin=admin,
                        addresses=tuple(addrs), groups=tuple(groups), profiles=profiles,
                        default_rules={str(k): dict(v) for k, v in (f.get("default_rules") or {}).items()},
                        crypto=tuple(crypto), vpns=tuple(vpns), app_default=app_default)

    # -- storage -------------------------------------------------------------------------
    def _storage(self, name: str) -> Storage:
        r = self.raw[name]
        st = dict(r.get("storage") or {})
        nics = []
        for o, far, l in self._ends(name):
            nics.append(Nic(node=name, eth=o.eth, index=o.index, role="bond-member" if l.kind == "bundle" else l.kind,
                            attachment=l.attachment, peer=far, link=l.id, mtu=l.mtu,
                            vlan=l.vlans[0] if l.vlans else None))
        data = mgmt_if = None
        d = st.get("data") or {}
        if d:
            seg = self.segments[d["segment"]]
            data = StorageIf(address=seg.cidr(int(d["octet"])), nics=tuple(ports.eth(x) for x in d.get("nics") or []),
                             vlan=int(seg.vlan) if seg.vlan else 0, mtu=d.get("mtu") or seg.mtu, lacp=d.get("lacp"))
        m = st.get("mgmt_if") or {}
        if m:
            seg = self.segments[m["segment"]]
            mnics = tuple(ports.eth(x) for x in m.get("nics") or []) or (ports.eth(m["nic"]),)
            mgmt_if = StorageIf(address=seg.cidr(int(m["octet"])), nics=mnics, vlan=int(seg.vlan) if seg.vlan else 0,
                                mtu=m.get("mtu") or seg.mtu, lacp=m.get("lacp"))
        routes = []
        for x in st.get("routes") or []:
            dest = str(x["dest"])
            if dest == "mgmt":
                dest = self.mgmtnet.subnet
            routes.append(Route(dest=dest, via=x.get("via"), id=x.get("id"), first=bool(x.get("first", False))))

        def res(lst):
            out = []
            for s in lst or []:
                p = self.primary.get(s)
                if not p:
                    raise SpecError(f"appliances.{name}: {s!r} has no address")
                out.append(addr.ip(p).compressed)
            return tuple(out)

        settings = {k: v for k, v in st.items() if k not in ("product", "data", "mgmt_if", "gateway", "routes", "dns", "ntp", "decision")}
        b = self.base(name, tuple(sorted(nics, key=lambda n: n.index)))
        if st.get("decision") and not b.get("decision"):
            b["decision"] = st.get("decision")
        return Storage(**b, product=str(st.get("product", r["kind"])), data=data, mgmt_if=mgmt_if,
                       gateway=self._gw_of(st.get("gateway")), routes=tuple(routes), dns=res(st.get("dns")), ntp=res(st.get("ntp")),
                       settings=settings)

    # -- services ------------------------------------------------------------------------
    def _node_segment(self) -> str:
        """The nodes' segment (VLAN 100): k8s.node_segment, else nodes."""
        return str((self.t.get("k8s") or {}).get("node_segment") or "nodes")

    def _gateways(self) -> dict:
        out = {}
        data = self.segments.get(self._node_segment())
        users = tuple(self.org.fqdn(x) for x in (self.t.get("dns") or {}).get("users") or [])
        admin = tuple(self.org.fqdn(x) for x in (self.t.get("dns") or {}).get("admin") or [])
        auds = {a["id"]: a for a in self.t.get("audiences") or []}
        for g in self.t.get("gateways") or []:
            gid = g["id"]
            _keys(g, "gateways", f"gateways.{gid}")
            seg = self.segments.get(g.get("segment") or self._node_segment()) or data
            if seg is None:
                raise SpecError(f"gateways.{gid}: no segment")
            vip = seg.host(int(g["vip"]))
            lo, hi = (int(x) for x in g["pool"])
            start, end = seg.host(lo), seg.host(hi)
            cidrs = tuple(str(n) for n in ipaddress.summarize_address_range(ipaddress.ip_address(start), ipaddress.ip_address(end)))
            a = auds.get(g.get("audience"))
            hosts = users + (admin if a and a.get("admin") else ())
            out[gid] = Gateway(name=gid, audience=str(g.get("audience")), vip=vip, vip_cidr=addr.host32(vip), pool_start=start,
                               pool_end=end, pool_cidrs=cidrs, segment=seg.id, hostnames=hosts, decision=g.get("decision"),
                               since=g.get("since"))
        return out

    def _models(self) -> dict:
        out = {}
        aud = self.t.get("audiences") or []
        for m in self.t.get("models") or []:
            mid = m["id"]
            _keys(m, "models", f"models.{mid}")
            copies = []
            for c in m.get("copies") or []:
                _keys(c, "copies", f"models.{mid}.copies.{c.get('id')}")
                r = int(c["rail"])
                # one StatefulSet a row, its one pod <controller>-0 (build A revision 2)
                ctl = f"{mid}-{c['id']}-server"
                pods = [PlacementRow(model=mid, copy=str(c["id"]), role="server", index=0, pod=f"{ctl}-0",
                                     node=str(c["server"]), rail=r, nad=f"rail{r}", decision=c.get("decision"), controller=ctl)]
                for k, w in enumerate(c.get("workers") or []):
                    ctl = f"{mid}-{c['id']}-worker{k}"
                    pods.append(PlacementRow(model=mid, copy=str(c["id"]), role="worker", index=k, pod=f"{ctl}-0",
                                             node=str(w), rail=r, nad=f"rail{r}", decision=c.get("decision"), controller=ctl))
                copies.append(Copy(model=mid, name=str(c["id"]), rail=r, parity="odd" if r % 2 else "even", server=str(c["server"]),
                                   workers=_tuple_str(c.get("workers")), pods=tuple(pods), decision=c.get("decision"),
                                   spans=bool(c.get("spans", False))))
            auds = tuple(a["id"] for a in aud if a.get("models") == "all" or mid in (a.get("models") or []))
            out[mid] = ServedModel(name=mid, weights=m.get("weights"), route_id=self.org.route_id(mid), audiences=auds,
                                   copies=tuple(copies), since=m.get("since"))
        return out

    def _answer(self, ref: str | None, public: str | None) -> str | None:
        if not ref:
            return None
        if ref == "public":
            return public
        kind, _, val = str(ref).partition(":")
        if kind == "vip":
            g = self.gateways.get(val)
            if g is None:
                raise SpecError(f"answer {ref!r}: no Gateway {val!r} in this state")
            return g.vip
        if kind == "fw" and val:
            # one of the firewall's own addresses: the internet side's published address is the
            # firewall's own isp address (part III)
            fi = next((i for i in (getattr(self, "fw_raw", None) or {}).get("interfaces") or [] if str(i.get("name")) == val), None)
            if not fi or not fi.get("address"):
                raise SpecError(f"answer {ref!r}: the firewall has no interface {val!r} with an address")
            return addr.ip(str(fi["address"])).compressed
        raise SpecError(f"answer {ref!r}: use public, vip:<gateway> or fw:<interface>")

    def _public(self) -> str | None:
        pub_if = self.fw_raw.get("public")
        for i in self.fw_raw.get("interfaces") or []:
            if i["name"] == pub_if and i.get("address"):
                return addr.ip(i["address"]).compressed
        return None

    def _populations(self, nodes: dict) -> dict:
        out = {}
        public = self._public()
        for p in self.t.get("populations") or []:
            pid = p["id"]
            _keys(p, "populations", f"populations.{pid}")
            segs = _tuple_str(p.get("segments"))
            for s in segs:
                if s not in self.segments:
                    raise SpecError(f"populations.{pid}: unknown segment {s!r}")
            ress = self._resolver_list(p.get("resolver"))
            res = ress[0] if ress else None
            res_addr = None
            if res:
                pa = self.primary.get(res)
                res_addr = addr.ip(pa).compressed if pa else None
            out[pid] = Population(name=pid, segments=segs, prefixes=tuple(self.segments[s].prefix for s in segs),
                                  zones=_tuple_str(p.get("zones")), audience=str(p.get("audience")), clients=_tuple_str(p.get("clients")),
                                  resolver=res, resolver_address=res_addr, answer=str(p.get("answer")),
                                  answer_address=self._answer(p.get("answer"), public), translated=bool(p.get("translated", False)),
                                  decision=p.get("decision"), since=p.get("since"), resolvers=ress)
        return out

    def _audiences(self, populations: dict) -> dict:
        out = {}
        all_ids = tuple(self.models)
        for a in self.t.get("audiences") or []:
            aid = a["id"]
            _keys(a, "audiences", f"audiences.{aid}")
            ms = all_ids if a.get("models") == "all" else _tuple_str(a.get("models"))
            out[aid] = Audience(name=aid, gateway=str(a.get("gateway")), models=ms, admin=bool(a.get("admin", False)),
                                populations=tuple(p.name for p in populations.values() if p.audience == aid),
                                decision=a.get("decision"), since=a.get("since"))
        return out

    def _registry(self, nodes: dict) -> Registry | None:
        r = self.t.get("registry")
        if not r or r.get("node") not in nodes:
            return None
        n = nodes[r["node"]]
        a = n.primary if isinstance(n, Host) else None
        if not a:
            return None
        port = int(r.get("port", 5000))
        nm = str(r.get("name", r["node"]))
        scheme = str(r.get("scheme") or "http")
        if scheme not in ("http", "https"):
            raise SpecError(f"registry.scheme: {scheme!r} is not http or https")
        return Registry(node=n.name, address=a, port=port, name=nm, fqdn=self.org.fqdn(nm), mirror=f"{a}:{port}", scheme=scheme)

    def _match_ref(self, ref: str, where: str) -> list:
        """A view's or resolver's client reference: a segment id (its prefix) or node:<host> (its
        primary address, /32)."""
        kind, _, val = str(ref).partition(":")
        if kind == "node" and val:
            if val not in self.raw:
                raise SpecError(f"{where}: {ref!r}: no node {val!r} in this state")
            p = self.primary.get(val)
            if not p:
                raise SpecError(f"{where}: {ref!r}: node {val!r} has no primary address")
            return [addr.host32(p)]
        if ref in self.segments:
            return [self.segments[ref].prefix]
        raise SpecError(f"{where}: unknown segment or node reference {ref!r}")

    def _dns(self, nodes: dict) -> Dns | None:
        d = self.t.get("dns")
        if not d:
            return None
        public = self._public()
        views = []
        for v in d.get("views") or []:
            where = f"dns.views.{v.get('id')}"
            _keys(v, "dns.views", where)
            match = _tuple_str(v.get("match"))
            cidrs: list = []
            for m in match:
                for c in self._match_ref(m, where):
                    if c not in cidrs:
                        cidrs.append(c)
            servers = self._resolver_list(v.get("server"))
            if not servers:
                raise SpecError(f"{where}: server: is required")
            for x in servers:
                if x not in self.raw:
                    raise SpecError(f"{where}: server {x!r} is not a node in this state")
            names = _tuple_str(v["names"]) if "names" in v else ("users", "admin", "internal")
            bad = [n for n in names if n not in ("users", "admin", "internal", "identity")]
            if bad:
                raise SpecError(f"{where}: names: {bad} (each is users, admin, internal or identity)")
            views.append(DnsView(name=v["id"], server=servers[0], servers=servers, kind=str(v.get("kind", "bind-views")), match=match,
                                 match_cidrs=tuple(cidrs), answer=str(v.get("answer")),
                                 answer_address=self._answer(v.get("answer"), public), recursion=bool(v.get("recursion", False)),
                                 infra=bool(v.get("infra", False)), names=names, decision=v.get("decision"), since=v.get("since")))
        resolvers = []
        local_names: set = set()
        for r in d.get("resolvers") or []:
            where = f"dns.resolvers.{r.get('id')}"
            _keys(r, "dns.resolvers", where)
            servers = _tuple_str(r.get("servers"))
            if not servers:
                raise SpecError(f"{where}: servers: is required")
            for x in servers + _tuple_str(r.get("to")) + _tuple_str(r.get("local")):
                if x not in self.raw:
                    raise SpecError(f"{where}: {x!r} is not a node in this state")
            clients = _tuple_str(r.get("clients"))
            ccidrs: list = []
            for c in clients:
                for x in self._match_ref(c, where):
                    if x not in ccidrs:
                        ccidrs.append(x)
            to = _tuple_str(r.get("to"))
            local = _tuple_str(r.get("local"))
            local_names |= set(local)
            resolvers.append(DnsResolver(name=str(r["id"]), servers=servers, kind=str(r.get("kind", "bind-recursive")), clients=clients,
                                         client_cidrs=tuple(ccidrs), to=to,
                                         to_addresses=tuple(addr.ip(self.primary[x]).compressed for x in to if self.primary.get(x)),
                                         local=local, since=r.get("since")))
        records = []
        for n in nodes.values():
            if n.name in local_names:
                continue  # a corporate host: its name is the enterprise's, under the org domain
            if isinstance(n, Host) and n.primary and self._internal(n.primary):
                records.append(DnsRecord(name=self.org.fqdn(n.name), address=n.primary, kind="infra"))
            elif isinstance(n, Storage):
                if n.data:
                    records.append(DnsRecord(name=self.org.fqdn(n.name), address=addr.ip(n.data.address).compressed, kind="infra"))
                if n.mgmt_if:
                    records.append(DnsRecord(name=self.org.fqdn(f"{n.name}-mgmt"), address=addr.ip(n.mgmt_if.address).compressed, kind="infra"))
        k = self.t.get("k8s") or {}
        if k.get("api_vip") is not None and self._node_segment() in self.segments:
            records.append(DnsRecord(name=self.org.fqdn(str(k.get("api_name", "k8s"))),
                                     address=self.segments[self._node_segment()].host(int(k["api_vip"])), kind="api"))
        records.sort(key=lambda x: x.name)
        return Dns(zone=self.org.names, users=tuple(self.org.fqdn(x) for x in d.get("users") or []),
                   admin=tuple(self.org.fqdn(x) for x in d.get("admin") or []),
                   wildcard=self.org.fqdn("*") if d.get("wildcard") else None, views=tuple(views), records=tuple(records),
                   internal=tuple(self.org.fqdn(x) for x in d.get("internal") or []), resolvers=tuple(resolvers),
                   # the identity provider's names exist only where it runs: a lab with Kubernetes and serving on
                   identity=tuple(self.org.fqdn(x) for x in d.get("identity") or []
                                  if self.t.get("identity") and self.meta.features.get("k8s") and self.meta.features.get("serving")))

    def _internal(self, a: str) -> bool:
        sid = self._seg_id(a)
        return bool(sid) and self.segments[sid].scope == "internal"

    def _ca(self) -> Ca | None:
        c = self.t.get("ca")
        if not c:
            return None
        inter = []
        for i in c.get("intermediates") or []:
            pr = i.get("proof") or {}
            inter.append(CaIntermediate(name=i["id"], cn=str(i["cn"]), key=str(i.get("key", "ec-p256")), dns=_tuple_str(i.get("dns")),
                                        ip=_tuple_str(i.get("ip")), proof_inside=_tuple_str(pr.get("inside")),
                                        proof_outside=_tuple_str(pr.get("outside"))))
        names = {i.name for i in inter}
        leaves = []
        for lf in c.get("leaves") or []:
            where = f"ca.leaves.{lf.get('id')}"
            _keys(lf, "ca.leaves", where)
            if lf.get("ca") not in names:
                raise SpecError(f"{where}: ca {lf.get('ca')!r} is not one of the intermediates {sorted(names)}")
            node = str(_need(lf, "node", where))
            if node not in self.raw:
                raise SpecError(f"{where}: node {node!r} is not a node in this state")
            ips = []
            for a in _tuple_str(lf.get("ip")):
                kind, _, val = a.partition(":")
                if kind == "node" and val:
                    p = self.primary.get(val)
                    if not p:
                        raise SpecError(f"{where}: {a!r}: node {val!r} has no primary address")
                    ips.append(addr.ip(p).compressed)
                else:
                    ips.append(addr.ip(a).compressed)
            leaves.append(CaLeaf(name=str(lf["id"]), ca=str(lf["ca"]), node=node, dns=_tuple_str(lf.get("dns")), ip=tuple(ips)))
        pr = c.get("proof") or {}
        return Ca(root_cn=str((c.get("root") or {}).get("cn")), intermediates=tuple(inter), proof_inside=_tuple_str(pr.get("inside")),
                  proof_outside=_tuple_str(pr.get("outside")), leaves=tuple(leaves))

    def _k8s(self, nodes: dict, reg: Registry | None) -> K8s | None:
        k = self.t.get("k8s")
        if not k or not self.meta.features.get("k8s"):
            return None
        data = self.segments[self._node_segment()]
        hosts = [n for n in nodes.values() if isinstance(n, Host) and n.k8s]
        init = next((n.name for n in hosts if n.k8s == "init"), None)
        control = tuple(n.name for n in hosts if n.k8s in ("init", "join-control"))
        workers = tuple(n.name for n in hosts if n.k8s == "join-worker")
        labels = {}
        for role, v in (k.get("labels") or {}).items():
            labels[role] = self.org.label_key(str(v["name"]), v.get("prefix"))
        lo, hi = (int(x) for x in k.get("rail_pod_range") or [100, 199])
        nads = tuple(Nad(name=f"rail{r.r}", rail=r.r, master=f"rail{r.r}", prefix=r.prefix, range_start=addr.host(r.prefix, lo),
                         range_end=addr.host(r.prefix, hi)) for r in sorted(self.rails.values(), key=lambda x: x.r))
        versions = (self.meta.versions or {}).get("kubernetes") or {}
        return K8s(version=str(versions.get("version", "")), api_vip=data.host(int(k["api_vip"])),
                   api_fqdn=self.org.fqdn(str(k.get("api_name", "k8s"))), pod_cidr=self.segments[k.get("pod_segment", "pods")].prefix,
                   service_cidr=self.segments[k.get("service_segment", "services")].prefix, init=init, control=control, workers=workers,
                   gateway_class=str(k.get("gateway_class", "cilium")), labels=labels, l2_announce=dict(k.get("l2_announce") or {}),
                   nads=nads, registry=reg)


def build(tree: dict, meta: Meta, keep: set[str] | None = None) -> Model:
    """Build the model from a merged, when-filtered profile tree. keep=None keeps every node."""
    return _Builder(tree, meta).run(keep)
