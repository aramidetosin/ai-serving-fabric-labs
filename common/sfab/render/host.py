"""Linux hosts: bootstrap/<node>/node.env for VM guests and bootstrap/<node>/init.env for the
container hosts (FRAMEWORK.md section 2.2).

node.env (kind vm-node) is read twice. vm-init.sh, PID 1 of the sfab/vm-node container, reads it
to build the guest (memory, vCPUs, disk, one bridge and tap per NIC, the NIC MACs, the cloud-init
seed); netsetup.sh reads it inside the guest to build the network: the 802.3ad bond, management
in table 150, out-of-band in table 100, and either the in-node relay (build A: rail addresses in
one namespace per rail) or routed rails (an address on each rail NIC and table 300 + r).

init.env (kinds bastion, client, resolver, registry) is read by the image's init script. The
bastion's init runs as PID 1 and waits for its own links (FRAMEWORK.md section 5); clients,
resolvers and the registry run theirs as the topology's exec once the links are attached
(render/clab.py). FRR routers get theirs from render/frr.py.

Both files have one header comment line, then KEY=value lines sorted by key, so `sort` leaves
the file unchanged and node-sync can compare files by sha256. Values are shell words: bare when
they hold only safe characters, single-quoted otherwise. Lists are space-separated; a route is
dest,via,dev,src with empty fields left empty; a key with no value is left out. Nothing here is
a secret: the SSH key, passwords and tokens reach a node through state/, never these files.

A VM guest also gets NTP_SERVERS (the spec's ntp.servers, the two resolvers' chrony, those in the
lab) and, when it is a Kubernetes node in a lab with the in-lab registry,
bootstrap/<node>/containerd/<upstream>/hosts.toml for each of the spec's registry.upstreams
(containerd_hosts(); vm-init.sh installs them under /etc/containerd/certs.d/), and in a lab that
runs the serving recipe bootstrap/<node>/containerd/<mirror>/hosts.toml for the images built here,
which the mirror serves under its own name. Each file is
byte for byte what images/registry/seed.py hosts-toml prints for that upstream, so the mirror
path a node asks for is the one the seed copied the image to. A registry that serves HTTPS
(registry.scheme) is named with https:// and the lab root as its CA, at the path the guest mounts
the lab's shared directory (/shared/ca/root.crt). The Kubernetes join material is
render/k8s.py's (bootstrap/<node>/k8s/).
"""

from __future__ import annotations

import re
import uuid

from .. import addr, ports
from ..model import Host, Model

# Container hosts that get an init.env here (frr routers are render/frr.py's).
CONTAINER_KINDS = ("bastion", "client", "registry", "resolver", "vpngw")

# virtio NICs report no speed or duplex, and 802.3ad needs both; the guest and QEMU set this.
NIC_SPEED_MBPS = 10000

# Fourth MAC octet that marks a relay namespace's macvlan (guest NICs use 00 there).
RELAY_MAC_TAG = 0x01

# sfab-ca publishes the lab root CA here on the lab host (make ca, and the up stage before every
# deploy); the containers that trust it bind state/shared/ca read-only at /shared/ca, and the VM
# guests mount state/shared at /shared (render/clab.py).
CA_ROOT_PATH = "/shared/ca/root.crt"
# Where a node's leaf (render/ca.py) and the TSIG keys of the authoritative servers are bound.
TLS_DIR = "/sfab/tls"
TSIG_DIR = "/sfab/tsig"
# Where the bastion finds each operator's short-lived kubeconfig (state/operators, bound read-only).
OPERATOR_DIR = "/sfab/operators"
# Where a VPN router finds its tunnel's pre-shared key (state/secrets/ipsec, bound read-only).
IPSEC_DIR = "/sfab/ipsec"
# A host that listens (hosts.<n>.listen) runs this from its bootstrap directory (render/clab.py).
LISTEN_SCRIPT = "listen.py"


def trusts_lab_ca(model: Model) -> bool:
    """True when the hosts get CA_ROOT: the lab runs its CA on the lab host (render/ca.py ca_on)."""
    from .ca import ca_on  # noqa: PLC0415

    return ca_on(model)

_SAFE = re.compile(r"^[A-Za-z0-9_./:@%+,=-]+$")
_KEY = re.compile(r"^[A-Z][A-Z0-9_]*$")


class HostRenderError(ValueError):
    """The model holds something an env file cannot carry."""


# ------------------------------------------------------------------------------------------
# env file helpers


def quote(value) -> str:
    """One shell word for value: bare when safe, else single-quoted ('' for the empty string)."""
    if isinstance(value, bool):
        value = "1" if value else "0"
    s = str(value)
    if s and _SAFE.match(s):
        return s
    return "'" + s.replace("'", "'\\''") + "'"


def env_file(header: str, env: dict) -> str:
    """The file: the header comment, then KEY=value lines sorted by key, then a newline."""
    if "\n" in header or not header.startswith("# "):
        raise HostRenderError(f"env header must be one comment line, got {header!r}")
    lines = [header]
    for k in sorted(env):
        if not _KEY.match(k):
            raise HostRenderError(f"env key {k!r} is not an upper-case shell name")
        v = env[k]
        if v is None or v == "":
            continue
        if "\n" in str(v):
            raise HostRenderError(f"{k}: a value may not hold a newline")
        lines.append(f"{k}={quote(v)}")
    return "\n".join(lines) + "\n"


def header(model: Model, node: str, ctx) -> str:
    return (f"# {model.lab} {node}: rendered from {ctx.profile_file(model)} by render/host.py; "
            f"edit the spec and run make render")


def words(items) -> str:
    return " ".join(str(x) for x in items)


def route_word(r) -> str:
    """A Route as dest,via,dev,src (empty fields stay empty)."""
    parts = [r.dest, r.via or "", r.dev or "", r.src or ""]
    for p in parts:
        if "," in p or " " in p:
            raise HostRenderError(f"route field {p!r} holds a comma or a space")
    return ",".join(parts)


def iqn(model: Model, node: str) -> str:
    """iqn.2026-10.<org domain reversed>:<node>, for example iqn.2026-10.example.tarnwick:k8s-gpu1."""
    rev = ".".join(reversed(model.org.domain.split(".")))
    return f"iqn.2026-10.{rev}:{node}"


def vm_uuid(model: Model, node: str) -> str:
    """The guest's SMBIOS UUID: unique per lab and node (kubeadm wants a unique product_uuid)."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://{model.org.domain}/labs/{model.lab}/nodes/{node}"))


def relay_mac(prefix: str, octet: int, index: int) -> str:
    """The MAC of a relay namespace's macvlan: 02:5a:<mgmt octet>:01:00:<rail NIC index>.

    A macvlan may not share its lower NIC's MAC, and a fixed one keeps the rail switches' MAC
    tables the same across reboots.
    """
    base = addr.mac(prefix, octet, index).split(":")
    base[3] = f"{RELAY_MAC_TAG:02x}"
    return ":".join(base)


def _guest(model: Model) -> dict:
    return model.common.get("guest") or {}


def _timeouts(model: Model) -> dict:
    return model.common.get("timeouts") or {}


def _mgmt(model: Model, h: Host) -> dict:
    return {
        "MGMT_IF": "eth0",
        "MGMT_ADDR": f"{h.mgmt}/{model.mgmt.prefixlen}",
        "MGMT_GW": model.mgmt.gw,
        "MGMT_TABLE": int(h.tables.get("mgmt", 150)),
    }


def domain_of(model: Model, h: Host) -> str:
    """The domain a host lives in: the corporate domain for the enterprise's own hosts (a corporate
    resolver's local names), the platform's zone for every other."""
    if model.dns is not None and any(h.name in r.local for r in model.dns.resolvers):
        return model.org.domain
    return model.org.names


def _identity(model: Model, h: Host) -> dict:
    dom = domain_of(model, h)
    return {
        "LAB": model.lab,
        "NODE_NAME": h.name,
        "NODE_KIND": h.kind,
        "NODE_ROLE": h.role,
        "DOMAIN": dom,
        "FQDN": f"{h.name}.{dom}",
    }


def dns_env(model: Model, h: Host) -> dict:
    """Resolver settings (render/frr.py uses them too). SEARCH, the host's own domain (domain_of),
    goes to every host, with or without a lab resolver: Docker writes a container's resolv.conf from
    the lab host's own file, search line included, and the image's init script replaces that line
    with SEARCH. DNS_SERVERS (every resolver the host asks that is in this lab, in order) and
    RESOLV_OPTIONS only when one of them is; without them the init script keeps Docker's
    nameserver and options lines. A VM guest's resolv.conf is the guest's own, never Docker's, so
    netsetup.sh writes it only when DNS_SERVERS is set."""
    env = {"SEARCH": domain_of(model, h)}
    servers = []
    for n in h.resolvers or ((h.resolver,) if h.resolver else ()):
        x = model.nodes.get(n)
        a = getattr(x, "primary", None) if x is not None and not getattr(x, "pending", None) else None
        if a and a not in servers:
            servers.append(a)
    if servers:
        env["DNS_SERVERS"] = " ".join(servers)
        if h.resolv_options:
            env["RESOLV_OPTIONS"] = h.resolv_options
    return env


def _bond(h: Host, mtu_default: int) -> dict:
    b = h.bond
    if b is None:
        return {}
    env = {
        "BOND_NAME": b.name,
        "BOND_MEMBERS": words(_guest_name(h, m) for m in b.members),
        "BOND_MODE": b.mode,
        "BOND_LACP_RATE": b.lacp_rate,
        "BOND_MIIMON": b.miimon,
        "BOND_HASH": b.xmit_hash_policy,
        "BOND_MTU": b.mtu or mtu_default,
        "BOND_ADDR": b.address,
        "BOND_GW": b.gateway,
        "BOND_VLAN": b.vlan,
    }
    if b.mac:
        env["BOND_MAC"] = b.mac
    return env


def _oob(h: Host) -> dict:
    o = h.oob
    if o is None:
        return {}
    env = {
        "OOB_IF": _guest_name(h, o.eth),
        "OOB_ADDR": o.address,
        "OOB_GW": o.gateway,
        "OOB_TABLE": o.table,
        "OOB_VLAN": o.vlan,
    }
    if o.netns:
        # the BMC stand-in: the NIC lives in this namespace, out of the host OS
        env["OOB_NETNS"] = o.netns
        env["OOB_SERVICES"] = words(o.services)
    return env


def _vlan_ifs(h: Host) -> dict:
    """The bond's tagged units: BOND_VLANS lists them; VLAN<id>_ADDR, _MTU and, for a unit whose
    segment's traffic leaves by its own table, _TABLE, _GW and _PREFIX."""
    b = h.bond
    if b is None or not b.vlan_ifs:
        return {}
    env = {"BOND_VLANS": words(str(v.vlan) for v in b.vlan_ifs)}
    for v in b.vlan_ifs:
        k = f"VLAN{v.vlan}"
        env[f"{k}_ADDR"] = v.address
        env[f"{k}_MTU"] = v.mtu
        if v.table:
            env[f"{k}_TABLE"] = v.table
            env[f"{k}_PREFIX"] = v.prefix
            if v.gateway:
                env[f"{k}_GW"] = v.gateway
    return env


def _guest_name(h: Host, eth: str) -> str:
    """The NIC's name inside a VM guest (rail3), or its container name (eth1) elsewhere."""
    n = h.nic(eth)
    if n is not None and n.ifname and h.kind == "vm-node":
        return n.ifname
    return eth


# ------------------------------------------------------------------------------------------
# node.env (VM guests)


def node_env(model: Model, h: Host, ctx) -> str:
    guest = _guest(model)
    tmo = _timeouts(model)
    mtu = int(guest.get("data_mtu", 9000))
    env = _identity(model, h)
    env.update(_mgmt(model, h))
    if not h.mgmt_mac:
        raise HostRenderError(f"{h.name}: a VM guest needs a management MAC")
    env["MGMT_MAC"] = h.mgmt_mac
    env.update({
        "GUEST_USER": guest.get("user", "admin"),
        # The same names and values as the topology's env for this container (render/clab.py).
        "VM_MEMORY_MB": int(round(h.budget.mem_gib * 1024)),
        "VM_SMP": int(h.budget.vcpus),
        "VM_DISK_GIB": int(h.disk_gib),
        "VM_TX_OFF": bool(guest.get("tx_offload_off", True)),
        "VM_UUID": vm_uuid(model, h.name),
        "HOLD_S": int(tmo.get("guest_hold_s", 3600)),
        "HOLD_POLL_S": int(tmo.get("guest_hold_poll_s", 5)),
        "NIC_SPEED": NIC_SPEED_MBPS,
        "ISCSI_IQN": iqn(model, h.name),
    })

    # Every connected container port, by index: the MAC QEMU gives the guest NIC, the name the
    # guest gives it (by MAC, through .link files), its MTU and role.
    env["VM_NICS"] = words(n.eth for n in h.nics)
    for n in h.nics:
        if not n.mac:
            raise HostRenderError(f"{h.name}:{n.eth}: a VM guest NIC needs a MAC")
        k = f"NIC{n.index:02d}"
        env[f"{k}_MAC"] = n.mac
        env[f"{k}_NAME"] = n.ifname or n.eth
        env[f"{k}_ROLE"] = n.role
        if n.mtu:
            env[f"{k}_MTU"] = n.mtu
        if n.rail is not None:
            env[f"{k}_RAIL"] = n.rail

    env.update(_bond(h, mtu))
    env.update(_vlan_ifs(h))
    env.update(_oob(h))
    env.update(_rails(model, h, mtu))
    env.update(dns_env(model, h))
    env.update(_ntp(model))
    env.update(_k8s(model, h))
    env.update(_models_share(model, h))
    return env_file(header(model, h.name, ctx), env)


def _models_share(model: Model, h: Host) -> dict:
    """A GPU node that runs a model server (a lab with serving on): the models share vm-init.sh
    exports to the guest read-only (MODELS_TAG) and the guest path it is mounted at (MODELS_MOUNT)."""
    from .k8s import serving_settings, weights_nodes  # noqa: PLC0415

    if h.name not in weights_nodes(model):
        return {}
    w = serving_settings(model)["weights"]
    return {"MODELS_TAG": str(w["tag"]), "MODELS_MOUNT": str(w["guest"])}


def ntp_addresses(model: Model) -> list:
    """The addresses of the spec's ntp.servers (the resolvers' chrony) that are in the lab."""
    from .dns import ntp_addresses as _na  # noqa: PLC0415

    return _na(model)


def ntp_address(model: Model) -> str | None:
    a = ntp_addresses(model)
    return a[0] if a else None


def _ntp(model: Model) -> dict:
    a = ntp_addresses(model)
    return {"NTP_SERVERS": " ".join(a)} if a else {}


# ------------------------------------------------------------------------------------------
# containerd registry mirrors (Kubernetes guests)

# Where containerd sends a pull when the mirror fails: docker.io's API lives elsewhere. An offline
# lab cannot reach either, so a pull the mirror cannot serve fails rather than leaving the lab.
# The same table and file as images/registry/seed.py (hosts_toml), which the tests hold equal.
UPSTREAM_SERVER = {"docker.io": "https://registry-1.docker.io"}


def hosts_toml(upstream: str, mirror: str, scheme: str = "http", ca: str | None = None) -> str:
    """containerd's certs.d/<upstream>/hosts.toml: pulls of <upstream>/<repo> go to
    <scheme>://<mirror>/v2/<upstream>/<repo> (override_path = true makes that path the API root),
    verified against ca (the lab root) when the mirror serves HTTPS."""
    server = UPSTREAM_SERVER.get(upstream, f"https://{upstream}")
    return (f'server = "{server}"\n\n'
            f'[host."{scheme}://{mirror}/v2/{upstream}"]\n'
            f'  capabilities = ["pull", "resolve"]\n'
            f'  override_path = true\n' + (f'  ca = "{ca}"\n' if ca else ""))


def hosts_toml_local(mirror: str, scheme: str = "http", ca: str | None = None) -> str:
    """containerd's certs.d/<mirror>/hosts.toml for the images built here, which a pod names as
    <mirror>/<repo>:<tag>: the mirror itself is the server. The same file as
    images/registry/seed.py hosts-toml --local prints."""
    return (f'server = "{scheme}://{mirror}"\n\n'
            f'[host."{scheme}://{mirror}"]\n'
            f'  capabilities = ["pull", "resolve"]\n' + (f'  ca = "{ca}"\n' if ca else ""))


def serves_local_images(model: Model) -> bool:
    """A lab that runs the serving recipe pulls the images this repository builds from the mirror."""
    return bool(model.features.get("serving")) and bool((model.spec or {}).get("serving"))


def registry_upstreams(model: Model) -> list:
    return [str(u) for u in ((model.spec.get("registry") or {}).get("upstreams") or [])]


def containerd_hosts(model: Model, h: Host) -> dict:
    """bootstrap/<node>/containerd/<upstream>/hosts.toml for a Kubernetes guest, one per upstream."""
    if h.kind != "vm-node" or not h.k8s or model.k8s is None or model.registry is None:
        return {}
    scheme = model.registry.scheme
    ca = CA_ROOT_PATH if scheme == "https" else None
    out = {}
    for up in registry_upstreams(model):
        if "/" in up or up.startswith("."):
            raise HostRenderError(f"registry.upstreams: {up!r} is not a registry host name")
        out[f"bootstrap/{h.name}/containerd/{up}/hosts.toml"] = hosts_toml(up, model.registry.mirror, scheme, ca)
    if serves_local_images(model):
        out[f"bootstrap/{h.name}/containerd/{model.registry.mirror}/hosts.toml"] = hosts_toml_local(model.registry.mirror, scheme, ca)
    return out


def _rails(model: Model, h: Host, mtu: int) -> dict:
    if not h.rails:
        return {}
    env = {
        "RAILS": words(r.rail for r in h.rails),
        "RAIL_MODE": "relay" if h.relay is not None else "routed",
        "RAIL_MTU": max((n.mtu or mtu) for n in h.nics if n.role == "rail"),
    }
    for r in h.rails:
        env[f"RAIL{r.rail}_IF"] = r.ifname
        env[f"RAIL{r.rail}_ADDR"] = r.address
        env[f"RAIL{r.rail}_VLAN"] = r.vlan
        if h.relay is None:
            # Routed rails (build B): the address sits on the NIC, and traffic sourced from it
            # leaves on that rail through its own table.
            env[f"RAIL{r.rail}_TABLE"] = int(h.tables.get("rail_base", 300)) + r.rail
            v = model.vlans.get(r.vlan)
            if v is not None and v.gw:
                env[f"RAIL{r.rail}_GW"] = v.gw
    if h.relay is not None:
        env.update(_relay(model, h))
    return env


def _relay(model: Model, h: Host) -> dict:
    rl = h.relay
    prefix = str(_guest(model).get("mac_prefix", "02:5a"))
    env = {
        "RELAY_BRIDGE": rl.bridge,
        "RELAY_PREFIX": rl.prefix,
        "RELAY_MTU": rl.mtu,
        "RELAY_RP_FILTER": rl.rp_filter,
        "RELAY_IP_FORWARD": rl.ip_forward,
    }
    rails = {r.rail: r for r in h.rails}
    for ns in rl.namespaces:
        ri = rails.get(ns.rail)
        if ri is None:
            raise HostRenderError(f"{h.name}: relay namespace {ns.ns} has no rail {ns.rail} NIC")
        if ns.rail_master != ri.ifname or ns.rail_addr != ri.address:
            raise HostRenderError(f"{h.name}: relay namespace {ns.ns} does not match rail {ns.rail}")
        nic = h.nic(ri.eth)
        k = f"RELAY{ns.rail}"
        env[f"{k}_NS"] = ns.ns
        env[f"{k}_MACVLAN"] = ns.rail_if
        env[f"{k}_MACVLAN_MAC"] = relay_mac(prefix, h.mgmt_octet, nic.index)
        env[f"{k}_VETH"] = ns.veth
        env[f"{k}_PORT"] = ns.bridge_port
        env[f"{k}_ADDR"] = ns.relay_addr
        env[f"{k}_ROUTES"] = words(route_word(x) for x in ns.routes)
    return env


def _k8s(model: Model, h: Host) -> dict:
    k = model.k8s
    if k is None or not h.k8s:
        return {}
    env = {
        "K8S_ROLE": h.k8s,
        "K8S_VERSION": k.version,
        "K8S_API_VIP": k.api_vip,
        "K8S_API_FQDN": k.api_fqdn,
        "K8S_POD_CIDR": k.pod_cidr,
        "K8S_SERVICE_CIDR": k.service_cidr,
        "K8S_INIT_NODE": k.init,
        # kubeadm's control-plane endpoint must resolve before the resolvers answer.
        "HOSTS": f"{k.api_vip},{k.api_fqdn}",
    }
    if k.registry is not None:
        env["K8S_REGISTRY_MIRROR"] = k.registry.mirror
    return env


# ------------------------------------------------------------------------------------------
# init.env (container hosts)


def init_env(model: Model, h: Host, ctx) -> str:
    env = _identity(model, h)
    env.update(_mgmt(model, h))
    mtu = int(_guest(model).get("data_mtu", 9000))

    # Addressed ports outside a bond, wired in this lab.
    ifaces = [i for i in h.ifaces if i.peer is not None and i.address]
    env["IFACES"] = words(i.eth for i in ifaces)
    gw_dev = None
    for i in ifaces:
        k = i.eth.upper()
        env[f"{k}_ADDR"] = i.address
        if i.mtu:
            env[f"{k}_MTU"] = i.mtu
        if h.gateway and addr.contains(addr.prefix_of(i.address), h.gateway):
            gw_dev = gw_dev or i.eth
    env.update(_bond(h, mtu))
    env.update(_oob(h))
    if h.bond is not None:
        gw_dev = h.bond.name
    if h.gateway:
        if gw_dev is None:
            raise HostRenderError(f"{h.name}: gateway {h.gateway} is on no interface in this lab")
        env["GATEWAY"] = h.gateway
        env["GATEWAY_DEV"] = gw_dev
    if h.routes:
        env["ROUTES"] = words(route_word(r) for r in h.routes)
    if h.vlan is not None:
        env["VLAN"] = h.vlan

    # TX checksum offload off on every data NIC (TCP fails silently on a routed path otherwise).
    if _guest(model).get("tx_offload_off", True):
        env["TX_OFF"] = words(sorted({n.eth for n in h.nics}, key=ports.eth_index))
    if h.dns_role:
        env["DNS_ROLE"] = h.dns_role
    if h.kind == "bastion":
        # the operator user sshd lets in, the VM guests' user (bastion-init.sh), and where each
        # operator's short-lived kubeconfig appears (state/operators/<user>/kubeconfig)
        env["GUEST_USER"] = _guest(model).get("user", "admin")
        if model.k8s is not None:
            env["OPERATOR_DIR"] = OPERATOR_DIR
    env.update(dns_env(model, h))
    if trusts_lab_ca(model):
        env["CA_ROOT"] = CA_ROOT_PATH
    from .ca import leaf_of  # noqa: PLC0415
    from .dns import tsig_servers  # noqa: PLC0415

    if trusts_lab_ca(model) and leaf_of(model, h.name) is not None:
        env["TLS_DIR"] = TLS_DIR
    if h.name in tsig_servers(model):
        env["TSIG_DIR"] = TSIG_DIR
    if h.kind == "vpngw":
        v = vpn_of(model, h)
        env["IPSEC_DIR"] = IPSEC_DIR
        env["IPSEC_PSK"] = v.psk
        env["IPSEC_PEER_ID"] = model.firewall.public
    return env_file(header(model, h.name, ctx), env)


def vpn_of(model: Model, h: Host):
    """The firewall's tunnel a VPN router is the far end of (hosts.<n>.vpn.firewall_vpn)."""
    fw = model.firewall
    want = ((h.props or {}).get("vpn") or {}).get("firewall_vpn")
    v = next((x for x in (fw.vpns if fw else ()) if x.name == want), None)
    if v is None:
        raise HostRenderError(f"{h.name}: vpn.firewall_vpn {want!r} is not a tunnel of the firewall in this lab")
    if v.peer != h.primary:
        raise HostRenderError(f"{h.name}: the firewall's tunnel {v.name} peers with {v.peer}, not this router's {h.primary}")
    return v


def swanctl_conf(model: Model, h: Host, ctx) -> str:
    """strongSwan's swanctl.conf for a VPN router: one IKEv2 connection to the firewall's public
    address, one child per proxy ID of the firewall's tunnel with the selectors mirrored, the
    firewall's crypto profiles as proposals. The key is not here: sfab-init.sh adds it from the
    bound secrets directory."""
    fw = model.firewall
    v = vpn_of(model, h)
    cr = {c.name: c for c in fw.crypto}
    enc = {"aes-256-cbc": "aes256", "aes-128-cbc": "aes128", "aes-256-gcm": "aes256gcm16"}
    hsh = {"sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
    dh = {"group14": "modp2048", "group19": "ecp256", "group20": "ecp384"}

    def proposal(c):
        try:
            return f"{enc[c.encryption[0]]}-{hsh[c.hash[0]]}-{dh[c.dh]}"
        except KeyError as e:
            raise HostRenderError(f"crypto profile {c.name}: {e} has no strongSwan name in render/host.py") from None

    ike, esp = cr[v.ike_crypto], cr[v.ipsec_crypto]
    lines = [f"# {model.lab} {h.name}: rendered from {ctx.profile_file(model)} by render/host.py; edit the spec and run make render",
             f"# The far end of the firewall's tunnel {v.name}: IKEv2 to {fw.public}, its selectors the firewall's proxy IDs mirrored.",
             "# The pre-shared key is not in this file: sfab-init.sh adds it from IPSEC_DIR.",
             "connections {", f"  {v.name} {{", "    version = 2", f"    local_addrs = {h.primary}", f"    remote_addrs = {fw.public}",
             f"    proposals = {proposal(ike)}", f"    rekey_time = {ike.lifetime_h}h", "    keyingtries = 0", "    dpd_delay = 10s",
             "    local {", "      auth = psk", f"      id = {h.primary}", "    }",
             "    remote {", "      auth = psk", f"      id = {fw.public}", "    }",
             "    children {"]
    for name, local, remote in v.proxy_ids:
        lines += [f"      {name} {{", f"        local_ts = {remote}", f"        remote_ts = {local}", f"        esp_proposals = {proposal(esp)}",
                  f"        rekey_time = {esp.lifetime_h}h", "        start_action = start", "        dpd_action = restart", "        close_action = start",
                  "      }"]
    lines += ["    }", "  }", "}"]
    return "\n".join(lines) + "\n"


LISTEN_PY = """#!/usr/bin/env python3
# A plain TCP listener on {ports}: it accepts and closes, so a connect from anywhere the path allows
# opens (rendered by render/host.py from hosts.<n>.listen; nothing is served).
import socket, threading

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        c, _ = s.accept()
        c.close()

for p in {plist}:
    threading.Thread(target=serve, args=(p,), daemon=False).start()
"""


def listen_py(h: Host) -> str:
    ports_ = [int(x) for x in (h.props or {}).get("listen") or []]
    return LISTEN_PY.format(ports=", ".join(str(p) for p in ports_), plist=repr(ports_))


# ------------------------------------------------------------------------------------------


def render(model: Model, ctx) -> dict:
    out = {}
    for h in model.hosts.values():
        if h.pending:
            ctx.warn(f"host: {h.name} is pending ({h.pending}); no env file rendered")
            continue
        if h.kind == "vm-node":
            out[f"bootstrap/{h.name}/node.env"] = node_env(model, h, ctx)
            out.update(containerd_hosts(model, h))
        elif h.kind in CONTAINER_KINDS:
            out[f"bootstrap/{h.name}/init.env"] = init_env(model, h, ctx)
            if h.kind == "vpngw":
                out[f"bootstrap/{h.name}/swanctl.conf"] = swanctl_conf(model, h, ctx)
        if (h.props or {}).get("listen"):
            out[f"bootstrap/{h.name}/{LISTEN_SCRIPT}"] = listen_py(h)
    return out
