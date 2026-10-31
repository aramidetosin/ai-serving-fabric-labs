#!/usr/bin/env python3
"""judge: the audit's verdicts, read from a result set's saved files only (FRAMEWORK.md 4.4).

    judge.py plan  --inv INV --node NODE [--quick]
    judge.py split --style klish|panos --plan PLAN --session FILE --out DIR
    judge.py run   --set DIR --inv INV --render DIR GROUP [NODE ...]
    judge.py body  --style klish|panos --command CMD < session
    judge.py offloads [--nics N] FILE

plan prints one node's collection plan, expanded from common/audit/cmds/ (see cmds/README.md),
as tab-separated lines: number, slug, surface, extension, command. split cuts one interactive
session (sonic-cli or the PAN-OS CLI) into the plan's files by the device's own prompt lines.
run judges one group of checks and prints the result vocabulary (vocab.py), appending each line
to $SFAB_VERDICT. body prints one command's output from a session on stdin; offloads lists
the data NICs whose GRO, rx-gro-hw or LRO is on (boot's gro_check). Groups:

    shared             every switch: launcher line, NUM_NICS, GRO off, IPv6 off on the container
                       veths, ip vrf mgmt, passthrough, parity
    vlans              every switch: VLAN membership as rendered
    mac-tables         every switch: the MAC table holds host MACs only
    forwarding-only    the named switches: no routing protocol, no address but an MCLAG member's two
                       keepalive /31s in the keepalive VRF, an empty default table
    l2-hygiene SW...   chapter 3: the spanning-tree mode, every used port's MTU, BPDU guard on each
                       edge port (and on no other), storm control on each member and access port
    mclag-pair A B     the pair: session, roles, keepalive addresses, PortChannels (--except-peers
                       leaves out the PortChannels facing the nodes it names)
    firewall           the PA-VM: commit marker, delivered file, enforced lines, ae1, units
    guests             every VM guest: bond, TX offload, management table, gateways
    rails              every GPU node: relay namespaces, same-rail jumbo, cross-rail through the relay
    cluster-nodes      every Kubernetes node: its bootstrap unit, kubelet, the registry mirrors and
                       the registry over HTTPS through the source NAT, NTP from both resolvers, DNS
                       through them, storage ports
    bastion            the jump host: bond and tables, sshd and nothing that serves, the lab CA it
                       trusts, no admin kubeconfig, the operator's short-lived certificate and role
    services           the platform's DNS and time servers: the authoritative pair (the secondary at
                       the primary's serial), the resolvers (answers, NXDOMAIN outside the zone, NTS
                       to the reference), the corporate resolver and the time reference
    routers            FRR routers: VRF mgmt, interfaces, forwarding, connected routes, peers,
                       resolv.conf searching the lab's domain only
    registry           the registry: address and tables, catalog, pulls through the source NAT,
                       resolv.conf searching the lab's domain only
    clients            clients: address, tables, TX offload, gateway, resolver, the lab root trusted
    storage            storage appliances: container health, the launcher's login (presence only)
    cluster            the cluster as the harness's kubectl printed it on the init node (M2 exit criterion 8)
    populations        each population's probe: its resolver's answers and its Gateway's replies
    pair-roles A B     chapter 3: the lower keepalive source address active, the other standby; the
                       ICCP session on TCP 8888 in the keepalive's VRF, and iccpd's keepalive state
    bond-legs [NODE..] chapter 3: every bond toward the pair leg by leg (hosts from their bonding
                       file, the firewall from its LACP table, a storage appliance from the switches)
    rail-backend [SW..] chapter 5: on each rail switch the absences the design is made of (no VLAN
                       interface address, no gateway, no router bgp, no inter-switch link, only
                       Management0 in the mgmt VRF), its rail ports up with no shutdown at their
                       MTU; on each GPU node collected, every GPU namespace's routes as rendered
                       (source-pinned), no default route, loose reverse-path filtering, and the MTU
                       ceilings (rail NICs, the relay's veths and bridge); from the plan's files and
                       the namespace link reads audit_rail_backend saved in rail-backend/
    fw-edge [FW]       chapter 4: zone bindings, rule order (no-nat-public above internet-snat),
                       the LAND counter at zero and unmoved by a node's requests to the public
                       address, administrative access from the jump host only, the service routes
                       to the lab's resolvers, and the uplink router's routes to the inside prefixes
                       with an operator request refused by deny-all-log (chapter 2's matrix);
                       from the plan's files and the active reads audit_fw_edge saved in fw-edge/
    placement          chapter 6: the serving pods read back against the placement table
                       (placement.py), from what audit_placement saved in placement/
    keys               chapter 7: each model route's refusals (no key, an unknown key, another
                       model's key, all 401 alike) and the per-pod key probe (gwlayer.py), from
                       what audit_gateway_layer saved in keys/
    gateway-layer      chapter 7: the GatewayClass, each Gateway's allowedRoutes and labelled
                       namespaces, the hostnames and paths each Gateway answers, the leases, the
                       VIPs (ARP and TCP, no ICMP), the chains through each VIP, the CA's proof and
                       the timeout chain as the cluster runs it (gwlayer.py), from gateway-layer/

A file the plan names but the set lacks is a FAIL (not collected), never a pass. Nothing here
connects to a device; collect.sh does that.
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
COMMON = HERE.parent
sys.path.insert(0, str(HERE))
import evfile  # noqa: E402
import panos_parse as PP  # noqa: E402
import vocab  # noqa: E402

CMDS = HERE / "cmds"
SURFACE_EXT = {
    "klish": ".txt", "vtysh": ".txt", "shell": ".txt", "shell-json": ".json",
    "cli": ".txt", "cli-set": ".txt", "xml": ".xml",
    "guest": ".txt", "guest-json": ".json",
    "host": ".txt", "host-json": ".json", "host-xml": ".xml",
    # M2: docker exec in the node's own container, vtysh in an FRR container, kubectl (and a shell)
    # on the init node, and "node": the node's own shell, over SSH on a VM guest, else docker exec
    "exec": ".txt", "exec-json": ".json", "frr": ".txt", "frr-json": ".json",
    "kubectl": ".txt", "kubectl-json": ".json", "node": ".txt", "node-json": ".json",
}
# Where a container and a VM guest find the lab root CA (state/shared/ca, bound or 9p-mounted).
CA_ROOT = "/shared/ca/root.crt"
PROMPT_KLISH = re.compile(r"^([A-Za-z0-9._-]+)(\([^)]*\))?# ?(.*)$")
PROMPT_PANOS = re.compile(r"^([A-Za-z0-9._-]+@[A-Za-z0-9._-]+)(\([^)]*\))?[>#] ?(.*)$")
FIELD = re.compile(r"\{([a-z_][a-z0-9_.]*)(\|ip)?\}")
# SONiC's own kernel addresses that a forwarding-only switch still holds (SONiC 4.6.0).
KERNEL_WHITELIST = {"lo", "eth0", "lo-m", "docker-mgmt", "redirect", "docker0", "mgmt"}
DATA_NETDEV = re.compile(r"^(Vlan|PortChannel|Ethernet)[0-9]")


def natural(s: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"([0-9]+)", s)]


def bare(a):
    return None if a is None else str(a).split("/")[0]


def load_inv(path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dig(d, path: str):
    cur = d
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


# --------------------------------------------------------------------------------------------
# plans


def read_list(path: Path):
    out = []
    if not path.is_file():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            raise SystemExit(f"judge: {path.name}: malformed line: {raw!r}")
        slug, surface, command = parts
        quick = slug.startswith("+")
        slug = slug.lstrip("+")
        if surface not in SURFACE_EXT:
            raise SystemExit(f"judge: {path.name}: unknown surface {surface!r}")
        out.append((quick, slug, surface, command))
    return out


def plan_files(node: dict, inv: dict | None = None, name: str | None = None) -> list:
    """<kind>.list, then <role>.list; then, with the cluster on, k8s-node.list for a Kubernetes node,
    k8s.list for the node the harness's kubectl runs on (stages.kubectl: the init node, its admin
    kubeconfig; never the bastion), and population.list for the node
    that probes a population (population_ctx). Without the cluster no Gateway answers, so no node
    probes a population (M1's GPU nodes sit inside the nodes population's prefixes)."""
    files = [CMDS / f"{node['kind']}.list"]
    role = CMDS / f"{node['role']}.list"
    if role not in files:
        files.append(role)
    if inv is not None and name is not None:
        st = inv.get("stages") or {}
        if st.get("cluster") and node.get("k8s"):
            files.append(CMDS / "k8s-node.list")
        if st.get("cluster") and st.get("kubectl") == name:
            files.append(CMDS / "k8s.list")
        if st.get("cluster") and population_ctx(inv, name):
            files.append(CMDS / "population.list")
    return [f for f in files if f.is_file()]


def fqdn(inv: dict, label) -> str | None:
    """A lab name: under the platform's zone (org.zone), else the org domain."""
    org = inv.get("org") or {}
    dom = org.get("zone") or org.get("domain")
    return f"{label}.{dom}" if label and dom else None


def view_of_address(inv: dict, address) -> tuple:
    """(name, view) of the authoritative view whose clients hold ADDRESS, or (None, {})."""
    try:
        a = ipaddress.ip_address(bare(address))
    except (TypeError, ValueError):
        return None, {}
    for name, v in ((inv.get("dns") or {}).get("views") or {}).items():
        if any(a in ipaddress.ip_network(c) for c in v.get("match_cidrs") or []):
            return name, v
    return None, {}


def client_view(inv: dict, name: str) -> tuple:
    """(name, view) of the view that answers a node's lookups: a client of one of the lab's
    resolvers (dns.resolvers: dns-res1 and dns-res2, the corporate one) is answered from the view that holds
    its resolver's address; a client of an authoritative server (the public ones) from the view that
    holds its own address."""
    nodes = inv.get("nodes") or {}
    n = nodes.get(name) or {}
    res = n.get("resolver")
    dns = inv.get("dns") or {}
    if res and any(res in (r.get("servers") or []) for r in (dns.get("resolvers") or {}).values()):
        return view_of_address(inv, (nodes.get(res) or {}).get("address"))
    return view_of_address(inv, n.get("address"))


def probers(inv: dict, pop: dict) -> list:
    """The nodes that probe a population: its clients in this lab or, for a population with no
    client node (the nodes population), the first Kubernetes node inside its prefixes."""
    nodes = inv.get("nodes") or {}
    have = [c for c in pop.get("clients") or [] if c in nodes]
    if have or pop.get("clients"):
        return have
    for n in inv.get("order") or []:
        d = nodes[n]
        if d.get("kind") == "vm-node" and d.get("k8s") and d.get("address"):
            a = ipaddress.ip_interface(d["address"]).ip
            if any(a in ipaddress.ip_network(p) for p in pop.get("prefixes") or []):
                return [n]
    return []


def population_ctx(inv: dict, name: str) -> dict:
    """The plan fields of the population NAME probes, or {} when it probes none. A population whose
    resolver is not in the lab (ops-dns before sfab/resolver) has no pop_resolver, so its resolver
    lines are left out, and its HTTPS lines pin the name to the answer address instead."""
    nodes = inv.get("nodes") or {}
    k8s = inv.get("k8s") or {}
    tb = k8s.get("test_backend") or {}
    dns = inv.get("dns") or {}
    for pname, pop in sorted((inv.get("populations") or {}).items()):
        # a population with no audience (an internet host that is not the operator) has no Gateway to
        # probe: chapter 2's matrix proves it reaches nothing
        if name not in probers(inv, pop) or not pop.get("answer_address") or not pop.get("gateway"):
            continue
        users = (dns.get("users") or [None])[0]
        admin = (dns.get("admin") or [None])[0]
        resolver_in = pop.get("resolver") in nodes and pop.get("resolver_address")
        view, vs = client_view(inv, name)
        # a view that holds no record for the admin name (the enterprise's, a public one) answers it
        # NXDOMAIN: the request for it is pinned to the users' answer, so the Gateway still judges it
        held = admin in (vs.get("names") or []) if vs else True
        # a view that publishes no platform name at all (the operator's public server in state one,
        # nothing is published on the uplink: the operator names the VIP directly) answers the users' name NXDOMAIN too
        users_held = users in (vs.get("names") or []) if vs else True
        pin = lambda f, ok: "" if (resolver_in and ok) or not f else f"--resolve {f}:443:{pop['answer_address']}"  # noqa: E731
        init = k8s.get("init") or next(iter(k8s.get("control") or []), None)
        return {
            "pop": pname, "pop_answer": pop["answer_address"],
            "pop_resolver": pop.get("resolver_address") if resolver_in else None,
            "pop_view": view, "pop_admin_held": held, "pop_users_held": users_held,
            "users_fqdn": users, "admin_fqdn": admin, "infra_fqdn": fqdn(inv, init) if init else None,
            "pop_pin_users": pin(users, users_held), "pop_pin_admin": pin(admin, held and users_held),
            "echo_path": tb.get("path"), "echo_msg": f"sfab-audit-{pname}", "ca_root": CA_ROOT,
        }
    return {}


def gpu_peer(inv: dict, name: str):
    gpus = [g for g in (inv.get("groups") or {}).get("gpu", []) if g in inv["nodes"]]
    if name not in gpus or len(gpus) < 2:
        return None
    return gpus[(gpus.index(name) + 1) % len(gpus)]


def rail_rows(inv: dict, name: str) -> list:
    node = inv["nodes"][name]
    rails = node.get("rails") or {}
    order = sorted(rails, key=int)
    relay = node.get("relay") or {}
    nss = list(relay.get("namespaces") or [])
    peer = gpu_peer(inv, name)
    prails = (inv["nodes"][peer].get("rails") or {}) if peer else {}
    rows = []
    for i, r in enumerate(order):
        nxt = order[(i + 1) % len(order)]
        rows.append({
            "r": r,
            "ns": nss[i] if i < len(nss) else None,
            "rail_if": rails[r].get("ifname"),
            "rail_addr": bare(rails[r].get("address")),
            "peer": peer,
            "peer_addr": bare((prails.get(r) or {}).get("address")),
            "next_r": nxt,
            "next_peer_addr": bare((prails.get(nxt) or {}).get("address")),
        })
    return rows


def p2p_rows(inv: dict, name: str) -> list:
    """A routed node's point-to-point peers in this lab: [{p2p: peer node, p2p_addr: its address
    on the shared link, p2p_iface: this node's NIC on it, and p2p_host_addr or p2p_appliance_addr:
    the address again, named by the peer's kind}], in port order (the firewall's address is its
    interface on that port). A host peer is pinged; an appliance peer (the firewall) is read by ARP,
    since its rulebase need not admit a ping from that side."""
    nodes = inv.get("nodes") or {}
    rows = []
    for eth, nic in sorted(((nodes[name].get("nics") or {}).items()), key=lambda kv: natural(kv[0])):
        if nic.get("role") != "p2p" or not nic.get("peer"):
            continue
        pn, pe = str(nic["peer"]).split(":", 1)
        peer = nodes.get(pn) or {}
        addr = None
        if peer.get("section") == "appliances":
            addr = next((i.get("address") for i in (peer.get("interfaces") or {}).values() if i.get("eth") == pe), None)
        else:
            addr = ((peer.get("ifaces") or {}).get(pe) or {}).get("address") or ((peer.get("nics") or {}).get(pe) or {}).get("address")
        if addr:
            kind = "p2p_appliance_addr" if peer.get("section") == "appliances" else "p2p_host_addr"
            rows.append({"p2p": pn, "p2p_addr": bare(addr), "p2p_iface": eth, kind: bare(addr)})
    return rows


def base_ctx(inv: dict, name: str) -> dict:
    node = inv["nodes"][name]
    nics = node.get("nics") or {}
    eths = sorted(nics, key=natural)
    k8s = inv.get("k8s") or {}
    reg = inv.get("registry") or {}
    st = inv.get("stages") or {}
    stor = next((s for s in st.get("storage") or [] if s in inv["nodes"]), None)
    sdata = ((inv["nodes"].get(stor) or {}).get("data") or {}) if stor else {}
    smgmt = ((inv["nodes"].get(stor) or {}).get("mgmt_if") or {}) if stor else {}
    certs = (inv.get("ca") or {}).get("certificates") or []
    dns = inv.get("dns") or {}
    nodes = inv.get("nodes") or {}
    views = [v for v, d in (dns.get("views") or {}).items() if name in (d.get("servers") or [d.get("server")])]
    res_addrs = [bare((nodes.get(r) or {}).get("address")) for r in node.get("resolvers") or [] if (nodes.get(r) or {}).get("address")]
    locals_ = [x for r in (dns.get("resolvers") or {}).values() if name in (r.get("servers") or []) for x in r.get("local") or []]
    org = inv.get("org") or {}
    ctx = {
        "data_eths": " ".join(eths),
        # the BMC stand-in's NIC lives in its own namespace, out of the host OS's reach
        "guest_data_ifs": " ".join((nics[e].get("ifname") or e) for e in eths
                                   if not ((node.get("oob") or {}).get("netns") and e == (node.get("oob") or {}).get("eth"))),
        "mgmt_gw": (inv.get("mgmt") or {}).get("gw"),
        "ca_root": CA_ROOT,
        "registry_url": f"{reg.get('scheme') or 'http'}://{reg['mirror']}" if reg.get("mirror") else None,
        "storage_addr": bare(sdata.get("address")),
        "storage_fqdn": fqdn(inv, stor) if stor and sdata.get("address") else None,
        "stor_mgmt_addr": bare(smgmt.get("address")),
        "users_fqdn": ((inv.get("dns") or {}).get("users") or [None])[0],
        "api_vip": k8s.get("api_vip"),
        "api_fqdn": k8s.get("api_fqdn"),
        # the listener certificate the cluster group decodes: the shared wildcard one, else the first Gateway's own
        "wildcard_secret": next((c.get("secret") for c in certs if c.get("id") == "wildcard"), None)
        or next((c.get("secret") for c in certs), None),
        "zone": dns.get("zone"),
        "dns_views": " ".join(views) or None,
        "resolver_addresses": " ".join(res_addrs) or None,
        "ntp_servers": " ".join(bare(a) for a in ((inv.get("ntp") or {}).get("servers") or {}).values()) or None,
        "admin_name": (dns.get("admin") or [None])[0],
        "corporate_fqdn": f"{locals_[0]}.{org.get('domain')}" if locals_ else None,
    }
    ctx.update(population_ctx(inv, name))
    return ctx


def fill(template: str, ctx: dict, node: dict, inv: dict):
    missing = []

    def sub(m):
        key, flt = m.group(1), m.group(2)
        if key in ctx:
            v = ctx[key]
        elif key.startswith("inv."):
            v = dig(inv, key[4:])
        else:
            v = dig(node, key)
        if v is None or isinstance(v, (dict, list)):
            missing.append(key)
            return ""
        v = str(v)
        return bare(v) if flt == "|ip" else v

    # {{ and }} are literal braces (curl's -w fields, for example)
    t = template.replace("{{", "\x00").replace("}}", "\x01")
    out = FIELD.sub(sub, t).replace("\x00", "{").replace("\x01", "}")
    return None if missing else out


def plan(inv: dict, name: str, quick: bool = False) -> list:
    node = inv["nodes"][name]
    ctx0 = base_ctx(inv, name)
    rows = []
    seen = set()
    for f in plan_files(node, inv, name):
        for q, slug, surface, command in read_list(f):
            if quick and not q:
                continue
            ctxs = [dict(ctx0)]
            if "{r}" in slug:
                ctxs = [dict(ctx0, **r) for r in rail_rows(inv, name)]
            elif "{subif}" in slug:
                subs = [n for n, i in sorted((node.get("interfaces") or {}).items(), key=lambda kv: natural(kv[0]))
                        if i.get("kind") == "subinterface"]
                ctxs = [dict(ctx0, subif=s) for s in subs]
            elif "{p2p}" in slug:
                ctxs = [dict(ctx0, **r) for r in p2p_rows(inv, name)]
            for ctx in ctxs:
                s = fill(slug, ctx, node, inv)
                c = fill(command, ctx, node, inv)
                if s is None or c is None:
                    continue
                s = re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_")
                if s in seen:
                    raise SystemExit(f"judge: {name}: slug {s} appears twice in its plan")
                seen.add(s)
                rows.append({"slug": s, "surface": surface, "ext": SURFACE_EXT[surface], "command": c})
    for i, r in enumerate(rows, 1):
        r["nn"] = f"{i:02d}"
    return rows


def cmd_plan(a) -> int:
    inv = load_inv(a.inv)
    if a.node not in inv.get("nodes", {}):
        print(f"judge: no node {a.node} in {a.inv}", file=sys.stderr)
        return 2
    for r in plan(inv, a.node, a.quick):
        print("\t".join((r["nn"], r["slug"], r["surface"], r["ext"], r["command"])))
    return 0


# --------------------------------------------------------------------------------------------
# splitting an interactive session by the device's own prompts


def _norm(s: str) -> str:
    return " ".join(s.split())


def split_session(text: str, commands: list, style: str) -> list:
    """Return one output (prompt line first) per command, or None where it was not found.

    The session is the cleaned transcript of `terminal length 0` (or the PAN-OS set-up lines),
    the commands in order, then `exit`. Each command's output is everything from its prompt line
    to the next prompt line. A prompt whose echo starts with the command (KLISH can echo a
    completion, as in "show vlanVlan") counts as that command.
    """
    rx = PROMPT_KLISH if style == "klish" else PROMPT_PANOS
    lines = text.splitlines()
    prompts = [(i, _norm(m.group(3))) for i, l in enumerate(lines) if (m := rx.match(l.rstrip()))]
    out = [None] * len(commands)
    pi = 0
    for ci, cmd in enumerate(commands):
        want = _norm(cmd)
        while pi < len(prompts) and not (prompts[pi][1] and prompts[pi][1].startswith(want)):
            pi += 1
        if pi >= len(prompts):
            break
        start = prompts[pi][0]
        end = prompts[pi + 1][0] if pi + 1 < len(prompts) else len(lines)
        out[ci] = "\n".join(l.rstrip() for l in lines[start:end]).rstrip() + "\n"
        pi += 1
    return out


def cmd_body(a) -> int:
    """The output of one command from a session on stdin, without its prompt line."""
    out = split_session(sys.stdin.read(), [a.command], a.style)[0]
    if out is None:
        return 1
    print("\n".join(out.splitlines()[1:]))
    return 0


def offload_problems(text: str, nics) -> list:
    o = p_offloads(text)
    probs = []
    if nics is not None and len(o) != int(nics):
        probs.append(f"{len(o)} data NICs inside the VM, want {nics}")
    for i in sorted(o, key=natural):
        for f in ("generic-receive-offload", "rx-gro-hw", "large-receive-offload"):
            if o[i].get(f) != "off":
                probs.append(f"{i} {f} {o[i].get(f, 'missing')}")
    if not o:
        probs.append("no data NIC listed")
    return probs


def cmd_offloads(a) -> int:
    probs = offload_problems(Path(a.file).read_text(encoding="utf-8", errors="replace"), a.nics)
    for p in probs:
        print(p)
    return 1 if probs else 0


def cmd_split(a) -> int:
    rows = []
    for line in Path(a.plan).read_text(encoding="utf-8").splitlines():
        p = line.split("\t")
        if len(p) == 5:
            rows.append(p)
    text = Path(a.session).read_text(encoding="utf-8", errors="replace")
    outs = split_session(text, [r[4] for r in rows], a.style)
    missing = 0
    for r, o in zip(rows, outs):
        nn, slug, _surface, ext, _command = r
        if o is None:
            print(f"{nn}_{slug}")
            missing += 1
            continue
        (Path(a.out) / f"{nn}_{slug}{ext}").write_text(o, encoding="utf-8")
    return 1 if missing else 0


# --------------------------------------------------------------------------------------------
# reading a result set


class ResultSet:
    def __init__(self, path):
        self.path = Path(path)

    def has(self, node) -> bool:
        return (self.path / node).is_dir()

    def file(self, node, slug):
        """The saved file of one planned command, stored plain or compressed (NAME.gz, evfile.py)."""
        d = self.path / node
        if not d.is_dir():
            return None
        for p in sorted(d.iterdir()):
            m = re.match(r"^[0-9]{2}_(.+)\.(txt|json|xml)(\.gz)?$", p.name)
            if m and m.group(1) == slug:
                return p
        return None

    def raw(self, node, slug):
        p = self.file(node, slug)
        return None if p is None else evfile.read_bytes(p)

    def body(self, node, slug):
        """The saved output, without the device's prompt line when it has one."""
        p = self.file(node, slug)
        if p is None:
            return None
        text = evfile.read_text(p)
        lines = text.splitlines()
        if lines and (PROMPT_KLISH.match(lines[0]) or PROMPT_PANOS.match(lines[0])):
            lines = lines[1:]
        return "\n".join(lines)

    def json(self, node, slug):
        b = self.body(node, slug)
        if b is None:
            return None
        try:
            return json.loads(b)
        except ValueError:
            return ValueError("not JSON")


# --------------------------------------------------------------------------------------------
# parsers (formats as SONiC 4.6.0 prints them; PAN-OS and guest formats as the
# tools print them)


def p_ip_interfaces(text: str) -> list:
    rows, dashes = [], 0
    for line in text.splitlines():
        if line.startswith("-----"):
            dashes += 1
            continue
        if dashes >= 2 and line.strip():
            f = line.split()
            addr = f[1] if len(f) > 1 and "/" in f[1] else ""
            vrf = f[2] if len(f) >= 4 else ""
            rows.append({"iface": f[0], "addr": addr, "vrf": vrf})
    return rows


def p_routes_brief(text: str) -> list:
    """`show ip route [vrf X]` in KLISH: [(code, prefix)] for every route row (' C>*   10.20.255.4/31 ...')."""
    out = []
    for line in (text or "").splitlines():
        m = re.match(r"^\s*([A-Za-z])[>*\s]*?\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b", line)
        if m and not line.strip().startswith("Codes"):
            out.append((m.group(1), m.group(2)))
    return out


def p_if_status_mtu(text: str) -> dict:
    """`show interface status`: {name: mtu} for every Ethernet and PortChannel row, by the column the
    header names MTU."""
    out, col = {}, None
    for line in (text or "").splitlines():
        if col is None and re.match(r"^Name\s", line) and " MTU " in f" {line} ":
            col = line.index(" MTU") + 1
            continue
        m = re.match(r"^((?:Ethernet|PortChannel)\d+)\s", line)
        if m and col is not None:
            v = line[col:].split()
            if v and v[0].isdigit():
                out[m.group(1)] = int(v[0])
    return out


def p_bpdu_guard(text: str) -> dict:
    """`show spanning-tree bpdu-guard`: {port: {configured: Y|N, shut: Y|N}}."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*((?:Ethernet|PortChannel)\d+)\s+([YN])\s+([YN])\b", line)
        if m:
            out[m.group(1)] = {"configured": m.group(2), "shut": m.group(3)}
    return out


def p_storm(text: str) -> dict:
    """`show storm-control`: {port: {type: kbps}}."""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\s*(Ethernet\d+)\s+(broadcast|unknown-unicast|unknown-multicast)\s+(\d+)\b", line)
        if m:
            out.setdefault(m.group(1), {})[m.group(2)] = int(m.group(3))
    return out


def p_blocks(text: str) -> list:
    """Running configuration as [(header, [indented lines])], top-level lines without a body too."""
    out = []
    for line in text.splitlines():
        if not line.strip() or line.strip() == "!":
            continue
        if line[0] not in " \t":
            out.append((line.strip(), []))
        elif out:
            out[-1][1].append(line.strip())
    return out


def p_mclag(text: str) -> dict:
    """`show mclag brief`: the domain's fields, "_interfaces" (PortChannel: local/remote) and
    "_backup", the Backup Keepalive Session Information block's own fields (Session Vrf, Session
    Status, Source Address, Peer Address, Keepalive Interval), kept apart from the session's."""
    d, ifs, bk, in_backup, in_ifs = {}, {}, {}, False, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Backup Keepalive"):
            in_backup = True
            continue
        if s.startswith("Number of MLAG Interfaces"):
            in_backup = False
        if s.startswith("MLAG Interface"):
            in_ifs = True
            continue
        if in_ifs:
            m = re.match(r"^(PortChannel\d+)\s+(\S+)", s)
            if m:
                ifs[m.group(1)] = m.group(2)
            continue
        m = re.match(r"^([A-Za-z][A-Za-z ]*?)\s*:\s*(.*)$", s)
        if m and not in_backup:
            d.setdefault(m.group(1).strip(), m.group(2).strip())
        elif m and in_backup:
            bk.setdefault(m.group(1).strip(), m.group(2).strip())
    d["_interfaces"] = ifs
    d["_backup"] = bk
    return d


def p_pc_summary(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+(PortChannel\d+)\s*\((\w+)\)(.*)$", line)
        if m:
            cur = m.group(2)
            out[cur] = {"state": m.group(3), "members": {}}
            rest = m.group(4)
        elif cur and re.match(r"^\s+Ethernet", line):
            rest = line
        else:
            continue
        for mm in re.finditer(r"(Ethernet\d+)\((\w+)\)", rest):
            out[cur]["members"][mm.group(1)] = mm.group(2)
    return out


def p_vlan(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^(\d+)\s+\S+(?:\s+([AT])\s+(\S+))?", line)
        if m:
            cur = int(m.group(1))
            out.setdefault(cur, {})
            if m.group(2):
                out[cur][m.group(3)] = m.group(2)
            continue
        m = re.match(r"^\s+([AT])\s+(\S+)", line)
        if m and cur is not None:
            out[cur][m.group(2)] = m.group(1)
    return out


def p_mac_table(text: str) -> list:
    rows = []
    for line in text.splitlines():
        m = re.match(r"^\s*(\d+)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(\S+)\s+(\S+)", line)
        if m:
            rows.append((int(m.group(1)), m.group(2).lower(), m.group(3), m.group(4)))
    return rows


def p_offloads(text: str) -> dict:
    out, cur = {}, None
    for line in text.splitlines():
        m = re.match(r"^== (\S+)", line)
        if m:
            cur = m.group(1)
            out[cur] = {}
            continue
        m = re.match(r"^([a-z-]+):\s*(\S+)", line.strip())
        if m and cur:
            out[cur][m.group(1)] = m.group(2)
    return out


def p_kv(text: str, sep: str = "=") -> dict:
    out = {}
    for line in text.splitlines():
        if sep in line:
            k, v = line.split(sep, 1)
            out[k.strip()] = v.strip()
    return out


def p_ping(text: str):
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received(?:, \+(\d+) duplicates)?", text or "")
    if not m:
        return None
    return {"tx": int(m.group(1)), "rx": int(m.group(2)), "dup": int(m.group(3) or 0),
            "toolong": bool(re.search(r"message too long|Frag needed", text, re.I))}


def p_bonding(text: str) -> dict:
    d = {"active_agg": None, "partner": None, "slaves": {}}
    cur, active = None, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("Active Aggregator Info"):
            active = True
            continue
        m = re.match(r"^Slave Interface:\s*(\S+)", s)
        if m:
            cur, active = m.group(1), False
            d["slaves"][cur] = {"agg": None, "mii": None, "partner": None}
            continue
        m = re.match(r"^Aggregator ID:\s*(\d+)", s)
        if m:
            if cur is None and active and d["active_agg"] is None:
                d["active_agg"] = int(m.group(1))
            elif cur and d["slaves"][cur]["agg"] is None:
                d["slaves"][cur]["agg"] = int(m.group(1))
            continue
        m = re.match(r"^Partner Mac Address:\s*(\S+)", s)
        if m and cur is None and d["partner"] is None:
            d["partner"] = m.group(1).lower()
            continue
        m = re.match(r"^MII Status:\s*(\S+)", s)
        if m and cur:
            d["slaves"][cur]["mii"] = m.group(1)
            continue
        m = re.match(r"^system mac address:\s*(\S+)", s, re.I)
        if m and cur and d["slaves"][cur]["partner"] is None:
            d["slaves"][cur]["partner"] = m.group(1).lower()
    return d


def p_bond_legs(text: str) -> dict:
    """/proc/net/bonding/<bond> per leg: {active_agg, ports, partner, legs: {slave: {agg, mii,
    actor_mac, actor_state, partner_mac, partner_state}}}. Under each slave the kernel prints
    "details actor lacp pdu:" then "details partner lacp pdu:", each with its system mac address
    and port state; without those headers the first system mac is the actor's, the second the
    partner's (the kernel's order)."""
    d = {"active_agg": None, "ports": None, "partner": None, "legs": {}}
    cur, side, active = None, None, False
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("Active Aggregator Info"):
            active, cur = True, None
            continue
        m = re.match(r"^Slave Interface:\s*(\S+)", s)
        if m:
            cur, side, active = m.group(1), None, False
            d["legs"][cur] = {"agg": None, "mii": None, "actor_mac": None, "actor_state": None,
                              "partner_mac": None, "partner_state": None}
            continue
        if re.match(r"^details actor lacp pdu", s, re.I):
            side = "actor"
            continue
        if re.match(r"^details partner lacp pdu", s, re.I):
            side = "partner"
            continue
        m = re.match(r"^Aggregator ID:\s*(\d+)", s)
        if m:
            if cur is None and active and d["active_agg"] is None:
                d["active_agg"] = int(m.group(1))
            elif cur and d["legs"][cur]["agg"] is None:
                d["legs"][cur]["agg"] = int(m.group(1))
            continue
        m = re.match(r"^Number of ports:\s*(\d+)", s)
        if m and cur is None and active:
            d["ports"] = int(m.group(1))
            continue
        m = re.match(r"^Partner Mac Address:\s*(\S+)", s)
        if m and cur is None and d["partner"] is None:
            d["partner"] = m.group(1).lower()
            continue
        if cur is None:
            continue
        leg = d["legs"][cur]
        m = re.match(r"^MII Status:\s*(\S+)", s)
        if m and leg["mii"] is None:
            leg["mii"] = m.group(1)
            continue
        m = re.match(r"^system mac address:\s*(\S+)", s, re.I)
        if m:
            who = side or ("actor" if leg["actor_mac"] is None else "partner")
            if leg[f"{who}_mac"] is None:
                leg[f"{who}_mac"] = m.group(1).lower()
            continue
        m = re.match(r"^port state:\s*(\d+)", s, re.I)
        if m:
            who = side or ("actor" if leg["actor_state"] is None else "partner")
            if leg[f"{who}_state"] is None:
                leg[f"{who}_state"] = int(m.group(1))
    return d


def p_iccp(text: str) -> list:
    """`ss -tanp | grep 8888` on a switch: [{state, local, local_vrf, local_port, peer, peer_port, proc}]."""
    rows = []
    ep = re.compile(r"^(\S+?)(?:%(\S+))?:(\d+|\*)$")
    for line in (text or "").splitlines():
        f = line.split()
        if len(f) < 5 or not re.match(r"^[A-Z-]+$", f[0]):
            continue
        a, b = ep.match(f[3]), ep.match(f[4])
        if not a or not b:
            continue
        proc = re.findall(r'\("([^"]+)"', line)
        rows.append({"state": f[0], "local": a.group(1), "local_vrf": a.group(2), "local_port": a.group(3),
                     "peer": b.group(1), "peer_port": b.group(3), "proc": proc})
    return rows


def p_panos_lacp(text: str) -> dict:
    """PAN-OS `show lacp aggregate-ethernet all`: {group: {partner_mac, members: {name: {bundled,
    selected, rate, state, partner_rate, partner_state}}}} (the Members table and the Port State
    table, where each member's row is followed by its Partner row)."""
    out, cur, last = {}, None, None
    section = None
    for line in (text or "").splitlines():
        s = line.strip()
        m = re.match(r"^AE group:\s*(\S+)", s)
        if m:
            cur = out.setdefault(m.group(1), {"partner_mac": None, "members": {}})
            section, last = "members", None
            continue
        if cur is None:
            continue
        if s.startswith("Partner:"):
            section = "partner"
            continue
        if s.startswith("Local:"):
            section = "local"
            continue
        if s.startswith("Port State"):
            section = "state"
            continue
        if s.startswith("Port Counters"):
            section = "counters"
            continue
        m = re.match(r"^System MAC:\s*(\S+)", s)
        if m and section == "partner":
            cur["partner_mac"] = m.group(1).lower()
            continue
        m = re.match(r"^(ethernet\S+)\s+(yes|no)\s+(\S+)\s+(\S+)\s+(\S+)", s)
        if m and section == "members":
            cur["members"].setdefault(m.group(1), {})["bundled"] = m.group(2) == "yes"
            cur["members"][m.group(1)]["selected"] = m.group(5) == "Selected"
            continue
        if section == "state":
            m = re.match(r"^(ethernet\S+)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+\d+\s+(0x[0-9A-Fa-f]+)", s)
            if m:
                last = m.group(1)
                cur["members"].setdefault(last, {}).update({"rate": m.group(3), "state": int(m.group(4), 16)})
                continue
            m = re.match(r"^Partner\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+\d+\s+(0x[0-9A-Fa-f]+)", s)
            if m and last:
                cur["members"][last].update({"partner_rate": m.group(2), "partner_state": int(m.group(3), 16)})
    return out


# LACP port state bits (IEEE 802.1AX): short timeout (fast), aggregation, in sync, collecting,
# distributing. A leg that carries traffic in a bundle has the last four set.
LACP_SHORT, LACP_AGGREGATING = 0x02, 0x3C


def p_panos_interfaces(text: str) -> tuple:
    """PAN-OS `show interface all`: ({hardware name: state}, {logical name: {zone, tag, address}}).

    The hardware table prints speed/duplex/state as one field; the logical table's columns are
    read by the spans of its dashed header line, since the zone column can be empty.
    """
    hw, logical, spans, section = {}, {}, None, None
    for line in text.splitlines():
        if line.startswith("total configured hardware interfaces"):
            section, spans = "hw", None
            continue
        if line.startswith("total configured logical interfaces"):
            section, spans = "logical", None
            continue
        if section == "hw":
            m = re.match(r"^(\S+)\s+\d+\s+\S+/\S+/(\S+)\s", line)
            if m:
                hw[m.group(1)] = m.group(2)
        elif section == "logical":
            if re.match(r"^-+( +-+)+\s*$", line):
                spans = [(m.start(), m.end()) for m in re.finditer(r"-+", line)]
                continue
            if spans and line.strip() and not line.startswith(("name ", "admin@")):
                cols = [line[a:b + 1].strip() if i < len(spans) - 1 else line[a:].strip() for i, (a, b) in enumerate(spans)]
                if len(cols) >= 7 and re.match(r"^\d+$", cols[1]):
                    logical[cols[0]] = {"zone": cols[3], "tag": cols[5], "address": cols[6]}
    return hw, logical


def macs_in(text: str) -> list:
    return [m.lower().replace("-", ":") for m in re.findall(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b", text or "")]


# M2 parsers: ip -j, sectioned outputs ("== name" headers), HTTP, dig, openssl x509, kubectl JSON


def slugify(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_")


def p_ip_addrs(data) -> dict:
    """ip -j addr show: {ifname: {state, flags, addrs (CIDR, IPv4 and global IPv6), master}}."""
    out = {}
    for link in data or []:
        if not isinstance(link, dict) or not link.get("ifname"):
            continue
        addrs = [f"{a.get('local')}/{a.get('prefixlen')}" for a in link.get("addr_info") or []
                 if a.get("family") == "inet" or (a.get("family") == "inet6" and a.get("scope") == "global")]
        out[link["ifname"]] = {"state": link.get("operstate"), "flags": list(link.get("flags") or []), "addrs": addrs,
                               "master": link.get("master")}
    return out


def p_sections(text: str) -> dict:
    """Output cut into sections by '== <name>' header lines: {name: body}."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"^== (.+)$", line)
        if m:
            cur = m.group(1).strip()
            out[cur] = ""
            continue
        if cur is not None:
            out[cur] += line + "\n"
    return out


def p_http_status(text: str):
    """The last HTTP status line's code (curl -D -, curl -i), or None."""
    codes = re.findall(r"^HTTP/[0-9.]+ (\d{3})\b", text or "", re.M)
    return int(codes[-1]) if codes else None


def p_curl_i(text: str):
    """curl -i output: (code, {header: value} of the last response, body)."""
    lines = (text or "").replace("\r", "").split("\n")
    starts = [i for i, l in enumerate(lines) if re.match(r"^HTTP/[0-9.]+ \d{3}\b", l)]
    if not starts:
        return None, {}, text or ""
    i = starts[-1]
    code = int(lines[i].split()[1])
    headers, j = {}, i + 1
    while j < len(lines) and lines[j].strip():
        if ":" in lines[j]:
            k, v = lines[j].split(":", 1)
            headers[k.strip().lower()] = v.strip()
        j += 1
    return code, headers, "\n".join(lines[j + 1:])


def p_dig(text: str) -> list:
    """dig +short: the IPv4 answers, in order."""
    return [l.strip() for l in (text or "").splitlines() if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", l.strip())]


def _cn(dn: str):
    m = re.search(r"(?:^|,)\s*CN\s*=\s*([^,]+)", dn or "")
    return m.group(1).strip() if m else None


def p_x509(text: str) -> dict:
    """openssl x509 -subject -issuer -nameopt RFC2253 [-ext ...], openssl verify: the subject and
    issuer and their CNs, the permitted name constraints, the SAN line, and verify's OK."""
    d = {"subject": None, "issuer": None, "permitted": [], "san": None, "verified": False}
    lines = (text or "").splitlines()
    mode = None
    for i, raw in enumerate(lines):
        l = raw.strip()
        if l.startswith("subject="):
            d["subject"] = l.split("=", 1)[1].strip()
        elif l.startswith("issuer="):
            d["issuer"] = l.split("=", 1)[1].strip()
        elif l.startswith("X509v3 Subject Alternative Name"):
            d["san"] = lines[i + 1].strip() if i + 1 < len(lines) else ""
        elif l.startswith("Permitted:"):
            mode = "permitted"
            continue
        elif l.startswith("Excluded:") or l.startswith("X509v3") or l.startswith("=="):
            mode = None
        elif re.search(r": OK$", l):
            d["verified"] = True
        if mode == "permitted" and not re.match(r"^(DNS|IP|email|URI|DirName|othername):", l):
            mode = None
        if mode == "permitted":
            kind, val = l.split(":", 1)
            val = val.strip()
            if kind.strip() == "IP" and "/" in val:
                a, m = val.split("/", 1)
                try:
                    val = str(ipaddress.ip_network(f"{a}/{m}", strict=False))
                except ValueError:
                    pass
            d["permitted"].append(val)
    d["cn"], d["issuer_cn"] = _cn(d["subject"]), _cn(d["issuer"])
    return d


def cond_true(status: dict, kind: str) -> bool:
    return any(c.get("type") == kind and c.get("status") == "True" for c in (status or {}).get("conditions") or [])


def pod_ready(p: dict) -> bool:
    st = p.get("status") or {}
    if st.get("phase") == "Succeeded":
        return True
    cs = st.get("containerStatuses") or []
    return st.get("phase") == "Running" and bool(cs) and all(c.get("ready") for c in cs)


def deploy_ready(d: dict) -> bool:
    want = (d.get("spec") or {}).get("replicas", 1)
    st = d.get("status") or {}
    return st.get("availableReplicas", 0) >= want and cond_true(st, "Available")


def blk_covers(cidr: str, start: str, end: str) -> bool:
    try:
        n = ipaddress.ip_network(cidr, strict=False)
        return ipaddress.ip_address(start) in n and ipaddress.ip_address(end) in n
    except ValueError:
        return False


# --------------------------------------------------------------------------------------------
# judging


class Judge:
    def __init__(self, rs: ResultSet, inv: dict, render: Path, v: vocab.Vocab, except_peers=()):
        self.rs, self.inv, self.render, self.v = rs, inv, Path(render), v
        self.nodes = inv.get("nodes") or {}
        # PortChannels whose far end is one of these nodes are set aside (boot's wait_fabric, while
        # the guests are held and their bonds cannot be up yet)
        self.except_peers = set(except_peers or ())

    # helpers ----------------------------------------------------------------------------
    def need(self, node, slug, label):
        b = self.rs.body(node, slug)
        if b is None:
            self.v.bad(label, f"{slug} not collected")
        return b

    def of_kind(self, *kinds) -> list:
        return [n for n in self.inv.get("order", []) if self.nodes[n]["kind"] in kinds]

    def present(self, names) -> list:
        out = []
        for n in names:
            if n not in self.nodes:
                self.v.bad(f"{n}: in the lab", "not in the inventory")
            elif not self.rs.has(n):
                self.v.bad(f"{n}: collected", "no saved files for this node")
            else:
                out.append(n)
        return out

    def system_mac_of(self, switch):
        return ((self.nodes.get(switch) or {}).get("mclag") or {}).get("system_mac")

    def host_macs(self) -> set:
        out = set()
        for n in self.nodes.values():
            for nic in (n.get("nics") or {}).values():
                if nic.get("mac"):
                    out.add(nic["mac"].lower())
        return out

    def container_macs(self) -> set:
        out = set()
        for n in self.inv.get("order", []):
            data = self.rs.json(n, "container_links")
            if isinstance(data, list):
                for link in data:
                    if link.get("address"):
                        out.add(link["address"].lower())
                    # a bond slave's own address (ip -d): its LACPDUs leave from it
                    perm = (((link.get("linkinfo") or {}).get("info_slave_data") or {}).get("perm_hwaddr") or "")
                    if perm:
                        out.add(perm.lower())
        return out

    # groups -----------------------------------------------------------------------------
    def g_shared(self, names):
        for sw in self.present(names or self.of_kind("dell_sonic")):
            n = self.nodes[sw]
            self.v.sec(f"{sw}: switch")
            log = self.need(sw, "launcher_log", "launcher typed the KLISH startup file")
            if log is not None:
                self.v.check("launcher log: KLISH startup config applied", "KLISH startup config applied" in log,
                             "line absent from the container log")
            env = self.need(sw, "container_env", "NUM_NICS in the container env")
            env = p_kv(env) if env is not None else None
            if env is not None:
                self.v.chk(f"NUM_NICS in the container env is {n['num_nics']}", n["num_nics"], env.get("NUM_NICS", "unset"))
                if n.get("passthrough"):
                    self.v.chk("CLAB_MGMT_PASSTHROUGH is true", "true", env.get("CLAB_MGMT_PASSTHROUGH", "unset").lower())
            off = self.need(sw, "offloads", "GRO, rx-gro-hw and LRO off")
            if off is not None:
                o = p_offloads(off)
                self.v.chk(f"data NICs inside the switch VM: {n['num_nics']}", n["num_nics"], len(o))
                feats = ("generic-receive-offload", "rx-gro-hw", "large-receive-offload")
                on = [f"{i}:{f}={o[i].get(f, 'missing')}" for i in sorted(o, key=natural) for f in feats
                      if o[i].get(f) != "off"]
                self.v.check(f"GRO, rx-gro-hw and LRO off on all {len(o)} data NICs", bool(o) and not on,
                             ", ".join(on[:6]) or "no NIC listed")
            v6 = self.need(sw, "container_ipv6", "IPv6 off on the container's data veths")
            if v6 is not None:
                kv = p_kv(v6, " ")
                on = [k for k, x in sorted(kv.items(), key=lambda kv: natural(kv[0])) if x != "1"]
                self.v.check(f"IPv6 off on the container's {len(kv)} data veths", bool(kv) and not on,
                             ", ".join(on) or "no veth listed")
            run = self.need(sw, "running_config", "ip vrf mgmt present")
            if run is not None:
                tops = [h for h, _ in p_blocks(run)]
                self.v.check("ip vrf mgmt present", "ip vrf mgmt" in tops, "no ip vrf mgmt line in the running configuration")
                self.parity(sw, run)

    def parity(self, sw, running: str):
        tool = COMMON / "klish" / "parity.py"
        rendered = self.render / "bootstrap" / sw / "startup-config.cfg"
        label = "parity: every rendered line is in the running configuration"
        if not tool.is_file():
            self.v.skip(label, "common/klish/parity.py is not present")
            return
        if not rendered.is_file():
            self.v.bad(label, f"no rendered {rendered.name} for {sw}")
            return
        with tempfile.TemporaryDirectory(prefix="sfab-parity-") as tmp:
            run_f, out_f = os.path.join(tmp, "running.txt"), os.path.join(tmp, "parity.json")
            with open(run_f, "w", encoding="utf-8") as t:
                t.write(running + "\n")
            cmd = [sys.executable, str(tool), str(rendered), run_f, "--switch", sw, "--json", out_f, "--quiet"]
            norm = self.render / "gen" / "klish-normalize.json"
            if norm.is_file():
                cmd += ["--normalize", str(norm)]
            p = subprocess.run(cmd, capture_output=True, text=True, env=dict(os.environ), timeout=120)
            try:
                res = json.load(open(out_f, encoding="utf-8"))
            except (OSError, ValueError):
                res = None
        if p.returncode in (0, 1) and res is not None:
            miss = res.get("missing") or []
            if not miss:
                self.v.ok(f"parity: 0 missing lines ({res.get('present')} of {res.get('rendered')} rendered lines present"
                          + (f", {len(res.get('absent') or [])} absent by a normalize row" if res.get("absent") else "") + ")")
            else:
                self.v.bad(label, f"{len(miss)} of {res.get('rendered')} missing: " +
                           "; ".join(str(m.get("line")) for m in miss[:3]))
        else:
            self.v.bad(label, f"parity.py exited {p.returncode}: {(p.stderr or p.stdout).strip()[:200]}")

    def expected_vlans(self, sw) -> dict:
        n = self.nodes[sw]
        want = {v: {} for v in n.get("vlans") or []}
        for name, pc in (n.get("portchannels") or {}).items():
            mode = "T" if pc.get("mode") == "trunk" else "A"
            for v in pc.get("vlans") or []:
                want.setdefault(v, {})[name] = mode
            # an access PortChannel's tagged VLANs (a host's VLAN units)
            for v in pc.get("tagged") or []:
                want.setdefault(v, {})[name] = "T"
        for native, ap in (n.get("access") or {}).items():
            want.setdefault(ap["vlan"], {})[native] = "A"
        return want

    def g_vlans(self, names):
        for sw in self.present(names or self.of_kind("dell_sonic")):
            self.v.sec(f"{sw}: VLAN membership")
            text = self.need(sw, "vlan", "show vlan")
            if text is None:
                continue
            got = p_vlan(text)
            for vid, ports in sorted(self.expected_vlans(sw).items()):
                have = got.get(vid)
                want_s = ",".join(f"{p}({m})" for p, m in sorted(ports.items(), key=lambda kv: natural(kv[0])))
                if have is None:
                    self.v.bad(f"Vlan{vid}: {want_s or 'no members'}", "VLAN absent")
                    continue
                have_s = ",".join(f"{p}({m})" for p, m in sorted(have.items(), key=lambda kv: natural(kv[0])))
                self.v.chk(f"Vlan{vid}: {want_s or 'no members'}", want_s, have_s)
            extra = sorted(set(got) - set(self.expected_vlans(sw)) - {1})
            self.v.check("no VLAN outside the render", not extra, "extra: " + ",".join(map(str, extra)))

    def g_mac_tables(self, names):
        hosts = self.host_macs()
        veths = self.container_macs()
        for sw in self.present(names or self.of_kind("dell_sonic")):
            n = self.nodes[sw]
            self.v.sec(f"{sw}: MAC table")
            text = self.need(sw, "mac_table", "show mac address-table")
            if text is None:
                continue
            # a port facing an appliance (the firewall, storage) learns that appliance's own MACs
            appliance_ports = set()
            for name, pc in (n.get("portchannels") or {}).items():
                peer = pc.get("peer_node")
                if peer and self.nodes.get(peer, {}).get("section") == "appliances":
                    appliance_ports.add(name)
            for native, ap in (n.get("access") or {}).items():
                peer = str(ap.get("peer", "")).split(":")[0]
                if self.nodes.get(peer, {}).get("section") == "appliances":
                    appliance_ports.add(native)
            # gen/expect/<sw>.json names the MACs this switch may learn from hosts, the relay
            # namespaces' macvlan MACs among them (those live only in the guests' node.env)
            known = set(hosts)
            try:
                exp = json.load(open(self.render / "gen" / "expect" / f"{sw}.json", encoding="utf-8"))
                known |= {m.lower() for m in (exp.get("known_macs") or {})}
            except (OSError, ValueError):
                pass
            rows = p_mac_table(text)
            # the partner's backup keepalive VLAN interface, learned on the peer link in that VLAN only
            ka = n.get("keepalive") or {}
            pl = (n.get("mclag") or {}).get("peer_link")
            partner_ka = [r for r in rows if ka.get("backup_vlan") and r[0] == ka["backup_vlan"] and r[3] == pl]
            counted = [r for r in rows if r[0] != 1 and r[1] not in veths and r not in partner_ka]
            foreign = [f"{mac} on {port} (Vlan{vid})" for vid, mac, _t, port in counted
                       if mac not in known and port not in appliance_ports]
            ignored = len(rows) - len(counted) - len(partner_ka)
            self.v.check(f"MAC table holds host MACs only ({len(counted)} entries; {ignored} VLAN 1 or container veth entries set aside"
                         + (f"; {len(partner_ka)} on {pl} in Vlan{ka['backup_vlan']}, the partner's backup keepalive" if partner_ka else "") + ")",
                         not foreign, "; ".join(foreign[:4]))

    def g_forwarding(self, names):
        """Chapter 2's forwarding-only reads, restated for build A revision 2: no routing protocol and
        no address on any served VLAN, PortChannel or host port; an MCLAG member holds exactly its two
        keepalive addresses (the dedicated link and the backup VLAN interface), both in the keepalive
        VRF, whose table holds only their two connected /31s; the default table is empty."""
        for sw in self.present(names or self.of_kind("dell_sonic")):
            self.v.sec(f"{sw}: forwarding only")
            ka = self.nodes.get(sw, {}).get("keepalive") or None
            allowed = {"Management0": ("mgmt", None)}
            if ka:
                allowed[ka["port"]] = (ka["vrf"], ka["address"])
                if ka.get("backup_interface"):
                    allowed[ka["backup_interface"]] = (ka["vrf"], ka["backup_address"])
            want_names = ",".join(sorted(allowed, key=natural))
            ipi = self.need(sw, "ip_interfaces", "show ip interfaces")
            if ipi is not None:
                rows = p_ip_interfaces(ipi)
                names_ = [r["iface"] for r in rows]
                if ka:
                    self.v.chk(f"show ip interfaces lists only Management0 and the keepalive addresses ({want_names})", want_names,
                               ",".join(sorted(names_, key=natural)) or "nothing")
                    for r in rows:
                        if r["iface"] in allowed and r["iface"] != "Management0":
                            vrf, a = allowed[r["iface"]]
                            self.v.chk(f"{r['iface']} holds {a} in VRF {vrf}", f"{a} {vrf}", f"{r['addr'] or 'no address'} {r['vrf'] or 'default'}")
                else:
                    self.v.chk("show ip interfaces lists only Management0", "Management0", ",".join(names_) or "nothing")
                mg = [r for r in rows if r["iface"] == "Management0"]
                if mg:
                    self.v.chk("Management0 in VRF mgmt", "mgmt", mg[0]["vrf"] or "default")
            rt = self.need(sw, "ip_route", "show ip route")
            if rt is not None:
                self.v.check("show ip route (the default table) prints nothing", not rt.strip(), f"{len(rt.strip().splitlines())} lines")
            if ka:
                rk = self.need(sw, "ip_route_ka", f"show ip route vrf {ka['vrf']}")
                if rk is not None:
                    got = sorted(p_routes_brief(rk), key=lambda x: natural(x[1]))
                    want = sorted([("C", str(ipaddress.ip_interface(a).network)) for _, a in allowed.values() if a],
                                  key=lambda x: natural(x[1]))
                    self.v.chk(f"VRF {ka['vrf']} holds only its connected keepalive /31s",
                               " ".join(f"{c} {n}" for c, n in want), " ".join(f"{c} {n}" for c, n in got) or "nothing")
            rr = self.need(sw, "running_router", "no router line")
            if rr is not None:
                self.v.check("no router line in the running configuration", not rr.strip(), rr.strip().splitlines()[0][:80] if rr.strip() else "")
            run = self.rs.body(sw, "running_config")
            if run is not None:
                bkp = f"interface {ka['backup_interface']}" if ka and ka.get("backup_interface") else None
                kport = f"interface {ka['port']}" if ka else None
                addressed = [(h, body) for h, body in p_blocks(run) if re.match(r"^interface (Vlan|PortChannel|Ethernet) ?\d+", h)
                             and any(l.startswith("ip address") or l.startswith("ipv6 address") for l in body)]
                served = [h for h, _ in addressed if re.match(r"^interface Vlan ?\d+", h) and h.replace(" ", "") != (bkp or "").replace(" ", "")]
                self.v.check("no address on any served VLAN's interface Vlan block" + (f" (only {ka['backup_interface']}, the backup keepalive)" if bkp else ""),
                             not served, ", ".join(served))
                ports_ = [h for h, _ in addressed if not re.match(r"^interface Vlan ?\d+", h) and h.replace(" ", "") != (kport or "").replace(" ", "")]
                self.v.check("no address on any PortChannel or host port" + (f" (only {ka['port']}, the keepalive link)" if kport else ""),
                             not ports_, ", ".join(ports_))
                if ka:
                    for h, body in addressed:
                        if h.replace(" ", "") in ((bkp or "").replace(" ", ""), kport.replace(" ", "")):
                            self.v.check(f"{h.split(' ', 1)[1]} is in VRF {ka['vrf']}", f"ip vrf forwarding {ka['vrf']}" in body,
                                         ", ".join(l for l in body if l.startswith("ip vrf")) or "no ip vrf forwarding line")
            frr = self.need(sw, "frr_running", "FRR view")
            if frr is not None:
                rl = [l.strip() for l in frr.splitlines() if l.strip().startswith("router ")]
                self.v.check("FRR view holds no router block", not rl, ", ".join(rl[:3]))
            kv = self.rs.json(sw, "kernel_addr")
            if kv is None:
                self.v.bad("kernel holds no data address", "kernel_addr not collected")
            elif not isinstance(kv, list):
                self.v.bad("kernel holds no data address", "kernel_addr is not ip -j output")
            else:
                found, seen = [], set()
                for link in kv:
                    ifn = link.get("ifname", "")
                    for ai in link.get("addr_info") or []:
                        fam, scope = ai.get("family"), ai.get("scope")
                        cidr = f"{ai.get('local')}/{ai.get('prefixlen')}"
                        if fam == "inet" and ifn in allowed and ifn != "Management0" and allowed[ifn][1] == cidr:
                            seen.add(ifn)
                            continue
                        if fam == "inet" and ifn not in KERNEL_WHITELIST:
                            found.append(f"{ifn} {cidr}")
                        elif fam == "inet6" and scope == "global" and DATA_NETDEV.match(ifn):
                            found.append(f"{ifn} {cidr}")
                if ka:
                    self.v.check(f"kernel holds no address on any Vlan, PortChannel or Ethernet netdev but the keepalive addresses ({', '.join(f'{k} {v[1]}' for k, v in allowed.items() if v[1])}; "
                                 "lo-m, docker-mgmt, redirect, docker0 set aside)", not found and len(seen) == len(allowed) - 1,
                                 "; ".join(found[:4]) or f"missing: {', '.join(k for k in allowed if k != 'Management0' and k not in seen)}")
                else:
                    self.v.check("kernel holds no address on any Vlan, PortChannel or Ethernet netdev "
                                 "(lo-m, docker-mgmt, redirect, docker0 set aside)", not found, "; ".join(found[:4]))

    def g_l2_hygiene(self, names):
        """Build A revision 2's Layer 2 hygiene on the pair and the rail switches, from the inventory:
        the spanning-tree mode; every used port at its rendered MTU (9216 under the l2 policy, a member
        at its PortChannel's); BPDU guard with port-shutdown on every edge port, none tripped, and on
        no other port (the peer link and the firewall's trunk are not edge ports); storm control of
        each type at its rate on every member and access port the policy names."""
        for sw in self.present(names or self.of_kind("dell_sonic")):
            n = self.nodes.get(sw) or {}
            self.v.sec(f"{sw}: Layer 2 hygiene")
            factory = 9100
            if n.get("stp"):
                rs_ = self.need(sw, "running_stp", "show running-configuration spanning-tree")
                if rs_ is not None:
                    m = re.search(r"^spanning-tree mode (\S+)", rs_, re.M)
                    self.v.chk(f"spanning-tree mode {n['stp']}", n["stp"], m.group(1) if m else "absent")
            want = {}
            pcs = n.get("portchannels") or {}
            for name, pc in pcs.items():
                for mb in pc.get("members") or []:
                    want[mb] = pc.get("mtu") or factory
                want[name] = pc.get("mtu") or factory
            for nat, a in (n.get("access") or {}).items():
                want[nat] = a.get("mtu") or factory
            ka = n.get("keepalive") or None
            if ka:
                want[ka["port"]] = ka.get("mtu") or factory
            st = self.need(sw, "interface_status", "show interface status")
            if st is not None:
                got = p_if_status_mtu(st)
                eth = sorted((k for k in want if k.startswith("Ethernet")), key=natural)
                bad = [f"{k} {got.get(k, 'absent')}" for k in eth if str(got.get(k)) != str(want[k])]
                vals = sorted({str(want[k]) for k in eth})
                self.v.check(f"every used port ({len(eth)}) at its rendered MTU ({', '.join(vals)})", not bad, ", ".join(bad[:6]))
                pcn = sorted((k for k in want if k.startswith("PortChannel") and k in got), key=natural)
                if pcn:
                    badp = [f"{k} {got.get(k)}" for k in pcn if str(got.get(k)) != str(want[k])]
                    self.v.check(f"every PortChannel ({len(pcn)}) at its rendered MTU", not badp, ", ".join(badp[:6]))
            edge = list(n.get("edge") or [])
            if n.get("stp") or edge:
                bg = self.need(sw, "bpdu_guard", "show spanning-tree bpdu-guard")
                if bg is not None:
                    rows = p_bpdu_guard(bg)
                    miss = [e for e in edge if rows.get(e, {}).get("configured") != "Y"]
                    self.v.check(f"BPDU guard with port-shutdown on every edge port ({len(edge)})", not miss, ", ".join(miss[:6]))
                    tripped = sorted((k for k, r in rows.items() if r.get("shut") == "Y"), key=natural)
                    self.v.check("no port shut by BPDU guard", not tripped, ", ".join(tripped))
                    others = sorted((k for k in rows if k not in edge), key=natural)
                    self.v.check("BPDU guard on no other port" + (" (the peer link and the firewall's trunk are not edge ports)" if n.get("mclag") else ""), not others,
                                 ", ".join(others))
            storm = (n.get("storm") or {})
            if storm.get("ports"):
                sc = self.need(sw, "storm_control", "show storm-control")
                if sc is not None:
                    rows = p_storm(sc)
                    want_k = {k: int(v) for k, v in (storm.get("kbps") or {}).items()}
                    bad = [f"{pt} {t} {rows.get(pt, {}).get(t, 'absent')}" for pt in storm["ports"] for t, k in sorted(want_k.items())
                           if rows.get(pt, {}).get(t) != k]
                    self.v.check(f"storm control on every member and access port ({len(storm['ports'])}): "
                                 + ", ".join(f"{t} {k} kbps" for t, k in sorted(want_k.items())), not bad, ", ".join(bad[:6]))

    def g_mclag(self, names):
        if len(names) != 2:
            self.v.bad("mclag-pair", f"needs two switches, got {len(names)}")
            return
        a, b = names
        self.v.sec(f"pair {a} {b}")
        pres = self.present(names)
        roles = {}
        for sw in pres:
            n = self.nodes[sw]
            mc = n.get("mclag") or {}
            text = self.need(sw, "mclag_brief", f"{sw}: show mclag brief")
            if text is not None:
                d = p_mclag(text)
                roles[sw] = d.get("Role", "")
                self.v.chk(f"{sw}: MCLAG domain", mc.get("domain"), d.get("Domain ID", "absent"))
                self.v.chk(f"{sw}: session up", "up", d.get("Session Status", "absent"))
                self.v.chk(f"{sw}: peer link up", "up", d.get("Peer Link Status", "absent"))
                self.v.chk(f"{sw}: peer link {mc.get('peer_link')}", mc.get("peer_link"), d.get("Peer Link", "absent"))
                ka = n.get("keepalive") or {}
                self.v.chk(f"{sw}: keepalive in VRF {mc.get('session_vrf')}", mc.get("session_vrf"), d.get("Session Vrf", "absent"))
                where = f"its address on the keepalive link {ka.get('port')}" if ka else "the passthrough address"
                self.v.chk(f"{sw}: keepalive source is {where}, {mc.get('source_ip')}", mc.get("source_ip"),
                           d.get("Source Address", "absent"))
                self.v.chk(f"{sw}: keepalive peer is {mc.get('peer_ip')}", mc.get("peer_ip"), d.get("Peer Address", "absent"))
                bkw = mc.get("backup") or None
                if bkw:
                    got = d.get("_backup") or {}
                    self.v.chk(f"{sw}: backup keepalive session up on {ka.get('backup_interface')}, {bkw.get('source_ip')} to "
                               f"{bkw.get('peer_ip')} in VRF {bkw.get('vrf')}",
                               f"up {bkw.get('source_ip')} {bkw.get('peer_ip')} {bkw.get('vrf')}",
                               " ".join(got.get(k, "absent") for k in ("Session Status", "Source Address", "Peer Address", "Session Vrf")))
                self.v.chk(f"{sw}: mclag-system-mac {mc.get('system_mac')}", str(mc.get("system_mac")).lower(),
                           d.get("Mclag System Mac", "absent").lower())
                ifs = d.get("_interfaces") or {}
                for name, pc in sorted((n.get("portchannels") or {}).items(), key=lambda kv: natural(kv[0])):
                    if pc.get("peer_node") in self.except_peers:
                        continue
                    if pc.get("mclag"):
                        self.v.chk(f"{sw}: MLAG interface {name} up/up", "up/up", ifs.get(name, "absent"))
            text = self.need(sw, "portchannel_summary", f"{sw}: show PortChannel summary")
            if text is not None:
                got = p_pc_summary(text)
                for name, pc in sorted((n.get("portchannels") or {}).items(), key=lambda kv: natural(kv[0])):
                    if pc.get("peer_node") in self.except_peers:
                        continue
                    g = got.get(name)
                    mem = ",".join(pc.get("members") or [])
                    if g is None:
                        self.v.bad(f"{sw}: {name} up with {mem}", "PortChannel absent")
                        continue
                    down = [f"{m}({g['members'].get(m, 'absent')})" for m in pc.get("members") or []
                            if g["members"].get(m) != "P"]
                    self.v.check(f"{sw}: {name} up with {mem}", g["state"] == "U" and not down,
                                 f"state {g['state']}" + (", " + ", ".join(down) if down else ""))
        if len(roles) == 2:
            self.v.chk("roles: one active, one standby", "active,standby", ",".join(sorted(r.lower() for r in roles.values())))

    # Chapter 3: the domain's roles, the ICCP session, and every bond's legs under the system MAC --

    def g_pair_roles(self, names):
        """The roles the keepalive addresses elect (the lower source address is active), the ICCP
        session on TCP 8888 in the keepalive's VRF on both switches, and iccpd's own keepalive state."""
        if len(names) != 2:
            self.v.bad("pair-roles", f"needs two switches, got {len(names)}")
            return
        a, b = names
        self.v.sec(f"pair {a} {b}: roles and the ICCP session")
        pres = self.present(names)
        briefs = {}
        for sw in pres:
            t = self.need(sw, "mclag_brief", f"{sw}: show mclag brief")
            if t is not None:
                briefs[sw] = p_mclag(t)
        mcs = {sw: (self.nodes[sw].get("mclag") or {}) for sw in names}
        if len(briefs) == 2 and all(mcs[sw].get("source_ip") for sw in names):
            src = {sw: ipaddress.ip_address(mcs[sw]["source_ip"]) for sw in names}
            lo, hi = sorted(names, key=lambda s: src[s])
            self.v.chk(f"{lo} is active: its keepalive source {src[lo]} is the lower of the two", "active",
                       (briefs[lo].get("Role") or "absent").lower())
            self.v.chk(f"{hi} is standby: its keepalive source {src[hi]} is the higher", "standby",
                       (briefs[hi].get("Role") or "absent").lower())
        for sw in pres:
            mc = mcs[sw]
            vrf, me, peer = mc.get("session_vrf"), mc.get("source_ip"), mc.get("peer_ip")
            ss = self.need(sw, "iccp_session", f"{sw}: the ICCP session")
            if ss is not None:
                rows = p_iccp(ss)
                est = [r for r in rows if r["state"].startswith("ESTAB") and r["local"] == me and r["peer"] == peer
                       and "8888" in (r["local_port"], r["peer_port"]) and (r["local_vrf"] or "default") == (vrf or "default")]
                self.v.check(f"{sw}: ICCP session established on TCP 8888 in VRF {vrf}, {me} to {peer}"
                             + (f" ({est[0]['proc'][0]})" if est and est[0]["proc"] else ""),
                             bool(est), "; ".join(f"{r['state']} {r['local']}%{r['local_vrf'] or ''}:{r['local_port']} {r['peer']}:{r['peer_port']}"
                                                   for r in rows[:3]) or "no TCP 8888 socket")
                lis = [r for r in rows if r["state"] == "LISTEN" and r["local_port"] == "8888"]
                self.v.check(f"{sw}: iccpd listens on TCP 8888 in VRF {vrf}", any((r["local_vrf"] or "default") == (vrf or "default") for r in lis),
                             ", ".join(f"{r['local']}%{r['local_vrf'] or 'default'}" for r in lis) or "no listener")
            st = self.need(sw, "iccp_state", f"{sw}: iccpd's keepalive state")
            if st is not None:
                m = re.search(r"keepalive is:\s*(\S+)", st)
                self.v.chk(f"{sw}: iccpd reports the keepalive OK", "OK", m.group(1) if m else "absent")

    def g_bond_legs(self, names):
        """Every bond toward the pair, leg by leg: each leg in the active aggregator with the pair's
        mclag-system-mac as its partner, aggregating, and fast LACP both ways. Hosts read their own
        /proc/net/bonding; the firewall its LACP table; a storage appliance, whose own view is not
        collected, is read from the switches' side only (and says so)."""
        self.v.sec("every bond's legs under the system MAC")
        want = names or [n for n in self.inv.get("order", []) if self.rs.has(n)]
        for n in want:
            node = self.nodes.get(n)
            if node is None:
                self.v.bad(f"{n}: in the lab", "not in the inventory")
                continue
            if node.get("bond") and node.get("kind") in ("vm-node", "bastion", "resolver"):
                self._bond_host(n, node)
            elif node.get("kind") == "paloalto_panos":
                self._bond_fw(n, node)
            elif node.get("section") == "appliances" and any(x.get("role") == "bond-member" for x in (node.get("nics") or {}).values()):
                self._bond_switch_side(n)

    def _bond_host(self, n, node):
        bond = node["bond"]
        text = self.rs.body(n, "bonding")
        if text is None:
            return
        b = p_bond_legs(text)
        members = list(bond.get("members") or [])
        peer_sw = str((node.get("nics") or {}).get(members[0], {}).get("peer", "")).split(":")[0] if members else ""
        sysmac = (self.system_mac_of(peer_sw) or "").lower()
        probs, legs = [], []
        for m in members:
            leg = b["legs"].get(m)
            if leg is None:
                probs.append(f"{m} absent")
                continue
            legs.append(f"{m} (partner state {leg['partner_state']})")
            if leg["agg"] != b["active_agg"]:
                probs.append(f"{m} in aggregator {leg['agg']}, active {b['active_agg']}")
            if leg["mii"] != "up":
                probs.append(f"{m} MII {leg['mii']}")
            if leg["partner_mac"] != sysmac:
                probs.append(f"{m} partner {leg['partner_mac']}")
            for who in ("actor", "partner"):
                st = leg[f"{who}_state"]
                if st is None or (st & LACP_AGGREGATING) != LACP_AGGREGATING:
                    probs.append(f"{m} {who} state {st}")
        if b["ports"] is not None and b["ports"] != len(members):
            probs.append(f"{b['ports']} ports in the active aggregator")
        self.v.check(f"{n} {bond['name']}: {len(members)} of {len(members)} legs in aggregator {b['active_agg']}, each with partner {sysmac}, "
                     f"aggregating: {', '.join(legs)}", not probs, "; ".join(probs))
        slow = [f"{m} {who}" for m in members for who in ("actor", "partner")
                if (b["legs"].get(m) or {}).get(f"{who}_state") is not None and not (b["legs"][m][f"{who}_state"] & LACP_SHORT)]
        self.v.check(f"{n} {bond['name']}: fast LACP both ways on every leg (short timeout in the actor and partner state)", not slow,
                     ", ".join(slow))

    def _bond_fw(self, n, node):
        text = self.rs.body(n, "lacp")
        if text is None:
            return
        groups = p_panos_lacp(text)
        ifaces = node.get("interfaces") or {}
        for ae in sorted((k for k, i in ifaces.items() if i.get("kind") == "aggregate"), key=natural):
            g = groups.get(ae)
            members = sorted((k for k, i in ifaces.items() if i.get("kind") == "aggregate-member"), key=natural)
            sysmacs = {self.system_mac_of(str(nic.get("peer", "")).split(":")[0])
                       for nic in (node.get("nics") or {}).values() if nic.get("role") == "bundle-member"} - {None}
            sysmac = (next(iter(sysmacs)) if len(sysmacs) == 1 else "").lower()
            if g is None:
                self.v.bad(f"{n} {ae}: its legs under the system MAC", f"no AE group {ae} in show lacp")
                continue
            probs, legs = [], []
            for m in members:
                x = g["members"].get(m) or {}
                legs.append(f"{m} (state 0x{x.get('state', 0):02X}, partner 0x{x.get('partner_state', 0):02X})")
                if not (x.get("bundled") and x.get("selected")):
                    probs.append(f"{m} not bundled and selected")
                for k in ("state", "partner_state"):
                    if x.get(k) is None or (x[k] & LACP_AGGREGATING) != LACP_AGGREGATING:
                        probs.append(f"{m} {k} {x.get(k)}")
                if x.get("rate") != "Fast" or x.get("partner_rate") != "Fast":
                    probs.append(f"{m} rate {x.get('rate')}/{x.get('partner_rate')}")
            if g["partner_mac"] != sysmac:
                probs.append(f"partner {g['partner_mac']}")
            self.v.check(f"{n} {ae}: {len(members)} of {len(members)} legs selected under partner {sysmac}, fast both ways: {', '.join(legs)}",
                         not probs, "; ".join(probs))

    def _bond_switch_side(self, n):
        """A storage appliance's bonds (data, and management when it is a bond), from the pair's
        side: each PortChannel up with every member selected (P) on each switch. Its own LACP view is
        not collected."""
        pcs = []
        for sw in self.of_kind("dell_sonic"):
            for name, pc in sorted((self.nodes[sw].get("portchannels") or {}).items(), key=lambda kv: natural(kv[0])):
                if pc.get("peer_node") == n:
                    pcs.append((sw, name, pc))
        if not pcs:
            return
        probs, seen = [], []
        for sw, name, pc in pcs:
            t = self.rs.body(sw, "portchannel_summary")
            if t is None:
                probs.append(f"{sw}: show PortChannel summary not collected")
                continue
            g = p_pc_summary(t).get(name) or {"state": "absent", "members": {}}
            sel = [m for m in pc.get("members") or [] if g["members"].get(m) == "P"]
            seen.append(f"{sw} {name} {','.join(sel) or 'none'}")
            if g["state"] != "U" or len(sel) != len(pc.get("members") or []):
                probs.append(f"{sw} {name} state {g['state']}, selected {','.join(sel) or 'none'}")
        what = "its data bond's PortChannel" if len({name for _, name, _ in pcs}) == 1 else "its bonds' PortChannels"
        self.v.check(f"{n}: {what} up with every member selected on both switches ({'; '.join(seen)})",
                     not probs, "; ".join(probs))
        self.v.skip(f"{n}: each leg's partner MAC from the appliance's own side", "its LACP state is not collected")

    def g_firewall(self, names):
        fws = names or [x for x in [((self.inv.get("stages") or {}).get("fw"))] if x]
        for fw in self.present(fws):
            n = self.nodes[fw]
            self.v.sec(f"{fw}: firewall")
            mk = self.need(fw, "commit_marker", "commit marker present")
            if mk is not None:
                self.v.check("commit marker present", "result=OK" in mk or "marker present" in mk,
                             "neither the launcher's commit line nor /tmp/lab-startup-committed")
            rendered = self.render / "bootstrap" / fw / "startup-config.xml"
            got = self.rs.raw(fw, "delivered_config")
            label = "delivered /config/startup-config.cfg matches the render byte for byte"
            if not rendered.is_file():
                self.v.bad(label, "no rendered startup-config.xml")
            elif got is None:
                self.v.bad(label, "delivered_config not collected")
            else:
                self.v.check(label, got == rendered.read_bytes(),
                             f"{len(got)} bytes delivered, {rendered.stat().st_size} rendered")
            enf = self.render / "bootstrap" / fw / "enforced.txt"
            if not enf.is_file():
                self.v.bad("enforced.txt present", "no rendered enforced.txt")
            else:
                want = [_norm(l) for l in enf.read_text(encoding="utf-8").splitlines() if l.strip() and not l.lstrip().startswith("#")]
                self.v.ok(f"enforced.txt present ({len(want)} lines)")
                cs = self.need(fw, "config_set", "enforced lines in the running configuration")
                if cs is not None:
                    have = {_norm(l) for l in cs.splitlines()}
                    miss = [w for w in want if w not in have]
                    self.v.check(f"all {len(want)} enforced lines in the set-format running configuration", not miss,
                                 f"{len(miss)} missing: " + "; ".join(miss[:2]))
            ifaces = n.get("interfaces") or {}
            members = sorted((k for k, i in ifaces.items() if i.get("kind") == "aggregate-member"), key=natural)
            sysmacs = {self.system_mac_of(str(nic.get("peer", "")).split(":")[0])
                       for nic in (n.get("nics") or {}).values() if nic.get("role") == "bundle-member"} - {None}
            lacp = self.need(fw, "lacp", "LACP on the aggregate")
            if lacp is not None and members:
                # "  ethernet1/1   yes  Current  Tx_Rx  Selected": bundled, in sync, selected
                out = [m for m in members if not re.search(rf"^\s*{re.escape(m)}\s+yes\s+Current\s+\S+\s+Selected\b", lacp, re.M)]
                self.v.check(f"{' and '.join(members)} in the aggregate (bundled, current, selected)", not out,
                             "not bundled: " + ", ".join(out))
                seen = set(macs_in(lacp))
                for mac in sorted(sysmacs):
                    self.v.check(f"LACP partner is the pair's mclag-system-mac {mac}", mac.lower() in seen,
                                 "partner MACs seen: " + (", ".join(sorted(seen)[:4]) or "none"))
            # A sub-interface has no state of its own in PAN-OS: it is up when it stands in the logical
            # table with its rendered tag, address and zone, and its parent is up in the hardware table.
            alltext = self.rs.body(fw, "interface_all")
            hw, logical = p_panos_interfaces(alltext or "")
            for sub in sorted((k for k, i in ifaces.items() if i.get("kind") == "subinterface"), key=natural):
                want = ifaces[sub]
                parent, tag = sub.split(".", 1)
                t = self.need(fw, f"iface_{re.sub(r'[^A-Za-z0-9_]+', '_', sub)}", f"{sub} up")
                if t is None or alltext is None:
                    if alltext is None:
                        self.v.bad(f"{sub} up", "interface_all not collected")
                    continue
                row = logical.get(sub) or {}
                probs = []
                if not row:
                    probs.append("not in the logical interfaces")
                else:
                    if row.get("tag") != tag:
                        probs.append(f"tag {row.get('tag')}")
                    if want.get("address") and row.get("address") != want["address"]:
                        probs.append(f"address {row.get('address')}")
                    if want.get("zone") and row.get("zone") != want["zone"]:
                        probs.append(f"zone {row.get('zone')}")
                if hw.get(parent) != "up":
                    probs.append(f"{parent} is {hw.get(parent, 'absent')}")
                if not re.search(rf"^Name: {re.escape(sub)}, ID: \d+, 802\.1q tag: {re.escape(tag)}\b", t, re.M):
                    probs.append("show interface does not name it with its tag")
                self.v.check(f"{sub} up: tag {tag}, {want.get('address')}, zone {want.get('zone')}, on {parent} which is up",
                             not probs, "; ".join(probs))
            # the tunnels the firewall terminates: an established IKEv2 SA with each peer, and one
            # IPsec child SA per proxy ID
            vpns = n.get("vpns") or []
            if vpns:
                ike = self.need(fw, "vpn_ike_sa", "show vpn ike-sa")
                esp = self.need(fw, "vpn_ipsec_sa", "show vpn ipsec-sa")
                for x in vpns:
                    if ike is not None:
                        row = next((l for l in ike.splitlines() if re.search(rf"\b{re.escape(x['peer'])}\s+{re.escape(x['name'])}\b", l)), "")
                        self.v.check(f"tunnel {x['name']}: IKEv2 SA with {x['peer']} established", "Established" in row,
                                     row.strip()[:100] or "no SA with the peer")
                    if esp is not None:
                        miss = [pid for pid, *_ in x.get("proxy_ids") or [] if f"{x['name']}:{pid}" not in esp]
                        self.v.check(f"tunnel {x['name']}: an IPsec SA for each proxy ID "
                                     f"({', '.join(p[0] for p in x.get('proxy_ids') or [])}) on {x['tunnel_interface']}", not miss,
                                     "none for " + ", ".join(miss))
                    # the far end, from its own side: the gateway container healthy, and swanctl
                    # reaching charon with the IKE SA established and each child SA installed (when
                    # this set collected the gateway: a quick audit reads the switches and the firewall)
                    gw = x.get("peer_node")
                    if gw in self.nodes and self.nodes[gw]["kind"] == "vpngw" and self.rs.has(gw):
                        h = self.need(gw, "container_health", f"{gw}: the container running and healthy")
                        if h is not None:
                            self.v.check(f"{gw}: the container running and healthy", bool(re.search(r"^running healthy\b", h.strip(), re.M)),
                                         h.strip()[:80])
                        sas = self.need(gw, "swanctl_sas", f"{gw}: swanctl --list-sas")
                        if sas is not None:
                            ike_up = bool(re.search(rf"^{re.escape(x['name'])}: #\d+, ESTABLISHED, IKEv2\b", sas, re.M))
                            self.v.check(f"{gw}: swanctl reaches charon and lists IKE SA {x['name']} established", ike_up,
                                         "" if ike_up else (sas.strip().splitlines() or ["no output"])[0][:100])
                            miss = [pid for pid, *_ in x.get("proxy_ids") or []
                                    if not re.search(rf"^\s+{re.escape(pid)}: #\d+, reqid \d+, INSTALLED, TUNNEL\b", sas, re.M)]
                            self.v.check(f"{gw}: a child SA installed for each proxy ID", ike_up and not miss,
                                         "none for " + ", ".join(miss) if miss else "")

    def g_guests(self, names):
        mgmt_gw = (self.inv.get("mgmt") or {}).get("gw")
        for g in self.present(names or list((self.inv.get("stages") or {}).get("guests") or [])):
            n = self.nodes[g]
            self.v.sec(f"{g}: guest")
            ns = self.need(g, "netsetup_unit", "sfab-netsetup.service ran in this boot")
            if ns is not None:
                kv = p_kv(ns)
                ran = kv.get("Result") == "success" and kv.get("ExecMainStatus") == "0" and kv.get("ExecMainExitTimestampMonotonic", "0") != "0"
                self.v.check("sfab-netsetup.service ran in this boot and succeeded", ran,
                             " ".join(f"{k}={kv.get(k)}" for k in ("Result", "ExecMainStatus", "ExecMainExitTimestampMonotonic")))
            bond = n.get("bond")
            if bond:
                text = self.need(g, "bonding", f"{bond['name']}")
                if text is not None:
                    b = p_bonding(text)
                    slaves = b["slaves"]
                    self.v.chk(f"{bond['name']} has {len(bond['members'])} slaves", ",".join(bond["members"]),
                               ",".join(sorted(slaves, key=natural)) or "none")
                    aggs = {s["agg"] for s in slaves.values()}
                    self.v.check(f"{bond['name']} slaves under one aggregator ID", len(aggs) == 1 and None not in aggs
                                 and b["active_agg"] in aggs, f"slave IDs {sorted(map(str, aggs))}, active {b['active_agg']}")
                    peer_sw = str((n.get("nics") or {}).get(bond["members"][0], {}).get("peer", "")).split(":")[0]
                    want = self.system_mac_of(peer_sw)
                    if want:
                        self.v.chk(f"{bond['name']} partner MAC is the mclag-system-mac", want.lower(), b["partner"] or "absent")
            tc = self.need(g, "tx_container", "TX checksum offload off, container side")
            if tc is not None:
                o = p_offloads(tc)
                on = [e for e in sorted(o, key=natural) if o[e].get("tx-checksumming") != "off"]
                self.v.check(f"TX checksum offload off on the container's {len(o)} data NICs", bool(o) and not on, ", ".join(on))
            tg = self.need(g, "tx_guest", "TX checksum offload off, guest side")
            if tg is not None:
                rows = [l.split() for l in tg.splitlines() if "tx-checksumming:" in l]
                on = [r[0] for r in rows if len(r) < 3 or r[2] != "off"]
                self.v.check(f"TX checksum offload off on the guest's {len(rows)} data NICs", bool(rows) and not on, ", ".join(on))
            tm = self.need(g, "table_mgmt", "management in its own table")
            if tm is not None:
                table = dig(self.inv, "guest.tables.mgmt")
                self.v.check(f"management default in table {table} via {mgmt_gw}", f"default via {mgmt_gw}" in tm,
                             (tm.strip().splitlines() or ["table empty"])[0])
            if n.get("gateway"):
                self.ping(g, "ping_gw", f"{n['gateway']} answers ping")
                self.ping(g, "gw_one_hop", f"{n['gateway']} is one hop away (an echo sent with TTL 1 is answered)")
            oob = n.get("oob") or {}
            if oob.get("gateway"):
                where = f" from the BMC stand-in's namespace {oob['netns']}" if oob.get("netns") else ""
                self.ping(g, "ping_oob_gw", f"{oob['gateway']} answers over the out-of-band network{where}")
            if oob.get("netns"):
                self.bmc_checks(g, n, oob)

    def bmc_checks(self, g, n, oob):
        """The BMC stand-in: its address in namespace oob.netns only (the host OS has none on the BMC
        VLAN), and the namespace listening on each of its services' ports."""
        want = oob["address"]
        ns = self.rs.json(g, "bmc_addr")
        if not isinstance(ns, list):
            self.v.bad(f"{g}: {want} in namespace {oob['netns']}", "bmc_addr not collected or not JSON")
        else:
            held = [f"{a.get('local')}/{a.get('prefixlen')}" for i in ns for a in i.get("addr_info") or [] if a.get("family") == "inet"]
            self.v.check(f"{g}: the BMC address {want} on {oob['eth']} in namespace {oob['netns']}", want in held, ", ".join(held) or "none")
        host = self.rs.json(g, "ip_addr")
        if isinstance(host, list):
            ip = want.split("/")[0]
            held = [a.get("local") for i in host for a in i.get("addr_info") or [] if a.get("family") == "inet"]
            self.v.check(f"{g}: the host OS holds no address on the BMC VLAN ({ip} is the namespace's)", ip not in held,
                         "the host OS holds it")
        ls = self.need(g, "bmc_listen", f"{g}: the BMC stand-in listens")
        if ls is not None:
            ports = {"ssh": "22", "https": "443"}
            for svc in oob.get("services") or []:
                p = ports.get(svc)
                got = bool(p) and bool(re.search(rf"\S+:{p}\s", ls))
                self.v.check(f"{g}: namespace {oob['netns']} listens on {svc} ({p})", got, "not listening")

    def arp(self, node, slug, label) -> bool:
        """arping's summary (busybox or iputils): at least one reply."""
        text = self.need(node, slug, label)
        if text is None:
            return False
        m = re.search(r"Received (\d+) response", text)
        if m is None:
            return self.v.bad(label, "no arping summary in the output")
        return self.v.check(label, int(m.group(1)) >= 1, f"{m.group(1)} replies")

    def ping(self, node, slug, label, jumbo=False) -> bool:
        text = self.need(node, slug, label)
        if text is None:
            return False
        p = p_ping(text)
        if p is None:
            return self.v.bad(label, "no ping statistics in the output")
        good = p["rx"] >= 1 and not (jumbo and p["toolong"])
        ok = self.v.check(label, good, f"{p['rx']}/{p['tx']} replies" + (", message too long" if p["toolong"] else ""))
        if good and p["dup"]:
            self.v.known("L1", f"{label}: {p['dup']} duplicate replies (peer-link isolation is not enforced)")
        return ok

    def g_rails(self, names):
        gpus = names or [g for g in (self.inv.get("stages") or {}).get("guests") or [] if (self.nodes.get(g) or {}).get("relay")]
        for g in self.present(gpus):
            n = self.nodes[g]
            relay = n.get("relay") or {}
            want_ns = list(relay.get("namespaces") or [])
            self.v.sec(f"{g}: relay and rails")
            nl = self.need(g, "netns_list", "relay namespaces")
            if nl is not None:
                have = {l.split()[0] for l in nl.splitlines() if l.strip()}
                miss = [x for x in want_ns if x not in have]
                self.v.check(f"{len(want_ns)} relay namespaces ({','.join(want_ns)})", not miss, "missing: " + ",".join(miss))
            try:
                rprefix = ipaddress.ip_network(relay.get("prefix")) if relay.get("prefix") else None
            except ValueError:
                rprefix = None
            rpf = relay.get("rp_filter")
            for row in rail_rows(self.inv, g):
                r, nsn = row["r"], row["ns"]
                rt = self.need(g, f"ns_routes_{r}", f"{nsn}: routes")
                if rt is not None:
                    dflt = [l for l in rt.splitlines() if l.startswith("default")]
                    self.v.check(f"{nsn}: no default route", not dflt, dflt[0] if dflt else "")
                rp = self.need(g, f"ns_rpf_{r}", f"{nsn}: rp_filter")
                if rp is not None and rpf is not None:
                    kv = {k: int(v) for k, v in p_kv(rp, " ").items() if v.isdigit()}
                    base = kv.get("all", 0)
                    eff = {k: max(base, v) for k, v in kv.items() if k not in ("all", "default", "lo")}
                    wrong = [f"{k}={v}" for k, v in sorted(eff.items()) if v != rpf]
                    self.v.check(f"{nsn}: rp_filter {rpf} on {','.join(sorted(eff)) or 'no interface'}", bool(eff) and not wrong,
                                 ", ".join(wrong))
                if row["peer"] and row["peer_addr"]:
                    self.ping(g, f"same_rail_{r}", f"rail {r}: 9000-byte DF ping {g} to {row['peer']} ({row['peer_addr']})", jumbo=True)
                if row["peer"] and row["next_peer_addr"]:
                    self.ping(g, f"cross_rail_{r}", f"rail {r} to rail {row['next_r']}: {g} to {row['peer']} ({row['next_peer_addr']})")
                    rg = self.need(g, f"cross_route_{r}", f"rail {r} to rail {row['next_r']} through the relay")
                    if rg is not None:
                        m = re.search(r"\bvia (\S+)", rg)
                        through = False
                        if m and rprefix is not None:
                            try:
                                through = ipaddress.ip_address(m.group(1)) in rprefix
                            except ValueError:
                                through = False
                        self.v.check(f"rail {r} to rail {row['next_r']} leaves {nsn} through the relay ({relay.get('prefix')})",
                                     through, rg.strip().splitlines()[0][:100] if rg.strip() else "no route")

    # M2: the cluster's nodes, the bastion, the uplink side, the clients, storage, the cluster and
    # the populations (dev/m2/RESULTS.md, criteria 3 to 9) ------------------------------------------

    def bond_checks(self, node, n) -> None:
        """A bond to the MCLAG pair: its members, one aggregator, the pair's system MAC as partner."""
        bond = n.get("bond")
        if not bond:
            return
        text = self.need(node, "bonding", f"{bond['name']}")
        if text is None:
            return
        b = p_bonding(text)
        slaves = b["slaves"]
        self.v.chk(f"{bond['name']} has {len(bond['members'])} slaves", ",".join(bond["members"]),
                   ",".join(sorted(slaves, key=natural)) or "none")
        aggs = {s["agg"] for s in slaves.values()}
        self.v.check(f"{bond['name']} slaves under one aggregator ID", len(aggs) == 1 and None not in aggs
                     and b["active_agg"] in aggs, f"slave IDs {sorted(map(str, aggs))}, active {b['active_agg']}")
        peer_sw = str((n.get("nics") or {}).get(bond["members"][0], {}).get("peer", "")).split(":")[0]
        want = self.system_mac_of(peer_sw)
        if want:
            self.v.chk(f"{bond['name']} partner MAC is the mclag-system-mac", want.lower(), b["partner"] or "absent")

    def addr_check(self, node, ifname, cidr) -> None:
        label = f"{ifname} holds {cidr}"
        data = self.rs.json(node, "ip_addr")
        if not isinstance(data, list):
            self.v.bad(label, "ip_addr not collected" if data is None else "ip_addr is not ip -j output")
            return
        links = p_ip_addrs(data)
        got = links.get(ifname)
        if got is None:
            self.v.bad(label, f"no {ifname}")
            return
        up = got["state"] == "UP" or ("UP" in got["flags"] and "LOWER_UP" in got["flags"])
        self.v.check(label + " and is up", cidr in got["addrs"] and up,
                     f"addresses {','.join(got['addrs']) or 'none'}, state {got['state']}")

    def route_check(self, node, slug, label, want) -> None:
        text = self.need(node, slug, label)
        if text is not None:
            self.v.check(label, any(l.strip().startswith(want) for l in text.splitlines()),
                         (text.strip().splitlines() or ["table empty"])[0][:100])

    def tx_container(self, node) -> None:
        tc = self.need(node, "tx_container", "TX checksum offload off, container side")
        if tc is not None:
            o = p_offloads(tc)
            on = [e for e in sorted(o, key=natural) if o[e].get("tx-checksumming") != "off"]
            self.v.check(f"TX checksum offload off on the container's {len(o)} data NICs", bool(o) and not on, ", ".join(on))

    def render_env(self, node) -> dict:
        p = self.render / "bootstrap" / node / "init.env"
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            return {}
        out = {}
        for line in text.splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip("'\"")
        return out

    def view_for(self, address):
        """The DNS view (name, spec) whose clients hold ADDRESS."""
        return view_of_address(self.inv, address)

    def view_of(self, node):
        """The DNS view (name, spec) that answers NODE's lookups, through its resolver."""
        return client_view(self.inv, node)

    def k8s_nodes(self) -> list:
        st = self.inv.get("stages") or {}
        return [g for g in st.get("guests") or [] if (self.nodes.get(g) or {}).get("k8s")]

    def g_cluster_nodes(self, names):
        reg = self.inv.get("registry") or {}
        ntp = self.inv.get("ntp") or {}
        dns = self.inv.get("dns") or {}
        for g in self.present(names or self.k8s_nodes()):
            n = self.nodes[g]
            ctx = base_ctx(self.inv, g)
            self.v.sec(f"{g}: cluster node")
            cu = self.need(g, "cluster_unit", "sfab-cluster.service finished in this boot with status 0")
            if cu is not None:
                kv = p_kv(cu)
                st, sub = kv.get("ActiveState"), kv.get("SubState")
                done = (st == "inactive" or (st == "active" and sub == "exited")) and kv.get("ExecMainStatus") == "0" \
                    and kv.get("ExecMainExitTimestampMonotonic", "0") not in ("", "0")
                self.v.check("sfab-cluster.service finished in this boot with status 0", done,
                             " ".join(f"{k}={kv.get(k)}" for k in ("ActiveState", "SubState", "ExecMainStatus", "NRestarts")))
            ka = self.need(g, "kubelet_active", "kubelet active")
            if ka is not None:
                last = (ka.strip().splitlines() or [""])[-1].strip()
                self.v.chk("kubelet active", "active", last or "nothing")
            ups = list(reg.get("upstreams") or [])
            url = ctx.get("registry_url")
            if ups and url:
                ch = self.need(g, "containerd_hosts", "containerd mirrors")
                if ch is not None:
                    sections = p_sections(ch)
                    mirror = url.split("://", 1)[1]
                    probs = []
                    for up in ups:
                        body = next((b for path, b in sections.items() if f"/{up}/" in path), None)
                        if body is None:
                            probs.append(f"{up}: no hosts.toml")
                        elif mirror not in body or not re.search(r"override_path\s*=\s*true", body):
                            probs.append(f"{up}: does not name {mirror} with override_path = true")
                    self.v.check(f"containerd mirrors: a hosts.toml for each of {', '.join(ups)} naming {url} with override_path",
                                 not probs, "; ".join(probs))
                rv = self.need(g, "registry_v2", "the registry answers through the firewall's source NAT")
                if rv is not None:
                    code = p_http_status(rv)
                    self.v.check(f"the registry answers through the firewall's source NAT (GET {url}/v2/ is 200)",
                                 code == 200, f"HTTP {code}" if code else (rv.strip().splitlines() or ["no answer"])[-1][:100])
            servers = (ntp.get("servers") or {})
            if servers:
                nt = self.need(g, "ntp_resolvers", "the resolvers answer NTP")
                if nt is not None:
                    for srv, a in sorted(servers.items()):
                        m = re.search(rf"stratum (\d+) from {re.escape(bare(a))}$", nt, re.M)
                        good = bool(m) and 1 <= int(m.group(1)) <= 15
                        self.v.check(f"{srv} answers NTP from {g}'s segment ({bare(a)}, stratum {m.group(1) if m else '?'})", good,
                                     next((l for l in nt.splitlines() if bare(a) in l), "no reply")[:100])
                ts = self.need(g, "timesync", "the guest's time servers")
                if ts is not None:
                    want = " ".join(bare(a) for _, a in sorted(servers.items()))
                    have = (re.search(r"^SystemNTPServers=(.*)$", ts, re.M) or [None, ""])[1].strip()
                    self.v.chk("systemd-timesyncd names both resolvers as its time servers", want, have or "none")
            view, vs = self.view_of(g)
            users = ctx.get("users_fqdn")
            if users and vs.get("answer_address"):
                d = self.need(g, "dns_users", f"the {view} view answers {users}")
                if d is not None:
                    self.v.chk(f"the {view} view answers {users} with {vs['answer_address']}", vs["answer_address"],
                               ",".join(p_dig(d)) or "no answer")
                d2 = self.need(g, "dns_both", f"both resolvers answer {users}")
                if d2 is not None:
                    rows = [l.split() for l in d2.splitlines() if l.strip()]
                    bad_ = [r[0] for r in rows if r[1:] != [vs["answer_address"]]]
                    self.v.check(f"each of the node's {len(rows)} resolvers answers {users} with {vs['answer_address']}",
                                 bool(rows) and not bad_, "wrong or no answer from " + ", ".join(bad_))
            sf = ctx.get("storage_fqdn")
            want = (dns.get("records") or {}).get(sf) if sf else None
            if sf and want:
                d = self.need(g, "dns_storage", f"the {view} view answers {sf}")
                if d is not None:
                    self.v.chk(f"the {view} view answers an infrastructure name: {sf} is {want}", want, ",".join(p_dig(d)) or "no answer")
            sa = ctx.get("storage_addr")
            units = ((self.nodes[g].get("bond") or {}).get("vlan_ifs")) or []
            in_vlan = bool(sa) and any(ipaddress.ip_address(sa) in ipaddress.ip_interface(u["address"]).network for u in units)
            if sa and in_vlan:
                # NVMe/TCP 4420 is judged by the audit's volume check: TrueNAS listens on it only
                # while a subsystem exists, and none does between volumes
                sp = self.need(g, "storage_ports", f"TrueNAS's data address {sa} answers on NFS 2049")
                if sp is not None:
                    self.v.check(f"TrueNAS's data address {sa} answers on NFS 2049", "2049 open" in sp, "closed: 2049")
                self.ping(g, "ping_storage", f"TrueNAS's data address {sa} answers ping")
            elif sa:
                # the storage data VLAN is Layer 2 only: a node with no unit in it has no path there
                sp = self.need(g, "storage_ports", f"TrueNAS's data address {sa} is out of reach (no unit in its VLAN)")
                if sp is not None:
                    self.v.check(f"TrueNAS's data address {sa} does not answer on NFS 2049: the node has no unit in the storage VLAN",
                                 "2049 closed" in sp, "it answered")

    def g_bastion(self, names):
        """The jump host: its one leg, its tables, the services it runs (sshd and lldpd, nothing else:
        no DNS, no time), the lab CA it trusts, no admin kubeconfig and no cluster or CA state, and the
        operator's short-lived client certificate with what its ClusterRole lets it do."""
        mgmt_gw = (self.inv.get("mgmt") or {}).get("gw")
        tables = dig(self.inv, "guest.tables") or {}
        ca = self.inv.get("ca") or {}
        k8s = self.inv.get("k8s") or {}
        st = self.inv.get("stages") or {}
        dns = self.inv.get("dns") or {}
        for b in self.present(names or [x for x in [st.get("bastion")] if x]):
            n = self.nodes[b]
            self.v.sec(f"{b}: bastion, the jump host")
            self.bond_checks(b, n)
            bond = n.get("bond") or {}
            if bond.get("address"):
                self.addr_check(b, bond["name"], bond["address"])
            if n.get("gateway"):
                self.route_check(b, "table_main", f"default via {n['gateway']} in the main table", f"default via {n['gateway']}")
            self.route_check(b, "table_mgmt", f"management default in table {tables.get('mgmt')} via {mgmt_gw}", f"default via {mgmt_gw}")
            oob = n.get("oob") or {}
            if oob:
                self.addr_check(b, oob["eth"], oob["address"])
                self.route_check(b, "table_oob", f"out-of-band default in table {oob.get('table')} via {oob['gateway']}",
                                 f"default via {oob['gateway']}")
            else:
                self.v.ok("one leg only: no NIC in the BMC VLAN (the render names none)")
            self.tx_container(b)
            sv = self.need(b, "services", "the bastion's services")
            if sv is not None:
                for p in ("sshd", "lldpd"):
                    self.v.check(f"{p} running", f"{p} running" in sv, "not running")
                ran = [p for p in ("named", "chronyd", "dnsmasq") if f"{p} running" in sv]
                self.v.check("no DNS or time server runs on the jump host (named, chronyd, dnsmasq absent)", not ran,
                             "running: " + ", ".join(ran))
            rv = self.need(b, "resolv_conf", "the bastion's resolvers")
            if rv is not None:
                want = [bare((self.nodes.get(r) or {}).get("address")) for r in n.get("resolvers") or [] if r in self.nodes]
                got = [l.split()[1] for l in rv.splitlines() if l.startswith("nameserver ") and len(l.split()) > 1]
                self.v.chk(f"the bastion asks the lab's resolvers ({', '.join(n.get('resolvers') or [])})", ",".join(want), ",".join(got) or "none")
            if ca.get("root_cn"):
                cc = self.need(b, "ca_certs", "the lab CA published")
                if cc is not None:
                    certs = {Path(k).name: p_x509(v) for k, v in p_sections(cc).items()}
                    root = certs.get("root.crt") or {}
                    self.v.check(f"the lab root CA published: state/shared/ca/root.crt, subject {ca['root_cn']}",
                                 root.get("cn") == ca["root_cn"] and root.get("issuer_cn") == ca["root_cn"],
                                 f"subject {root.get('subject') or 'absent'}, issuer {root.get('issuer') or 'absent'}")
                    for iname, i in sorted((ca.get("intermediates") or {}).items()):
                        c = certs.get(f"{iname}.crt") or {}
                        self.v.check(f"the {iname} intermediate ({i['cn']}) chains to the lab root",
                                     c.get("cn") == i["cn"] and c.get("issuer_cn") == ca["root_cn"] and c.get("verified"),
                                     f"subject {c.get('subject') or 'absent'}, issuer {c.get('issuer') or 'absent'}, "
                                     f"verify {'OK' if c.get('verified') else 'failed'}")
                        want = sorted(set(i.get("dns") or []) | set(i.get("ip") or []))
                        if want:
                            self.v.chk(f"the {iname} intermediate's name constraints: {', '.join(want)}", ",".join(want),
                                       ",".join(sorted(c.get("permitted") or [])) or "none")
                sk = self.need(b, "shared_keys", "private keys under state/shared/")
                if sk is not None:
                    # finish retracts kubeadm's keys (sfab-ca retract) once every node is Ready
                    rows = [l.split(None, 1) for l in sk.splitlines() if re.match(r"^[0-7]{3,4} ", l)]
                    found = [f"{p} ({m})" for m, p in rows]
                    self.v.check("no private key under state/shared/ (kubeadm's keys retracted once every control node joined)",
                                 "scanned state/shared" in sk and not found, "; ".join(found) or "scan did not finish")
            ak = self.need(b, "admin_kubeconfig", "no standing admin credential on the bastion")
            if ak is not None:
                self.v.check("no kubeconfig for root on the bastion (the admin kubeconfig stays on the init node)",
                             "root kubeconfig absent" in ak, "a root kubeconfig is present")
                self.v.check("no cluster or CA state reaches the bastion (no state/shared/cluster, no state/ca)",
                             "no cluster or CA state" in ak, "cluster or CA state is visible")
            if st.get("cluster") and k8s:
                ops = k8s.get("operators") or self.k8s_names().get("operators") or {}
                user = dig(self.inv, "guest.user") or "admin"
                oc = self.need(b, "operator_cert", f"the operator {user}'s kubeconfig")
                if oc is not None:
                    subj = (re.search(r"^subject=(.*)$", oc, re.M) or [None, ""])[1]
                    na = (re.search(r"^notAfter=(.*)$", oc, re.M) or [None, ""])[1]
                    group = (ops or {}).get("group") or "operators"
                    self.v.check(f"{user}'s kubeconfig on the bastion carries a client certificate for {user} in group {group}",
                                 f"CN={user}" in subj and f"O={group}" in subj, subj or (oc.strip().splitlines() or ["none"])[0][:80])
                    # kubeadm signs with the CA's own notBefore, so the lifetime is read from the
                    # collector's clock at the read (now=): the certificate expires within validity_h
                    now = (re.search(r"^now=(.*)$", oc, re.M) or [None, ""])[1]
                    left = None
                    try:
                        fmt = "%b %d %H:%M:%S %Y %Z"
                        t1 = datetime.datetime.strptime(re.sub(r"\s+", " ", na.strip()), fmt)
                        t0 = datetime.datetime.strptime(re.sub(r"\s+", " ", now.strip()), fmt)
                        left = (t1 - t0).total_seconds() / 3600
                    except ValueError:
                        pass
                    want_h = float((ops or {}).get("validity_h") or 8)
                    self.v.check(f"the client certificate is short-lived: it expires within {want_h:g} hours of its issue, not a standing credential",
                                 left is not None and 0 < left <= want_h + 0.1,
                                 (f"{left:.2f} h left" + (" (expired: finish's operators step issues a new one)" if left <= 0 else ""))
                                 if left is not None else f"notAfter {na or 'absent'}, read at {now or 'no time'}")
                ci = self.need(b, "operator_can_i", f"what {user} may do")
                if ci is not None:
                    got = dict((k.strip(), v.strip()) for k, _, v in (l.partition(": ") for l in ci.splitlines()) if k)
                    role = (ops or {}).get("cluster_role") or "view"
                    if role == "view":
                        # view reads namespaced objects only; the render also binds the group to
                        # <group>-cluster-view, which reads nodes and the other cluster-scoped objects
                        # and no Secret, so the operator lists nodes and changes nothing
                        want = {"get pods -A": "yes", "list nodes": "yes", "create pods -A": "no", "get secrets -A": "no", "delete nodes": "no"}
                        self.v.check(f"{user} may read the workloads and the nodes and change nothing, no Secrets (ClusterRole {role} and {(ops or {}).get('group') or 'operators'}-cluster-view)",
                                     all(got.get(k) == v for k, v in want.items()),
                                     "; ".join(f"{k}: {got.get(k) or 'no answer'}" for k in want))
                    else:
                        self.v.skip(f"what {user} may do", f"the ClusterRole {role} has no expectation here")
            sm = base_ctx(self.inv, b).get("stor_mgmt_addr")
            if sm:
                h = self.need(b, "stor_mgmt_https", "TrueNAS's web interface")
                if h is not None:
                    code = p_http_status(h)
                    self.v.check(f"TrueNAS's web interface answers on its management address from the bastion (https://{sm}, rule bastion-to-stor-mgmt)",
                                 code is not None, (h.strip().splitlines() or ["no answer"])[-1][:100])

    def g_services(self, names):
        """The platform's DNS and time services: the authoritative pair (the secondary holds each
        view's zone at the primary's serial, the render's), the recursive resolvers (the users' name,
        a reverse name, NXDOMAIN at once outside the zone, chrony following the reference over NTS),
        the corporate resolver (the users' name from the enterprise view, no admin name, a corporate
        name of its own) and the time reference."""
        dns = self.inv.get("dns") or {}
        ntp = self.inv.get("ntp") or {}
        views = dns.get("views") or {}
        gws = self.inv.get("gateways") or {}
        want = [x for x in self.inv.get("order") or [] if (self.nodes.get(x) or {}).get("kind") == "resolver"
                and (self.nodes[x].get("role") in ("dns-auth", "dns-res", "dns-corporate", "inet-ntp"))]
        for x in self.present(names or want):
            n = self.nodes[x]
            role = n.get("role")
            ctx = base_ctx(self.inv, x)
            self.v.sec(f"{x}: {role}")
            if n.get("bond"):
                self.bond_checks(x, n)
                self.addr_check(x, n["bond"]["name"], n["bond"]["address"])
            sv = self.need(x, "services", "the servers it runs")
            if sv is not None:
                need = {"dns-auth": ["named"], "dns-res": ["named", "chronyd"], "dns-corporate": ["dnsmasq"], "inet-ntp": ["chronyd"]}.get(role, [])
                for p in need:
                    self.v.check(f"{p} running", f"{p} running" in sv, "not running")
            if role == "dns-auth":
                zs = self.need(x, "zonestatus", "each view's zone")
                if zs is not None:
                    secs = p_sections(zs)
                    for v in (ctx.get("dns_views") or "").split():
                        body = secs.get(v) or ""
                        typ = (re.search(r"^type: (\S+)", body, re.M) or [None, ""])[1]
                        ser = (re.search(r"^serial: (\d+)", body, re.M) or [None, ""])[1]
                        prim = (views.get(v) or {}).get("server")
                        want_t = "primary" if prim == x else "secondary"
                        rendered = self.rendered_serial(prim, v, dns.get("zone"))
                        self.v.check(f"view {v}: {dns.get('zone')} is {want_t} here at serial {rendered} (the render's{', from ' + prim + ' by transfer' if want_t == 'secondary' else ''})",
                                     typ in (want_t, "master" if want_t == "primary" else "slave") and rendered is not None and ser == str(rendered),
                                     f"type {typ or 'unknown'}, serial {ser or 'none'}")
                lu = self.need(x, "local_users", "the local view's answer")
                lv = next((v for v in (ctx.get("dns_views") or "").split() if (views.get(v) or {}).get("infra")), None)
                if lu is not None and lv:
                    a = (views.get(lv) or {}).get("answer_address")
                    self.v.chk(f"view {lv} answers {ctx.get('users_fqdn')} with {a}", a, ",".join(p_dig(lu)) or "no answer")
                rc = self.need(x, "recursion", "recursion off")
                if rc is not None:
                    self.v.check("recursion is off: a name outside its zones is REFUSED", "status: REFUSED" in rc, rc.strip()[:80])
            elif role == "dns-res":
                view, vs = self.view_for(n.get("address"))
                u = self.need(x, "res_users", "the users' name")
                if u is not None and vs.get("answer_address"):
                    self.v.chk(f"{ctx.get('users_fqdn')} resolves to {vs['answer_address']} through the {view} view",
                               vs["answer_address"], ",".join(p_dig(u)) or "no answer")
                api = (self.inv.get("k8s") or {}).get("api_fqdn")
                rv = self.need(x, "res_reverse", "a reverse name")
                if rv is not None and api:
                    self.v.chk(f"the reverse name of {ctx.get('api_vip')} is {api}", api + ".", (rv.strip().splitlines() or ["none"])[0])
                ro = self.need(x, "res_outside", "a name outside the zone")
                if ro is not None:
                    self.v.check("a name outside the platform's zone is NXDOMAIN at once, from the resolver's own empty root (aa)",
                                 "status: NXDOMAIN" in ro and re.search(r"flags:[^;]*\baa\b", ro) is not None, ro.strip()[:80])
                up = ntp.get("upstream") or {}
                cs = self.need(x, "chrony_sources", "chrony's sources")
                if cs is not None and up.get("address"):
                    sel = [l for l in cs.splitlines() if l.startswith("^*") and up["address"] in l]
                    self.v.check(f"chrony follows the reference {up.get('node')} ({up['address']}): selected, marked ^*", bool(sel),
                                 next((l for l in cs.splitlines() if up["address"] in l), "not among the sources")[:100])
                if ntp.get("nts") and up.get("address"):
                    ad = self.need(x, "chrony_authdata", "chrony's authentication")
                    if ad is not None:
                        row = next((l.split() for l in ad.splitlines() if l.split()[:1] == [up["address"]]), None)
                        self.v.check(f"the reference is authenticated with NTS (chronyc authdata: mode NTS, a key and cookies)",
                                     bool(row) and len(row) > 1 and row[1] == "NTS" and any(c.isdigit() and int(c) > 0 for c in row[2:3]),
                                     " ".join(row) if row else "no row for the reference")
            elif role == "dns-corporate":
                ev = next((v for v, d in views.items() if bare(n.get("address")) in [bare(c) for c in d.get("match_cidrs") or []]), None)
                a = (views.get(ev) or {}).get("answer_address")
                u = self.need(x, "corp_users", "the users' name")
                if u is not None and a:
                    self.v.chk(f"{ctx.get('users_fqdn')} resolves to {a}, forwarded to the platform's {ev} view", a, ",".join(p_dig(u)) or "no answer")
                ca_ = self.need(x, "corp_admin", "an admin name")
                if ca_ is not None:
                    self.v.check(f"{ctx.get('admin_name')} is not published to staff: NXDOMAIN", "status: NXDOMAIN" in ca_, ca_.strip()[:80])
                lc = self.need(x, "corp_local", "a corporate name")
                local = next((r for r in (dns.get("resolvers") or {}).values() if x in (r.get("servers") or [])), {})
                first = (local.get("local") or [None])[0]
                want_a = bare((self.nodes.get(first) or {}).get("address")) if first else None
                if lc is not None and want_a:
                    self.v.chk(f"{ctx.get('corporate_fqdn')}, a corporate name, answered here: {want_a}", want_a, ",".join(p_dig(lc)) or "no answer")
            elif role == "inet-ntp":
                tr = self.need(x, "chrony_tracking", "chrony's own clock")
                if tr is not None:
                    st_ = (re.search(r"^Stratum\s*:\s*(\d+)", tr, re.M) or [None, ""])[1]
                    want_s = str(ntp.get("reference_stratum") or "")
                    self.v.chk("the reference serves its own clock at its stratum", want_s or "?", st_ or "none")
                if ntp.get("nts"):
                    ss = self.need(x, "chrony_serverstats", "chrony's server statistics")
                    if ss is not None:
                        m = re.search(r"^NTS-KE connections accepted\s*:\s*(\d+)", ss, re.M)
                        self.v.check("the reference accepted NTS key exchanges", bool(m) and int(m.group(1)) > 0,
                                     m.group(0) if m else "no NTS-KE line")

    def rendered_serial(self, server, view, zone):
        """The serial the render wrote into a view's forward zone on its primary."""
        if not server or not view or not zone:
            return None
        try:
            text = (self.render / "bootstrap" / server / "zones" / f"db.{view}.{zone}").read_text(encoding="utf-8")
        except OSError:
            return None
        m = re.search(r"^\s*(\d+) ; serial", text, re.M)
        return int(m.group(1)) if m else None

    def pinned(self, tool):
        """A tool's pinned version from the render's versions (gen/RENDER.json), or None."""
        try:
            rj = json.load(open(self.render / "gen" / "RENDER.json", encoding="utf-8"))
        except (OSError, ValueError):
            return None
        vs = rj.get("versions") or {}
        for block in (vs.get("kubernetes") or {}, vs.get("tools") or {}):
            v = block.get(tool)
            if isinstance(v, dict) and v.get("version"):
                return str(v["version"])
        return None

    def g_routers(self, names):
        mgmt_gw = (self.inv.get("mgmt") or {}).get("gw")
        for r in self.present(names or self.of_kind("frr")):
            n = self.nodes[r]
            self.v.sec(f"{r}: router")
            want = str(n.get("image") or "").rsplit(":", 1)[-1].split("-")[0]
            ver = self.need(r, "frr_version", f"FRR {want} running")
            if ver is not None:
                # the version field alone: the rest of FRR's line names the lab host's kernel release
                vm = re.search(r"FRRouting \S+", ver)
                self.v.check(f"FRR {want} running", f"FRRouting {want}" in ver, vm.group(0) if vm else "no FRRouting version line")
            lk = self.rs.json(r, "link_eth0")
            if not isinstance(lk, list) or not lk:
                self.v.bad("eth0 in VRF mgmt", "link_eth0 not collected")
            else:
                self.v.chk("eth0 in VRF mgmt", "mgmt", lk[0].get("master") or "no master")
            main = self.need(r, "table_main", "no management default in the main table")
            if main is not None:
                bad_ = [l for l in main.splitlines() if l.startswith("default") or (mgmt_gw and f"via {mgmt_gw}" in l)]
                self.v.check("no management default in the main table", not bad_, bad_[0] if bad_ else "")
            self.route_check(r, "table_vrf_mgmt", f"management default in VRF mgmt via {mgmt_gw}", f"default via {mgmt_gw}")
            routes = self.rs.json(r, "frr_routes")
            for eth, i in sorted((n.get("ifaces") or {}).items(), key=lambda kv: natural(kv[0])):
                if eth not in (n.get("nics") or {}) or not i.get("address"):
                    continue
                self.addr_check(r, eth, i["address"])
                pfx = str(ipaddress.ip_interface(i["address"]).network)
                if not isinstance(routes, dict):
                    self.v.bad(f"connected route {pfx} on {eth}", "frr_routes not collected or not JSON")
                else:
                    have = [x for x in routes.get(pfx) or [] if x.get("protocol") == "connected"]
                    self.v.check(f"connected route {pfx} on {eth}", bool(have), "absent from show ip route")
            fwd = self.need(r, "ip_forward", "IP forwarding on")
            if fwd is not None:
                self.v.check("IP forwarding on", bool(re.search(r"ip_forward\s*=\s*1\b", fwd)), fwd.strip()[:60])
            self.tx_container(r)
            rc = self.need(r, "resolv_conf", "resolv.conf")
            if rc is not None:
                self.resolv_search(rc, r)
            for row in p2p_rows(self.inv, r):
                if row.get("p2p_appliance_addr"):
                    self.arp(r, slugify(f"arp_{row['p2p']}"), f"{row['p2p']} answers ARP on {row['p2p_addr']} ({row['p2p_iface']})")
                else:
                    self.ping(r, slugify(f"ping_{row['p2p']}"), f"{row['p2p']} answers ping on {row['p2p_addr']}")

    def g_registry(self, names):
        reg = self.inv.get("registry") or {}
        mgmt_gw = (self.inv.get("mgmt") or {}).get("gw")
        tables = dig(self.inv, "guest.tables") or {}
        fw = (self.inv.get("stages") or {}).get("fw")
        public = (self.nodes.get(fw) or {}).get("public") if fw else None
        for g in self.present(names or self.of_kind("registry")):
            n = self.nodes[g]
            self.v.sec(f"{g}: registry")
            for eth, i in sorted((n.get("ifaces") or {}).items()):
                if eth in (n.get("nics") or {}) and i.get("address"):
                    self.addr_check(g, eth, i["address"])
            if n.get("gateway"):
                self.route_check(g, "table_main", f"default via {n['gateway']} in the main table", f"default via {n['gateway']}")
            self.route_check(g, "table_mgmt", f"management default in table {tables.get('mgmt')} via {mgmt_gw}", f"default via {mgmt_gw}")
            self.tx_container(g)
            rc = self.need(g, "resolv_conf", "resolv.conf")
            if rc is not None:
                self.resolv_search(rc, g)
            cat = self.rs.json(g, "catalog")
            ups = list(reg.get("upstreams") or [])
            charts = reg.get("charts") or "charts"
            if not isinstance(cat, dict):
                self.v.bad("the catalog lists the mirrored images and the charts", "catalog not collected or not JSON")
            else:
                repos = list(cat.get("repositories") or [])
                empty = [u for u in ups if not any(x.startswith(u + "/") for x in repos)]
                self.v.check(f"the catalog holds images mirrored from each upstream ({', '.join(ups)}; {len(repos)} repositories)",
                             bool(ups) and not empty, "none from " + ",".join(empty))
                nch = len([x for x in repos if x.startswith(charts + "/")])
                self.v.check(f"the catalog holds the charts ({nch} under {charts}/)", nch > 0, "no chart")
            if public:
                al = self.need(g, "access_log", "the registry's access log")
                if al is not None:
                    hits = [l for l in al.splitlines() if public in l and "/v2/" in l]
                    self.v.check(f"its access log shows pulls from {public}, the firewall's public address (a node's pull crossed the source NAT)",
                                 bool(hits), "no request from it in the log")

    def g_clients(self, names):
        mgmt_gw = (self.inv.get("mgmt") or {}).get("gw")
        tables = dig(self.inv, "guest.tables") or {}
        for c in self.present(names or self.of_kind("client")):
            n = self.nodes[c]
            self.v.sec(f"{c}: client")
            for eth, i in sorted((n.get("ifaces") or {}).items()):
                if eth in (n.get("nics") or {}) and i.get("address"):
                    self.addr_check(c, eth, i["address"])
            if n.get("gateway"):
                self.route_check(c, "table_main", f"default via {n['gateway']} in the main table", f"default via {n['gateway']}")
            self.route_check(c, "table_mgmt", f"management default in table {tables.get('mgmt')} via {mgmt_gw}", f"default via {mgmt_gw}")
            self.tx_container(c)
            if n.get("gateway"):
                self.ping(c, "ping_gw", f"{n['gateway']} answers ping")
            cb = self.need(c, "ca_bundle", "the lab root CA is in the system bundle")
            if cb is not None:
                self.v.check("the lab root CA is in the system bundle", "root in bundle" in cb, cb.strip()[:80])
            env = self.render_env(c)
            servers = env.get("DNS_SERVERS", "").replace(",", " ").split()
            rc = self.need(c, "resolv_conf", "resolv.conf")
            if rc is not None:
                if servers:
                    have = [l.split()[1] for l in rc.splitlines() if l.startswith("nameserver ") and len(l.split()) > 1]
                    self.v.chk(f"resolv.conf names {', '.join(servers)}", ",".join(servers), ",".join(have) or "none")
                    opts = env.get("RESOLV_OPTIONS", "").split()
                    if opts:
                        got = " ".join(w for l in rc.splitlines() if l.startswith("options ") for w in l.split()[1:])
                        miss = [o for o in opts if o not in got.split()]
                        self.v.check(f"resolv.conf options {' '.join(opts)}", not miss, f"options '{got}'")
                self.resolv_search(rc, c)

    def node_domain(self, node: str | None) -> str:
        """The domain a node lives in (render/host.py domain_of): the corporate domain for a corporate
        resolver's local hosts, the platform's zone for every other."""
        org = self.inv.get("org") or {}
        local = {h for r in ((self.inv.get("dns") or {}).get("resolvers") or {}).values() for h in (r.get("local") or [])}
        if node in local:
            return str(org.get("domain") or "").lower()
        return str(org.get("zone") or org.get("domain") or "").lower()

    def resolv_search(self, rc: str, node: str | None = None) -> None:
        """A recorded resolv.conf searches the node's own domain and nothing else. Docker writes a
        container's file from the lab host's own, search line included, until the image's init
        script replaces that line (render/host.py dns_env). Any other domain is counted, never
        printed, so the verdict cannot carry a name from the lab host."""
        dom = self.node_domain(node)
        words = [w for l in rc.splitlines() if l.split()[:1] in (["search"], ["domain"]) for w in l.split()[1:]]
        other = [w for w in words if w.rstrip(".").lower() != dom]
        if not dom:
            detail = "the inventory names no lab domain"
        elif not words:
            detail = "no search line"
        else:
            detail = f"{len(other)} other domain{'' if len(other) == 1 else 's'} in the search list (not printed)" if other else ""
        self.v.check(f"resolv.conf searches the lab's domain only ({dom or 'none'})", bool(dom and words) and not other, detail)

    def g_storage(self, names):
        st = self.inv.get("stages") or {}
        for s in self.present(names or list(st.get("storage") or [])):
            self.v.sec(f"{s}: storage")
            h = self.need(s, "container_health", "the container running and healthy")
            if h is not None:
                self.v.check("the container running and healthy", bool(re.search(r"^running healthy\b", h.strip(), re.M)), h.strip()[:80])
            lg = self.need(s, "launcher_login", "the launcher's login")
            if lg is not None:
                self.v.check("the launcher was given a username and a password (presence and a keyed mark only, never a value)",
                             "username: present" in lg and "password: present" in lg, " ".join(lg.split())[:120])

    # the cluster, from what the harness's kubectl printed on the init node -----------------------

    def k8s_names(self) -> dict:
        """gen/k8s.json (render/k8s.py): the cluster's own names, or {} before it is rendered."""
        try:
            return json.load(open(self.render / "gen" / "k8s.json", encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def kj(self, slug, label):
        b = (self.inv.get("stages") or {}).get("kubectl")
        data = self.rs.json(b, slug) if b else None
        if not isinstance(data, dict):
            self.v.bad(label, f"{slug} not collected" if data is None else f"{slug} is not kubectl JSON")
            return None
        return data

    def g_cluster(self, names):
        k8s = self.inv.get("k8s") or {}
        st = self.inv.get("stages") or {}
        b = st.get("kubectl")
        self.v.sec("cluster")
        if not k8s or not b:
            self.v.bad("the cluster", "k8s is off or the lab has no init node for the harness's kubectl")
            return
        if not self.rs.has(b):
            self.v.bad("the cluster", f"{b} was not collected")
            return
        kv = self.rs.json(b, "kube_version")
        label = f"the harness's kubectl reaches the API from {b} with the admin kubeconfig kubeadm wrote there: server {k8s.get('version')}"
        if not isinstance(kv, dict):
            self.v.bad(label, "kube_version not collected or not JSON")
        else:
            self.v.chk(label, k8s.get("version"), (kv.get("serverVersion") or {}).get("gitVersion") or "no server")
        ks = self.need(b, "kube_server", "kubectl's API endpoint")
        if ks is not None:
            srv = ks.strip()
            self.v.check(f"kubectl's API endpoint is the VIP ({k8s.get('api_fqdn')} or {k8s.get('api_vip')}, port 6443)",
                         bool(re.match(rf"^https://({re.escape(str(k8s.get('api_fqdn')))}|{re.escape(str(k8s.get('api_vip')))}):6443/?$", srv)),
                         srv or "empty")
        hv = self.need(b, "helm_version", "helm")
        if hv is not None:
            want = self.pinned("node_helm") or self.pinned("helm")
            mv = re.search(r"v\d+\.\d+\.\d+", hv)
            got = mv.group(0) if mv else None
            if want:
                self.v.chk(f"helm on {b} is the pinned {want}", want, got or hv.strip()[:60])
            else:
                self.v.bad("helm is the pinned version", f"spec/versions.yaml pins no helm version (helm answers {got})")
        control, workers = list(k8s.get("control") or []), list(k8s.get("workers") or [])
        labels = k8s.get("labels") or {}
        nodes = self.kj("nodes", "the nodes")
        if nodes is not None:
            items = {i["metadata"]["name"]: i for i in nodes.get("items") or []}
            for n in control + workers:
                i = items.get(n)
                if i is None:
                    self.v.bad(f"{n} Ready", "not in kubectl get nodes")
                    continue
                stt = i.get("status") or {}
                probs = []
                if not cond_true(stt, "Ready"):
                    probs.append("not Ready")
                kv = (stt.get("nodeInfo") or {}).get("kubeletVersion")
                if kv != k8s.get("version"):
                    probs.append(f"kubelet {kv}")
                ip = next((a.get("address") for a in stt.get("addresses") or [] if a.get("type") == "InternalIP"), None)
                want_ip = bare((self.nodes.get(n) or {}).get("address"))
                if ip != want_ip:
                    probs.append(f"InternalIP {ip}")
                key = labels.get("control") if n in control else labels.get("gpu") if (self.nodes.get(n) or {}).get("group") == "gpu" else None
                if key and key not in ((i.get("metadata") or {}).get("labels") or {}):
                    probs.append(f"no label {key}")
                self.v.check(f"{n} Ready, kubelet {k8s.get('version')}, InternalIP {want_ip}" + (f", label {key}" if key else ""),
                             not probs, "; ".join(probs))
            extra = sorted(set(items) - set(control + workers))
            self.v.check(f"the cluster has the spec's {len(control + workers)} nodes and no other", not extra, "extra: " + ",".join(extra))
        pods = self.kj("pods", "the pods")
        ks = [p for p in (pods or {}).get("items") or [] if (p.get("metadata") or {}).get("namespace") == "kube-system"]
        if pods is not None:
            badp = [p["metadata"]["name"] for p in ks if not pod_ready(p)]
            self.v.check(f"every pod in kube-system Running and Ready ({len(ks)} pods)", bool(ks) and not badp, ", ".join(badp[:5]))
        ds = self.kj("daemonsets", "the DaemonSets")
        if ds is not None:
            dsk = {(d["metadata"]["namespace"], d["metadata"]["name"]): d for d in ds.get("items") or []}
            self.v.check("no kube-proxy DaemonSet (Cilium replaces kube-proxy)", ("kube-system", "kube-proxy") not in dsk, "kube-system/kube-proxy exists")
            cil = dsk.get(("kube-system", "cilium"))
            want_n = len(control + workers)
            if cil is None:
                self.v.bad("Cilium: one ready agent per node", "no kube-system/cilium DaemonSet")
            else:
                s_ = cil.get("status") or {}
                self.v.check(f"Cilium: one ready agent per node ({s_.get('numberReady')} of {want_n})",
                             s_.get("desiredNumberScheduled") == want_n and s_.get("numberReady") == want_n,
                             f"desired {s_.get('desiredNumberScheduled')}, ready {s_.get('numberReady')}")
        cm = self.kj("cilium_config", "cilium-config")
        if cm is not None:
            data = cm.get("data") or {}
            self.v.check("Cilium kube-proxy-replacement on", str(data.get("kube-proxy-replacement", "")).lower() in ("true", "strict"),
                         f"kube-proxy-replacement {data.get('kube-proxy-replacement')}")
            want = sorted(set(k8s.get("cilium_devices") or []))
            if want:
                have = sorted({d for d in re.split(r"[ ,]+", data.get("devices") or "") if d})
                self.v.chk(f"Cilium devices are the spec's ({','.join(want)})", ",".join(want), ",".join(have) or "none")
            for key, label in (("enable-l2-announcements", "Cilium L2 announcements enabled"),
                               ("enable-gateway-api", "Cilium Gateway API support enabled")):
                self.v.chk(label, "true", str(data.get(key, "unset")).lower())
            md = cm.get("metadata") or {}
            times = [m.get("time") for m in md.get("managedFields") or [] if m.get("time")]
            changed = max(times) if times else md.get("creationTimestamp") or ""
            agents = [p for p in (pods or {}).get("items") or [] if ((p.get("metadata") or {}).get("labels") or {}).get("k8s-app") == "cilium"]
            old = [p["metadata"]["name"] for p in agents if ((p.get("status") or {}).get("startTime") or "") < changed]
            self.v.check(f"every Cilium agent started after cilium-config last changed ({len(agents)} agents)", bool(agents) and not old,
                         ", ".join(old) or "no agent")
        leases = self.kj("leases", "the leases")
        litems = (leases or {}).get("items") or []
        if leases is not None:
            want = ((self.k8s_names().get("api") or {}).get("kube_vip_lease") or "kube-system/plndr-cp-lock").split("/", 1)
            kv = [l for l in litems if [l["metadata"].get("namespace"), l["metadata"]["name"]] == want]
            holder = ((kv[0].get("spec") or {}).get("holderIdentity") if kv else None)
            self.v.check(f"the API VIP {k8s.get('api_vip')}: the kube-vip lease held by a control node ({holder})",
                         holder in control, "no kube-vip lease" if not kv else f"held by {holder}")
        ac = self.need(b, "api_cert", "the API server's certificate")
        icn = ((self.inv.get("ca") or {}).get("intermediates") or {}).get("kubernetes", {}).get("cn")
        if ac is not None and icn:
            x = p_x509(ac)
            ok_ = x.get("issuer_cn") == icn and "Verify return code: 0" in ac
            self.v.check(f"the API server's certificate is issued by {icn} and verifies against the lab root", ok_,
                         f"issuer {x.get('issuer') or 'absent'}; " + (re.search(r"Verify return code: [^\n]*", ac) or ["no verify line"])[0])
        self.g_cluster_certs(b)
        self.g_cluster_gateways(b, control, litems if leases is not None else None)
        self.g_cluster_storage(b)
        ev = self.kj("events_warning", "the Warning events")
        if ev is not None:
            items = ev.get("items") or []
            self.v.check("no Warning event since finish archived them", not items,
                         "; ".join(f"{(e.get('involvedObject') or {}).get('name')}: {e.get('reason')}" for e in items[:3]))

    def g_cluster_certs(self, b):
        ca = self.inv.get("ca") or {}
        dep = self.kj("deployments", "the Deployments")
        if dep is not None:
            cmd = [d for d in dep.get("items") or [] if d["metadata"]["namespace"] == "cert-manager"]
            down = [d["metadata"]["name"] for d in cmd if not deploy_ready(d)]
            self.v.check(f"cert-manager ready ({len(cmd)} Deployments available)", bool(cmd) and not down, ", ".join(down) or "none found")
        iss = (ca.get("issuer") or {}).get("name")
        if iss:
            ci = self.kj("clusterissuers", "the ClusterIssuers")
            if ci is not None:
                it = next((i for i in ci.get("items") or [] if i["metadata"]["name"] == iss), None)
                self.v.check(f"ClusterIssuer {iss} Ready", bool(it) and cond_true(it.get("status") or {}, "Ready"),
                             "absent" if not it else "not Ready")
        wc = next((c for c in ca.get("certificates") or [] if c.get("id") == "wildcard"), None) \
            or next((c for c in ca.get("certificates") or []), None)
        pcn = (ca.get("intermediates") or {}).get((ca.get("issuer") or {}).get("intermediate") or "platform", {}).get("cn")
        # the certificate's name: "wildcard" in its dns list is the zone's wildcard name, which is a
        # certificate name only (the zone publishes no wildcard record)
        org = self.inv.get("org") or {}
        zone = org.get("zone") or org.get("domain")
        wildcard = next((f"*.{zone}" if d == "wildcard" else d for d in (wc or {}).get("dns") or []), None) \
            or (self.inv.get("dns") or {}).get("wildcard")
        if wc:
            crt = self.kj("certificates", "the Certificates")
            if crt is not None:
                for c in ca.get("certificates") or []:
                    it = next((i for i in crt.get("items") or [] if (i.get("spec") or {}).get("secretName") == c["secret"]), None)
                    self.v.check(f"the Certificate for {c['secret']} Ready", bool(it) and cond_true(it.get("status") or {}, "Ready"),
                                 "absent" if not it else "not Ready")
            t = self.need(b, "wildcard_cert", f"the wildcard certificate in {wc['secret']}")
            if t is not None and pcn:
                x = p_x509(t)
                self.v.check(f"the wildcard certificate in {wc['secret']} ({wildcard}) is issued by {pcn}",
                             x.get("issuer_cn") == pcn and (not wildcard or f"DNS:{wildcard}" in t),
                             f"issuer {x.get('issuer') or 'absent'}, SAN {x.get('san') or 'absent'}")

    def g_cluster_gateways(self, b, control, leases):
        k8s = self.inv.get("k8s") or {}
        gws = self.inv.get("gateways") or {}
        ns = k8s.get("gateway_namespace")
        if not gws:
            return
        gw = self.kj("gateways", "the Gateways")
        if gw is not None:
            items = {(i["metadata"]["namespace"], i["metadata"]["name"]): i for i in gw.get("items") or []}
            for name, g in sorted(gws.items()):
                it = items.get((ns, name)) if ns else next((v for (n_, nm), v in items.items() if nm == name), None)
                stt = (it or {}).get("status") or {}
                addrs = [a.get("value") for a in stt.get("addresses") or []]
                self.v.check(f"Gateway {name} Programmed with address {g['vip']}", bool(it) and cond_true(stt, "Programmed") and g["vip"] in addrs,
                             "absent" if not it else f"addresses {','.join(map(str, addrs)) or 'none'}, Programmed {cond_true(stt, 'Programmed')}")
        pools = self.kj("lb_pools", "the load-balancer pools")
        if pools is not None:
            blocks = [blk for p in pools.get("items") or [] for blk in (p.get("spec") or {}).get("blocks") or []]
            for name, g in sorted(gws.items()):
                start, end = g["pool"]
                cover = any((blk.get("start") == start and blk.get("stop") == end) or (blk.get("cidr") and blk_covers(blk["cidr"], start, end))
                            for blk in blocks)
                self.v.check(f"a load-balancer pool covers {name}'s range {start} to {end}", cover, f"{len(blocks)} blocks, none covers it")
        la = k8s.get("l2_announce") or {}
        # the nodes the announcement policy selects: the role its spec names (control, ingress)
        role = str(la.get("nodes") or "control")
        announcers = list(control) if role == "control" else [n for n in (list(k8s.get("control") or []) + list(k8s.get("workers") or []))
                                                              if (self.nodes.get(n) or {}).get("group") == role]
        rword = "control" if role == "control" else role
        if la:
            pol = self.kj("l2_policies", "the L2 announcement policies")
            if pol is not None:
                key = (k8s.get("labels") or {}).get(role)
                good = [p for p in pol.get("items") or [] if list((p.get("spec") or {}).get("interfaces") or []) == list(la.get("interfaces") or [])
                        and key and key in json.dumps((p.get("spec") or {}).get("nodeSelector") or {})]
                self.v.check(f"an L2 announcement policy on {','.join(la.get('interfaces') or [])} from the {rword} nodes ({key})", bool(good),
                             f"{len(pol.get('items') or [])} policies, none matches")
        if leases is not None:
            names = (self.k8s_names().get("gateways") or {})
            for name in sorted(gws):
                want = ((names.get(name) or {}).get("l2_lease") or f"kube-system/cilium-l2announce-{ns}-cilium-gateway-{name}").split("/", 1)
                hl = [l for l in leases if [l["metadata"].get("namespace"), l["metadata"]["name"]] == want]
                holder = (hl[0].get("spec") or {}).get("holderIdentity") if hl else None
                self.v.check(f"{name}'s Service announced: its lease held by an {rword} node ({holder})" if rword[0] in "aeiou"
                             else f"{name}'s Service announced: its lease held by a {rword} node ({holder})", holder in announcers,
                             "no cilium-l2announce lease for it" if not hl else f"held by {holder}")
        tb = k8s.get("test_backend") or {}
        if tb:
            dep = self.kj("deployments", "the Deployments")
            if dep is not None:
                it = next((d for d in dep.get("items") or [] if d["metadata"]["namespace"] == tb.get("namespace") and d["metadata"]["name"] == tb.get("name")), None)
                r = (it or {}).get("status", {}).get("readyReplicas") if it else None
                self.v.check(f"the test backend {tb.get('namespace')}/{tb.get('name')}: {tb.get('replicas')} of {tb.get('replicas')} replicas ready",
                             bool(it) and r == tb.get("replicas"), "absent" if not it else f"{r} ready")
            hr = self.kj("httproutes", "the HTTPRoutes")
            if hr is not None:
                for name in tb.get("gateways") or []:
                    g = gws.get(name) or {}
                    want = sorted(g.get("hostnames") or [])
                    cands = [r for r in hr.get("items") or [] if any(pr.get("name") == name for pr in (r.get("spec") or {}).get("parentRefs") or [])]
                    good = []
                    for r in cands:
                        sp, ss = r.get("spec") or {}, r.get("status") or {}
                        parents = [p for p in ss.get("parents") or [] if (p.get("parentRef") or {}).get("name") == name]
                        acc = any(cond_true(p, "Accepted") and cond_true(p, "ResolvedRefs") for p in parents)
                        backs = {br.get("name") for rule in sp.get("rules") or [] for br in rule.get("backendRefs") or []}
                        if acc and sorted(sp.get("hostnames") or []) == want and tb.get("name") in backs:
                            good.append(r["metadata"]["name"])
                    self.v.check(f"an HTTPRoute on {name} Accepted with its references resolved, listing {', '.join(want)}, to {tb.get('name')}",
                                 bool(good), f"{len(cands)} routes on it, none Accepted with those hostnames")

    def g_cluster_storage(self, b):
        st = self.inv.get("stages") or {}
        if not st.get("storage_setup"):
            return
        for s in st.get("storage") or []:
            try:
                setup = json.load(open(self.render / "bootstrap" / s / "setup.json", encoding="utf-8"))
            except (OSError, ValueError):
                continue
            csi = setup.get("csi") or {}
            classes = csi.get("classes") or []
            if not classes:
                continue
            ns = (csi.get("kubernetes") or {}).get("namespace") or "democratic-csi"
            sc = self.kj("storageclasses", "the StorageClasses")
            if sc is not None:
                items = {i["metadata"]["name"]: i for i in sc.get("items") or []}
                for c in classes:
                    it = items.get(c["storage_class"])
                    default = c["name"] == csi.get("default_class")
                    is_def = ((it or {}).get("metadata", {}).get("annotations") or {}).get("storageclass.kubernetes.io/is-default-class") == "true"
                    self.v.check(f"StorageClass {c['storage_class']} present" + (", the cluster's default" if default else ""),
                                 bool(it) and is_def == default, "absent" if not it else f"default {is_def}")
            pods = self.kj("pods", "the pods")
            if pods is not None:
                pp = [p for p in pods.get("items") or [] if p["metadata"]["namespace"] == ns]
                down = [p["metadata"]["name"] for p in pp if not pod_ready(p)]
                miss = [f"{c['release']} {k}" for c in classes for k in ("controller", "node")
                        if not any(p["metadata"]["name"].startswith(c["release"]) and f"-{k}" in p["metadata"]["name"] for p in pp)]
                self.v.check(f"democratic-csi: a controller and a node pod per class, every pod in {ns} Running and Ready ({len(pp)} pods)",
                             bool(pp) and not down and not miss, "; ".join(down[:3] + miss[:3]))

    # the populations ------------------------------------------------------------------------------

    def g_populations(self, names):
        dns = self.inv.get("dns") or {}
        gws = self.inv.get("gateways") or {}
        for pname, pop in sorted((self.inv.get("populations") or {}).items()):
            ps = [p for p in probers(self.inv, pop) if not names or p in names]
            # a population with no audience probes no Gateway (population_ctx plans nothing for it)
            if not ps or not pop.get("gateway"):
                continue
            self.v.sec(f"population {pname}")
            gw = gws.get(pop.get("gateway") or "") or {}
            for p in self.present(ps):
                ctx = population_ctx(self.inv, p)
                users, admin, infra = ctx.get("users_fqdn"), ctx.get("admin_fqdn"), ctx.get("infra_fqdn")
                answer = ctx.get("pop_answer")
                res = ctx.get("pop_resolver")
                view, vs = self.view_of(p)
                held = ctx.get("pop_admin_held", True)
                uheld = ctx.get("pop_users_held", True)
                if res:
                    d = self.need(p, "pop_dns_users", f"{p}: {res} answers {users}")
                    if d is not None and uheld:
                        self.v.chk(f"{p}: the resolver {res} answers {users} with {answer} (the {view} view)", answer, ",".join(p_dig(d)) or "no answer")
                    elif d is not None:
                        self.v.check(f"{p}: {users} has no answer: the {view} view publishes no platform name, so the population names {answer}",
                                     not p_dig(d), ",".join(p_dig(d)))
                    d = self.need(p, "pop_dns_admin", f"{p}: {res} answers {admin}")
                    if d is not None:
                        if held:
                            self.v.chk(f"{p}: the resolver {res} answers {admin} with {answer}", answer, ",".join(p_dig(d)) or "no answer")
                        else:
                            self.v.check(f"{p}: {admin} has no answer: the {view} view publishes no admin name to this population",
                                         not p_dig(d), ",".join(p_dig(d)))
                    rec = (dns.get("records") or {}).get(infra)
                    d = self.need(p, "pop_dns_infra", f"{p}: {res} answers {infra}")
                    if d is not None and rec:
                        got = p_dig(d)
                        if vs.get("infra"):
                            self.v.chk(f"{p}: {infra} is {rec}: the {view} view holds the infrastructure records", rec, ",".join(got) or "no answer")
                        elif dns.get("wildcard"):
                            self.v.check(f"{p}: {infra} answers {answer} (the wildcard), never {rec}: the {view} view holds no infrastructure record",
                                         got == [answer], ",".join(got) or "no answer")
                        else:
                            self.v.check(f"{p}: {infra} has no answer, never {rec}: the {view} view holds no infrastructure record",
                                         not got, ",".join(got))
                pinned = "" if res else f" (name pinned to {answer}: the population's resolver is not in this lab)"
                if res and not uheld:
                    pinned = f" (pinned to {answer}: the {view} view publishes no platform name)"
                pinned_admin = pinned if (not res or held or not uheld) else f" (pinned to {answer}: the {view} view publishes no admin name)"
                path = ctx.get("echo_path") or ""
                for slug, name in (("pop_https_users", users), ("pop_https_admin", admin)):
                    t = self.need(p, slug, f"{p}: https://{name}{path}")
                    if t is None:
                        continue
                    code, headers, body = p_curl_i(t)
                    if name in (gw.get("hostnames") or []):
                        self.v.check(f"{p}: https://{name}{path}: 200, the message echoed, the chain verified against the lab root{pinned}",
                                     code == 200 and ctx["echo_msg"] in body, f"HTTP {code}" if code else (t.strip().splitlines() or ["no answer"])[-1][:100])
                    else:
                        srv = headers.get("server", "")
                        self.v.check(f"{p}: https://{name}{path}: 404 from {pop.get('gateway')} (the Gateway has no route for the name)"
                                     f"{pinned_admin if name == admin else pinned}",
                                     code == 404 and "envoy" in srv.lower(),
                                     f"HTTP {code}, server {srv or 'none'}" if code else (t.strip().splitlines() or ["no answer"])[-1][:100])


# --------------------------------------------------------------------------------------------
# chapter 4: the firewall edge


def _fw_edge(self, names):
    fws = names or [x for x in [((self.inv.get("stages") or {}).get("fw"))] if x]
    d = self.rs.path / "fw-edge"
    try:
        plan_ = json.loads(evfile.read_text(d / "plan.json", "strict"))
    except (OSError, ValueError):
        plan_ = {}
    rd = lambda name: PP.read(d / name)  # noqa: E731
    for fw in self.present(fws):
        n = self.nodes[fw]
        ifaces = n.get("interfaces") or {}

        # zone bindings: every layer 3 interface wired here, in its zone with its address
        self.v.sec(f"{fw}: zone bindings (chapter 4)")
        text = self.need(fw, "interface_all", "show interface all")
        _, logical = p_panos_interfaces(text or "")
        for name, i in sorted(ifaces.items(), key=lambda kv: natural(kv[0])):
            if i.get("kind") not in ("layer3", "subinterface") or not i.get("connected") or not i.get("zone"):
                continue
            row = logical.get(name) or {}
            self.v.check(f"{name} in zone {i['zone']} with {i.get('address')}",
                         row.get("zone") == i["zone"] and row.get("address") == i.get("address"),
                         f"zone {row.get('zone') or 'none'}, address {row.get('address') or 'none'}" if row else "not in the logical interfaces")

        # rule order: the running rulebase in the render's order
        self.v.sec(f"{fw}: rule order (chapter 4)")
        for slug, key, what in (("running_security", "rules", "security"), ("running_nat", "nat", "NAT")):
            want = list(n.get(key) or [])
            t = self.need(fw, slug, f"the {what} rules in the render's order")
            if t is None:
                continue
            # the predefined defaults are listed by name, or as <vsys>+<name> once overridden (build A
            # overrides both to deny with log)
            got = [x for x in PP.policy(t) if x.split("+", 1)[-1] not in ("intrazone-default", "interzone-default")]
            self.v.check(f"the {len(want)} {what} rules run in the render's order: {', '.join(want)}", got == want,
                         "running: " + (", ".join(got) or "none"))
            if key == "rules" and "deny-all-log" in want:
                self.v.check("deny-all-log is the last rule before the predefined defaults", bool(got) and got[-1] == "deny-all-log",
                             f"last: {got[-1] if got else 'none'}")
            if key == "nat" and "no-nat-public" in want and "internet-snat" in want:
                ok = "no-nat-public" in got and "internet-snat" in got and got.index("no-nat-public") < got.index("internet-snat")
                self.v.check("no-nat-public sits above internet-snat", ok,
                             "running: " + (", ".join(got) or "none"))

        # the LAND counter
        name = plan_.get("counter")
        self.v.sec(f"{fw}: the LAND counter (chapter 4)")
        if not name:
            self.v.skip("the LAND counter", "the lab's drills plan names no counter")
        else:
            b = PP.counters(rd("counters-before.txt"), rd("counters-before.xml"))
            a = PP.counters(rd("counters-after.txt"), rd("counters-after.xml"))
            seen = name in b or name in a
            self.v.check(f"{name} is in this firewall's own show counter global table", seen,
                         f"{len(b)} counters read, {name} not among them" if b else "no counter table saved")
            if seen:
                v0 = (b.get(name) or a.get(name) or {}).get("value")
                if v0 == 0:
                    self.v.ok(f"{name} reads 0")
                else:
                    self.v.skip(f"{name} reads 0", f"it reads {v0}: it counts since the counters were last cleared, "
                                                   "and the land drill and break-4a raise it on purpose; judged by its rise below")
                pg = PP.ping(rd("node-public-ping.txt"))
                who = f"{plan_.get('node')} ({plan_.get('node_addr')})"
                self.v.check(f"{who} reaches the public address {plan_.get('public')}: {pg['received']} of {pg['sent']} requests answered",
                             bool(pg["sent"]) and pg["received"] == pg["sent"], "no ping statistics" if pg["sent"] is None else "")
                dl = PP.delta(b, a, name).get(name)
                self.v.check(f"{name} did not rise while {who} sent them (no-nat-public keeps the source)", dl == 0,
                             f"rose by {dl}" if dl is not None else "not read twice")

        # an egress the allowlist does not name
        eg = plan_.get("egress") or {}
        if eg and plan_.get("node"):
            self.v.sec(f"{fw}: an egress the allowlist does not name (chapter 4)")
            who = f"{plan_.get('node')} ({plan_.get('node_addr')})"
            out = rd("egress-connect.txt").strip()
            self.v.check(f"{who} to {eg['client']}, an internet host, on {eg['addr']}:{eg['port']}: refused ({out or 'no result'})",
                         out.startswith("failed: timed out"),
                         "it connected" if out == "connected" else ("refused by the far host, so the firewall let it out"
                                                                    if out.startswith("failed") else ""))
            es = PP.tlog_find(rd(f"egress-tlog-{eg['port']}.txt"), src=plan_.get("node_addr"), dst=eg["addr"], dport=str(eg["port"]))
            e = es[0] if es else None
            self.v.check(f"... logged under {eg['rule']}, deny, zone {eg.get('from_zone') or '?'} to {eg.get('to_zone') or '?'} "
                         "(no rule admits the inside to an internet host but the registry and the time source)",
                         bool(e) and e["rule"] == eg["rule"][:19] and e["action"] in ("deny", "drop", "reset-both", "reset-client", "reset-server")
                         and (not eg.get("from_zone") or e["from"] == eg["from_zone"]) and (not eg.get("to_zone") or e["to"] == eg["to_zone"]),
                         f"rule {e['rule']}, {e['action']}, zone {e['from']} to {e['to']}" if e else "no entry for it in the log read")

        # administrative access
        adm = n.get("admin") or {}
        self.v.sec(f"{fw}: administrative access from the jump host (chapter 4)")
        cs = self.need(fw, "config_set", "the running configuration")
        if not adm:
            self.v.skip("administrative access", "the render names no administrative profile")
        elif cs is not None:
            have = {_norm(l) for l in cs.splitlines()}
            prof = adm["profile"]
            want = [f"set network profiles interface-management-profile {prof} {s} yes" for s in adm.get("allow") or []]
            want += [f"set network profiles interface-management-profile {prof} permitted-ip {c}" for c in adm.get("permitted") or []]
            miss = [w for w in want if _norm(w) not in have]
            self.v.check(f"profile {prof}: {', '.join(adm.get('allow') or [])}, permitted only from {', '.join(adm.get('permitted') or ['anywhere'])}",
                         not miss, "missing: " + "; ".join(miss[:2]))
            l3 = [k for k, i in sorted(ifaces.items(), key=lambda kv: natural(kv[0]))
                  if i.get("kind") in ("layer3", "subinterface") and i.get("connected")]
            wrong = []
            for k in l3:
                p = prof if k == adm["interface"] else "ping-only"
                pre = (f"set network interface ethernet {k} layer3" if "." not in k else
                       f"set network interface aggregate-ethernet {k.split('.')[0]} layer3 units {k}")
                if _norm(f"{pre} interface-management-profile {p}") not in have:
                    wrong.append(f"{k} not {p}")
            self.v.check(f"{adm['interface']} takes {prof}; the other {len(l3) - 1} interfaces answer ping only", not wrong, "; ".join(wrong))
        if adm and plan_.get("admin_addr"):
            ad, ba = plan_["admin_addr"], plan_.get("bastion_addr")
            code = (rd("bastion-admin-https.txt").split() or ["none"])[0]
            self.v.check(f"the bastion from its own address {ba} reaches HTTPS on {ad} (HTTP {code})",
                         bool(re.match(r"^[1-5]\d\d$", code)), "no answer")
            banner = rd("bastion-admin-ssh.txt")
            self.v.check(f"the bastion from {ba} reaches SSH on {ad}", "SSH-2.0" in banner,
                         (banner.strip().splitlines() or ["no banner"])[-1][:80])
            if plan_.get("node"):
                code2 = (rd("other-admin-https.txt").split() or ["none"])[0]
                self.v.check(f"HTTPS on {ad} does not answer another inside host, {plan_['node']} ({plan_.get('node_addr')}) (HTTP {code2})",
                             code2 == "000", "it answered")
        if plan_.get("operator"):
            pub = plan_.get("public")
            banner = rd("operator-public-ssh.txt")
            self.v.check(f"{plan_['operator']}: SSH on the public address {pub} does not answer (nothing administrative is published)",
                         "SSH-2.0" not in banner, (banner.strip().splitlines() or [""])[0][:80])
            hdr = rd("operator-public-https.txt")
            srv = (re.search(r"(?im)^server:\s*(\S+)", hdr) or [None, ""])[1]
            if plan_.get("published"):
                self.v.check(f"{plan_['operator']}: HTTPS on {pub} is the internal Gateway's (server {srv or 'none'}), not the firewall's web interface",
                             srv.lower() == "envoy", "no server header")
            else:
                code = (re.search(r"(?m)^HTTP/\S+\s+(\d{3})", hdr) or [None, ""])[1]
                self.v.check(f"{plan_['operator']}: HTTPS on {pub} answers nothing: nothing is published on the uplink",
                             not srv and not code, f"HTTP {code}, server {srv or 'none'}")

        # service routes to the lab's resolvers
        sysd = n.get("system") or {}
        self.v.sec(f"{fw}: service routes to the lab's resolvers (chapter 4)")
        sr = sysd.get("service_routes") or {}
        if not sr:
            self.v.skip("service routes", "the render names none")
        if sr and cs is not None:
            have = {_norm(l) for l in cs.splitlines()}
            for svc, r in sorted(sr.items()):
                want = [f"set deviceconfig system route service {svc} source interface {r['interface']}",
                        f"set deviceconfig system route service {svc} source address {r['address']}"]
                srv = (sysd.get(svc) or ["?"])[0]
                self.v.check(f"{svc} to {srv} leaves from {r['interface']} ({r['address']})", all(_norm(w) in have for w in want),
                             "not in the running configuration")
        if sr.get("ntp"):
            # audit_fw_edge's last read of show ntp (it reads until synched), else the collected one
            nt = rd("ntp.txt") or self.need(fw, "ntp", "show ntp")
            if nt is not None:
                st = PP.ntp(nt)
                # name the server the firewall says it synched to, which may be either configured one
                cfg = list(sysd.get("ntp") or [])
                to = st.get("synched_to")
                self.v.check(f"show ntp: synched to {to or 'none'}, one of its NTP servers ({', '.join(cfg) or 'none configured'})",
                             bool(st["synched"] and to and to in cfg),
                             (nt.strip().splitlines() or ["no output"])[0][:80] if nt.strip() else "no output")
        src = (plan_.get("svc_src") or "")
        if sr and src:
            tl = rd("svc-tlog.txt")
            for svc, port in (("dns", "53"), ("ntp", "123")):
                if svc not in sr:
                    continue
                srv = (sysd.get(svc) or ["?"])[0]
                rule = plan_.get(f"{svc}_rule") or ""
                es = [e for e in PP.tlog_find(tl, src=src, dst=srv, dport=port) if e["action"] == "allow"]
                self.v.check(f"the traffic log has the firewall's own {svc} from {src} to {srv}:{port} allowed by {rule or 'a rule'}",
                             bool(es) and (not rule or es[0]["rule"] == rule[:19]),
                             f"rule {es[0]['rule']}" if es else "no allowed entry in the log read")
            if "dns" in sr:
                pd = rd("fw-dns.txt")
                want = (sysd.get("dns") or ["?"])[0]
                self.v.check(f"the firewall resolved {plan_.get('bastion_fqdn')} through its DNS service route",
                             bool(re.search(rf"\({re.escape(str(plan_.get('bastion_addr') or ''))}\)", pd)),
                             (pd.strip().splitlines() or ["no output"])[0][:80])

    # the uplink router's routes, and an operator request refused by deny-all-log
    for r in [x for x in self.of_kind("frr") if (self.nodes[x].get("routes") or [])]:
        if not self.rs.has(r):
            continue
        n = self.nodes[r]
        self.v.sec(f"{r}: routes to the inside prefixes (chapter 4)")
        routes = self.rs.json(r, "frr_routes")
        for rt in n.get("routes") or []:
            label = f"{rt['dest']} via {rt.get('via')}" + (f" ({rt['decision']})" if rt.get("decision") else "")
            if not isinstance(routes, dict):
                self.v.bad(label, "frr_routes not collected or not JSON")
                continue
            got = [x for x in routes.get(rt["dest"]) or [] if x.get("protocol") == "static"]
            hops = [h.get("ip") for x in got for h in x.get("nexthops") or []]
            sel = any(x.get("selected") or x.get("installed") for x in got)
            self.v.check(label + ": static, selected", bool(got) and rt.get("via") in hops and sel,
                         "absent" if not got else f"next hops {','.join(h or '?' for h in hops)}, selected {sel}")
    cells = plan_.get("cells") or []
    if cells:
        self.v.sec("the operator's forbidden cells reach the firewall (chapter 4)")
        for c in cells:
            # the client's view of each cell (operator-cells-<cell>.txt) and one traffic log read per
            # destination port (operator-cells-tlog-<port>.txt)
            tl = rd(f"operator-cells-tlog-{c['port']}.txt")
            out = rd(f"operator-cells-{c['id']}.txt").strip()
            es = PP.tlog_find(tl, src=plan_.get("operator_addr"), dst=c["addr"], dport=str(c["port"]), rule="deny-all-log")
            self.v.check(f"{plan_.get('operator')} to {c['addr']}:{c['port']} ({c['id']}) refused: {out or 'no result'}",
                         out.split(":")[0] == "failed", "it connected" if out == "connected" else "")
            if c.get("via") == "uplink-spoof":
                # outside the tunnel's proxy IDs: the operator's site address arrives on the uplink,
                # where the firewall routes it through the tunnel, and zone protection drops it
                drops = rd("operator-drops.txt")
                m = re.search(r"^flow_dos_pf_strictip\s+(\d+)", drops, re.M)
                self.v.check("... outside the tunnel's proxy IDs, so it reached the uplink in the clear and zone protection dropped it before "
                             f"any rule (strict IP check: the operator's site is routed through the tunnel; flow_dos_pf_strictip "
                             f"{m.group(1) if m else 'not counted'}), and no rule logged it",
                             bool(m) and int(m.group(1)) > 0 and not es, "a deny-all-log line for it" if es else "no strict-IP drop counted")
                continue
            self.v.check(f"... and the firewall logged it under deny-all-log, zone {es[0]['from'] if es else '?'} to {es[0]['to'] if es else '?'}",
                         bool(es) and es[0]["action"] in ("deny", "drop", "reset-both", "reset-client", "reset-server"),
                         "no deny-all-log entry for it in the log read")


Judge.g_fw_edge = _fw_edge


# --------------------------------------------------------------------------------------------
# chapter 5: the rail backend


def p_interface_status(text: str) -> dict:
    """show interface status: {name: {desc, oper, reason, mtu}} for every Ethernet row."""
    out = {}
    for line in (text or "").splitlines():
        x = line.split()
        if len(x) >= 7 and re.match(r"^Ethernet\d+$", x[0]):
            # Name Description Oper Reason AutoNeg Speed MTU [Alternate Name]
            out[x[0]] = {"desc": x[1], "oper": x[2], "reason": x[3], "mtu": x[6] if x[6].isdigit() else None}
    return out


def p_ip_vrf(text: str) -> dict:
    """show ip vrf: {vrf: [interfaces]} (a VRF with no interface maps to [])."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        if not line.strip() or line.startswith("VRF-NAME") or set(line.strip()) <= {"-"}:
            continue
        if line[:1] not in (" ", "\t"):
            x = line.split()
            cur = x[0]
            out[cur] = x[1:]
        elif cur:
            out[cur] += line.split()
    return out


def node_env(render: Path, node: str) -> dict:
    """A VM guest's rendered bootstrap/<node>/node.env, as KEY: value (quotes removed)."""
    out = {}
    try:
        text = (Path(render) / "bootstrap" / node / "node.env").read_text(encoding="utf-8")
    except OSError:
        return out
    for line in text.splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip("'\"")
    return out


def rendered_relay(render: Path, node: str) -> dict:
    """rail -> {ns, rail_if, rail_addr, veth, routes: [(dest, via, dev, src)]} from node.env."""
    env = node_env(render, node)
    out = {}
    for r in (env.get("RAILS") or "").split():
        rt = []
        for d in (env.get(f"RELAY{r}_ROUTES") or "").split():
            x = (d.split(",") + [None] * 4)[:4]
            rt.append(tuple(v or None for v in x))
        out[int(r)] = {"ns": env.get(f"RELAY{r}_NS"), "rail_if": env.get(f"RELAY{r}_MACVLAN"), "rail_addr": env.get(f"RAIL{r}_ADDR"),
                       "veth": env.get(f"RELAY{r}_VETH"), "routes": rt}
    return out


def _route_rows(text: str) -> list:
    """ip route show, one dict per line: dest, via, dev, src, scope."""
    rows = []
    for line in (text or "").splitlines():
        x = line.split()
        if not x:
            continue
        r = {"dest": x[0], "raw": line.strip()}
        for k in ("via", "dev", "src", "scope", "proto"):
            if k in x and x.index(k) + 1 < len(x):
                r[k] = x[x.index(k) + 1]
        rows.append(r)
    return rows


def _rail_backend(self, names):
    sws = names or [n for n in self.inv.get("order", []) if self.nodes[n].get("role") == "rail_vlan"]
    exp_dir = self.render / "gen" / "expect"
    for sw in self.present(sws):
        n = self.nodes[sw]
        acc = n.get("access") or {}
        natives = sorted(acc, key=natural)
        rails = ", ".join(str(r) for r in n.get("rails") or [])
        vlans = ", ".join(str(v) for v in n.get("vlans") or [])
        self.v.sec(f"{sw}: the rail backend's absences (chapter 5)")
        run = self.need(sw, "running_config", "the running configuration")
        blocks = p_blocks(run) if run is not None else []
        vblocks = [(h, body) for h, body in blocks if re.match(r"^interface Vlan ?\d+$", h)]
        if run is not None:
            want_v = {f"interface Vlan{v}" for v in n.get("vlans") or []}
            have_v = {h.replace("interface Vlan ", "interface Vlan") for h, _ in vblocks}
            self.v.check(f"rails {rails} are VLANs {vlans}, one interface Vlan block each", want_v == have_v,
                         f"blocks: {', '.join(sorted(have_v)) or 'none'}")
            addr = [f"{h}: {l}" for h, body in vblocks for l in body if "address" in l]
            self.v.check(f"no VLAN interface address: none of the {len(vblocks)} interface Vlan blocks holds an ip, ipv6 or anycast "
                         "address line", not addr, "; ".join(addr[:3]))
        ipi = self.need(sw, "ip_interfaces", "show ip interfaces")
        if ipi is not None:
            vl = [r["iface"] for r in p_ip_interfaces(ipi) if r["iface"].startswith("Vlan")]
            self.v.check("show ip interfaces lists no Vlan interface", not vl, ", ".join(vl))
        rt = self.need(sw, "ip_route", "show ip route")
        if run is not None and rt is not None:
            statics = [h for h, _ in blocks if h.startswith(("ip route ", "ipv6 route "))] + \
                      [l.strip() for l in run.splitlines() if l.startswith(("ip route ", "ipv6 route "))]
            self.v.check("no gateway: no static route in the running configuration, and show ip route (the default VRF) prints nothing",
                         not statics and not rt.strip(), "; ".join(statics[:2]) or f"show ip route: {len(rt.strip().splitlines())} lines")
        frr = self.need(sw, "frr_running", "FRR's view")
        if run is not None and frr is not None:
            bgp = [l.strip() for l in (run + "\n" + frr).splitlines() if l.strip().startswith("router bgp")]
            self.v.check("no router bgp: neither the KLISH running configuration nor FRR's own view holds a router bgp line", not bgp,
                         "; ".join(bgp[:2]))
        vrf = self.need(sw, "ip_vrf", "show ip vrf")
        if vrf is not None:
            vr = p_ip_vrf(vrf)
            others = {k: v for k, v in vr.items() if k != "mgmt" and v}
            self.v.check("only Management0 in the mgmt VRF, and no interface in any other VRF",
                         vr.get("mgmt") == ["Management0"] and not others,
                         f"mgmt: {','.join(vr.get('mgmt') or []) or 'none'}" + (f"; {others}" if others else ""))
        st = self.need(sw, "interface_status", "show interface status")
        if st is not None:
            rows = p_interface_status(st)
            up = sorted((k for k, x in rows.items() if x["oper"] == "up"), key=natural)
            down = [k for k, x in rows.items() if k not in acc]
            not_admin = [k for k in down if rows[k]["reason"] != "admin-down"]
            self.v.check(f"no inter-switch link: only the {len(natives)} rendered GPU access ports are up, and the other "
                         f"{len(down)} ports are admin down", up == natives and not not_admin,
                         f"up: {','.join(up) or 'none'}" + (f"; not admin down: {','.join(not_admin[:4])}" if not_admin else ""))
            desc = {x.get("native"): x.get("desc") for x in (n.get("nics") or {}).values()}
            wrong = [f"{k} {rows.get(k, {}).get('desc')} (rendered {desc.get(k)})" for k in natives if rows.get(k, {}).get("desc") != desc.get(k)]
            self.v.check("each up port's description names the GPU NIC the render cables there", not wrong, "; ".join(wrong[:3]))
            want_mtu = {k: str(acc[k].get("mtu") or 9100) for k in natives}
            mtu = [f"{k}={rows.get(k, {}).get('mtu')}" for k in natives if rows.get(k, {}).get("mtu") != want_mtu[k]]
            vals = sorted(set(want_mtu.values()))
            self.v.check(f"the {len(natives)} rail ports at MTU {', '.join(vals)} as rendered"
                         + (" (the factory value; the render types no mtu line)" if vals == ["9100"] else " (the l2 policy's port MTU)")
                         + ", above the GPU NICs' 9000", not mtu, ", ".join(mtu))
        mac = self.need(sw, "mac_table", "show mac address-table")
        if mac is not None:
            try:
                km = json.load(open(exp_dir / f"{sw}.json", encoding="utf-8")).get("known_macs") or {}
            except (OSError, ValueError):
                km = {}
            veths = self.container_macs()
            rows_ = [r for r in p_mac_table(mac) if r[0] != 1 and r[1] not in veths]
            off = [f"{m} on {port}" for _v, m, _t, port in rows_ if (km.get(m) or {}).get("via") != port]
            self.v.check(f"every MAC learned on a rail port is a GPU NIC or relay macvlan the render cables to that port ({len(rows_)} entries)",
                         not off, "; ".join(off[:3]))
        startup = self.render / "bootstrap" / sw / "startup-config.cfg"
        try:
            rend = startup.read_text(encoding="utf-8")
        except OSError:
            rend = ""
        if run is not None:
            rb = dict(p_blocks(run))
            miss = [k for k in natives if "no shutdown" not in (rb.get(f"interface {k}") or [])]
            # an mtu line only where the inventory renders one, at that value
            typed = {b[0]: (re.search(r"^mtu (\d+)$", b[1], re.M) or [None, None])[1]
                     for b in re.findall(r"(?ms)^interface (Ethernet\d+)\n(.*?)^exit", rend)}
            off_mtu = [f"{k} {typed.get(k)}" for k in natives if str(typed.get(k)) != str(acc[k].get("mtu"))]
            self.v.check("every rail port runs no shutdown (the factory profile leaves all ports admin down), and each mtu line the "
                         "render types is the rendered port MTU", bool(natives) and not miss and not off_mtu,
                         ("no shutdown missing: " + ",".join(miss)) if miss else ("mtu typed: " + ",".join(off_mtu)))
    gpus = [g for g in self.inv.get("order", []) if (self.nodes.get(g) or {}).get("relay") and self.rs.has(g)]
    ns_dir = self.rs.path / "rail-backend"
    for g in gpus:
        n = self.nodes[g]
        rel = rendered_relay(self.render, g)
        relay = n.get("relay") or {}
        self.v.sec(f"{g}: GPU namespaces and their relay (chapter 5)")
        dflt, wrong_rt, rpf_bad = [], [], []
        for r in sorted(rel):
            x = rel[r]
            text = self.rs.body(g, f"ns_routes_{r}")
            if text is None:
                wrong_rt.append(f"{x['ns']}: routes not collected")
                continue
            rows = _route_rows(text)
            dflt += [f"{x['ns']}: {row['raw']}" for row in rows if row["dest"] == "default"]
            have = {(row["dest"], row.get("via"), row.get("dev"), row.get("src")) for row in rows if row.get("via")}
            want = set(x["routes"])
            if have != want:
                wrong_rt.append(f"{x['ns']}: " + "; ".join(sorted(f"{d} via {v} dev {dv} src {sr}" for d, v, dv, sr in have ^ want))[:160])
            conn = [row for row in rows if row["dest"] == addr_prefix(x["rail_addr"]) and row.get("dev") == x["rail_if"]]
            if not conn:
                wrong_rt.append(f"{x['ns']}: no connected {addr_prefix(x['rail_addr'])} on {x['rail_if']}")
            rp = self.rs.body(g, f"ns_rpf_{r}")
            kv = {k: int(v) for k, v in p_kv(rp or "", " ").items() if v.isdigit()}
            eff = {k: max(kv.get("all", 0), v) for k, v in kv.items() if k not in ("all", "default", "lo")}
            if not eff or any(v != 2 for v in eff.values()):
                rpf_bad.append(f"{x['ns']}: " + (",".join(f"{k}={v}" for k, v in sorted(eff.items())) or "not read"))
        nss = ",".join(rel[r]["ns"] or "?" for r in sorted(rel))
        self.v.check(f"the {len(rel)} GPU namespaces ({nss}) hold no default route", bool(rel) and not dflt, "; ".join(dflt[:2]))
        self.v.check(f"each holds its connected rail and {max(len(rel) - 1, 0)} relay routes, one to each other rail via that rail's "
                     "namespace, every one pinned to the namespace's own rail address, as rendered", bool(rel) and not wrong_rt,
                     "; ".join(wrong_rt[:2]))
        self.v.check("reverse-path filtering loose (rp_filter 2) on every interface of every GPU namespace", bool(rel) and not rpf_bad,
                     "; ".join(rpf_bad[:2]))
        data = self.rs.json(g, "ip_addr")
        links = p_ip_addrs(data) if isinstance(data, list) else {}
        mtus = {}
        if isinstance(data, list):
            for l in data:
                mtus[l.get("ifname")] = l.get("mtu")
        rails_if = [(n.get("rails") or {})[str(r)]["ifname"] for r in sorted(rel) if str(r) in (n.get("rails") or {})]
        bad_mtu = [f"{i}={mtus.get(i)}" for i in rails_if + [relay.get("bridge")] if mtus.get(i) != 9000]
        self.v.check(f"the {len(rails_if)} rail NICs and the relay bridge {relay.get('bridge')} at MTU 9000",
                     bool(links) and not bad_mtu, ", ".join(bad_mtu[:4]) or ("ip_addr not collected" if not links else ""))
        ns_bad, ns_seen = [], 0
        for r in sorted(rel):
            x = rel[r]
            try:
                ll = json.loads(evfile.read_text(ns_dir / f"{g}-{x['ns']}-links.json", "strict"))
            except (OSError, ValueError):
                ns_bad.append(f"{x['ns']}: not read")
                continue
            ns_seen += 1
            got = {l.get("ifname"): l.get("mtu") for l in ll if isinstance(l, dict)}
            for i in (x["rail_if"], x["veth"]):
                if got.get(i) != 9000:
                    ns_bad.append(f"{x['ns']} {i}={got.get(i)}")
        self.v.check(f"in each GPU namespace the rail macvlan and the relay veth at MTU 9000: the cross-rail ceiling is the relay's 9000 "
                     f"({ns_seen} namespaces read)", ns_seen == len(rel) and bool(rel) and not ns_bad, "; ".join(ns_bad[:3]))


def addr_prefix(cidr):
    try:
        return str(ipaddress.ip_interface(cidr).network)
    except ValueError:
        return None


Judge.g_rail_backend = _rail_backend

# chapter 6: the serving pods against the placement table (placement.py)
from placement import g_placement  # noqa: E402

Judge.g_placement = g_placement

# chapter 7: the gateway layer and the callers' keys (gwlayer.py)
from gwlayer import g_gateway_layer, g_keys  # noqa: E402

Judge.g_gateway_layer = g_gateway_layer
Judge.g_keys = g_keys

# build A revision 2: the cluster's protections and a person's token (clustersec.py)
from clustersec import g_cluster_security, g_identity  # noqa: E402

Judge.g_cluster_security = g_cluster_security
Judge.g_identity = g_identity


GROUPS = {
    "shared": "g_shared", "vlans": "g_vlans", "mac-tables": "g_mac_tables", "forwarding-only": "g_forwarding",
    "l2-hygiene": "g_l2_hygiene",
    "mclag-pair": "g_mclag", "firewall": "g_firewall", "guests": "g_guests", "rails": "g_rails",
    "cluster-nodes": "g_cluster_nodes", "bastion": "g_bastion", "services": "g_services", "routers": "g_routers", "registry": "g_registry",
    "clients": "g_clients", "storage": "g_storage", "cluster": "g_cluster", "populations": "g_populations",
    "pair-roles": "g_pair_roles", "bond-legs": "g_bond_legs", "fw-edge": "g_fw_edge", "rail-backend": "g_rail_backend",
    "placement": "g_placement", "gateway-layer": "g_gateway_layer", "keys": "g_keys",
    "cluster-security": "g_cluster_security", "identity": "g_identity",
}


def cmd_run(a) -> int:
    inv = load_inv(a.inv)
    v = vocab.Vocab(known=set(inv.get("known") or []) or None)
    j = Judge(ResultSet(a.set), inv, Path(a.render), v,
              except_peers=[x for x in (a.except_peers or "").split(",") if x])
    before = v.counts()["fail"]
    getattr(j, GROUPS[a.group])(list(a.nodes))
    return 1 if v.counts()["fail"] > before else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="judge", description="judge an audit result set from its saved files")
    sub = p.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("plan")
    sp.add_argument("--inv", required=True)
    sp.add_argument("--node", required=True)
    sp.add_argument("--quick", action="store_true")
    sp = sub.add_parser("split")
    sp.add_argument("--style", choices=("klish", "panos"), required=True)
    sp.add_argument("--plan", required=True)
    sp.add_argument("--session", required=True)
    sp.add_argument("--out", required=True)
    sp = sub.add_parser("body")
    sp.add_argument("--style", choices=("klish", "panos"), required=True)
    sp.add_argument("--command", required=True)
    sp = sub.add_parser("offloads")
    sp.add_argument("--nics", type=int)
    sp.add_argument("file")
    sp = sub.add_parser("run")
    sp.add_argument("--set", required=True)
    sp.add_argument("--inv", required=True)
    sp.add_argument("--render", required=True)
    sp.add_argument("--except-peers", default="",
                    help="comma-separated nodes: leave out the PortChannels that face them (mclag-pair)")
    sp.add_argument("group", choices=sorted(GROUPS))
    sp.add_argument("nodes", nargs="*")
    a = p.parse_args(argv)
    return {"plan": cmd_plan, "split": cmd_split, "body": cmd_body, "offloads": cmd_offloads, "run": cmd_run}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
