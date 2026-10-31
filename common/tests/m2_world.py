"""A healthy sfab-m2, as its collection plans would read it, for common/tests/test_m2.py and the M2
stand-ins (common/tests/shims-m2/).

healthy(inv, render) returns {node: {slug: text}} for every slug the M2 plans add (the bastion, the
DNS and time servers, the router, the registry, the clients, TrueNAS, the Kubernetes nodes with the
cluster reads on the init node that runs the harness's kubectl, the populations). Every value is built from the inventory and the render, so the judges see the lab
exactly as rendered. answer(inv, render, node, command) finds a planned command's slug and returns
its text, or None for a command no M2 plan names (the shared stand-ins answer those).

break_world(files, fault) changes one thing in a healthy world, the way a fault would show.
Fixtures use the book's own addressing plan and made-up names only.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import judge  # noqa: E402

T_CHANGED = "2026-10-20T10:00:00Z"
T_STARTED = "2026-10-20T10:05:00Z"


def bare(a):
    return None if a is None else str(a).split("/")[0]


def ping(n=3):
    return f"PING x\n{n} packets transmitted, {n} received, 0% packet loss, time 2003ms"


def offloads(eths):
    return "\n".join(f"== {e}\ntx-checksumming: off\ngeneric-receive-offload: off\nrx-gro-hw: off [fixed]\n"
                     f"large-receive-offload: off [fixed]" for e in eths)


def ip_addrs(rows):
    """rows: [(ifname, cidr or None, master or None)]"""
    out = [{"ifname": "lo", "operstate": "UNKNOWN", "flags": ["LOOPBACK", "UP", "LOWER_UP"],
            "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]}]
    for name, cidr, master in rows:
        d = {"ifname": name, "operstate": "UP", "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"], "addr_info": []}
        if master:
            d["master"] = master
        if cidr:
            a, l = cidr.split("/")
            d["addr_info"].append({"family": "inet", "local": a, "prefixlen": int(l), "scope": "global"})
        out.append(d)
    return json.dumps(out)


def bonding(partner="02:5a:00:00:00:01", members=("eth1", "eth2"), mac="0c:00:aa:bb:cc:02", state=63):
    """/proc/net/bonding/bond0 as the kernel prints it (M2's record set): each leg's actor and
    partner LACP details, which chapter 3's bond-legs check reads leg by leg."""
    out = ["Bonding Mode: IEEE 802.3ad Dynamic link aggregation", "802.3ad info", "Active Aggregator Info:",
           "\tAggregator ID: 1", f"\tNumber of ports: {len(members)}", f"\tPartner Mac Address: {partner}", ""]
    for i, m in enumerate(members, 1):
        out += [f"Slave Interface: {m}", "MII Status: up", "Aggregator ID: 1", "details actor lacp pdu:",
                f"    system mac address: {mac}", f"    port number: {i}", f"    port state: {state}", "details partner lacp pdu:",
                f"    system mac address: {partner}", "    port number: 7", f"    port state: {state}", ""]
    return "\n".join(out)


def curl_ok(msg, server="envoy"):
    return f"HTTP/2 200 \ncontent-type: text/plain\nserver: {server}\n\n{msg}"


def curl_404(server="envoy"):
    return f"HTTP/2 404 \ncontent-length: 0\nserver: {server}\n\n"


def x509(subject, issuer, verified=True, path="", constraints=None, san=None):
    out = [f"subject={subject}", f"issuer={issuer}"]
    if constraints:
        out += ["X509v3 Name Constraints: critical", "    Permitted:"]
        for c in constraints:
            if "/" in c:
                n = ipaddress.ip_network(c)
                out.append(f"      IP:{n.network_address}/{n.netmask}")
            else:
                out.append(f"      DNS:{c}")
    if san:
        out += ["X509v3 Subject Alternative Name: ", f"    {san}"]
    if verified:
        out.append(f"{path}: OK")
    return "\n".join(out)


def pod(ns, name, node=None, labels=None, started=T_STARTED, ready=True, phase="Running"):
    return {"metadata": {"namespace": ns, "name": name, "labels": labels or {}},
            "spec": {"nodeName": node},
            "status": {"phase": phase, "startTime": started,
                       "containerStatuses": [{"name": "c", "ready": ready}]}}


def cond(kind, status="True"):
    return {"type": kind, "status": status}


def kubeitems(items):
    return json.dumps({"apiVersion": "v1", "kind": "List", "items": items})


def bmc_files(n: dict) -> tuple:
    """The BMC stand-in's namespace as ip -j addr and ss -ltnH show it: its address, SSH and HTTPS."""
    o = n.get("oob") or {}
    a, _, plen = str(o.get("address") or "").partition("/")
    addr_json = json.dumps([{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
                            {"ifname": o.get("eth") or "eth3", "addr_info": [{"family": "inet", "local": a, "prefixlen": int(plen or 24)}]}])
    return addr_json, f"LISTEN 0      128    {a}:22  0.0.0.0:*\nLISTEN 0      16        0.0.0.0:443 0.0.0.0:*"


def setup_json(render: Path, node: str) -> dict:
    try:
        return json.loads((render / "bootstrap" / node / "setup.json").read_text())
    except (OSError, ValueError):
        return {}


def cluster_files(inv: dict, render: Path) -> dict:
    k8s = inv.get("k8s") or {}
    ca = inv.get("ca") or {}
    nodes = inv["nodes"]
    control, workers = list(k8s.get("control") or []), list(k8s.get("workers") or [])
    labels = k8s.get("labels") or {}
    gws = inv.get("gateways") or {}
    ns = k8s.get("gateway_namespace") or "gateways"
    tb = k8s.get("test_backend") or {}
    f = {}
    f["kube_version"] = json.dumps({"clientVersion": {"gitVersion": k8s.get("version")}, "serverVersion": {"gitVersion": k8s.get("version")}})
    f["kube_server"] = f"https://{k8s.get('api_fqdn')}:6443"
    f["helm_version"] = "v3.22.0+g1e4ab49"
    items = []
    for n in control + workers:
        lab = {"kubernetes.io/hostname": n}
        if n in control:
            lab[labels["control"]] = ""
        if nodes[n].get("group") == "gpu":
            lab[labels["gpu"]] = ""
        if nodes[n].get("group") == "ingress" and labels.get("ingress"):
            lab[labels["ingress"]] = ""
        items.append({"metadata": {"name": n, "labels": lab},
                      "status": {"conditions": [cond("Ready")], "nodeInfo": {"kubeletVersion": k8s.get("version")},
                                 "addresses": [{"type": "InternalIP", "address": bare(nodes[n]["address"])}, {"type": "Hostname", "address": n}]}})
    f["nodes"] = kubeitems(items)
    pods = [pod("kube-system", f"cilium-{i}", n, {"k8s-app": "cilium"}) for i, n in enumerate(control + workers)]
    pods += [pod("kube-system", "coredns-1", control[0]), pod("kube-system", f"kube-apiserver-{control[0]}", control[0]),
             pod("kube-system", f"kube-vip-{control[0]}", control[0]), pod("kube-system", "cilium-operator-1", control[0])]
    pods += [pod("cert-manager", f"cert-manager-{x}", control[1]) for x in ("controller", "webhook", "cainjector")]
    # the ingress nodes are tainted: the workloads run on the other workers
    sched = [w for w in workers if nodes[w].get("group") != "ingress"] or workers
    if tb:
        pods += [pod(tb["namespace"], f"{tb['name']}-{i}", sched[i % len(sched)]) for i in range(tb.get("replicas") or 1)]
    for s in (inv.get("stages") or {}).get("storage") or []:
        csi = setup_json(render, s).get("csi") or {}
        cns = (csi.get("kubernetes") or {}).get("namespace") or "democratic-csi"
        for c in csi.get("classes") or []:
            pods.append(pod(cns, f"{c['release']}-democratic-csi-controller-0", control[0]))
            for n in control + workers:
                pods.append(pod(cns, f"{c['release']}-democratic-csi-node-{n}", n))
    f["pods"] = kubeitems(pods)
    want = len(control + workers)
    f["daemonsets"] = kubeitems([{"metadata": {"namespace": "kube-system", "name": "cilium"},
                                  "status": {"desiredNumberScheduled": want, "numberReady": want}}])
    deps = [{"metadata": {"namespace": "cert-manager", "name": f"cert-manager{x}"}, "spec": {"replicas": 1},
             "status": {"availableReplicas": 1, "readyReplicas": 1, "conditions": [cond("Available")]}} for x in ("", "-webhook", "-cainjector")]
    if tb:
        deps.append({"metadata": {"namespace": tb["namespace"], "name": tb["name"]}, "spec": {"replicas": tb["replicas"]},
                     "status": {"availableReplicas": tb["replicas"], "readyReplicas": tb["replicas"], "conditions": [cond("Available")]}})
    f["deployments"] = kubeitems(deps)
    f["cilium_config"] = json.dumps({"metadata": {"name": "cilium-config", "namespace": "kube-system", "creationTimestamp": T_CHANGED,
                                                  "managedFields": [{"manager": "helm", "time": T_CHANGED}]},
                                     "data": {"devices": " ".join(k8s.get("cilium_devices") or []), "kube-proxy-replacement": "true",
                                              "enable-l2-announcements": "true", "enable-gateway-api": "true"}})
    leases = [{"metadata": {"namespace": "kube-system", "name": "plndr-cp-lock"}, "spec": {"holderIdentity": control[0]}}]
    # the Gateway VIPs' leases sit with the nodes the L2 announcement policy selects: the ingress
    # nodes where the lab has them
    holders = [n for n in control + workers if nodes[n].get("group") == "ingress"] or control
    for i, g in enumerate(sorted(gws)):
        leases.append({"metadata": {"namespace": "kube-system", "name": f"cilium-l2announce-{ns}-cilium-gateway-{g}"},
                       "spec": {"holderIdentity": holders[(i + 1) % len(holders)]}})
    f["leases"] = kubeitems(leases)
    kcn = ca["intermediates"]["kubernetes"]["cn"]
    f["api_cert"] = (f"depth=2 CN={ca['root_cn']}\ndepth=1 CN={kcn}\ndepth=0 CN=kube-apiserver\nVerify return code: 0 (ok)\n"
                     f"subject=CN=kube-apiserver\nissuer=CN={kcn}")
    iss = (ca.get("issuer") or {}).get("name")
    f["clusterissuers"] = kubeitems([{"metadata": {"name": iss}, "status": {"conditions": [cond("Ready")]}}])
    # every listener certificate the lab issues (one per Gateway), each Ready
    f["certificates"] = kubeitems([{"metadata": {"namespace": ns, "name": c.get("id")}, "spec": {"secretName": c.get("secret")},
                                    "status": {"conditions": [cond("Ready")]}} for c in ca.get("certificates") or []])
    pcn = ca["intermediates"][(ca.get("issuer") or {}).get("intermediate") or "platform"]["cn"]
    wildcard = f"*.{(inv.get('org') or {}).get('zone') or inv['org']['domain']}"
    f["wildcard_cert"] = x509(f"CN={wildcard}", f"CN={pcn}", verified=False, san=f"DNS:{wildcard}")
    f["gateways"] = kubeitems([{"metadata": {"namespace": ns, "name": g},
                                "status": {"addresses": [{"type": "IPAddress", "value": v["vip"]}],
                                           "conditions": [cond("Accepted"), cond("Programmed")]}} for g, v in sorted(gws.items())])
    routes = []
    for g in tb.get("gateways") or []:
        routes.append({"metadata": {"namespace": tb["namespace"], "name": f"{tb['name']}-{g}"},
                       "spec": {"parentRefs": [{"name": g, "namespace": ns}], "hostnames": gws[g]["hostnames"],
                                "rules": [{"backendRefs": [{"name": tb["name"], "port": tb["port"]}]}]},
                       "status": {"parents": [{"parentRef": {"name": g, "namespace": ns},
                                               "conditions": [cond("Accepted"), cond("ResolvedRefs")]}]}})
    f["httproutes"] = kubeitems(routes)
    f["lb_pools"] = kubeitems([{"metadata": {"name": g}, "spec": {"blocks": [{"start": v["pool"][0], "stop": v["pool"][1]}]}}
                               for g, v in sorted(gws.items())])
    la = k8s.get("l2_announce") or {}
    f["l2_policies"] = kubeitems([{"metadata": {"name": "gateways"},
                                   "spec": {"interfaces": la.get("interfaces"), "loadBalancerIPs": True,
                                            "nodeSelector": {"matchExpressions": [{"key": labels[str(la.get("nodes") or "control")],
                                                                                   "operator": "Exists"}]}}}])
    scs = []
    for s in (inv.get("stages") or {}).get("storage") or []:
        csi = setup_json(render, s).get("csi") or {}
        for c in csi.get("classes") or []:
            ann = {"storageclass.kubernetes.io/is-default-class": "true"} if c["name"] == csi.get("default_class") else {}
            scs.append({"metadata": {"name": c["storage_class"], "annotations": ann}, "provisioner": f"org.democratic-csi.{c['name']}"})
    f["storageclasses"] = kubeitems(scs)
    f["events_warning"] = kubeitems([])
    return f


def docker_resolv(inv: dict, search: str | None = None) -> str:
    """resolv.conf as sfab-init.sh leaves Docker's file in a container with no resolver in the lab:
    the search line replaced with the node's domain (the platform zone), Docker's nameserver and
    options kept."""
    return f"search {search or inv['org'].get('zone') or inv['org']['domain']}\nnameserver 127.0.0.11\noptions edns0 trust-ad ndots:0"


def rendered_serial(render: Path, server: str, view: str, zone: str):
    try:
        text = (Path(render) / "bootstrap" / server / "zones" / f"db.{view}.{zone}").read_text()
    except OSError:
        return None
    for line in text.splitlines():
        if line.strip().endswith("; serial, from the zone's data") or "; serial" in line:
            return line.split(";")[0].strip()
    return None


def services_files(inv: dict, render: Path, name: str) -> dict:
    """A DNS or time server's reads (resolver.list and its role's list) as a healthy lab returns them."""
    nodes = inv["nodes"]
    n = nodes[name]
    dns = inv.get("dns") or {}
    ntp = inv.get("ntp") or {}
    views = dns.get("views") or {}
    zone = dns.get("zone") or (inv.get("org") or {}).get("zone")
    role = n.get("role")
    mgmt_gw = (inv.get("mgmt") or {}).get("gw")
    f = {}
    bond = n.get("bond")
    if bond:
        f["ip_addr"] = ip_addrs([("eth1", None, "bond0"), ("eth2", None, "bond0"), (bond["name"], bond["address"], None),
                                 ("eth0", f"{n['mgmt']}/24", None)])
        f["bonding"] = bonding()
    else:
        f["ip_addr"] = ip_addrs([("eth1", n["address"], None), ("eth0", f"{n['mgmt']}/24", None)])
    f["table_main"] = f"default via {n['gateway']} dev {'bond0' if bond else 'eth1'}"
    f["table_mgmt"] = f"default via {mgmt_gw} dev eth0"
    f["tx_container"] = offloads(n.get("eths") or [])
    f["container_links"] = "[]"
    f["ping_gw"] = ping()
    corp = any(name in (r.get("local") or []) for r in (dns.get("resolvers") or {}).values())
    search = (inv.get("org") or {}).get("domain") if corp else zone
    res = [bare(nodes[r]["address"]) for r in n.get("resolvers") or [] if r in nodes]
    f["resolv_conf"] = f"search {search}\n" + "\n".join(f"nameserver {a}" for a in res) if res else docker_resolv(inv)
    run = {"dns-auth": ("named",), "dns-res": ("named", "chronyd"), "dns-corporate": ("dnsmasq",), "inet-ntp": ("chronyd",)}.get(role, ())
    f["services"] = "\n".join(f"{p} {'running' if p in run else 'absent'}" for p in ("named", "dnsmasq", "chronyd"))
    f["named_running"] = "  147 named -u named -c /etc/sfab/dns/named.conf" if "named" in run else "no named process"
    internal = next((v for v in views.values() if v.get("infra")), {})
    if role == "dns-auth":
        secs = []
        for v, d in sorted(views.items()):
            if name not in (d.get("servers") or []):
                continue
            typ = "primary" if d.get("server") == name else "secondary"
            secs.append(f"== {v}\nname: {zone}\ntype: {typ}\nserial: {rendered_serial(render, d.get('server'), v, zone)}")
        f["zonestatus"] = "\n".join(secs)
        f["local_users"] = internal.get("answer_address") or ""
        f["recursion"] = ";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 1\n;; flags: qr rd; QUERY: 1, ANSWER: 0"
    elif role == "dns-res":
        f["res_users"] = internal.get("answer_address") or ""
        f["res_reverse"] = f"{(inv.get('k8s') or {}).get('api_fqdn')}."
        f["res_outside"] = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 2\n;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1"
        up = (ntp.get("upstream") or {}).get("address")
        f["chrony_sources"] = ("MS Name/IP address         Stratum Poll Reach LastRx Last sample\n" + "=" * 79 +
                               f"\n^* {up:<29} 2   6   377     3    -61us[  -72us] +/-  677us")
        f["chrony_authdata"] = ("Name/IP address             Mode KeyID Type KLen Last Atmp  NAK Cook CLen\n" + "=" * 73 +
                                f"\n{up:<28} NTS     1   30  128  398    0    0    8   64")
        f["chrony_tracking"] = f"Reference ID    : C000020E ({up})\nStratum         : 3\nLeap status     : Normal"
    elif role == "dns-corporate":
        ev = next((d for d in views.values() if bare(n.get("address")) in [bare(c) for c in d.get("match_cidrs") or []]), {})
        f["corp_users"] = ev.get("answer_address") or ""
        f["corp_admin"] = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 3"
        local = next((r for r in (dns.get("resolvers") or {}).values() if name in (r.get("servers") or [])), {})
        first = (local.get("local") or [None])[0]
        f["corp_local"] = bare((nodes.get(first) or {}).get("address")) or ""
    elif role == "inet-ntp":
        f["chrony_tracking"] = f"Reference ID    : 7F7F0101 ()\nStratum         : {ntp.get('reference_stratum')}\nLeap status     : Normal"
        f["chrony_serverstats"] = "NTP packets received       : 20\nNTS-KE connections accepted: 2\nNTS-KE connections dropped : 0"
    return f


def healthy(inv: dict, render: Path) -> dict:
    render = Path(render)
    nodes = inv["nodes"]
    st = inv.get("stages") or {}
    mgmt_gw = (inv.get("mgmt") or {}).get("gw")
    reg = inv.get("registry") or {}
    ca = inv.get("ca") or {}
    dns = inv.get("dns") or {}
    out: dict = {}
    fw = st.get("fw")
    public = (nodes.get(fw) or {}).get("public")
    for name in inv["order"]:
        n = nodes[name]
        f = {}
        kind = n["kind"]
        eths = n.get("eths") or []
        ctx = judge.base_ctx(inv, name)
        if kind == "bastion":
            bond = n["bond"]
            f["init_log"] = "[bastion] lab root CA trusted\n[bastion] bastion ready"
            f["bonding"] = bonding()
            f["ip_addr"] = ip_addrs([("eth1", None, "bond0"), ("eth2", None, "bond0"), (bond["name"], bond["address"], None),
                                     ("eth0", f"{n['mgmt']}/24", None)])
            f["ip_rule"] = f"0:\tfrom all lookup local\n100:\tfrom {n['mgmt']} lookup 150"
            f["table_main"] = f"default via {n['gateway']} dev bond0\n10.20.3.0/24 dev bond0 proto kernel scope link src 10.20.3.10"
            f["table_mgmt"] = f"default via {mgmt_gw} dev eth0"
            f["tx_container"] = offloads(eths)
            f["container_links"] = "[]"
            f["services"] = "sshd running\nlldpd running\nnamed absent\nchronyd absent\ndnsmasq absent"
            f["resolv_conf"] = f"search {inv['org'].get('zone') or inv['org']['domain']}\n" + "\n".join(
                f"nameserver {bare(nodes[r]['address'])}" for r in n.get("resolvers") or [] if r in nodes)
            f["admin_kubeconfig"] = "root kubeconfig absent\nno cluster or CA state"
            if st.get("cluster"):
                user = (inv.get("guest") or {}).get("user") or "admin"
                ops = (inv.get("k8s") or {}).get("operators") or {}
                kcn = ca["intermediates"]["kubernetes"]["cn"]
                f["operator_cert"] = (f"subject=CN={user},O={ops.get('group') or 'operators'}\nissuer=CN={kcn},O=Tarnwick\n"
                                      "notBefore=Oct 20 09:00:00 2026 GMT\nnotAfter=Oct 20 18:05:00 2026 GMT\n"
                                      "now=Oct 20 10:05:30 2026 GMT")
                f["operator_can_i"] = "get pods -A: yes\nlist nodes: yes\ncreate pods -A: no\nget secrets -A: no\ndelete nodes: no"
            certs = []
            for iname, i in sorted((ca.get("intermediates") or {}).items()):
                certs.append(f"== /shared/ca/{iname}.crt\n" + x509(f"CN={i['cn']}", f"CN={ca['root_cn']}", True, f"/shared/ca/{iname}.crt",
                                                                   list(i.get("dns") or []) + list(i.get("ip") or [])))
            certs.append("== /shared/ca/root.crt\n" + x509(f"CN={ca['root_cn']}", f"CN={ca['root_cn']}", True, "/shared/ca/root.crt"))
            f["ca_certs"] = "\n".join(certs)
            f["shared_keys"] = "scanned state/shared"
            f["stor_mgmt_https"] = "HTTP/1.1 200 OK"
        elif kind == "resolver":
            f.update(services_files(inv, render, name))
        elif kind == "frr":
            routes = {}
            rows = [("eth0", f"{n['mgmt']}/24", "mgmt")]
            for eth, i in sorted((n.get("ifaces") or {}).items()):
                if eth in (n.get("nics") or {}):
                    routes[str(ipaddress.ip_interface(i["address"]).network)] = [{"protocol": "connected", "selected": True}]
                    rows.append((eth, i["address"], None))
            f["frr_version"] = "FRRouting 10.5.4 (uplink-rtr) on Linux(6.8.0).\nCopyright 1996-2005 Kunihiro Ishiguro, et al."
            f["frr_routes"] = json.dumps(routes)
            f["frr_route_text"] = "Codes: K - kernel route, C - connected, L - local, S - static\n" + "\n".join(
                f"C>* {p} is directly connected, eth{i}" for i, p in enumerate(routes, 1))
            f["link_eth0"] = json.dumps([{"ifname": "eth0", "master": "mgmt", "operstate": "UP"}])
            f["ip_addr"] = ip_addrs(rows)
            f["table_main"] = "\n".join(f"{p} dev eth{i} proto kernel scope link" for i, p in enumerate(routes, 1))
            f["table_vrf_mgmt"] = f"default via {mgmt_gw} dev eth0\n172.21.40.0/24 dev eth0 proto kernel scope link"
            f["ip_forward"] = "net.ipv4.ip_forward = 1"
            f["tx_container"] = offloads(eths)
            f["container_links"] = "[]"
            f["resolv_conf"] = docker_resolv(inv)
            for row in judge.p2p_rows(inv, name):
                if row.get("p2p_appliance_addr"):
                    f[judge.slugify(f"arp_{row['p2p']}")] = (
                        f"ARPING {row['p2p_addr']} from 198.51.100.1 {row['p2p_iface']}\n"
                        f"Unicast reply from {row['p2p_addr']} [aa:c1:ab:3b:80:c0] 0.300ms\n"
                        "Sent 3 probe(s) (0 broadcast(s))\nReceived 3 response(s) (0 request(s), 0 broadcast(s))")
                else:
                    f[judge.slugify(f"ping_{row['p2p']}")] = ping()
        elif kind in ("registry", "client"):
            rows = [("eth0", f"{n['mgmt']}/24", None)] + [(e, i["address"], None) for e, i in sorted((n.get("ifaces") or {}).items())
                                                         if e in (n.get("nics") or {})]
            f["ip_addr"] = ip_addrs(rows)
            f["table_main"] = f"default via {n['gateway']} dev eth1"
            f["table_mgmt"] = f"default via {mgmt_gw} dev eth0"
            f["tx_container"] = offloads(eths)
            f["container_links"] = "[]"
            f["ping_gw"] = ping()
            if kind == "registry":
                cat = [f"{u}/x/{u.split('.')[0]}" for u in reg.get("upstreams") or []] + [f"{reg.get('charts', 'charts')}/cert-manager"]
                f["catalog"] = json.dumps({"repositories": cat})
                f["access_log"] = (f'time="2026-10-20T10:01:00Z" level=info msg="response completed" http.request.method=GET '
                                   f'http.request.remoteaddr="{public}:40512" http.request.uri="/v2/" http.response.status=200\n'
                                   f'{public} - - [20/Oct/2026:10:01:00 +0000] "GET /v2/ HTTP/1.1" 200 2 "" "containerd/2.2"')
                f["resolv_conf"] = docker_resolv(inv)
            else:
                env = {}
                try:
                    for line in (render / "bootstrap" / name / "init.env").read_text().splitlines():
                        if "=" in line and not line.startswith("#"):
                            k, v = line.split("=", 1)
                            env[k] = v.strip("'")
                except OSError:
                    pass
                servers = env.get("DNS_SERVERS", "").replace(",", " ").split()
                rc = [f"search {inv['org']['domain']}"] + [f"nameserver {x}" for x in servers]
                if env.get("RESOLV_OPTIONS"):
                    rc.append(f"options {env['RESOLV_OPTIONS']}")
                f["resolv_conf"] = "\n".join(rc) if servers else docker_resolv(inv)
                f["ca_bundle"] = "root in bundle"
        elif kind == "truenas":
            f["container_health"] = "running healthy restarts=0 started=2026-10-20T09:00:00Z"
            f["launcher_login"] = ("username: present, from the container env (USERNAME), <redacted hmac:0123456789ab>\n"
                                   "password: present, from the container env (PASSWORD), <redacted hmac:ba9876543210>")
            f["container_links"] = "[]"
        elif kind == "vpngw":
            f["container_health"] = "running healthy restarts=0 started=2026-10-20T09:00:00Z"
            sas = []
            for x in (nodes.get(fw) or {}).get("vpns") or []:
                if x.get("peer_node") != name:
                    continue
                sas += [f"{x['name']}: #1, ESTABLISHED, IKEv2, 0123456789abcdef_i* fedcba9876543210_r",
                        f"  local  '{x['peer']}' @ {x['peer']}[500]"]
                sas += [f"  {pid}: #{i}, reqid {i}, INSTALLED, TUNNEL, ESP:AES_CBC-256/HMAC_SHA2_256_128/MODP_2048"
                        for i, (pid, *_) in enumerate(x.get("proxy_ids") or [], 1)]
            f["swanctl_sas"] = "\n".join(sas)
            f["swanctl_conns"] = ""
        elif kind == "vm-node" and n.get("k8s") and st.get("cluster"):
            if name == st.get("kubectl"):
                f.update(cluster_files(inv, render))
            f["cluster_unit"] = "ActiveState=inactive\nSubState=dead\nExecMainStatus=0\nExecMainExitTimestampMonotonic=93456789\nNRestarts=0"
            f["kubelet_active"] = "active"
            f["containerd_hosts"] = "\n".join(
                f"== /etc/containerd/certs.d/{u}/hosts.toml\nserver = \"https://{u}\"\n\n[host.\"{ctx['registry_url']}/v2/{u}\"]\n"
                f"  capabilities = [\"pull\", \"resolve\"]\n  override_path = true\n"
                + (f"  ca = \"{ctx['ca_root']}\"\n" if str(ctx.get("registry_url", "")).startswith("https") else "")
                for u in reg.get("upstreams") or [])
            f["registry_v2"] = "HTTP/2 200 \ncontent-length: 2\ndocker-distribution-api-version: registry/2.0"
            servers = list(((inv.get("ntp") or {}).get("servers") or {}).values())
            f["ntp_resolvers"] = "\n".join(f"stratum 3 from {a}" for a in servers)
            f["timesync"] = (f"SystemNTPServers={' '.join(servers)}\nServerName={servers[0]}\nServerAddress={servers[0]}\n"
                             "NTPSynchronized=yes") if servers else "NTPSynchronized=no"
            view = next((v for v in (dns.get("views") or {}).values()
                         if any(ipaddress.ip_address(bare(n["address"])) in ipaddress.ip_network(c) for c in v["match_cidrs"])), {})
            res = [bare(nodes[r]["address"]) for r in n.get("resolvers") or [] if r in nodes]
            f["dns_users"] = (dns.get("views") or {}).get("internal", {}).get("answer_address") or view.get("answer_address") or ""
            f["dns_both"] = "\n".join(f"{r} {f['dns_users']} " for r in res)
            f["dns_storage"] = (dns.get("records") or {}).get(ctx.get("storage_fqdn")) or ""
            # the storage data VLAN is Layer 2 only: open from a node with a unit in it, closed from the rest
            sdata = next(((nodes.get(x) or {}).get("data") or {} for x in st.get("storage") or [] if (nodes.get(x) or {}).get("data")), {})
            units = (n.get("bond") or {}).get("vlan_ifs") or []
            in_vlan = bool(sdata) and any(ipaddress.ip_address(bare(sdata["address"])) in ipaddress.ip_interface(u["address"]).network
                                          for u in units)
            f["storage_ports"] = "2049 open" if in_vlan else "2049 closed"
            if (n.get("oob") or {}).get("netns"):
                f["bmc_addr"], f["bmc_listen"] = bmc_files(n)
            f["ping_storage"] = ping() if in_vlan else "PING x\n3 packets transmitted, 0 received, 100% packet loss, time 2003ms"
        pc = judge.population_ctx(inv, name)
        if pc and st.get("cluster"):
            pop = inv["populations"][pc["pop"]]
            gw = inv["gateways"][pop["gateway"]]
            # the view a population sees is the one its resolver's address matches (the resolvers ask
            # the authoritative pair, and each view is keyed by the asking resolver)
            raddr = pop.get("resolver_address")
            view = next((v for v in (dns.get("views") or {}).values() if raddr and
                         any(ipaddress.ip_address(raddr) in ipaddress.ip_network(c) for c in v["match_cidrs"])), {})
            if pc.get("pop_resolver"):
                names = set(view.get("names") or [])
                f["pop_dns_users"] = pc["pop_answer"]
                f["pop_dns_admin"] = pc["pop_answer"] if pc["admin_fqdn"] in names or not names else ""
                rec = (dns.get("records") or {}).get(pc["infra_fqdn"])
                f["pop_dns_infra"] = (rec or "") if view.get("infra") else ""
            f["pop_https_users"] = curl_ok(pc["echo_msg"])
            f["pop_https_admin"] = curl_ok(pc["echo_msg"]) if pc["admin_fqdn"] in gw["hostnames"] else curl_404()
        if f:
            out[name] = f
    return out


def write_set(rs: Path, files: dict) -> None:
    """Write {node: {slug: text}} as a result set's saved files (NN_<slug>.<ext>)."""
    for node, slugs in files.items():
        d = Path(rs) / node
        d.mkdir(parents=True, exist_ok=True)
        for i, (slug, text) in enumerate(slugs.items(), 1):
            ext = ".json" if text.lstrip().startswith(("{", "[")) else ".txt"
            (d / f"{i:02d}_{slug}{ext}").write_text(text if text.endswith("\n") else text + "\n")


def answer(inv: dict, render, node: str, command: str):
    """The healthy text for the planned command COMMAND on NODE, or None."""
    world = healthy(inv, Path(render))
    for row in judge.plan(inv, node):
        if row["command"].strip() == command.strip():
            return (world.get(node) or {}).get(row["slug"])
    return None


FAULTS = {
    # one population refused by the firewall, not by its Gateway
    "admin-timeout": lambda w: w["ent-client"].update(pop_https_admin="curl: (28) Connection timed out after 20001 milliseconds"),
    # the users' Gateway answers 404 from something other than Envoy
    "admin-404-not-envoy": lambda w: w["ent-client"].update(pop_https_admin=curl_404(server="nginx")),
    "lease-on-gpu": lambda w: w["k8s-cp1"].update(leases=w["k8s-cp1"]["leases"].replace('"holderIdentity": "k8s-cp1"', '"holderIdentity": "k8s-gpu1"', 1)),
    "cilium-devices": lambda w: w["k8s-cp1"].update(cilium_config=w["k8s-cp1"]["cilium_config"].replace('"devices": "bond0 bond0.110"', '"devices": "eth0"')),
    "kube-proxy": lambda w: w["k8s-cp1"].update(daemonsets=json.dumps({"items": json.loads(w["k8s-cp1"]["daemonsets"])["items"] + [
        {"metadata": {"namespace": "kube-system", "name": "kube-proxy"}, "status": {}}]})),
    "stray-key": lambda w: w["bastion"].update(shared_keys="600 state/shared/cluster/ca/ca.key\nscanned state/shared"),
    "no-snat-pull": lambda w: w["inet-registry"].update(access_log=""),
    # not a fault: the nodes' pulls, then an hour of the image's own healthcheck from 127.0.0.1 in
    # both of the registry's line formats, as chapter 3's lab logged them; the collector must keep
    # the pulls (ch03/RESULTS.md, problem 2)
    "healthcheck-flood": lambda w: w["inet-registry"].update(access_log=w["inet-registry"]["access_log"] + "\n" + "\n".join(
        '\x1b[34mINFO\x1b[0m[4217] response completed \x1b[34mhttp.request.host\x1b[0m="127.0.0.1:5000" '
        f'\x1b[34mhttp.request.remoteaddr\x1b[0m="127.0.0.1:{40000 + i}" \x1b[34mhttp.request.uri\x1b[0m="/v2/"\n'
        f'127.0.0.1 - - [20/Oct/2026:11:{i % 60:02d}:00 +0000] "GET /v2/ HTTP/1.1" 200 2 "" "Wget"' for i in range(360))),
    "ntp-silent": lambda w: [w[n].update(ntp_resolvers="socket.timeout: timed out\nsocket.timeout: timed out") for n in ("k8s-cp2",)],
    # the secondary behind the primary: a transfer that never happened
    "secondary-stale": lambda w: w["dns-auth2"].update(zonestatus=w["dns-auth2"]["zonestatus"].replace("serial: ", "serial: 1", 1)),
    # the reference answering without NTS
    "nts-off": lambda w: w["dns-res1"].update(chrony_authdata=w["dns-res1"]["chrony_authdata"].replace(" NTS ", " -   ")),
    # a DNS server left running on the jump host
    "bastion-named": lambda w: w["bastion"].update(services=w["bastion"]["services"].replace("named absent", "named running")),
    "enterprise-sees-infra": lambda w: w["ent-client"].update(pop_dns_infra="10.20.1.11"),
    "router-no-vrf": lambda w: w["uplink-rtr"].update(link_eth0=json.dumps([{"ifname": "eth0", "operstate": "UP"}])),
    # Docker's search line kept: the lab host's domain (a stand-in, .invalid) in place of the lab's,
    # beside it, or no search line at all
    "client-host-search": lambda w: w["ops-client"].update(resolv_conf="search lab-host.invalid\nnameserver 127.0.0.11\noptions ndots:0"),
    "router-host-search": lambda w: w["uplink-rtr"].update(resolv_conf="search tarnwick.example lab-host.invalid other.invalid\nnameserver 127.0.0.11"),
    "registry-no-search": lambda w: w["inet-registry"].update(resolv_conf="nameserver 127.0.0.11\noptions ndots:0"),
    # another FRR release, on a stand-in host kernel release that the FAIL detail must not print
    "frr-other-release": lambda w: w["uplink-rtr"].update(
        frr_version="FRRouting 10.4.1_git (uplink-rtr) on Linux(9.9.9-stand-in+).\nCopyright 1996-2005 Kunihiro Ishiguro, et al."),
    "nfs-closed": lambda w: w["k8s-gpu1"].update(storage_ports="2049 closed"),
    "cluster-failed": lambda w: w["k8s-cp1"].update(cluster_unit="ActiveState=failed\nSubState=failed\nExecMainStatus=1\n"
                                                                "ExecMainExitTimestampMonotonic=93456789\nNRestarts=5"),
}


# faults the shims show on their own (a probe's answer, not a saved file): the world stays healthy
SHIM_FAULTS = {"nvme-closed"}


def break_world(files: dict, fault: str) -> dict:
    w = copy.deepcopy(files)
    if fault not in SHIM_FAULTS:
        FAULTS[fault](w)
    return w
