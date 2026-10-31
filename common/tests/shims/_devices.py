#!/usr/bin/env python3
"""A healthy sfab-m1, as ssh, sshpass and curl would see it, for common/tests/test_stages.py.

Every answer is built from the lab's inventory ($SHIM_INV): switch sessions (sonic-cli) print the
hostname prompt and the output KLISH would, the firewall CLI prints admin@fw> prompts, guests
answer their probe commands. $SHIM_BREAK names one fault to show instead (session-down).
"""
import json
import os
import re
import shlex
import sys

INV = json.load(open(os.environ["SHIM_INV"]))
NODES = INV["nodes"]
BY_IP = {n["mgmt"]: name for name, n in NODES.items()}
BREAK = os.environ.get("SHIM_BREAK", "")


def log(argv):
    with open(os.environ["SHIM_LOG"], "a") as f:
        f.write(json.dumps(["ssh"] + argv) + "\n")


def nat(s):
    return [int(t) if t.isdigit() else t for t in re.split(r"([0-9]+)", s)]


def mclag_brief(sw):
    n = NODES[sw]
    m = n["mclag"]
    role = "active" if sw < m["peer"] else "standby"
    status = "down" if BREAK == "session-down" and sw == "fe-sw2" else "up"
    pcs = [p for p, v in sorted(n["portchannels"].items(), key=lambda kv: nat(kv[0])) if v["mclag"]]
    return "\n".join([
        " ", f"Domain ID            : {m['domain']}", f"Role                 : {role}",
        f"Session Status       : {status}", "Peer Link Status     : up",
        f"Source Address       : {m['source_ip']}", f"Peer Address         : {m['peer_ip']}",
        f"Session Vrf          : {m['session_vrf']}", f"Peer Link            : {m['peer_link']}",
        "Keepalive Interval   : 1 secs", "Session Timeout      : 30 secs", "Delay Restore        : 300 secs",
        "System Mac           : 0c:00:12:34:56:06", f"Mclag System Mac     : {m['system_mac']}", " ", " ",
        "Backup Keepalive Session Information:", "-----------------------------------",
    ] + ([f"Session Vrf          : {m['backup']['vrf']}", f"Session Status       : {status}",
          f"Source Address       : {m['backup']['source_ip']}", f"Peer Address         : {m['backup']['peer_ip']}",
          f"Keepalive Interval   : {m['backup']['interval']} secs"] if m.get("backup") else
         ["Session Vrf          : default", "Source Address       : "]) + [
        "-----------------------------------", " ",
        f"Number of MLAG Interfaces:{len(pcs)}", "-" * 59, "MLAG Interface       Local/Remote Status ", "-" * 59,
    ] + [f"{p}            up/up" for p in pcs])


def pc_summary(sw):
    out = ["Flags(oper-status):  D - Down U - Up (portchannel) P - Up in portchannel (members) I - LACP individual",
           "-" * 92, "Group               PortChannel                   Type                Protocol          Member Ports", "-" * 92]
    for p, v in sorted(NODES[sw]["portchannels"].items(), key=lambda kv: nat(kv[0])):
        mem = v["members"]
        out.append(f"{v['id']:<20}{p:<15}(U)            Eth                 LACP              {mem[0]}(P)")
        out += [" " * 88 + f"{x}(P)" for x in mem[1:]]
    return "\n".join(out)


def show_vlan(sw):
    n = NODES[sw]
    want = {v: {} for v in n["vlans"]}
    for p, v in n["portchannels"].items():
        for vid in v["vlans"]:
            # the peer link also carries the backup keepalive's VLAN, which is no served VLAN
            want.setdefault(vid, {})[p] = "T" if v["mode"] == "trunk" else "A"
        # an access PortChannel that also carries VLANs tagged (switchport trunk allowed Vlan N)
        for vid in v.get("tagged") or []:
            want.setdefault(vid, {})[p] = "T"
    for native, a in n["access"].items():
        want[a["vlan"]][native] = "A"
    out = ["Q: A - Access (Untagged), T - Tagged", "NUM        Status      Q Ports            Autostate   Dynamic     "]
    for vid in sorted(want):
        ports = sorted(want[vid].items(), key=lambda kv: nat(kv[0]))
        if not ports:
            out.append(f"{vid:<11}Active")
            continue
        for i, (p, q) in enumerate(ports):
            head = f"{vid:<11}Active      " if i == 0 else " " * 23
            out.append(f"{head}{q}  {p:<17}{'Enable' if i == 0 else '':<12}No")
    return "\n".join(out)


def mac_table(sw):
    n = NODES[sw]
    rows = ["-" * 60, "VLAN     MAC Address         Type          Interface", "-" * 60]
    for p, v in n["portchannels"].items():
        peer = v["peer_node"]
        if peer and NODES[peer]["kind"] == "vm-node":
            mac = NODES[peer]["bond"]["mac"]
            rows.append(f"{v['vlans'][0]:<9}{mac}   DYNAMIC       {p}")
        if v["mode"] == "trunk" and v["peer_node"]:
            rows.append(f"1        aa:c1:ab:00:01:01   DYNAMIC       {p}")
            rows.append(f"100      0c:00:aa:bb:cc:01   DYNAMIC       {p}")
    for native, a in n["access"].items():
        peer, eth = a["peer"].split(":")
        mac = NODES[peer]["nics"][eth].get("mac") or "0c:00:aa:bb:cc:03"
        rows.append(f"{a['vlan']:<9}{mac}   DYNAMIC       {native}")
    return "\n".join(rows)


OPENS = ("interface ", "mclag domain", "router ", "vrf ")


def ip_interfaces(sw):
    rows = [f"Management0          {NODES[sw]['mgmt']}/24                              mgmt                up/up"]
    ka = NODES[sw].get("keepalive")
    if ka:
        for ifn, a in sorted(((ka["port"], ka["address"]), (ka.get("backup_interface"), ka.get("backup_address"))), key=lambda x: nat(str(x[0]))):
            if ifn:
                rows.append(f"{ifn:<21}{a:<45}{ka['vrf']:<20}up/up")
    return "\n".join(["Flags: U-Unnumbered interface, A-Anycast IP", "-" * 89,
                      "Interface            IP address/mask                              VRF                 Admin/Oper     Flags          ",
                      "-" * 89] + rows)


def ip_route_vrf(sw):
    ka = NODES[sw].get("keepalive") or {}
    out = ["Codes:  K - kernel route, C - connected, S - static, B - BGP, O - OSPF, A - attached-host",
           "        > - selected route, * - FIB route, q - queued route, r - rejected route, b - backup",
           "       Destination        Gateway                                                                    Dist/Metric   Last Update ", "-" * 128]
    import ipaddress
    for ifn, a in ((ka.get("port"), ka.get("address")), (ka.get("backup_interface"), ka.get("backup_address"))):
        if ifn and a:
            out.append(f" C>*   {str(ipaddress.ip_interface(a).network):<19}Direct                          {ifn:<43}0/0           00:10:00 ago")
    return "\n".join(out)


def interface_status(sw):
    n = NODES[sw]
    mtu = {}
    for p, v in n["portchannels"].items():
        for mb in v["members"]:
            mtu[mb] = v.get("mtu") or 9100
        mtu[p] = v.get("mtu") or 9100
    for nat_, a in n["access"].items():
        mtu[nat_] = a.get("mtu") or 9100
    ka = n.get("keepalive")
    if ka:
        mtu[ka["port"]] = ka.get("mtu") or 9100
    out = ["-" * 134, "Name                Description                   Oper        Reason         AutoNeg   Speed          MTU            Alternate Name      ", "-" * 134]
    for k in sorted(mtu, key=nat):
        out.append(f"{k:<20}{'-':<30}{'up':<12}{'oper-up':<17}{'off':<10}{'25000':<15}{mtu[k]:<15}Eth1/1")
    return "\n".join(out)


def bpdu_guard(sw):
    edge = NODES[sw].get("edge") or []
    shut = "Y" if BREAK == "bpdu-tripped" else "N"
    return "\n".join(["PortNum          Shutdown    Port shut          ", "                 Configured  due to BPDU guard  "]
                     + [f"{e:<17}Y           {shut}                  " for e in edge])


def storm_control(sw):
    st = NODES[sw].get("storm") or {}
    out = ["-" * 53, "Interface Name      Storm-type          Rate (kbps)    ", "-" * 53]
    for pt in st.get("ports") or []:
        for t, k in sorted((st.get("kbps") or {}).items()):
            out.append(f"{pt:<20}{t:<20}{k:<15}")
    return "\n".join(out)


def running_config(sw):
    """The running configuration a switch shows after taking its rendered startup file whole."""
    src = os.path.join(os.environ.get("SHIM_RENDER", ""), "bootstrap", sw, "startup-config.cfg")
    if os.path.isfile(src):
        out, in_block = ["!"], False
        for raw in open(src):
            line = raw.strip()
            if not line or line.startswith("!") or line in ("configure terminal", "end"):
                if line == "end" and in_block:
                    out.append("!")
                    in_block = False
                continue
            if line == "exit":
                if in_block:
                    out.append("!")
                in_block = False
                continue
            if line.startswith(OPENS) and not in_block:
                out.append(line)
                in_block = True
            elif in_block:
                out.append(" " + line)
            else:
                out += [line, "!"]
        return "\n".join(out)
    n = NODES[sw]
    out = ["!", "ip vrf mgmt", "!", f"hostname {sw}", "!"]
    for v in n["vlans"]:
        out += [f"interface Vlan{v}", "!"]
    for p, v in sorted(n["portchannels"].items(), key=lambda kv: nat(kv[0])):
        out += [f"interface {p} mode active min-links 1", " no shutdown", "!"]
    return "\n".join(out)


KLISH = {
    "terminal length 0": lambda sw: "",
    "show version": lambda sw: "Software Version : 4.6.0-Enterprise_Base\nHwSKU            : DellEMC-S5248f-P-25G-DPB",
    "show ip interfaces": ip_interfaces,
    "show running-configuration spanning-tree": lambda sw: f"spanning-tree mode {NODES[sw]['stp']}" if NODES[sw].get("stp") else "",
    "show spanning-tree bpdu-guard": bpdu_guard,
    "show storm-control": storm_control,
    "show ip route": lambda sw: "",
    "show ip vrf": lambda sw: "VRF-NAME                        Interfaces\n----------------------------------\nmgmt                            Management0",
    "show running-configuration": running_config,
    "show running-configuration | grep router": lambda sw: "",
    "show vlan": show_vlan,
    "show mac address-table": mac_table,
    "show interface status": interface_status,
    "show mclag brief": mclag_brief,
    "show PortChannel summary": pc_summary,
    "show running-configuration mclag": lambda sw: "mclag domain 1",
    "show interface counters": lambda sw: "Interface  State  RX_OK  TX_OK\nEthernet0  U  10  10",
}


def sonic_cli(sw):
    for line in sys.stdin.read().splitlines():
        echo = "show vlanVlan" if line == "show vlan" else line
        print(f"{sw}# {echo}")
        if line == "exit":
            return 0
        fn = KLISH.get(line) or (ip_route_vrf if line.startswith("show ip route vrf ") else None)
        print(fn(sw) if fn else "% Error: Invalid input detected at \"^\" marker.")
    return 0


# PAN-OS formats as the PA-VM 12.1.2 prints them (the M1 deploy's captures), filled from the inventory.
def panos_interface_all(fw):
    ifs = NODES[fw]["interfaces"]
    hw = [n for n, i in sorted(ifs.items(), key=lambda kv: nat(kv[0])) if i["kind"] in ("aggregate-member", "layer3", "aggregate") and i.get("connected")]
    out = [f"total configured hardware interfaces: {len(hw)}", "",
           "name                    id    speed/duplex/state            mac address       ", "-" * 80]
    for i, n in enumerate(hw):
        sp = "[n/a]/[n/a]/up" if ifs[n]["kind"] == "aggregate" else "10000/full/up"
        out.append(f"{n:<24}{16 + i:<6}{sp:<30}0c:00:aa:bb:cc:{i:02x} ")
    logical = [n for n, i in sorted(ifs.items(), key=lambda kv: nat(kv[0])) if i.get("connected") and i["kind"] in ("layer3", "aggregate", "subinterface")]
    out += ["", "", f"total configured logical interfaces: {len(logical)}", "",
            "name                      id    vsys zone             forwarding               tag    address                                         ",
            "------------------------- ----- ---- ---------------- ------------------------ ------ ------------------"]
    for i, n in enumerate(logical):
        tag = n.split(".", 1)[1] if "." in n else "0"
        addr = ifs[n].get("address") or "N/A"
        fwd = "vr:core" if ifs[n].get("address") else "N/A"
        out.append(f"{n:<26}{256 + i:<6}{'1':<5}{ifs[n].get('zone') or '':<17}{fwd:<25}{tag:<7}{addr:<18}")
    return "\n".join(out)


def panos_lacp(fw):
    """show lacp aggregate-ethernet all, in the layout the PA-VM printed in M2's record set."""
    mem = [n for n, i in sorted(NODES[fw]["interfaces"].items(), key=lambda kv: nat(kv[0])) if i["kind"] == "aggregate-member"]
    out = ["", "LACP:", "", "*" * 82, "AE group: ae1", "Members:                Bndl Rx state       Mux state  Sel state"]
    out += [f"  {m:<22}yes  Current        Tx_Rx      Selected" for m in mem]
    out += ["Status:           Enabled", "Mode:             Active", "Rate:             Fast",
            "Local:            System Priority: 32768", "                  System MAC:      0c:00:aa:bb:cc:01", "                  Key:             240",
            "Partner:          System Priority: 65535", "                  System MAC:      02:5a:00:00:00:01", "                  Key:             10",
            "Port State", "-" * 80, "Interface                       Port", "                    Number Priority  Mode    Rate  Key      State", "-" * 80]
    for i, m in enumerate(mem):
        out += [f"{m:<21}{16 + i:<7}32768    Active  Fast  240      0x3F", "Partner              3      255      Active  Fast  10       0x3F", ""]
    return "\n".join(out)


def panos_subif(fw, name):
    i = NODES[fw]["interfaces"].get(name) or {}
    return "\n".join(["", "-" * 80, f"Name: {name}, ID: 256, 802.1q tag: {name.split('.', 1)[-1]}", "Operation mode: layer3",
                      "Virtual router core", "Interface MTU 9216", f"Interface IP address: {i.get('address')}",
                      f"Zone: {i.get('zone')}, virtual system: vsys1", "-" * 80])


def panos_vpn(fw, what):
    """show vpn ike-sa / ipsec-sa as the PA-VM prints them with each rendered tunnel up."""
    vpns = NODES[fw].get("vpns") or []
    if what == "ike-sa":
        out = ["", "There is no IKEv1 phase-1 SA found.", "", "There is no IKEv1 phase-2 SA found.", "", "", "IKEv2 SAs",
               "Gateway ID      Peer-Address                            Gateway Name                                                    Role SN       "
               "Algorithm                                                        Established     Expiration      Xt Child  ST"]
        for i, x in enumerate(vpns, 1):
            out.append(f"{i:<16}{x['peer']:<40}{x['name']:<64}Resp {i:<9}{'PSK/DH14/A256/SHA256':<65}Oct.20 09:20:25 Oct.20 17:20:25 0  "
                       f"{len(x.get('proxy_ids') or [])}      Established")
        out += ["", f"Show IKEv2 SA: Total {len(vpns)} gateways found. {len(vpns)} ike sa found."]
        return "\n".join(out)
    out = ["", "GwID/client IP  TnID   Peer-Address                            Tunnel(Gateway)"]
    n = 0
    for i, x in enumerate(vpns, 1):
        for pid, *_ in x.get("proxy_ids") or []:
            n += 1
            out.append(f"{i:<16}{n:<7}{x['peer']:<40}{x['name']}:{pid}({x['name']})   ESP/A256/SHA256/DH14   3600/Unlimited   2168")
    out += ["", f"Show IPSec SA: Total {n} tunnels found. {n} ipsec sa found."]
    return "\n".join(out)


def bmc_addr(g):
    o = NODES[g].get("oob") or {}
    a, _, plen = str(o.get("address") or "").partition("/")
    return json.dumps([{"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
                       {"ifname": o.get("eth") or "eth3", "addr_info": [{"family": "inet", "local": a, "prefixlen": int(plen or 24)}]}])


def bmc_listen(g):
    a = str((NODES[g].get("oob") or {}).get("address") or "").split("/")[0]
    return f"LISTEN 0      128    {a}:22  0.0.0.0:*\nLISTEN 0      16        0.0.0.0:443 0.0.0.0:*"


def panos_cli(fw):
    mode = ">"
    enforced = os.environ.get("SHIM_FW_ENFORCED", "")
    for line in sys.stdin.read().splitlines():
        print(f"admin@{fw}{mode} {line}")
        if line == "configure":
            mode = "#"
            print("Entering configuration mode\n[edit]")
        elif line == "exit":
            if mode == "#":
                mode = ">"
                continue
            return 0
        elif line == "show" and mode == "#":
            print(open(enforced).read() if enforced else "")
            print("[edit]")
        elif line == "show lacp aggregate-ethernet all":
            print(panos_lacp(fw))
        elif line.startswith("show interface ae1."):
            print(panos_subif(fw, line.split()[-1]))
        elif line == "show interface all":
            print(panos_interface_all(fw))
        elif line in ("show vpn ike-sa", "show vpn ipsec-sa"):
            print(panos_vpn(fw, line.split()[-1]))
        elif line.startswith("show"):
            print("ok")
    return 0


def switch_shell(sw, cmd):
    n = NODES[sw]
    if "vtysh -c" in cmd:
        return "Building configuration...\n!\nfrr version 8.2.2\n!\nend"
    if cmd.startswith("ip -j addr"):
        return json.dumps([
            {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
            {"ifname": "eth0", "addr_info": [{"family": "inet", "local": n["mgmt"], "prefixlen": 24, "scope": "global"}]},
            {"ifname": "lo-m", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"}]},
            {"ifname": "docker-mgmt", "addr_info": [{"family": "inet", "local": "240.127.10.10", "prefixlen": 24, "scope": "global"}]},
            {"ifname": "Vlan100", "addr_info": []},
        ] + [{"ifname": ifn, "addr_info": [{"family": "inet", "local": a.split("/")[0], "prefixlen": int(a.split("/")[1]), "scope": "global"}]}
             for ka in [n.get("keepalive") or {}] for ifn, a in ((ka.get("port"), ka.get("address")), (ka.get("backup_interface"), ka.get("backup_address")))
             if ifn and a])
    if "ethtool -k" in cmd:
        return "\n".join(f"== eth{i}\ngeneric-receive-offload: off\nrx-gro-hw: off [fixed]\nlarge-receive-offload: off [fixed]"
                         for i in range(1, n["num_nics"] + 1))
    if "sonic-cfggen" in cmd:
        return "{}"
    mc = n.get("mclag") or {}
    if cmd.startswith("sudo ss -tanp") and mc:
        # as SONiC 4.6.0 prints it: iccpd listening in VRF mgmt, and one established session
        me, peer, vrf = mc["source_ip"], mc["peer_ip"], mc["session_vrf"]
        active = me < peer
        est = (f"ESTAB     0      0     {me}%{vrf}:56537 {peer}:8888  users:((\"iccpd\",pid=4601,fd=24))" if active
               else f"ESTAB     0      0     {me}%{vrf}:8888  {peer}:56537 users:((\"iccpd\",pid=4601,fd=24))")
        return f"LISTEN    0      20    0.0.0.0%{vrf}:8888       0.0.0.0:*     users:((\"iccpd\",pid=4601,fd=16))\n{est}"
    if "mclagdctl" in cmd and mc:
        role = "Active" if mc["source_ip"] < mc["peer_ip"] else "Standby"
        return f"The MCLAG's keepalive is: OK\nMCLAG info sync is: completed\nDomain id: {mc['domain']}\nRole: {role}"
    return ""


def bonding(mac, members=("eth1", "eth2"), partner="02:5a:00:00:00:01", state=63, agg=None):
    """/proc/net/bonding/bond0 as the kernel prints it (M2's record set), every leg aggregated."""
    agg = agg or {}
    out = ["Ethernet Channel Bonding Driver: v6.8.0", "", "Bonding Mode: IEEE 802.3ad Dynamic link aggregation",
           "Transmit Hash Policy: layer3+4 (1)", "MII Status: up", "", "802.3ad info", "LACP active: on", "LACP rate: fast",
           f"System MAC address: {mac}", "Active Aggregator Info:", "\tAggregator ID: 1",
           f"\tNumber of ports: {sum(1 for m in members if agg.get(m, 1) == 1)}", "\tActor Key: 15", "\tPartner Key: 21",
           f"\tPartner Mac Address: {partner}", ""]
    for i, m in enumerate(members, 1):
        out += [f"Slave Interface: {m}", "MII Status: up", "Speed: 10000 Mbps", "Duplex: full", f"Aggregator ID: {agg.get(m, 1)}",
                "details actor lacp pdu:", "    system priority: 65535", f"    system mac address: {mac}", "    port key: 15",
                f"    port number: {i}", f"    port state: {state}", "details partner lacp pdu:", "    system priority: 65535",
                f"    system mac address: {partner}", "    oper key: 21", "    port number: 7", f"    port state: {state}", ""]
    return "\n".join(out)


def guest(g, cmd):
    n = NODES[g]
    if cmd.startswith("systemctl show"):
        return "Result=success\nExecMainStatus=0\nExecMainExitTimestampMonotonic=41234567\nActiveState=active"
    if cmd.startswith("cat /proc/net/bonding"):
        return bonding(n["bond"]["mac"] or "0c:00:aa:bb:cc:02", n["bond"]["members"])
    if cmd.startswith("ip -j addr"):
        return "[]"
    if cmd.startswith("ip rule"):
        return f"0:\tfrom all lookup local\n150:\tfrom {n['mgmt']} lookup 150"
    if cmd == "ip route show table 150":
        return f"default via {INV['mgmt']['gw']} dev eth0"
    if cmd.startswith("ip route show table"):
        return "default via 10.20.9.254 dev eth3"
    if cmd.startswith("for i in"):
        names = cmd.split(" in ", 1)[1].split(";", 1)[0].split()
        return "\n".join(f"{x} tx-checksumming: off" for x in names)
    if "ping" in cmd:
        return "PING x\n3 packets transmitted, 3 received, 0% packet loss, time 2003ms"
    m = re.match(r"(?:sudo )?ip -n (\S+) -j addr show$", cmd)
    if m and (n.get("oob") or {}).get("netns") == m.group(1):
        return bmc_addr(g)
    m = re.match(r"(?:sudo )?ip netns exec (\S+) ss -ltnH$", cmd)
    if m and (n.get("oob") or {}).get("netns") == m.group(1):
        return bmc_listen(g)
    if cmd == "ip netns list":
        return "\n".join(f"gpu{r} (id: {r})" for r in range(1, 9))
    m = re.match(r"ip -n (gpu(\d+)) route show", cmd)
    if m:
        r = int(m.group(2))
        return f"10.21.{r % 8 + 1}.0/24 via 10.21.250.{r % 8 + 1} dev relay src 10.21.{r}.11\n10.21.{r}.0/24 dev rail{r} scope link"
    m = re.match(r"ip netns exec (gpu(\d+)) sh -c", cmd)
    if m:
        return f"all 0\ndefault 2\nlo 0\nrail{m.group(2)} 2\nrelay 2"
    m = re.match(r"ip -n gpu(\d+) route get (\S+)", cmd)
    if m:
        dst = m.group(2)
        return f"{dst} via 10.21.250.{dst.split('.')[2]} dev relay src 10.21.{m.group(1)}.11 uid 0"
    return ""


def ssh(argv):
    log(argv)
    i, target = 0, None
    while i < len(argv):
        a = argv[i]
        if a in ("-o", "-i", "-p", "-l"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        target = a
        break
    rest = argv[i + 1:]
    user, host = target.split("@", 1)
    node = BY_IP[host]
    remote = " ".join(rest)
    if not remote:
        return panos_cli(node)
    if remote == "sonic-cli":
        return sonic_cli(node)
    if NODES[node]["kind"] == "dell_sonic":
        print(switch_shell(node, remote))
        return 0
    parts = shlex.split(remote)
    if parts[:3] == ["sudo", "bash", "-c"]:
        print(guest(node, parts[3]))
        return 0
    return 0


def sshpass(argv):
    assert argv[0] == "-e" and os.environ.get("SSHPASS"), "sshpass -e with SSHPASS set"
    assert "shimpw" not in " ".join(argv), "the password must never be on a command line"
    return ssh(argv[2:])


def curl(argv):
    with open(os.environ["SHIM_LOG"], "a") as f:
        f.write(json.dumps(["curl"] + argv) + "\n")
    url = argv[-1]
    if "type=keygen" in url:
        # stand-in values: a made-up API key in the LUFRPT form PAN-OS keys take
        print("<response status='success'><result><key>LUFRPTshimkey0123456789abcdef==</key></result></response>")
    else:
        print("<response status='success'><result><ifnet><entry><name>ae1.100</name><state>up</state></entry></ifnet></result></response>")
    return 0


if __name__ == "__main__":
    tool = sys.argv[1]
    sys.exit({"ssh": ssh, "sshpass": sshpass, "curl": curl}[tool](sys.argv[2:]))
