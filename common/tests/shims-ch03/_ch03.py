#!/usr/bin/env python3
"""Stand-ins for sfab-ch03's drills and break-3a, for common/tests/test_ch03.py.

They model what drills.sh and breakheal.sh do to the lab and what the probes would see, and hand
everything else to the M2 stand-ins (common/tests/shims-m2/), which hand the rest to the shared ones.
The world lives in $SHIM_CH03_STATE (JSON); times are the host clock, as the harness's are.

The model, deliberately simple and deterministic (made-up figures, never the book's):
- a ping id leaves k8s-gpu1 on eth1 (fe-sw1) when it is even, on eth2 (fe-sw2) when it is odd, and its
  reply comes back the same way; a TCP connect's SYN leaves the firewall on ethernet1/1 (fe-sw1)
  when its source port is even, else ethernet1/2;
- a KLISH shutdown of k8s-gpu1's member on a switch loses the requests sent on that leg for 3 s (the
  LACP timeout), after which the id rides the other leg until 1 s after no shutdown;
- a shutdown of the firewall's member on a switch fails the connects whose SYN takes that leg for
  3 s, after which every SYN takes the other leg until 1 s after no shutdown;
- the peer link shut costs no ping and no connect; the orphan probe's odd attempts fail meanwhile;
- sudo reboot on a switch: its PortChannels go traffic-disabled for 2 s while it still answers,
  then its management stops answering until 8 s after the command; each bond's leg toward it
  leaves the aggregator from 1 s after the command until 2 s after its return, and one request on
  that leg is lost at each move;
- a shutdown of the active's dedicated keepalive link: the session is lost KA_TIMEOUT_S after it
  (iccpd's keepalive ERROR on both switches until KA_UP_S after no shutdown); with the peer link up (the backup
  keepalive alive) the standby then shuts its own MCLAG PortChannels until DELAY_RESTORE_S after
  no shutdown, so each bond's leg toward the standby loses its requests for LACP_S, then rides the
  other leg; with the peer link shut too nothing is shut and nothing is held;
- break-3a's VLAN 200 removal on fe-sw2 fails every third of the bastion's storage connects;
- break-3b's shut of fe-sw1's leg toward TrueNAS's management bond (Ethernet11, PortChannel32's only
  member there): show mclag brief reads PortChannel32 down/up on fe-sw1 and up/down on fe-sw2 until
  no shutdown, and every storage connect succeeds.
"""

import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
M2 = HERE.parent / "shims-m2" / "_m2.py"
SHARED = HERE.parent / "shims"
INV = json.load(open(os.environ["SHIM_INV"]))
NODES = INV["nodes"]
BY_IP = {n["mgmt"]: name for name, n in NODES.items()}
PREFIX = INV["prefix"]
STATE = os.environ["SHIM_CH03_STATE"]
LACP_S, REBOOT_UP_S, REBOOT_DOWN_S = 3.0, 2.0, 8.0
KA_TIMEOUT_S, KA_UP_S, DELAY_RESTORE_S = 1.0, 1.5, 4.0


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(s):
    tmp = f"{STATE}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(s, f, indent=1, sort_keys=True)
    os.replace(tmp, STATE)


class locked:
    """The world's lock: every change is load, change, save under it (stand-ins run in parallel)."""

    def __enter__(self):
        import fcntl  # noqa: PLC0415
        self.f = open(STATE + ".lock", "w")
        fcntl.flock(self.f, fcntl.LOCK_EX)
        return self

    def __exit__(self, *a):
        import fcntl  # noqa: PLC0415
        fcntl.flock(self.f, fcntl.LOCK_UN)
        self.f.close()


def log(tool, argv):
    with open(os.environ["SHIM_LOG"], "a") as f:
        f.write(json.dumps([tool + "-ch03"] + argv) + "\n")


def delegate(tool, argv, stdin=None):
    r = subprocess.run([sys.executable, str(M2), tool] + argv, input=stdin, text=True, capture_output=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


# ---------------------------------------------------------------------------- the world's faults

def shuts(s):
    """[(switch, port, since, until or None)]"""
    return [(x["sw"], x["port"], x["t"], x.get("until")) for x in s.get("shuts") or []]


def member_of(sw, native):
    for pc, v in (NODES[sw].get("portchannels") or {}).items():
        if native in v.get("members") or []:
            return pc, v
    return None, None


def fault_on(s, sw, peer_node, t):
    """The shut of SW's member facing PEER_NODE that covers time t: (since, until) or None."""
    for fsw, port, a, b in shuts(s):
        if fsw != sw:
            continue
        pc, v = member_of(sw, port)
        if v and v.get("peer_node") == peer_node and a <= t and (b is None or t < b + 1.0):
            return a, b
    return None


def peer_link_shut(s, t):
    for fsw, port, a, b in shuts(s):
        pc, v = member_of(fsw, port)
        if v and v.get("kind") == "peer-link" and a <= t and (b is None or t < b):
            return True
    return False


def ka_cut(s, t):
    """The keepalive link's shut covering t, the session coming back KA_UP_S after no shutdown:
    (since, until or None), or None."""
    for fsw, port, a, b in shuts(s):
        if port == ((NODES[fsw].get("keepalive") or {}).get("port")) and a <= t and (b is None or t < b + KA_UP_S):
            return a, b
    return None


def standby_name():
    return next((sw for sw, n in NODES.items() if (n.get("mclag") or {}) and n["mclag"]["source_ip"] > n["mclag"]["peer_ip"]), None)


def standby_held(s, sw, t):
    """(since, until) when SW, the standby, holds its MCLAG PortChannels down after a keepalive cut
    with the backup alive; None otherwise."""
    if sw != standby_name():
        return None
    for fsw, port, a, b in shuts(s):
        if port != ((NODES[fsw].get("keepalive") or {}).get("port")):
            continue
        down = a + KA_TIMEOUT_S
        if peer_link_shut(s, down):
            continue
        up = (b + DELAY_RESTORE_S) if b is not None else None
        if down <= t and (up is None or t < up):
            return down, up
    return None


def reboot_of(s, sw):
    return (s.get("reboots") or {}).get(sw)


def rebooting(s, sw, t):
    r = reboot_of(s, sw)
    return r is not None and r <= t < r + REBOOT_DOWN_S


def leg_switch(n, eth):
    return str(((NODES[n].get("nics") or {}).get(eth) or {}).get("peer") or "").split(":")[0]


def other_eth(eth):
    return "eth2" if eth == "eth1" else "eth1"


def legs_out(s, node, t):
    """A bonded host's legs in the active aggregator at t."""
    out = []
    for m in NODES[node]["bond"]["members"]:
        sw = leg_switch(node, m)
        r = reboot_of(s, sw)
        if r is not None and r + 1.0 <= t < r + REBOOT_DOWN_S + 2.0:
            continue
        f = fault_on(s, sw, node, t)
        if f and t >= f[0] + LACP_S:
            continue
        h = standby_held(s, sw, t)
        if h and t >= h[0] + LACP_S:
            continue
        out.append(m)
    return out


# ---------------------------------------------------------------------------- probe synthesis

def ping_frames(s, node, eth, now, runs=None):
    """tcpdump -nn -tt -e lines on NODE's container ETH for every ping probe so far (or RUNS)."""
    src, dst = "10.20.1.21", "10.20.1.22"
    out = []
    for run in (s.get("pings") or []) if runs is None else runs:
        stop = run.get("stop") or now
        for pid in run["ids"]:
            home = "eth1" if pid % 2 == 0 else "eth2"
            seq = 1
            while True:
                t = run["start"] + (seq - 1) * 0.1
                if t > min(stop, now):
                    break
                leg, lost = home, False
                sw = leg_switch("k8s-gpu1", home)
                f = fault_on(s, sw, "k8s-gpu1", t)
                if f:
                    if t < f[0] + LACP_S:
                        lost = True
                    else:
                        leg = other_eth(home)
                h = standby_held(s, sw, t)
                if h:
                    if t < h[0] + LACP_S:
                        lost = True
                    else:
                        leg = other_eth(home)
                r = reboot_of(s, sw)
                if r is not None:
                    if r + 1.0 <= t < r + 1.1 or r + REBOOT_DOWN_S + 2.0 <= t < r + REBOOT_DOWN_S + 2.1:
                        lost = True
                    elif r + 1.1 <= t < r + REBOOT_DOWN_S + 2.0:
                        leg = other_eth(home)
                if eth == leg:
                    mac = "02:5a:6f:00:00:01"
                    if node == "k8s-gpu1":
                        out.append(f"{t:.6f} {mac} > 02:5a:70:00:00:01, ethertype IPv4 (0x0800), length 98: {src} > {dst}: ICMP echo request, id {pid}, seq {seq}, length 64")
                    if not lost:
                        out.append(f"{t + 0.0004:.6f} 02:5a:70:00:00:01 > {mac}, ethertype IPv4 (0x0800), length 98: {dst} > {src}: ICMP echo reply, id {pid}, seq {seq}, length 64")
                        if node == "k8s-gpu2":
                            out.insert(len(out) - 1, f"{t + 0.0002:.6f} {mac} > 02:5a:70:00:00:01, ethertype IPv4 (0x0800), length 98: {src} > {dst}: ICMP echo request, id {pid}, seq {seq}, length 64")
                seq += 1
    return sorted(out, key=lambda l: float(l.split()[0]))


def tcp_attempts(s, now):
    """[(t, seq, ok, sport, leg)] of the connect loop so far."""
    run = s.get("tcp")
    if not run:
        return []
    out, seq = [], 0
    stop = run.get("stop") or now
    while True:
        t = run["start"] + seq * run["interval"]
        if t > min(stop, now):
            break
        sport = 40001 + seq
        home = "eth1" if sport % 2 == 0 else "eth2"
        leg, ok = home, True
        sw = leg_switch("fw", home)
        f = fault_on(s, sw, "fw", t)
        if f:
            if t < f[0] + LACP_S:
                ok = False
            else:
                leg = other_eth(home)
        out.append((t, seq, ok, sport, leg))
        seq += 1
    return out


def users_vip():
    """The users' Gateway VIP and the VLAN it rides inside (110 in revision 2: the ingress VLAN, tagged
    on the firewall's legs, the trunks and the ingress nodes' bonds; None when untagged there)."""
    import ipaddress  # noqa: PLC0415
    gw = next((g for g in (INV.get("gateways") or {}).values() if g.get("audience") == "enterprise"), {})
    vip = gw.get("vip") or "10.20.1.210"
    for n in NODES.values():
        for u in ((n.get("bond") or {}).get("vlan_ifs") or []) if isinstance(n, dict) else []:
            if u.get("address") and ipaddress.ip_address(vip) in ipaddress.ip_interface(u["address"]).network:
                return vip, u.get("vlan")
    return vip, None


def tcp_frames(s, eth, now):
    out = []
    for t, seq, ok, sport, leg in tcp_attempts(s, now):
        if leg != eth:
            continue
        vip, vlan = users_vip()
        hdr = f"ethertype 802.1Q (0x8100), length 78: vlan {vlan or 100}, p 0, ethertype IPv4 (0x0800), "
        out.append(f"{t + 0.0002:.6f} 0c:00:aa:bb:cc:f0 > 02:5a:67:00:00:01, {hdr}10.24.10.10.{sport} > {vip}.443: Flags [S], seq {1000 + seq}, length 0")
        if ok:
            out.append(f"{t + 0.0006:.6f} 02:5a:67:00:00:01 > 0c:00:aa:bb:cc:f0, {hdr}{vip}.443 > 10.24.10.10.{sport}: Flags [S.], seq 7, ack {1001 + seq}, length 0")
    return out


def ping_log(s, run, pid, now):
    """The guest's ping -D -O log for one id of one run, ended by SIGINT."""
    lines = ["PING 10.20.1.22 (10.20.1.22) 56(84) bytes of data."]
    stop = run.get("stop") or now
    seq, rx = 1, 0
    reps = {}
    for l in ping_frames(s, "k8s-gpu1", "eth1", now, [run]) + ping_frames(s, "k8s-gpu1", "eth2", now, [run]):
        m = re.search(r"echo reply, id (\d+), seq (\d+)", l)
        if m and int(m.group(1)) == pid:
            reps[int(m.group(2))] = float(l.split()[0])
    while True:
        t = run["start"] + (seq - 1) * 0.1
        if t > min(stop, now):
            break
        if seq in reps:
            rx += 1
            lines.append(f"[{reps[seq]:.6f}] 64 bytes from 10.20.1.22: icmp_seq={seq} ttl=64 time=0.412 ms")
        else:
            lines.append(f"[{t + 0.1:.6f}] no answer yet for icmp_seq={seq}")
        seq += 1
    tx = seq - 1
    lines += ["", "--- 10.20.1.22 ping statistics ---", f"{tx} packets transmitted, {rx} received, {100 * (tx - rx) // max(tx, 1)}% packet loss, time {int((stop - run['start']) * 1000)}ms"]
    return "\n".join(lines)


def orphan_log(s, now):
    run = s.get("orphan")
    if not run:
        return ""
    out, i = [], 0
    stop = run.get("stop") or now
    while True:
        t = run["start"] + i * run["interval"]
        if t > min(stop, now):
            break
        ok = 0 if (peer_link_shut(s, t) and i % 2 == 1) else 1
        out.append(f"{t:.6f} {i} {ok}")
        i += 1
    return "\n".join(out)


# ---------------------------------------------------------------------------- the four-point trace

def trace_decode(point: str) -> str:
    """tcpdump -nn -e -tttt -v -S -r for one of ch03's trace points, for the recorded SYN from
    ent-client to the users' VIP held by $SHIM_TRACE_HOLDER: ae1 leg 1 and fe-sw1's trunk port
    tagged with the VIP's VLAN (110, the ingress VLAN), fe-sw1's server port and the holder's bond0
    tagged the same (the ingress VLAN rides the bond tagged), all one frame; nothing on the
    other legs."""
    holder = os.environ.get("SHIM_TRACE_HOLDER", "k8s-ingress1")
    bmac = (NODES.get(holder, {}).get("bond") or {}).get("mac") or "02:5a:67:00:00:01"
    vip, vlan = users_vip()

    def syn(vlan, sport=41443, seq=1234567890):
        eth = (f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan
               else "ethertype IPv4 (0x0800), length 74: ")
        return (f"2026-10-20 10:00:01.000300 0c:00:aa:bb:cc:f0 > {bmac}, {eth}(tos 0x0, ttl 63, id 4321, offset 0, flags [DF], "
                f"proto TCP (6), length 60)\n    10.24.10.10.{sport} > {vip}.443: Flags [S], cksum 0x1a2b (correct), "
                f"seq {seq}, win 64240, options [mss 1460], length 0\n")
    if point in ("1-fw-ae1-leg1", "2-fe-sw1-Ethernet2"):
        return syn(vlan or 100, 41442, 99) + syn(vlan or 100)
    if point.startswith("3-fe-sw1-") or point.startswith("4-"):
        return syn(vlan)
    return ""


# ---------------------------------------------------------------------------- devices

def bonding_text(s, node, now):
    sys.path.insert(0, str(SHARED))
    os.environ.setdefault("SHIM_RENDER", "")
    import _devices  # noqa: PLC0415
    legs = legs_out(s, node, now)
    agg = {m: (1 if m in legs else 2) for m in NODES[node]["bond"]["members"]}
    return _devices.bonding(NODES[node]["bond"]["mac"] or "0c:00:aa:bb:cc:02", NODES[node]["bond"]["members"], agg=agg)


def monitor_line(s, sw, now):
    n = NODES[sw]
    peer = n["mclag"]["peer"]
    r = reboot_of(s, sw)
    ka = "ERROR" if (reboot_of(s, peer) is not None and reboot_of(s, peer) + 2.5 <= now < reboot_of(s, peer) + REBOOT_DOWN_S + 1.0) else "OK"
    if r is not None and r + REBOOT_DOWN_S <= now < r + REBOOT_DOWN_S + 1.0:
        ka = "ERROR"
    c = ka_cut(s, now)
    if c and now >= c[0] + KA_TIMEOUT_S:
        ka = "ERROR"
    held = standby_held(s, sw, now)
    role = "Active" if n["mclag"]["source_ip"] < n["mclag"]["peer_ip"] else "Standby"
    parts = [f"sys=running The MCLAG's keepalive is: {ka} Role: {role}"]
    rp = reboot_of(s, peer)
    for pc in sorted(n["portchannels"], key=lambda x: int(x[11:])):
        down = (r is not None and r <= now < r + REBOOT_UP_S + 0.5 or bool(held)) and pc != "PortChannel1"
        # the peer link goes down on the switch that stays up while its peer is away
        pl_down = pc == "PortChannel1" and rp is not None and rp + REBOOT_UP_S <= now < rp + REBOOT_DOWN_S + 0.5
        parts.append(f"{pc}={'down' if down or pl_down else 'up'}/td={'true' if down else 'false'}")
    return " ".join(parts)


def counters_json(s, sw, now):
    """ip -s -j link show in a switch container: packets grow at 2 a second on every link, 40 a
    second on the peer link of a switch whose firewall member is shut."""
    out = []
    for e in NODES[sw]["eths"]:
        rate = 2.0
        pl = (NODES[sw]["portchannels"].get("PortChannel1") or {}).get("member_eths") or []
        if e in pl and any(fsw == sw and member_of(sw, port)[1] and member_of(sw, port)[1].get("peer_node") == "fw" and a <= now
                           and (b is None or now < b) for fsw, port, a, b in shuts(s)):
            rate = 40.0
        base = int(now * 2)
        out.append({"ifname": e, "stats64": {"rx": {"packets": base}, "tx": {"packets": int(now * rate) if rate > 2 else base}}})
    return json.dumps(out)


def show_vlan(s, sw):
    sys.path.insert(0, str(SHARED))
    import _devices  # noqa: PLC0415
    text = _devices.show_vlan(sw)
    if not ((s.get("vlan_removed") or {}).get(sw)):
        return text
    out, cur = [], None
    for line in text.splitlines():
        m = re.match(r"^(\d+)\s", line)
        if m:
            cur = int(m.group(1))
        if cur == 200 and "PortChannel10" in line:
            if m:   # the VLAN's first row carries its number: keep the number, drop the port
                line = re.sub(r"\s+[AT]\s+PortChannel10\b", "", line)
            else:
                continue
        out.append(line)
    return "\n".join(out)


def mclag_brief(s, sw, now):
    """The shared stand-in's show mclag brief, with each MCLAG interface whose every member is shut
    (and not yet given no shutdown) down on its switch: down/up there, up/down on the peer."""
    sys.path.insert(0, str(SHARED))
    import _devices  # noqa: PLC0415
    peer = (NODES[sw].get("mclag") or {}).get("peer")

    def dead(x):
        out = set()
        for pc, v in (NODES.get(x, {}).get("portchannels") or {}).items():
            mem = v.get("members") or []
            if mem and all(any(f == x and p == m and a <= now and b is None for f, p, a, b in shuts(s)) for m in mem):
                out.add(pc)
        return out
    loc, rem = dead(sw), dead(peer) if peer else set()
    lines = []
    for line in _devices.mclag_brief(sw).splitlines():
        m = re.match(r"^(PortChannel\d+)(\s+)up/up$", line)
        if m:
            line = f"{m.group(1)}{m.group(2)}{'down' if m.group(1) in loc else 'up'}/{'down' if m.group(1) in rem else 'up'}"
        lines.append(line)
    return "\n".join(lines)


def running(s, sw):
    sys.path.insert(0, str(SHARED))
    import _devices  # noqa: PLC0415
    text = _devices.running_config(sw)
    if (s.get("vlan_removed") or {}).get(sw):
        out, cur = [], None
        for line in text.splitlines():
            if not line.startswith(" "):
                cur = line.strip()
            if cur in ("interface PortChannel 10", "interface PortChannel10") and line.strip().startswith("switchport trunk allowed Vlan "):
                keep = [v for v in line.split()[-1].split(",") if v != "200"]
                line = " switchport trunk allowed Vlan " + ",".join(keep)
            out.append(line)
        return "\n".join(out)
    return text


def sonic_cli(sw, data):
    with locked():
        return _sonic_cli(sw, data)


def _sonic_cli(sw, data):
    """A sonic-cli session: configuration lines change the world and answer with prompts; the
    show lines this chapter's tools read are answered here, the rest by the shared stand-in."""
    s = load()
    now = time.time()
    lines = data.splitlines()
    if not any(l.strip() == "configure terminal" for l in lines) and not any(
            l in ("show vlan", "show interface counters", "show running-configuration", "write memory", "show mclag brief") for l in lines):
        return None
    out, ctx = [], None
    mode = "#"
    # SHIM_CH03_CUT_RESTORE: the first session that types no shutdown loses its typed-ahead lines
    # after the interface line, as a real sonic-cli once did (the port stays shut)
    if os.environ.get("SHIM_CH03_CUT_RESTORE") and "no shutdown" in [l.strip() for l in lines] and not s.get("cut_done"):
        s["cut_done"] = True
        lines = lines[:next(i for i, l in enumerate(lines) if l.strip().startswith("interface ")) + 1]
    # SHIM_CH03_CUT_PAIR_READ: the first read of show PortChannel summary on fe-sw1 after a restore
    # ends right after its echo, nothing printed and no exit, as a real sonic-cli once did
    cut_read = bool(os.environ.get("SHIM_CH03_CUT_PAIR_READ") and sw == "fe-sw1" and "show PortChannel summary" in lines
                    and any(x.get("until") for x in s.get("shuts") or []) and not s.get("pair_cut_done"))
    if cut_read:
        s["pair_cut_done"] = True
    for line in lines:
        out.append(f"{sw}{mode} {'show vlanVlan' if line == 'show vlan' else line}")
        l = line.strip()
        if cut_read and l == "show PortChannel summary":
            break
        if l == "exit" and mode == "#":
            break
        if l == "configure terminal":
            mode = "(config)#"
            continue
        if l == "end":
            mode, ctx = "#", None
            continue
        if l == "exit":
            ctx = None
            mode = "(config)#"
            continue
        m = re.match(r"^interface (range )?(\S+)$", l)
        if m:
            ctx = m.group(2)
            mode = "(config-if)#"
            continue
        if l in ("shutdown", "no shutdown") and ctx:
            ports = [ctx]
            r = re.match(r"^Ethernet(\d+)-(\d+)$", ctx)
            if r:
                ports = [f"Ethernet{k}" for k in range(int(r.group(1)), int(r.group(2)) + 1)]
            for p in ports:
                if l == "shutdown":
                    s.setdefault("shuts", []).append({"sw": sw, "port": p, "t": now})
                else:
                    for x in s.get("shuts") or []:
                        if x["sw"] == sw and x["port"] == p and x.get("until") is None:
                            x["until"] = now
            continue
        if l.startswith("switchport trunk allowed Vlan") or l.startswith("no switchport trunk allowed Vlan"):
            if l == "switchport trunk allowed Vlan remove 200" and os.environ.get("SHIM_CH03_REFUSE_REMOVE"):
                out.append("% Error: Invalid input detected at \"^\" marker.")
                continue
            if l in ("switchport trunk allowed Vlan remove 200", "no switchport trunk allowed Vlan 200"):
                s.setdefault("vlan_removed", {})[sw] = now
            elif "200" in l.split()[-1]:
                (s.get("vlan_removed") or {}).pop(sw, None)
            continue
        if l == "write memory" or l == "terminal length 0":
            continue
        if l == "show vlan":
            out.append(show_vlan(s, sw))
        elif l == "show mclag brief":
            out.append(mclag_brief(s, sw, now))
        elif l == "show interface counters":
            out.append("Interface      State     RX_OK                 RX_ERR                RX_DRP                RX_OVERSIZE           TX_OK                 TX_ERR                TX_DRP                TX_OVERSIZE")
            for e in ("Ethernet0", "Ethernet1", "Ethernet2", "PortChannel1", "PortChannel10"):
                out.append(f"{e:<15}U         {int(now) % 100000:<22}0                     0                     0                     {int(now) % 100000:<22}0                     0                     0")
        elif l == "show running-configuration":
            out.append(running(s, sw))
        elif l.startswith("show"):
            sys.path.insert(0, str(SHARED))
            import _devices  # noqa: PLC0415
            fn = _devices.KLISH.get(l)
            out.append(fn(sw) if fn else "")
    save(s)
    return "\n".join(out)


def switch_shell(sw, cmd):
    with locked():
        return _switch_shell(sw, cmd)


def _switch_shell(sw, cmd):
    s = load()
    now = time.time()
    if cmd.strip() == "sudo reboot":
        s.setdefault("reboots", {})[sw] = now
        save(s)
        return "requested COLD shutdown", 255
    if "sonic-db-cli" in cmd:
        if rebooting(s, sw, now) and now >= reboot_of(s, sw) + REBOOT_UP_S:
            return "ssh: connect to host port 22: Connection refused", 255
        return monitor_line(s, sw, now), 0
    return None, 0


# ---------------------------------------------------------------------------- the tools

def target_of(argv):
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-o", "-i", "-p", "-l"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a, argv[i + 1:]
    return None, []


def guest_script(remote):
    if not remote.startswith(("sudo bash -c ", "sudo setsid bash -c ")):
        return None
    idx = 3
    if remote.startswith("sudo setsid bash -c "):
        remote, idx = remote.split(" </dev/null", 1)[0], 4
    r = subprocess.run(["bash", "-c", f'eval "a=($1)"; printf %s "${{a[{idx}]}}"', "_", remote], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def ssh(argv, data=None):
    target, rest = target_of(argv)
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = BY_IP.get(host)
    remote = " ".join(rest)
    if node and NODES[node]["kind"] == "dell_sonic":
        if remote == "sonic-cli":
            out = sonic_cli(node, data or "")
            if out is not None:
                log("sshpass", argv)
                print(out)
                return 0
        else:
            out, rc = switch_shell(node, remote)
            if out is not None:
                log("sshpass", argv)
                print(out)
                return rc
        return None
    if node and NODES[node]["kind"] == "paloalto_panos" and "show lacp aggregate-ethernet all" in (data or ""):
        s = load()
        now = time.time()
        away = [sw for sw in (s.get("reboots") or {}) if s["reboots"][sw] + 1.0 <= now < s["reboots"][sw] + REBOOT_DOWN_S + 2.0]
        if away:
            sys.path.insert(0, str(SHARED))
            import _devices  # noqa: PLC0415
            text = _devices.panos_lacp(node)
            for eth, nic in NODES[node]["nics"].items():
                if nic.get("role") == "bundle-member" and str(nic["peer"]).split(":")[0] in away:
                    m = nic.get("ifname") or ("ethernet1/" + eth[3:])
                    text = text.replace(f"  {m:<22}yes  Current        Tx_Rx      Selected", f"  {m:<22}no   Defaulted      Detached   Unselected")
            out = []
            for line in (data or "").splitlines():
                out.append(f"admin@fw> {line}")
                if line == "show lacp aggregate-ethernet all":
                    out.append(text)
                if line == "exit":
                    break
            log("sshpass", argv)
            print("\n".join(out))
            return 0
        return None
    if node and NODES[node]["kind"] == "vm-node":
        script = guest_script(remote)
        if script is None:
            return None
        with locked():
            return guest(node, argv, script)
    return None


def guest(node, argv, script):
    if True:
        s = load()
        now = time.time()
        if "setsid ping -D -O" in script:
            ids = [int(x) for x in re.search(r"for id in ([\d ]+);", script).group(1).split()]
            for run in s.get("pings") or []:
                run.setdefault("stop", now)
            s.setdefault("pings", []).append({"ids": ids, "start": now + 0.05})
            save(s)
            log("ssh", argv)
            print(len(ids))
            return 0
        if script.startswith("pkill -INT -f '[p]ing"):
            for run in s.get("pings") or []:
                if run.get("stop") is None:
                    run["stop"] = now
            save(s)
            log("ssh", argv)
            return 0
        if script.startswith("pgrep -f '[p]ing"):
            return 0 if any(r.get("stop") is None for r in s.get("pings") or []) else 1
        if "ping-*.log" in script and script.startswith("for f in"):
            # the guest's directory holds this drill's logs only: the fetch removes it
            log("ssh", argv)
            for run in s.get("pings") or []:
                if run.get("fetched"):
                    continue
                for pid in run["ids"]:
                    print(f"==> /tmp/sfab-drill/ping-{pid}.log")
                    print(ping_log(s, run, pid, now))
                run["fetched"] = True
            save(s)
            return 0
        if script.startswith("cat /proc/net/bonding/"):
            print(bonding_text(s, node, now))
            return 0
        m = re.match(r"^cat /tmp/sfab-trace-([1-4]-\S+)\.txt$", script)
        if m:
            print(trace_decode(m.group(1)))
            return 0
    return None


def sshpass(argv):
    data = sys.stdin.read()
    rc = ssh(argv[2:], data)
    if rc is not None:
        return rc
    return delegate("sshpass", argv, data)


def ssh_tool(argv):
    rc = ssh(argv)
    if rc is not None:
        return rc
    os.execv(sys.executable, [sys.executable, str(M2), "ssh"] + argv)


def docker(argv):
    with locked():
        rc = _docker(argv)
    if rc is not None:
        return rc
    os.execv(sys.executable, [sys.executable, str(M2), "docker"] + argv)


def _docker(argv):
    s = load()
    now = time.time()
    if argv[:1] == ["exec"]:
        rest = argv[1:]
        detach = False
        while rest and rest[0].startswith("-"):
            detach = detach or rest[0] == "-d"
            rest = rest[2:] if rest[0] in ("-e", "-u", "-w") else rest[1:]
        ctr, cmd = rest[0], rest[1:]
        node = ctr[len(PREFIX):] if ctr.startswith(PREFIX) else None
        if detach and cmd[:2] == ["python3", "/tmp/sfab-probe-tcp.py"]:
            s["tcp"] = {"start": now + 0.05, "interval": float(cmd[5])}
            save(s)
            log("docker", argv)
            return 0
        if detach and cmd[:2] == ["bash", "-c"] and "sfab-drill-orphan" in cmd[2]:
            iv = float(re.search(r"sleep ([\d.]+); done", cmd[2]).group(1))
            s["orphan"] = {"start": now + 0.05, "interval": iv}
            save(s)
            log("docker", argv)
            return 0
        if cmd[:2] == ["sh", "-c"] and "pkill -f '[s]fab-probe-tcp'" in cmd[2]:
            (s.get("tcp") or {}).setdefault("stop", now)
            save(s)
            return 0
        if cmd[:2] == ["sh", "-c"] and "pkill -f '[s]fab-drill-orphan'" in cmd[2]:
            (s.get("orphan") or {}).setdefault("stop", now)
            save(s)
            return 0
        if cmd == ["cat", "/tmp/sfab-drill-tcp.log"]:
            for t, seq, ok, sport, leg in tcp_attempts(s, now):
                print(f"{t:.6f} {seq} {1 if ok else 0} {sport} {0.6 if ok else 1000.0}")
            return 0
        if cmd == ["cat", "/tmp/sfab-drill-orphan.log"]:
            print(orphan_log(s, now))
            return 0
        if cmd[:2] == ["rm", "-f"]:
            return 0
        if node == "bastion" and cmd[:1] == ["cat"] and cmd[1].startswith("/proc/net/bonding/"):
            print(bonding_text(s, node, now))
            return 0
        if node == "bastion" and cmd[:2] == ["bash", "-c"] and "/dev/tcp/" in cmd[2] and "for i in $(seq 0" in cmd[2]:
            n = int(re.search(r"seq 0 (\d+)", cmd[2]).group(1)) + 1
            broken = bool((s.get("vlan_removed") or {}).get("fe-sw2"))
            for i in range(n):
                print(f"{now + i * 0.01:.6f} {i} {0 if (broken and i % 3 == 0) else 1}")
            log("docker", argv)
            return 0
        if cmd[:1] == ["curl"] and os.environ.get("SHIM_TRACE_HOLDER"):
            url = cmd[-1]
            msg = re.search(r"[?&]msg=([^&]+)", url)
            log("docker", argv)
            print("HTTP/2 200 \nserver: envoy\n\n" + (msg.group(1) if msg else ""))
            return 0
    if argv[:1] == ["cp"]:
        log("docker", argv)
        return 0
    return None


def tcpdump(argv):
    if "-w" in argv:
        out = argv[argv.index("-w") + 1]
        with locked():
            s = load()
            s.setdefault("captures", {})[os.path.abspath(out)] = time.time()
            save(s)
        open(out, "wb").write(b"\xd4\xc3\xb2\xa1stand-in\n")
        import signal  # noqa: PLC0415
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        for _ in range(6000):
            time.sleep(0.1)
        return 0
    if "-r" in argv:
        f = argv[argv.index("-r") + 1]
        name = os.path.basename(f).rsplit(".", 1)[0]
        m = re.match(r"^(ping|tcp)-([a-z0-9-]+?)-(eth\d+)$", name)
        if not m and re.match(r"^[1-4]-", name):
            sys.stdout.write(trace_decode(name))
            return 0
        if not m:
            os.execv(sys.executable, [sys.executable, str(HERE.parent / "shims-m2" / "_trace.py")] + argv)
        s = load()
        now = time.time()
        # a capture shows what crossed its port after it started (the decodes under captures/place/
        # and captures/ read the same pcap)
        start = (s.get("captures") or {}).get(os.path.abspath(f), 0.0)
        lines = ping_frames(s, m.group(2), m.group(3), now) if m.group(1) == "ping" else tcp_frames(s, m.group(3), now)
        print("\n".join(l for l in lines if float(l.split()[0]) >= start))
        return 0
    return 0


def nsenter(argv):
    pid = int(argv[argv.index("-t") + 1])
    cmd = argv[argv.index("-n") + 1:]
    if cmd[:1] == ["timeout"]:
        cmd = cmd[2:]
    if cmd[:1] == ["tcpdump"] and "-w" in cmd and re.search(r"/(ping|tcp)-[a-z0-9-]+-eth\d+\.pcap$", cmd[cmd.index("-w") + 1]):
        return tcpdump(cmd[1:])
    if cmd[:4] == ["ip", "-s", "-j", "link"]:
        st = json.load(open(os.environ["SHIM_STATE"]))
        name = next((n for n, c in (st.get("containers") or {}).items() if c.get("pid") == pid), "")
        node = name[len(PREFIX):] if name.startswith(PREFIX) else None
        print(counters_json(load(), node, time.time()) if node in NODES else "[]")
        return 0
    os.execv(sys.executable, [sys.executable, str(M2), "nsenter"] + argv)


def ping(argv):
    host = argv[-1]
    node = BY_IP.get(host)
    if node and rebooting(load(), node, time.time()) and time.time() >= reboot_of(load(), node) + REBOOT_UP_S:
        return 1
    return 0


if __name__ == "__main__":
    tool = sys.argv[1]
    sys.exit({"ssh": ssh_tool, "sshpass": sshpass, "docker": docker, "nsenter": nsenter, "tcpdump": tcpdump, "ping": ping}[tool](sys.argv[2:]))
