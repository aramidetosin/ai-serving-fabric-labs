#!/usr/bin/env python3
"""Stand-ins for sfab-ch05's audit reads, rail trace, dark-switch drill and break-5a, for
common/tests/test_ch05.py.

They model the rail backend as the render describes it and hand everything else to the shared
stand-ins (common/tests/shims/). The world lives in $SHIM_CH05_STATE (JSON); times are the host
clock, as the harness's are.

The model, deterministic and made up (never the book's figures):
- a ping from GPU namespace r on node N to node M's address on rail q leaves with N's rail r address
  when q is r, else with the source pin of N's relay route to rail q (its relay address, .r of the
  relay segment, when the pin was removed). Across rails the request crosses N's relay bridge at TTL
  64, then leaves N on rail q at TTL 63; on one rail it leaves at TTL 64. On rail q it shows on N's
  container port, on both rail switch ports and on M's container port, unless the rail's switch is
  dark, which drops it inside the switch (the switch container's port facing N still sees it);
- M answers from its rail q address: to an address on rail q directly, to a relay address into its
  own relay bridge only (the reply never leaves M), to another rail's address through its relay
  bridge (TTL 64) and out of its namespace on that rail (TTL 63), the same way on the wire;
- a DF ping larger than the rail NICs' and the relay's MTU (9000) is refused at the sender with
  ping's "local error: message too long, mtu=9000", and nothing leaves; ping's requests carry DF,
  the far kernel's echo replies do not (as the guests' kernels send them);
- a KLISH shutdown of an interface range on a rail switch darkens it until no shutdown.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHARED = HERE.parent / "shims"
INV = json.load(open(os.environ["SHIM_INV"]))
NODES = INV["nodes"]
BY_IP = {n["mgmt"]: name for name, n in NODES.items()}
PREFIX = INV["prefix"]
STATE = os.environ["SHIM_CH05_STATE"]
RENDER = Path(os.environ.get("SHIM_RENDER", ""))
MTU = 9000
SYNC_STEP = 0.001   # a synchronous ping's requests, spaced on the model's clock


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
        f.write(json.dumps([tool + "-ch05"] + argv) + "\n")


def delegate(tool, argv, stdin=None):
    script = SHARED / ("_devices.py" if tool in ("ssh", "sshpass") else "_shim.py")
    r = subprocess.run([sys.executable, str(script), tool] + argv, input=stdin, text=True, capture_output=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


# ---------------------------------------------------------------------------- the rendered relay

def node_env(node):
    out = {}
    try:
        for line in (RENDER / "bootstrap" / node / "node.env").read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k] = v.strip("'\"")
    except OSError:
        pass
    return out


ENV = {n: node_env(n) for n, d in NODES.items() if d.get("relay")}


def rail_addr(node, r):
    return ENV[node].get(f"RAIL{r}_ADDR", "").split("/")[0]


def relay_addr(node, r):
    return ENV[node].get(f"RELAY{r}_ADDR", "").split("/")[0]


def owner(addr):
    """(node, rail) holding a rail address, or (node, rail) of a relay address on a given node."""
    for n in ENV:
        for r in range(1, 9):
            if rail_addr(n, r) == addr:
                return n, r
    return None, None


def rendered_routes(node, r):
    out = []
    for d in (ENV[node].get(f"RELAY{r}_ROUTES") or "").split():
        dest, via, dev, src = (d.split(",") + [""] * 4)[:4]
        out.append({"dest": dest, "via": via, "dev": dev, "src": src})
    return out


def routes_now(s, node, r):
    un = set(tuple(x) for x in (s.get("unpinned") or []))
    out = []
    for rt in rendered_routes(node, r):
        x = dict(rt)
        if (node, r, rt["dest"]) in un:
            x["src"] = ""
        out.append(x)
    return out


def src_for(s, node, r, q):
    """The source a ping from namespace r on node takes toward rail q."""
    if q == r:
        return rail_addr(node, r)
    dest = f"10.21.{q}.0/24"
    rt = next((x for x in routes_now(s, node, r) if x["dest"] == dest), None)
    return (rt or {}).get("src") or relay_addr(node, r)


def switch_of(q):
    for n, d in NODES.items():
        if d.get("role") == "rail_vlan" and q in (d.get("rails") or []):
            return n
    return None


def port_facing(sw, node, q):
    for eth, nic in (NODES[sw].get("nics") or {}).items():
        if nic.get("rail") == q and str(nic.get("peer", "")).split(":")[0] == node:
            return eth
    return None


def dark(s, sw, t):
    for x in (s.get("dark") or {}).get(sw, []):
        if x["since"] <= t and (x.get("until") is None or t < x["until"]):
            return True
    return False


def mac_of(node, q):
    return ENV[node].get(f"RELAY{q}_MACVLAN_MAC", "02:5a:00:01:00:00")


# ---------------------------------------------------------------------------- one echo, hop by hop

def echo(s, node, r, dst, t, size=56, pid=1, seq=1, ipid=1000):
    """(answered, ttl at the source, frames: [(point, frame)]) for one echo request from namespace r
    on node to dst at time t. A point is ('ctr', node, eth) or ('guest', node, iface)."""
    m, q = owner(dst)
    if m is None:
        return False, None, []
    src = src_for(s, node, r, q)
    iplen = size + 28
    frames = []

    def fr(kind, a, b, ttl, tt, smac, dmac):
        return {"t": tt, "kind": kind, "src": a, "dst": b, "id": pid, "seq": seq, "ttl": ttl, "ipid": ipid if kind == "request" else ipid + 7,
                "ip_len": iplen, "frame_len": iplen + 14, "smac": smac, "dmac": dmac}
    tt = t
    ttl = 64
    if q != r:
        frames.append((("guest", node, "relay0"), fr("request", src, dst, 64, tt, mac_of(node, r), mac_of(node, q))))
        ttl = 63
    sw = switch_of(q)
    req = fr("request", src, dst, ttl, tt + 0.0001, mac_of(node, q), mac_of(m, q))
    frames += [(("guest", node, f"rail{q}"), req), (("ctr", node, NODES[node]["rails"][str(q)]["eth"]), req),
               (("ctr", sw, port_facing(sw, node, q)), req)]
    if dark(s, sw, tt):
        return False, None, frames
    frames += [(("ctr", sw, port_facing(sw, m, q)), dict(req, t=tt + 0.0002)), (("ctr", m, NODES[m]["rails"][str(q)]["eth"]), dict(req, t=tt + 0.0002)),
               (("guest", m, f"rail{q}"), dict(req, t=tt + 0.0002))]
    t2 = tt + 0.0003
    if src.startswith("10.21.250."):
        frames.append((("guest", m, "relay0"), fr("reply", dst, src, 64, t2, mac_of(m, q), mac_of(m, int(src.split(".")[-1])))))
        return False, None, frames
    n2, r2 = owner(src)
    if r2 == q:
        rep = fr("reply", dst, src, 64, t2, mac_of(m, q), mac_of(node, q))
        frames += [(("guest", m, f"rail{q}"), rep), (("ctr", m, NODES[m]["rails"][str(q)]["eth"]), rep), (("ctr", sw, port_facing(sw, m, q)), rep)]
        if dark(s, sw, t2):
            return False, None, frames
        frames += [(("ctr", sw, port_facing(sw, node, q)), rep), (("ctr", node, NODES[node]["rails"][str(q)]["eth"]), rep),
                   (("guest", node, f"rail{q}"), rep)]
        return True, 64, frames
    frames.append((("guest", m, "relay0"), fr("reply", dst, src, 64, t2, mac_of(m, q), mac_of(m, r2))))
    sw2 = switch_of(r2)
    rep = fr("reply", dst, src, 63, t2 + 0.0001, mac_of(m, r2), mac_of(node, r2))
    frames += [(("guest", m, f"rail{r2}"), rep), (("ctr", m, NODES[m]["rails"][str(r2)]["eth"]), rep), (("ctr", sw2, port_facing(sw2, m, r2)), rep)]
    if dark(s, sw2, t2):
        return False, None, frames
    frames += [(("ctr", sw2, port_facing(sw2, node, r2)), rep), (("ctr", node, NODES[node]["rails"][str(r2)]["eth"]), rep),
               (("guest", node, f"rail{r2}"), rep)]
    return True, 63, frames


def run_echoes(s, run, until):
    """Every echo of one recorded ping run up to until: [(seq, t, answered, ttl, frames)]."""
    out = []
    stop = min(run.get("stop") or until, until)
    if run.get("end"):
        stop = min(stop, run["end"])
    seq = 1
    while True:
        t = run["start"] + (seq - 1) * run["step"]
        if t > stop or (run.get("count") and seq > run["count"]):
            break
        if run["size"] + 28 > MTU and run.get("df"):
            out.append((seq, t, False, None, []))
        else:
            ok, ttl, frs = echo(s, run["node"], run["ns_rail"], run["dst"], t, run["size"], run["id"], seq, 2000 + 37 * seq + run["id"] % 97)
            out.append((seq, t, ok, ttl, frs))
        seq += 1
    return out


def frames_at(s, point, start, until):
    out = []
    for run in s.get("runs") or []:
        for seq, t, ok, ttl, frs in run_echoes(s, run, until):
            for pt, f in frs:
                if tuple(pt) == tuple(point) and start <= f["t"] <= until:
                    out.append(f)
    return sorted(out, key=lambda f: f["t"])


def fmt(f, style):
    if style == "tt":
        return (f"{f['t']:.6f} {f['smac']} > {f['dmac']}, ethertype IPv4 (0x0800), length {f['frame_len']}: "
                f"{f['src']} > {f['dst']}: ICMP echo {f['kind']}, id {f['id']}, seq {f['seq']}, length {f['ip_len'] - 20}")
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(f["t"])) + f".{int((f['t'] % 1) * 1e6):06d}"
    return (f"{ts} {f['smac']} > {f['dmac']}, ethertype IPv4 (0x0800), length {f['frame_len']}: (tos 0x0, ttl {f['ttl']}, id {f['ipid']}, "
            f"offset 0, flags [{'DF' if f['kind'] == 'request' else 'none'}], proto ICMP (1), length {f['ip_len']})\n"
            f"    {f['src']} > {f['dst']}: ICMP echo {f['kind']}, id {f['id']}, "
            f"seq {f['seq']}, length {f['ip_len'] - 20}")


# ---------------------------------------------------------------------------- guest commands

def ping_cmd(s, node, ns, args, now, background=False, logname=None):
    """ip netns exec <ns> ping ...: a recorded run, and (synchronous) its output."""
    r = int(ns[3:])
    a = args.split()
    opt = {}
    i = 0
    while i < len(a):
        if a[i] in ("-c", "-i", "-W", "-e", "-s", "-M", "-w"):
            opt[a[i]] = a[i + 1]
            i += 2
        elif a[i] in ("-D", "-O"):
            opt[a[i]] = True
            i += 1
        else:
            opt["dst"] = a[i]
            i += 1
    size = int(opt.get("-s", 56))
    pid = int(opt.get("-e", 4000 + r))
    run = {"node": node, "ns_rail": r, "dst": opt["dst"], "id": pid, "size": size, "df": opt.get("-M") == "do",
           "count": int(opt["-c"]) if "-c" in opt else None, "start": now + 0.05 if background else now,
           "step": float(opt.get("-i", 1)) if background else SYNC_STEP, "interval": float(opt.get("-i", 1)), "bg": background}
    if background:
        run["end"] = run["start"] + float(opt.get("-w", 60))
        run["log"] = logname
    s.setdefault("runs", []).append(run)
    if background:
        return None
    ech = run_echoes(s, run, now + 10)
    return ping_output(run, ech)


def ping_output(run, ech, guest_log=False):
    dst, size = run["dst"], run["size"]
    lines = [f"PING {dst} ({dst}) {size}({size + 28}) bytes of data."]
    rx = 0
    for seq, t, ok, ttl, frs in ech:
        if run["size"] + 28 > MTU and run.get("df"):
            lines.append(f"ping: local error: message too long, mtu={MTU}")
            continue
        if ok:
            rx += 1
            pre = f"[{t + 0.0004:.6f}] " if guest_log else ""
            lines.append(f"{pre}{size + 8} bytes from {dst}: icmp_seq={seq} ttl={ttl} time=0.412 ms")
        elif guest_log:
            lines.append(f"[{t + 1.0:.6f}] no answer yet for icmp_seq={seq}")
    tx = len(ech)
    lines += ["", f"--- {dst} ping statistics ---", f"{tx} packets transmitted, {rx} received, "
              + (f"+{tx} errors, " if run["size"] + 28 > MTU and run.get("df") else "") + f"{100 * (tx - rx) // max(tx, 1)}% packet loss, time 2003ms"]
    return "\n".join(lines)


def traceroute(s, node, ns, dst, now):
    r = int(ns[3:])
    m, q = owner(dst)
    lines = [f"traceroute to {dst} ({dst}), 4 hops max, 60 byte packets"]
    ok, ttl, _ = echo(s, node, r, dst, now)
    if q == r:
        lines.append(f" 1  {dst}  0.512 ms  0.401 ms  0.399 ms" if ok else " 1  * * *")
    else:
        lines.append(f" 1  {rail_addr(node, q)}  0.311 ms  0.290 ms  0.288 ms")
        lines.append(f" 2  {dst}  0.702 ms  0.655 ms  0.640 ms" if ok else " 2  * * *")
    return "\n".join(lines)


def ns_routes(s, node, r, dest=None):
    out = []
    a = rail_addr(node, r)
    if dest is None:
        out.append(f"10.21.{r}.0/24 dev rail{r} proto kernel scope link src {a} ")
    for rt in routes_now(s, node, r):
        if dest is None or rt["dest"] == dest:
            out.append(f"{rt['dest']} via {rt['via']} dev {rt['dev']}" + (f" src {rt['src']}" if rt["src"] else "") + " ")
    if dest is None:
        out.append(f"10.21.250.0/24 dev relay proto kernel scope link src {relay_addr(node, r)} ")
    return "\n".join(out)


def guest_cmd(node, script):
    with locked():
        s = load()
        now = time.time()
        out = _guest(s, node, script, now)
        save(s)
    return out


def _guest(s, node, script, now):
    sc = script.strip()
    caps = s.setdefault("gcaps", {})
    # guest captures: start, test, stop, decode, fetch
    m = re.search(r"tcpdump -i (\S+) .*-w /tmp/sfab-rail-(\S+)\.pcap", sc)
    if m and "exec timeout" in sc:
        caps[m.group(2)] = {"node": node, "iface": m.group(1), "start": now, "stop": None}
        return ""
    m = re.match(r"^test -f /tmp/sfab-rail-(\S+)\.pcap$", sc)
    if m:
        return "" if m.group(1) in caps else ("", 1)
    m = re.match(r"^pkill -INT -f '\[s\]fab-rail-(\S+)\.pcap'", sc)
    if m:
        c = caps.get(m.group(1))
        if c and c["stop"] is None:
            c["stop"] = now
        return ""
    m = re.match(r"^pgrep -f '\[s\]fab-rail-(\S+)\.pcap'", sc)
    if m:
        c = caps.get(m.group(1))
        return "" if c and c["stop"] is None else ("", 1)
    m = re.match(r"^tcpdump (.*) -r /tmp/sfab-rail-(\S+)\.pcap > ", sc)
    if m:
        c = caps.get(m.group(2)) or {}
        style = "tt" if "-tt " in m.group(1) + " " and "-tttt" not in m.group(1) else "tttt"
        fs = frames_at(s, ("guest", c.get("node"), c.get("iface")), c.get("start", 0), c.get("stop") or now)
        c["decode"] = "\n".join(fmt(f, style) for f in fs)
        return str(len(fs))
    m = re.match(r"^cat /tmp/sfab-rail-(\S+)\.txt$", sc)
    if m:
        return (caps.get(m.group(1)) or {}).get("decode", "")
    if sc.startswith("base64 -w0 /tmp/sfab-rail-"):
        return "c3RhbmQtaW4K"
    if sc.startswith("rm -f /tmp/sfab-rail-"):
        return ""
    # the drill's background pings
    if "setsid ping -D -O" in sc:
        for part in sc.split(";"):
            mm = re.search(r"ip netns exec (gpu\d+) setsid ping (.*?) >/tmp/sfab-drill/ping-([A-Za-z0-9-]+)\.log", part)
            if mm:
                ping_cmd(s, node, mm.group(1), mm.group(2), now, background=True, logname=mm.group(3))
        return str(sum(1 for r in s.get("runs") or [] if r.get("bg") and r.get("stop") is None))
    if sc.startswith("pkill -INT -f '[p]ing -D -O -i'"):
        for r in s.get("runs") or []:
            if r.get("bg") and r.get("stop") is None:
                r["stop"] = min(now, r["end"])
        return ""
    if sc.startswith("pgrep -f '[p]ing -D -O -i'"):
        return "" if any(r.get("bg") and r.get("stop") is None and now < r["end"] for r in s.get("runs") or []) else ("", 1)
    if sc.startswith("for f in /tmp/sfab-drill/ping-*.log"):
        out = []
        for r in s.get("runs") or []:
            if r.get("bg") and r.get("log") and not r.get("fetched"):
                out.append(f"==> /tmp/sfab-drill/ping-{r['log']}.log")
                out.append(ping_output(r, run_echoes(s, r, r.get("stop") or now), guest_log=True))
                r["fetched"] = True
        return "\n".join(out)
    # pings, traceroute, routes and links in a GPU namespace
    m = re.match(r"^ip netns exec (gpu\d+) ping (.*)$", sc)
    if m:
        return ping_cmd(s, node, m.group(1), m.group(2), now)
    m = re.match(r"^ip netns exec (gpu\d+) traceroute .* (\S+)$", sc)
    if m:
        return traceroute(s, node, m.group(1), m.group(2), now)
    m = re.match(r"^ip -n gpu(\d+) route replace (\S+) via (\S+) dev (\S+)( src (\S+))?( && ip -n gpu\d+ route show (\S+))?$", sc)
    if m:
        r, dest = int(m.group(1)), m.group(2)
        un = [x for x in (s.get("unpinned") or []) if tuple(x) != (node, r, dest)]
        if not m.group(6):
            un.append([node, r, dest])
        s["unpinned"] = un
        return ns_routes(s, node, r, dest) if m.group(7) else ""
    m = re.match(r"^ip -n gpu(\d+) route show( (\S+))?$", sc)
    if m:
        return ns_routes(s, node, int(m.group(1)), m.group(3))
    m = re.match(r"^ip -n gpu(\d+) route get (\S+)$", sc)
    if m:
        r = int(m.group(1))
        mm, q = owner(m.group(2))
        if q == r:
            return f"{m.group(2)} dev rail{r} src {rail_addr(node, r)} uid 0 \n    cache "
        rt = next((x for x in routes_now(s, node, r) if x["dest"] == f"10.21.{q}.0/24"), {})
        return f"{m.group(2)} via {rt.get('via')} dev relay src {rt.get('src') or relay_addr(node, r)} uid 0 \n    cache "
    m = re.match(r"^ip -n gpu(\d+) -j link show$", sc)
    if m:
        r = int(m.group(1))
        return json.dumps([{"ifname": "lo", "mtu": 65536, "operstate": "UNKNOWN"}, {"ifname": f"rail{r}", "mtu": MTU, "operstate": "UP"},
                           {"ifname": "relay", "mtu": MTU, "operstate": "UP"}])
    if sc == "ip -j addr show":
        n = NODES[node]
        links = [{"ifname": "lo", "mtu": 65536, "operstate": "UNKNOWN", "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]},
                 {"ifname": "eth0", "mtu": 1500, "operstate": "UP", "addr_info": [{"family": "inet", "local": n["mgmt"], "prefixlen": 24}]}]
        links += [{"ifname": f"rail{r}", "mtu": MTU, "operstate": "UP", "addr_info": []} for r in sorted(int(x) for x in n.get("rails") or {})]
        links += [{"ifname": "bond0", "mtu": MTU, "operstate": "UP", "addr_info": [{"family": "inet", "local": n["address"].split("/")[0], "prefixlen": 24}]},
                  {"ifname": "relay0", "mtu": MTU, "operstate": "UP", "addr_info": []}]
        return json.dumps(links)
    if sc.startswith("ip -br link show"):
        return "\n".join(f"rail{r:<13} UP             {ENV[node].get(f'NIC{r + 3:02d}_MAC', '02:5a:00:00:00:00')} <BROADCAST,MULTICAST,UP,LOWER_UP>"
                         for r in range(1, 9))
    return None


def guest_script(remote):
    if not remote.startswith(("sudo bash -c ", "sudo setsid bash -c ")):
        return None
    idx = 3
    if remote.startswith("sudo setsid bash -c "):
        remote, idx = remote.split(" </dev/null", 1)[0], 4
    r = subprocess.run(["bash", "-c", f'eval "a=($1)"; printf %s "${{a[{idx}]}}"', "_", remote], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


# ---------------------------------------------------------------------------- switches

def all_natives():
    return [f"Ethernet{i}" for i in range(48)] + [f"Ethernet{48 + 4 * k}" for k in range(8)]


def interface_status(s, sw, now):
    n = NODES[sw]
    nics = {x["native"]: x for x in (n.get("nics") or {}).values()}
    dk = dark(s, sw, now)
    out = ["-" * 134, "Name                Description                   Oper        Reason         AutoNeg   Speed          MTU            Alternate Name",
           "-" * 134]
    for i, nat in enumerate(all_natives()):
        if nat in nics and not dk:
            oper, reason, desc = "up", "oper-up", nics[nat].get("desc") or "-"
        elif nat in nics:
            oper, reason, desc = "down", "admin-down", nics[nat].get("desc") or "-"
        else:
            oper, reason, desc = "down", "admin-down", "-"
        mtu = (n.get("access") or {}).get(nat, {}).get("mtu") or 9100  # the rendered port MTU (the l2 policy's 9216)
        out.append(f"{nat:<20}{desc:<30}{oper:<12}{reason:<17}off       25000          {mtu:<15}Eth1/{i + 1}")
    return "\n".join(out)


def running(s, sw, now):
    sys.path.insert(0, str(SHARED))
    import _devices  # noqa: PLC0415
    text = _devices.running_config(sw)
    if dark(s, sw, now):
        text = text.replace(" no shutdown", " shutdown")
    return text


def sonic_cli(sw, data):
    with locked():
        s = load()
        now = time.time()
        out = _sonic_cli(s, sw, data, now)
        save(s)
    return out


def _sonic_cli(s, sw, data, now):
    lines = data.splitlines()
    if NODES[sw].get("role") != "rail_vlan":
        return None
    out, ctx, mode = [], None, "#"
    for line in lines:
        out.append(f"{sw}{mode} {'show vlanVlan' if line == 'show vlan' else line}")
        l = line.strip()
        if l == "exit" and mode == "#":
            break
        if l == "configure terminal":
            mode = "(config)#"
            continue
        if l == "end":
            mode, ctx = "#", None
            continue
        if l == "exit":
            ctx, mode = None, "(config)#"
            continue
        m = re.match(r"^interface (range )?(\S+)$", l)
        if m:
            ctx, mode = m.group(2), "(config-if)#"
            continue
        if l in ("shutdown", "no shutdown") and ctx:
            d = s.setdefault("dark", {}).setdefault(sw, [])
            if l == "shutdown":
                d.append({"since": now, "until": None})
            else:
                for x in d:
                    if x.get("until") is None:
                        x["until"] = now
            continue
        if l == "terminal length 0":
            continue
        if l == "show interface status":
            out.append(interface_status(s, sw, now))
        elif l == "show running-configuration":
            out.append(running(s, sw, now))
        elif l == "show ip vrf":
            out.append("VRF-NAME            INTERFACES\n" + "-" * 64 + "\ndefault\nmgmt                Management0")
        elif l.startswith("show"):
            sys.path.insert(0, str(SHARED))
            import _devices  # noqa: PLC0415
            fn = _devices.KLISH.get(l)
            out.append(fn(sw) if fn else "")
        else:
            out.append("% Error: Invalid input detected at \"^\" marker.")
    return "\n".join(out)


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


def ssh_tool(argv):
    target, rest = target_of(argv)
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = BY_IP.get(host)
    if node and NODES[node]["kind"] == "vm-node":
        script = guest_script(" ".join(rest))
        if script is not None:
            out = guest_cmd(node, script)
            if out is not None:
                log("ssh", argv)
                rc = 0
                if isinstance(out, tuple):
                    out, rc = out
                if out:
                    print(out)
                return rc
    os.execv(sys.executable, [sys.executable, str(SHARED / "_devices.py"), "ssh"] + argv)


def sshpass(argv):
    data = sys.stdin.read()
    target, rest = target_of(argv[2:])
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = BY_IP.get(host)
    if node and NODES[node]["kind"] == "dell_sonic" and " ".join(rest) == "sonic-cli":
        out = sonic_cli(node, data)
        if out is not None:
            log("sshpass", argv)
            print(out)
            return 0
    return delegate("sshpass", argv, data)


def node_of_pid(pid):
    st = json.load(open(os.environ["SHIM_STATE"]))
    name = next((n for n, c in (st.get("containers") or {}).items() if c.get("pid") == pid), "")
    return name[len(PREFIX):] if name.startswith(PREFIX) else None


def tcpdump(argv, node=None):
    if "-w" in argv:
        out = os.path.abspath(argv[argv.index("-w") + 1])
        iface = argv[argv.index("-i") + 1] if "-i" in argv else None
        with locked():
            s = load()
            s.setdefault("hcaps", {})[out] = {"node": node, "eth": iface, "start": time.time()}
            save(s)
        open(out, "wb").write(b"\xd4\xc3\xb2\xa1stand-in\n")
        import signal  # noqa: PLC0415
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        for _ in range(6000):
            time.sleep(0.1)
        return 0
    if "-r" in argv:
        f = os.path.abspath(argv[argv.index("-r") + 1])
        s = load()
        c = (s.get("hcaps") or {}).get(f)
        if c is None:
            return 0
        style = "tt" if "-tt" in argv else "tttt"
        fs = frames_at(s, ("ctr", c["node"], c["eth"]), c["start"], time.time())
        print("\n".join(fmt(x, style) for x in fs))
        return 0
    return 0


def nsenter(argv):
    pid = int(argv[argv.index("-t") + 1])
    cmd = argv[argv.index("-n") + 1:]
    if cmd[:1] == ["timeout"]:
        cmd = cmd[2:]
    if cmd[:1] == ["tcpdump"] and "-w" in cmd:
        log("nsenter", argv)
        return tcpdump(cmd[1:], node_of_pid(pid))
    os.execv(sys.executable, [sys.executable, str(SHARED / "_shim.py"), "nsenter"] + argv)


if __name__ == "__main__":
    tool = sys.argv[1]
    sys.exit({"ssh": ssh_tool, "sshpass": sshpass, "nsenter": nsenter, "tcpdump": tcpdump}[tool](sys.argv[2:]))
