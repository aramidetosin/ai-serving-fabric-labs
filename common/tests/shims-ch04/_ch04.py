#!/usr/bin/env python3
"""Stand-ins for sfab-ch04's firewall edge, for common/tests/test_ch04.py.

They model what the chapter 4 harness does to the firewall and what its reads would see, and hand
everything else to chapter 3's stand-ins (common/tests/shims-ch03/), which hand the rest to M2's and
the shared ones. The world lives in $SHIM_CH04_STATE (JSON); times are the host clock.

The model, deliberately simple and deterministic (made-up figures and ids, never the book's):
- the firewall keeps a candidate and a running NAT rulebase and NTP service route; the XML API
  changes the candidate (delete, set, move, edit) and a commit copies it to the running one;
- k8s-cp2's ping of the public address is answered while no-nat-public runs; without it every request
  is discarded, flow_policy_nat_land rises by one per request, and packet-diag's receive and drop
  stages capture each request when its filter matches;
- the firewall's own NTP takes the source of the DNS service route, whose server is the same
  address (as the PA-VM did on the first deploy, ch04/RESULTS.md, problem 5): a commit that moves the DNS
  route to ethernet1/5 writes a deny-all-log entry for the firewall's NTP from 198.51.100.2 (zone
  uplink to the resolver's zone), one that moves it back an allowed entry from the route's own
  address under the rule the render names for it (inside-to-resolvers for DNS and inside-to-ntp for NTP in build A), and moving the NTP route alone changes nothing; a name looked up with
  ping host (no source) writes the DNS query's entry from the DNS route's source;
- a held request is listed by show session all until its client closes it, then logged;
- k8s-gpu2's pull crosses ae1 leg 2 tagged 100 and the uplink with its source rewritten;
- an inside node's connect to an internet host other than the registry is refused under
  deny-all-log, from the node's zone to the uplink, and times out;
- the operator's connects to inside addresses are refused: logged under deny-all-log when the
  tunnel's proxy IDs protect them, else dropped by zone protection's strict IP check (a counter);
- SHIM_CH04_COMMIT_FAIL=<text> refuses every commit whose description holds the text.
Every capture a drill or the trace starts on the firewall's ports records the frames those events
put on its port, and is written when it is stopped (with the pcap magic, then the decode, which
the tcpdump stand-in prints back).
"""

import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
CH03 = HERE.parent / "shims-ch03" / "_ch03.py"
SHARED = HERE.parent / "shims"
sys.path.insert(0, str(HERE.parent))
import ch04_world as W  # noqa: E402

INV = json.load(open(os.environ["SHIM_INV"]))
NODES = INV["nodes"]
BY_IP = {n["mgmt"]: name for name, n in NODES.items()}
PREFIX = INV["prefix"]
STATE = os.environ["SHIM_CH04_STATE"]
FW = INV["stages"]["fw"]
PUBLIC = NODES[FW]["public"]
MARK = b"\xd4\xc3\xb2\xa1SHIMDECODE\n"


def bare(a):
    return str(a).split("/")[0] if a else ""


def addr_of(node):
    return bare(NODES[node].get("address"))


def initial():
    fw = NODES[FW]
    run = {"nat": list(fw["nat"]), "rules": list(fw["rules"]), "ntp_if": fw["system"]["service_routes"]["ntp"]["interface"],
           "dns_if": fw["system"]["service_routes"]["dns"]["interface"]}
    return {"running": dict(run), "candidate": json.loads(json.dumps(run)), "counters": {"pkt_recv": 1000, "flow_policy_nat_land": 0,
            "flow_policy_deny": 0, "flow_dos_pf_strictip": 0}, "delta_base": None, "diag": {"filter": None, "filter_on": False, "capture_on": False, "stages": {}},
            "pcaps": {}, "log": [], "captures": {}, "held": {}, "jobs": 0}


def load():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return initial()


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
        f.write(json.dumps([tool + "-ch04"] + [str(x) for x in argv]) + "\n")


def delegate(tool, argv, stdin=None):
    r = subprocess.run([sys.executable, str(CH03), tool] + argv, input=stdin, text=True, capture_output=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


def stamp(t=None):
    t = time.time() if t is None else t
    return time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(t))


def tick(t=None):
    t = time.time() if t is None else t
    return time.strftime("%S", time.gmtime(t)) + f".{int((t % 1) * 1e6):06d}"


def frame(s, eth, text):
    """Put a decoded frame on the firewall's port ETH: every running capture there records it."""
    for c in (s.get("captures") or {}).values():
        if c["node"] == FW and c["eth"] == eth and not c.get("stopped"):
            c["frames"].append(text)


def add_log(s, app, frm, sport, src, rule, action, to, dport, dst):
    s["log"].append([time.time(), app, frm, sport, src, rule, action, to, dport, dst])


def sr_rule(svc="dns"):
    """The rule that admits the firewall's own DNS or NTP through its service route (the render's)."""
    sr = (NODES[FW].get("system") or {}).get("service_routes") or {}
    return (sr.get(svc) or sr.get("dns") or {}).get("rule") or "deny-all-log"


def tunnel_if():
    return next((n for n in NODES[FW]["interfaces"] if n.startswith("tunnel.")), "ethernet1/5")


def tunnel_zone():
    return (NODES[FW]["interfaces"].get(tunnel_if()) or {}).get("zone") or "uplink"


def if_of(a):
    import ipaddress  # noqa: PLC0415
    for n, i in NODES[FW]["interfaces"].items():
        if i.get("address") and ipaddress.ip_address(a) in ipaddress.ip_interface(i["address"]).network:
            return n
    return "ethernet1/5"


def zone_of(a):
    for i in NODES[FW]["interfaces"].values():
        if i.get("address") and i.get("zone"):
            import ipaddress  # noqa: PLC0415
            if ipaddress.ip_address(a) in ipaddress.ip_interface(i["address"]).network:
                return i["zone"]
    return "uplink"


# ---------------------------------------------------------------------------- the XML API


def api(argv):
    params, hdr, out, url = {}, None, None, None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--data-urlencode", "--data"):
            k, _, v = argv[i + 1].partition("=")
            if a == "--data" and k.startswith("@"):
                for kv in open(k[1:]).read().split("&"):
                    kk, _, vv = kv.partition("=")
                    params[kk] = urllib.parse.unquote(vv)
            elif k.endswith("@-") and not v:
                params[k[:-2]] = sys.stdin.read()
            else:
                params[k] = v
            i += 2
            continue
        if a == "-H":
            hdr = argv[i + 1]
            i += 2
            continue
        if a == "-o":
            out = argv[i + 1]
            i += 2
            continue
        if a in ("-m", "--max-time"):
            i += 2
            continue
        if not a.startswith("-"):
            url = a
        i += 1
    if not url or "/api/" not in url:
        return None
    q = urllib.parse.urlparse(url)
    for k, v in urllib.parse.parse_qsl(q.query):
        params.setdefault(k, v)
    host = q.hostname
    if BY_IP.get(host) != FW:
        return None
    t = params.get("type")
    ok = lambda body: print(f"<response status=\"success\">{body}</response>")  # noqa: E731
    if t == "keygen":
        # stand-in values: a made-up API key in the LUFRPT form PAN-OS keys take
        print("<response status='success'><result><key>LUFRPTshimkey0123456789abcdef==</key></result></response>")
        return 0
    with locked():
        s = load()
        if t == "config":
            act, xp = params.get("action"), params.get("xpath", "")
            el = params.get("element", "")
            cand = s["candidate"]
            m = re.search(r"/rulebase/nat/rules/entry\[@name='([^']+)'\]$", xp)
            if act in ("show", "get") and xp.endswith("/rulebase"):
                src = s["running"] if act == "show" else cand
                sec = "".join(f"<entry name=\"{n}\"/>" for n in src["rules"])
                nat = "".join(f"<entry name=\"{n}\"/>" for n in src["nat"])
                ok(f"<result><rulebase><security><rules>{sec}</rules></security><nat><rules>{nat}</rules></nat></rulebase></result>")
            elif act in ("show", "get") and (sv := re.search(r"/service/entry\[@name='(ntp|dns)'\]$", xp)):
                src = s["running"] if act == "show" else cand
                k = sv.group(1) + "_if"
                a = NODES[FW]["interfaces"][src[k]]["address"]
                ok(f"<result><entry name=\"{sv.group(1)}\"><source><interface>{src[k]}</interface><address>{a}</address></source></entry></result>")
            elif act == "delete" and m:
                if m.group(1) in cand["nat"]:
                    cand["nat"].remove(m.group(1))
                ok("<msg>command succeeded</msg>")
            elif act == "set" and xp.endswith("/rulebase/nat/rules"):
                n = re.search(r'<entry name="([^"]+)"', el).group(1)
                if n not in cand["nat"]:
                    cand["nat"].append(n)
                ok("<msg>command succeeded</msg>")
            elif act == "move" and m:
                n, where, dst = m.group(1), params.get("where"), params.get("dst")
                if n in cand["nat"]:
                    cand["nat"].remove(n)
                    if where == "before" and dst in cand["nat"]:
                        cand["nat"].insert(cand["nat"].index(dst), n)
                    elif where == "after" and dst in cand["nat"]:
                        cand["nat"].insert(cand["nat"].index(dst) + 1, n)
                    elif where == "top":
                        cand["nat"].insert(0, n)
                    else:
                        cand["nat"].append(n)
                ok("<msg>command succeeded</msg>")
            elif act == "edit" and (sv := re.search(r"/service/entry\[@name='(ntp|dns)'\]$", xp)):
                cand[sv.group(1) + "_if"] = re.search(r"<interface>([^<]+)</interface>", el).group(1)
                ok("<msg>command succeeded</msg>")
            else:
                print(f"<response status=\"error\"><msg>shim: {act} {xp} not modelled</msg></response>")
        elif t == "commit":
            fail = os.environ.get("SHIM_CH04_COMMIT_FAIL")
            if fail and fail in params.get("cmd", ""):
                print("<response status=\"error\"><msg><line>shim: commit refused</line></msg></response>")
                return 0
            s["jobs"] += 1
            # the NTP source follows the DNS route (they share the server address)
            before = s["running"].get("dns_if")
            s["running"] = json.loads(json.dumps(s["candidate"]))
            after = s["running"].get("dns_if")
            if after != before:
                src = bare(NODES[FW]["interfaces"][after]["address"])
                ntp = NODES[FW]["system"]["ntp"][0]
                if after == "ethernet1/5":
                    add_log(s, "ntp", "uplink", 123, src, "deny-all-log", "deny", zone_of(ntp), 123, ntp)
                else:
                    add_log(s, "ntp", zone_of(src), 123, src, sr_rule("ntp"), "allow", zone_of(ntp), 123, ntp)
            ok(f"<result><msg><line>Commit job enqueued with jobid {s['jobs']}</line></msg><job>{s['jobs']}</job></result>")
        elif t == "op":
            cmd = params.get("cmd", "")
            if "<jobs>" in cmd:
                jid = re.search(r"<id>(\d+)</id>", cmd).group(1)
                ok(f"<result><job><id>{jid}</id><status>FIN</status><result>OK</result><details><line>Configuration committed successfully"
                   "</line></details></job></result>")
            elif "<counter>" in cmd:
                print(W.counters_xml(s["counters"]))
            elif "<session>" in cmd:
                ok("<result></result>")
            else:
                ok("<result>ok</result>")
        elif t == "export" and params.get("category") == "filter-pcap":
            f = params.get("from")
            if f in s["pcaps"] and out:
                Path(out).write_bytes(MARK + "\n".join(s["pcaps"][f]).encode())
            elif out:
                Path(out).write_text("<response status=\"error\"><msg>file not found</msg></response>")
        else:
            return None
        save(s)
    return 0


def curl(argv):
    rc = api(argv)
    if rc is not None:
        log("curl", argv)
        return rc
    os.execv(sys.executable, [sys.executable, str(SHARED / "_devices.py"), "curl"] + argv)


# ---------------------------------------------------------------------------- the PAN-OS CLI


def tlog_text(s, dport):
    es = [e for e in sorted(s["log"], key=lambda e: -e[0]) if str(e[8]) == str(dport)]
    return W.tlog([(stamp(e[0]),) + tuple(e[1:]) for e in es])


def fw_line(s, line):
    """The output of one CLI line, or None when the shim does not model it."""
    if line == "show counter global filter value all":
        # every show counter global read starts the next delta sampling, as on the PA-VM
        s["delta_base"] = dict(s["counters"])
        return W.counters_cli(s["counters"])
    if line == "show counter global filter delta yes severity drop":
        base = s.get("delta_base") or {k: 0 for k in s["counters"]}
        d = {k: v - base.get(k, 0) for k, v in s["counters"].items() if W.COUNTER_DESC[k][0] == "drop" and v != base.get(k, 0)}
        s["delta_base"] = dict(s["counters"])
        return W.counters_cli(d)
    if line == "show running nat-policy":
        return W.running_policy(s["running"]["nat"], "nat")
    if line == "show running security-policy":
        return W.running_policy(s["running"]["rules"] + ["intrazone-default", "interzone-default"])
    m = re.match(r"^show log traffic .*dport equal (\d+)$", line)
    if m:
        return tlog_text(s, m.group(1))
    m = re.match(r"^show session all filter source (\S+) source-port (\d+)$", line)
    if m:
        h = (s.get("held") or {}).get(m.group(2))
        if not h or h.get("end"):
            return "No Active Sessions"
        frm = tunnel_zone() if h["src"] == addr_of("ops-client") else "enterprise"
        return W.session_all(1000 + int(h["sport"]), "ssl", h["src"], int(h["sport"]), frm, h["src"], int(h["sport"]), h["dst"], 443,
                             zone_of(h["xdst"]), h["xdst"], 443, "ND" if h["xdst"] != h["dst"] else "")
    m = re.match(r"^show session id (\d+)$", line)
    if m:
        h = (s.get("held") or {}).get(str(int(m.group(1)) - 1000))
        if not h:
            return "Session not found"
        op = h["src"] == addr_of("ops-client")
        # revision 2: the operator over the tunnel to the internal VIP, no NAT; both VIPs on ae1.110
        return W.session_detail(int(m.group(1)), h["src"], int(h["sport"]), tunnel_zone() if op else "enterprise", h["dst"], 443, h["xdst"],
                                zone_of(h["xdst"]), "operator-to-internal-gateway" if op else "staff-to-users-gateway",
                                None, tunnel_if() if op else "ethernet1/4", if_of(h["xdst"]))
    if line == "show ntp":
        return W.ntp(NODES[FW]["system"]["ntp"][0])
    m = re.match(r"^ping count \d+ host (\S+)$", line)
    if m:
        src = bare(NODES[FW]["interfaces"][s["running"]["dns_if"]]["address"])
        a = NODES[FW]["system"]["dns"][0]
        if s["running"]["dns_if"] == "ethernet1/5":
            add_log(s, "not-applicable", "uplink", 41000, src, "deny-all-log", "deny", zone_of(a), 53, a)
        else:
            add_log(s, "dns-base", zone_of(src), 41000, src, sr_rule(), "allow", zone_of(a), 53, a)
        return f"/bin/ping: {m.group(1)}: Name or service not known"
    m = re.match(r"^ping source (\S+) count \d+ host (\S+)$", line)
    if m:
        dns = INV.get("dns") or {}
        a = (dns.get("records") or {}).get(m.group(2), "")
        # the query goes to the firewall's DNS server, the time to its NTP server, both from the route's source
        rs, ts = NODES[FW]["system"]["dns"][0], NODES[FW]["system"]["ntp"][0]
        add_log(s, "dns", zone_of(m.group(1)), 33000, m.group(1), sr_rule(), "allow", zone_of(rs), 53, rs)
        add_log(s, "ntp", zone_of(m.group(1)), 123, m.group(1), sr_rule("ntp"), "allow", zone_of(ts), 123, ts)
        return f"PING {m.group(2)} ({a}) from {m.group(1)} : 56(84) bytes of data.\n\n--- {m.group(2)} ping statistics ---\n1 packets transmitted, 0 received, 100% packet loss"
    d = s["diag"]
    m = re.match(r"^debug dataplane packet-diag (.*)$", line)
    if m:
        a = m.group(1)
        if a == "clear all":
            s["diag"] = {"filter": None, "filter_on": False, "capture_on": False, "stages": {}}
        elif a.startswith("set filter match "):
            f = a.split()
            d["filter"] = {"source": f[f.index("source") + 1], "destination": f[f.index("destination") + 1]}
        elif a in ("set filter on", "set filter off"):
            d["filter_on"] = a.endswith("on")
        elif a.startswith("set capture stage "):
            f = a.split()
            d["stages"][f[3]] = f[5]
            s["pcaps"].setdefault(f[5], [])
        elif a in ("set capture on", "set capture off"):
            d["capture_on"] = a.endswith("on")
        elif a == "show setting":
            return json.dumps(d)
        return ""
    if line == "show debug dataplane packet-diag":
        return "Invalid syntax."
    m = re.match(r"^view-pcap filter-pcap (\S+)$", line)
    if m:
        return "\n".join(s["pcaps"].get(m.group(1), []))
    m = re.match(r"^delete debug-filter file (\S+)$", line)
    if m:
        s["pcaps"].pop(m.group(1), None)
        return ""
    return None


def fw_cli(argv, data):
    sys.path.insert(0, str(SHARED))
    os.environ.setdefault("SHIM_INV", os.environ["SHIM_INV"])
    import _devices  # noqa: PLC0415
    out = []
    with locked():
        s = load()
        for line in data.splitlines():
            out.append(f"admin@{FW}> {line}")
            if line == "exit":
                break
            got = fw_line(s, line)
            if got is not None:
                out.append(got)
            elif line == "show lacp aggregate-ethernet all":
                out.append(_devices.panos_lacp(FW))
            elif line == "show interface all":
                out.append(_devices.panos_interface_all(FW))
            elif line.startswith("show interface ae1."):
                out.append(_devices.panos_subif(FW, line.split()[-1]))
            elif line.startswith("show"):
                out.append("ok")
        save(s)
    log("sshpass", argv)
    print("\n".join(out))
    return 0


def target_of(argv):
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-o", "-i", "-p", "-l", "-b"):
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a, argv[i + 1:]
    return None, []


def sshpass(argv):
    data = sys.stdin.read()
    target, _ = target_of(argv[2:])
    host = target.split("@", 1)[1] if target and "@" in target else None
    if BY_IP.get(host) == FW and "configure" not in data:
        return fw_cli(argv, data)
    return delegate("sshpass", argv, data)


# ---------------------------------------------------------------------------- guests


def guest_script(remote):
    if not remote.startswith("sudo bash -c "):
        return None
    r = subprocess.run(["bash", "-c", 'eval "a=($1)"; printf %s "${a[3]}"', "_", remote], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else None


def public_ping(s, node, n):
    answered = "no-nat-public" in s["running"]["nat"]
    src = addr_of(node)
    s["counters"]["pkt_recv"] += n
    d = s["diag"]
    matches = d["filter_on"] and d["capture_on"] and d["filter"] == {"source": src, "destination": PUBLIC}
    for seq in range(1, n + 1):
        t = time.time() + seq * 0.001
        req = W.icmp_frame(tick(t), src, PUBLIC, "request", seq, vlan=100)
        frame(s, "eth1", req)
        if answered:
            frame(s, "eth1", W.icmp_frame(tick(t + 0.0005), PUBLIC, src, "reply", seq, vlan=100))
        else:
            s["counters"]["flow_policy_nat_land"] += 1
        if matches:
            if "receive" in d["stages"]:
                s["pcaps"][d["stages"]["receive"]].append(W.icmp_frame(tick(t), src, PUBLIC, "request", seq))
            if "drop" in d["stages"] and not answered:
                s["pcaps"][d["stages"]["drop"]].append(W.icmp_frame(tick(t), src, PUBLIC, "request", seq))
    return W.ping(PUBLIC, n, n if answered else 0)


def admin_addr():
    """The address the firewall's management answers on (its admin interface's, in the render)."""
    fw = NODES[FW]
    i = (fw.get("admin") or {}).get("interface")
    return bare(((fw.get("interfaces") or {}).get(i) or {}).get("address")) if i else None


def guest(node, argv, script):
    admin = admin_addr()
    if admin and script.startswith("curl ") and f"https://{admin}/" in script:
        # another inside host: the admin profile does not permit it, the connect times out
        log("ssh", argv)
        print("000")
        return 28
    m = re.match(r"^ping -c (\d+) -i \S+ -W \S+ (\S+)$", script)
    if m and m.group(2) == PUBLIC:
        with locked():
            s = load()
            out = public_ping(s, node, int(m.group(1)))
            save(s)
        log("ssh", argv)
        print(out)
        return 0
    m = re.match(r"^crictl --runtime-endpoint \S+ (pull|rmi) (\S+)$", script)
    if m:
        log("ssh", argv)
        if m.group(1) == "rmi":
            print(f"Deleted: {m.group(2)}")
            return 0
        reg = INV["registry"]
        src, ra, port = addr_of(node), bare(reg["address"]), int(reg["port"])
        with locked():
            s = load()
            t = time.time()
            frame(s, "eth2", W.tcp_syn(tick(t), src, 51000, ra, port, 777000, vlan=100))
            frame(s, "eth5", W.tcp_syn(tick(t + 0.0002), PUBLIC, 18011, ra, port, 777000))
            frame(s, "eth5", W.tcp_data(tick(t + 0.01), ra, port, PUBLIC, 18011, 1, 1500))
            frame(s, "eth2", W.tcp_data(tick(t + 0.0102), ra, port, src, 51000, 1, 1500, vlan=100))
            add_log(s, "ssl", zone_of(src), 51000, src, "nodes-to-registry", "allow", "uplink", port, ra)
            save(s)
        print("Image is up to date for sha256:" + "b" * 64)
        return 0
    m = re.match(r"^timeout 4 bash -c 'exec 3<>/dev/tcp/(\d+\.\d+\.\d+\.\d+)/(\d+)' 2>&1; echo rc=\$\?$", script)
    if m and not m.group(1).startswith("10."):
        # an inside node's connect to an internet host: no rule admits it but the registry's, so
        # deny-all-log refuses it from the node's zone to the uplink, and the connect times out
        with locked():
            s = load()
            add_log(s, "incomplete", zone_of(addr_of(node)), 45000 + len(s["log"]), addr_of(node), "deny-all-log", "deny", "uplink",
                    int(m.group(2)), m.group(1))
            save(s)
        log("ssh", argv)
        print("rc=124")
        return 0
    return None


def ssh_tool(argv):
    target, rest = target_of(argv)
    host = target.split("@", 1)[1] if target and "@" in target else None
    node = BY_IP.get(host)
    if node and NODES[node]["kind"] == "vm-node":
        script = guest_script(" ".join(rest))
        if script is not None:
            rc = guest(node, argv, script)
            if rc is not None:
                return rc
    os.execv(sys.executable, [sys.executable, str(CH03), "ssh"] + argv)


# ---------------------------------------------------------------------------- containers


def hold_request(node, args):
    addr, fqdn, path, sport, hold = args[0], args[1], args[2], args[3], float(args[4])
    msg = re.search(r"[?&]msg=([^&]+)", path)
    src = addr_of(node)
    with locked():
        s = load()
        s.setdefault("held", {})[sport] = {"src": src, "sport": sport, "dst": addr, "start": time.time(), "end": None,
                                           "xdst": addr}
        save(s)
    print(f"HTTP/1.1 200 OK\ncontent-length: 20\nserver: envoy\n\n{msg.group(1) if msg else ''}", flush=True)
    print(f"HELD {time.time():.6f}", flush=True)
    time.sleep(hold)
    with locked():
        s = load()
        h = s["held"][sport]
        h["end"] = time.time()
        op = node == "ops-client"
        add_log(s, "ssl", tunnel_zone() if op else "enterprise", int(sport), src, "operator-to-internal-gateway" if op else "staff-to-users-gateway",
                "allow", zone_of(addr), 443, addr)
        save(s)
    print(f"CLOSED {time.time():.6f}", flush=True)
    return 0


def container(node, argv, cmd):
    if NODES[node]["kind"] == "frr" and cmd == ["vtysh", "-c", "show ip route json"]:
        routes = json.loads(W.frr_routes(NODES[node].get("routes") or []))
        for eth, i in sorted((NODES[node].get("ifaces") or {}).items()):
            if eth in (NODES[node].get("nics") or {}) and i.get("address"):
                import ipaddress  # noqa: PLC0415
                pfx = str(ipaddress.ip_interface(i["address"]).network)
                routes[pfx] = [{"prefix": pfx, "protocol": "connected", "selected": True, "installed": True,
                                "nexthops": [{"interfaceName": eth, "directlyConnected": True}]}]
        print(json.dumps(routes))
        return 0
    if cmd[:2] == ["python3", "-"] and len(cmd) >= 7:
        sys.stdin.read()
        return hold_request(node, cmd[2:])
    text = " ".join(cmd)
    m = re.search(r"/dev/tcp/(\d+\.\d+\.\d+\.\d+)/(\d+)'", text)
    if node == "ops-client" and cmd[:2] == ["bash", "-c"] and m and "for i in" not in text:
        with locked():
            s = load()
            # revision 2: the operator's client reaches the firewall over the IPsec tunnel, in the
            # tunnel's zone, for what the tunnel's proxy IDs protect; anything else leaves its site in
            # the clear and arrives on the uplink from an address routed through the tunnel, which
            # zone protection's strict IP check drops before any rule (a counter, no log line)
            import ipaddress  # noqa: PLC0415
            dst = ipaddress.ip_address(m.group(1))
            vpns = NODES[FW].get("vpns") or []
            inside = any(dst in ipaddress.ip_network(local) for v in vpns for _, local, _ in v.get("proxy_ids") or [])
            if vpns and not inside:
                s["counters"]["flow_dos_pf_strictip"] = s["counters"].get("flow_dos_pf_strictip", 0) + 1
            else:
                frm = tunnel_zone()
                add_log(s, "incomplete", frm, 40000 + len(s["log"]), addr_of(node), "deny-all-log", "deny", zone_of(m.group(1)),
                        int(m.group(2)), m.group(1))
            save(s)
        return 1
    # the firewall's management answers the jump host alone (its admin profile permits the bastion's
    # own address), on the interface the render names for it
    admin = admin_addr()
    if "telnet://" in text:
        print("SSH-2.0-shim" if node == "bastion" and admin and f"telnet://{admin}:" in text else "")
        return 0
    if cmd[:1] == ["curl"] and "%{http_code}" in text:
        if node == "bastion" and admin and f"https://{admin}/" in text:
            print("200")
            return 0
        print("000")
        return 28
    if cmd[:1] == ["curl"] and "-D" in cmd and PUBLIC in text:
        if not NODES[FW].get("published"):
            return 28  # nothing is published on the uplink: the request times out
        print("HTTP/2 404 \nserver: envoy\ndate: Tue, 20 Oct 2026 10:00:00 GMT")
        return 0
    if cmd[:2] == ["bash", "-c"] and "for i in $(seq 0" in text and "curl" in text:
        n = int(re.search(r"seq 0 (\d+)", text).group(1)) + 1
        now = time.time()
        for i in range(n):
            print(f"{now + i * 0.01:.6f} {i} 1 200")
        return 0
    return None


def docker(argv):
    if argv[:1] == ["exec"]:
        rest = argv[1:]
        while rest and rest[0].startswith("-"):
            rest = rest[2:] if rest[0] in ("-e", "-u", "-w") else rest[1:]
        ctr, cmd = rest[0], rest[1:]
        node = ctr[len(PREFIX):] if ctr.startswith(PREFIX) else None
        if node in NODES and NODES[node]["kind"] in ("client", "bastion", "frr"):
            rc = container(node, argv, cmd)
            if rc is not None:
                log("docker", argv)
                return rc
    os.execv(sys.executable, [sys.executable, str(CH03), "docker"] + argv)


# ---------------------------------------------------------------------------- captures


def capture(node, eth, out):
    key = os.path.abspath(out)
    with locked():
        s = load()
        s.setdefault("captures", {})[key] = {"node": node, "eth": eth, "frames": [], "stopped": False}
        save(s)
    Path(out).write_bytes(MARK)

    def stop(*_):
        with locked():
            s = load()
            c = s["captures"][key]
            c["stopped"] = True
            save(s)
        Path(out).write_bytes(MARK + "\n".join(c["frames"]).encode())
        sys.exit(0)

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    for _ in range(6000):
        time.sleep(0.1)
    stop()
    return 0


def nsenter(argv):
    pid = int(argv[argv.index("-t") + 1])
    cmd = argv[argv.index("-n") + 1:]
    if cmd[:1] == ["timeout"]:
        cmd = cmd[2:]
    if cmd[:1] == ["tcpdump"] and "-w" in cmd:
        out = cmd[cmd.index("-w") + 1]
        st = json.load(open(os.environ["SHIM_STATE"]))
        name = next((n for n, c in (st.get("containers") or {}).items() if c.get("pid") == pid), "")
        node = name[len(PREFIX):] if name.startswith(PREFIX) else None
        if node == FW and "/captures/" in out:
            log("nsenter", argv)
            return capture(node, cmd[cmd.index("-i") + 1], out)
    os.execv(sys.executable, [sys.executable, str(CH03), "nsenter"] + argv)


def tcpdump(argv):
    if "-r" in argv:
        f = argv[argv.index("-r") + 1]
        try:
            b = Path(f).read_bytes()
        except OSError:
            b = b""
        if b.startswith(MARK):
            sys.stdout.write(b[len(MARK):].decode() + "\n")
            return 0
    os.execv(sys.executable, [sys.executable, str(CH03), "tcpdump"] + argv)


if __name__ == "__main__":
    tool = sys.argv[1]
    sys.exit({"curl": curl, "ssh": ssh_tool, "sshpass": sshpass, "docker": docker, "nsenter": nsenter, "tcpdump": tcpdump}[tool](sys.argv[2:]))
