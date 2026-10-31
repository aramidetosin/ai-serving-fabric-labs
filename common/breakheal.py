#!/usr/bin/env python3
"""breakheal.py: a chapter's break-fix exercises (FRAMEWORK.md section 4.7).

    breakheal.py break ID          apply break ID, record it, check it broke as designed
    breakheal.py heal ID           heal it, check it healed, then run the chapter audit
    breakheal.py heal all          heal every break this lab holds as applied, then restore every switch
    breakheal.py steps --breaks gen/breaks.json --id ID --part PART     the actions of one part, one per line
    breakheal.py vlan --file SHOW_VLAN --vlan N --port P --present 0|1 [--mode T|A]
    breakheal.py mclag --file SHOW_MCLAG_BRIEF --portchannel P --status LOCAL/REMOTE
                                                                        an MCLAG interface's status (break-3b)
    breakheal.py share --log FILE                                       a connect log's attempts and failures
    breakheal.py pingshare --log FILE                                   a ping's requests and those unanswered
    breakheal.py counter --dir DIR --probe ID --mode MODE --name N      a counter's rise across a probe's passes
    breakheal.py farcap --breaks gen/breaks.json --id ID --dir DIR --probe PROBE --mode MODE --src relay|rail
                                                                        where the far node saw a probe_rail's requests come from
    breakheal.py synat --breaks gen/breaks.json --id ID --dir DIR --mode MODE --check JSON
                                                                        where a probe_syn's SYNs were captured (chapter 1)
    breakheal.py tlogcmd --breaks gen/breaks.json --id ID --probe PROBE the traffic log read a probe_syn's check needs
    breakheal.py tlogrule --breaks gen/breaks.json --id ID --dir DIR --mode MODE --file LOG --check JSON
                                                                        the rule and action the log names for each connect
    breakheal.py cellmode --dir DIR --plan gen/matrix.json --check JSON a matrix cell's mode as its evidence shows (chapter 2)

Run from a lab directory (make break-3a does). The breaks are the lab's breaks/<id>.yaml, rendered
to gen/breaks.json (sfab.render.drills), so nothing here needs PyYAML. break and heal hand over to
common/break/breakheal.sh, which holds the lab's lock, owns the result set
(audits/<lab>_break-<id>_<UTC>/ or audits/<lab>_heal-<id>_<UTC>/) and runs the device actions with
lib.sh's runners; the other subcommands are its helpers. state/breaks/<id> marks a break as applied,
so the same break is never applied twice.

steps prints one action per line, tab-separated: kind, node, then the action as JSON. Kinds: klish
(a session, and its fallback), show (lines read and saved), probe_tcp (a connect loop run passes
times from a container), restore (a switch's render replayed, then parity), vlan_member, parity,
probe_share and mclag_iface (the checks: an MCLAG interface's Local/Remote status in show mclag
brief, which mclag prints); from chapter 4 panos_api, fw_show, probe_ping, probe_http, and the checks
counter and rule_order. From chapter 6 pod_rail, pod_route, serve, k8s_show, pod_net, probe_gateway,
and the checks endpoints, placement and reply_path, with the helpers netstatus (a pod's rail attachments as its network-status
annotation names them), epready (a Service's ready addresses from its EndpointSlices) and gwshare (a
gateway probe's requests and those that failed). From chapter 7 key_hold, key_mint, key_probe, key_show,
gateway_restart, the check key_pods and the cleanup part's key_revoke (common/break/lib-keybreak.sh). counter prints "absent <why>" when the name is in none of the firewall's
counter tables saved before the probe's passes (nothing then relies on it), else "rise <N>", the
sum over the passes of its value after less its value before. From chapter 1 the probe probe_syn and the checks syn_at and tlog_rule: synat counts, in
each capture the probe saved in this mode, the SYNs from the client to the probe's address and port
from the source ports its connects used (read from its own logs), and prints them; tlogrule finds each
of those connects in a saved traffic log, prints "missing ..." while one is not there yet, and
"logged ..." when every one is, each under the rule and with the action the check wants. From
chapter 2 the action dns_answer and restore of a DNS server, the probe matrix_cells and the check
cell_mode: cellmode reads the mode a matrix cell's saved evidence shows (common/matrix/matrix.py
observe) and, for a log line, the rule that logged it, and prints what it found. From
chapter 5 also relay_route,
ns_show, probe_rail and the checks route_src and far_capture. farcap reads the far node's captures
around a probe_rail's passes (its rail NIC and its relay bridge, decoded in the guest): with src relay
it wants every request to arrive from an address of the relay segment and every reply to go into the
far node's own relay bridge toward that same address, with src rail every request from the source's
own rail address and every reply toward it; it prints what it found. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "audit"))
import judge  # noqa: E402
import panos_parse as PP  # noqa: E402

PARTS = ("break", "record", "expect_broken", "heal", "expect_healed", "cleanup")


def labdir() -> Path:
    d = os.environ.get("SFAB_LABDIR") or os.getcwd()
    return Path(d)


def renderdir() -> Path:
    v = os.environ.get("VARIANT") or ""
    return labdir() / "variants" / v if v else labdir()


def load_breaks(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))["breaks"]
    except (OSError, ValueError, KeyError):
        return {}


def cmd_steps(a) -> int:
    b = load_breaks(Path(a.breaks)).get(a.id)
    if b is None:
        print(f"breakheal: no break {a.id}", file=sys.stderr)
        return 2
    for x in b.get(a.part) or []:
        print("\t".join((x["kind"], x.get("node") or "-", json.dumps(x, sort_keys=True))))
    return 0


def cmd_vlan(a) -> int:
    """Is PORT in VLAN N (with mode T or A) in a saved show vlan? Prints what it found; exit 0 when
    the finding is the one wanted."""
    try:
        text = Path(a.file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        print("show vlan not saved")
        return 1
    got = judge.p_vlan(text)
    if a.vlan not in got:
        print(f"Vlan{a.vlan} absent")
        return 1
    mode = got[a.vlan].get(a.port)
    print(f"Vlan{a.vlan}: " + (",".join(f"{p}({m})" for p, m in sorted(got[a.vlan].items(), key=lambda kv: judge.natural(kv[0]))) or "no members"))
    want_present = a.present == "1"
    if want_present:
        return 0 if mode is not None and (not a.mode or mode == a.mode) else 1
    return 0 if mode is None else 1


def cmd_mclag(a) -> int:
    """An MCLAG interface's Local/Remote status in a saved show mclag brief, printed; exit 0 when it is
    the one wanted."""
    try:
        text = Path(a.file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        print("show mclag brief not saved")
        return 1
    got = (judge.p_mclag(text).get("_interfaces") or {}).get(a.portchannel)
    if got is None:
        print(f"{a.portchannel} is not among the MLAG interfaces it lists")
        return 1
    print(f"{a.portchannel} {got}")
    return 0 if got == a.status else 1


def cmd_share(a) -> int:
    n = f = 0
    for line in Path(a.log).read_text(encoding="utf-8", errors="replace").splitlines() if Path(a.log).is_file() else []:
        x = line.split()
        if len(x) >= 3 and x[2] in ("0", "1"):
            n += 1
            f += x[2] == "0"
    print(f"{n} {f}")
    return 0


def cmd_pingshare(a) -> int:
    p = PP.ping(PP.read(a.log))
    n = p["sent"] or 0
    print(f"{n} {n - (p['received'] or 0) if p['sent'] is not None else 0}")
    return 0


def cmd_counter(a) -> int:
    d = Path(a.dir)
    passes = sorted({int(x.name.split("-pass")[1].split("-")[0]) for x in d.glob(f"{a.probe}-{a.mode}-pass*-counters-before.txt")})
    if not passes:
        print("none no counter table saved around the probe")
        return 1
    rise, seen = 0, False
    for p in passes:
        pre = d / f"{a.probe}-{a.mode}-pass{p}-counters"
        b = PP.counters(PP.read(f"{pre}-before.txt"), PP.read(f"{pre}-before.xml"))
        c = PP.counters(PP.read(f"{pre}-after.txt"), PP.read(f"{pre}-after.xml"))
        if a.name in b or a.name in c:
            seen = True
        rise += PP.delta(b, c, a.name).get(a.name, 0)
    if not seen:
        print(f"absent not among the counters this firewall printed around {a.probe} ({len(passes)} passes read)")
        return 1
    print(f"rise {rise}")
    return 0


ICMP_ECHO = re.compile(r"(\d+\.\d+\.\d+\.\d+) > (\d+\.\d+\.\d+\.\d+): ICMP echo (request|reply), id (\d+), seq (\d+)")


def echoes(text: str) -> list:
    """(src, dst, kind) of every ICMP echo in a tcpdump decode (one or two lines a frame)."""
    return [(m.group(1), m.group(2), m.group(3)) for m in ICMP_ECHO.finditer(text or "")]


def cmd_farcap(a) -> int:
    b = load_breaks(Path(a.breaks)).get(a.id) or {}
    pr = next((x for x in b.get("record") or [] if x.get("kind") == "probe_rail" and x.get("id") == a.probe), None)
    cap = (pr or {}).get("capture")
    if not cap:
        print(f"no probe_rail {a.probe} with a capture in break {a.id}")
        return 1
    d = Path(a.dir)
    rail, bridge = cap["rail_iface"], cap["bridge"]
    reqs, reps = [], []
    passes = sorted(d.glob(f"{a.probe}-{a.mode}-pass*-{rail}.txt"))
    for f in passes:
        reqs += [x for x in echoes(f.read_text(encoding="utf-8", errors="replace")) if x[2] == "request" and x[1] == cap["dst_addr"]]
        g = f.with_name(f.name[: -len(f"{rail}.txt")] + f"{bridge}.txt")
        if g.is_file():
            reps += [x for x in echoes(g.read_text(encoding="utf-8", errors="replace")) if x[2] == "reply" and x[0] == cap["dst_addr"]]
    import ipaddress  # noqa: PLC0415
    net = ipaddress.ip_network(cap["relay_prefix"])
    srcs = sorted({x[0] for x in reqs})
    dsts = sorted({x[1] for x in reps})
    seen = (f"{cap['node']} saw {len(reqs)} requests arrive on {rail} from {', '.join(srcs) or 'nowhere'}, and its {len(reps)} replies "
            f"go into its relay bridge {bridge} toward {', '.join(dsts) or 'nowhere'} ({len(passes)} pass{'es' if len(passes) != 1 else ''} captured)")
    if not passes:
        print(f"no capture of {cap['node']}'s {rail} saved around {a.probe}")
        return 1
    if a.src == "relay":
        good = bool(srcs) and all(ipaddress.ip_address(x) in net for x in srcs) and bool(dsts) and dsts == srcs
        print(seen + (f": the source left unpinned took the relay address, of {cap['relay_prefix']}, which on {cap['node']} is its own "
                      "namespace's, so no reply leaves it" if good else ""))
    else:
        good = srcs == [cap["src_addr"]] and dsts == [cap["src_addr"]]
        print(seen + (f": the pinned source {cap['src_addr']}, answered through {cap['node']}'s relay toward the source's rail" if good else ""))
    return 0 if good else 1


# --------------------------------------------------------------------------------------------
# chapter 1: a probe_syn's SYNs and its traffic log lines

SYN_FRAME = re.compile(r"^\d+\.\d+ ")
SYN_TCP = re.compile(r"(\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]*)\]")


def _syn_probe(breaks: Path, bid: str, probe: str):
    b = load_breaks(breaks).get(bid) or {}
    return next((x for x in b.get("record") or [] if x.get("kind") == "probe_syn" and x.get("id") == probe), None)


def _syn_sports(d: Path, probe: str, mode: str) -> list:
    out = []
    for f in sorted(d.glob(f"{probe}-{mode}-pass*.log")):
        for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
            x = line.split()
            if len(x) >= 5 and x[3].isdigit():
                out.append(int(x[3]))
    return out


def _syn_count(text: str, src: str, dst: str, dport: int, sports: set) -> int:
    n, frame = 0, ""
    for line in (text or "").splitlines() + [""]:
        if line[:1] in (" ", "\t"):
            frame += " " + line.strip()
            continue
        m = SYN_TCP.search(frame)
        if m and m.group(5) == "S" and m.group(1) == src and int(m.group(2)) in sports and m.group(3) == dst and int(m.group(4)) == dport:
            n += 1
        frame = line if SYN_FRAME.match(line) else ""
    return n


def cmd_synat(a) -> int:
    chk = json.loads(a.check)
    p = _syn_probe(Path(a.breaks), a.id, chk["probe"])
    if p is None:
        print(f"no probe_syn {chk['probe']} in break {a.id}")
        return 1
    d = Path(a.dir)
    sports = set(_syn_sports(d, p["id"], a.mode))
    counts = {}
    for c in p["capture"]:
        counts[c["id"]] = sum(_syn_count(f.read_text(encoding="utf-8", errors="replace"), p["client_addr"], p["dst_addr"], p["port"], sports)
                              for f in sorted(d.glob(f"{p['id']}-{a.mode}-pass*-{c['id']}.txt")))
    seen, any_, unseen = chk.get("seen") or [], chk.get("seen_any") or [], chk.get("unseen") or []
    good = bool(sports) and all(counts.get(x, 0) > 0 for x in seen) and (not any_ or any(counts.get(x, 0) > 0 for x in any_)) \
        and all(counts.get(x, 0) == 0 for x in unseen)
    parts = [f"{x} {counts.get(x, 0)}" for x in counts]
    what = []
    if seen:
        what.append(f"seen at {', '.join(seen)}")
    if any_:
        what.append(f"at one at least of {', '.join(any_)}")
    if unseen:
        what.append(f"at none of {', '.join(unseen)}")
    ports = f"{min(sports)} to {max(sports)}" if sports else "none"
    print(f"SYNs from {p['client_addr']} (source ports {ports}) to {p['dst_addr']}:{p['port']}: " + ", ".join(parts)
          + (f": {'; '.join(what)}" if good else ""))
    return 0 if good else 1


def cmd_tlogcmd(a) -> int:
    p = _syn_probe(Path(a.breaks), a.id, a.probe)
    if p is None:
        return 1
    print(f"show log traffic direction equal backward receive_time in last-15-minutes dport equal {p['port']}")
    return 0


def cmd_tlogrule(a) -> int:
    chk = json.loads(a.check)
    p = _syn_probe(Path(a.breaks), a.id, chk["probe"])
    if p is None:
        print(f"no probe_syn {chk['probe']} in break {a.id}")
        return 1
    sports = _syn_sports(Path(a.dir), p["id"], a.mode)
    text = PP.read(a.file)
    found = {sp: PP.tlog_find(text, src=p["client_addr"], sport=sp, dst=p["dst_addr"], dport=p["port"]) for sp in sports}
    missing = [sp for sp, e in found.items() if not e]
    if not sports or missing:
        print(f"missing {len(missing)} of {len(sports)} connects in the traffic log" + (f" (ports {', '.join(map(str, missing))})" if missing else ""))
        return 1
    want = chk["rule"][:19]
    es = [e[0] for e in found.values()]
    wrong = [e for e in es if e["rule"] != want or e["action"] != chk["action"]]
    zones = sorted({f"{e['from']} to {e['to']}" for e in es})
    if wrong:
        print(f"wrong {len(wrong)} of {len(es)} connects logged otherwise: " + ", ".join(f"port {e['sport']} {e['rule']} {e['action']}" for e in wrong[:3]))
        return 1
    print(f"logged {len(es)} connects from {p['client_addr']} (source ports {min(sports)} to {max(sports)}) to {p['dst_addr']}:{p['port']}, each "
          f"under {chk['rule']} (shown as {want}), {chk['action']}, zone {', '.join(zones)}")
    return 0


# --------------------------------------------------------------------------------------------
# chapter 2: a matrix cell's mode


def cmd_cellmode(a) -> int:
    """The mode a cell's evidence shows (common/matrix/matrix.py observe), against the check's mode
    and, for a log line, its rule; prints what it found."""
    sys.path.insert(0, str(HERE / "matrix"))
    import matrix as MX  # noqa: PLC0415

    chk = json.loads(a.check)
    try:
        plan = MX.load(a.plan)
    except (OSError, ValueError):
        print(f"no plan {a.plan}")
        return 1
    obs = MX.observe(Path(a.dir), plan, [chk["cell"]])
    o = obs[0] if obs else {}
    first = next(iter((o.get("requests") or {}).values()), {})
    got = o.get("mode")
    what = f"mode {got}"
    if first.get("tlog"):
        e = first["tlog"]
        what += f", {e['rule']} ({e['action']}), zone {e['from']} to {e['to']}"
    if first.get("outcome"):
        what += f"; the client: {MX.view_text(first)}"
    if first.get("dst"):
        what += f"; asked at {first['dst']}"
    elif first.get("remote"):
        what += f"; answered from {first['remote']}"
    good = got == chk["mode"] and (not chk.get("rule") or (first.get("tlog") or {}).get("rule") == chk["rule"][:19])
    print(what if good else f"want {chk['mode']}" + (f" ({chk['rule']})" if chk.get("rule") else "") + f", got {what}")
    return 0 if good else 1


# --------------------------------------------------------------------------------------------
# chapter 6: the serving recipe's reads


def _jload(path: str):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _rail_atts(pod: dict) -> list:
    raw = ((pod.get("metadata") or {}).get("annotations") or {}).get("k8s.v1.cni.cncf.io/network-status") or "[]"
    try:
        nets = json.loads(raw)
    except ValueError:
        nets = []
    return [n for n in nets if not n.get("default")]


def cmd_netstatus(a) -> int:
    """A pod's (or every pod's, from a list) rail attachments as its network-status annotation names
    them; with --rail, exit 0 only when the pod's attachment is that rail's (rail<N>)."""
    d = _jload(a.file)
    if d is None:
        print("unreadable")
        return 1
    items = d.get("items") if "items" in d else [d]
    for i in sorted(items, key=lambda x: (x.get("metadata") or {}).get("name") or ""):
        atts = _rail_atts(i)
        text = "; ".join(f"{n.get('name')} {n.get('interface', '-')} {','.join(n.get('ips') or [])}" for n in atts) or "no rail attachment"
        print(f"{i['metadata']['name']}: {text}" if "items" in d else text)
        if a.rail is not None and "items" not in d:
            names = [str(n.get("name") or "").split("/")[-1] for n in atts]
            return 0 if names == [f"rail{a.rail}"] else 1
    return 0


def cmd_epready(a) -> int:
    d = _jload(a.file)
    if d is None:
        print("unreadable")
        return 1
    print(" ".join(sorted({x for sl in d.get("items") or [] for e in sl.get("endpoints") or []
                           if (e.get("conditions") or {}).get("ready") for x in e.get("addresses") or []})))
    return 0


def cmd_gwshare(a) -> int:
    n = f = 0
    for line in Path(a.file).read_text(encoding="utf-8").splitlines() if Path(a.file).is_file() else []:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        n += 1
        f += r.get("outcome") != "answered"
    print(f"{n} {f}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] in (["break"], ["heal"]):
        if len(argv) != 2:
            print("usage: breakheal.py break|heal ID (heal all)", file=sys.stderr)
            return 2
        mode, bid = argv
        bfile = renderdir() / "gen" / "breaks.json"
        breaks = load_breaks(bfile)
        if not breaks:
            print(f"breakheal: {bfile} holds no break (does the lab have breaks/? run make render)", file=sys.stderr)
            return 2
        if not (mode == "heal" and bid == "all") and bid not in breaks:
            print(f"breakheal: no break {bid} in this lab (have {', '.join(sorted(breaks))})", file=sys.stderr)
            return 2
        drv = HERE / "break" / "breakheal.sh"
        os.execvp("bash", ["bash", str(drv), mode, bid])
    ap = argparse.ArgumentParser(prog="breakheal")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("steps")
    s.add_argument("--breaks", required=True)
    s.add_argument("--id", required=True)
    s.add_argument("--part", required=True, choices=PARTS)
    s = sub.add_parser("vlan")
    s.add_argument("--file", required=True)
    s.add_argument("--vlan", type=int, required=True)
    s.add_argument("--port", required=True)
    s.add_argument("--present", choices=("0", "1"), required=True)
    s.add_argument("--mode", choices=("T", "A"))
    s = sub.add_parser("mclag")
    s.add_argument("--file", required=True)
    s.add_argument("--portchannel", required=True)
    s.add_argument("--status", required=True)
    s = sub.add_parser("share")
    s.add_argument("--log", required=True)
    s = sub.add_parser("pingshare")
    s.add_argument("--log", required=True)
    s = sub.add_parser("counter")
    s.add_argument("--dir", required=True)
    s.add_argument("--probe", required=True)
    s.add_argument("--mode", required=True)
    s.add_argument("--name", required=True)
    s = sub.add_parser("farcap")
    s.add_argument("--breaks", required=True)
    s.add_argument("--id", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--probe", required=True)
    s.add_argument("--mode", required=True)
    s.add_argument("--src", choices=("relay", "rail"), required=True)
    s = sub.add_parser("synat")
    s.add_argument("--breaks", required=True)
    s.add_argument("--id", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--mode", required=True)
    s.add_argument("--check", required=True)
    s = sub.add_parser("tlogcmd")
    s.add_argument("--breaks", required=True)
    s.add_argument("--id", required=True)
    s.add_argument("--probe", required=True)
    s = sub.add_parser("tlogrule")
    s.add_argument("--breaks", required=True)
    s.add_argument("--id", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--mode", required=True)
    s.add_argument("--file", required=True)
    s.add_argument("--check", required=True)
    s = sub.add_parser("netstatus")
    s.add_argument("--file", required=True)
    s.add_argument("--rail", type=int)
    s = sub.add_parser("epready")
    s.add_argument("--file", required=True)
    s = sub.add_parser("gwshare")
    s.add_argument("--file", required=True)
    s = sub.add_parser("cellmode")
    s.add_argument("--dir", required=True)
    s.add_argument("--plan", required=True)
    s.add_argument("--check", required=True)
    a = ap.parse_args(argv)
    return {"steps": cmd_steps, "vlan": cmd_vlan, "mclag": cmd_mclag, "share": cmd_share, "pingshare": cmd_pingshare, "counter": cmd_counter,
            "farcap": cmd_farcap, "netstatus": cmd_netstatus, "epready": cmd_epready, "gwshare": cmd_gwshare, "synat": cmd_synat,
            "tlogcmd": cmd_tlogcmd, "tlogrule": cmd_tlogrule, "cellmode": cmd_cellmode}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
