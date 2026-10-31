"""Chapter 4's stand-in firewall texts, for common/tests/test_ch04.py and the ch04 shims.

Each function prints what the PA-VM's CLI or XML API prints for one command, in the shapes the
harness reads (common/audit/panos_parse.py), filled from the lab's inventory. The figures and ids are
made up; nothing here is the book's or a lab's record. The traffic log's layout is the one chapter
3's revision 1 trace recorded (common/tests/recorded/ch03-rev1/fw-traffic-log.txt); the others
are the CLI's documented shapes, as unproven as the parsers that read them.
"""

from __future__ import annotations

import json

COUNTER_DESC = {
    "pkt_recv": ("info", "packet", "pktproc", "Packets received"),
    "flow_policy_nat_land": ("drop", "flow", "session", "Session setup: source NAT IP allocation result in LAND attack"),
    "flow_policy_deny": ("drop", "flow", "session", "Session setup: denied by policy"),
    "flow_dos_pf_strictip": ("drop", "flow", "dos", "Packets dropped: Zone protection option 'strict-ip-check'"),
}


def counters_cli(values: dict) -> str:
    rows = [f"{n:<39}{v:>9}{0:>9} {COUNTER_DESC[n][0]:<9} {COUNTER_DESC[n][1]:<9} {COUNTER_DESC[n][2]:<9} {COUNTER_DESC[n][3]}"
            for n, v in values.items()]
    return "\n".join(["", "Global counters:", "Elapsed time since last sampling: 2.395 seconds", "",
                      "name                                   value     rate severity  category  aspect    description",
                      "-" * 80, *rows, "-" * 80, f"Total counters shown: {len(rows)}", "-" * 80])


def counters_xml(values: dict) -> str:
    es = "".join(f"<entry><category>{COUNTER_DESC[n][1]}</category><severity>{COUNTER_DESC[n][0]}</severity><value>{v}</value>"
                 f"<rate>0</rate><aspect>{COUNTER_DESC[n][2]}</aspect><desc>{COUNTER_DESC[n][3]}</desc><id>{i}</id><name>{n}</name></entry>"
                 for i, (n, v) in enumerate(values.items()))
    return f"<response status=\"success\"><result><global><t>2</t><len>{len(values)}</len><counters>{es}</counters></global></result></response>"


TLOG_HEAD = ["Time                App             From                            Src Port          Source",
             "Rule                Action          To                              Dst Port          Destination",
             "Src User        Dst User                        End Reason", "Rule_UUid", "=" * 100]


def tlog_entry(time: str, app: str, frm: str, sport, src: str, rule: str, action: str, to: str, dport, dst: str, end="aged-out") -> list:
    return [f"{time} {app:<16}{frm:<32}{str(sport):<18}{src}",
            f"{rule[:19]:<20}{action:<16}{to:<32}{str(dport):<18}{dst}",
            f"{'':<48}{end}", "c4fdb3cf-0296-4dbe-9932-5a5dcf067d6f"]


def tlog(entries: list) -> str:
    out = list(TLOG_HEAD)
    for e in entries:
        out += tlog_entry(*e)
    return "\n".join(out)


def session_all(sid: int, app: str, src: str, sport: int, frm: str, xsrc: str, xsport: int, dst: str, dport: int, to: str,
                xdst: str, xdport: int, flag: str = "") -> str:
    return "\n".join(["-" * 80,
                      "ID          Application    State   Type Flag  Src[Sport]/Zone/Proto (translated IP[Port])",
                      "Vsys                                          Dst[Dport]/Zone (translated IP[Port])",
                      "-" * 80,
                      f"{sid:<12} {app:<14} ACTIVE  FLOW  {flag:<4} {src}[{sport}]/{frm}/6  ({xsrc}[{xsport}])",
                      f"vsys1                                          {dst}[{dport}]/{to}  ({xdst}[{xdport}])"])


def session_detail(sid: int, src: str, sport: int, frm: str, dst: str, dport: int, s2c_src: str, to: str, rule: str,
                   nat_rule: str | None, ingress: str, egress: str) -> str:
    lines = ["", "--------------------------------------------------------------------------------", f"Session        {sid}", "",
             "        c2s flow:", f"                source:      {src} [{frm}]", f"                dst:         {dst}",
             "                proto:       6", f"                sport:       {sport}           dport:      {dport}",
             "                state:       ACTIVE          type:       FLOW", "                src user:    unknown",
             "                dst user:    unknown", "", "        s2c flow:", f"                source:      {s2c_src} [{to}]",
             f"                dst:         {src}", "                proto:       6",
             f"                sport:       {dport}             dport:      {sport}",
             "                state:       ACTIVE          type:       FLOW", "                src user:    unknown",
             "                dst user:    unknown", "",
             "        start time                           : Tue Oct 20 10:00:01 2026",
             "        timeout                              : 3600 sec",
             "        vsys                                 : vsys1",
             "        application                          : ssl",
             f"        rule                                 : {rule}",
             "        session to be logged at end          : True"]
    if nat_rule:
        lines += ["        address/port translation             : destination",
                  f"        nat-rule                             : {nat_rule}(vsys1)"]
    else:
        lines += ["        address/port translation             : none"]
    lines += [f"        ingress interface                    : {ingress}", f"        egress interface                     : {egress}"]
    return "\n".join(lines)


def running_policy(names: list, kind: str = "security") -> str:
    head = ["", "Nat policy configured on vsys1:"] if kind == "nat" else [""]
    out = list(head)
    for i, n in enumerate(names, 1):
        out += [f'"{n}; index: {i}" {{', "        from any;", "}", ""]
    return "\n".join(out)


def ntp(server: str, synched: bool = True) -> str:
    return "\n".join(["", "NTP state:", f"    NTP synched to {server}" if synched else "    NTP not synched",
                      f"    NTP server: {server}", f"        status: {'synched' if synched else 'rejected'}",
                      "        reachable: yes", "        authentication-type: none"])


def frr_routes(routes: list) -> str:
    out = {}
    for r in routes:
        out[r["dest"]] = [{"prefix": r["dest"], "protocol": "static", "selected": True, "installed": True,
                           "nexthops": [{"ip": r["via"], "afi": "ipv4", "active": True}]}]
    return json.dumps(out)


def ping(dst: str, sent: int, received: int) -> str:
    lines = [f"PING {dst} ({dst}) 56(84) bytes of data."]
    lines += [f"64 bytes from {dst}: icmp_seq={i} ttl=64 time=0.5 ms" for i in range(1, received + 1)]
    lines += ["", f"--- {dst} ping statistics ---",
              f"{sent} packets transmitted, {received} received, {int(100 * (sent - received) / sent) if sent else 0}% packet loss, time 2000ms"]
    return "\n".join(lines)


def icmp_frame(t: str, src: str, dst: str, kind: str, seq: int, vlan: int | None = None) -> str:
    eth = f"ethertype 802.1Q (0x8100), length 102: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan else "ethertype IPv4 (0x0800), length 98: "
    return (f"2026-10-20 10:00:{t} 0c:00:aa:bb:cc:01 > ba:db:ee:fb:ad:f0, {eth}(tos 0x0, ttl 64, id 4242, offset 0, flags [DF], "
            f"proto ICMP (1), length 84)\n    {src} > {dst}: ICMP echo {kind}, id 7, seq {seq}, length 64")


def tcp_syn(t: str, src: str, sport: int, dst: str, dport: int, seq: int, vlan: int | None = None) -> str:
    eth = f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan else "ethertype IPv4 (0x0800), length 74: "
    return (f"2026-10-20 10:00:{t} 0c:00:aa:bb:cc:02 > ba:db:ee:fb:ad:f0, {eth}(tos 0x0, ttl 64, id 999, offset 0, flags [DF], "
            f"proto TCP (6), length 60)\n    {src}.{sport} > {dst}.{dport}: Flags [S], cksum 0x1a2b (correct), seq {seq}, win 64240, length 0")


def tcp_data(t: str, src: str, sport: int, dst: str, dport: int, seq: int, length: int, vlan: int | None = None) -> str:
    eth = f"ethertype 802.1Q (0x8100), length {length + 18}: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan else f"ethertype IPv4 (0x0800), length {length + 14}: "
    return (f"2026-10-20 10:00:{t} 0c:00:aa:bb:cc:03 > ba:db:ee:fb:ad:f0, {eth}(tos 0x0, ttl 63, id 1000, offset 0, flags [DF], "
            f"proto TCP (6), length {length})\n    {src}.{sport} > {dst}.{dport}: Flags [.], cksum 0x1a2b (correct), seq {seq}:{seq + length - 52}, ack 1, win 501, length {length - 52}")
