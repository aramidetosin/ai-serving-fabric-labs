#!/usr/bin/env python3
"""Stand-ins for tcpdump and the firewall's traffic log in common/tests/test_m2.py's trace test.

tcpdump -w FILE writes a placeholder and waits for SIGINT; tcpdump -r FILE prints the decode the
point (named by the file) would show for the recorded SYN on its way from ent-client to the users'
VIP held by $SHIM_TRACE_HOLDER: the client and ethernet1/4 untagged with TTL 64, one ae1 leg and its
trunk port tagged 110, the server port and bond0 tagged 110 (the ingress VLAN rides the bond
tagged) with TTL 63, nothing on the other legs.
"""
import os
import re
import signal
import sys
import time

SEQ = 1234567890


def syn(vlan, ttl, sport=41443, seq=SEQ):
    eth = (f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan
           else "ethertype IPv4 (0x0800), length 74: ")
    return (f"2026-10-20 10:00:01.000100 0c:00:aa:bb:cc:01 > 02:5a:67:00:00:01, {eth}(tos 0x0, ttl {ttl}, id 4321, offset 0, "
            f"flags [DF], proto TCP (6), length 60)\n    10.24.10.10.{sport} > 10.20.11.210.443: Flags [S], cksum 0x1a2b (correct), "
            f"seq {seq}, win 64240, options [mss 1460], length 0\n")


def decode_for(point: str) -> str:
    if point.startswith(("1-", "2-")):
        return (syn(None, 64, 41442, 99) if point.startswith("1-") else "") + syn(None, 64)
    if point.endswith("ae1-leg1") or point.startswith("4-fe-sw1-"):
        return syn(110, 63)
    if point.startswith("5-fe-sw1-") or point.startswith("6-"):
        return syn(110, 63)
    return ""


def point_of(path: str) -> str:
    base = os.path.basename(path)
    base = re.sub(r"\.(pcap|txt)$", "", base)
    return base[len("sfab-trace-"):] if base.startswith("sfab-trace-") else base


def tcpdump(argv):
    if "-w" in argv:
        out = argv[argv.index("-w") + 1]
        open(out, "wb").write(b"\xd4\xc3\xb2\xa1stand-in\n")
        signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        for _ in range(600):
            time.sleep(0.2)
        return 0
    if "-r" in argv:
        sys.stdout.write(decode_for(point_of(argv[argv.index("-r") + 1])))
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(tcpdump(sys.argv[1:]))
