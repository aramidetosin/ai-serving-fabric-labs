#!/usr/bin/env python3
"""dnsq.py: one DNS query over UDP from a chosen source address, printed in dig's own shape, for a
node that holds no dig (the ISP router, sfab/frr). Fed to the node's python3 on its standard input:

    python3 - SERVER NAME TYPE [SOURCE] [RD] [TIMEOUT_S] < common/trace/dnsq.py

SOURCE binds the query's source address (the ISP router's link toward the firewall, outside the
ISP resolver's clients); RD is 1 (recursion desired, as dig asks) or 0; TYPE is A or AAAA. The
answer is printed as dig prints its header, flags, answer section and server line, so one parser
reads both (common/audit/tenancy.py dig_result); a query with no answer prints dig's own
";; connection timed out; no servers could be reached". Standard library only; it changes nothing.
"""

import random
import socket
import struct
import sys

TYPES = {"A": 1, "AAAA": 28}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def query(name: str, qtype: int, rd: bool) -> tuple:
    qid = random.randint(1, 65535)
    flags = 0x0100 if rd else 0
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"
    return qid, struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)


def _name(b: bytes, i: int) -> tuple:
    out, jumped, end = [], False, i
    while True:
        n = b[i]
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = i + 2
            i = ((n & 0x3F) << 8) | b[i + 1]
            jumped = True
            continue
        if n == 0:
            return ".".join(out) + ".", (end if jumped else i + 1)
        out.append(b[i + 1:i + 1 + n].decode(errors="replace"))
        i += 1 + n


def decode(b: bytes) -> dict:
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", b[:12])
    i = 12
    for _ in range(qd):
        _n, i = _name(b, i)
        i += 4
    answers = []
    for _ in range(an):
        n, i = _name(b, i)
        t, _c, ttl, ln = struct.unpack(">HHIH", b[i:i + 10])
        i += 10
        rd = b[i:i + ln]
        i += ln
        if t == 1 and ln == 4:
            answers.append((n, ttl, "A", socket.inet_ntop(socket.AF_INET, rd)))
        elif t == 28 and ln == 16:
            answers.append((n, ttl, "AAAA", socket.inet_ntop(socket.AF_INET6, rd)))
    names = [("qr", 0x8000), ("aa", 0x0400), ("tc", 0x0200), ("rd", 0x0100), ("ra", 0x0080)]
    return {"id": qid, "status": RCODES.get(flags & 0xF, str(flags & 0xF)), "flags": [x for x, m in names if flags & m],
            "counts": (qd, an, ns, ar), "answers": answers}


def main(argv) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    server, name, qt = argv[0], argv[1], argv[2].upper()
    src = argv[3] if len(argv) > 3 and argv[3] not in ("", "-") else None
    rd = (argv[4] if len(argv) > 4 else "1") != "0"
    timeout = float(argv[5]) if len(argv) > 5 else 5.0
    qid, pkt = query(name, TYPES[qt], rd)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if src:
        s.bind((src, 0))
    s.settimeout(timeout)
    print(f"; <<>> dnsq.py <<>> @{server} {name} {qt}" + (f" -b {src}" if src else ""))
    try:
        s.sendto(pkt, (server, 53))
        while True:
            b, _a = s.recvfrom(4096)
            if len(b) >= 12 and struct.unpack(">H", b[:2])[0] == qid:
                break
    except (socket.timeout, OSError):
        print(";; connection timed out; no servers could be reached")
        return 9
    d = decode(b)
    qd, an, ns, ar = d["counts"]
    print(";; Got answer:")
    print(f";; ->>HEADER<<- opcode: QUERY, status: {d['status']}, id: {d['id']}")
    print(f";; flags: {' '.join(d['flags'])}; QUERY: {qd}, ANSWER: {an}, AUTHORITY: {ns}, ADDITIONAL: {ar}")
    if d["answers"]:
        print("")
        print(";; ANSWER SECTION:")
        for n, ttl, t, v in d["answers"]:
            print(f"{n}\t\t{ttl}\tIN\t{t}\t{v}")
    print("")
    print(f";; SERVER: {server}#53({server}) (UDP)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
