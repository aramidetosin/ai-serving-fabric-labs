#!/usr/bin/env python3
"""hold_conns.py: N keep-alive HTTPS connections from one client, held open and used again, for
Part III's session measurement (chapter 10) and the isolation drill under load (chapter 11).

    python3 - ADDRESS FQDN PATH N HOLD_S EVERY_S SPORT CAFILE TAG [STOPFILE] < common/trace/hold_conns.py

It runs in a client container (python3, standard library only), fed on stdin through docker exec.
Connection i (0 to N-1) leaves from source port SPORT + i, connects to ADDRESS (the Gateway's VIP,
or the published address the firewall translates), names FQDN in TLS (verified against CAFILE) and
in the Host header, and sends GET PATH?msg=sfab-hold-TAG-<i>-<k> with keep-alive; every EVERY_S it
sends the next request on the same connection, so each stays one TCP connection, one firewall
session, for HOLD_S. Every event is one JSON line on stdout, stamped with the client's clock (the
host's, for a container):

    {"t": ..., "event": "open", "conn": i, "sport": ...}        the TLS handshake done
    {"t": ..., "event": "reply", "conn": i, "k": k, "status": 200}
    {"t": ..., "event": "error", "conn": i, "k": k, "error": "..."}   the connection is then dropped
    {"t": ..., "event": "held", "open": n}                       once, when every connection has had
                                                                 its first reply (the counts are read
                                                                 after this line)
    {"t": ..., "event": "closed", "conn": i}
    {"t": ..., "event": "done", "open": n, "replies": r, "errors": e}

It stops after HOLD_S, or as soon as STOPFILE exists (the harness removes the held load early),
closing every connection itself. No credential is involved: the test backend's path needs none.
Exit status 0 when every connection lived to the end with every reply 200, 1 otherwise.
"""

import json
import os
import socket
import ssl
import sys
import time


def ev(**k):
    k["t"] = round(time.time(), 6)
    print(json.dumps(k, sort_keys=True), flush=True)


def read_reply(t) -> int:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = t.recv(4096)
        if not chunk:
            raise OSError("closed by the server")
        buf += chunk
    head, _, body = buf.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    length, chunked = None, False
    for h in lines[1:]:
        k, _, v = h.partition(":")
        if k.strip().lower() == "content-length":
            length = int(v.strip())
        elif k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
            chunked = True
    while (length is not None and len(body) < length) or (chunked and not body.endswith(b"0\r\n\r\n")):
        chunk = t.recv(4096)
        if not chunk:
            break
        body += chunk
    return status


def main(argv) -> int:
    address, fqdn, path, n, hold, every, sport, cafile, tag = (argv[1], argv[2], argv[3], int(argv[4]), float(argv[5]),
                                                              float(argv[6]), int(argv[7]), argv[8], argv[9])
    stop = argv[10] if len(argv) > 10 else None
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.set_alpn_protocols(["http/1.1"])
    conns, replies, errors = {}, 0, 0
    sep = "&" if "?" in path else "?"

    def send(i, k):
        nonlocal replies, errors
        t = conns[i]
        req = (f"GET {path}{sep}msg=sfab-hold-{tag}-{i}-{k} HTTP/1.1\r\nHost: {fqdn}\r\nUser-Agent: sfab-hold\r\n"
               "Accept: */*\r\nConnection: keep-alive\r\n\r\n").encode()
        try:
            t.sendall(req)
            st = read_reply(t)
            ev(event="reply", conn=i, k=k, status=st)
            replies += 1
            if st != 200:
                errors += 1
        except (OSError, ssl.SSLError, ValueError, IndexError) as e:
            ev(event="error", conn=i, k=k, error=str(e)[:120])
            errors += 1
            try:
                t.close()
            except OSError:
                pass
            del conns[i]

    t0 = time.time()
    for i in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(20)
        try:
            s.bind(("", sport + i))
            s.connect((address, 443))
            conns[i] = ctx.wrap_socket(s, server_hostname=fqdn)
            ev(event="open", conn=i, sport=sport + i)
        except (OSError, ssl.SSLError) as e:
            ev(event="error", conn=i, k=0, error=str(e)[:120])
            errors += 1
            continue
        send(i, 0)
    ev(event="held", open=len(conns))
    k = 1
    nxt = t0 + every
    while time.time() - t0 < hold:
        if stop and os.path.exists(stop):
            break
        if time.time() >= nxt:
            for i in sorted(conns):
                send(i, k)
            k += 1
            nxt += every
        time.sleep(0.2)
    alive = len(conns)
    for i in sorted(conns):
        try:
            conns[i].close()
        except OSError:
            pass
        ev(event="closed", conn=i)
    ev(event="done", open=alive, replies=replies, errors=errors)
    return 0 if alive == n and errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
