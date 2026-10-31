#!/usr/bin/env python3
"""hold_request.py ADDRESS FQDN PATH SPORT HOLD_S CAFILE [METHOD BODYFILE HEADERFILE]: one HTTPS request
from a pinned source port, its connection held open HOLD_S seconds after the reply (chapter 4's trace,
common/trace/lib-fwtrace.sh; chapter 1's walk).

It runs in a client container (python3, standard library only), fed on stdin through docker exec,
so the firewall's session table still lists the connection while the trace reads it. It connects to
ADDRESS (the Gateway's VIP, or the public address the firewall translates), names FQDN in TLS and in
the Host header, verifies the chain against CAFILE, sends one GET for PATH with keep-alive, and
prints the reply's status line, headers and body; then "HELD <epoch>" while it holds, and "CLOSED
<epoch>" when it closes. Exit status: 0 a reply, 1 none.

With METHOD (chapter 1: POST), the request carries BODYFILE's bytes as a JSON body and each line of
HEADERFILE as a header (the model's key, in the 0600 file lib-servecap.sh key_to_client wrote in the
client): both files are read inside the client, and neither the body's file nor a header's value is
ever printed. The reply is waited for 120 s, since a model answers once it has run.
"""

import socket
import ssl
import sys
import time


def request_bytes(fqdn, path, method=None, body_file=None, header_file=None) -> bytes:
    head = [f"{method or 'GET'} {path} HTTP/1.1", f"Host: {fqdn}", "User-Agent: sfab-trace", "Accept: */*"]
    body = b""
    if method:
        with open(body_file, "rb") as f:
            body = f.read()
        head += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
        with open(header_file, encoding="utf-8") as f:
            head += [line.strip() for line in f if line.strip() and ":" in line]
    head.append("Connection: keep-alive")
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


def main(argv) -> int:
    address, fqdn, path, sport, hold, cafile = argv[1], argv[2], argv[3], int(argv[4]), float(argv[5]), argv[6]
    method, body_file, header_file = (argv[7], argv[8], argv[9]) if len(argv) > 9 else (None, None, None)
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.set_alpn_protocols(["http/1.1"])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("", sport))
    s.settimeout(120 if method else 20)
    try:
        req = request_bytes(fqdn, path, method, body_file, header_file)
        s.connect((address, 443))
        t = ctx.wrap_socket(s, server_hostname=fqdn)
        t.sendall(req)
        req = b""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = t.recv(4096)
            if not chunk:
                break
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        headers = head.decode("latin-1").split("\r\n")
        length = None
        chunked = False
        for h in headers[1:]:
            k, _, v = h.partition(":")
            if k.strip().lower() == "content-length":
                length = int(v.strip())
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                chunked = True
        while (length is not None and len(body) < length) or (chunked and not body.endswith(b"0\r\n\r\n")):
            chunk = t.recv(4096)
            if not chunk:
                break
            body += chunk
    except (OSError, ssl.SSLError) as e:
        print(f"no reply: {e}", flush=True)
        return 1
    print("\n".join(headers), flush=True)
    print("", flush=True)
    print(body.decode("utf-8", "replace"), flush=True)
    print(f"HELD {time.time():.6f}", flush=True)
    time.sleep(hold)
    try:
        t.close()
    except OSError:
        pass
    print(f"CLOSED {time.time():.6f}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
