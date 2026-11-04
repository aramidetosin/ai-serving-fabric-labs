#!/usr/bin/env python3
"""probe_echo.py: the lease drill's probe of the test backend through a Gateway (chapter 8), run in a
client container (common/drill/lib-leasedrill.sh).

    probe_echo.py --url URL --log FILE [--resolve HOST:PORT:ADDR] [--cafile FILE] [--interval 2]
                  [--timeout 3] --stop FILE [--max-s 1800]

Every --interval seconds one GET of URL?msg=sfab-lease-<n> on a new TCP and TLS connection of its
own (so each request is a new flow to the VIP, as the lease's holder answers it), each in its own
thread so a hung one never holds the next back. It needs nothing on the cut node but the lease: the
test backend's pods run elsewhere. One JSON line a request in FILE, written as it ends:

    n, sent, done   its number and when it was sent and ended, in seconds since the epoch on the
                    container's clock (the lab host's)
    status          the HTTP status, or null
    outcome         answered (HTTP 200) or failed
    why             for a failed request: http <status>, timeout, refused, reset, or the error's name

It stops when FILE --stop exists, or after --max-s, waits for the requests in flight and prints how
many were sent, answered and failed. Standard library only; no credential is involved.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import threading
import time
import urllib.parse


class Pinned(http.client.HTTPSConnection):
    def __init__(self, host, port, address, **kw):
        super().__init__(host, port, **kw)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address or self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def one(n: int, a, ctx, lock, out, counts):
    u = urllib.parse.urlsplit(a.url)
    host = u.hostname
    addr = None
    if a.resolve:
        h, _p, addr = a.resolve.split(":", 2)
        if h != host:
            addr = None
    sep = "&" if u.query else "?"
    path = (u.path or "/") + (f"?{u.query}" if u.query else "") + f"{sep}msg=sfab-lease-{n}"
    t0 = time.time()
    rec = {"n": n, "sent": round(t0, 6), "status": None}
    try:
        c = Pinned(host, u.port or 443, addr, timeout=a.timeout, context=ctx)
        c.request("GET", path, headers={"User-Agent": "sfab-lease", "Connection": "close"})
        r = c.getresponse()
        r.read()
        rec["status"] = r.status
        rec["outcome"] = "answered" if r.status == 200 else "failed"
        if r.status != 200:
            rec["why"] = f"http {r.status}"
        c.close()
    except socket.timeout:
        rec.update(outcome="failed", why="timeout")
    except ConnectionRefusedError:
        rec.update(outcome="failed", why="refused")
    except ConnectionResetError:
        rec.update(outcome="failed", why="reset")
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        rec.update(outcome="failed", why=type(e).__name__)
    rec["done"] = round(time.time(), 6)
    with lock:
        out.write(json.dumps(rec, sort_keys=True) + "\n")
        out.flush()
        counts[rec["outcome"]] = counts.get(rec["outcome"], 0) + 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="probe_echo")
    ap.add_argument("--url", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--resolve")
    ap.add_argument("--cafile", default="/shared/ca/root.crt")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--stop", required=True)
    ap.add_argument("--max-s", type=float, default=1800.0)
    a = ap.parse_args()
    ctx = ssl.create_default_context(cafile=a.cafile)
    lock, counts, threads = threading.Lock(), {}, []
    t_end = time.time() + a.max_s
    n = 0
    nxt = time.time()
    with open(a.log, "w", encoding="utf-8") as out:
        while time.time() < t_end and not os.path.exists(a.stop):
            th = threading.Thread(target=one, args=(n, a, ctx, lock, out, counts), daemon=True)
            th.start()
            threads.append(th)
            n += 1
            nxt += a.interval
            time.sleep(max(0.0, nxt - time.time()))
        for th in threads:
            th.join(a.timeout + 2)
    print(f"sent {n} answered {counts.get('answered', 0)} failed {counts.get('failed', 0)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
