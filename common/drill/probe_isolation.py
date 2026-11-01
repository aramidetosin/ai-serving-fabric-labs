#!/usr/bin/env python3
"""probe_isolation.py: chapter 11's isolation drill in one client (common/drill/lib-p3drill.sh).

    probe_isolation.py --plan PLAN.json --log FILE

PLAN (p3drill.py iso-plan) names the population's own Gateway's /echo URL (with its pin when the
client's resolver is not in the lab), the matrix's cells it tries (a connect or a GET each, with its
mode), the rounds, the interval and the connect timeout. Every interval, one round: the own probe,
then every cell once, each from a fresh source port. One JSON line an attempt in FILE:

    {"round": r, "t": ..., "what": "own" | <cell>, "mode": ..., "kind": "connect" | "http",
     "outcome": "CONNECTED" | "TIMEOUT" | "REFUSED" | "ERROR:..." | "HTTP <status>"}

and a last line {"done": true}. Standard library only; no credential is involved (a cell that would
need a key is left out by the plan).
"""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import ssl
import time
import urllib.parse


def connect(address: str, port: int, timeout: float) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((address, port))
        return "CONNECTED"
    except socket.timeout:
        return "TIMEOUT"
    except ConnectionRefusedError:
        return "REFUSED"
    except OSError as e:
        return "ERROR:" + (e.strerror or type(e).__name__).replace(" ", "_")
    finally:
        s.close()


def get(url: str, resolve, cafile: str, timeout: float) -> str:
    u = urllib.parse.urlsplit(url)
    addr = None
    if resolve:
        h, _p, a = resolve.split(":", 2)
        if h == u.hostname:
            addr = a
    ctx = ssl.create_default_context(cafile=cafile)
    try:
        sock = socket.create_connection((addr or u.hostname, u.port or 443), timeout)
    except socket.timeout:
        return "TIMEOUT"
    except ConnectionRefusedError:
        return "REFUSED"
    except OSError as e:
        return "ERROR:" + (e.strerror or type(e).__name__).replace(" ", "_")
    try:
        c = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
        c.sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
        c.request("GET", (u.path or "/") + (f"?{u.query}" if u.query else ""), headers={"User-Agent": "sfab-isolation", "Connection": "close"})
        r = c.getresponse()
        r.read()
        return f"HTTP {r.status}"
    except socket.timeout:
        return "TIMEOUT"
    except (OSError, ssl.SSLError, http.client.HTTPException) as e:
        return "ERROR:" + type(e).__name__
    finally:
        sock.close()


def main() -> int:
    ap = argparse.ArgumentParser(prog="probe_isolation")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    p = json.load(open(a.plan, encoding="utf-8"))
    to, ca = float(p["timeout_s"]), p.get("ca_root") or "/shared/ca/root.crt"
    with open(a.log, "w", encoding="utf-8") as out:
        def w(rec):
            out.write(json.dumps(rec, sort_keys=True) + "\n")
            out.flush()

        nxt = time.time()
        for r in range(int(p["rounds"])):
            own = p["own"]
            w({"round": r, "t": round(time.time(), 6), "what": "own", "mode": "allowed", "kind": "http",
               "outcome": get(own["url"] + f"?msg=sfab-iso-{r}", own.get("resolve"), ca, to)})
            for t in p["tries"]:
                t0 = round(time.time(), 6)
                if t["kind"] == "connect":
                    o = connect(t["address"], int(t["port"]), to)
                else:
                    o = get(t["url"], t.get("resolve"), ca, to)
                w({"round": r, "t": t0, "what": t["cell"], "mode": t["mode"], "kind": t["kind"], "outcome": o})
            nxt += float(p["interval_s"])
            time.sleep(max(0.0, nxt - time.time()))
        w({"done": True, "t": round(time.time(), 6)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
