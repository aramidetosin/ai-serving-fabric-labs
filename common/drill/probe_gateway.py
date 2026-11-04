#!/usr/bin/env python3
"""probe_gateway.py: the gateway probe of chapter 6's drills and break, run in a client container.

    probe_gateway.py --dir DIR --target MODEL URL [--target MODEL URL ...] [--interval 1] [--timeout 100]
                     [--max-tokens 8] (--count N | --until-stop [--max-s 3600]) [--resolve HOST:PORT:ADDR]
                     [--cafile FILE] [--every MODEL K ...]

Every --interval seconds, for each model, one chat completion (not streamed) to the model's URL with
the model's key, read from DIR/key-<model>; each request runs on its own, so a slow answer never
holds the next one back, and the rate stays the same while answers slow down. --every MODEL K sends
that model's request on every K-th interval only, from the first (a slower model at a lower rate).
Each request is one JSON line in DIR/records-<model>.jsonl:

  n, sent, done    its number among its model's requests, and when it was sent and when it ended,
                   in seconds since the epoch on the container's clock, which is the lab host's (a
                   container has no clock of its own), with microseconds
  status, outcome  the HTTP status; answered (HTTP 200 and a choice) or failed (anything else)
  why              for a failed request: http <status>, timeout, refused, reset, or the error's name
  model, base,     the router's own headers: the deployment that answered, its API base, and how
  retries          many times it tried again (x-litellm-model-name, -model-api-base, -attempted-retries)

With --count it runs N intervals (N requests a model, fewer for a model under --every), with
--until-stop until DIR/stop exists (or --max-s passes); either way it then waits for the requests in
flight and prints, a model a line, how many were sent, answered and failed. Standard library only.
The key travels only in the Authorization header; it is never printed or written anywhere else.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import threading
import time
import urllib.parse

DEFAULT_CA = "/etc/ssl/certs/ca-certificates.crt"
PROMPT = "Answer in one short sentence: what does a load balancer do?"
MAX_IN_FLIGHT = 64


class Pinned(http.client.HTTPSConnection):
    """An HTTPS connection to an address that still sends SNI and Host for the URL's name."""

    def __init__(self, host, port, address, **kw):
        super().__init__(host, port, **kw)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address or self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def one(url: str, key: str, model: str, max_tokens: int, timeout: float, resolve, ctx) -> dict:
    u = urllib.parse.urlsplit(url)
    port = u.port or 443
    addr = resolve[2] if resolve and resolve[0] == u.hostname and resolve[1] == port else None
    body = json.dumps({"model": model, "max_tokens": max_tokens, "messages": [{"role": "user", "content": PROMPT}]}).encode()
    hdr = {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}
    out = {"status": 0, "outcome": "failed", "why": "", "model": None, "base": None, "retries": None}
    conn = Pinned(u.hostname, port, addr, timeout=timeout, context=ctx)
    try:
        conn.request("POST", u.path, body=body, headers=hdr)
        r = conn.getresponse()
        raw = r.read()
        out["status"] = r.status
        out["model"] = r.getheader("x-litellm-model-name")
        out["base"] = r.getheader("x-litellm-model-api-base")
        rt = r.getheader("x-litellm-attempted-retries")
        out["retries"] = int(rt) if rt and rt.isdigit() else None
        if r.status != 200:
            out["why"] = f"http {r.status}"
            return out
        try:
            doc = json.loads(raw)
        except ValueError:
            out["why"] = "no JSON"
            return out
        if doc.get("choices"):
            out["outcome"] = "answered"
        else:
            out["why"] = "no choice"
    except (socket.timeout, TimeoutError):
        out["why"] = "timeout"
    except ConnectionRefusedError:
        out["why"] = "refused"
    except ConnectionResetError:
        out["why"] = "reset"
    except ssl.SSLError as e:
        out["why"] = f"tls {e.reason or 'error'}"
    except (http.client.HTTPException, OSError) as e:
        out["why"] = type(e).__name__
    finally:
        conn.close()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="probe_gateway", description=__doc__.strip().splitlines()[0])
    ap.add_argument("--dir", required=True)
    ap.add_argument("--target", nargs=2, action="append", metavar=("MODEL", "URL"), required=True)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--timeout", type=float, default=100.0)
    ap.add_argument("--max-tokens", type=int, default=8)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--count", type=int)
    g.add_argument("--until-stop", action="store_true")
    ap.add_argument("--max-s", type=float, default=3600.0)
    ap.add_argument("--resolve", default="")
    ap.add_argument("--cafile", default="")
    ap.add_argument("--every", nargs=2, action="append", default=[], metavar=("MODEL", "K"))
    a = ap.parse_args(argv)
    every = {}
    for model, k in a.every:
        if model not in {m for m, _ in a.target} or not k.isdigit() or int(k) < 1:
            print(f"probe_gateway: --every {model} {k}: a model of the targets and a whole number of intervals", file=sys.stderr)
            return 2
        every[model] = int(k)
    keys = {}
    for model, _ in a.target:
        try:
            with open(os.path.join(a.dir, f"key-{model}"), encoding="utf-8") as f:
                keys[model] = f.read().strip()
        except OSError as e:
            print(f"probe_gateway: no key for {model}: {e.strerror}", file=sys.stderr)
            return 2
        if not keys[model]:
            print(f"probe_gateway: the key file for {model} is empty", file=sys.stderr)
            return 2
    resolve = None
    if a.resolve:
        h, p, ad = (a.resolve.split(":", 2) + ["", ""])[:3]
        resolve = (h, int(p), ad) if p.isdigit() else None
    cafile = a.cafile or (DEFAULT_CA if os.path.exists(DEFAULT_CA) else None)
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    lock = threading.Lock()
    slots = threading.Semaphore(MAX_IN_FLIGHT)
    counts = {m: {"sent": 0, "answered": 0, "failed": 0} for m, _ in a.target}
    files = {m: open(os.path.join(a.dir, f"records-{m}.jsonl"), "a", encoding="utf-8") for m, _ in a.target}
    threads: list = []

    def run(model: str, url: str, n: int) -> None:
        try:
            sent = time.time()
            r = one(url, keys[model], model, a.max_tokens, a.timeout, resolve, ctx)
            rec = {"n": n, "model": model, "sent": round(sent, 6), "done": round(time.time(), 6), "status": r["status"],
                   "outcome": r["outcome"], "why": r["why"], "answered_by": r["model"], "base": r["base"], "retries": r["retries"]}
            with lock:
                files[model].write(json.dumps(rec, sort_keys=True) + "\n")
                files[model].flush()
                counts[model][r["outcome"]] += 1
        finally:
            slots.release()

    start = time.time()
    stop = os.path.join(a.dir, "stop")
    i = 0
    while True:
        if a.count is not None and i >= a.count:
            break
        if a.until_stop and (os.path.exists(stop) or time.time() - start > a.max_s):
            break
        for model, url in a.target:
            if i % every.get(model, 1):
                continue
            slots.acquire()
            counts[model]["sent"] += 1
            t = threading.Thread(target=run, args=(model, url, counts[model]["sent"]), daemon=True)
            t.start()
            threads.append(t)
        i += 1
        time.sleep(max(0.0, start + i * a.interval - time.time()))
    for t in threads:
        t.join()
    for f in files.values():
        f.close()
    for model, _ in a.target:
        c = counts[model]
        print(f"{model}: sent {c['sent']}, answered {c['answered']}, failed {c['failed']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
