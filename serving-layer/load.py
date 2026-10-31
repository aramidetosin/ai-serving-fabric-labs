#!/usr/bin/env python3
"""load.py: N concurrent streaming clients for T seconds against an OpenAI-compatible endpoint.

    load.py --url https://serve.tarnwick.example/chat/v1 --key-file KEY [--users 10] [--seconds 60]
            [--resolve serve.tarnwick.example:443:198.51.100.2] [--model chat] [--max-tokens 64]
            [--records FILE] [--cut-ok] [--cafile FILE] [--timeout 120]

Each user sends one streamed chat completion after another (POST <url>/chat/completions with
"stream": true and the key as a bearer token) until T seconds have passed; a request already
started is always read to its end, and a user whose request failed waits --pause seconds (1 by
default) before its next. Every request ends one of three ways:

  answered   HTTP 200, and the stream finished: a choice with a finish_reason, or data: [DONE]
  failed     no answer reached the client: an HTTP status other than 200, a refused or reset
             connection, or a timeout or end of stream before the first streamed token
  cut        the stream had sent tokens and then ended without finishing (a reset, a timeout or
             the end of the stream): the client holds a part of an answer, which cannot be sent
             again without repeating it

The report counts each, and the failed requests by what ended them, and prints the repository's
PASS, FAIL and RESULT lines: no failed request (the criterion every drill under load uses), no
stream cut mid-answer (with --cut-ok it is reported beside the count, not judged), and at least
one request answered. Nothing here measures how fast: the report and the records hold no
duration, token count or rate. --records writes one JSON line per request (its user, when it
started in whole seconds from the start of the run, its status, its outcome and what ended it).

--resolve pins a hostname to an address, as curl's option does, so the request can be aimed at a
Service, a Gateway VIP or a population's public address while TLS still names the host. The key
is read from a file (mode 0600 in the labs) and travels only in the Authorization header; it is
never printed. Standard library only, so it runs on any Python 3.8 or later, the labs' sfab/client
among them.
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

PROMPTS = (
    "Name three uses of a network rail in an AI cluster, one line each.",
    "Explain in two sentences what a load balancer does.",
    "List four colors of the rainbow.",
    "Write one sentence about why tests should be repeatable.",
)
DEFAULT_CA = "/etc/ssl/certs/ca-certificates.crt"


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection to `address` that still sends SNI and Host for `host`."""

    def __init__(self, host, port, address, **kw):
        super().__init__(host, port, **kw)
        self._address = address

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port, address, **kw):
        super().__init__(host, port, **kw)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


def parse_resolve(v: str) -> tuple:
    host, port, addr = (v.split(":", 2) + ["", ""])[:3]
    if not host or not port.isdigit() or not addr:
        raise SystemExit(f"load.py: --resolve {v!r} is not host:port:address")
    return host, int(port), addr


def connection(url: str, resolve, timeout: float, cafile: str | None):
    u = urllib.parse.urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    addr = u.hostname
    if resolve and resolve[0] == u.hostname and resolve[1] == port:
        addr = resolve[2]
    if u.scheme == "https":
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        return PinnedHTTPSConnection(u.hostname, port, addr, timeout=timeout, context=ctx)
    if u.scheme == "http":
        return PinnedHTTPConnection(u.hostname, port, addr, timeout=timeout)
    raise SystemExit(f"load.py: --url {url!r} is neither http nor https")


def one_request(url: str, key: str, model: str, prompt: str, max_tokens: int, resolve, timeout: float,
                cafile: str | None) -> dict:
    """Send one streamed request and read it to its end: {status, outcome, why, first}."""
    u = urllib.parse.urlsplit(url)
    path = u.path.rstrip("/") + "/chat/completions"
    body = json.dumps({"model": model, "stream": True, "max_tokens": max_tokens,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream", "Authorization": f"Bearer {key}"}
    first = finished = False
    status = 0
    conn = connection(url, resolve, timeout, cafile)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        status = resp.status
        if status != 200:
            resp.read()
            return {"status": status, "outcome": "failed", "why": f"http {status}", "first": False}
        while True:
            line = resp.readline()
            if not line:
                break
            line = line.strip()
            if not line.startswith(b"data:"):
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                finished = True
                break
            try:
                chunk = json.loads(data)
            except ValueError:
                continue
            for c in chunk.get("choices") or []:
                if (c.get("delta") or {}).get("content"):
                    first = True
                if c.get("finish_reason"):
                    finished = True
            if finished and first:
                # read on to the end of the stream: [DONE] may follow, or a final usage chunk
                continue
        if finished:
            return {"status": status, "outcome": "answered", "why": "", "first": first}
        return {"status": status, "outcome": "cut" if first else "failed", "why": "stream ended", "first": first}
    except (socket.timeout, TimeoutError):
        why = "timeout"
    except ConnectionRefusedError:
        why = "refused"
    except ConnectionResetError:
        why = "reset"
    except ssl.SSLError as e:
        why = f"tls {e.reason or 'error'}"
    except (http.client.HTTPException, OSError) as e:
        why = type(e).__name__
    finally:
        conn.close()
    if finished:
        return {"status": status, "outcome": "answered", "why": "", "first": first}
    return {"status": status, "outcome": "cut" if first else "failed", "why": why, "first": first}


def run(a, key: str, out=sys.stdout) -> int:
    resolve = parse_resolve(a.resolve) if a.resolve else None
    model = a.model or urllib.parse.urlsplit(a.url).path.strip("/").split("/")[0] or "model"
    cafile = a.cafile if a.cafile else (DEFAULT_CA if os.path.exists(DEFAULT_CA) else None)
    records: list = []
    lock = threading.Lock()
    t0 = time.monotonic()
    deadline = t0 + a.seconds

    def user(u: int) -> None:
        n = 0
        while time.monotonic() < deadline:
            start = time.monotonic() - t0
            r = one_request(a.url, key, model, PROMPTS[(u + n) % len(PROMPTS)], a.max_tokens, resolve, a.timeout, cafile)
            r.update({"user": u, "start_s": int(start)})
            with lock:
                records.append(r)
            n += 1
            if r["outcome"] == "failed" and a.pause > 0:
                # a user whose request failed waits before the next, as a client would, so a
                # refused address is counted about once a second, not as fast as it refuses
                time.sleep(a.pause)

    threads = [threading.Thread(target=user, args=(u,), daemon=True) for u in range(1, a.users + 1)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    records.sort(key=lambda r: (r["start_s"], r["user"]))
    if a.records:
        with open(a.records, "w", encoding="utf-8") as f:
            for i, r in enumerate(records, 1):
                f.write(json.dumps({"n": i, "user": r["user"], "start_s": r["start_s"], "status": r["status"],
                                    "outcome": r["outcome"], "why": r["why"]}, sort_keys=True) + "\n")
    return report(a, records, resolve, out)


def report(a, records: list, resolve, out=sys.stdout) -> int:
    n = len(records)
    answered = sum(1 for r in records if r["outcome"] == "answered")
    failed = [r for r in records if r["outcome"] == "failed"]
    cut = [r for r in records if r["outcome"] == "cut"]
    pin = f" ({resolve[0]} pinned to {resolve[2]})" if resolve else ""
    print(f"== load: {a.users} users for {a.seconds} s against {a.url}{pin}", file=out)
    print(f"  requests {n}, answered {answered}, failed {len(failed)}, cut mid-answer {len(cut)}", file=out)
    kinds: dict = {}
    for r in failed:
        kinds[r["why"]] = kinds.get(r["why"], 0) + 1
    if kinds:
        print("  failed by what ended them: " + ", ".join(f"{k} {v}" for k, v in sorted(kinds.items())), file=out)
    passed = bad = 0

    def chk(ok: bool, label: str, detail: str) -> None:
        nonlocal passed, bad
        if ok:
            passed += 1
            print(f"  PASS  {label}", file=out)
        else:
            bad += 1
            print(f"  FAIL  {label} -> {detail}", file=out)

    chk(answered > 0, "at least one request answered", "none")
    chk(not failed, f"no failed request ({len(failed)} of {n})", f"{len(failed)} failed")
    if a.cut_ok:
        print(f"  streams cut mid-answer: {len(cut)} (reported, not judged)", file=out)
    else:
        chk(not cut, f"no stream cut mid-answer ({len(cut)} of {n})", f"{len(cut)} cut")
    print(f"== RESULT: {passed} passed, {bad} failed, 0 known platform limitation(s), 0 skipped", file=out, flush=True)
    return 1 if bad else 0


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(prog="load.py", description=__doc__.strip().splitlines()[0])
    ap.add_argument("--url", required=True, help="the OpenAI-compatible base URL, ending /v1")
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--users", type=int, default=10)
    ap.add_argument("--seconds", type=int, default=60)
    ap.add_argument("--resolve", default="")
    ap.add_argument("--model", default="")
    ap.add_argument("--max-tokens", type=int, default=64)
    ap.add_argument("--timeout", type=float, default=120.0, help="seconds to wait for any read")
    ap.add_argument("--pause", type=float, default=1.0, help="seconds a user waits after a failed request")
    ap.add_argument("--cafile", default="")
    ap.add_argument("--records", default="")
    ap.add_argument("--cut-ok", action="store_true")
    a = ap.parse_args(argv)
    if a.users < 1 or a.seconds < 1:
        ap.error("--users and --seconds must be at least 1")
    try:
        with open(a.key_file, encoding="utf-8") as f:
            key = f.read().strip()
    except OSError as e:
        print(f"load.py: the key file: {e.strerror}", file=sys.stderr)
        return 2
    if not key:
        print("load.py: the key file is empty", file=sys.stderr)
        return 2
    return run(a, key)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
