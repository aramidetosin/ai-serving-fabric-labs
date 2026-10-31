#!/usr/bin/env python3
"""client.py: one chat completion, sent as any OpenAI-compatible client sends it.

    client.py --base-url https://serve.tarnwick.example/chat/v1 --key-file KEY [--model chat]
              [--prompt TEXT] [--max-tokens 64] [--resolve HOST:PORT:ADDRESS] [--cafile FILE]
              [--timeout 120]

An OpenAI-compatible client needs two settings to reach a model: its base URL and its key. This
client takes those two and nothing of the recipe: it sends POST <base URL>/chat/completions with a
JSON body of the model's name, one user message and max_tokens, the key as a bearer token in the
Authorization header, exactly the request the OpenAI client libraries send for a chat completion,
and reads the JSON answer. It prints the request line (never the key), the HTTP status and content
type, the answer's model, finish reason and text, then the repository's PASS or FAIL line (HTTP 200
with a finished answer) and the RESULT line. The key is read from a file (mode 0600 in the labs)
and travels only in the Authorization header.

Nothing here measures how fast: the answer's timings and token counts, which llama-server adds to
its JSON, are not printed. --resolve pins a hostname to an address, as curl's option does, for a
client whose resolver does not know the name. Standard library only, so it runs on any Python 3.8
or later, the labs' sfab/client among them; serving.py client hands it the key and runs it.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.parse

PROMPT = "Name the three primary colors of light, separated by commas."
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
        raise SystemExit(f"client.py: --resolve {v!r} is not host:port:address")
    return host, int(port), addr


def connection(url: str, resolve, timeout: float, cafile):
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
    raise SystemExit(f"client.py: --base-url {url!r} is neither http nor https")


def chat(base_url: str, key: str, model: str, prompt: str, max_tokens: int, resolve=None, timeout: float = 120.0,
         cafile=None) -> dict:
    """One chat completion: {status, content_type, model, finish_reason, text, why}."""
    u = urllib.parse.urlsplit(base_url)
    path = u.path.rstrip("/") + "/chat/completions"
    body = json.dumps({"model": model, "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens}).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Authorization": f"Bearer {key}"}
    out = {"status": 0, "content_type": "", "model": None, "finish_reason": None, "text": None, "why": ""}
    conn = connection(base_url, resolve, timeout, cafile)
    try:
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        out["status"] = resp.status
        out["content_type"] = resp.getheader("Content-Type") or ""
        raw = resp.read()
        try:
            doc = json.loads(raw or b"{}")
        except ValueError:
            out["why"] = "the answer is not JSON"
            return out
        if resp.status != 200:
            err = doc.get("error") if isinstance(doc, dict) else None
            msg = (err.get("message") if isinstance(err, dict) else err) or (doc.get("message") if isinstance(doc, dict) else None)
            out["why"] = f"http {resp.status}" + (f": {msg}" if msg else "")
            return out
        choice = next(iter(doc.get("choices") or []), {}) if isinstance(doc, dict) else {}
        out["model"] = doc.get("model") if isinstance(doc, dict) else None
        out["finish_reason"] = choice.get("finish_reason")
        out["text"] = ((choice.get("message") or {}).get("content") or "").strip()
        if not out["finish_reason"]:
            out["why"] = "no finish_reason in the answer"
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


def report(a, r: dict, resolve, out=None) -> int:
    out = out or sys.stdout
    pin = f" ({resolve[0]} pinned to {resolve[2]})" if resolve else ""
    u = urllib.parse.urlsplit(a.base_url)
    print(f"== client: base URL {a.base_url}{pin}, model {a.model}, the key from {a.key_file} as a bearer token", file=out)
    print(f"  POST {u.path.rstrip('/')}/chat/completions -> HTTP {r['status'] or 'none'}"
          + (f", {r['content_type']}" if r["content_type"] else "") + (f" ({r['why']})" if r["why"] else ""), file=out)
    if r["status"] == 200:
        print(f"  model: {r['model']}", file=out)
        print(f"  finish_reason: {r['finish_reason']}", file=out)
        print(f"  answer: {r['text']}", file=out)
    good = r["status"] == 200 and bool(r["finish_reason"]) and bool(r["text"])
    label = f"an OpenAI-compatible chat completion at {a.base_url} answered HTTP 200 with a finished answer"
    if good:
        print(f"  PASS  {label}", file=out)
    else:
        print(f"  FAIL  {label} -> HTTP {r['status'] or 'none'}" + (f", {r['why']}" if r["why"] else ""), file=out)
    print(f"== RESULT: {1 if good else 0} passed, {0 if good else 1} failed, 0 known platform limitation(s), 0 skipped", file=out, flush=True)
    return 0 if good else 1


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(prog="client.py", description=__doc__.strip().splitlines()[0])
    ap.add_argument("--base-url", required=True, help="the OpenAI-compatible base URL, ending /v1")
    ap.add_argument("--key-file", required=True)
    ap.add_argument("--model", default="", help="the model's name (by default the base URL's first path element)")
    ap.add_argument("--prompt", default=PROMPT)
    ap.add_argument("--max-tokens", type=int, default=64)
    ap.add_argument("--resolve", default="")
    ap.add_argument("--cafile", default="")
    ap.add_argument("--timeout", type=float, default=120.0)
    a = ap.parse_args(argv)
    a.model = a.model or urllib.parse.urlsplit(a.base_url).path.strip("/").split("/")[0] or "model"
    try:
        with open(a.key_file, encoding="utf-8") as f:
            key = f.read().strip()
    except OSError as e:
        print(f"client.py: the key file: {e.strerror}", file=sys.stderr)
        return 2
    if not key:
        print("client.py: the key file is empty", file=sys.stderr)
        return 2
    resolve = parse_resolve(a.resolve) if a.resolve else None
    cafile = a.cafile if a.cafile else (DEFAULT_CA if os.path.exists(DEFAULT_CA) else None)
    r = chat(a.base_url, key, a.model, a.prompt, a.max_tokens, resolve, a.timeout, cafile)
    return report(a, r, resolve)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
