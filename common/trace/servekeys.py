#!/usr/bin/env python3
"""servekeys.py: a model's key from its Secret, handed to a client container, never printed.

    servekeys.py pick  --model M [--field F] [--mark-key FILE] < SECRET_JSON
                                    on stdout two lines, for a pipe into a client container only
                                    (lib-servecap.sh key_to_client): the key, then its
                                    Authorization header line; on stderr the key's field and
                                    fingerprint (and its mark with --mark-key)
    servekeys.py which --model M [--field F] [--mark-key FILE] < SECRET_JSON
                                    the key's field and fingerprint (and mark), nothing else
    servekeys.py mark  --field F --mark-key FILE < SECRET_JSON
                                    one field of any Secret (the router's master key, the backend
                                    key): its field, fingerprint and mark
    servekeys.py list  < SECRET_JSON
                                    every field of the Secret with its fingerprint

SECRET_JSON is `kubectl get secret -o json`. In the API keys' Secret (the key Job made it with
sfab-keys mint) each field <caller>.<id> holds one key of an application caller (inference.callers).
"The model's key" is a key of the first application caller in the spec's order that may call the
model: the render's gen/k8s.json (--k8s, else $SFAB_RENDERDIR/gen/k8s.json) names which; in a lab
with no callers the caller is the model itself. That caller's first field in sorted order is the
one taken, unless --field names one. --caller names the caller instead of the model. The fingerprint is sfab-keys' own (sha256: and the first 12
hex digits of the key's sha256), so a run's lines name the same key the key Job's log named. The
mark is the one common/audit/redact.py and common/trace/keyscrub.py leave where they replace a
value, <redacted hmac:XXXXXXXXXXXX> under the lab's redaction key (--mark-key, the lab's
state/secrets/redact.key), so a trace can say which key a hop carried by the mark its capture
holds. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "audit"))

FIELD = re.compile(r"^([a-z0-9]{1,16})\.([0-9a-f]{8})$")


def fingerprint(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode()).hexdigest()[:12]


def _value(data: dict, f: str):
    try:
        v = base64.b64decode(data[f], validate=True).decode().strip()
    except (KeyError, ValueError, UnicodeDecodeError):
        return None
    return v or None


def caller_of(model: str, k8s: str | None = None) -> str:
    """The application caller whose key stands for the model's (see the module's docstring)."""
    path = k8s or (os.path.join(os.environ["SFAB_RENDERDIR"], "gen", "k8s.json") if os.environ.get("SFAB_RENDERDIR") else None)
    if not path or not os.path.isfile(path):
        return model
    try:
        inf = (json.load(open(path, encoding="utf-8")) or {}).get("inference") or {}
    except ValueError:
        return model
    for c in inf.get("callers") or []:
        if c.get("kind") == "application" and model in (c.get("models") or []):
            return str(c["id"])
    return model


def first_key(doc: dict, model: str, field: str | None = None) -> tuple:
    """(field, key) of the model's first key (or of the field named), or (None, None)."""
    data = (doc or {}).get("data") or {}
    if field:
        m = FIELD.match(field)
        if not m or m.group(1) != model:
            return None, None
        v = _value(data, field)
        return (field, v) if v else (None, None)
    for f in sorted(data):
        m = FIELD.match(f)
        if m and m.group(1) == model:
            v = _value(data, f)
            if v:
                return f, v
    return None, None


def mark_of(key: str, keyfile) -> str:
    if not keyfile:
        return ""
    import redact  # noqa: PLC0415

    return redact.mark(key, redact.read_key(keyfile))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="servekeys")
    ap.add_argument("cmd", choices=("pick", "which", "mark", "list"))
    ap.add_argument("--model")
    ap.add_argument("--caller")
    ap.add_argument("--k8s")
    ap.add_argument("--field")
    ap.add_argument("--mark-key")
    a = ap.parse_args(argv)
    try:
        doc = json.load(sys.stdin)
    except ValueError:
        print("servekeys: the Secret could not be read", file=sys.stderr)
        return 1
    if a.cmd == "list":
        data = (doc or {}).get("data") or {}
        for f in sorted(data):
            v = _value(data, f)
            print(f"{f} {fingerprint(v) if v else 'empty'}")
        return 0
    if a.cmd == "mark":
        if not a.field or not a.mark_key:
            print("servekeys: mark needs --field and --mark-key", file=sys.stderr)
            return 2
        v = _value((doc or {}).get("data") or {}, a.field)
        if not v:
            print(f"servekeys: the Secret holds no {a.field}", file=sys.stderr)
            return 1
        print(f"{a.field} {fingerprint(v)} {mark_of(v, a.mark_key)}")
        return 0
    if not a.model and not a.caller:
        print(f"servekeys: {a.cmd} needs --model or --caller", file=sys.stderr)
        return 2
    slug = a.caller or caller_of(a.model, a.k8s)
    field, key = first_key(doc, slug, a.field)
    if key is None:
        print(f"servekeys: the Secret holds no key {a.field or 'for ' + slug}", file=sys.stderr)
        return 1
    tail = f" {mark_of(key, a.mark_key)}" if a.mark_key else ""
    if a.cmd == "which":
        print(f"{field} {fingerprint(key)}{tail}")
        return 0
    sys.stdout.write(f"{key}\nAuthorization: Bearer {key}\n")
    print(f"{field} {fingerprint(key)}{tail}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
