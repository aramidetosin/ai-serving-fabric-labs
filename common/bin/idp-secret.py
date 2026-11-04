#!/usr/bin/env python3
"""idp-secret: the identity provider's credentials as a Kubernetes Secret, on a pipe only.

    idp-secret.py --k8s gen/k8s.json --env state/secrets.env | kubectl apply -f -

Prints the Secret <identity.secret> in <identity.namespace> that Dex reads its credentials from
(render/identity.py): each client's secret (SFAB_IDP_CLIENT_<client>) and each person's password
as a bcrypt hash (SFAB_IDP_HASH_<person>, from SFAB_IDP_PASSWORD_<person>). The values come from
the lab's state/secrets.env, which common/bin/secrets.py made; the plain passwords never enter the
cluster. The hash's salt is derived from the person and the password, so the same password gives
the same Secret at every run and an apply changes nothing. It refuses a terminal: the finish stage
pipes it to the harness's kubectl, and nothing prints it.

The hash is crypt(3)'s bcrypt ($2b$, cost 10) through Python's crypt module where the interpreter
still has it and its crypt(3) knows bcrypt (glibc's libxcrypt, musl), else `htpasswd -niBC 10`
reading the password on its standard input, whose salt is its own: then the Secret differs at
every run and finish restarts Dex for it.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import warnings

BCRYPT64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
COST = 10


def read_env(path: str) -> dict:
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def salt_for(person: str, password: str) -> str:
    """A bcrypt salt (22 characters) derived from the person and the password; its last character is
    one of the four a canonical bcrypt salt ends in, so every crypt(3) takes it."""
    d = hashlib.sha256(f"sfab-idp:{person}:{password}".encode()).digest()
    chars = [BCRYPT64[b % 64] for b in d[:21]]
    chars.append(".Oeu"[d[21] % 4])
    return "".join(chars)


def bcrypt(person: str, password: str) -> str:
    salt = f"$2b${COST:02d}${salt_for(person, password)}"
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import crypt  # noqa: PLC0415  (removed in Python 3.13; htpasswd below covers it)
        h = crypt.crypt(password, salt)
        if h and h.startswith(salt[:7]) and len(h) == 60:
            return h
    except ImportError:
        pass
    r = subprocess.run(["htpasswd", "-niBC", str(COST), person], input=password + "\n", capture_output=True, text=True)
    if r.returncode != 0 or ":" not in r.stdout:
        raise SystemExit("idp-secret: no bcrypt: Python's crypt module is missing and htpasswd failed")
    return r.stdout.strip().split(":", 1)[1]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="idp-secret")
    ap.add_argument("--k8s", required=True)
    ap.add_argument("--env", required=True)
    a = ap.parse_args(argv)
    if sys.stdout.isatty():
        print("idp-secret: this writes credentials: pipe it to kubectl apply -f -, never to a terminal", file=sys.stderr)
        return 2
    idp = (json.load(open(a.k8s, encoding="utf-8")) or {}).get("identity")
    if not idp:
        print("idp-secret: gen/k8s.json has no identity provider", file=sys.stderr)
        return 1
    env = read_env(a.env)
    data = {}
    for c in idp["clients"]:
        v = env.get(c["secret_env"])
        if not v:
            print(f"idp-secret: {a.env} has no {c['secret_env']} (run the secrets step: make up runs it in preflight)", file=sys.stderr)
            return 1
        data[c["secret_env"]] = v
    for p in idp["people"]:
        v = env.get(p["password_env"])
        if not v:
            print(f"idp-secret: {a.env} has no {p['password_env']}", file=sys.stderr)
            return 1
        data[p["hash_env"]] = bcrypt(p["id"], v)
    doc = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
           "metadata": {"name": idp["secret"], "namespace": idp["namespace"], "labels": {"app.kubernetes.io/name": idp["name"]}},
           "data": {k: base64.b64encode(v.encode()).decode() for k, v in sorted(data.items())}}
    sys.stdout.write(json.dumps(doc, sort_keys=True) + "\n")
    print(f"idp-secret: Secret {idp['namespace']}/{idp['secret']}: {len(idp['clients'])} client secret(s) and "
          f"{len(idp['people'])} password hash(es), written to the pipe", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
