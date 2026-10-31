#!/usr/bin/env python3
"""secrets: a lab's credentials, made on first use and kept out of git (FRAMEWORK.md 2.2).

    secrets.py ensure --state STATE_DIR --lab LAB     create what is missing (preflight's pf_secrets)
    secrets.py check  --state STATE_DIR               exit 1 unless everything exists with mode 0600
                                                      (the redaction key may be missing; see below)
    secrets.py names  --state STATE_DIR               the variable names, never the values

STATE_DIR is the lab's state/ directory (gitignored). ensure writes, without ever replacing a
value that exists:

- state/secrets.env (0600): SFAB_SW_USER and SFAB_SW_PASSWORD (the switches), SFAB_TRUENAS_USER
  and SFAB_TRUENAS_PASSWORD, SFAB_ONTAP_USER and SFAB_ONTAP_PASSWORD, SFAB_KUBEADM_TOKEN
  ([a-z0-9]{6}.[a-z0-9]{16}) and SFAB_KUBEADM_CERT_KEY (64 hex digits). containerlab expands the
  ${SFAB_*} references in topo.clab.yml from it at deploy; every name render/clab.py references
  (gen/clab-state.json "env") is made here. The user names are each platform's administrator,
  not secrets. Nothing is made for the PA-VM: it keeps containerlab's paloalto_panos default
  login, which its launcher takes from its command line (the M1 deploy, dev/m1/RESULTS.md, problem 4).
- state/secrets/lab_ed25519 and lab_ed25519.pub: the lab's SSH key pair (ssh-keygen).
- state/secrets/authorized_keys (0644), written again at every ensure: the lab key's public half,
  then each public key in ~/.ssh/*.pub of the user who runs make up ($HOME's, and SUDO_USER's
  when make up runs under sudo), each once. The topology binds it into every VM guest, the
  bastion and the FRR routers as the authorized keys of the login user (guest.user, admin), so
  `ssh admin@<lab>-<node>` works from the lab host with the lab key or the user's own key, as the
  containerlab VS Code extension's Connect (SSH) runs it. SFAB_USER_SSH_DIRS, a colon-separated
  list of directories, replaces ~/.ssh as the place the extra keys are read from (empty: none).
  Only the count of keys is printed, never a path or a comment.
- state/secrets/tsig/<name>.key (0600, the directory 0700): one TSIG key per name the lab's
  gen/clab-state.json lists under "tsig" (render/dns.py: one per DNS view whose zones the
  authoritative pair transfers), in BIND's own syntax, key "<name>" { algorithm hmac-sha256;
  secret "<base64 of 32 random bytes>"; }. The topology binds the directory read-only into the
  authoritative servers only; their image installs the keys for named. A key that exists is kept.
- state/secrets/ipsec/<name>.psk (0600, the directory 0700): one pre-shared key per name the lab's
  gen/clab-state.json lists under "ipsec" (render/panos.py: one per tunnel the firewall
  terminates), 40 letters and digits. The topology binds the directory read-only into the VPN
  router; boot sets each key on the firewall through the API, from a 0600 file, never on a command
  line. A key that exists is kept.
- In a lab with the identity provider (gen/k8s.json identity.secrets): SFAB_IDP_CLIENT_<client>
  (32 letters and digits, each OIDC client's secret) and SFAB_IDP_PASSWORD_<person> (each person's
  password) in state/secrets.env. finish writes the identity provider's Secret from them
  (common/bin/idp-secret.py: the client secrets and bcrypt hashes of the passwords, never the
  passwords themselves); the harness hands a person's password to that person's client only.
- state/secrets/redact.key (0600): 64 hex digits, the key under which common/audit/redact.py
  marks a redacted value (an HMAC, so nobody without the key can test a guess against a mark). No
  container or device ever sees it. check passes without it, so a lab made before the key existed
  still audits; redact.py then uses a key of its own for that run, and the next ensure makes it.

Passwords are 20 letters and digits with at least one of each kind, accepted by TrueNAS and
ONTAP alike and safe in XML, YAML and a shell. Nothing is printed but file paths and names.
"""

from __future__ import annotations

import argparse
import base64
import glob
import json
import os
import pwd
import random
import re
import string
import subprocess
import sys

# This file is named secrets.py, so it cannot import the standard secrets module; SystemRandom
# draws from os.urandom just the same.
rnd = random.SystemRandom()
USERS = {"SFAB_SW_USER": "admin", "SFAB_TRUENAS_USER": "truenas_admin", "SFAB_ONTAP_USER": "admin"}
PASSWORDS = ("SFAB_SW_PASSWORD", "SFAB_TRUENAS_PASSWORD", "SFAB_ONTAP_PASSWORD")
ALNUM = string.ascii_letters + string.digits
IDP_NAME = re.compile(r"^SFAB_IDP_(CLIENT|PASSWORD)_[A-Z0-9_]{1,48}$")
LOWER_DIGITS = string.ascii_lowercase + string.digits


def password(n: int = 20) -> str:
    while True:
        p = "".join(rnd.choice(ALNUM) for _ in range(n))
        if any(c.islower() for c in p) and any(c.isupper() for c in p) and any(c.isdigit() for c in p):
            return p


def kubeadm_token() -> str:
    return "".join(rnd.choice(LOWER_DIGITS) for _ in range(6)) + "." + "".join(rnd.choice(LOWER_DIGITS) for _ in range(16))


def idp_names(state: str | None) -> list:
    """The identity provider's credential names the lab's render lists (gen/k8s.json identity.secrets,
    beside state/): each client's secret and each person's password, SFAB_IDP_*."""
    if not state:
        return []
    f = os.path.join(os.path.dirname(os.path.abspath(state)), "gen", "k8s.json")
    try:
        names = ((json.load(open(f, encoding="utf-8")) or {}).get("identity") or {}).get("secrets") or []
    except (OSError, ValueError):
        return []
    return [str(n) for n in names if IDP_NAME.match(str(n))]


def wanted(state: str | None = None) -> dict:
    w = dict(USERS)
    for k in PASSWORDS:
        w[k] = None
    w["SFAB_KUBEADM_TOKEN"] = None
    w["SFAB_KUBEADM_CERT_KEY"] = None
    for k in idp_names(state):
        w[k] = None
    return w


def fresh(key: str) -> str:
    if key in USERS:
        return USERS[key]
    if key == "SFAB_KUBEADM_TOKEN":
        return kubeadm_token()
    if key == "SFAB_KUBEADM_CERT_KEY":
        return os.urandom(32).hex()
    if key.startswith("SFAB_IDP_CLIENT_"):
        return password(32)
    return password()


def read_env(path: str) -> dict:
    out = {}
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return out


def paths(state: str) -> dict:
    sec = os.path.join(state, "secrets")
    return {"env": os.path.join(state, "secrets.env"), "dir": sec,
            "key": os.path.join(sec, "lab_ed25519"), "pub": os.path.join(sec, "lab_ed25519.pub"),
            "redact": os.path.join(sec, "redact.key"), "authorized": os.path.join(sec, "authorized_keys")}


KEY_TYPE = re.compile(r"^(ssh-(ed25519|rsa|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$")
KEY_BLOB = re.compile(r"^[A-Za-z0-9+/]+={0,3}$")


def user_ssh_dirs() -> list:
    """The directories whose *.pub keys join the lab key: SFAB_USER_SSH_DIRS when it is set,
    else ~/.ssh of $HOME and, under sudo, of SUDO_USER."""
    env = os.environ.get("SFAB_USER_SSH_DIRS")
    if env is not None:
        return [d for d in env.split(":") if d]
    dirs = [os.path.join(os.path.expanduser("~"), ".ssh")]
    su = os.environ.get("SUDO_USER")
    if su and su != "root":
        try:
            dirs.append(os.path.join(pwd.getpwnam(su).pw_dir, ".ssh"))
        except KeyError:
            pass
    out = []
    for d in dirs:
        if os.path.realpath(d) not in [os.path.realpath(x) for x in out]:
            out.append(d)
    return out


def pub_keys(path: str) -> list:
    """The public key lines of one file: type, base64 blob and any comment, nothing else."""
    keys = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                w = line.split()
                if len(w) >= 2 and KEY_TYPE.match(w[0]) and KEY_BLOB.match(w[1]):
                    keys.append(" ".join(w))
    except OSError:
        pass
    return keys


TSIG_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def tsig_names(state: str, what: str = "tsig") -> list:
    """The TSIG key names the lab's render lists (gen/clab-state.json "tsig", beside state/), or
    with what="ipsec" its tunnels' pre-shared key names."""
    f = os.path.join(os.path.dirname(os.path.abspath(state)), "gen", "clab-state.json")
    try:
        names = json.load(open(f, encoding="utf-8")).get(what) or []
    except (OSError, ValueError):
        return []
    return [str(n) for n in names if TSIG_NAME.match(str(n))]


def ipsec_names(state: str) -> list:
    return tsig_names(state, "ipsec")


def psk() -> str:
    """A tunnel's pre-shared key: 40 letters and digits (PAN-OS and strongSwan both take it as is)."""
    alpha = string.ascii_letters + string.digits
    return "".join(rnd.choice(alpha) for _ in range(40))


def write_ipsec(p: dict, state: str) -> list:
    """Each pre-shared key the render lists and state/secrets/ipsec lacks; the names made."""
    made = []
    names = ipsec_names(state)
    if not names:
        return made
    d = os.path.join(p["dir"], "ipsec")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    for n in names:
        f = os.path.join(d, f"{n}.psk")
        if not os.path.exists(f):
            tmp = f + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(psk() + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, f)
            made.append(n)
        os.chmod(f, 0o600)
    return made


def tsig_key(name: str) -> str:
    secret = base64.b64encode(os.urandom(32)).decode("ascii")
    return f'key "{name}" {{\n    algorithm hmac-sha256;\n    secret "{secret}";\n}};\n'


def write_tsig(p: dict, state: str) -> list:
    """Each TSIG key the render lists and state/secrets/tsig lacks; the names made."""
    made = []
    names = tsig_names(state)
    if not names:
        return made
    d = os.path.join(p["dir"], "tsig")
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    for n in names:
        f = os.path.join(d, f"{n}.key")
        if not os.path.exists(f):
            tmp = f + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(tsig_key(n))
            os.chmod(tmp, 0o600)
            os.replace(tmp, f)
            made.append(n)
        os.chmod(f, 0o600)
    return made


def write_authorized(p: dict) -> int:
    """state/secrets/authorized_keys from the lab key and the user's own; the number of user keys."""
    seen, lines = set(), []
    for path in [p["pub"]] + [f for d in user_ssh_dirs() for f in sorted(glob.glob(os.path.join(d, "*.pub")))]:
        for k in pub_keys(path):
            ident = tuple(k.split()[:2])
            if ident not in seen:
                seen.add(ident)
                lines.append(k)
    tmp = p["authorized"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("".join(k + "\n" for k in lines))
    os.chmod(tmp, 0o644)
    os.replace(tmp, p["authorized"])
    return len(lines) - 1


def ensure(state: str, lab: str) -> int:
    p = paths(state)
    old_umask = os.umask(0o077)
    try:
        os.makedirs(state, exist_ok=True)
        os.makedirs(p["dir"], mode=0o700, exist_ok=True)
        os.chmod(p["dir"], 0o700)
        have = read_env(p["env"])
        added = [k for k in wanted(state) if k not in have]
        if added or not os.path.exists(p["env"]):
            merged = dict(have)
            for k in added:
                merged[k] = fresh(k)
            tmp = p["env"] + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write("# sfab lab credentials: made by common/bin/secrets.py, never committed\n")
                for k in sorted(merged):
                    f.write(f"{k}={merged[k]}\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, p["env"])
            print(f"secrets: {p['env']}: added {', '.join(added) if added else 'nothing'}")
        os.chmod(p["env"], 0o600)
        if not os.path.exists(p["key"]):
            r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"{lab}-lab-key", "-f", p["key"]],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(f"secrets: ssh-keygen failed: {r.stderr.strip()}", file=sys.stderr)
                return 1
            print(f"secrets: made the lab SSH key {p['key']}")
        os.chmod(p["key"], 0o600)
        if os.path.exists(p["pub"]):
            os.chmod(p["pub"], 0o644)
        n = write_authorized(p)
        print(f"secrets: {p['authorized']}: the lab key and {n} of the deploying user's own public key{'' if n == 1 else 's'}")
        if not os.path.exists(p["redact"]):
            tmp = p["redact"] + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(os.urandom(32).hex() + "\n")
            os.chmod(tmp, 0o600)
            os.replace(tmp, p["redact"])
            print(f"secrets: made the lab's redaction key {p['redact']}")
        os.chmod(p["redact"], 0o600)
        made = write_tsig(p, state)
        if made:
            print(f"secrets: made {len(made)} TSIG key(s) in {os.path.join(p['dir'], 'tsig')}: {', '.join(made)}")
        made = write_ipsec(p, state)
        if made:
            print(f"secrets: made {len(made)} pre-shared key(s) in {os.path.join(p['dir'], 'ipsec')}: {', '.join(made)}")
    finally:
        os.umask(old_umask)
    return 0


def check(state: str) -> int:
    p = paths(state)
    probs = []
    have = read_env(p["env"])
    if not os.path.exists(p["env"]):
        probs.append(f"{p['env']} missing")
    else:
        mode = os.stat(p["env"]).st_mode & 0o777
        if mode != 0o600:
            probs.append(f"{p['env']} has mode {mode:o}, want 600")
        miss = [k for k in wanted(state) if k not in have]
        if miss:
            probs.append("missing " + ", ".join(miss))
    if not os.path.exists(p["key"]):
        probs.append(f"{p['key']} missing")
    elif os.stat(p["key"]).st_mode & 0o077:
        probs.append(f"{p['key']} is readable by others")
    if os.path.exists(p["redact"]) and os.stat(p["redact"]).st_mode & 0o077:
        probs.append(f"{p['redact']} is readable by others")
    for n in ipsec_names(state):
        f = os.path.join(p["dir"], "ipsec", f"{n}.psk")
        if not os.path.exists(f):
            probs.append(f"{f} missing")
        elif os.stat(f).st_mode & 0o077:
            probs.append(f"{f} is readable by others")
    for n in tsig_names(state):
        f = os.path.join(p["dir"], "tsig", f"{n}.key")
        if not os.path.exists(f):
            probs.append(f"{f} missing")
        elif os.stat(f).st_mode & 0o077:
            probs.append(f"{f} is readable by others")
    for x in probs:
        print(f"secrets: {x}")
    return 1 if probs else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="secrets")
    ap.add_argument("cmd", choices=("ensure", "check", "names"))
    ap.add_argument("--state", required=True)
    ap.add_argument("--lab", default="sfab-lab")
    a = ap.parse_args(argv)
    if a.cmd == "ensure":
        return ensure(a.state, a.lab)
    if a.cmd == "check":
        return check(a.state)
    for k in sorted(read_env(paths(a.state)["env"])):
        print(k)
    return 0


if __name__ == "__main__":
    sys.exit(main())
