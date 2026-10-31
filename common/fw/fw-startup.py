#!/usr/bin/env python3
"""fw-startup.py: load and commit the PA-VM's rendered startup configuration through the XML API.

Inside the firewall container (what the boot stage runs when the launcher's commit did not take):

    docker exec -i sfab-m1-fw /.venv/bin/python3 - --expect-sha256 <the render's sha256> \
        < common/fw/fw-startup.py

From the lab host, against the firewall's management address, with the login read from the
firewall container:

    common/fw/fw-startup.py --api https://172.21.40.40 --container sfab-m1-fw \\
        --config bootstrap/fw/startup-config.xml --marker state/stage/fw-startup.ok

--expect-sha256 refuses a delivered file that is not the render (gen/RENDER.json holds its sha256).
Without touching the firewall, to see what a run would do:

    common/fw/fw-startup.py --plan --config bootstrap/fw/startup-config.xml

Why it exists. containerlab delivers bootstrap/fw/startup-config.xml as /config/startup-config.cfg.
The image's launcher turns jumbo-frame mode on and reboots, waits for PAN-OS's own auto-commit,
imports the file, merges it into the candidate and commits. Its wait can end a few seconds early;
PAN-OS then refuses the commit because the auto-commit has not finished, and the launcher still
reports "Startup complete" with the factory configuration in place. This script runs the same
steps with that race closed:

  1. an API key from the credentials (never printed, never on a command line);
  2. when the file asks for jumbo frames and the box is not in jumbo-frame mode: turn it on,
     restart PAN-OS and wait for the API (an MTU above 1500 does not validate otherwise);
  3. wait until PAN-OS has no unfinished job (its auto-commit included);
  4. import the file, then a partial merge of deviceconfig, network, vsys and shared (only the
     sections the file holds), then a partial replace of each vsys rulebase, so the rules stand
     in the rendered order with nothing left over (a merge appends a re-added rule at the end);
  5. a full validate; a file that does not validate is reported with PAN-OS's reason and not
     committed;
  6. commit, retried while PAN-OS says an auto-commit or another commit is running, then poll the
     job to FIN. The poll rides out the API going away (a commit that touches the management web
     server restarts it) and takes a fresh key once the API answers again;
  7. write the marker file, /tmp/lab-startup-committed inside the container by default.

Credentials. The PA-VM keeps containerlab's paloalto_panos default login: the kind gives the
image's launcher (PID 1) its default --username and --password on the command line, and the
launcher never reads USERNAME and PASSWORD from the environment (the M1 deploy showed it,
dev/m1/RESULTS.md, problem 4). So the login is read from the launcher's arguments, as the harness reads
a switch's. In order:

  1. SFAB_FW_PASSWORD (and SFAB_FW_USER, default admin), only when the operator exports it: an
     explicit override. Nothing generates it and no file is read for it.
  2. Inside the container: the launcher's own arguments (/proc/1/cmdline), else USERNAME and
     PASSWORD of the container environment.
  3. From the host, with --container NAME: the same two, read from that container with docker
     inspect.

The password travels in the keygen request body; the key travels only in the X-PAN-KEY header.
Anything printed passes through a redactor that removes both.

Exit status: 0 committed (or nothing left to commit); 1 a step failed; 2 a usage or file error;
5 the firewall refused the credentials. Standard library only, Python 3.10 or later.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape

DEVICE = "localhost.localdomain"
DEV_XPATH = f"/config/devices/entry[@name='{DEVICE}']"
# What containerlab delivered, then the launcher's copy of it.
IN_CONTAINER_CONFIGS = ("/config/startup-config.cfg", "/config/startup-config.xml")
IN_CONTAINER_MARKER = "/tmp/lab-startup-committed"
IMPORT_NAME = "sfab-startup-config.xml"
# What --container accepts: a docker container name, never an option.
CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
# Sections merged into the candidate, in the launcher's order: (label, xpath, path in the file).
SECTIONS = (
    ("deviceconfig", f"{DEV_XPATH}/deviceconfig", "devices/entry/deviceconfig"),
    ("network", f"{DEV_XPATH}/network", "devices/entry/network"),
    ("vsys", f"{DEV_XPATH}/vsys", "devices/entry/vsys"),
    ("shared", "/config/shared", "shared"),
)
# What PAN-OS answers while it cannot queue a commit yet.
BUSY = ("auto-commit not yet finished", "commit is in progress", "another commit", "is currently in progress",
        "pending jobs", "commit job was not queued")
NO_CHANGES = "no changes to commit"
TRANSIENT = (OSError, http.client.HTTPException, ET.ParseError)


class Timing:
    """Tries and pauses (seconds). The tests shrink them."""

    keygen_tries = 60
    keygen_pause = 10.0
    refused_tries = 6
    idle_tries = 90
    idle_pause = 10.0
    job_tries = 90
    job_pause = 5.0
    commit_tries = 40
    commit_pause = 15.0
    commit_poll_tries = 180
    restart_down_tries = 24
    restart_down_pause = 5.0
    restart_back_wait = 120.0
    http_timeout = 120.0


class Refused(Exception):
    """The firewall refused the credentials."""


class Failed(Exception):
    """A step failed; the message says which and why."""


class NoCredentials(Exception):
    """No password was found where this run looks for one."""


# --------------------------------------------------------------------------------------------
# Output with every secret removed

_SECRETS: list[str] = []


def remember(*values: str | None) -> None:
    for v in values:
        if v and v not in _SECRETS:
            _SECRETS.append(v)
    _SECRETS.sort(key=len, reverse=True)


def redact(text: str) -> str:
    s = str(text)
    for v in _SECRETS:
        s = s.replace(v, "<redacted>")
    s = re.sub(r"(?i)(key=)[^&\s\"'<>]+", r"\1<redacted>", s)
    s = re.sub(r"(?i)(x-pan-key:\s*)\S+", r"\1<redacted>", s)
    s = re.sub(r"(?is)<key>.*?</key>", "<key><redacted></key>", s)
    s = re.sub(r"(?i)(password=)[^&\s\"'<>]+", r"\1<redacted>", s)
    return s


def log(msg: str) -> None:
    print(f"{time.strftime('%H:%M:%S', time.gmtime())} fw-startup: {redact(msg)}", flush=True)


def text(e: ET.Element | None, path: str | None = None) -> str:
    x = e if path is None or e is None else e.find(path)
    return " ".join("".join(x.itertext()).split()) if x is not None else ""


def short(s: str, n: int = 300) -> str:
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 3] + "..."


# --------------------------------------------------------------------------------------------
# The XML API


class Api:
    def __init__(self, base: str, user: str, password: str):
        u = urllib.parse.urlsplit(base if "://" in base else f"https://{base}")
        if u.scheme not in ("https", "http") or not u.netloc:
            raise ValueError(f"--api {base!r}: want https://HOST[:PORT]")
        self.url = urllib.parse.urlunsplit((u.scheme, u.netloc, "/api/", "", ""))
        self.ctx = ssl._create_unverified_context() if u.scheme == "https" else None  # the PA-VM's own certificate
        self.user = user
        self._password = password
        self.key: str | None = None
        remember(password)

    def _post(self, body: bytes, ctype: str, query: dict | None = None, keyed: bool = True,
              timeout: float | None = None) -> ET.Element:
        url = self.url + ("?" + urllib.parse.urlencode(query) if query else "")
        headers = {"Content-Type": ctype}
        if keyed:
            if not self.key:
                raise Failed("no API key yet")
            headers["X-PAN-KEY"] = self.key
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout or Timing.http_timeout, context=self.ctx) as r:
                data = r.read()
        except urllib.error.HTTPError as e:
            data = e.read()  # PAN-OS answers an error with an XML body, 403 for a key it does not take
        return ET.fromstring(data)

    def form(self, fields: dict, keyed: bool = True, timeout: float | None = None) -> ET.Element:
        return self._post(urllib.parse.urlencode(fields).encode(), "application/x-www-form-urlencoded",
                          keyed=keyed, timeout=timeout)

    def keygen(self) -> str:
        e = self.form({"type": "keygen", "user": self.user, "password": self._password}, keyed=False, timeout=30)
        k = e.find(".//key")
        if e.get("status") == "success" and k is not None and k.text:
            self.key = k.text.strip()
            remember(self.key)
            return self.key
        msg = text(e)
        if e.get("code") == "403" or "invalid credential" in msg.lower():
            raise Refused(msg or "invalid credentials")
        raise Failed(f"keygen: {short(msg) or e.get('status')}")

    def op(self, cmd: str, timeout: float | None = None) -> ET.Element:
        return self.form({"type": "op", "cmd": cmd}, timeout=timeout)

    def commit(self, cmd: str) -> ET.Element:
        return self.form({"type": "commit", "cmd": cmd}, timeout=60)

    def import_config(self, name: str, data: bytes) -> ET.Element:
        boundary = f"sfab{uuid.uuid4().hex}"
        body = b"".join([
            f"--{boundary}\r\n".encode(),
            f'Content-Disposition: form-data; name="file"; filename="{name}"\r\n'.encode(),
            b"Content-Type: application/xml\r\n\r\n",
            data,
            f"\r\n--{boundary}--\r\n".encode(),
        ])
        return self._post(body, f"multipart/form-data; boundary={boundary}",
                          query={"type": "import", "category": "configuration"})


def is_key_error(e: ET.Element) -> bool:
    """An answer that means the key is no longer taken (403 forbidden, 16 unauthorized, 22 session
    timed out), as after the web server restarts."""
    if e.get("status") != "error":
        return False
    msg = text(e).lower()
    return e.get("code") in ("403", "16", "22") or "invalid key" in msg or "api key" in msg


# --------------------------------------------------------------------------------------------
# Steps


def keygen(api: Api, tries: int | None = None) -> str:
    refused = 0
    last = ""
    tries = tries or Timing.keygen_tries
    for i in range(tries):
        try:
            return api.keygen()
        except Refused as x:
            refused += 1
            last = str(x)
            if refused >= Timing.refused_tries:
                raise
        except TRANSIENT as x:
            last = type(x).__name__
            if i % 6 == 0:
                log(f"the API does not answer yet ({last}); waiting")
        time.sleep(Timing.keygen_pause)
    raise Failed(f"no API key after {tries} tries ({short(last)})")


def call(api: Api, fn, *args):
    """One API call; a key the server no longer takes is replaced once."""
    e = fn(*args)
    if is_key_error(e):
        keygen(api)
        e = fn(*args)
    return e


def jobs_unfinished(api: Api) -> list:
    e = call(api, api.op, "<show><jobs><all></all></jobs></show>")
    out = []
    for j in e.iter("job"):
        st = text(j, "status")
        if j.find("id") is not None and st not in ("FIN", ""):
            out.append((text(j, "id"), text(j, "type"), st))
    return out


def wait_idle(api: Api) -> None:
    for i in range(Timing.idle_tries):
        try:
            busy = jobs_unfinished(api)
        except TRANSIENT as x:
            busy = [("?", "api", type(x).__name__)]
        if not busy:
            log("no unfinished PAN-OS job")
            return
        if i % 6 == 0:
            log(f"waiting for PAN-OS jobs to finish: {busy}")
        time.sleep(Timing.idle_pause)
    raise Failed(f"PAN-OS jobs still unfinished after {Timing.idle_tries} polls")


def wait_job(api: Api, jid: str, what: str, tries: int) -> tuple[str, str]:
    away = 0
    for _ in range(tries):
        try:
            e = api.op(f"<show><jobs><id>{jid}</id></jobs></show>", timeout=30)
        except TRANSIENT as x:
            if away == 0:
                log(f"{what} job {jid}: the API went away ({type(x).__name__}); polling on")
            away += 1
            time.sleep(Timing.job_pause)
            continue
        if away:
            log(f"{what} job {jid}: the API answers again after {away} failed polls")
            away = 0
        if is_key_error(e):
            try:
                keygen(api)
            except TRANSIENT:
                pass
            continue
        j = e.find(".//job")
        if j is not None and text(j, "status") == "FIN":
            return text(j, "result"), short(text(j, "details"), 600)
        time.sleep(Timing.job_pause)
    raise Failed(f"{what} job {jid} did not finish in {tries} polls")


def jumbo_mode(api: Api) -> str | None:
    """'on', 'off', or None when the answer cannot be read."""
    try:
        e = call(api, api.op, "<show><system><setting><jumbo-frame></jumbo-frame></setting></system></show>")
    except TRANSIENT:
        return None
    t = text(e).lower()
    m = re.search(r"jumbo-frame mode:\s*(on|off)", t)
    if m:
        return m.group(1)
    if e.get("status") == "success":
        for word in ("on", "off"):
            if re.fullmatch(rf"\s*{word}\s*", t):
                return word
    return None


def jumbo_on_and_restart(api: Api) -> None:
    log("the file asks for jumbo frames and the box is not in jumbo-frame mode: turning it on and restarting PAN-OS")
    e = call(api, api.op, "<set><system><setting><jumbo-frame>on</jumbo-frame></setting></system></set>")
    log(f"jumbo-frame on: {e.get('status')} {short(text(e), 120)}")
    wait_idle(api)
    call(api, api.op, "<request><restart><system></system></restart></request>")
    for _ in range(Timing.restart_down_tries):
        time.sleep(Timing.restart_down_pause)
        try:
            api.op("<show><system><info></info></system></show>", timeout=5)
        except TRANSIENT:
            log("PAN-OS is restarting")
            break
    else:
        raise Failed("PAN-OS did not go down after the restart request")
    time.sleep(Timing.restart_back_wait)
    keygen(api, tries=Timing.keygen_tries + 30)
    log("PAN-OS answers again after the restart")
    wait_idle(api)


def sections_in(tree: ET.Element) -> tuple[list, list]:
    """(merge sections present, rulebase replace targets) for a parsed <config> file."""
    merges = [(label, xp) for label, xp, rel in SECTIONS if tree.find(rel) is not None]
    replaces = []
    for v in tree.findall("devices/entry/vsys/entry"):
        name = v.get("name")
        if name and v.find("rulebase") is not None:
            replaces.append((f"{name} rulebase", f"{DEV_XPATH}/vsys/entry[@name='{name}']/rulebase"))
    return merges, replaces


def load_partial(api: Api, mode: str, label: str, xpath: str) -> None:
    cmd = (f"<load><config><partial><mode>{mode}</mode><from-xpath>{xpath}</from-xpath><to-xpath>{xpath}</to-xpath>"
           f"<from>{IMPORT_NAME}</from></partial></config></load>")
    e = call(api, api.op, cmd)
    log(f"partial {mode} {label}: {e.get('status')}")
    if e.get("status") != "success":
        raise Failed(f"partial {mode} of {label} failed: {short(text(e))}")


def commit(api: Api, description: str) -> str | None:
    """Queue the commit, retrying while PAN-OS is busy. None means nothing was left to commit."""
    cmd = f"<commit><description>{escape(description)}</description></commit>"
    for i in range(Timing.commit_tries):
        try:
            e = call(api, api.commit, cmd)
        except TRANSIENT as x:
            log(f"commit: the API does not answer ({type(x).__name__}); retrying")
            time.sleep(Timing.commit_pause)
            continue
        jid, msg = text(e, ".//job"), text(e)
        if e.get("status") == "success" and jid:
            return jid
        if e.get("status") == "success" and NO_CHANGES in msg.lower():
            return None
        if any(b in msg.lower() for b in BUSY):
            if i % 4 == 0:
                log(f"commit not queued yet ({short(msg, 120)}); retrying")
            time.sleep(Timing.commit_pause)
            continue
        raise Failed(f"commit refused: {short(msg)}")
    raise Failed(f"commit still refused after {Timing.commit_tries} tries")


def run(args, api: Api, data: bytes, tree: ET.Element) -> str:
    keygen(api)
    log(f"API key taken for user {api.user}")
    merges, replaces = sections_in(tree)
    if args.jumbo == "auto" and tree.find("devices/entry/deviceconfig/setting/jumbo-frame") is not None:
        wait_idle(api)
        mode = jumbo_mode(api)
        log(f"jumbo-frame mode: {mode or 'unknown'}")
        if mode == "off":
            jumbo_on_and_restart(api)
    wait_idle(api)
    e = call(api, api.import_config, IMPORT_NAME, data)
    log(f"import {IMPORT_NAME}: {e.get('status')}")
    if e.get("status") != "success":
        raise Failed(f"import failed: {short(text(e))}")
    for label, xp in merges:
        load_partial(api, "merge", label, xp)
    for label, _xp, _rel in SECTIONS:
        if label not in [m[0] for m in merges]:
            log(f"partial merge {label}: not in the file, skipped")
    if args.rulebase == "replace":
        for label, xp in replaces:
            load_partial(api, "replace", label, xp)
    v = call(api, api.op, "<validate><full></full></validate>")
    jid = text(v, ".//job")
    if not jid:
        raise Failed(f"validate was not queued: {short(text(v))}")
    res, det = wait_job(api, jid, "validate", Timing.job_tries)
    log(f"validate job {jid}: {res}")
    if res != "OK":
        raise Failed(f"the file does not validate, nothing committed: {det}")
    jid = commit(api, args.description)
    if jid is None:
        log("commit: there are no changes to commit; the running configuration already holds the file")
        return "none"
    log(f"commit job {jid} queued")
    res, det = wait_job(api, jid, "commit", Timing.commit_poll_tries)
    log(f"commit job {jid}: result={res} {short(det, 300)}")
    if res != "OK":
        raise Failed(f"commit job {jid} did not succeed: {det}")
    return jid


# --------------------------------------------------------------------------------------------
# Command line


def _arg(argv: list, name: str) -> str | None:
    for i, a in enumerate(argv):
        if a == name and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None


def launcher_args(cmdline: str = "/proc/1/cmdline") -> tuple[str | None, str | None]:
    """The --username and --password the container's PID 1 (the image's launcher) was given."""
    try:
        with open(cmdline, "rb") as f:
            argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
    except OSError:
        return None, None
    return _arg(argv, "--username"), _arg(argv, "--password")


def container_login(name: str, docker: str = "docker") -> tuple[str | None, str | None]:
    """From the host: the --username and --password the named container's launcher was started
    with, else USERNAME and PASSWORD of its environment, read with docker inspect (as lib.sh's
    _creds and common/klish/session.sh read a switch's). Nothing read here is printed."""
    if not CONTAINER_NAME.match(name):
        raise ValueError(f"--container {name!r}: not a container name")
    try:
        r = subprocess.run([docker, "inspect", "-f", "{{json .Config}}", name], capture_output=True, text=True,
                           timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None, None
    if r.returncode != 0:
        return None, None
    try:
        cfg = json.loads(r.stdout)
    except ValueError:
        return None, None
    if not isinstance(cfg, dict):
        return None, None
    argv = [str(a) for a in (cfg.get("Cmd") or [])]
    env = dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)
    return (_arg(argv, "--username") or env.get("USERNAME"), _arg(argv, "--password") or env.get("PASSWORD"))


def credentials(in_container: bool, container: str | None = None, cmdline: str = "/proc/1/cmdline",
                docker: str = "docker") -> tuple[str, str]:
    """(user, password): an exported SFAB_FW_PASSWORD first (the operator's override), then the
    login containerlab gave the firewall's launcher, the paloalto_panos kind's default."""
    env = os.environ
    if env.get("SFAB_FW_PASSWORD"):
        return env.get("SFAB_FW_USER") or "admin", env["SFAB_FW_PASSWORD"]
    if in_container:
        user, password = launcher_args(cmdline)
        if password:
            return user or "admin", password
        if env.get("PASSWORD"):
            return env.get("USERNAME") or "admin", env["PASSWORD"]
    if container:
        user, password = container_login(container, docker)
        if password:
            return user or "admin", password
    raise NoCredentials("no firewall password: run inside the firewall container, pass --container NAME, "
                        "or export SFAB_FW_PASSWORD as an override")


def is_local(api: str) -> bool:
    host = urllib.parse.urlsplit(api if "://" in api else f"https://{api}").hostname or ""
    return host in ("127.0.0.1", "localhost", "::1")


def parse_args(argv):
    p = argparse.ArgumentParser(prog="fw-startup.py", description="load and commit the PA-VM's rendered startup configuration")
    p.add_argument("--api", default="https://127.0.0.1", help="the firewall's API base (default: inside the container)")
    p.add_argument("--config", help="the rendered XML (default inside the container: /config/startup-config.cfg, else .xml)")
    p.add_argument("--expect-sha256", metavar="HEX", help="refuse unless the file's sha256 is this (the render's)")
    p.add_argument("--marker", help=f"marker file written on success (default inside the container: {IN_CONTAINER_MARKER})")
    p.add_argument("--container", metavar="NAME",
                   help="host runs: the firewall container whose launcher arguments hold the login (docker inspect)")
    p.add_argument("--rulebase", choices=("replace", "merge"), default="replace",
                   help="replace each vsys rulebase with the file's after the merge (default), or merge only")
    p.add_argument("--jumbo", choices=("auto", "skip"), default="auto",
                   help="auto: enable jumbo-frame mode and restart PAN-OS when the file needs it and the box is off")
    p.add_argument("--description", default="sfab startup-config", help="the commit description")
    p.add_argument("--plan", action="store_true", help="read the file and print the steps; contact nothing")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    local = is_local(args.api)
    path = args.config
    if not path:
        path = next((c for c in IN_CONTAINER_CONFIGS if os.path.isfile(c)), None) if local else None
        if not path:
            print("fw-startup: no --config given and no /config/startup-config.* found", file=sys.stderr)
            return 2
    try:
        with open(path, "rb") as f:
            data = f.read()
        tree = ET.fromstring(data)
    except (OSError, ET.ParseError) as x:
        print(f"fw-startup: cannot read {path}: {x}", file=sys.stderr)
        return 2
    if args.expect_sha256 and hashlib.sha256(data).hexdigest() != args.expect_sha256.lower():
        print(f"fw-startup: {path} is not the rendered file (sha256 {hashlib.sha256(data).hexdigest()})", file=sys.stderr)
        return 2
    if tree.tag != "config" or tree.find(f"devices/entry[@name='{DEVICE}']") is None:
        print(f"fw-startup: {path} is not a PAN-OS <config> with devices/entry[@name='{DEVICE}']", file=sys.stderr)
        return 2
    if b"<mgt-config" in data:
        print(f"fw-startup: {path} carries mgt-config; the launcher owns the login, refusing", file=sys.stderr)
        return 2
    marker = args.marker if args.marker else (IN_CONTAINER_MARKER if local else None)
    merges, replaces = sections_in(tree)
    if args.plan:
        print(f"config: {path} ({len(data)} bytes)")
        src = ("the launcher's arguments, else the container environment" if local else
               f"the launcher arguments of container {args.container}" if args.container else "no container (pass --container NAME)")
        print(f"api: {args.api} (credentials: SFAB_FW_PASSWORD if exported, else {src})")
        print(f"jumbo-frame: {'asked for' if tree.find('devices/entry/deviceconfig/setting/jumbo-frame') is not None else 'not asked for'} (mode {args.jumbo})")
        print("merge: " + (", ".join(m[0] for m in merges) or "nothing"))
        print("replace: " + (", ".join(r[0] for r in replaces) if args.rulebase == "replace" and replaces else "nothing"))
        print("then: validate full, commit, poll the job")
        print(f"marker: {marker or 'none'}")
        return 0
    try:
        user, password = credentials(local, args.container)
        api = Api(args.api, user, password)
        jid = run(args, api, data, tree)
    except NoCredentials as x:
        print(f"fw-startup: {x}", file=sys.stderr)
        return 2
    except Refused as x:
        log(f"the firewall refused the credentials: {short(str(x), 120)}")
        return 5
    except Failed as x:
        log(f"FAILED: {x}")
        return 1
    except ValueError as x:
        print(f"fw-startup: {x}", file=sys.stderr)
        return 2
    if marker:
        d = os.path.dirname(marker)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(marker, "w", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} commit job {jid} result OK\n")
        log(f"marker written: {marker}")
    log("startup configuration committed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
