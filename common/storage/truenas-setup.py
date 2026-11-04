#!/usr/bin/env python3
"""truenas-setup.py: bring a lab's TrueNAS system to its rendered state through the middleware API.

    truenas-setup.py all --node truenas1               every step of setup.json, in order (finish runs this)
    truenas-setup.py STEP --node truenas1              one step: wait, network, services, users or csi
    truenas-setup.py plan --node truenas1              what the steps do, from setup.json alone (no contact)
    truenas-setup.py dump --node truenas1 --out DIR    one file per read-only call, for the audit

It reads bootstrap/<node>/setup.json (render/storage.py) from the lab's render directory: --render,
else $SFAB_RENDERDIR, else $SFAB_LABDIR, else the current directory. It runs on the lab host and
talks to the system on its containerlab management address (setup.json api.host; --api HOST:PORT
overrides it). Every step checks before it changes anything, so a second run changes nothing.

  wait      the container is running and its health check reads healthy: the image's launcher
            has finished the first boot (administrator password, SSH, ARC cap, pool).
  network   1. the routes marked first: the management network via the VM's user-mode NIC, so
               this session, which reaches the system through that NIC with its own source
               address, keeps a way back when the default route moves to the firewall;
            2. the data bond (members found by MAC: TrueNAS's NICs carry the container ports'
               MACs; an existing bond gets its members set again when they differ), the storage
               management NIC, and the user-mode NIC made static with no gateway, so there is
               one default route;
            3. interface.commit with rollback armed, then interface.checkin: TrueNAS undoes a
               network change nobody checks in. Re-addressing the user-mode NIC can stall the
               commit call for minutes, so a dropped session reconnects, asks whether a check-in
               is waiting and checks in; the interfaces are then read back, so a change TrueNAS
               rolled back fails the step instead of passing it;
            4. the other routes, the default gateway, DNS, the domain and NTP.
  services  the pool exists; the datasets; NFS bound to the data address; the NVMe-oF TCP port on
            the data address; each service enabled and running.
  users     the CSI user, an administrator of its own, with the administrator's password.
  csi       one Secret per democratic-csi class, holding the driver's configuration with the
            password and the NVMe-oF port ids, applied with the harness's kubectl (setup.json's
            csi.kubernetes.kubectl: common/bin/sfab-kubectl and the lab's directory, kubectl with
            the admin kubeconfig on the init node over SSH) with kubectl apply --server-side. The values files in bootstrap/k8s/ name these Secrets, so the
            democratic-csi releases install after this step.

Sessions. TrueNAS allows 10 sessions per user and 20 logins a minute from one client, so a run
holds one session for all its steps, logs in at most once every few seconds when it must
reconnect, and logs out at the end.

Credentials. The setup logs in as truenas_admin, whose password the launcher sets at first boot
to its own --password; the launcher reads only its command line, never its environment.
containerlab 0.81.0's generic_vm kind builds --username and --password from the node's USERNAME
and PASSWORD env, which the topology fills from state/secrets.env (with USERNAME truenas_admin
the launcher creates no second administrator). The password, in order:
  1. SFAB_TRUENAS_PASSWORD from the environment, an explicit operator override;
  2. the launcher's --password, read from the container with docker inspect (else its PASSWORD);
  3. SFAB_TRUENAS_PASSWORD in the lab's state/secrets.env.
This script never puts the password on a command line or in a file: it travels in the login
request and, for the CSI Secrets, on kubectl's standard input. Everything printed passes through
a redactor.

Every docker call names a container of this lab (the setup.json lab name plus a dash, as the
harness's dk does) and is refused otherwise.

Exit status: 0 done; 1 a step failed; 2 a usage or file error; 5 TrueNAS refused the password.
Standard library only, Python 3.10 or later.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tnrpc  # noqa: E402

STEPS = ("wait", "network", "services", "users", "csi", "ui")
DUMP_CALLS = (
    ("system.info", []),
    ("pool.query", []),
    ("interface.query", []),
    ("network.general.summary", []),
    ("network.configuration.config", []),
    ("staticroute.query", []),
    ("system.ntpserver.query", []),
    ("service.query", []),
    ("nfs.config", []),
    ("sharing.nfs.query", []),
    ("nvmet.port.query", []),
    ("nvmet.subsys.query", []),
    ("nvmet.namespace.query", []),
    ("pool.dataset.query", [[], {"select": ["id", "type", "used", "available", "readonly"]}]),
    ("user.query", [[["builtin", "=", False]], {"select": ["username", "full_name", "groups", "locked"]}]),
    # the CSI user's last API calls; dump_calls() puts setup.json's CSI user in the filter
    ("audit.query", [{"services": ["MIDDLEWARE"], "query-filters": [["username", "=", "democratic-csi"]],
                      "query-options": {"order_by": ["-message_timestamp"], "limit": 30}}]),
)


class Timing:
    """Tries and pauses (seconds). The tests shrink them."""

    health_wait_s = 1800.0
    health_poll_s = 10.0
    login_tries = 60
    login_gap_s = 5.0          # at most 12 logins a minute, under TrueNAS's 20
    busy_pause_s = 30.0
    connect_timeout_s = 20.0
    call_timeout_s = 300.0
    job_timeout_s = 1800.0
    job_poll_s = 2.0
    checkin_tries = 40
    checkin_pause_s = 5.0
    after_drop_s = 10.0
    docker_timeout_s = 120.0
    ntp_tries = 18             # an NTP server TrueNAS cannot reach yet, tried every ntp_pause_s
    ntp_pause_s = 10.0


class Failed(Exception):
    """A step failed; the message says which and why."""


class Usage(Exception):
    """A usage or file error."""


# --------------------------------------------------------------------------------------------
# output with the password removed

_SECRETS: list = []


def remember(*values) -> None:
    for v in values:
        if v and v not in _SECRETS:
            _SECRETS.append(v)
    _SECRETS.sort(key=len, reverse=True)


def redact(text) -> str:
    s = str(text)
    for v in _SECRETS:
        s = s.replace(v, "<redacted>")
    return s


class Log:
    def __init__(self, node: str, stream=None):
        self.node = node
        self.stream = stream or sys.stdout

    def __call__(self, *parts) -> None:
        msg = " ".join(str(p) for p in parts)
        print(f"{time.strftime('%H:%M:%SZ', time.gmtime())} {self.node}: {redact(msg)}", file=self.stream, flush=True)


# --------------------------------------------------------------------------------------------
# docker, scoped to the lab


class Docker:
    def __init__(self, lab: str, log: Log):
        self.prefix = f"{lab}-"
        self.log = log

    def own(self, container: str) -> str:
        if not container or not container.startswith(self.prefix) or container.startswith("-"):
            raise Failed(f"container {container!r} is not in this lab (prefix {self.prefix})")
        return container

    def run(self, args: list, container: str, stdin: str | None = None, timeout: float | None = None) -> str:
        self.own(container)
        try:
            p = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True,
                               timeout=timeout or Timing.docker_timeout_s)
        except FileNotFoundError as e:
            raise Failed("docker is not installed here") from e
        except subprocess.TimeoutExpired as e:
            raise Failed(f"docker {args[0]} {container}: no answer in {e.timeout:.0f} s") from e
        if p.returncode != 0:
            last = ((p.stderr or p.stdout or "").strip().splitlines() or [f"exit {p.returncode}"])[-1]
            raise Failed(f"docker {args[0]} {container}: {redact(last)}")
        return p.stdout

    def inspect(self, container: str, what: str) -> dict:
        out = self.run(["inspect", "-f", "{{json ." + what + "}}", container], container)
        try:
            return json.loads(out) or {}
        except ValueError as e:
            raise Failed(f"docker inspect {container}: unreadable {what}") from e

    def mac(self, container: str, eth: str) -> str:
        if not eth.startswith("eth") or not eth[3:].isdigit():
            raise Failed(f"{eth!r} is not a container port")
        return self.run(["exec", container, "cat", f"/sys/class/net/{eth}/address"], container).strip().lower()


def launcher_credentials(cfg: dict) -> tuple:
    """(user, password) from a container's Config: the launcher's --username and --password on its
    command line, else USERNAME and PASSWORD in its environment."""
    cmd = [str(a) for a in (cfg.get("Cmd") or [])]
    env = dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)

    def arg(name):
        for i, a in enumerate(cmd):
            if a == name and i + 1 < len(cmd):
                return cmd[i + 1]
            if a.startswith(name + "="):
                return a.split("=", 1)[1]
        return None

    return arg("--username") or env.get("USERNAME"), arg("--password") or env.get("PASSWORD")


def read_env_file(path: str) -> dict:
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


def find_password(setup: dict, docker: Docker, state_dir: str | None, environ=None) -> tuple:
    """(password, where it came from), in the order the module docstring gives."""
    environ = os.environ if environ is None else environ
    if environ.get("SFAB_TRUENAS_PASSWORD"):
        return environ["SFAB_TRUENAS_PASSWORD"], "the environment (SFAB_TRUENAS_PASSWORD)"
    try:
        _, pw = launcher_credentials(docker.inspect(setup["container"], "Config"))
    except Failed:
        pw = None
    if pw:
        return pw, f"the launcher's arguments in {setup['container']}"
    if state_dir:
        pw = read_env_file(os.path.join(state_dir, "secrets.env")).get("SFAB_TRUENAS_PASSWORD")
        if pw:
            return pw, "state/secrets.env"
    raise Failed("no TrueNAS password: not exported, not in the container, not in state/secrets.env")


# --------------------------------------------------------------------------------------------
# one API session for the whole run


class Session:
    def __init__(self, host: str, port: int, path: str, user: str, password: str, log: Log):
        self.host, self.port, self.path = host, port, path
        self.user, self.password = user, password
        self.log = log
        self.c = None
        self.logins = 0
        self._last_login = -1e9

    def open(self) -> None:
        last = None
        for i in range(Timing.login_tries):
            gap = Timing.login_gap_s - (time.monotonic() - self._last_login)
            if gap > 0:
                time.sleep(gap)
            self._last_login = time.monotonic()
            try:
                c = tnrpc.Client(self.host, self.port, self.path, timeout=Timing.connect_timeout_s)
            except OSError as e:
                last = e
                self.log(f"API not reachable yet ({e}); try {i + 1}")
                continue
            c.job_poll_s = Timing.job_poll_s
            try:
                c.login(self.user, self.password)
                self.logins += 1
                self.c = c
                return
            except tnrpc.LoginRefused:
                c.close()
                raise
            except tnrpc.RPCError as e:
                c.close()
                last = e
                busy = e.errname in ("EBUSY", "RATE_LIMIT_EXCEEDED") or "rate" in str(e).lower()
                self.log(f"login not taken ({e}); try {i + 1}")
                if busy:
                    time.sleep(Timing.busy_pause_s)
            except (OSError, TimeoutError, ValueError) as e:
                c.close()
                last = e
                self.log(f"API not ready ({e}); try {i + 1}")
        raise Failed(f"no API session on {self.host}:{self.port} after {Timing.login_tries} tries ({last})")

    def reconnect(self) -> None:
        if self.c is not None:
            try:
                self.c.close()
            except OSError:
                pass
            self.c = None
        self.open()

    def call(self, method: str, *params, timeout: float | None = None):
        if self.c is None:
            self.open()
        return self.c.call(method, list(params), timeout=timeout or Timing.call_timeout_s)

    def job(self, method: str, *params, timeout: float | None = None):
        if self.c is None:
            self.open()
        return self.c.job(method, list(params), timeout=timeout or Timing.job_timeout_s)

    def one(self, method: str, filters: list):
        r = self.call(method, filters)
        return r[0] if r else None

    def close(self) -> None:
        if self.c is not None:
            self.c.logout()
            self.c.close()
            self.c = None


# --------------------------------------------------------------------------------------------
# the steps


def _mac_of(i: dict) -> str:
    st = i.get("state") or {}
    return str(st.get("permanent_link_address") or st.get("link_address") or "").lower()


def _alias(cidr: str) -> dict:
    a = ipaddress.ip_interface(cidr)
    return {"type": "INET" if a.version == 4 else "INET6", "address": str(a.ip), "netmask": a.network.prefixlen}


def _aliases_of(i: dict, where: str = "config") -> list:
    src = i.get("aliases") if where == "config" else (i.get("state") or {}).get("aliases")
    return sorted(f"{a.get('address')}/{a.get('netmask')}" for a in (src or []) if a.get("type") in ("INET", "INET6"))


def step_wait(ctx) -> None:
    setup, log = ctx["setup"], ctx["log"]
    c = setup["container"]
    deadline = time.monotonic() + Timing.health_wait_s
    status = None
    while True:
        st = ctx["docker"].inspect(c, "State")
        if not st.get("Running"):
            raise Failed(f"{c} is not running ({st.get('Status')})")
        status = (st.get("Health") or {}).get("Status")
        if status == "healthy":
            log(f"{c} is healthy: the launcher's first boot is done")
            return
        if time.monotonic() >= deadline:
            raise Failed(f"{c} not healthy after {Timing.health_wait_s:.0f} s (health {status})")
        time.sleep(Timing.health_poll_s)


def ensure_route(S: Session, r: dict, log: Log) -> bool:
    if S.call("staticroute.query", [["destination", "=", r["dest"]]]):
        return False
    log(f"static route {r['dest']} via {r['gateway']} ({r.get('description') or r.get('id')})")
    S.call("staticroute.create", {"destination": r["dest"], "gateway": r["gateway"],
                                  "description": r.get("description") or r.get("id") or ""})
    return True


def map_nics(ctx, ifs: list) -> dict:
    """{container port: TrueNAS interface name, ...} for the bond members and the management NIC,
    by MAC, plus 'qemu_user': the one physical NIC left, the VM's user-mode NIC."""
    setup, docker = ctx["setup"], ctx["docker"]
    net = setup["network"]
    phys = {_mac_of(i): i["name"] for i in ifs if i.get("type") == "PHYSICAL" and _mac_of(i)}
    mg = net["mgmt"]
    eths = [m["eth"] for m in net["bond"]["members"]] + ([m["eth"] for m in mg["members"]] if mg.get("members") else [mg["eth"]])
    names = {e: phys.get(docker.mac(setup["container"], e)) for e in eths}
    used = {n for n in names.values() if n}
    qprefix = ipaddress.ip_network(net["qemu_user"]["prefix"])
    rest = [i for i in ifs if i.get("type") == "PHYSICAL" and i["name"] not in used]
    inq = [i for i in rest if any(ipaddress.ip_interface(a).ip in qprefix for a in _aliases_of(i, "state") + _aliases_of(i))]
    names["qemu_user"] = inq[0]["name"] if len(inq) == 1 else (rest[0]["name"] if len(rest) == 1 else None)
    return names


def step_network(ctx) -> None:
    S, setup, log = ctx["S"], ctx["setup"], ctx["log"]
    net = setup["network"]
    for r in net["routes"]:
        if r.get("first"):
            ensure_route(S, r, log)
    ifs = S.call("interface.query")
    names = map_nics(ctx, ifs)
    by_name = {i["name"]: i for i in ifs}
    log("interfaces by MAC: " + ", ".join(f"{k} {v or '?'}" for k, v in sorted(names.items())))
    changed = []
    mg = net["mgmt"]
    ensure_lagg(S, net["bond"], names, by_name, changed, log)
    if mg.get("members"):
        # the management bond, one leg on each switch of the pair
        ensure_lagg(S, mg, names, by_name, changed, log)
    else:
        ensure_mgmt_nic(S, mg, names, by_name, changed, log)
    ensure_qemu_user(S, net, names, by_name, changed, log)
    finish_network(ctx, net, names, changed)


def ensure_lagg(S, bond: dict, names: dict, by_name: dict, changed: list, log) -> None:
    """A LACP link aggregation over its members (by MAC) with its one address and MTU."""
    want_bond = sorted([bond["address"]])
    cur = by_name.get(bond["name"])
    members = [names.get(m["eth"]) for m in bond["members"]]
    release_members(S, bond, names, by_name, changed, log)
    if cur is None:
        if not all(members):
            missing = [m["eth"] for m, n in zip(bond["members"], members) if not n]
            raise Failed(f"bond members not found by MAC: {', '.join(missing)}")
        log(f"{bond['name']}: LACP {bond['lacpdu_rate']}, {bond['xmit_hash_policy']}, MTU {bond['mtu']}, "
            f"over {', '.join(members)}, {bond['address']}")
        S.call("interface.create", {"type": "LINK_AGGREGATION", "name": bond["name"], "lag_protocol": bond["protocol"],
                                    "lag_ports": members, "lacpdu_rate": bond["lacpdu_rate"],
                                    "xmit_hash_policy": bond["xmit_hash_policy"], "mtu": bond["mtu"],
                                    "aliases": [_alias(bond["address"])]})
        changed.append(bond["name"])
    else:
        upd = {}
        if _aliases_of(cur) != want_bond or (cur.get("mtu") or 0) != bond["mtu"]:
            upd.update({"aliases": [_alias(bond["address"])], "mtu": bond["mtu"]})
        # The members by MAC again: a NIC that is no longer the container port it was moves out.
        # A member whose MAC is not found leaves the bond as it is.
        if all(members) and sorted(cur.get("lag_ports") or []) != sorted(members):
            upd["lag_ports"] = members
        elif not all(members):
            log(f"{bond['name']}: members not all found by MAC; the bond keeps {', '.join(cur.get('lag_ports') or [])}")
        if upd:
            log(f"{bond['name']}: " + ", ".join(f"{k} {v if k != 'aliases' else bond['address']}" for k, v in sorted(upd.items())))
            S.call("interface.update", bond["name"], upd)
            changed.append(bond["name"])


def release_members(S, bond: dict, names: dict, by_name: dict, changed: list, log) -> None:
    """A bond member that has a configuration of its own (the management NIC before it was bonded)
    has it deleted. TrueNAS refuses a new bond over a port with any configuration row, even one
    with no address left ("Interface ... is currently in use"); interface.delete on a physical NIC
    removes that row and so its address and DHCP."""
    for m in bond["members"]:
        mname = names.get(m["eth"])
        mi = by_name.get(mname) or {}
        live = [a for a in ((mi.get("state") or {}).get("aliases") or []) if a.get("type") == "INET"]
        configured = mi.get("ipv4_dhcp") or _aliases_of(mi) or live
        # before the bond exists every member is cleared, since a row with no address still blocks it
        if mname and mname not in changed and (configured or bond["name"] not in by_name):
            log(f"{mname}: its own configuration (address, DHCP) removed, to join {bond['name']}")
            S.call("interface.delete", mname)
            changed.append(mname)


def ensure_mgmt_nic(S, mg: dict, names: dict, by_name: dict, changed: list, log) -> None:
    mname = names.get(mg["eth"]) or next((n for n, i in by_name.items() if mg["address"] in _aliases_of(i)), None)
    if not mname:
        raise Failed(f"management NIC ({mg['eth']}) not found by MAC")
    mi = by_name.get(mname) or {}
    if mi.get("ipv4_dhcp") or _aliases_of(mi) != [mg["address"]]:
        log(f"{mname} (container {mg['eth']}, VLAN {mg['vlan']}): {mg['address']}")
        upd = {"ipv4_dhcp": False, "aliases": [_alias(mg["address"])]}
        if mg.get("mtu"):
            upd["mtu"] = mg["mtu"]
        S.call("interface.update", mname, upd)
        changed.append(mname)


def ensure_qemu_user(S, net: dict, names: dict, by_name: dict, changed: list, log) -> None:
    q = net["qemu_user"]
    qname = names.get("qemu_user")
    if not qname:
        raise Failed("the VM's user-mode NIC was not found (no single physical NIC left after the MAC map)")
    qi = by_name.get(qname) or {}
    if qi.get("ipv4_dhcp"):
        qprefix = ipaddress.ip_network(q["prefix"])
        held = [a for a in _aliases_of(qi, "state") if ipaddress.ip_interface(a).ip in qprefix]
        addr = held[0] if held else q["address"]
        log(f"{qname} (the VM's user-mode NIC): static {addr}, no gateway, so the firewall's is the one default route")
        S.call("interface.update", qname, {"ipv4_dhcp": False, "aliases": [_alias(addr)]})
        changed.append(qname)


def finish_network(ctx, net: dict, names: dict, changed: list) -> None:
    S, setup, log = ctx["S"], ctx["setup"], ctx["log"]
    pending = bool(S.call("interface.has_pending_changes"))
    if changed or pending:
        commit(ctx, changed)
        drift = network_drift(net, S.call("interface.query"), names)
        if drift:
            raise Failed("after the commit and check-in the interfaces are not as rendered (rolled back?): " + "; ".join(drift))
        log("interfaces as rendered after the commit")
    else:
        log("interfaces as rendered; nothing to commit")

    for r in net["routes"]:
        if not r.get("first"):
            ensure_route(S, r, log)
    gc = S.call("network.configuration.config") or {}
    want = {"hostname": setup["hostname"], "domain": setup["domain"], "ipv4gateway": net["gateway"]}
    for k, v in zip(("nameserver1", "nameserver2", "nameserver3"), net.get("nameservers") or []):
        want[k] = v
    if any(gc.get(k) != v for k, v in want.items()):
        log(f"default gateway {net['gateway']}, DNS {', '.join(net.get('nameservers') or [])}, domain {setup['domain']}")
        S.call("network.configuration.update", want)
    for a in net.get("ntp") or []:
        if not S.call("system.ntpserver.query", [["address", "=", a]]):
            log(f"NTP server {a}")
            # TrueNAS sends the server a query before it saves it, and right after the network
            # commit the first query can go unanswered ("Server could not be reached"): try again
            for t in range(Timing.ntp_tries):
                try:
                    S.call("system.ntpserver.create", {"address": a, "iburst": True, "prefer": True})
                    break
                except Exception as e:  # noqa: BLE001 (the API client's error carries the reason)
                    if "could not be reached" not in str(e) or t == Timing.ntp_tries - 1:
                        raise
                    log(f"NTP server {a} not reached yet; again in {Timing.ntp_pause_s:.0f} s")
                    time.sleep(Timing.ntp_pause_s)


def network_drift(net: dict, ifs: list, names: dict) -> list:
    """How TrueNAS's configured interfaces differ from setup.json (empty when they are as rendered):
    the bond's address, MTU and members (when every member was found by MAC), the management NIC's
    one static address, and the user-mode NIC off DHCP."""
    by_name = {i["name"]: i for i in ifs}
    out = []
    b = net["bond"]
    cur = by_name.get(b["name"])
    if cur is None:
        out.append(f"no {b['name']}")
    else:
        if _aliases_of(cur) != [b["address"]]:
            out.append(f"{b['name']} holds {', '.join(_aliases_of(cur)) or 'no address'}")
        if (cur.get("mtu") or 0) != b["mtu"]:
            out.append(f"{b['name']} has MTU {cur.get('mtu')}")
        members = [names.get(m["eth"]) for m in b["members"]]
        if all(members) and sorted(cur.get("lag_ports") or []) != sorted(members):
            out.append(f"{b['name']} is over {', '.join(cur.get('lag_ports') or []) or 'no member'}")
    mg = net["mgmt"]
    if mg.get("members"):
        cur = by_name.get(mg["name"])
        if cur is None:
            out.append(f"no {mg['name']}")
        elif _aliases_of(cur) != [mg["address"]]:
            out.append(f"{mg['name']} holds {', '.join(_aliases_of(cur)) or 'no address'}")
        elif (cur.get("mtu") or 0) != mg["mtu"]:
            out.append(f"{mg['name']} has MTU {cur.get('mtu')}")
        else:
            members = [names.get(m["eth"]) for m in mg["members"]]
            if all(members) and sorted(cur.get("lag_ports") or []) != sorted(members):
                out.append(f"{mg['name']} is over {', '.join(cur.get('lag_ports') or []) or 'no member'}")
        q = names.get("qemu_user")
        if q and (by_name.get(q) or {}).get("ipv4_dhcp"):
            out.append(f"{q} (the user-mode NIC) is still on DHCP")
        return out
    mname = names.get(mg["eth"])
    mi = by_name.get(mname) if mname else next((i for i in ifs if mg["address"] in _aliases_of(i)), None)
    if mi is None:
        out.append(f"no interface holds {mg['address']}")
    elif mi.get("ipv4_dhcp") or _aliases_of(mi) != [mg["address"]]:
        out.append(f"{mi['name']} holds {', '.join(_aliases_of(mi)) or 'no address'}{' and DHCP' if mi.get('ipv4_dhcp') else ''}")
    q = names.get("qemu_user")
    if q and (by_name.get(q) or {}).get("ipv4_dhcp"):
        out.append(f"{q} (the user-mode NIC) is still on DHCP")
    return out


def commit(ctx, changed: list) -> None:
    S, log, setup = ctx["S"], ctx["log"], ctx["setup"]
    cm = setup["network"]["commit"]
    log(f"committing {', '.join(changed) or 'pending changes'} (rollback armed, check-in within {cm['checkin_timeout_s']} s)")
    try:
        S.call("interface.commit", {"rollback": bool(cm["rollback"]), "checkin_timeout": cm["checkin_timeout_s"]},
               timeout=cm["call_timeout_s"])
    except tnrpc.RPCError as e:
        try:
            S.call("interface.rollback")
        except (OSError, TimeoutError, tnrpc.RPCError):
            pass
        raise Failed(f"interface.commit refused the change, rolled back: {e}") from e
    except (OSError, TimeoutError, ValueError) as e:
        log(f"the commit call ended without an answer ({e}); reconnecting to check in")
        time.sleep(Timing.after_drop_s)
        S.reconnect()
    # Ask before checking in: interface.checkin_waiting is the seconds left before TrueNAS rolls the
    # change back, or null when nothing waits (a check-in already arrived, or there was nothing to
    # roll back). Whether the change stuck is judged afterwards from the interfaces themselves.
    last = None
    for i in range(Timing.checkin_tries):
        try:
            waiting = S.call("interface.checkin_waiting")
            if waiting is None:
                log("no check-in is waiting")
                break
            S.call("interface.checkin")
            log(f"checked in ({waiting} s were left)")
            break
        except (OSError, TimeoutError, ValueError, tnrpc.RPCError) as e:
            last = e
            log(f"check-in try {i + 1} ({e})")
            time.sleep(Timing.checkin_pause_s)
            try:
                S.reconnect()
            except Failed as f:
                last = f
    else:
        raise Failed(f"no check-in after the commit: TrueNAS rolls the network back ({last})")
    waiting = S.call("interface.checkin_waiting")
    pending = S.call("interface.has_pending_changes")
    if waiting not in (None, 0) or pending:
        raise Failed(f"after the check-in: checkin_waiting {waiting}, pending changes {pending}")
    log("commit done: no check-in waiting, no pending change")


def step_services(ctx) -> None:
    S, setup, log = ctx["S"], ctx["setup"], ctx["log"]
    pool = setup["pool"]
    p = S.one("pool.query", [["name", "=", pool]])
    if not p:
        raise Failed(f"pool {pool} does not exist: the launcher builds it at first boot (TRUENAS_POOL)")
    if p.get("status") not in (None, "ONLINE"):
        raise Failed(f"pool {pool} is {p.get('status')}")
    for d in setup["datasets"]:
        if not S.one("pool.dataset.query", [["id", "=", d]]):
            log(f"dataset {d}")
            S.call("pool.dataset.create", {"name": d})
    svcs = setup.get("services") or {}
    if "nfs" in svcs:
        want = svcs["nfs"]
        cur = S.call("nfs.config") or {}
        if sorted(cur.get("bindip") or []) != sorted(want["bindip"]) or sorted(cur.get("protocols") or []) != sorted(want["protocols"]):
            log(f"NFS on {', '.join(want['bindip'])}, {' and '.join(want['protocols'])}")
            S.call("nfs.update", {"protocols": want["protocols"], "bindip": want["bindip"]})
        service(ctx, "nfs")
    if "nvmet" in svcs:
        for port in svcs["nvmet"]["ports"]:
            if not nvmet_ports(S, port):
                log(f"NVMe-oF {port['trtype']} port {port['traddr']}:{port['trsvcid']}")
                S.call("nvmet.port.create", {"addr_trtype": port["trtype"], "addr_traddr": port["traddr"],
                                             "addr_trsvcid": port["trsvcid"]})
        service(ctx, "nvmet")


def nvmet_ports(S: Session, port: dict) -> list:
    """The NVMe-oF ports on this address and TCP port (the API may hold the port as a string)."""
    found = S.call("nvmet.port.query", [["addr_traddr", "=", port["traddr"]]]) or []
    return [p for p in found if str(p.get("addr_trsvcid")) == str(port["trsvcid"])
            and str(p.get("addr_trtype", port["trtype"])).upper() == str(port["trtype"]).upper()]


def service(ctx, name: str) -> None:
    S, log = ctx["S"], ctx["log"]
    cur = S.one("service.query", [["service", "=", name]]) or {}
    if not cur.get("enable"):
        log(f"service {name}: enabled at boot")
        S.call("service.update", name, {"enable": True})
    if cur.get("state") != "RUNNING":
        log(f"service {name}: start")
        S.job("service.control", "START", name)


def step_users(ctx) -> None:
    S, setup, log = ctx["S"], ctx["setup"], ctx["log"]
    users = ((setup.get("csi") or {}).get("users")) or []
    if not users:
        log("no CSI user in setup.json")
        return
    gid = None
    for u in users:
        if S.one("user.query", [["username", "=", u["username"]]]):
            continue
        spec = {"username": u["username"], "full_name": u.get("full_name") or u["username"], "password": ctx["password"],
                "group_create": True, "smb": False}
        if u.get("administrator"):
            if gid is None:
                g = S.one("group.query", [["name", "=", "builtin_administrators"]])
                if not g:
                    raise Failed("group builtin_administrators not found")
                gid = g["id"]
            spec["groups"] = [gid]
        log(f"user {u['username']}{' (administrator)' if u.get('administrator') else ''}")
        S.call("user.create", spec)


def csi_manifest(setup: dict, password: str, nvme_port_ids: list) -> dict:
    """The kubectl manifest: the namespace and one Secret per class with the driver configuration,
    the runtime fields filled in."""
    csi = setup["csi"]
    k = csi["kubernetes"]
    labels = dict(k.get("secret_labels") or {})
    items = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": k["namespace"]}}]
    for c in csi["classes"]:
        cfg = json.loads(json.dumps(c["driver_config"]))
        cfg.setdefault("httpConnection", {})["password"] = password
        if "nvmeof" in cfg:
            if not nvme_port_ids:
                raise Failed(f"class {c['name']}: no NVMe-oF port on {setup['services']['nvmet']['ports'][0]['traddr']}")
            cfg["nvmeof"]["ports"] = list(nvme_port_ids)
        body = json.dumps(cfg, indent=2, sort_keys=True) + "\n"
        items.append({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                      "metadata": {"name": c["config_secret"], "namespace": k["namespace"], "labels": labels},
                      "data": {c["config_key"]: base64.b64encode(body.encode()).decode()}})
    return {"apiVersion": "v1", "kind": "List", "items": items}


# the repository root, which a relative kubectl program path (common/bin/sfab-kubectl) is taken from
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def run_kubectl(argv, args: list, stdin: str) -> str:
    """The harness's kubectl (argv: the program and its leading arguments, the program relative to the
    repository root unless absolute), the manifest on its standard input; its output, redacted."""
    argv = list(argv)
    if argv and not os.path.isabs(argv[0]):
        argv[0] = os.path.join(REPO_ROOT, argv[0])
    try:
        p = subprocess.run(argv + list(args), input=stdin, capture_output=True, text=True, timeout=300)
    except FileNotFoundError as e:
        raise Failed(f"kubectl: {argv[0]} is not there") from e
    except subprocess.TimeoutExpired as e:
        raise Failed("kubectl apply: no answer in 300 s") from e
    if p.returncode != 0:
        last = (p.stderr.strip().splitlines() or [f"exit {p.returncode}"])[-1]
        raise Failed(f"kubectl apply: {redact(last)}")
    return redact(p.stdout)


def step_csi(ctx) -> None:
    S, setup, log = ctx["S"], ctx["setup"], ctx["log"]
    csi = setup.get("csi") or {}
    k = csi.get("kubernetes")
    if not csi.get("classes") or not k:
        log("csi: no Kubernetes in this lab's setup.json; nothing to write")
        return
    ids = []
    if any("nvmeof" in c["driver_config"] for c in csi["classes"]):
        for port in (setup.get("services") or {}).get("nvmet", {}).get("ports", []):
            ids.extend(p["id"] for p in nvmet_ports(S, port))
    manifest = csi_manifest(setup, ctx["password"], sorted(set(ids)))
    names = [i["metadata"]["name"] for i in manifest["items"] if i["kind"] == "Secret"]
    out = run_kubectl(k["kubectl"], ["apply", "--server-side", "--force-conflicts", "-f", "-"], json.dumps(manifest))
    for line in out.strip().splitlines():
        log(f"kubectl: {line}")
    log(f"csi: Secrets {', '.join(names)} in {k['namespace']} (NVMe-oF ports {ids or 'none'})")


def step_ui(ctx) -> None:
    """The web interface and API answer only on the addresses setup.json names (the storage
    management address, and the user-mode NIC the harness reaches the system through): bound
    there, never on the data address. Rebinding restarts the web server, which drops this session."""
    S, setup, log = ctx["S"], ctx["setup"], ctx["log"]
    ui = setup.get("ui") or {}
    want = sorted(ui.get("addresses") or [])
    if not want:
        log("ui: setup.json names no bind address; the web interface keeps its own")
        return
    have = sorted((S.call("system.general.config") or {}).get("ui_address") or [])
    if have == want:
        log(f"ui: bound to {', '.join(want)}")
        return
    log(f"ui: binding to {', '.join(want)} (was {', '.join(have) or 'none'}); the web server restarts")
    S.call("system.general.update", {"ui_address": want})
    try:
        S.call("system.general.ui_restart", timeout=60)
    except (OSError, TimeoutError, ValueError, tnrpc.RPCError) as e:
        log(f"ui: the restart call ended without an answer ({e}), as the web server restarts")
    time.sleep(Timing.after_drop_s)
    S.reconnect()
    have = sorted((S.call("system.general.config") or {}).get("ui_address") or [])
    if have != want:
        raise Failed(f"ui: bound to {', '.join(have) or 'none'} after the update, not {', '.join(want)}")
    log(f"ui: bound to {', '.join(want)}")


STEP_FN = {"wait": step_wait, "network": step_network, "services": step_services, "users": step_users, "csi": step_csi,
           "ui": step_ui}
NEEDS_API = ("network", "services", "users", "csi", "ui")


# --------------------------------------------------------------------------------------------
# plan and dump


def plan(setup: dict) -> list:
    net = setup["network"]
    b = net["bond"]
    lines = [f"{setup['node']} ({setup['container']}), API ws://{setup['api']['host']}:{setup['api']['port']}{setup['api']['path']}"
             f" as {setup['api']['user']}"]
    lines.append(f"wait: {setup['container']} healthy (the launcher's first boot done)")
    for r in net["routes"]:
        lines.append(f"network: route {r['dest']} via {r['gateway']}{' (first)' if r.get('first') else ''}")
    lines.append(f"network: {b['name']} LACP {b['lacpdu_rate']} {b['xmit_hash_policy']} MTU {b['mtu']} over "
                 + ", ".join(m["eth"] for m in b["members"]) + f" (by MAC), {b['address']}")
    mg = net["mgmt"]
    if mg.get("members"):
        lines.append(f"network: {mg['name']} LACP {mg['lacpdu_rate']} {mg['xmit_hash_policy']} MTU {mg['mtu']} over "
                     + ", ".join(m["eth"] for m in mg["members"]) + f" (by MAC), {mg['address']}")
    else:
        lines.append(f"network: {mg['eth']} (by MAC) {mg['address']}")
    lines.append(f"network: the user-mode NIC static {net['qemu_user']['address']}, no gateway")
    lines.append(f"network: commit with rollback, check-in within {net['commit']['checkin_timeout_s']} s")
    lines.append(f"network: gateway {net['gateway']}, DNS {', '.join(net.get('nameservers') or [])}, NTP {', '.join(net.get('ntp') or [])}")
    lines.append(f"services: pool {setup['pool']}; datasets {', '.join(setup['datasets'])}")
    for name, svc in sorted((setup.get("services") or {}).items()):
        if name == "nfs":
            lines.append(f"services: nfs on {', '.join(svc['bindip'])}")
        elif name == "nvmet":
            lines.append("services: nvmet ports " + ", ".join(f"{p['traddr']}:{p['trsvcid']}" for p in svc["ports"]))
    csi = setup.get("csi") or {}
    for u in csi.get("users") or []:
        lines.append(f"users: {u['username']}{' (administrator)' if u.get('administrator') else ''}")
    if csi.get("kubernetes"):
        k = csi["kubernetes"]
        lines.append(f"csi: Secrets {', '.join(c['config_secret'] for c in csi['classes'])} in {k['namespace']}"
                     f" through {' '.join(k['kubectl'])}")
    else:
        lines.append("csi: nothing (no Kubernetes in this lab)")
    return lines


def dump_calls(setup: dict) -> list:
    """DUMP_CALLS, with the audit log filtered on setup.json's CSI user."""
    users = [u["username"] for u in ((setup.get("csi") or {}).get("users") or []) if u.get("username")]
    out = []
    for m, p in DUMP_CALLS:
        if m == "audit.query" and users:
            p = [dict(p[0], **{"query-filters": [["username", "=", users[0]]]})]
        out.append((m, p))
    return out


def dump(S: Session, setup: dict, out: str, first: int = 1) -> int:
    os.makedirs(out, exist_ok=True)
    n = 0
    for i, (m, p) in enumerate(dump_calls(setup), first):
        with open(os.path.join(out, f"{i:02d}_{m}.txt"), "w", encoding="utf-8") as f:
            f.write(f"{setup['node']} api> {m} {json.dumps(p) if p else ''}".rstrip() + "\n")
            try:
                f.write(redact(json.dumps(S.call(m, *p, timeout=120), indent=1, sort_keys=True, default=str)) + "\n")
                n += 1
            except (tnrpc.RPCError, TimeoutError, OSError, ValueError) as e:
                f.write(f"ERROR {redact(e)}\n")
    return n


# --------------------------------------------------------------------------------------------


def load_setup(path: str) -> dict:
    try:
        with open(path, encoding="utf-8") as f:
            setup = json.load(f)
    except FileNotFoundError as e:
        raise Usage(f"{path} not found: run make render") from e
    except ValueError as e:
        raise Usage(f"{path}: not JSON ({e})") from e
    if setup.get("schema") != 1 or setup.get("product") != "truenas":
        raise Usage(f"{path}: not a TrueNAS setup file of schema 1")
    if not str(setup.get("container", "")).startswith(f"{setup.get('lab')}-"):
        raise Usage(f"{path}: container {setup.get('container')!r} is not in lab {setup.get('lab')!r}")
    return setup


def main(argv=None, environ=None) -> int:
    environ = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(prog="truenas-setup.py", description="Bring a lab's TrueNAS system to its rendered state.")
    ap.add_argument("step", choices=("all", "plan", "dump") + STEPS)
    ap.add_argument("--node", default="truenas1")
    ap.add_argument("--render", help="the lab's render directory (default $SFAB_RENDERDIR, $SFAB_LABDIR or .)")
    ap.add_argument("--setup", help="the setup file (default <render>/bootstrap/<node>/setup.json)")
    ap.add_argument("--state", help="the lab's state directory (default $SFAB_STATEDIR or <render>/state)")
    ap.add_argument("--api", help="HOST:PORT of the API instead of setup.json's")
    ap.add_argument("--out", help="dump: the directory for the files")
    ap.add_argument("--first", type=int, default=1, help="dump: the first file number")
    a = ap.parse_args(argv)
    render = a.render or environ.get("SFAB_RENDERDIR") or environ.get("SFAB_LABDIR") or os.getcwd()
    path = a.setup or os.path.join(render, "bootstrap", a.node, "setup.json")
    log = Log(a.node)
    try:
        setup = load_setup(path)
        if setup.get("node") != a.node:
            raise Usage(f"{path} is for {setup.get('node')}, not {a.node}")
        if a.step == "plan":
            for line in plan(setup):
                print(line)
            return 0
        if a.step == "dump" and not a.out:
            raise Usage("dump needs --out DIR")
    except Usage as e:
        print(f"truenas-setup: {e}", file=sys.stderr)
        return 2
    state = a.state or environ.get("SFAB_STATEDIR") or os.path.join(render, "state")
    docker = Docker(setup["lab"], log)
    steps = list(setup.get("steps") or STEPS) if a.step == "all" else ([] if a.step == "dump" else [a.step])
    host, port = setup["api"]["host"], int(setup["api"]["port"])
    if a.api:
        h, _, p = a.api.rpartition(":")
        host, port = (h or host), int(p)
    ctx = {"setup": setup, "log": log, "docker": docker, "S": None, "password": None}
    S = None
    step = a.step
    try:
        if a.step == "dump" or any(s in NEEDS_API for s in steps):
            pw, where = find_password(setup, docker, state, environ)
            remember(pw)
            ctx["password"] = pw
            log(f"password from {where}")
            S = Session(host, port, setup["api"]["path"], setup["api"]["user"], pw, log)
            ctx["S"] = S
        if a.step == "dump":
            S.open()
            n = dump(S, setup, a.out, a.first)
            log(f"dump: {n} of {len(DUMP_CALLS)} calls answered, in {a.out}")
            return 0
        for step in steps:
            if step not in STEP_FN:
                raise Usage(f"unknown step {step!r} in setup.json")
            log(f"== {step}")
            STEP_FN[step](ctx)
        log(f"truenas-setup {a.step}: done ({S.logins if S else 0} login(s))")
        return 0
    except tnrpc.LoginRefused as e:
        log(f"truenas-setup {a.step}: FAILED at {step}: TrueNAS refused {setup['api']['user']}'s password ({e.response_type})")
        return 5
    except Usage as e:
        log(f"truenas-setup {a.step}: {e}")
        return 2
    except (Failed, tnrpc.RPCError, OSError, TimeoutError, ValueError, KeyError) as e:
        log(f"truenas-setup {a.step}: FAILED at {step}: {e}")
        return 1
    finally:
        if S is not None:
            S.close()


if __name__ == "__main__":
    sys.exit(main())
