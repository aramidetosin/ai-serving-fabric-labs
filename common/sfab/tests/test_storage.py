"""Storage tests: render/storage.py (bootstrap/<node>/setup.json and the democratic-csi values),
common/storage/tnrpc.py (the websocket JSON-RPC client) and common/storage/truenas-setup.py run
against an in-process stand-in for the TrueNAS API, with a docker stand-in first on PATH.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_storage -v

Nothing here reaches a real device or the network: the API stand-in listens on 127.0.0.1, and
docker, ssh and sshpass resolve to stand-ins (standins.check proves it before each script run).
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import re
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sfab.tests import standins

ROOT = Path(__file__).resolve().parents[3]
STORAGE_DIR = ROOT / "common" / "storage"
DASHES = ("\u2014", "\u2013")
# Stand-in values: a made-up TrueNAS password, never a real credential
PASSWORD = "Pw0rdForTheTestOnly7"

M2 = {"lab": "sfab-m2", "profile": "a", "state": "one",
      "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2", "k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion",
                          "inet-registry", "uplink-rtr", "ops-client", "ent-client", "truenas1"]},
      "features": {"k8s": True, "serving": False, "storage_setup": True}}
NO_K8S = {"lab": "sfab-ch03", "profile": "a", "state": "one",
          "slice": {"nodes": ["fe", "fw", "truenas1"]},
          "features": {"k8s": False, "serving": False, "storage_setup": False}}
M1 = {"lab": "sfab-m1", "profile": "a", "state": "one",
      "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2"]},
      "features": {"k8s": False, "serving": False, "storage_setup": False}}

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_SPEC = None


def spec():
    global _SPEC
    if _SPEC is None:
        from sfab.spec import load

        _SPEC = load(ROOT)
    return _SPEC


def model(chapter):
    from sfab.spec import select

    return select(spec(), chapter)


def ctx():
    from sfab.render import Context

    return Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-storage", labdir=ROOT / "dev" / "m2", root=ROOT, spec=spec())


def render(chapter) -> dict:
    from sfab.render import storage

    return storage.render(model(chapter), ctx())


def load_script(name: str, path: Path):
    s = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    return mod


def load_setup_module():
    sys.path.insert(0, str(STORAGE_DIR))
    mod = load_script("truenas_setup", STORAGE_DIR / "truenas-setup.py")
    t = mod.Timing
    t.health_wait_s, t.health_poll_s, t.login_gap_s, t.busy_pause_s = 2.0, 0.01, 0.0, 0.0
    t.connect_timeout_s, t.call_timeout_s, t.job_timeout_s, t.job_poll_s = 5.0, 10.0, 10.0, 0.01
    t.checkin_tries, t.checkin_pause_s, t.after_drop_s, t.login_tries, t.docker_timeout_s = 5, 0.01, 0.01, 5, 30.0
    return mod


# --------------------------------------------------------------------------------------------
# render/storage.py


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = render(M2)
        cls.setup = json.loads(cls.out["bootstrap/truenas1/setup.json"])

    def test_paths(self):
        self.assertEqual(sorted(self.out), ["bootstrap/k8s/60-democratic-csi-nfs.yaml", "bootstrap/k8s/60-democratic-csi-nvmeof.yaml",
                                            "bootstrap/truenas1/setup.json"])

    def test_m1_has_no_storage(self):
        self.assertEqual(render(M1), {})

    def test_without_kubernetes_only_the_setup(self):
        out = render(NO_K8S)
        self.assertEqual(sorted(out), ["bootstrap/truenas1/setup.json"])
        s = json.loads(out["bootstrap/truenas1/setup.json"])
        self.assertNotIn("kubernetes", s["csi"])

    def test_byte_stable_and_sorted(self):
        again = render(M2)
        self.assertEqual(again, self.out)
        text = self.out["bootstrap/truenas1/setup.json"]
        self.assertEqual(json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n", text)
        for k, v in self.out.items():
            self.assertTrue(v.endswith("\n") and "\r" not in v, k)

    def test_addresses_from_the_plan(self):
        s = self.setup
        n = s["network"]
        self.assertEqual(s["api"]["host"], "172.21.40.121")
        self.assertEqual((s["api"]["port"], s["api"]["path"], s["api"]["user"]), (80, "/api/current", "truenas_admin"))
        self.assertEqual(n["bond"]["address"], "10.20.12.31/24", "storage data on its own VLAN, 120")
        self.assertEqual((n["bond"]["vlan"], n["bond"]["mtu"], n["bond"]["lacpdu_rate"], n["bond"]["xmit_hash_policy"]),
                         (120, 9000, "FAST", "LAYER3+4"))
        self.assertEqual(n["mgmt"]["address"], "10.20.2.31/24")
        self.assertEqual((n["mgmt"]["name"], n["mgmt"]["vlan"], n["mgmt"]["mtu"], n["mgmt"]["lacpdu_rate"]), ("bond1", 200, 1500, "FAST"))
        self.assertEqual(n["gateway"], "10.20.2.1")
        self.assertEqual(n["nameservers"], ["10.20.13.21", "10.20.14.21"], "the two resolvers")
        self.assertEqual(n["ntp"], ["10.20.13.21", "10.20.14.21"])
        self.assertEqual((s["container"], s["lab"], s["hostname"], s["domain"]), ("sfab-m2-truenas1", "sfab-m2", "truenas1", "ai.tarnwick.example"))

    def test_bond_members_by_mac_on_the_pair(self):
        b = self.setup["network"]["bond"]
        self.assertEqual([(m["eth"], m["match"], m["peer"]) for m in b["members"]],
                         [("eth1", "mac", "fe-sw1:eth10"), ("eth2", "mac", "fe-sw1:eth11"),
                          ("eth3", "mac", "fe-sw2:eth10"), ("eth4", "mac", "fe-sw2:eth11")])
        m = self.setup["network"]["mgmt"]
        # the management bond: one leg on each switch, so no TrueNAS port is an orphan
        self.assertEqual([(x["eth"], x["match"], x["peer"]) for x in m["members"]],
                         [("eth5", "mac", "fe-sw1:eth12"), ("eth6", "mac", "fe-sw2:eth12")])

    def test_management_return_route_first(self):
        r = self.setup["network"]["routes"]
        self.assertTrue(r[0]["first"])
        self.assertEqual((r[0]["dest"], r[0]["via"], r[0]["gateway"]), ("172.21.40.0/24", "qemu-user", "10.0.0.2"))
        self.assertEqual(self.setup["network"]["qemu_user"], {"prefix": "10.0.0.0/24", "gateway": "10.0.0.2", "address": "10.0.0.15/24"})
        self.assertEqual(self.setup["steps"], ["wait", "network", "services", "users", "csi", "ui"])
        self.assertEqual(self.setup["ui"], {"addresses": ["10.20.2.31", "10.0.0.15"]},
                         "the API answers on storage management and the harness's user-mode NIC, never on the data address")

    def test_commit_with_rollback_and_checkin(self):
        c = self.setup["network"]["commit"]
        self.assertTrue(c["rollback"])
        self.assertGreater(c["checkin_timeout_s"], c["call_timeout_s"])

    def test_services_and_datasets(self):
        s = self.setup
        self.assertEqual(s["pool"], "tank")
        self.assertEqual(s["datasets"], ["tank/k8s", "tank/k8s/nvmeof", "tank/k8s/nvmeof-snaps", "tank/k8s/nfs", "tank/k8s/nfs-snaps"])
        self.assertEqual(s["services"]["nfs"], {"bindip": ["10.20.12.31"], "protocols": ["NFSV3", "NFSV4"]})
        self.assertEqual(s["services"]["nvmet"]["ports"], [{"traddr": "10.20.12.31", "trsvcid": 4420, "trtype": "TCP"}])

    def test_csi_api_on_the_management_address(self):
        c = self.setup["csi"]
        self.assertEqual((c["api"], c["api_address"], c["default_class"]), ("mgmt", "10.20.2.31", "nvmeof"))
        self.assertEqual([u["username"] for u in c["users"]], ["democratic-csi"])
        self.assertTrue(c["users"][0]["administrator"])
        self.assertEqual([k["name"] for k in c["classes"]], ["nvmeof", "nfs"])
        nv, nf = (k["driver_config"] for k in c["classes"])
        self.assertEqual(nv["driver"], "freenas-api-nvmeof")
        self.assertEqual((nv["httpConnection"]["protocol"], nv["httpConnection"]["host"], nv["httpConnection"]["port"]),
                         ("https", "10.20.2.31", 443), "the API over HTTPS on storage management, through the firewall")
        self.assertEqual(nv["httpConnection"]["username"], "democratic-csi")
        self.assertEqual(nv["nvmeof"]["transports"], ["tcp://10.20.12.31:4420"], "the data on the storage VLAN")
        self.assertEqual(nv["zfs"]["datasetParentName"], "tank/k8s/nvmeof")
        self.assertEqual(nf["driver"], "freenas-api-nfs")
        self.assertEqual(nf["nfs"]["shareHost"], "10.20.12.31")
        self.assertEqual(nf["nfs"]["shareAllowedNetworks"], ["10.20.12.0/24"])
        self.assertEqual(c["kubernetes"], {"kubectl": ["common/bin/sfab-kubectl", "dev/m2"], "namespace": "democratic-csi",
                                           "secret_labels": {"decision.tarnwick.example/id": "dec-storage-data-address"}})
        self.assertEqual(c["runtime_fields"], ["httpConnection.password", "nvmeof.ports"])
        for k in c["classes"]:
            self.assertNotIn("password", k["driver_config"]["httpConnection"])

    def test_no_secret_and_plain_prose(self):
        for path, text in self.out.items():
            for d in DASHES:
                self.assertNotIn(d, text, path)
            self.assertNotIn(PASSWORD, text)
            self.assertNotRegex(text, r'"password"\s*:', path)
            self.assertNotRegex(text, r"(?m)^\s*password:", path)

    def test_values_files(self):
        from sfab.render import storage

        pins = spec().versions["kubernetes"]["democratic_csi"]
        for cls, default in (("nvmeof", True), ("nfs", False)):
            text = self.out[f"bootstrap/k8s/60-democratic-csi-{cls}.yaml"]
            self.assertTrue(text.startswith("# sfab-m2 democratic-csi release truenas-" + cls))
            self.assertIn(f"existingConfigSecret: truenas-{cls}-driver-config", text)
            self.assertIn(f"driver: freenas-api-{cls}", text)
            self.assertIn(f"defaultClass: {'true' if default else 'false'}", text)
            for key, img in pins["images"].items():
                if img.get("used") is False:
                    self.assertNotIn(img["digest"], text, key)
                else:
                    self.assertIn(img["digest"], text, key)
            v = storage.values(model(M2), model(M2).node("truenas1"), cls)
            # the cleanup sidecar runs the driver image: nothing from Docker Hub, whose images the
            # registry seed copies for one platform only
            self.assertEqual(v["node"]["cleanup"]["image"], v["node"]["driver"]["image"])
            self.assertNotIn("docker.io", text)
            self.assertEqual(v["controller"]["externalSnapshotter"], {"enabled": False})
            self.assertEqual(v["node"]["tolerations"], [{"operator": "Exists"}])
            self.assertTrue(v["node"]["hostPID"])

    @unittest.skipUnless(HAVE_YAML, "PyYAML is not installed")
    def test_values_parse_as_written(self):
        from sfab.render import storage

        m = model(M2)
        for cls in ("nvmeof", "nfs"):
            parsed = yaml.safe_load(self.out[f"bootstrap/k8s/60-democratic-csi-{cls}.yaml"])
            self.assertEqual(parsed, storage.values(m, m.node("truenas1"), cls))
            self.assertEqual(parsed["controller"]["driver"]["image"]["tag"].split("@")[0], "next")

    def test_yaml_scalars(self):
        from sfab.render import storage

        tricky = {"a": "false", "b": "0777", "c": "10.20.1.31", "d": None, "e": True, "f": 4420, "g": "next@sha256:ab",
                  "h": "", "i": [], "j": {}, "k": [{"x": 1, "y": [1, 2]}, "s"], "l": "a: b", "m": "yes"}
        text = "\n".join(storage.to_yaml(tricky)) + "\n"
        if HAVE_YAML:
            self.assertEqual(yaml.safe_load(text), tricky)
        self.assertIn('a: "false"', text)
        self.assertIn('b: "0777"', text)

    def test_releases_for_k8s(self):
        from sfab.render import storage

        rel = storage.csi_releases(model(M2))
        self.assertEqual([(r["release"], r["namespace"], r["values"], r["default"]) for r in rel],
                         [("truenas-nvmeof", "democratic-csi", "60-democratic-csi-nvmeof.yaml", True),
                          ("truenas-nfs", "democratic-csi", "60-democratic-csi-nfs.yaml", False)])
        self.assertEqual({r["chart"] for r in rel}, {"democratic-csi"})
        self.assertEqual({r["version"] for r in rel}, {str(spec().versions["kubernetes"]["democratic_csi"]["chart"]["version"])})
        self.assertEqual(storage.csi_releases(model(NO_K8S)), [])
        self.assertEqual(storage.csi_releases(model(M1)), [])

    def test_missing_pins_refused(self):
        from sfab.render import RenderError, storage

        m = model(M2)
        k8s = dict(m.meta.versions["kubernetes"])
        k8s["democratic_csi"] = {"chart": None, "status": "open"}
        meta = dataclasses.replace(m.meta, versions={**m.meta.versions, "kubernetes": k8s})
        m2 = dataclasses.replace(m, meta=meta)
        with self.assertRaises(RenderError):
            storage.render(m2, ctx())


# --------------------------------------------------------------------------------------------
# a stand-in for the TrueNAS middleware API


def _ws_frame(op: int, payload: bytes, fin: bool = True) -> bytes:
    sys.path.insert(0, str(STORAGE_DIR))
    import tnrpc

    return tnrpc.frame(op, payload, masked=False, fin=fin)


class FakeTrueNAS:
    """Enough of the middleware API for truenas-setup.py, with the system's state in memory."""

    QEMU_MAC = "0c:00:12:34:56:00"

    def __init__(self, macs: dict, password: str = PASSWORD, drop_commits: int = 1, rollback_on_drop: bool = False):
        self.lock = threading.Lock()
        self.password = password
        self.calls: list = []        # (connection id, method, params)
        self.logins: list = []
        self.active: dict = {}       # connection id -> user
        self.max_sessions = 0
        self.drop_commits = drop_commits
        # True: a commit that drops the session is rolled back before the client is back, as
        # TrueNAS does when the check-in comes too late
        self.rollback_on_drop = rollback_on_drop
        self.jobs: dict = {}
        self.next_id = 100
        nics = {"enp1s1": (self.QEMU_MAC, True, [{"type": "INET", "address": "10.0.0.15", "netmask": 24}])}
        for i, eth in enumerate(sorted(macs), start=2):
            nics[f"enp1s{i}"] = (macs[eth], False, [])
        self.running = {n: {"name": n, "type": "PHYSICAL", "ipv4_dhcp": dhcp, "aliases": [], "mtu": None,
                            "state": {"link_address": mac, "permanent_link_address": mac, "aliases": st}}
                        for n, (mac, dhcp, st) in nics.items()}
        self.candidate = json.loads(json.dumps(self.running))
        self.checkin_waiting = None
        self.routes: list = []
        self.netconf = {"hostname": "truenas1", "domain": "local", "ipv4gateway": "", "nameserver1": ""}
        self.ntp = [{"id": 1, "address": "0.debian.pool.ntp.org"}]
        self.general = {"ui_address": ["0.0.0.0"], "ui_httpsport": 443}
        self.ui_restarts = 0
        self.pools = [{"name": "tank", "status": "ONLINE"}]
        self.datasets: list = [{"id": "tank"}]
        self.nfs = {"protocols": ["NFSV3", "NFSV4"], "bindip": []}
        self.services = {s: {"service": s, "enable": False, "state": "STOPPED"} for s in ("nfs", "nvmet", "ssh", "cifs")}
        self.ports: list = []
        self.groups = [{"id": 41, "name": "builtin_administrators"}]
        self.users = [{"id": 1, "username": "truenas_admin", "builtin": False}]
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.server.shutdown()
        self.server.server_close()

    def methods(self) -> list:
        return [m for _, m, _ in self.calls]

    # -- the API

    @staticmethod
    def _match(item: dict, filters: list) -> bool:
        for f in filters or []:
            k, op, v = f
            if op == "=" and item.get(k) != v:
                return False
        return True

    def _new_id(self) -> int:
        self.next_id += 1
        return self.next_id

    def dispatch(self, conn: int, method: str, params: list):
        p = params
        if method == "auth.login_ex":
            self.logins.append(time.monotonic())
            ok = p[0].get("password") == self.password and p[0].get("username") in {u["username"] for u in self.users}
            if ok:
                self.active[conn] = p[0]["username"]
                self.max_sessions = max(self.max_sessions, list(self.active.values()).count(p[0]["username"]))
            return {"response_type": "SUCCESS" if ok else "AUTH_ERR"}
        if conn not in self.active:
            raise PermissionError("not authenticated")
        if method == "auth.logout":
            self.active.pop(conn, None)
            return True
        if method == "core.get_jobs":
            jid = p[0][0][2]
            return [self.jobs[jid]] if jid in self.jobs else []
        if method == "staticroute.query":
            return [r for r in self.routes if self._match(r, p[0] if p else [])]
        if method == "staticroute.create":
            r = dict(p[0], id=self._new_id())
            self.routes.append(r)
            return r
        if method == "interface.query":
            return list(json.loads(json.dumps(self.candidate)).values())
        if method == "interface.create":
            d = p[0]
            rows = getattr(self, "rows", None)
            if rows is None:
                rows = self.rows = {n for n, i in self.candidate.items() if i.get("ipv4_dhcp") or i.get("aliases")}
            for m in d.get("lag_ports") or []:
                if m in rows:
                    # TrueNAS refuses a bond over a port that has a configuration row of its own
                    import tnrpc
                    raise tnrpc.RPCError(method, {"message": f"Interface {m} is currently in use"})
            self.candidate[d["name"]] = {"name": d["name"], "type": d["type"], "ipv4_dhcp": False, "aliases": d["aliases"],
                                         "mtu": d.get("mtu"), "lag_ports": d["lag_ports"], "state": {"aliases": []}}
            return self.candidate[d["name"]]
        if method == "interface.delete":
            name = p[0]
            if getattr(self, "rows", None) is None:
                self.rows = {n for n, i in self.candidate.items() if i.get("ipv4_dhcp") or i.get("aliases")}
            self.rows.discard(name)
            self.candidate[name].update({"ipv4_dhcp": False, "aliases": []})
            return name
        if method == "interface.update":
            name, d = p
            if getattr(self, "rows", None) is None:
                self.rows = {n for n, i in self.candidate.items() if i.get("ipv4_dhcp") or i.get("aliases")}
            self.rows.add(name)
            self.candidate[name].update(d)
            return self.candidate[name]
        if method == "interface.has_pending_changes":
            return self.candidate != self.running
        if method == "interface.commit":
            before = self.running
            self.running = json.loads(json.dumps(self.candidate))
            self.checkin_waiting = p[0]["checkin_timeout"] if p[0].get("rollback") else None
            if self.drop_commits > 0:
                self.drop_commits -= 1
                if self.rollback_on_drop:
                    self.running, self.checkin_waiting = before, None
                    self.candidate = json.loads(json.dumps(before))
                raise ConnectionAbortedError("the commit re-addressed this session's path")
            return None
        if method == "interface.checkin":
            if self.checkin_waiting is None:
                raise ValueError("no check-in pending")
            self.checkin_waiting = None
            return None
        if method == "interface.checkin_waiting":
            return self.checkin_waiting
        if method == "interface.rollback":
            self.candidate = json.loads(json.dumps(self.running))
            return None
        if method == "network.configuration.config":
            return dict(self.netconf)
        if method == "network.configuration.update":
            self.netconf.update(p[0])
            return dict(self.netconf)
        if method == "system.general.config":
            return dict(self.general)
        if method == "system.general.update":
            self.general.update(p[0])
            return dict(self.general)
        if method == "system.general.ui_restart":
            self.ui_restarts += 1
            return None
        if method == "system.ntpserver.query":
            return [n for n in self.ntp if self._match(n, p[0] if p else [])]
        if method == "system.ntpserver.create":
            self.ntp.append(dict(p[0], id=self._new_id()))
            return self.ntp[-1]
        if method == "pool.query":
            return [x for x in self.pools if self._match(x, p[0] if p else [])]
        if method == "pool.dataset.query":
            return [x for x in self.datasets if self._match(x, p[0] if p else [])]
        if method == "pool.dataset.create":
            parent = p[0]["name"].rsplit("/", 1)[0]
            if not any(d["id"] == parent for d in self.datasets):
                raise ValueError(f"parent {parent} does not exist")
            self.datasets.append({"id": p[0]["name"]})
            return self.datasets[-1]
        if method == "nfs.config":
            return dict(self.nfs)
        if method == "nfs.update":
            self.nfs.update(p[0])
            return dict(self.nfs)
        if method == "service.query":
            return [s for s in self.services.values() if self._match(s, p[0] if p else [])]
        if method == "service.update":
            self.services[p[0]].update(p[1])
            return True
        if method == "service.control":
            verb, svc = p[0], p[1]
            self.services[svc]["state"] = "RUNNING" if verb == "START" else "STOPPED"
            jid = self._new_id()
            self.jobs[jid] = {"id": jid, "state": "SUCCESS", "result": True}
            return jid
        if method == "nvmet.port.query":
            return [x for x in self.ports if self._match(x, p[0] if p else [])]
        if method == "nvmet.port.create":
            self.ports.append({"id": len(self.ports) + 1, "addr_trtype": p[0]["addr_trtype"], "addr_traddr": p[0]["addr_traddr"],
                               "addr_trsvcid": str(p[0]["addr_trsvcid"])})
            return self.ports[-1]
        if method == "group.query":
            return [g for g in self.groups if self._match(g, p[0] if p else [])]
        if method == "user.query":
            return [u for u in self.users if self._match(u, p[0] if p else [])]
        if method == "user.create":
            u = {k: v for k, v in p[0].items() if k != "password"}
            u["id"] = self._new_id()
            u["password_ok"] = p[0].get("password") == self.password
            self.users.append(u)
            return u
        if method in ("system.info", "network.general.summary", "sharing.nfs.query", "nvmet.subsys.query",
                      "nvmet.namespace.query", "audit.query"):
            return {} if method in ("system.info", "network.general.summary") else []
        raise LookupError(method)

    def _handler(self):
        fake = self

        class H(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                conn = id(self)
                buf = b""
                while b"\r\n\r\n" not in buf:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                head, _, rest = buf.partition(b"\r\n\r\n")
                key = re.search(rb"(?im)^sec-websocket-key:\s*(\S+)", head).group(1).decode()
                acc = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
                sock.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                              f"Sec-WebSocket-Accept: {acc}\r\n\r\n").encode())
                self.buf = rest
                try:
                    while True:
                        op, payload = self.read_frame(sock)
                        if op == 0x8:
                            return
                        if op != 0x1:
                            continue
                        msg = json.loads(payload)
                        with fake.lock:
                            fake.calls.append((conn, msg["method"], msg.get("params") or []))
                            try:
                                result, error = fake.dispatch(conn, msg["method"], msg.get("params") or []), None
                            except ConnectionAbortedError:
                                fake.active.pop(conn, None)
                                return
                            except LookupError as e:
                                result, error = None, {"code": -32601, "message": f"Method not found: {e}"}
                            except (ValueError, PermissionError, KeyError, IndexError) as e:
                                result, error = None, {"code": -32001, "message": str(e), "data": {"errname": "EINVAL"}}
                        body = json.dumps({"jsonrpc": "2.0", "id": msg["id"], **({"error": error} if error else {"result": result})}).encode()
                        # a ping first, and big answers in two fragments, as a real server may send them
                        sock.sendall(_ws_frame(0x9, b"hi"))
                        if len(body) > 200:
                            sock.sendall(_ws_frame(0x1, body[:100], fin=False) + _ws_frame(0x0, body[100:]))
                        else:
                            sock.sendall(_ws_frame(0x1, body))
                except (ConnectionError, OSError):
                    return
                finally:
                    with fake.lock:
                        fake.active.pop(conn, None)

            def read_frame(self, sock):
                def exact(n):
                    while len(self.buf) < n:
                        chunk = sock.recv(65536)
                        if not chunk:
                            raise ConnectionError("closed")
                        self.buf += chunk
                    d, self.buf = self.buf[:n], self.buf[n:]
                    return d

                b0, b1 = exact(2)
                if not b1 & 0x80:
                    raise ConnectionError("a client frame must be masked")
                n = b1 & 0x7F
                if n == 126:
                    n = struct.unpack("!H", exact(2))[0]
                elif n == 127:
                    n = struct.unpack("!Q", exact(8))[0]
                k = exact(4)
                data = bytes(c ^ k[i % 4] for i, c in enumerate(exact(n)))
                return b0 & 0x0F, data

        return H


# --------------------------------------------------------------------------------------------
# a docker stand-in: containers from a JSON file, every call logged


FAKE_DOCKER = r'''#!{python}
import json, os, sys
state = json.load(open(os.environ["FAKE_DOCKER_STATE"]))
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\n")
a = sys.argv[1:]
cs = state["containers"]
if a[:1] == ["inspect"]:
    fmt, name = a[2], a[3]
    if name not in cs:
        print("Error: No such object: " + name, file=sys.stderr); sys.exit(1)
    what = fmt.split(".")[1].split("}")[0]
    print(json.dumps(cs[name][what])); sys.exit(0)
if a[:1] == ["exec"]:
    rest = a[1:]
    if rest[0] == "-i":
        rest = rest[1:]
    name, argv = rest[0], rest[1:]
    if name not in cs:
        print("Error: No such container: " + name, file=sys.stderr); sys.exit(1)
    if argv[:1] == ["cat"]:
        eth = argv[1].split("/")[4]
        print(cs[name]["macs"][eth]); sys.exit(0)
    if argv[:2] == ["kubectl", "apply"]:
        doc = json.loads(sys.stdin.read())
        with open(os.environ["FAKE_DOCKER_STDIN"], "a") as f:
            f.write(json.dumps(doc) + "\n")
        for it in doc["items"]:
            print(it["kind"].lower() + "/" + it["metadata"]["name"] + " serverside-applied")
        sys.exit(0)
print("stand-in docker: unexpected " + " ".join(a), file=sys.stderr)
sys.exit(1)
'''

# the harness's kubectl (common/bin/sfab-kubectl LABDIR ARGS) stand-in: an apply's manifest logged
FAKE_KUBECTL = r'''#!{python}
import json, os, sys
a = sys.argv[2:]
if a[:1] == ["apply"]:
    doc = json.loads(sys.stdin.read())
    with open(os.environ["FAKE_DOCKER_STDIN"], "a") as f:
        f.write(json.dumps(doc) + "\n")
    for it in doc["items"]:
        print(it["kind"].lower() + "/" + it["metadata"]["name"] + " serverside-applied")
    sys.exit(0)
print("stand-in kubectl: unexpected " + " ".join(a), file=sys.stderr)
sys.exit(1)
'''

MACS = {"eth1": "aa:c1:ab:00:00:01", "eth2": "aa:c1:ab:00:00:02", "eth3": "aa:c1:ab:00:00:03",
        "eth4": "aa:c1:ab:00:00:04", "eth5": "aa:c1:ab:00:00:05", "eth6": "aa:c1:ab:00:00:06"}


class Rig:
    """A temporary render directory holding M2's setup.json, the docker stand-in and its state."""

    def __init__(self, tmp: Path, health="healthy", cmd_password=PASSWORD, env_password=None, secrets_password=None):
        tmp.mkdir(parents=True, exist_ok=True)
        self.tmp = tmp
        self.render = tmp / "lab"
        (self.render / "bootstrap" / "truenas1").mkdir(parents=True)
        (self.render / "bootstrap" / "truenas1" / "setup.json").write_text(render(M2)["bootstrap/truenas1/setup.json"])
        self.state = self.render / "state"
        self.state.mkdir()
        if secrets_password:
            (self.state / "secrets.env").write_text(f"SFAB_TRUENAS_PASSWORD={secrets_password}\n")
        cmd = ["--username", "truenas_admin"] + (["--password", cmd_password] if cmd_password else []) + ["--hostname", "truenas1"]
        env = ["TRUENAS_POOL=tank"] + ([f"PASSWORD={env_password}"] if env_password else [])
        self.docker_state = tmp / "docker.json"
        self.docker_log = tmp / "docker.log"
        self.stdin_log = tmp / "kubectl-stdin.log"
        self.docker_state.write_text(json.dumps({"containers": {
            "sfab-m2-truenas1": {"Config": {"Cmd": cmd, "Env": env}, "State": {"Running": True, "Status": "running", "Health": {"Status": health}},
                                 "macs": MACS},
            "sfab-m2-bastion": {"Config": {"Cmd": [], "Env": []}, "State": {"Running": True}, "macs": {}},
            "other-lab-bastion": {"Config": {}, "State": {"Running": True}, "macs": {}}}}))
        self.bin = standins.make_bin(tmp / "bin", {"docker": FAKE_DOCKER.replace("{python}", sys.executable),
                                                   "sfab-kubectl": FAKE_KUBECTL.replace("{python}", sys.executable)})
        p = self.render / "bootstrap" / "truenas1" / "setup.json"
        s = json.loads(p.read_text())
        s["csi"]["kubernetes"]["kubectl"] = [str(self.bin / "sfab-kubectl"), str(self.render)]
        p.write_text(json.dumps(s))
        self.env = {"PATH": standins.path_with(self.bin), "FAKE_DOCKER_STATE": str(self.docker_state),
                    "FAKE_DOCKER_LOG": str(self.docker_log), "FAKE_DOCKER_STDIN": str(self.stdin_log)}

    def docker_calls(self) -> list:
        if not self.docker_log.exists():
            return []
        return [json.loads(x) for x in self.docker_log.read_text().splitlines()]

    def applied(self) -> list:
        if not self.stdin_log.exists():
            return []
        return [json.loads(x) for x in self.stdin_log.read_text().splitlines()]


class TestTnrpc(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(STORAGE_DIR))
        import tnrpc

        self.tnrpc = tnrpc

    def test_mask_round_trip(self):
        key = b"\x01\x02\x03\x04"
        for n in (0, 1, 3, 4, 5, 125, 126, 70000):
            data = os.urandom(n)
            self.assertEqual(self.tnrpc.mask(self.tnrpc.mask(data, key), key), data)
            self.assertEqual(self.tnrpc.mask(data, key), bytes(c ^ key[i % 4] for i, c in enumerate(data)))

    def test_frame_lengths(self):
        for n, hl in ((10, 2), (300, 4), (70000, 10)):
            f = self.tnrpc.frame(0x1, b"x" * n, masked=False)
            self.assertEqual(len(f), hl + n)
            self.assertEqual(f[0], 0x81)

    def test_accept_key(self):
        # RFC 6455 section 1.3's own example
        self.assertEqual(self.tnrpc.accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

    def test_calls_jobs_errors_and_login(self):
        with FakeTrueNAS(MACS) as fake:
            c = self.tnrpc.Client("127.0.0.1", fake.port, timeout=5)
            with self.assertRaises(self.tnrpc.LoginRefused):
                c.login("truenas_admin", "wrong")
            c.login("truenas_admin", PASSWORD)
            ifs = c.call("interface.query")          # a fragmented answer after a ping
            self.assertEqual(len(ifs), 7)
            c.job_poll_s = 0.01
            self.assertTrue(c.job("service.control", ["START", "nfs"]))
            with self.assertRaises(self.tnrpc.RPCError) as e:
                c.call("no.such.method")
            self.assertEqual(e.exception.error["code"], -32601)
            with self.assertRaises(self.tnrpc.RPCError) as e:
                c.call("pool.dataset.create", [{"name": "tank/a/b"}])
            self.assertEqual(e.exception.errname, "EINVAL")
            c.logout()
            c.close()


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestSetup(unittest.TestCase):
    def setUp(self):
        self.ts = load_setup_module()
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()
        self.ts._SECRETS.clear()

    def run_setup(self, rig: Rig, fake: FakeTrueNAS | None, *argv, extra_env=None):
        env = dict(rig.env, **(extra_env or {}))
        standins.check(dict(os.environ, **env), rig.bin)
        args = list(argv) + ["--render", str(rig.render)]
        if fake is not None:
            args += ["--api", f"127.0.0.1:{fake.port}"]
        out = io.StringIO()
        clean = {k: v for k, v in os.environ.items() if k not in ("SFAB_TRUENAS_PASSWORD", "SFAB_RENDERDIR", "SFAB_STATEDIR", "SFAB_LABDIR")}
        err = io.StringIO()
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = self.ts.main(args, environ=dict(os.environ))
        return rc, out.getvalue() + err.getvalue()

    def test_all_then_again(self):
        rig = Rig(self.tmp)
        with FakeTrueNAS(MACS) as fake:
            rc, out = self.run_setup(rig, fake, "all")
            self.assertEqual(rc, 0, out)
            self.assertNotIn(PASSWORD, out)
            m = fake.methods()
            # the return route before any interface change, the commit before its check-in
            self.assertLess(m.index("staticroute.create"), m.index("interface.create"))
            self.assertLess(m.index("interface.create"), m.index("interface.commit"))
            self.assertLess(m.index("interface.commit"), m.index("interface.checkin"))
            self.assertLess(m.index("interface.checkin"), m.index("network.configuration.update"))
            self.assertEqual(fake.routes[0]["destination"], "172.21.40.0/24")
            self.assertEqual(fake.routes[0]["gateway"], "10.0.0.2")
            bond = fake.running["bond0"]
            self.assertEqual(bond["lag_ports"], ["enp1s2", "enp1s3", "enp1s4", "enp1s5"])
            self.assertEqual(bond["aliases"], [{"type": "INET", "address": "10.20.12.31", "netmask": 24}])
            self.assertEqual(bond["mtu"], 9000)
            mg = fake.running["bond1"]
            self.assertEqual((mg["lag_ports"], mg["aliases"], mg["mtu"]),
                             (["enp1s6", "enp1s7"], [{"type": "INET", "address": "10.20.2.31", "netmask": 24}], 1500))
            self.assertEqual(fake.running["enp1s6"]["aliases"], [], "a bond member holds no address of its own")
            self.assertEqual(fake.general["ui_address"], ["10.0.0.15", "10.20.2.31"])
            self.assertEqual(fake.ui_restarts, 1)
            self.assertEqual((fake.running["enp1s1"]["ipv4_dhcp"], fake.running["enp1s1"]["aliases"]),
                             (False, [{"type": "INET", "address": "10.0.0.15", "netmask": 24}]))
            self.assertIsNone(fake.checkin_waiting)
            self.assertEqual(fake.netconf["ipv4gateway"], "10.20.2.1")
            self.assertEqual((fake.netconf["nameserver1"], fake.netconf["nameserver2"]), ("10.20.13.21", "10.20.14.21"))
            self.assertEqual(fake.netconf["domain"], "ai.tarnwick.example")
            self.assertEqual(sorted(n["address"] for n in fake.ntp if n["address"].startswith("10.20.1")), ["10.20.13.21", "10.20.14.21"])
            self.assertEqual([d["id"] for d in fake.datasets],
                             ["tank", "tank/k8s", "tank/k8s/nvmeof", "tank/k8s/nvmeof-snaps", "tank/k8s/nfs", "tank/k8s/nfs-snaps"])
            self.assertEqual(fake.nfs["bindip"], ["10.20.12.31"])
            self.assertEqual([(p["addr_traddr"], p["addr_trsvcid"]) for p in fake.ports], [("10.20.12.31", "4420")])
            for s in ("nfs", "nvmet"):
                self.assertEqual((fake.services[s]["enable"], fake.services[s]["state"]), (True, "RUNNING"))
            u = next(u for u in fake.users if u["username"] == "democratic-csi")
            self.assertEqual(u["groups"], [41])
            self.assertTrue(u["password_ok"])
            # one session at a time; one login, one after the dropped commit, one after the web server's
            # restart; logged out at the end
            self.assertEqual(fake.max_sessions, 1)
            self.assertEqual(len(fake.logins), 3)
            self.assertEqual(fake.active, {})
            self.assertEqual(m[-1], "auth.logout")

            applied = rig.applied()
            self.assertEqual(len(applied), 1)
            items = applied[0]["items"]
            self.assertEqual([(i["kind"], i["metadata"]["name"]) for i in items],
                             [("Namespace", "democratic-csi"), ("Secret", "truenas-nvmeof-driver-config"), ("Secret", "truenas-nfs-driver-config")])
            nv = json.loads(base64.b64decode(items[1]["data"]["driver-config-file.yaml"]))
            self.assertEqual(nv["httpConnection"]["password"], PASSWORD)
            self.assertEqual(nv["httpConnection"]["host"], "10.20.2.31")
            self.assertEqual(nv["nvmeof"]["ports"], [1])
            nf = json.loads(base64.b64decode(items[2]["data"]["driver-config-file.yaml"]))
            self.assertNotIn("ports", nf.get("nfs", {}))
            self.assertEqual(items[1]["metadata"]["labels"], {"decision.tarnwick.example/id": "dec-storage-data-address"})
            for argv in rig.docker_calls():
                self.assertNotIn(PASSWORD, " ".join(argv))
                name = next(x for x in argv[1:] if not x.startswith("-") and x not in ("{{json .Config}}", "{{json .State}}"))
                self.assertTrue(name.startswith("sfab-m2-"), argv)

            # a second run changes nothing
            before = len(fake.calls)
            rc, out = self.run_setup(rig, fake, "all")
            self.assertEqual(rc, 0, out)
            again = [c[1] for c in fake.calls[before:]]
            for verb in ("create", "update", "commit", "checkin", "service.control"):
                self.assertFalse([x for x in again if verb in x], (verb, again))
            self.assertEqual(len(rig.applied()), 2)

    def test_plan_touches_nothing(self):
        rig = Rig(self.tmp)
        rc, out = self.run_setup(rig, None, "plan")
        self.assertEqual(rc, 0)
        self.assertIn("route 172.21.40.0/24 via 10.0.0.2 (first)", out)
        self.assertIn("bond0 LACP FAST LAYER3+4 MTU 9000 over eth1, eth2, eth3, eth4 (by MAC), 10.20.12.31/24", out)
        self.assertIn("bond1 LACP FAST LAYER3+4 MTU 1500 over eth5, eth6 (by MAC), 10.20.2.31/24", out)
        self.assertIn(f"csi: Secrets truenas-nvmeof-driver-config, truenas-nfs-driver-config in democratic-csi through {rig.bin / 'sfab-kubectl'} {rig.render}", out)
        self.assertEqual(rig.docker_calls(), [])

    def test_wrong_password_exits_5(self):
        rig = Rig(self.tmp, cmd_password="NotTheRightOne1")
        with FakeTrueNAS(MACS) as fake:
            rc, out = self.run_setup(rig, fake, "network")
        self.assertEqual(rc, 5, out)
        self.assertNotIn("NotTheRightOne1", out)

    def test_password_order(self):
        docker = self.ts.Docker("sfab-m2", self.ts.Log("truenas1", io.StringIO()))
        setup = json.loads(render(M2)["bootstrap/truenas1/setup.json"])
        rig = Rig(self.tmp, cmd_password=None, env_password="FromTheEnvOfTheBox1", secrets_password="FromSecretsEnv1")
        with mock.patch.dict(os.environ, rig.env):
            self.assertEqual(self.ts.find_password(setup, docker, str(rig.state), {"SFAB_TRUENAS_PASSWORD": "Override1"})[0], "Override1")
            self.assertEqual(self.ts.find_password(setup, docker, str(rig.state), {})[0], "FromTheEnvOfTheBox1")
        rig2 = Rig(self.tmp / "b", cmd_password="FromTheLauncher1", env_password="FromTheEnvOfTheBox1")
        with mock.patch.dict(os.environ, rig2.env):
            self.assertEqual(self.ts.find_password(setup, docker, str(rig2.state), {})[0], "FromTheLauncher1")
        rig3 = Rig(self.tmp / "c", cmd_password=None, secrets_password="FromSecretsEnv1")
        with mock.patch.dict(os.environ, rig3.env):
            self.assertEqual(self.ts.find_password(setup, docker, str(rig3.state), {})[0], "FromSecretsEnv1")
        self.assertEqual(self.ts.launcher_credentials({"Cmd": ["--username=a", "--password=b"], "Env": []}), ("a", "b"))

    def test_refuses_other_containers(self):
        docker = self.ts.Docker("sfab-m2", self.ts.Log("truenas1", io.StringIO()))
        for name in ("other-lab-bastion", "sfab-m20-x", "-sfab-m2-x", ""):
            with self.assertRaises(self.ts.Failed):
                docker.own(name)
        rig = Rig(self.tmp)
        p = rig.render / "bootstrap" / "truenas1" / "setup.json"
        s = json.loads(p.read_text())
        s["container"] = "other-lab-truenas1"
        p.write_text(json.dumps(s))
        rc, _ = self.run_setup(rig, None, "plan")
        self.assertEqual(rc, 2)
        s["container"] = "sfab-m2-truenas1"
        # the harness's kubectl is a program, never a container named in setup.json
        with self.assertRaisesRegex(self.ts.Failed, "is not there"):
            self.ts.run_kubectl([str(self.tmp / "no-such-kubectl"), str(rig.render)], ["apply", "-f", "-"], "{}")
        with mock.patch.dict(os.environ, rig.env):
            out = self.ts.run_kubectl([str(rig.bin / "sfab-kubectl"), str(rig.render)], ["apply", "-f", "-"], '{"items": []}')
        self.assertEqual(out, "")
        self.assertEqual(rig.applied(), [{"items": []}])

    def test_waits_for_health(self):
        rig = Rig(self.tmp, health="starting")
        self.ts.Timing.health_wait_s = 0.05
        rc, out = self.run_setup(rig, None, "wait")
        self.assertEqual(rc, 1)
        self.assertIn("not healthy", out.splitlines()[-1])

    def test_missing_member_fails_before_any_change(self):
        rig = Rig(self.tmp)
        macs = dict(MACS, eth3="aa:c1:ab:00:00:99")
        with FakeTrueNAS(macs) as fake:
            rc, out = self.run_setup(rig, fake, "network")
        self.assertEqual(rc, 1)
        self.assertIn("eth3", out.splitlines()[-1])
        self.assertNotIn("interface.commit", fake.methods())

    def test_dump(self):
        rig = Rig(self.tmp)
        with FakeTrueNAS(MACS) as fake:
            rc, out = self.run_setup(rig, fake, "dump", "--out", str(self.tmp / "dump"))
        self.assertEqual(rc, 0, out)
        files = sorted(os.listdir(self.tmp / "dump"))
        self.assertEqual(len(files), len(self.ts.DUMP_CALLS))
        self.assertTrue(files[0].startswith("01_system.info"))
        self.assertTrue((self.tmp / "dump" / files[0]).read_text().startswith("truenas1 api> system.info"))
        audit = [p for _, m, p in fake.calls if m == "audit.query"]
        self.assertEqual(audit[0][0]["query-filters"], [["username", "=", "democratic-csi"]])
        # one session for the whole dump, logged out at the end
        self.assertEqual(len(fake.logins), 1)
        self.assertEqual(fake.methods()[-1], "auth.logout")

    def test_rolled_back_commit_fails(self):
        rig = Rig(self.tmp)
        with FakeTrueNAS(MACS, rollback_on_drop=True) as fake:
            rc, out = self.run_setup(rig, fake, "network")
        self.assertEqual(rc, 1, out)
        self.assertIn("not as rendered", out.splitlines()[-1])
        self.assertIn("no bond0", out.splitlines()[-1])
        # nothing past the network step's commit ran: no gateway moved to the firewall
        self.assertNotIn("network.configuration.update", fake.methods())

    def test_bond_members_set_again(self):
        rig = Rig(self.tmp)
        with FakeTrueNAS(MACS, drop_commits=0) as fake:
            rc, out = self.run_setup(rig, fake, "network")
            self.assertEqual(rc, 0, out)
            # the bond as a stale configuration left it: one member is the wrong NIC
            for state in (fake.running, fake.candidate):
                state["bond0"]["lag_ports"] = ["enp1s2", "enp1s3", "enp1s4", "enp1s7"]
            before = len(fake.calls)
            rc, out = self.run_setup(rig, fake, "network")
            self.assertEqual(rc, 0, out)
            again = fake.calls[before:]
            upd = [p for _, m, p in again if m == "interface.update" and p[0] == "bond0"]
            self.assertEqual(upd, [["bond0", {"lag_ports": ["enp1s2", "enp1s3", "enp1s4", "enp1s5"]}]])
            m = [x for _, x, _ in again]
            self.assertLess(m.index("interface.commit"), m.index("interface.checkin_waiting"))
            self.assertLess(m.index("interface.checkin_waiting"), m.index("interface.checkin"))
            self.assertEqual(fake.running["bond0"]["lag_ports"], ["enp1s2", "enp1s3", "enp1s4", "enp1s5"])
            self.assertIsNone(fake.checkin_waiting)

    def test_network_drift(self):
        net = json.loads(render(M2)["bootstrap/truenas1/setup.json"])["network"]
        names = {"eth1": "a", "eth2": "b", "eth3": "c", "eth4": "d", "eth5": "m", "eth6": "n", "qemu_user": "q"}
        good = [{"name": "bond0", "aliases": [{"type": "INET", "address": "10.20.12.31", "netmask": 24}], "mtu": 9000,
                 "lag_ports": ["a", "b", "c", "d"]},
                {"name": "bond1", "aliases": [{"type": "INET", "address": "10.20.2.31", "netmask": 24}], "mtu": 1500,
                 "lag_ports": ["m", "n"]},
                {"name": "q", "ipv4_dhcp": False, "aliases": [{"type": "INET", "address": "10.0.0.15", "netmask": 24}]}]
        self.assertEqual(self.ts.network_drift(net, good, names), [])
        bad = json.loads(json.dumps(good))
        bad[0]["mtu"], bad[1]["mtu"], bad[2]["ipv4_dhcp"] = 1500, 9000, True
        drift = self.ts.network_drift(net, bad, names)
        self.assertEqual(len(drift), 3, drift)
        self.assertEqual(self.ts.network_drift(net, good[1:], names), ["no bond0"])
        # a member not found by MAC is not judged; the rest still is
        self.assertEqual(self.ts.network_drift(net, good, dict(names, eth3=None)), [])

    def test_cli_usage(self):
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
        r = subprocess.run([sys.executable, str(STORAGE_DIR / "truenas-setup.py"), "plan", "--render", str(self.tmp)],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(r.returncode, 2)
        self.assertIn("make render", r.stderr)

    def test_plain_prose(self):
        for p in (STORAGE_DIR / "truenas-setup.py", STORAGE_DIR / "tnrpc.py", ROOT / "common" / "sfab" / "render" / "storage.py"):
            text = p.read_text(encoding="utf-8")
            for d in DASHES:
                self.assertNotIn(d, text, p)


if __name__ == "__main__":
    unittest.main()
