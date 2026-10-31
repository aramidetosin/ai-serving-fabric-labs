"""tnrpc: a client for the TrueNAS middleware API, JSON-RPC 2.0 over a websocket.

TrueNAS serves its API at ws://<address>/api/current. The lab host has no websocket library to
rely on, so this module carries the small part of RFC 6455 a client needs: the upgrade handshake
(with the Sec-WebSocket-Accept check), masked text frames out, unmasked frames in (fragmented or
not), answering pings, and the close frame.

    c = Client("172.21.40.121")                  # port 80, path /api/current
    c.login("truenas_admin", password)           # auth.login_ex, PASSWORD_PLAIN
    c.call("pool.query", [["name", "=", "tank"]])
    c.job("service.control", "START", "nfs")     # a method that answers with a job id: wait for it
    c.logout(); c.close()

Every call names its parameters positionally, as the API takes them. A JSON-RPC error raises
RPCError, which keeps the method and the error object; errname is TrueNAS's own error name
(EBUSY, EINVAL, ...) when it gives one. Standard library only, Python 3.10 or later.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
import json
import os
import socket
import struct
import time

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONT, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA
JOB_DONE = ("SUCCESS", "FAILED", "ABORTED")


class RPCError(Exception):
    """The API answered a call with an error."""

    def __init__(self, method: str, error):
        self.method = method
        self.error = error
        super().__init__(f"{method}: {json.dumps(error, default=str)[:1000]}")

    @property
    def errname(self) -> str | None:
        e = self.error if isinstance(self.error, dict) else {}
        data = e.get("data") if isinstance(e.get("data"), dict) else {}
        return data.get("errname") or e.get("errname")


class LoginRefused(Exception):
    """auth.login_ex did not answer SUCCESS."""

    def __init__(self, response_type):
        self.response_type = response_type
        super().__init__(f"login refused: {response_type}")


def mask(data: bytes, key: bytes) -> bytes:
    """XOR data with the 4-byte key repeated (RFC 6455 section 5.3)."""
    n = len(data)
    if not n:
        return b""
    k = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(k, "big")).to_bytes(n, "big")


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()


def frame(opcode: int, payload: bytes, masked: bool = True, fin: bool = True, key: bytes | None = None) -> bytes:
    """One frame. Clients mask (RFC 6455 section 5.1); a server does not."""
    head = bytes([(0x80 if fin else 0) | opcode])
    n = len(payload)
    m = 0x80 if masked else 0
    if n < 126:
        head += bytes([m | n])
    elif n < 65536:
        head += bytes([m | 126]) + struct.pack("!H", n)
    else:
        head += bytes([m | 127]) + struct.pack("!Q", n)
    if not masked:
        return head + payload
    key = key or os.urandom(4)
    return head + key + mask(payload, key)


class WebSocket:
    def __init__(self, host: str, port: int, path: str, timeout: float = 20.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("connection closed during the websocket handshake")
            resp += chunk
            if len(resp) > 65536:
                raise ConnectionError("websocket handshake answer too long")
        head, _, self.buf = resp.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        if len(lines[0].split()) < 2 or lines[0].split()[1] != "101":
            self.sock.close()
            raise ConnectionError(f"websocket upgrade refused: {lines[0]}")
        fields = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
        if fields.get("sec-websocket-accept") != accept_key(key):
            self.sock.close()
            raise ConnectionError("websocket upgrade answered with the wrong Sec-WebSocket-Accept")

    def _exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self.buf += chunk
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def send(self, text: str) -> None:
        self.sock.sendall(frame(OP_TEXT, text.encode()))

    def recv(self, timeout: float | None = None) -> str:
        """The next whole message; pings are answered and pongs dropped on the way."""
        self.sock.settimeout(timeout)
        message = b""
        while True:
            b0, b1 = self._exact(2)
            op, n = b0 & 0x0F, b1 & 0x7F
            if n == 126:
                n = struct.unpack("!H", self._exact(2))[0]
            elif n == 127:
                n = struct.unpack("!Q", self._exact(8))[0]
            key = self._exact(4) if b1 & 0x80 else None
            payload = self._exact(n)
            if key:
                payload = mask(payload, key)
            if op == OP_CLOSE:
                raise ConnectionError("websocket closed by the peer")
            if op == OP_PING:
                self.sock.sendall(frame(OP_PONG, payload))
                continue
            if op == OP_PONG:
                continue
            message += payload
            if b0 & 0x80:
                return message.decode()

    def close(self) -> None:
        try:
            self.sock.sendall(frame(OP_CLOSE, b""))
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class Client:
    """JSON-RPC 2.0 over one websocket. notify(method, params) gets the server's notifications."""

    def __init__(self, host: str, port: int = 80, path: str = "/api/current", timeout: float = 20.0, notify=None):
        self.ws = WebSocket(host, port, path, timeout)
        self.ids = itertools.count(1)
        self.notify = notify
        self.job_poll_s = 2.0

    def call(self, method: str, params=None, timeout: float = 300.0):
        rid = next(self.ids)
        self.ws.send(json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": list(params or [])}))
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"{method}: no answer in {timeout:.0f} s")
            try:
                raw = self.ws.recv(timeout=left)
            except socket.timeout as e:
                raise TimeoutError(f"{method}: no answer in {timeout:.0f} s") from e
            msg = json.loads(raw)
            if msg.get("id") == rid:
                if "error" in msg and msg["error"] is not None:
                    raise RPCError(method, msg["error"])
                return msg.get("result")
            if "method" in msg and self.notify:
                self.notify(msg["method"], msg.get("params"))

    def job(self, method: str, params=None, timeout: float = 1800.0):
        """Call a method that answers with a job id, then wait for the job to end."""
        job_id = self.call(method, params)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            jobs = self.call("core.get_jobs", [[["id", "=", job_id]]])
            if jobs and jobs[0].get("state") in JOB_DONE:
                if jobs[0]["state"] != "SUCCESS":
                    raise RPCError(method, {"job": job_id, "state": jobs[0]["state"], "error": jobs[0].get("error")})
                return jobs[0].get("result")
            time.sleep(self.job_poll_s)
        raise TimeoutError(f"{method}: job {job_id} did not end in {timeout:.0f} s")

    def login(self, username: str, password: str, timeout: float = 30.0) -> None:
        r = self.call("auth.login_ex", [{"mechanism": "PASSWORD_PLAIN", "username": username, "password": password}],
                      timeout=timeout)
        rt = r.get("response_type") if isinstance(r, dict) else r
        if rt != "SUCCESS":
            raise LoginRefused(rt)

    def logout(self) -> None:
        try:
            self.call("auth.logout", timeout=10)
        except (OSError, TimeoutError, RPCError, ValueError):
            pass

    def close(self) -> None:
        self.ws.close()
