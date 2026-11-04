#!/usr/bin/env python3
"""Run commands on a vrnetlab VM through its serial console (container port 5000). usage: console.py <user> <pass> <cmd>...
A debugging aid that no lab script runs (README.md, The console helper). The login is on the command line,
so the host's process list shows it while this runs."""
import socket, sys, time
user, pw, cmds = sys.argv[1], sys.argv[2], sys.argv[3:]
s = socket.create_connection(("127.0.0.1", 5000), timeout=5)
def rd(t=2.0):
    s.settimeout(0.5); buf = b""; end = time.time() + t
    while time.time() < end:
        try:
            c = s.recv(65536)
            if c: buf += c; end = max(end, time.time() + 0.6)
        except socket.timeout: pass
    return buf.decode(errors="replace")
def send(x, t=2.0): s.sendall(x.encode() + b"\r"); return rd(t)
out = send("", 2)
if "login:" in out:
    send(user, 2); out = send(pw, 6)
for c in cmds:
    print(f"$ {c}"); print(send(c, 12))
send("exit", 1)
