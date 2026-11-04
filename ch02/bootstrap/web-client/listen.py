#!/usr/bin/env python3
# A plain TCP listener on 443: it accepts and closes, so a connect from anywhere the path allows
# opens (rendered by render/host.py from hosts.<n>.listen; nothing is served).
import socket, threading

def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(64)
    while True:
        c, _ = s.accept()
        c.close()

for p in [443]:
    threading.Thread(target=serve, args=(p,), daemon=False).start()
