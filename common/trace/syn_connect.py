#!/usr/bin/env python3
"""syn_connect.py ADDRESS PORT SPORT COUNT TIMEOUT_S INTERVAL_S: COUNT TCP connects from a client, each
from its own pinned source port (SPORT, SPORT+1, ...), so a capture or a traffic log line names each
one (chapter 1's walk refuses a node's port with one; break-1a's probe_syn sends a few).

It runs in a client container (python3, standard library only), fed on stdin through docker exec. It
sends nothing over a connection it opens and closes it at once. One line an attempt:

    <epoch the attempt started> <attempt from 0> <1 connected, else 0> <source port> <outcome> <seconds>

the outcome CONNECTED, TIMEOUT (no answer within TIMEOUT_S, as a silent drop leaves it), REFUSED (a
reset), or ERROR:<reason> (an ICMP unreachable reads as one). The client's view is recorded, not
assumed. Exit status 0 always: the caller judges the lines.
"""

import socket
import sys
import time


def attempt(address: str, port: int, sport: int, timeout: float):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.bind(("", sport))
        s.connect((address, port))
        out = "CONNECTED"
    except socket.timeout:
        out = "TIMEOUT"
    except ConnectionRefusedError:
        out = "REFUSED"
    except OSError as e:
        out = "ERROR:" + (e.strerror or type(e).__name__).replace(" ", "_")
    finally:
        s.close()
    return t0, out, time.time() - t0


def main(argv) -> int:
    address, port, sport, count, timeout, interval = argv[1], int(argv[2]), int(argv[3]), int(argv[4]), float(argv[5]), float(argv[6])
    for i in range(count):
        t0, out, took = attempt(address, port, sport + i, timeout)
        print(f"{t0:.6f} {i} {1 if out == 'CONNECTED' else 0} {sport + i} {out} {took:.3f}", flush=True)
        if i + 1 < count:
            time.sleep(interval)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
