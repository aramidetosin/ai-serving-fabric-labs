#!/usr/bin/env python3
"""probe_tcp.py: the drills' TCP connect loop, run in a client container (common/drill/lib-drill.sh).

    probe_tcp.py DST PORT SECONDS INTERVAL TIMEOUT LOG

One new connection every INTERVAL seconds, each from a fresh source port (so each is its own
flow, hashed onto a bundle leg on its own), with a TIMEOUT-second connect timeout, for SECONDS.
One line per attempt, written as it ends: start time (epoch seconds, the container's clock, which
is the lab host's), sequence number, 1 or 0 for connected, the local port, milliseconds taken.
The local port is what the drill's captures on the firewall's legs match the attempt by. The
method is a plain connect loop: a new port per attempt and a short timeout.
"""

import socket
import sys
import time


def main(argv) -> int:
    dst, port, secs, interval, timeout, log = argv[1], int(argv[2]), float(argv[3]), float(argv[4]), float(argv[5]), argv[6]
    end = time.time() + secs
    i = 0
    with open(log, "w", buffering=1) as out:
        while time.time() < end:
            t = time.time()
            s = socket.socket()
            s.settimeout(timeout)
            ok, lp = 0, 0
            try:
                s.connect((dst, port))
                ok = 1
            except OSError:
                pass
            try:
                lp = s.getsockname()[1]
            except OSError:
                pass
            ms = (time.time() - t) * 1000
            s.close()
            out.write(f"{t:.6f} {i} {ok} {lp} {ms:.1f}\n")
            i += 1
            rest = interval - (time.time() - t)
            if rest > 0:
                time.sleep(rest)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
