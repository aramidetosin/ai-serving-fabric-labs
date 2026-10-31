#!/usr/bin/env python3
"""tick: read the lab host's kernel tick, or set it to 10000 (FRAMEWORK.md 3.1, pf_tick).

    tick.py [-v]          read it
    tick.py --set [-v]    set it to 10000 (root), then read it back

Calls adjtimex(2) through ctypes with modes 0, which reads and changes nothing, and prints
struct timex.tick (microseconds per kernel tick). Where the call is unavailable it falls back to
`adjtimex --print`. Exit status: 0 when the tick is 10000, 1 when it is anything else, 2 when it
cannot be read or set. With -v it also prints freq and status. Durations the labs record are
quotable only at 10000: at 9258, for example, CLOCK_MONOTONIC runs at 0.9258 of real time.

--set calls adjtimex(2) with ADJ_TICK and tick 10000 (or, where the call is unavailable,
`adjtimex --tick 10000`), which needs root (CAP_SYS_TIME). It changes the tick only, the rate of
the clock and not its time, and nothing under /etc, so a reboot leaves the tick at whatever the
host's boot sets; preflight reads it again before every run.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import re
import subprocess
import sys

WANT = 10000
ADJ_TICK = 0x4000  # <sys/timex.h>: modes bit that sets timex.tick


class Timex(ctypes.Structure):
    # struct timex from <sys/timex.h> on Linux (x86_64 and aarch64 share this layout)
    _fields_ = [
        ("modes", ctypes.c_uint), ("offset", ctypes.c_long), ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long), ("esterror", ctypes.c_long), ("status", ctypes.c_int),
        ("constant", ctypes.c_long), ("precision", ctypes.c_long), ("tolerance", ctypes.c_long),
        ("time_sec", ctypes.c_long), ("time_usec", ctypes.c_long), ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long), ("jitter", ctypes.c_long), ("shift", ctypes.c_int),
        ("stabil", ctypes.c_long), ("jitcnt", ctypes.c_long), ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long), ("stbcnt", ctypes.c_long), ("tai", ctypes.c_int),
        ("pad", ctypes.c_int * 11),
    ]


def _adjtimex():
    """libc's adjtimex(2), or None where there is none (not Linux, or no libc)."""
    if not sys.platform.startswith("linux"):
        return None
    name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        return ctypes.CDLL(name, use_errno=True).adjtimex
    except (OSError, AttributeError):
        return None


def read_adjtimex():
    fn = _adjtimex()
    if fn is None:
        return None
    t = Timex()
    t.modes = 0
    if fn(ctypes.byref(t)) < 0:
        return None
    return {"tick": int(t.tick), "freq": t.freq / 65536.0, "status": int(t.status)}


def set_adjtimex(tick: int):
    """Set timex.tick: None when adjtimex(2) is unavailable, "" when it took, else why not."""
    fn = _adjtimex()
    if fn is None:
        return None
    t = Timex()
    t.modes = ADJ_TICK
    t.tick = tick
    if fn(ctypes.byref(t)) < 0:
        e = ctypes.get_errno()
        return os.strerror(e) if e else "adjtimex(2) failed"
    return ""


def read_tool():
    try:
        p = subprocess.run(["adjtimex", "--print"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"^\s*tick:\s*(\d+)", p.stdout, re.M)
    if p.returncode != 0 or not m:
        return None
    f = re.search(r"^\s*frequency:\s*(-?\d+)", p.stdout, re.M)
    s = re.search(r"^\s*status:\s*(\d+)", p.stdout, re.M)
    return {"tick": int(m.group(1)), "freq": int(f.group(1)) / 65536.0 if f else 0.0,
            "status": int(s.group(1)) if s else 0}


def set_tool(tick: int):
    """`adjtimex --tick TICK`: None when the tool is missing, "" when it took, else why not."""
    try:
        p = subprocess.run(["adjtimex", "--tick", str(tick)], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return "" if p.returncode == 0 else ((p.stderr or p.stdout).strip() or f"exit status {p.returncode}")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--set" in argv:
        err = set_adjtimex(WANT)
        if err is None:
            err = set_tool(WANT)
        if err is None:
            print("tick: cannot set the kernel tick (no adjtimex(2) here, and no adjtimex tool)", file=sys.stderr)
            return 2
        if err:
            print(f"tick: cannot set the kernel tick to {WANT}: {err} (setting it needs root)", file=sys.stderr)
            return 2
    r = read_adjtimex() or read_tool()
    if r is None:
        print("tick: cannot read the kernel tick (no adjtimex(2) here, and no adjtimex tool)", file=sys.stderr)
        return 2
    print(r["tick"])
    if "-v" in argv:
        print(f"freq {r['freq']:.3f} ppm, status {r['status']:#06x}")
    return 0 if r["tick"] == WANT else 1


if __name__ == "__main__":
    sys.exit(main())
