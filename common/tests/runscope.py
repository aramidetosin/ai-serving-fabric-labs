"""The commands a lab test runs, each in a session of its own, and the stand-ins they leave running.

A lab test runs a lab's script (audit.sh, trace.sh, drills.sh, a break or a stage) with the
stand-ins of common/tests/shims*/ first on PATH. A capture the script starts runs on in the
background until the script stops it, and the test then checks that none is left running. That
check once listed every matching process on the machine, so a test running in another checkout,
or another test of the same run in a parallel process, made it fail. Here each command starts in
a session of its own, whose process group is its own and is inherited by everything the script
starts in the background, and the check lists the matching processes in this test's groups only.

    scope = Scope(self)                       # in setUp; stops what is left when the test ends
    r = scope.run(argv, env=..., cwd=..., capture_output=True, text=True, timeout=900)
    self.assertEqual(scope.left("shims-ch04/_ch04.py", wait_s=10.0), [])
"""

from __future__ import annotations

import os
import signal
import subprocess
import time


class Scope:
    def __init__(self, test=None):
        self.groups: list[int] = []
        if test is not None:
            test.addCleanup(self.stop)

    def run(self, argv, *, timeout=None, input=None, capture_output=False, **kw) -> subprocess.CompletedProcess:
        """subprocess.run(argv, ...) with the command started in a session of its own."""
        if capture_output:
            kw["stdout"] = kw["stderr"] = subprocess.PIPE
        with subprocess.Popen(argv, start_new_session=True, stdin=subprocess.PIPE if input is not None else None, **kw) as p:
            self.groups.append(p.pid)
            try:
                out, err = p.communicate(input, timeout=timeout)
            except subprocess.TimeoutExpired:
                # as subprocess.run does: the command is killed, its background is left to the check
                p.kill()
                p.wait()
                raise
            except BaseException:
                p.kill()
                raise
        return subprocess.CompletedProcess(p.args, p.returncode, out, err)

    def left(self, pattern: str, wait_s: float = 0.0) -> list:
        """The processes in this test's groups whose command line matches pattern (pgrep -f), after
        waiting up to wait_s for any that are exiting (a capture stopped with SIGINT writes its
        file before it exits)."""
        t0 = time.monotonic()
        while True:
            pids = []
            if self.groups:
                r = subprocess.run(["pgrep", "-g", ",".join(map(str, self.groups)), "-f", pattern],
                                   capture_output=True, text=True)
                pids = r.stdout.split()
            if not pids or time.monotonic() - t0 > wait_s:
                return pids
            time.sleep(0.5)

    def stop(self) -> None:
        """Ask whatever is still running in this test's groups to stop (SIGTERM)."""
        if not self.groups:
            return
        r = subprocess.run(["pgrep", "-g", ",".join(map(str, self.groups))], capture_output=True, text=True)
        for pid in r.stdout.split():
            try:
                os.kill(int(pid), signal.SIGTERM)
            except (OSError, ValueError):
                pass
