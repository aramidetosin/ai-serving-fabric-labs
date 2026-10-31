#!/usr/bin/env python3
"""truenas-setup.py's NTP step: an NTP server TrueNAS cannot reach yet is tried again, and any
other refusal, or one that lasts past the tries, still fails the step.

    python3 -m unittest discover -s common/tests -t common/tests
"""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("truenas_setup", ROOT / "common/storage/truenas-setup.py")
ts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ts)

UNREACHED = 'ntpserver_create.address: Server could not be reached. Check "Force" to continue regardless.'


class FakeSession:
    def __init__(self, fails: int, reason: str = UNREACHED):
        self.fails, self.reason, self.created = fails, reason, []

    def call(self, method, *params):
        if method == "interface.has_pending_changes":
            return False
        if method == "network.configuration.config":
            return {"hostname": "truenas1", "domain": "d", "ipv4gateway": "10.20.2.1"}
        if method == "system.ntpserver.query":
            return []
        if method == "system.ntpserver.create":
            if self.fails:
                self.fails -= 1
                raise RuntimeError(self.reason)
            self.created.append(params[0]["address"])
            return {}
        raise AssertionError(method)


class NtpRetry(unittest.TestCase):
    def setUp(self):
        self.saved = (ts.Timing.ntp_tries, ts.Timing.ntp_pause_s)
        ts.Timing.ntp_tries, ts.Timing.ntp_pause_s = 3, 0.0
        self.lines = []

    def tearDown(self):
        ts.Timing.ntp_tries, ts.Timing.ntp_pause_s = self.saved

    def run_step(self, S):
        ctx = {"S": S, "setup": {"hostname": "truenas1", "domain": "d"}, "log": self.lines.append}
        net = {"routes": [], "gateway": "10.20.2.1", "ntp": ["10.20.13.21"]}
        ts.finish_network(ctx, net, {}, [])

    def test_unreached_then_saved(self):
        S = FakeSession(fails=2)
        self.run_step(S)
        self.assertEqual(S.created, ["10.20.13.21"])
        self.assertEqual(sum("not reached yet" in x for x in self.lines), 2)

    def test_unreached_past_the_tries_fails(self):
        with self.assertRaises(RuntimeError):
            self.run_step(FakeSession(fails=3))

    def test_other_refusal_fails_at_once(self):
        S = FakeSession(fails=1, reason="address: Invalid IP")
        with self.assertRaises(RuntimeError):
            self.run_step(S)
        self.assertFalse(any("not reached yet" in x for x in self.lines))


if __name__ == "__main__":
    unittest.main()
