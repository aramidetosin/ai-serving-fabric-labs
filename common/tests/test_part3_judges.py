"""Part III's judges and readers on their own, from small made-up evidence (no lab, no render): the
DNS answer reader dig and dnsq.py share, the held connections' events and the firewall's session
reads, the API gateway's whitelists, the routers' tables, the traces' frame reader, the ladder's
forbidden tally and the NAT trace's one-leg rule, the lease drill's gap, Little's law in HOLD.md,
and the drill's isolation counts. Each failure case shows the judge refuses what it must.

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_part3_judges*.py'
"""

from __future__ import annotations

import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
for d in ("audit", "trace", "drill"):
    sys.path.insert(0, str(COMMON / d))

import p3drill  # noqa: E402
import p3trace  # noqa: E402
import tenancy as T  # noqa: E402
import vocab  # noqa: E402

DIG = """; <<>> DiG 9.18.49 <<>> @203.0.113.6 llm.ai.tarnwick.example A
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 31337
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
llm.ai.tarnwick.example. 300	IN	A	198.51.100.10

;; SERVER: 203.0.113.6#53(203.0.113.6) (UDP)
"""


def vio():
    buf = io.StringIO()
    return vocab.Vocab(verdict="", known=set(), out=buf), buf


class ReadersTest(unittest.TestCase):
    def test_dig_result(self):
        r = T.dig_result(DIG)
        self.assertEqual(r["status"], "NOERROR")
        self.assertEqual(r["flags"], ["qr", "aa"])
        self.assertEqual(r["answers"], [("llm.ai.tarnwick.example", "A", "198.51.100.10")])
        self.assertEqual(T.dig_result(";; connection timed out; no servers could be reached")["status"], "timeout")
        self.assertEqual(T.dig_result("")["status"], "none")

    def test_dnsq_prints_what_dig_result_reads(self):
        out = subprocess.run([sys.executable, str(COMMON / "trace" / "dnsq.py"), "127.0.0.1", "llm.ai.tarnwick.example", "A", "-", "1", "0.2"],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(T.dig_result(out.stdout)["status"], "timeout", out.stdout)
        import dnsq  # noqa: PLC0415

        qid, pkt = dnsq.query("llm.ai.tarnwick.example", 1, True)
        # a made-up answer: the query's header with qr ra and REFUSED, no record
        ans = (qid.to_bytes(2, "big") + (0x8185).to_bytes(2, "big") + pkt[4:6] + b"\0\0\0\0\0\0" + pkt[12:])
        d = dnsq.decode(ans)
        self.assertEqual((d["status"], d["answers"]), ("REFUSED", []))
        self.assertIn("ra", d["flags"])

    def test_hold_events_and_sessions(self):
        ev = [{"t": 1.0, "event": "open", "conn": 0, "sport": 44500}, {"t": 1.1, "event": "reply", "conn": 0, "k": 0, "status": 200},
              {"t": 1.2, "event": "held", "open": 1}, {"t": 2.0, "event": "reply", "conn": 0, "k": 1, "status": 502},
              {"t": 9.0, "event": "closed", "conn": 0}, {"t": 9.0, "event": "done", "open": 1, "replies": 2, "errors": 1}]
        s = T.hold_summary(ev)
        self.assertEqual((s["opened"], s["held"], s["non200"], s["rounds"], s["span_s"]), (1, 1, 1, 2, 8.0))
        self.assertEqual(T.session_count("\nNumber of sessions that match filter: 11\n"), 11)
        self.assertIsNone(T.session_count("No Active Sessions"))
        t = T.session_timeouts("  TCP default timeout:                           3600 secs\n"
                               "  TCP session timeout in TIME_WAIT:                15 secs\n")
        self.assertEqual(t, {"tcp": 3600, "tcp_time_wait": 15})

    def test_whitelists_ignore_consumer_groups(self):
        y = ("routes:\n- id: chat\n  plugins:\n    consumer-restriction:\n      whitelist:\n      - batch\n      - inetapp\n"
             "      rejected_code: 401\n- id: staff\n  plugins:\n    consumer-restriction:\n      whitelist:\n      - helpdesk\n"
             "consumer_groups:\n- id: staff\n  plugins: {}\n")
        self.assertEqual(T._apisix_whitelists(y), {"chat": ["batch", "inetapp"], "staff": ["helpdesk"]})

    def test_router_routes(self):
        rr = T.router_routes("C>* 198.51.100.8/30 is directly connected, eth1, 00:09:00\nS>* 10.20.11.0/24 [1/0] via 198.51.100.10, eth1\n")
        self.assertEqual([x["dest"] for x in rr], ["198.51.100.8/30", "10.20.11.0/24"])
        self.assertTrue(T.overlaps(rr[1]["dest"], "10.0.0.0/8"))
        self.assertFalse(T.overlaps(rr[0]["dest"], "10.0.0.0/8"))


def syn_line(t, src, sp, dst, dp, seq, vlan=None):
    eth = (f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan else
           "ethertype IPv4 (0x0800), length 74: ")
    return (f"{t:.6f} 0c:00:aa:bb:cc:02 > 02:00:00:00:00:02, {eth}(tos 0x0, ttl 63, id 9, offset 0, flags [DF], proto TCP (6), length 60)\n"
            f"    {src}.{sp} > {dst}.{dp}: Flags [S], cksum 0x1 (correct), seq {seq}, win 64240, length 0")


class FramesTest(unittest.TestCase):
    def test_packets_read_syns_and_dns(self):
        text = syn_line(1793000000.5, "203.0.113.2", 42936, "10.20.11.220", 443, 77, vlan=110) + "\n" + (
            "1793000000.600000 0c:00:aa:bb:cc:04 > 02:00:00:00:00:03, ethertype IPv4 (0x0800), length 90: (tos 0x0, ttl 64, id 77, offset 0, "
            "flags [none], proto UDP (17), length 76)\n    10.24.10.53.53 > 10.24.10.10.40000: [udp sum ok] 4242 q: A? llm.ai.tarnwick.example. "
            "1/0/0 llm.ai.tarnwick.example. [5m] A 10.20.11.210 (57)")
        pk = p3trace.packets(text)
        self.assertEqual((pk[0]["vlan"], pk[0]["seq"], pk[0]["dst"]), (110, 77, "10.20.11.220"))
        self.assertEqual(pk[1]["dns"]["a"], ["10.20.11.210"])
        self.assertFalse(pk[1]["dns"]["query"])
        self.assertEqual(len(p3trace.syns(pk, src="203.0.113.2", sport=range(42936, 42937))), 1)


class LadderTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="sfab-test-ladder-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        (self.d / "captures").mkdir()
        (self.d / "connects").mkdir()
        (self.d / "cluster").mkdir()
        (self.d / "pair").mkdir()
        self.plan = {"lab": "x", "vlan": 110, "pair": ["fe-sw1"], "ingress": [{"node": "k8s-ingress1", "mac": "02:5a:68:00:00:01"}],
                     "points": [{"id": "1-isp-rtr-eth1", "role": "router-uplink"}, {"id": "3-fw-ae1-leg1", "role": "leg"},
                                {"id": "4-fe-sw1-Ethernet13", "role": "pair-port"}, {"id": "5-k8s-ingress1-bond0.110", "role": "holder",
                                                                                     "node": "k8s-ingress1"}],
                     "flows": [{"id": "internet/gw-users", "client_addr": "203.0.113.2", "client": "inet-client", "gateway": "gw-users",
                                "lease": "kube-system/l-users", "sport": 44100, "tries": 3, "port": 443, "address": "10.20.11.210",
                                "allowed": False, "local": False, "mode": "silence", "may": [], "refused_at": "isp-rtr"}]}
        (self.d / "cluster" / "leases.json").write_text(json.dumps({"items": [{"metadata": {"name": "l-users"},
                                                                                "spec": {"holderIdentity": "k8s-ingress1"}}]}))
        (self.d / "pair" / "fe-sw1-mac.txt").write_text("110      02:5a:68:00:00:01   DYNAMIC       PortChannel14\n")
        (self.d / "connects" / "internet-gw-users.txt").write_text("1.0 0 0 44100 TIMEOUT 4.0\n1.1 1 0 44101 TIMEOUT 4.0\n")
        self.inv = {"nodes": {"fe-sw1": {"portchannels": {"PortChannel14": {"members": ["Ethernet13"]}}}}}

    def judge(self):
        v, buf = vio()
        p3trace.judge_ladder(v, self.d, self.plan, self.inv)
        return buf.getvalue()

    def test_zero_tally_passes(self):
        out = self.judge()
        self.assertIn("  PASS  every rung's forbidden tally is zero", out)
        self.assertIn("ports facing it by its MAC: 4-fe-sw1-Ethernet13", out)

    def test_a_leak_past_the_router_fails(self):
        (self.d / "captures" / "1-isp-rtr-eth1.txt").write_text(syn_line(1793000001.0, "203.0.113.2", 44100, "10.20.11.210", 443, 5) + "\n")
        out = self.judge()
        self.assertRegex(out, r"  FAIL  internet/gw-users: silence at isp-rtr .*past it: 1-isp-rtr-eth1 1")
        self.assertRegex(out, r"  FAIL  every rung's forbidden tally is zero .* -> 1-isp-rtr-eth1 1")


class NatOneLegTest(unittest.TestCase):
    def test_two_legs_fail(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-test-nat-"))
        self.addCleanup(shutil.rmtree, d, True)
        s = {"id": "internet", "client": "inet-client", "client_addr": "203.0.113.2", "dst_addr": "198.51.100.10", "translated_addr": "10.20.11.220",
             "sport": 42936, "entry": "1-isp-rtr-eth1", "legs": ["3-fw-ae1-leg1", "3-fw-ae1-leg2"], "vlan": 110,
             "points": ["1-isp-rtr-eth1", "3-fw-ae1-leg1", "3-fw-ae1-leg2"], "fqdn": "llm", "path": "/echo", "hold_s": 1, "msg": None,
             "expect": {"status": 200, "rule": "r", "nat_rule": "n", "from_zone": "isp", "to_zone": "ingress"}}
        cd = d / "captures" / "internet"
        cd.mkdir(parents=True)
        (cd / "1-isp-rtr-eth1.txt").write_text(syn_line(1793000001.0, "203.0.113.2", 42936, "198.51.100.10", 443, 9) + "\n")
        for leg in ("3-fw-ae1-leg1", "3-fw-ae1-leg2"):
            (cd / f"{leg}.txt").write_text(syn_line(1793000001.0, "203.0.113.2", 42936, "10.20.11.220", 443, 9, vlan=110) + "\n")
        v, buf = vio()
        p3trace.judge_nat(v, d, {"sessions": [s]})
        out = buf.getvalue()
        self.assertIn("  PASS  internet: the SYN at 1-isp-rtr-eth1", out)
        self.assertRegex(out, r"  FAIL  internet: the same SYN on exactly one leg \(3-fw-ae1-leg1, 3-fw-ae1-leg2\).* -> on 2 legs")


class LeaseGapTest(unittest.TestCase):
    def test_gap_and_lost(self):
        recs = [{"sent": t, "outcome": "answered" if t < 10 or t >= 14 else "failed"} for t in range(0, 20, 2)]
        g = p3drill.gap(recs, 10.5, lambda r: r["outcome"] == "answered", "sent")
        self.assertEqual((g["last_ok"], g["first_ok"], g["lost"], g["gap_s"]), (8, 14, 2, 6))

    def test_no_move_fails(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-test-lease-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "probes").mkdir()
        (d / "timeline.txt").write_text("100.0 CUT k8s-ingress2\n130.0 RESTORE k8s-ingress2\n")
        (d / "cut-node.txt").write_text("k8s-ingress2\n")
        doc = {"items": [{"metadata": {"name": "l-inet"}, "spec": {"holderIdentity": "k8s-ingress2"}}]}
        (d / "leases.jsonl").write_text("\n".join(json.dumps({"t0": t, "t1": t + 0.1, "doc": doc}) for t in (99, 101, 120)) + "\n")
        dr = {"id": "lease-holder-loss", "ingress": ["k8s-ingress1", "k8s-ingress2"], "leases": {"gw-inet": "kube-system/l-inet"},
              "echo": [], "vips": {"gw-inet": "10.20.11.220"}, "candidates": {}, "prediction": {}, "interval_s": 2}
        v, buf = vio()
        p3drill.analyze_lease(v, dr, d, "1")
        self.assertRegex(buf.getvalue(), r"  FAIL  pass 1 lease-holder-loss: gw-inet's lease, held by k8s-ingress2 at the cut, taken by nobody")


    def test_gap_from_both_ports_shut(self):
        # as chapter 8's first recordings showed: the pair ports are shut one switch after the other
        # between CUT and SHUT, so a request sent between them is still answered, and the request lost
        # comes after SHUT; timed from CUT the loss fell outside the gap and read 0 lost
        d = Path(tempfile.mkdtemp(prefix="sfab-test-lease-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "probes").mkdir()
        (d / "timeline.txt").write_text("100.0 CUT k8s-ingress2\n102.6 SHUT k8s-ingress2\n137.0 RESTORE k8s-ingress2\n")
        (d / "cut-node.txt").write_text("k8s-ingress2\n")
        held = {"items": [{"metadata": {"name": "l-users"}, "spec": {"holderIdentity": "k8s-ingress2"}}]}
        moved = {"items": [{"metadata": {"name": "l-users"}, "spec": {"holderIdentity": "k8s-ingress1"}}]}
        (d / "leases.jsonl").write_text("\n".join(json.dumps({"t0": t, "t1": t + 0.1, "doc": held if t < 106 else moved})
                                                  for t in (99, 101, 104, 106)) + "\n")
        recs = [{"sent": 98.7, "done": 98.75, "outcome": "answered"}, {"sent": 100.7, "done": 100.75, "outcome": "answered"},
                {"sent": 102.7, "done": 105.7, "outcome": "failed"}, {"sent": 104.7, "done": 105.77, "outcome": "answered"},
                {"sent": 106.7, "done": 106.75, "outcome": "answered"}]
        (d / "probes" / "echo-ent-client.jsonl").write_text("".join(json.dumps(r) + "\n" for r in recs))
        tcp = [(100.1 + 0.5 * i, "1" if not 102.5 < 100.1 + 0.5 * i < 104.5 else "0", 1.0 if i != 10 else 2.5) for i in range(20)]
        (d / "probes" / "tcp-ent-client.log").write_text("".join(f"{t:.6f} {i} {ok} 40000 {ms:.1f}\n" for i, (t, ok, ms) in enumerate(tcp)))
        dr = {"id": "lease-holder-loss", "ingress": ["k8s-ingress1", "k8s-ingress2"], "leases": {"gw-users": "kube-system/l-users"},
              "echo": [{"client": "ent-client", "gateway": "gw-users", "address": "10.20.11.210"}], "vips": {"gw-users": "10.20.11.210"},
              "candidates": {}, "prediction": {"min_ms": 2000, "max_ms": 4000}, "interval_s": 2, "connect_interval_s": 0.5}
        v, buf = vio()
        an = p3drill.analyze_lease(v, dr, d, "1")
        out = buf.getvalue()
        self.assertIn("taken by k8s-ingress1 within 3.5 s of both ports shut, 6.1 s of the cut's start", out)
        self.assertIn("ent-client through gw-users: 1 of 5 echo requests lost, the gap 4.0 s from the last request answered before both "
                      "ports were shut", out)
        self.assertIn("the slowest answer while cut 1.07 s", out)
        self.assertEqual(an["probes"]["ent-client"]["lost"], 1)
        self.assertEqual(an["connects"]["ent-client"]["lost"], 4)


class IsolationCountsTest(unittest.TestCase):
    def test_a_forbidden_try_through_fails(self):
        self.assertTrue(p3drill.through({"kind": "connect", "outcome": "CONNECTED"}))
        self.assertFalse(p3drill.through({"kind": "http", "outcome": "HTTP 404"}))
        self.assertTrue(p3drill.through({"kind": "http", "outcome": "HTTP 401"}), "past the route set to the API gateway")
        self.assertFalse(p3drill.through({"kind": "connect", "outcome": "TIMEOUT"}))


class HoldMdTest(unittest.TestCase):
    def test_little_without_a_rate(self):
        import holdrun  # noqa: PLC0415

        ev = [{"t": 0.0, "event": "open", "conn": 0}, {"t": 0.0, "event": "open", "conn": 1},
              {"t": 100.0, "event": "closed", "conn": 0}, {"t": 100.0, "event": "closed", "conn": 1}]
        lt = holdrun.little(ev, 100.0)
        self.assertEqual((lt["arrivals"], lt["window_s"], lt["mean_hold_s"], lt["predicted"]), (2, 100.0, 100.0, 2.0))
        self.assertNotIn("per_s", lt)


if __name__ == "__main__":
    unittest.main()
