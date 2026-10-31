"""Chapter 3's lab harness (ch03/): the pair checks the audit adds, the four-point trace's judgment,
the drill harness (placement, the fault, the restore, the reboot's monitor, the analysis, the passes
compared) and break-3a with its heal. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_ch03*.py'

Hermetic: ch03 is rendered into a temporary directory (PyYAML) and every device is a stand-in
(common/tests/shims/, shims-m2/, shims-ch03/, m2_world.py). The drills' stand-in world is a simple
deterministic model (shims-ch03/_ch03.py), so the figures asserted here are the model's, never the
lab's. Fixtures use the book's own addressing plan and made-up names only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
HERE = Path(__file__).resolve().parent
SHIMS, SHIMS_M2, SHIMS_CH03 = HERE / "shims", HERE / "shims-m2", HERE / "shims-ch03"
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(COMMON / "drill"))
sys.path.insert(0, str(HERE))

import analyze_ping as AP  # noqa: E402
import judge  # noqa: E402
import runscope  # noqa: E402
import vocab  # noqa: E402

CH03_NODES = ("fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw fw truenas1 k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2 bastion uplink-rtr "
              "ops-client inet-registry ent-client")
TMD = COMMON / "trace" / "trace-md.py"
DRILL = COMMON / "drill" / "drill.py"


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


_RENDER = None


def ch03_render() -> Path:
    """ch03 rendered once into a temporary directory (its inventory carries every service block)."""
    global _RENDER
    if _RENDER is None:
        out = Path(tempfile.mkdtemp(prefix="sfab-test-ch03-"))
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(ROOT / "ch03"), "--out", str(out), "-q"],
                       check=True, capture_output=True)
        _RENDER = out
    return _RENDER


def tearDownModule():
    if _RENDER is not None:
        shutil.rmtree(_RENDER, ignore_errors=True)


def inv() -> dict:
    return json.loads((ROOT / "ch03" / "gen" / "inventory.json").read_text())


# --------------------------------------------------------------------------------------------
# the audit's chapter 3 groups, on saved files


def mclag_brief(role, src, peer):
    return "\n".join([f"Domain ID            : 1", f"Role                 : {role}", "Session Status       : up",
                      "Peer Link Status     : up", f"Source Address       : {src}", f"Peer Address         : {peer}",
                      "Session Vrf          : VrfMclagKa", "Peer Link            : PortChannel1", "Mclag System Mac     : 02:5a:00:00:00:01"])


class PairChecksTest(unittest.TestCase):
    """judge.py pair-roles and bond-legs on saved files in the formats the lab printed."""

    def setUp(self):
        self.rs = Path(tempfile.mkdtemp(prefix="sfab-test-ch03rs-"))
        self.addCleanup(shutil.rmtree, self.rs, True)
        self.inv = inv()
        sys.path.insert(0, str(SHIMS))
        os.environ.setdefault("SHIM_INV", str(ROOT / "ch03" / "gen" / "inventory.json"))
        os.environ.setdefault("SHIM_LOG", os.devnull)
        import _devices
        self.dev = _devices

    def save(self, node, slug, text):
        d = self.rs / node
        d.mkdir(exist_ok=True)
        n = len(list(d.iterdir())) + 1
        (d / f"{n:02d}_{slug}.txt").write_text(f"{node}# x\n{text}\n" if slug == "mclag_brief" else text + "\n")

    def healthy(self, roles=("active", "standby")):
        for sw, role in zip(("fe-sw1", "fe-sw2"), roles):
            mc = self.inv["nodes"][sw]["mclag"]
            self.save(sw, "mclag_brief", mclag_brief(role, mc["source_ip"], mc["peer_ip"]))
            self.save(sw, "iccp_session", self.dev.switch_shell(sw, "sudo ss -tanp | grep 8888"))
            self.save(sw, "iccp_state", self.dev.switch_shell(sw, "docker exec iccpd mclagdctl -i 1 dump state"))
            self.save(sw, "portchannel_summary", self.dev.pc_summary(sw))
        for g in ("k8s-gpu1", "k8s-cp2", "bastion"):
            self.save(g, "bonding", self.dev.bonding(self.inv["nodes"][g]["bond"]["mac"] or "0c:00:aa:bb:cc:02"))
        self.save("fw", "lacp", "admin@fw> show lacp aggregate-ethernet all\n" + self.dev.panos_lacp("fw"))

    def run_judge(self, group, nodes):
        import io
        buf = io.StringIO()
        v = vocab.Vocab(verdict="", known=set(self.inv["known"]), out=buf)
        j = judge.Judge(judge.ResultSet(self.rs), self.inv, ROOT / "ch03", v)
        getattr(j, judge.GROUPS[group])(nodes)
        return buf.getvalue(), v.counts()

    def test_green(self):
        self.healthy()
        out, c = self.run_judge("pair-roles", ["fe-sw1", "fe-sw2"])
        self.assertEqual(c["fail"], 0, out)
        for line in ("  PASS  fe-sw1 is active: its keepalive source 10.20.255.0 is the lower of the two",
                     "  PASS  fe-sw2 is standby: its keepalive source 10.20.255.1 is the higher",
                     "  PASS  fe-sw1: ICCP session established on TCP 8888 in VRF VrfMclagKa, 10.20.255.0 to 10.20.255.1 (iccpd)",
                     "  PASS  fe-sw2: ICCP session established on TCP 8888 in VRF VrfMclagKa, 10.20.255.1 to 10.20.255.0 (iccpd)",
                     "  PASS  fe-sw2: iccpd listens on TCP 8888 in VRF VrfMclagKa", "  PASS  fe-sw1: iccpd reports the keepalive OK"):
            self.assertIn(line, out)
        out, c = self.run_judge("bond-legs", ["k8s-gpu1", "k8s-cp2", "bastion", "fw", "truenas1"])
        self.assertEqual((c["fail"], c["skip"]), (0, 1), out)
        self.assertIn("  PASS  k8s-gpu1 bond0: 2 of 2 legs in aggregator 1, each with partner 02:5a:00:00:00:01, aggregating: "
                      "eth1 (partner state 63), eth2 (partner state 63)", out)
        self.assertIn("  PASS  k8s-gpu1 bond0: fast LACP both ways on every leg (short timeout in the actor and partner state)", out)
        self.assertIn("  PASS  fw ae1: 2 of 2 legs selected under partner 02:5a:00:00:00:01, fast both ways: "
                      "ethernet1/1 (state 0x3F, partner 0x3F), ethernet1/2 (state 0x3F, partner 0x3F)", out)
        self.assertIn("  PASS  truenas1: its bonds' PortChannels up with every member selected on both switches "
                      "(fe-sw1 PortChannel31 Ethernet9,Ethernet10; fe-sw1 PortChannel32 Ethernet11; "
                      "fe-sw2 PortChannel31 Ethernet9,Ethernet10; fe-sw2 PortChannel32 Ethernet11)", out)
        self.assertIn("  SKIP  truenas1: each leg's partner MAC from the appliance's own side (its LACP state is not collected)", out)

    def test_roles_swapped_and_no_session(self):
        self.healthy(roles=("standby", "active"))
        for p in (self.rs / "fe-sw2").iterdir():
            if "iccp_session" in p.name:
                p.write_text("LISTEN    0      20    0.0.0.0:8888       0.0.0.0:*     users:((\"iccpd\",pid=4601,fd=16))\n")
        out, c = self.run_judge("pair-roles", ["fe-sw1", "fe-sw2"])
        self.assertIn("  FAIL  fe-sw1 is active: its keepalive source 10.20.255.0 is the lower of the two -> want active, got standby", out)
        self.assertIn("  FAIL  fe-sw2: ICCP session established on TCP 8888 in VRF VrfMclagKa, 10.20.255.1 to 10.20.255.0", out)
        self.assertIn("  FAIL  fe-sw2: iccpd listens on TCP 8888 in VRF VrfMclagKa -> 0.0.0.0%default", out)

    def test_a_leg_with_another_partner_or_slow_lacp(self):
        self.healthy()
        t = self.dev.bonding("02:5a:6f:00:00:01")
        bad_leg = t.replace("Slave Interface: eth2", "Slave Interface: eth2", 1)
        i = bad_leg.index("Slave Interface: eth2")
        bad_leg = bad_leg[:i] + bad_leg[i:].replace("system mac address: 02:5a:00:00:00:01", "system mac address: 0c:00:12:34:56:06", 1)
        for p in (self.rs / "k8s-gpu1").iterdir():
            p.write_text(bad_leg)
        for p in (self.rs / "k8s-cp2").iterdir():
            p.write_text(self.dev.bonding("02:5a:66:00:00:01", state=61))
        out, c = self.run_judge("bond-legs", ["k8s-gpu1", "k8s-cp2"])
        self.assertIn("FAIL  k8s-gpu1 bond0: 2 of 2 legs in aggregator 1", out)
        self.assertIn("eth2 partner 0c:00:12:34:56:06", out)
        self.assertIn("  FAIL  k8s-cp2 bond0: fast LACP both ways on every leg (short timeout in the actor and partner state) -> eth1 actor", out)

    def test_parsers(self):
        b = judge.p_bond_legs(self.dev.bonding("02:5a:6f:00:00:01", agg={"eth2": 2}))
        self.assertEqual((b["active_agg"], b["ports"], b["legs"]["eth1"]["partner_mac"], b["legs"]["eth2"]["agg"]), (1, 1, "02:5a:00:00:00:01", 2))
        self.assertEqual(b["legs"]["eth1"]["actor_mac"], "02:5a:6f:00:00:01")
        g = judge.p_panos_lacp(self.dev.panos_lacp("fw"))["ae1"]
        self.assertEqual((g["partner_mac"], g["members"]["ethernet1/2"]["partner_state"], g["members"]["ethernet1/1"]["selected"]),
                         ("02:5a:00:00:00:01", 0x3F, True))
        rows = judge.p_iccp(self.dev.switch_shell("fe-sw1", "sudo ss -tanp | grep 8888"))
        self.assertEqual([(r["state"], r["local"], r["local_vrf"], r["peer_port"]) for r in rows],
                         [("LISTEN", "0.0.0.0", "VrfMclagKa", "*"), ("ESTAB", "10.20.255.0", "VrfMclagKa", "8888")])


# --------------------------------------------------------------------------------------------
# the four-point trace


def syn_line(t, src_mac, dst_mac, vlan, ttl=63, ipid=2585, seq=1520102513, dst_ip="10.20.1.210", sport=41443):
    eth = (f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan
           else "ethertype IPv4 (0x0800), length 74: ")
    return (f"2026-10-20 10:00:01.{t:06d} {src_mac} > {dst_mac}, {eth}(tos 0x0, ttl {ttl}, id {ipid}, offset 0, flags [DF], proto TCP (6), length 60)\n"
            f"    10.24.10.10.{sport} > {dst_ip}.443: Flags [S], cksum 0x1a2b (correct), seq {seq}, win 64240, length 0\n")


class FourPointTraceTest(unittest.TestCase):
    """common/trace/trace-md.py on the four points of ch03's trace block."""

    FW, HOLDER = "0c:00:aa:bb:cc:f0", "02:5a:68:00:00:01"

    def setUp(self):
        self.rs = Path(tempfile.mkdtemp(prefix="sfab-test-ch03tr-"))
        self.addCleanup(shutil.rmtree, self.rs, True)
        (self.rs / "captures").mkdir()
        self.inv = ROOT / "ch03" / "gen" / "inventory.json"

    def run_trace(self, decodes):
        flow = subprocess.run([sys.executable, str(TMD), "flow", "--inv", str(self.inv), "--k8s", str(ROOT / "ch03" / "gen" / "k8s.json")],
                              capture_output=True, text=True, check=True).stdout
        (self.rs / "flow.env").write_text(flow + "HOLDER=k8s-ingress1\n")
        pts = subprocess.run([sys.executable, str(TMD), "points", "--inv", str(self.inv), "--holder", "k8s-ingress1"],
                             capture_output=True, text=True, check=True).stdout
        (self.rs / "points.tsv").write_text(pts)
        for pid, text in decodes.items():
            (self.rs / "captures" / f"{pid}.txt").write_text(text)
        (self.rs / "request.txt").write_text("HTTP/2 200 \nserver: envoy\n\nsfab-ch03-trace")
        (self.rs / "warmup.txt").write_text("HTTP/2 200 \n\nx")
        (self.rs / "dns.txt").write_text("10.20.11.210\n")
        (self.rs / "fw-traffic-log.txt").write_text(
            "2026/10/20 10:00:05 ssl             enterprise      41443      10.24.10.10\n"
            "staff-to-users-gate allow           ingress         443        10.20.11.210\n")
        env = dict(os.environ, SFAB_VERDICT=str(self.rs / "verdict.txt"))
        r = subprocess.run([sys.executable, str(TMD), "judge", "--set", str(self.rs), "--inv", str(self.inv), "--points",
                            str(self.rs / "points.tsv"), "--env", str(self.rs / "flow.env")], capture_output=True, text=True, env=env)
        return r, pts

    def healthy(self):
        # revision 2: the users' VIP on the ingress VLAN 110, tagged on every inside point (the ingress
        # node's bond carries it tagged), held by k8s-ingress1 on the pair's Ethernet13
        v, d = 110, "10.20.11.210"
        return {"1-fw-ae1-leg1": "", "1-fw-ae1-leg2": syn_line(100, self.FW, self.HOLDER, v, dst_ip=d),
                "2-fe-sw1-Ethernet2": "", "2-fe-sw2-Ethernet2": syn_line(103, self.FW, self.HOLDER, v, dst_ip=d),
                "3-fe-sw1-Ethernet13": "", "3-fe-sw2-Ethernet13": syn_line(140, self.FW, self.HOLDER, v, dst_ip=d),
                "4-k8s-ingress1-bond0": syn_line(180, self.FW, self.HOLDER, v, dst_ip=d)}

    def test_points(self):
        _, pts = self.run_trace(self.healthy())
        ids = [l.split("\t")[0] for l in pts.splitlines()]
        self.assertEqual(ids, ["1-fw-ae1-leg1", "1-fw-ae1-leg2", "2-fe-sw1-Ethernet2", "2-fe-sw2-Ethernet2",
                               "3-fe-sw1-Ethernet13", "3-fe-sw2-Ethernet13", "4-k8s-ingress1-bond0"])

    def test_green(self):
        r, _ = self.run_trace(self.healthy())
        self.assertEqual(r.returncode, 0, r.stdout)
        for line in ("  PASS  the recorded SYN from ent-client's pinned source port 41443 found at 1-fw-ae1-leg2 (seq 1520102513)",
                     "  PASS  exactly one of the ae1 points carries the SYN (1-fw-ae1-leg1, 1-fw-ae1-leg2)",
                     "  PASS  the SYN's trunk port is the pair port its ae1 leg lands on (1-fw-ae1-leg2 to fe-sw2:eth3)",
                     "  PASS  the SYN leaves the pair on the switch that received it (fe-sw2)",
                     "  PASS  1-fw-ae1-leg2: tagged 802.1Q 110", "  PASS  3-fe-sw2-Ethernet13: tagged 802.1Q 110",
                     f"  PASS  source MAC {self.FW} the same at all 4 points that saw the SYN",
                     "  PASS  IP id 2585 the same at all 4 points that saw the SYN", "  PASS  TTL 63 the same at all 4 points that saw the SYN",
                     "  PASS  destination MAC is k8s-ingress1's bond0 MAC 02:5a:68:00:00:01 (the frame is addressed to the node, not to a router)",
                     "  PASS  source 10.24.10.10 and destination 10.20.11.210:443 unchanged at every point (no translation)"):
            self.assertIn(line, r.stdout)
        md = (self.rs / "TRACE.md").read_text()
        self.assertIn("| `4-k8s-ingress1-bond0` | 1 | 1 | 0c:00:aa:bb:cc:f0 | 02:5a:68:00:00:01 | 2585 | 63 | 110 | correct |", md)

    def test_the_header_says_when_the_tree_had_uncommitted_changes(self):
        commit = "a" * 40
        for dirty, note in ((True, " (with uncommitted changes)"), (False, ""), (None, "")):
            (self.rs / "RUN.json").write_text(json.dumps({"labs_repo": {"commit": commit, "dirty": dirty, "source": "git"},
                                                          "utc_start": "2026-10-21T00:00:00Z"}))
            r, _ = self.run_trace(self.healthy())
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn(f"; labs repo commit `{commit}`{note}; UTC 2026-10-21T00:00:00Z\n", (self.rs / "TRACE.md").read_text())

    def test_a_routed_hop_shows(self):
        d = self.healthy()
        d["3-fe-sw2-Ethernet13"] = syn_line(140, "0c:00:12:34:56:06", self.HOLDER, 110, ttl=62, dst_ip="10.20.11.210")
        d["4-k8s-ingress1-bond0"] = syn_line(180, "0c:00:12:34:56:06", self.HOLDER, 110, ttl=62, dst_ip="10.20.11.210")
        r, _ = self.run_trace(d)
        self.assertEqual(r.returncode, 1)
        self.assertIn("  FAIL  TTL 63 the same at all 4 points that saw the SYN", r.stdout)
        self.assertIn(f"  FAIL  source MAC {self.FW} the same at all 4 points that saw the SYN", r.stdout)


# --------------------------------------------------------------------------------------------
# the drill analysis, on synthetic decodes


class AnalysisTest(unittest.TestCase):
    def test_round_trips_and_witnesses(self):
        t0 = 1000.0
        src, dst = "10.20.1.21", "10.20.1.22"
        frames = []
        guest = ["PING 10.20.1.22"]
        for seq in range(1, 201):
            t = 990.0 + (seq - 1) * 0.1
            frames.append({"proto": "icmp", "kind": "request", "src": src, "dst": dst, "id": 3100, "seq": seq, "t": t, "nic": "k8s-gpu1:eth1"})
            lost = t0 + 0.2 <= t < t0 + 3.0
            late = seq == 20
            if not lost:
                ta = t + (1.5 if late else 0.0005)
                frames.append({"proto": "icmp", "kind": "reply", "src": dst, "dst": src, "id": 3100, "seq": seq, "t": ta, "nic": "k8s-gpu1:eth1"})
                guest.append(f"[{ta:.6f}] 64 bytes from {dst}: icmp_seq={seq} ttl=64 time={1500.0 if late else 0.5} ms")
        guest.append("200 packets transmitted, 172 received, 14% packet loss, time 19900ms")
        p = AP.probe(frames, [], src, dst, 3100, t0=t0, restore=1010.0, guest=AP.guest_log("\n".join(guest)), place=(995.0, 1000.0))
        self.assertEqual((p["sent"], p["lost"], p["late"], p["lost_at_cut"], p["lost_elsewhere"]), (200, 29, 1, 28, 1))
        self.assertTrue(p["witness_agree"], p.get("witness_diff"))
        self.assertEqual(p["placement"]["req_out"], "k8s-gpu1:eth1")
        self.assertAlmostEqual(p["gap_cut_s"], 2.9, places=1)
        # the guest saw one more lost round trip than the captures: printed, never resolved
        g = AP.guest_log("\n".join(l for l in guest if "icmp_seq=40 " not in l))
        p2 = AP.probe(frames, [], src, dst, 3100, t0=t0, guest=g)
        self.assertFalse(p2["witness_agree"])
        self.assertEqual(p2["witness_diff"], {"guest_only": [40], "capture_only": []})

    def test_events(self):
        import drill as DR
        plan = json.loads((ROOT / "ch03" / "gen" / "drills.json").read_text())
        rows = []
        bonds = "k8s-cp1=eth1,eth2 k8s-gpu1=eth1,eth2"
        one = "k8s-cp1=eth1 k8s-gpu1=eth1"
        def line(t, b, s1, s2, fw="ethernet1/1,ethernet1/2"):
            return f"{t} | bonds {b} | fe-sw1 {s1} | fe-sw2 {s2} | fw ae1={fw}"
        ok1 = "mgmt=up sys=running The MCLAG's keepalive is: OK Role: Active PortChannel1=up/td=false PortChannel10=up/td=false"
        ok2 = "mgmt=up sys=running The MCLAG's keepalive is: OK Role: Standby PortChannel1=up/td=false PortChannel10=up/td=false"
        td2 = "mgmt=up sys=running The MCLAG's keepalive is: OK Role: Standby PortChannel1=down/td= PortChannel10=down/td=true"
        err1 = ok1.replace("is: OK", "is: ERROR")
        rows = [line(99, bonds, ok1, ok2), line(101, bonds, ok1, td2), line(103, one, ok1, td2), line(110, one, err1, "mgmt=down", "ethernet1/1"),
                line(150, one, err1, "mgmt=up sys=starting"), line(160, one, ok1, ok2), line(165, bonds, ok1, ok2)]
        ev = DR.events(plan, DR.monitor_rows("\n".join(rows)), 100.0, "fe-sw2", "fe-sw1")
        self.assertEqual((ev["standby_portchannels_down"], ev["bonds_on_one_leg"], ev["standby_mgmt_down"], ev["standby_mgmt_up"],
                          ev["session_up"], ev["return"], ev["fw_both_legs"]), (101, 103, 110, 150, 160, 165, 150))

    def test_compare_prints_a_conflict(self):
        rs = Path(tempfile.mkdtemp(prefix="sfab-test-ch03cmp-"))
        self.addCleanup(shutil.rmtree, rs, True)
        for p, lost in ((1, 30), (2, 0), (3, 28)):
            d = rs / f"pass{p}" / "server-member"
            d.mkdir(parents=True)
            a = {"drill": "server-member", "pass": p, "title": "t", "target": "fe-sw1", "placement": {"placed": p != 3},
                 "ping": {"on_target": ["3100"], "ids": {"3100": {}, "3101": {}}, "lost_on_target": [lost], "lost_at_cut_on_target": [lost],
                          "lost_at_restore_on_target": [0], "lost_spared": [0], "gap_cut_on_target": [3.0 if lost else 0.1]},
                 "tcp": {"failed_at_cut": 0, "failed_at_restore": 0, "failed_elsewhere": 0}, "problems": []}
            (d / "analysis.json").write_text(json.dumps(a))
        r = subprocess.run([sys.executable, str(COMMON / "drill" / "compare_passes.py"), "--set", str(rs)], capture_output=True, text=True)
        self.assertIn("| ping round trips lost, ids crossing fe-sw1 | 0 to 30 | no, passes conflict |", r.stdout)
        self.assertIn("DISAGREE server-member: placed in passes [1, 2], not in [3]", r.stdout)
        self.assertIn("| ping round trips lost, ids not crossing fe-sw1 | 0 | yes |", r.stdout)


# --------------------------------------------------------------------------------------------
# drills.sh and break-3a end to end, against the stand-in world


class Ch03LabTest(unittest.TestCase):
    TIMING = {"lead_s": 2.5, "place_s": 1.5, "place_tries": 3, "hold_s": 7, "tail_s": 3, "cut_window_s": 4,
              "restore_window_s": 3, "return_max_s": 45, "return_tail_s": 2, "whole_polls": 6}

    def setUp(self):
        if not have_yaml():
            self.skipTest("PyYAML is needed to render ch03")
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-ch03lab-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        self.scope = runscope.Scope(self)
        self.lab = self.t / "ch03"
        self.lab.mkdir()
        r = ch03_render()
        for part in ("gen", "bootstrap"):
            shutil.copytree(r / part, self.lab / part)
        shutil.copy(r / "topo.clab.yml", self.lab / "topo.clab.yml")
        for f in ("chapter.yaml", "audit.sh", "trace.sh", "drills.sh"):
            shutil.copy(ROOT / "ch03" / f, self.lab / f)
        os.symlink(COMMON, self.t / "common")
        os.symlink(ROOT / "spec", self.t / "spec")
        plan = json.loads((self.lab / "gen" / "drills.json").read_text())
        plan["timing"].update(self.TIMING)
        (self.lab / "gen" / "drills.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
        self.inv = json.loads((self.lab / "gen" / "inventory.json").read_text())
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS_CH03}:{SHIMS_M2}:{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab), "SHIM_STATE": str(self.state), "SHIM_LOG": str(self.log), "SHIM_NODES": CH03_NODES,
            "SFAB_HOST_LOCK": str(self.t / "sfab.lock"), "SFAB_TICK_OVERRIDE": "1", "SHIM_INV": str(self.lab / "gen" / "inventory.json"),
            "SHIM_RENDER": str(self.lab), "SHIM_CH03_STATE": str(self.t / "ch03-world.json"), "PYTHONDONTWRITEBYTECODE": "1",
            "SFAB_DRILL_POLL_S": "0.1", "SFAB_DRILL_MONITOR_S": "0.2", "SFAB_DRILL_STEP_S": "0.5", "SFAB_DRILL_SAMPLE_S": "0.5",
            "SFAB_DRILL_CAP_TAIL_S": "0.2", "SFAB_DRILL_AUDIT": "0", "SFAB_BREAK_SETTLE_S": "0", "SFAB_HEAL_AUDIT": "0",
            "SFAB_DRILL_CAP_POLL_S": "0.1", "SFAB_DRILL_CAP_SETTLE_S": "0.2", "SFAB_DRILL_PROBE_STOP_S": "0.2",
        })
        self.env.pop("VARIANT", None)
        cs = {}
        for i, n in enumerate(self.inv["order"]):
            node = self.inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            if node.get("passthrough"):
                env.append("CLAB_MGMT_PASSTHROUGH=true")
            cmd = ["--username", "admin", "--password", "shimpw"] if node["kind"] in ("dell_sonic", "paloalto_panos") else []
            cs[node["container"]] = {"running": True, "started": f"2026-10-20T09:00:{i:02d}Z", "pid": 4000 + i,
                                     "health": "healthy", "env": env, "cmd": cmd}
        self.state.write_text(json.dumps({"containers": cs}))
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-ch03"], check=True, capture_output=True)

    def run_cmd(self, argv, timeout=900, env=None):
        e = dict(self.env)
        e.update(env or {})
        return self.scope.run([str(x) for x in argv], env=e, capture_output=True, text=True, cwd=self.lab, timeout=timeout)

    def world(self):
        return json.loads((self.t / "ch03-world.json").read_text())

    def last_set(self, kind):
        return sorted((self.lab / "audits").glob(f"sfab-ch03_{kind}_*"))[-1]


class DrillsShTest(Ch03LabTest):
    def test_member_drills_two_passes(self):
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "fw-leg server-member", "--passes", "2"])
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict)
        # each drill archives the cluster's Warning events, so the full audit after it reads none
        self.assertIn("drills: 0 Warning event(s) archived in pass1/fw-leg/events and cleared", r.stdout)
        self.assertIn("drills: 0 Warning event(s) archived in events-after and cleared", r.stdout)
        for p in (1, 2):
            for line in (f"  PASS  pass {p} fw-leg: KLISH shutdown of Ethernet2 (PortChannel10) on fe-sw1 accepted",
                         f"  PASS  pass {p} fw-leg: no shutdown accepted on fe-sw1 after 7 s",
                         f"  PASS  pass {p} server-member: KLISH shutdown of Ethernet6 (PortChannel21) on fe-sw1 accepted",
                         f"  KNOWN pass {p} server-member: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9"):
                self.assertIn(line, verdict)
            self.assertRegex(verdict, rf"  PASS  pass {p} server-member: probes located before the fault as the drill needs them \(try 1\): ping: 4 of 8 ids cross fe-sw1, 4 do not")
            self.assertRegex(verdict, rf"  PASS  pass {p} fw-leg: the lab whole again after the drill")
        a = json.loads((rs / "pass1" / "server-member" / "analysis.json").read_text())
        self.assertEqual(sorted(a["ping"]["on_target"]), ["3100", "3102", "3104", "3106"])
        # the model loses the requests on fe-sw1's leg for 3 s: about 3 s of round trips each, at the
        # cut, at the chapter's probe intervals
        probes = json.loads((self.lab / "gen" / "drills.json").read_text())["probes"]
        iv_ping, iv_tcp = probes["ping"]["interval_s"], probes["tcp"]["interval_s"]
        for k in a["ping"]["on_target"]:
            self.assertGreaterEqual(a["ping"]["ids"][k]["lost_at_cut"], int(2.5 / iv_ping))
            self.assertTrue(a["ping"]["ids"][k]["witness_agree"])
            self.assertEqual(a["ping"]["ids"][k]["via"], ["fe-sw1"])
        self.assertEqual(a["ping"]["lost_spared"], [0, 0, 0, 0])
        self.assertEqual(a["tcp"]["failed"], 0)
        f = json.loads((rs / "pass2" / "fw-leg" / "analysis.json").read_text())
        self.assertGreater(f["tcp"]["failed_at_cut"], int(0.5 / iv_tcp))
        self.assertEqual(set(f["tcp"]["failed_by_leg"]), {"fe-sw1"})
        self.assertGreater(f["peer_link"]["during"]["fe-sw1"]["tx_pps"], f["peer_link"]["before"]["fe-sw1"]["tx_pps"])
        self.assertEqual(sum(f["ping"]["lost_on_target"] + f["ping"]["lost_spared"]), 0)
        cmp_ = (rs / "compare.txt").read_text()
        self.assertIn("## server-member", cmp_)
        md = (rs / "DRILLS.md").read_text()
        self.assertIn("## fw-leg: the firewall bundle's leg on fe-sw1 shut from the switch side", md)
        self.assertIn("== RESULT: ", md)
        # every shut was restored, and nothing is left running
        self.assertTrue(all(x.get("until") for x in self.world()["shuts"]))
        self.assertTrue(all(x.get("stop") for x in self.world()["pings"]))
        left = self.scope.left("_ch03.py")
        self.assertEqual(left, [])
        for ch in (chr(0x2014), chr(0x2013)):
            self.assertNotIn(ch, md)

    def test_restore_cut_short_is_typed_again(self):
        # a restore session whose typed-ahead lines sonic-cli dropped left the port shut on the lab
        # host; the drill types it again until the echo reaches the closing exit
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "fw-leg", "--passes", "1"], env={"SHIM_CH03_CUT_RESTORE": "1"})
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        self.assertNotIn("  FAIL  ", (rs / "verdict.txt").read_text())
        d = rs / "pass1" / "fw-leg"
        self.assertIn("RETYPED restore session on fe-sw1 cut short before its exit (try 1, restore.txt.try1)", (d / "timeline.txt").read_text())
        self.assertNotIn("fe-sw1# exit", (d / "restore.txt.try1").read_text())
        self.assertIn("fe-sw1# exit", (d / "restore.txt").read_text())
        self.assertTrue(all(x.get("until") for x in self.world()["shuts"]))

    def test_peer_link_and_standby_reboot(self):
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "peer-link standby-reboot", "--passes", "1"])
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict)
        for line in ("  PASS  pass 1 peer-link: KLISH shutdown of Ethernet0,Ethernet1 (PortChannel1) on fe-sw1 accepted",
                     "  PASS  pass 1 standby-reboot: sudo reboot sent to fe-sw2, the standby (the session is cut by the reboot, under a 25 s timeout)",
                     "  PASS  pass 1 standby-reboot: fe-sw2 after its reboot: GRO, rx-gro-hw and LRO off on all 19 data NICs",
                     "  PASS  pass 1 standby-reboot: fe-sw2 after its reboot: parity, 0 missing lines",
                     "  KNOWN pass 1 standby-reboot: delay-restore holds nothing down, so the return is boot plus LACP, recorded as an event and never as a span: L2"):
            self.assertIn(line, verdict)
        p = json.loads((rs / "pass1" / "peer-link" / "analysis.json").read_text())
        self.assertEqual(sum(p["ping"]["lost_on_target"] + p["ping"]["lost_spared"]), 0)
        # revision 2: TrueNAS's management is a bond across the pair, so no single-attached address is
        # left to probe as an orphan (render/drills.py refuses one on a dual-attached address)
        self.assertNotIn("orphan", p)
        b = json.loads((rs / "pass1" / "standby-reboot" / "analysis.json").read_text())
        self.assertEqual(b["target"], "fe-sw2")
        ev = b["events"]
        for k in ("standby_portchannels_down", "bonds_on_one_leg", "standby_mgmt_down", "standby_mgmt_up", "bonds_on_two_legs"):
            self.assertIsNotNone(ev.get(k), k)
        # the bonds leave the standby before its management stops answering; on a busy machine the
        # monitor's poll can see both at once
        self.assertLessEqual(ev["bonds_on_one_leg"], ev["standby_mgmt_down"])
        txt = (rs / "pass1" / "standby-reboot" / "analysis.txt").read_text()
        self.assertIn("the return is an event, not a redundancy gap", txt)
        md = (rs / "DRILLS.md").read_text()
        self.assertIn("every bond toward the pair back on two legs: the return", md)

    def test_keepalive_drills(self):
        """Revision 2's keepalive drills: the keepalive link alone (the standby shuts its MCLAG
        PortChannels and holds them down after the restore, and the drill waits for the return),
        then with the peer link (nothing shut, nothing held)."""
        plan = json.loads((self.lab / "gen" / "drills.json").read_text())
        for d in plan["list"]:
            if d["id"].startswith("keepalive"):
                d["hold_s"] = 8
        (self.lab / "gen" / "drills.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "keepalive-link keepalive-and-peer-link", "--passes", "1"])
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict)
        for line in ("  PASS  pass 1 keepalive-link: KLISH shutdown of Ethernet12 (the keepalive link Ethernet12) on fe-sw1 accepted",
                     "  PASS  pass 1 keepalive-link: no shutdown accepted on fe-sw1 after 8 s",
                     "  PASS  pass 1 keepalive-and-peer-link: KLISH shutdown of Ethernet0,Ethernet1,Ethernet12 (PortChannel1 and the keepalive link Ethernet12) on fe-sw1 accepted"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  pass 1 keepalive-link: the pair whole and every bond back on its legs \d+ s after the restore")
        k = json.loads((rs / "pass1" / "keepalive-link" / "analysis.json").read_text())
        self.assertEqual(k["standby"], "fe-sw2")
        ev = k["events"]
        for key in ("active_keepalive_not_ok", "standby_portchannels_down", "bonds_on_one_leg", "session_up", "standby_portchannels_up"):
            self.assertIsNotNone(ev.get(key), (key, ev))
        self.assertLess(ev["active_keepalive_not_ok"], ev["standby_portchannels_down"] + 1.5)
        # held past the restore (8 s) by the model's delay-restore
        self.assertGreater(ev["standby_portchannels_up"], 8 + 3)
        self.assertGreaterEqual(k["return_s"], ev["standby_portchannels_up"] - 1)
        # the ids leaving on fe-sw2's leg lose their requests for the LACP timeout; fe-sw1's lose none
        self.assertEqual(sorted(k["ping"]["spared"]), ["3101", "3103", "3105", "3107"])
        self.assertTrue(all(k["ping"]["ids"][i]["lost"] >= 25 for i in k["ping"]["spared"]))
        self.assertEqual(k["ping"]["lost_on_target"], [0, 0, 0, 0])
        b = json.loads((rs / "pass1" / "keepalive-and-peer-link" / "analysis.json").read_text())
        self.assertIsNone(b["events"].get("standby_portchannels_down"), "both keepalive paths gone: the standby shuts nothing")
        self.assertEqual(sum(b["ping"]["lost_on_target"] + b["ping"]["lost_spared"]), 0)
        txt = (rs / "pass1" / "keepalive-link" / "analysis.txt").read_text()
        self.assertIn("the standby (fe-sw2) as the monitor saw it", txt)
        self.assertTrue(all(x.get("until") for x in self.world()["shuts"]))
        self.assertEqual(self.scope.left("_ch03.py"), [])

    def test_pair_read_cut_short_is_typed_again(self):
        # a pair read whose session ended after echoing show PortChannel summary judged every
        # PortChannel absent through keepalive-link's whole return wait on the lab host; the poll
        # types it again, and each poll's outcome is kept in return/polls.txt
        plan = json.loads((self.lab / "gen" / "drills.json").read_text())
        for d in plan["list"]:
            if d["id"] == "keepalive-link":
                d["hold_s"] = 8
        (self.lab / "gen" / "drills.json").write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "keepalive-link", "--passes", "1"], env={"SHIM_CH03_CUT_PAIR_READ": "1"})
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        self.assertNotIn("  FAIL  ", (rs / "verdict.txt").read_text())
        d = rs / "pass1" / "keepalive-link"
        self.assertIn("RETYPED pair read on fe-sw1 cut short before its exit (try 1, pair/fe-sw1.session.try1)", (d / "timeline.txt").read_text())
        polls = (d / "return" / "polls.txt").read_text().splitlines()
        self.assertTrue(polls and all(p.startswith("+") and p.split(" ", 2)[0][1:].isdigit() and p.split(" ", 2)[1] == "s" for p in polls), polls)
        self.assertTrue(polls[-1].endswith("pair ok, bonds ok"), polls)

    def test_unplaced_probes_are_a_failure_line(self):
        # a model where every ICMP id hashes onto fe-sw2's leg cannot place the server-member drill
        plan = json.loads((self.lab / "gen" / "drills.json").read_text())
        plan["probes"]["ping"]["count"] = 1
        plan["probes"]["ping"]["id_base"] = 3101
        plan["timing"]["place_tries"] = 1
        (self.lab / "gen" / "drills.json").write_text(json.dumps(plan))
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "server-member", "--passes", "1"])
        self.assertEqual(r.returncode, 1)
        self.assertIn("  FAIL  pass 1 server-member: probes located before the fault -> not placed in 1 tries, so the drill measures no worst case: "
                      "ping: 0 of 1 ids cross fe-sw1, 1 do not (want at least one of each)", r.stdout)
        self.assertTrue(all(x.get("until") for x in self.world()["shuts"]), "the shut is restored all the same")


class TraceShTest(Ch03LabTest):
    """ch03/trace.sh end to end (common/trace/lib-trace.sh): the lease holder, seven captures on the
    host and in the guest, the client's attempts, the firewall's log and the four-point judgment."""

    def test_trace_green(self):
        env = {"SHIM_TRACE_HOLDER": "k8s-ingress1", "SFAB_TRACE_SETTLE_S": "0", "SFAB_TRACE_TAIL_S": "0", "SFAB_TRACE_GAP_S": "0",
               "SFAB_TRACE_TLOG_PAUSE_S": "0"}
        r = self.run_cmd([self.lab / "trace.sh"], env=env, timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("FAIL", verdict, verdict)
        for line in ("  PASS  7 capture points decoded (7 with a decode)",
                     "  PASS  the recorded SYN from ent-client's pinned source port 41443 found at 1-fw-ae1-leg1 (seq 1234567890)",
                     "  PASS  exactly one of the server points carries the SYN (3-fe-sw1-Ethernet13, 3-fe-sw2-Ethernet13)",
                     "  PASS  4-k8s-ingress1-bond0: the recorded SYN seen (seq 1234567890)",
                     "  PASS  destination MAC is k8s-ingress1's bond0 MAC 02:5a:68:00:00:01 (the frame is addressed to the node, not to a router)",
                     "  PASS  https://llm.ai.tarnwick.example/echo?msg=sfab-ch03-trace answers 200 with the echoed message sfab-ch03-trace"):
            self.assertIn(line, verdict)
        self.assertNotIn("TTL", "".join(l for l in verdict.splitlines() if "routed hop" in l))
        for f in ("TRACE.md", "points.tsv", "captures/4-k8s-ingress1-bond0.txt", "captures/1-fw-ae1-leg2.pcap"):
            self.assertTrue((rs / f).is_file(), f)
        left = self.scope.left("_trace.py|_ch03.py")
        self.assertEqual(left, [])


class BreakHealTest(Ch03LabTest):
    def bh(self, *args, env=None):
        return self.run_cmd([sys.executable, COMMON / "breakheal.py", *args], env=env)

    def test_break_then_heal(self):
        r = self.bh("break", "3a")
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-2000:])
        rs = self.last_set("break-3a")
        verdict = (rs / "verdict.txt").read_text()
        for line in ("  PASS  fe-sw2: interface PortChannel 10: switchport trunk allowed Vlan remove 200 accepted",
                     "  PASS  fe-sw2: show vlan has PortChannel10 not in Vlan200: Vlan200: PortChannel1(T),PortChannel32(A)",
                     "  PASS  fe-sw1: show vlan has PortChannel10 in Vlan200 (T): Vlan200: PortChannel1(T),PortChannel10(T),PortChannel32(A)",
                     "  PASS  bastion-stor-mgmt: some connects fail and some succeed, by hash (60 of 180 across the passes)"):
            self.assertIn(line, verdict)
        self.assertIn("  PASS  bastion-stor-mgmt, break, pass 3: 20 of 60 connects from bastion to 10.20.2.31:443 failed", verdict)
        self.assertTrue((self.lab / "state" / "breaks" / "3a").is_file())
        r2 = self.bh("break", "3a")
        self.assertNotEqual(r2.returncode, 0)
        self.assertIn("break-3a is already applied", r2.stderr)
        r = self.bh("heal", "3a")
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-2000:])
        verdict = (self.last_set("heal-3a") / "verdict.txt").read_text()
        for line in ("  PASS  fe-sw2: show vlan has PortChannel10 in Vlan200 (T)", "  PASS  fe-sw2: parity, 0 missing lines",
                     "  PASS  bastion-stor-mgmt: every connect succeeds (60 of 60)"):
            self.assertIn(line, verdict)
        self.assertFalse((self.lab / "state" / "breaks" / "3a").exists())

    def test_break_3b_one_leg_of_the_management_bond(self):
        r = self.bh("break", "3b")
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-2000:])
        verdict = (self.last_set("break-3b") / "verdict.txt").read_text()
        for line in ("  PASS  fe-sw1: interface Ethernet11: shutdown accepted",
                     "  PASS  fe-sw1: show mclag brief has PortChannel32 down/up (Local/Remote): PortChannel32 down/up",
                     "  PASS  fe-sw2: show mclag brief has PortChannel32 up/down (Local/Remote): PortChannel32 up/down",
                     "  PASS  bastion-stor-mgmt: every connect succeeds (180 of 180)"):
            self.assertIn(line, verdict)
        rec = self.last_set("break-3b") / "record"
        self.assertIn("PortChannel32", (rec / "broken-fe-sw1-show_mclag_brief.txt").read_text())
        r = self.bh("heal", "3b")
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-2000:])
        verdict = (self.last_set("heal-3b") / "verdict.txt").read_text()
        for line in ("  PASS  fe-sw1: interface Ethernet11: no shutdown accepted",
                     "  PASS  fe-sw1: show mclag brief has PortChannel32 up/up (Local/Remote): PortChannel32 up/up",
                     "  PASS  fe-sw2: show mclag brief has PortChannel32 up/up (Local/Remote): PortChannel32 up/up",
                     "  PASS  fe-sw1: parity, 0 missing lines", "  PASS  bastion-stor-mgmt: every connect succeeds (60 of 60)"):
            self.assertIn(line, verdict)
        self.assertFalse((self.lab / "state" / "breaks" / "3b").exists())

    def test_the_fallback_form_is_recorded(self):
        r = self.bh("break", "3a", env={"SHIM_CH03_REFUSE_REMOVE": "1"})
        self.assertEqual(r.returncode, 0, r.stdout[-5000:])
        verdict = (self.last_set("break-3a") / "verdict.txt").read_text()
        self.assertIn("the fallback no switchport trunk allowed Vlan 200 accepted: fix the break file to it", verdict)
        self.assertIn("fallback: no switchport trunk allowed Vlan 200", (self.lab / "state" / "breaks" / "3a").read_text())


if __name__ == "__main__":
    unittest.main()
