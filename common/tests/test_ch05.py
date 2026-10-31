"""Chapter 5's lab harness (ch05/): the rail-backend group the audit adds, the rail trace with its DF
probe matrix, the dark-switch drill, and break-5a with its heal. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_ch05*.py'

Hermetic: ch05 is rendered into a temporary directory (PyYAML) and every device is a stand-in
(common/tests/shims/, shims-ch05/). The stand-in world is a simple deterministic model of the rails
(shims-ch05/_ch05.py), so the figures asserted here are the model's, never the lab's. Fixtures use
the book's own addressing plan and made-up names only.
"""

from __future__ import annotations

import io
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
CH05 = ROOT / "ch05"
HERE = Path(__file__).resolve().parent
SHIMS, SHIMS_CH05 = HERE / "shims", HERE / "shims-ch05"
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(COMMON / "trace"))
sys.path.insert(0, str(COMMON / "drill"))
sys.path.insert(0, str(HERE))

import judge  # noqa: E402
import runscope  # noqa: E402
import vocab  # noqa: E402

CH05_NODES = "fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw k8s-gpu1 k8s-gpu2"


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


def load(p):
    return json.loads(Path(p).read_text())


_RENDER = None


def ch05_render() -> Path:
    global _RENDER
    if _RENDER is None:
        out = Path(tempfile.mkdtemp(prefix="sfab-test-ch05-"))
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(CH05), "--out", str(out), "-q"], check=True, capture_output=True)
        _RENDER = out
    return _RENDER


def tearDownModule():
    if _RENDER is not None:
        shutil.rmtree(_RENDER, ignore_errors=True)


# --------------------------------------------------------------------------------------------
# the parsers chapter 5 adds


class ParsersTest(unittest.TestCase):
    def test_interface_status_and_vrf(self):
        st = "\n".join(["-" * 80, "Name                Description                   Oper        Reason         AutoNeg   Speed          MTU            Alternate Name",
                        "-" * 80,
                        "Ethernet0           k8s-gpu1-rail1                    up          oper-up          off       25000          9100           Eth1/1",
                        "Ethernet8           -                             down        admin-down       off       25000          9100           Eth1/9"])
        rows = judge.p_interface_status(st)
        self.assertEqual(rows["Ethernet0"], {"desc": "k8s-gpu1-rail1", "oper": "up", "reason": "oper-up", "mtu": "9100"})
        self.assertEqual(rows["Ethernet8"]["reason"], "admin-down")
        vrf = judge.p_ip_vrf("VRF-NAME            INTERFACES\n" + "-" * 64 + "\ndefault\nmgmt                Management0\n")
        self.assertEqual(vrf, {"default": [], "mgmt": ["Management0"]})

    def test_rail_trace_frames(self):
        import railtrace as RT
        text = ("2026-10-21 10:00:01.000300 02:5a:6f:01:00:05 > 02:5a:70:01:00:05, ethertype IPv4 (0x0800), length 9014: (tos 0x0, ttl 63, "
                "id 4321, offset 0, flags [DF], proto ICMP (1), length 9000)\n    10.21.1.11 > 10.21.2.12: ICMP echo request, id 5205, seq 2, length 8980\n")
        f = RT.frames(text)[0]
        self.assertEqual((f["kind"], f["id"], f["seq"], f["ttl"], f["ipid"], f["frame_len"], f["ip_len"], f["df"], f["line"]),
                         ("request", 5205, 2, 63, 4321, 9014, 9000, True, 1))
        p = RT.ping_result("PING 10.21.1.12 (10.21.1.12) 8973(9001) bytes of data.\nping: local error: message too long, mtu=9000\n\n"
                           "--- 10.21.1.12 ping statistics ---\n3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2003ms\n")
        self.assertEqual((p["tx"], p["rx"], p["local_mtu"]), (3, 0, 9000))
        self.assertEqual(RT.hops("traceroute to 10.21.2.12 (10.21.2.12), 4 hops max\n 1  10.21.2.11  0.3 ms\n 2  10.21.2.12  0.7 ms\n"),
                         [(1, "10.21.2.11"), (2, "10.21.2.12")])


# --------------------------------------------------------------------------------------------
# the lab against the stand-in world


class Ch05LabTest(unittest.TestCase):
    def setUp(self):
        if not have_yaml():
            self.skipTest("PyYAML is needed to render ch05")
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-ch05lab-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        self.scope = runscope.Scope(self)
        self.lab = self.t / "ch05"
        self.lab.mkdir()
        r = ch05_render()
        for part in ("gen", "bootstrap"):
            shutil.copytree(r / part, self.lab / part)
        shutil.copy(r / "topo.clab.yml", self.lab / "topo.clab.yml")
        for f in ("chapter.yaml", "audit.sh", "trace.sh", "drills.sh"):
            shutil.copy(CH05 / f, self.lab / f)
        os.symlink(COMMON, self.t / "common")
        os.symlink(ROOT / "spec", self.t / "spec")
        dr = load(self.lab / "gen" / "drills.json")
        dr["timing"].update({"lead_s": 2, "hold_s": 3, "tail_s": 2, "whole_polls": 3})
        (self.lab / "gen" / "drills.json").write_text(json.dumps(dr, indent=2, sort_keys=True) + "\n")
        self.inv = load(self.lab / "gen" / "inventory.json")
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS_CH05}:{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab), "SHIM_STATE": str(self.state), "SHIM_LOG": str(self.log), "SHIM_NODES": CH05_NODES,
            "SFAB_HOST_LOCK": str(self.t / "sfab.lock"), "SFAB_TICK_OVERRIDE": "1", "SHIM_INV": str(self.lab / "gen" / "inventory.json"),
            "SHIM_RENDER": str(self.lab), "SHIM_CH05_STATE": str(self.t / "ch05-world.json"), "PYTHONDONTWRITEBYTECODE": "1",
            "SFAB_DRILL_AUDIT": "0", "SFAB_BREAK_SETTLE_S": "0", "SFAB_HEAL_AUDIT": "0", "SFAB_RETRY_PAUSE": "0",
            "SFAB_RAILCAP_SETTLE_S": "0", "SFAB_RAILCAP_TAIL_S": "0.2", "SFAB_DRILL_POLL_S": "0",
        })
        self.env.pop("VARIANT", None)
        cs = {}
        for i, n in enumerate(self.inv["order"]):
            node = self.inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            if node.get("passthrough"):
                env.append("CLAB_MGMT_PASSTHROUGH=true")
            cmd = ["--username", "admin", "--password", "shimpw"] if node["kind"] == "dell_sonic" else []
            cs[node["container"]] = {"running": True, "started": f"2026-10-21T09:00:{i:02d}Z", "pid": 6000 + i,
                                     "health": "healthy", "env": env, "cmd": cmd}
        self.state.write_text(json.dumps({"containers": cs}))
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-ch05"], check=True, capture_output=True)

    def run_cmd(self, argv, timeout=900, env=None):
        e = dict(self.env)
        e.update(env or {})
        return self.scope.run([str(x) for x in argv], env=e, capture_output=True, text=True, cwd=self.lab, timeout=timeout)

    def leftover_shims(self) -> list:
        """The stand-in captures this test's commands left running."""
        return self.scope.left("shims-ch05/_ch05.py tcpdump")

    def world(self):
        try:
            return load(self.t / "ch05-world.json")
        except (OSError, ValueError):
            return {}

    def set_world(self, w):
        (self.t / "ch05-world.json").write_text(json.dumps(w))

    def last_set(self, kind):
        return sorted((self.lab / "audits").glob(f"sfab-ch05_{kind}_*"))[-1]


class RailBackendShTest(Ch05LabTest):
    def audit(self):
        rs = self.t / "set"
        rs.mkdir(exist_ok=True)
        script = (f". {COMMON}/lib.sh; sfab_init audit --set {rs}; . {COMMON}/audit/lib-audit.sh; "
                  "audit_collect rail-sw1 rail-sw2 k8s-gpu1 k8s-gpu2; audit_rail_backend rail-sw1 rail-sw2; summary")
        r = self.run_cmd(["bash", "-c", script], timeout=600)
        return r.stdout, r

    def test_green(self):
        out, r = self.audit()
        self.assertIn("== rail-sw1: the rail backend's absences (chapter 5)", out, out[-4000:] + r.stderr[-2000:])
        part = out.split("== rail-sw1: the rail backend's absences (chapter 5)", 1)[1]
        self.assertEqual([l for l in part.splitlines() if l.startswith("  FAIL  ")], [], part[-4000:])
        for line in ("  PASS  rails 1, 3, 5, 7 are VLANs 101, 103, 105, 107, one interface Vlan block each",
                     "  PASS  no VLAN interface address: none of the 4 interface Vlan blocks holds an ip, ipv6 or anycast address line",
                     "  PASS  show ip interfaces lists no Vlan interface",
                     "  PASS  no gateway: no static route in the running configuration, and show ip route (the default VRF) prints nothing",
                     "  PASS  no router bgp: neither the KLISH running configuration nor FRR's own view holds a router bgp line",
                     "  PASS  only Management0 in the mgmt VRF, and no interface in any other VRF",
                     "  PASS  no inter-switch link: only the 8 rendered GPU access ports are up, and the other 48 ports are admin down",
                     "  PASS  each up port's description names the GPU NIC the render cables there",
                     "  PASS  the 8 rail ports at MTU 9216 as rendered (the l2 policy's port MTU), above the GPU NICs' 9000",
                     "  PASS  every rail port runs no shutdown (the factory profile leaves all ports admin down), and each mtu line the render types is the rendered port MTU",
                     "== k8s-gpu1: GPU namespaces and their relay (chapter 5)",
                     "  PASS  the 8 GPU namespaces (gpu1,gpu2,gpu3,gpu4,gpu5,gpu6,gpu7,gpu8) hold no default route",
                     "  PASS  each holds its connected rail and 7 relay routes, one to each other rail via that rail's namespace, every one pinned "
                     "to the namespace's own rail address, as rendered",
                     "  PASS  reverse-path filtering loose (rp_filter 2) on every interface of every GPU namespace",
                     "  PASS  the 8 rail NICs and the relay bridge relay0 at MTU 9000",
                     "  PASS  in each GPU namespace the rail macvlan and the relay veth at MTU 9000: the cross-rail ceiling is the relay's 9000 "
                     "(8 namespaces read)"):
            self.assertIn(line, out)
        self.assertTrue((self.t / "set" / "rail-backend" / "k8s-gpu2-gpu5-links.json").is_file())
        # a namespace's link read stored compressed (evfile.py) is read as the plain one
        import evfile
        evfile.compress_file(self.t / "set" / "rail-backend" / "k8s-gpu2-gpu5-links.json")
        env = {k: v for k, v in self.env.items() if k != "SFAB_VERDICT"}
        r = subprocess.run([sys.executable, str(COMMON / "audit" / "judge.py"), "run", "--set", str(self.t / "set"),
                            "--inv", str(self.lab / "gen" / "inventory.json"), "--render", str(self.lab), "rail-backend", "rail-sw1", "rail-sw2"],
                           env=env, capture_output=True, text=True, timeout=300)
        self.assertIn("  PASS  in each GPU namespace the rail macvlan and the relay veth at MTU 9000: the cross-rail ceiling is the relay's 9000 "
                      "(8 namespaces read)", r.stdout, r.stdout[-3000:] + r.stderr[-2000:])

    def test_an_unpinned_route_and_a_dark_switch(self):
        self.set_world({"unpinned": [["k8s-gpu1", 1, "10.21.2.0/24"]], "dark": {"rail-sw2": [{"since": 0, "until": None}]}})
        out, r = self.audit()
        self.assertIn("  FAIL  no inter-switch link: only the 8 rendered GPU access ports are up, and the other 48 ports are admin down -> up: none",
                      out, out[-4000:])
        self.assertIn("  FAIL  each holds its connected rail and 7 relay routes, one to each other rail via that rail's namespace, every one "
                      "pinned to the namespace's own rail address, as rendered -> gpu1: 10.21.2.0/24 via 10.21.250.2 dev relay src 10.21.1.11", out)


class RailTraceShTest(Ch05LabTest):
    def test_trace_green(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("FAIL", verdict, verdict)
        for line in ("  PASS  rail 1 (rail-sw1): k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.1.12: 2 of 2 answered",
                     "  PASS  rail 8 (rail-sw2): k8s-gpu1 (gpu8, 10.21.8.11) to 10.21.8.12: 2 of 2 answered",
                     "  PASS  the ping: 3 of 3 answered, every reply at TTL 64",
                     "  PASS  the ping: 3 of 3 answered, every reply at TTL 63",
                     "  PASS  1-k8s-gpu1-relay0 (k8s-gpu1's relay bridge relay0): 3 requests at TTL 64, no reply",
                     "  PASS  2-rail-sw2-Ethernet0 (rail-sw2 Ethernet0, facing k8s-gpu1 on rail 2): 3 requests at TTL 63, no reply",
                     "  PASS  2-rail-sw1-Ethernet0 (rail-sw1 Ethernet0, facing k8s-gpu1 on rail 1): no request, 3 replies at TTL 63",
                     "  PASS  4-k8s-gpu2-relay0 (k8s-gpu2's relay bridge relay0): no request, 3 replies at TTL 64",
                     "  PASS  the request crossed rail-sw2 (rail 2, the destination's rail) and the reply rail-sw1 (rail 1, the source's)",
                     "  PASS  traceroute: 1 hop, 10.21.1.12",
                     "  PASS  traceroute: 2 hops, 10.21.2.11 (k8s-gpu1's own address on rail 2: its namespace on that rail forwarded the probe and "
                     "answers from its route's pinned source), then 10.21.2.12",
                     "  PASS  cross-rail forward, 9000 bytes: k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.2.12: 3 of 3 answered",
                     "  PASS  cross-rail reverse, 9001 bytes: k8s-gpu2 (gpu2, 10.21.2.12) to 10.21.1.11: refused at the sender's own interface: "
                     "message too long, mtu 9000",
                     "  PASS  ... and no frame of it at any capture point",
                     "  PASS  the paths' ceiling: 9000 bytes answered on every path both ways, 9001 the first size refused on every one (the "
                     "relay's and the rail NICs' MTU is 9000)"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  the request with seq 1 carries one IP id at every point that saw it \(3 points; TTL 64 at 1-k8s-gpu1-relay0, "
                                  r"63 at 2-rail-sw2-Ethernet0, 63 at 3-rail-sw2-Ethernet4\)")
        self.assertRegex(verdict, r"  PASS  \.\.\. its requests and replies at 2-rail-sw1-Ethernet0, 3-rail-sw1-Ethernet4 as 9014-byte frames \(IP 9000\), "
                                  r"every request with DF set, and at no other point")
        md = (rs / "TRACE.md").read_text()
        for x in ("## Frames per point", "## Flow cross-rail", "## The DF probe matrix", "`captures/2-rail-sw2-Ethernet0.txt:"):
            self.assertIn(x, md)
        for ch in (chr(0x2014), chr(0x2013)):
            self.assertNotIn(ch, md)
        self.assertEqual(self.leftover_shims(), [])
        self.assertEqual([k for k, c in self.world().get("gcaps", {}).items() if c.get("stop") is None], [])
        # the header names the labs commit, and says when the tree had uncommitted changes
        run = load(rs / "RUN.json")
        env = {k: v for k, v in self.env.items() if k != "SFAB_VERDICT"}
        for dirty, note in ((True, " (with uncommitted changes)"), (False, ""), (None, "")):
            run["labs_repo"] = {"commit": "a" * 40, "dirty": dirty, "source": "git"}
            (rs / "RUN.json").write_text(json.dumps(run))
            r = subprocess.run([sys.executable, str(COMMON / "trace" / "railtrace.py"), "judge", "--set", str(rs),
                                "--plan", str(self.lab / "gen" / "trace.json"), "--inv", str(self.lab / "gen" / "inventory.json")],
                               env=env, capture_output=True, text=True, timeout=120)
            self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-2000:])
            self.assertIn(f"; labs repo commit `{'a' * 40}`{note}; UTC {run.get('utc_start')}\n", (rs / "TRACE.md").read_text())

    def test_a_dark_rail_fails_the_trace(self):
        self.set_world({"dark": {"rail-sw2": [{"since": 0, "until": None}]}})
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 1)
        verdict = (self.last_set("trace") / "verdict.txt").read_text()
        self.assertIn("  FAIL  rail 2 (rail-sw2): k8s-gpu1 (gpu2, 10.21.2.11) to 10.21.2.12: 0 of 2 answered -> no reply", verdict)
        self.assertIn("  PASS  rail 1 (rail-sw1): k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.1.12: 2 of 2 answered", verdict)
        self.assertIn("  FAIL  3-rail-sw2-Ethernet4 (rail-sw2 Ethernet4, facing k8s-gpu2 on rail 2): 3 requests at TTL 63, no reply -> 0 requests", verdict)


class RailDrillShTest(Ch05LabTest):
    def test_dark_switch_one_pass(self):
        r = self.run_cmd([self.lab / "drills.sh", "--passes", "1"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        for line in ("  PASS  pass 1 dark-switch: the rails whole before the fault: every rail answers its same-rail ping and every rail switch's "
                     "rendered ports are up (poll 2)",
                     "  PASS  pass 1 dark-switch: KLISH interface range Ethernet0-7, shutdown accepted on rail-sw1: every port it uses "
                     "(Ethernet0,Ethernet1,Ethernet2,Ethernet3,Ethernet4,Ethernet5,Ethernet6,Ethernet7)",
                     "  PASS  pass 1 dark-switch: no shutdown accepted on rail-sw1 after 3 s",
                     "  PASS  pass 1 dark-switch: rail-sw1 after the restore: parity, 0 missing lines"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: same-1 \(rail 1, rail-sw1\): while rail-sw1 was dark, 0 of \d+ answered \(dark, as planned")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: \.\.\. its requests left k8s-gpu1 on rail 1 \(\d+\) and none reached k8s-gpu2 \(0\): the dead rail is silent")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: same-2 \(rail 2, rail-sw2\): while rail-sw1 was dark, (\d+) of \1 answered")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: cross-2-1 \(rail 2 to rail 1: request on rail-sw1, reply on rail-sw2\): while rail-sw1 "
                                  r"was dark, 0 of \d+ answered")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: \.\.\. its requests reached k8s-gpu2 on rail 2 \(\d+ of \d+\), k8s-gpu2's replies left on rail 1 "
                                  r"\(\d+\) and none reached k8s-gpu1: the reply rides the dead rail")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: cross-2-4 \(rail 2 to rail 4: request on rail-sw2, reply on rail-sw2\): while rail-sw1 "
                                  r"was dark, (\d+) of \1 answered")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: \.\.\. after the no shutdown it answered again: the first answered request sent [\d.]+ s "
                                  r"after the restore's session began")
        self.assertIn("  KNOWN pass 1 dark-switch: a KLISH shutdown drops no carrier at the GPU NICs, so the dark rail shows only as silence", verdict)
        a = load(rs / "pass1" / "dark-switch" / "analysis.json")
        self.assertEqual(sorted(r["id"] for r in a["rows"] if r["expect"] == "dark"), ["cross-1-2", "cross-2-1", "same-1", "same-3", "same-5", "same-7"])
        md = (rs / "DRILLS.md").read_text()
        self.assertIn("## dark-switch: rail-sw1 dark, rails 1, 3, 5, 7", md)
        self.assertIn("Every pass agrees on which rows went dark.", md)
        self.assertIn("- Lab: `sfab-ch05`; labs repo commit `", md)
        self.assertIn("; passes: 1\n", md)
        # an analysis stored compressed (evfile.py) gives the same page
        import evfile
        evfile.compress_file(rs / "pass1" / "dark-switch" / "analysis.json")
        stamp = [x[2:] for x in md.splitlines()[3:4] if x.startswith("- ")]
        r = self.run_cmd([sys.executable, COMMON / "drill" / "raildrill.py", "summarize", "--set", rs] + (["--stamp", stamp[0]] if stamp else []))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((rs / "DRILLS.md").read_text(), md)
        w = self.world()
        self.assertTrue(all(x.get("until") for x in w["dark"]["rail-sw1"]), "the switch is restored")
        self.assertEqual(self.leftover_shims(), [])


class Break5aShTest(Ch05LabTest):
    def bh(self, *args):
        return self.run_cmd([sys.executable, COMMON / "breakheal.py", *args])

    def test_break_then_heal(self):
        r = self.bh("break", "5a")
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        verdict = (self.last_set("break-5a") / "verdict.txt").read_text()
        for line in ("  PASS  k8s-gpu1, namespace gpu1: the route to rail 2 carries no source pin",
                     "  PASS  k8s-gpu1, namespace gpu1: the route to rail 3 carries its rendered source pin, src 10.21.1.11",
                     "  PASS  rail1-to-rail2: every ping fails (30 of 30 across the passes)",
                     "  PASS  rail1-to-rail3: every ping succeeds (10 of 10)",
                     "  PASS  k8s-gpu2-rail1-to-rail2: every ping succeeds (10 of 10)",
                     "  PASS  same-rail-k8s-gpu1: every ping succeeds (24 of 24)",
                     "  PASS  rail-sw1: parity, 0 missing lines", "  PASS  rail-sw2: parity, 0 missing lines"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  k8s-gpu1, namespace gpu1: ip -n gpu1 route replace 10\.21\.2\.0/24 via 10\.21\.250\.2 dev relay \(reads back: "
                                  r"10\.21\.2\.0/24 via 10\.21\.250\.2 dev relay \)")
        self.assertRegex(verdict, r"  PASS  rail1-to-rail2: k8s-gpu2 saw 30 requests arrive on rail2 from 10\.21\.250\.1, and its 30 replies go into its "
                                  r"relay bridge relay0 toward 10\.21\.250\.1 \(3 passes captured\): the source left unpinned took the relay address")
        rec = self.last_set("break-5a") / "record"
        self.assertIn("10.21.2.12 via 10.21.250.2 dev relay src 10.21.250.1", (rec / "broken-k8s-gpu1-ip_n_gpu1_route_get_10_21_2_12.txt").read_text())
        self.assertEqual(self.world()["unpinned"], [["k8s-gpu1", 1, "10.21.2.0/24"]])
        r = self.bh("heal", "5a")
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        verdict = (self.last_set("heal-5a") / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        for line in ("  PASS  k8s-gpu1, namespace gpu1: the route to rail 2 carries its rendered source pin, src 10.21.1.11",
                     "  PASS  rail1-to-rail2: every ping succeeds (10 of 10)"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  rail1-to-rail2: k8s-gpu2 saw 10 requests arrive on rail2 from 10\.21\.1\.11, and its 10 replies go into its relay "
                                  r"bridge relay0 toward 10\.21\.1\.11 \(1 pass captured\): the pinned source 10\.21\.1\.11")
        self.assertEqual(self.world()["unpinned"], [])
        self.assertEqual(self.leftover_shims(), [])


if __name__ == "__main__":
    unittest.main()
