"""Tests for the harness: vocab, judge (plans, splitting, parsers, groups), redact, secrets,
tick and namecheck. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests

Fixtures use the book's own addressing plan and made-up names only.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(COMMON / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import codefiles  # noqa: E402
import judge  # noqa: E402
import namecheck  # noqa: E402
import redact  # noqa: E402
import vocab  # noqa: E402


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


_INV = None


def m1_inventory() -> dict:
    """Render dev/m1's inventory into a temporary directory (the render needs PyYAML)."""
    global _INV
    if _INV is None:
        out = tempfile.mkdtemp(prefix="sfab-test-inv-")
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(ROOT / "dev" / "m1"), "--out", out, "-q"],
                       check=True, capture_output=True)
        _INV = json.loads((Path(out) / "gen" / "inventory.json").read_text())
        shutil.rmtree(out)
    return _INV


# ------------------------------------------------------------------------------------------------


class VocabTest(unittest.TestCase):
    def test_lines_and_counts(self):
        with tempfile.TemporaryDirectory() as d:
            vf = os.path.join(d, "verdict.txt")
            buf = io.StringIO()
            v = vocab.Vocab(verdict=vf, known={"L1", "L9"}, out=buf)
            v.sec("pair  fe-sw1\nfe-sw2")
            v.ok("[U] label")
            v.bad("[U] other", "want 1, got 2")
            v.skip("[U] skipped", "no tool")
            v.known("L9", "[R] shut")
            v.known("L42", "[R] bogus")
            self.assertTrue(v.chk("c", 8, "8"))
            self.assertFalse(v.ge("g", 3, "x"))
            rc = v.summary()
            lines = buf.getvalue().splitlines()
            self.assertEqual(lines[0], "== pair fe-sw1 fe-sw2")
            self.assertEqual(lines[1], "  PASS  [U] label")
            self.assertEqual(lines[2], "  FAIL  [U] other -> want 1, got 2")
            self.assertEqual(lines[3], "  SKIP  [U] skipped (no tool)")
            self.assertEqual(lines[4], "  KNOWN [R] shut: L9")
            self.assertEqual(lines[5], "  FAIL  [R] bogus -> KNOWN id L42 is not in spec/known.yaml")
            self.assertEqual(lines[-1], "== RESULT: 2 passed, 3 failed, 1 known platform limitation(s), 1 skipped")
            self.assertEqual(rc, 1)
            self.assertEqual(Path(vf).read_text().splitlines(), lines)
            self.assertEqual(vocab.parse_result(Path(vf).read_text())["fail"], 3)

    def test_shell_helpers_print_the_same_lines(self):
        script = r'''
            . "$1/lib.sh"
            KNOWN_IDS=(L1 L9)
            SFAB_VERDICT="$2"
            sec "pair  fe-sw1"
            ok "[U] label"
            bad "[U] other" "want 1, got 2"
            skip "[U] skipped" "no tool"
            known L9 "[R] shut"
            known L42 "[R] bogus"
            chk c 8 8
            ge g 3 x
            summary || true
        '''
        with tempfile.TemporaryDirectory() as d:
            sh_v = os.path.join(d, "sh.txt")
            out = subprocess.run(["bash", "-c", script, "x", str(COMMON), sh_v], capture_output=True, text=True, check=True).stdout
            py_buf = io.StringIO()
            v = vocab.Vocab(verdict=None, known={"L1", "L9"}, out=py_buf)
            v.sec("pair  fe-sw1")
            v.ok("[U] label")
            v.bad("[U] other", "want 1, got 2")
            v.skip("[U] skipped", "no tool")
            v.known("L9", "[R] shut")
            v.known("L42", "[R] bogus")
            v.chk("c", 8, 8)
            v.ge("g", 3, "x")
            v.summary()
            self.assertEqual(out, py_buf.getvalue())
            self.assertEqual(Path(sh_v).read_text(), out)

    def test_audit_namecheck_skip_fails_under_the_author_flag(self):
        # audit_clean records namecheck's exit 3 (no scrub list) as a SKIP, or a FAIL when
        # SFAB_REQUIRE_NAMECHECK is set (not empty and not 0); namecheck and sfab check are stand-ins
        script = r'''
            . "$1/lib.sh"
            SFAB_COMMON="$2" RS="$2/rs" LABDIR="$2"
            py() { echo "namecheck: skipped, no scrub list"; return 3; }
            audit_clean
            not_run "a check" "a check clean" "no list"
        '''
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "bin").mkdir()
            (Path(d) / "bin" / "sfab").write_text("#!/bin/sh\necho 'check x: clean'\n")
            (Path(d) / "bin" / "sfab").chmod(0o755)
            outs = {}
            for flag in (None, "", "0", "1", "yes"):
                env = {k: v for k, v in os.environ.items() if k != "SFAB_REQUIRE_NAMECHECK"}
                if flag is not None:
                    env["SFAB_REQUIRE_NAMECHECK"] = flag
                outs[flag] = subprocess.run(["bash", "-c", script, "x", str(COMMON), d], env=env,
                                            capture_output=True, text=True, check=True).stdout.splitlines()
        for flag in (None, "", "0"):
            self.assertEqual(outs[flag], ["== repository", "  SKIP  namecheck (no scrub list)", "  PASS  sfab check clean",
                                          "  SKIP  a check (no list)"], flag)
        for flag in ("1", "yes"):
            self.assertEqual(outs[flag], ["== repository",
                                          "  FAIL  namecheck clean -> no scrub list, and SFAB_REQUIRE_NAMECHECK is set",
                                          "  PASS  sfab check clean",
                                          "  FAIL  a check clean -> no list, and SFAB_REQUIRE_NAMECHECK is set"], flag)


# ------------------------------------------------------------------------------------------------

MCLAG_BRIEF = """fe-sw1# show mclag brief

Domain ID            : 1
Role                 : active
Session Status       : up
Peer Link Status     : up
Source Address       : 10.20.255.0
Peer Address         : 10.20.255.1
Session Vrf          : VrfMclagKa
Peer Link            : PortChannel1
Keepalive Interval   : 1 secs
Session Timeout      : 30 secs
Delay Restore        : 300 secs
System Mac           : 0c:00:aa:bb:cc:06
Mclag System Mac     : 02:5a:00:00:00:01


Backup Keepalive Session Information:
-----------------------------------
Session Vrf          : VrfMclagKa
Session Status       : up
Source Address       : 10.20.255.4
Peer Address         : 10.20.255.5
Keepalive Interval   : 1 secs
-----------------------------------


Number of MLAG Interfaces:3
-----------------------------------------------------------
MLAG Interface       Local/Remote Status
-----------------------------------------------------------
PortChannel10            up/up
PortChannel21            up/up
PortChannel22            up/up
"""

PC_SUMMARY = """fe-sw1# show PortChannel summary
Flags(oper-status):  D - Down U - Up (portchannel) P - Up in portchannel (members) I - LACP individual
--------------------------------------------------------------------------------------------
Group               PortChannel                   Type                Protocol          Member Ports
--------------------------------------------------------------------------------------------
1                   PortChannel1   (U)            Eth                 LACP              Ethernet0(P)
                                                                                        Ethernet1(P)
10                  PortChannel10  (U)            Eth                 LACP              Ethernet2(P)
21                  PortChannel21  (U)            Eth                 LACP              Ethernet6(P)
22                  PortChannel22  (U)            Eth                 LACP              Ethernet7(P)
"""

SHOW_VLAN = """fe-sw1# show vlanVlan
Q: A - Access (Untagged), T - Tagged
NUM        Status      Q Ports            Autostate   Dynamic
100        Active      T  PortChannel1     Enable      No
                       T  PortChannel10                No
                       A  PortChannel21                No
                       A  PortChannel22                No
110        Active      T  PortChannel1     Enable      No
                       T  PortChannel10                No
120        Active      T  PortChannel1     Enable      No
                       T  PortChannel21                No
                       T  PortChannel22                No
130        Active      T  PortChannel1     Enable      No
                       T  PortChannel10                No
131        Active      T  PortChannel1     Enable      No
                       T  PortChannel10                No
200        Active      T  PortChannel1     Enable      No
                       T  PortChannel10                No
300        Active      T  PortChannel1     Enable      No
                       T  PortChannel10                No
3966       Active      T  PortChannel1     Enable      No
"""

IP_INTERFACES = """fe-sw1# show ip interfaces
Flags: U-Unnumbered interface, A-Anycast IP
-----------------------------------------------------------------------------------------
Interface            IP address/mask                              VRF                 Admin/Oper     Flags
-----------------------------------------------------------------------------------------
Management0          172.21.40.11/24                              mgmt                up/up
"""

BONDING = """Ethernet Channel Bonding Driver: v6.8.0

Bonding Mode: IEEE 802.3ad Dynamic link aggregation
Transmit Hash Policy: layer3+4 (1)
MII Status: up

802.3ad info
LACP active: on
LACP rate: fast
System MAC address: 02:5a:6f:00:00:01
Active Aggregator Info:
	Aggregator ID: 1
	Number of ports: 2
	Partner Mac Address: 02:5a:00:00:00:01

Slave Interface: eth1
MII Status: up
Aggregator ID: 1
details partner lacp pdu:
    system mac address: 02:5a:00:00:00:01

Slave Interface: eth2
MII Status: up
Aggregator ID: 1
details partner lacp pdu:
    system mac address: 02:5a:00:00:00:01
"""


class JudgeParsers(unittest.TestCase):
    def test_mclag(self):
        d = judge.p_mclag(MCLAG_BRIEF)
        self.assertEqual(d["Role"], "active")
        self.assertEqual(d["Session Vrf"], "VrfMclagKa")
        self.assertEqual(d["Source Address"], "10.20.255.0")
        self.assertEqual(d["_backup"], {"Session Vrf": "VrfMclagKa", "Session Status": "up", "Source Address": "10.20.255.4",
                                        "Peer Address": "10.20.255.5", "Keepalive Interval": "1 secs"}, "the backup block kept apart")
        self.assertEqual(d["_interfaces"], {"PortChannel10": "up/up", "PortChannel21": "up/up", "PortChannel22": "up/up"})

    def test_pc_summary(self):
        d = judge.p_pc_summary(PC_SUMMARY)
        self.assertEqual(d["PortChannel1"], {"state": "U", "members": {"Ethernet0": "P", "Ethernet1": "P"}})
        self.assertEqual(d["PortChannel22"]["members"], {"Ethernet7": "P"})

    def test_vlan(self):
        d = judge.p_vlan(SHOW_VLAN)
        self.assertEqual(d[100], {"PortChannel1": "T", "PortChannel10": "T", "PortChannel21": "A", "PortChannel22": "A"})
        self.assertEqual(sorted(d), [100, 110, 120, 130, 131, 200, 300, 3966])

    def test_ip_interfaces(self):
        self.assertEqual(judge.p_ip_interfaces(IP_INTERFACES),
                         [{"iface": "Management0", "addr": "172.21.40.11/24", "vrf": "mgmt"}])

    def test_revision2_switch_reads(self):
        """The reads build A revision 2 adds, in the forms SONiC 4.6.0 printed them in chapter 3's lab."""
        st = ("-" * 134 + "\nName                Description                   Oper        Reason         AutoNeg   Speed          MTU            Alternate Name      \n"
              + "-" * 134 + "\nEthernet0           peer-link-1                   up          oper-up          off       25000          9216           Eth1/1              \n"
              "Ethernet12          mclag-keepalive               up          oper-up          off       25000          9216           Eth1/13             \n"
              "Ethernet19          -                             down        admin-down       off       25000          9100           Eth1/20             \n")
        self.assertEqual(judge.p_if_status_mtu(st), {"Ethernet0": 9216, "Ethernet12": 9216, "Ethernet19": 9100})
        bg = ("PortNum          Shutdown    Port shut          \n                 Configured  due to BPDU guard  \n"
              "PortChannel11    Y           Y                  \nEthernet0        Y           N                  \n")
        self.assertEqual(judge.p_bpdu_guard(bg), {"PortChannel11": {"configured": "Y", "shut": "Y"}, "Ethernet0": {"configured": "Y", "shut": "N"}})
        sc = ("-----------------------------------------------------\nInterface Name      Storm-type          Rate (kbps)    \n"
              "-----------------------------------------------------\nEthernet0           broadcast           10000          \n"
              "Ethernet0           unknown-multicast   10000          \n")
        self.assertEqual(judge.p_storm(sc), {"Ethernet0": {"broadcast": 10000, "unknown-multicast": 10000}})
        rt = ("Codes:  K - kernel route, C - connected, S - static, B - BGP, O - OSPF, A - attached-host\n"
              "        > - selected route, * - FIB route, q - queued route, r - rejected route, b - backup\n"
              "       Destination        Gateway                                                                    Dist/Metric   Last Update \n"
              " C>*   10.20.255.4/31     Direct                          Vlan3966                                   0/0           00:14:35 ago\n")
        self.assertEqual(judge.p_routes_brief(rt), [("C", "10.20.255.4/31")])

    def test_bonding(self):
        b = judge.p_bonding(BONDING)
        self.assertEqual(b["active_agg"], 1)
        self.assertEqual(b["partner"], "02:5a:00:00:00:01")
        self.assertEqual({k: v["agg"] for k, v in b["slaves"].items()}, {"eth1": 1, "eth2": 1})

    def test_ping(self):
        p = judge.p_ping("3 packets transmitted, 3 received, +2 duplicates, 0% packet loss, time 2003ms")
        self.assertEqual((p["tx"], p["rx"], p["dup"]), (3, 3, 2))
        p = judge.p_ping("ping: local error: message too long, mtu=1500\n3 packets transmitted, 0 received, +3 errors")
        self.assertTrue(p["toolong"])
        self.assertIsNone(judge.p_ping("connect: Network is unreachable"))

    def test_blocks(self):
        run = "!\nip vrf mgmt\n!\ninterface Vlan100\n!\ninterface Vlan200\n ip address 10.20.2.9/24\n!\n"
        blocks = judge.p_blocks(run)
        self.assertIn(("ip vrf mgmt", []), blocks)
        self.assertIn(("interface Vlan200", ["ip address 10.20.2.9/24"]), blocks)

    def test_offloads(self):
        good = "== eth1\ngeneric-receive-offload: off\nrx-gro-hw: off [fixed]\nlarge-receive-offload: off [fixed]\n"
        self.assertEqual(judge.offload_problems(good, 1), [])
        self.assertTrue(judge.offload_problems(good.replace("receive-offload: off", "receive-offload: on", 1), 1))
        self.assertTrue(judge.offload_problems(good, 3))

    def test_split_session(self):
        session = ("fe-sw1# terminal length 0\nfe-sw1# show vlanVlan\nNUM  Status\n100  Active\n"
                   "fe-sw1# show ip route\nfe-sw1# show mclag brief\nRole : active\nfe-sw1# exit\n")
        outs = judge.split_session(session, ["show vlan", "show ip route", "show mclag brief", "show version"], "klish")
        self.assertEqual(outs[0], "fe-sw1# show vlanVlan\nNUM  Status\n100  Active\n")
        self.assertEqual(outs[1], "fe-sw1# show ip route\n")
        self.assertIn("Role : active", outs[2])
        self.assertIsNone(outs[3])
        outs = judge.split_session("admin@fw> show system info\nhostname: fw\nadmin@fw> exit\n", ["show system info"], "panos")
        self.assertIn("hostname: fw", outs[0])


@unittest.skipUnless(have_yaml(), "PyYAML renders the M1 inventory")
class JudgePlans(unittest.TestCase):
    def test_plans(self):
        inv = m1_inventory()
        plans = {n: judge.plan(inv, n) for n in inv["order"]}
        # 20 since M1, chapter 3's two pair reads (the ICCP socket and iccpd's keepalive state), and
        # revision 2's four: the keepalive VRF's table, spanning tree, BPDU guard, storm control
        self.assertEqual(len(plans["fe-sw1"]), 26)
        self.assertEqual([r["command"] for r in plans["fe-sw1"][-6:]],
                         ["sudo ss -tanp | grep 8888", "docker exec iccpd mclagdctl -i 1 dump state", "show ip route vrf VrfMclagKa",
                          "show running-configuration spanning-tree", "show spanning-tree bpdu-guard", "show storm-control"])
        # 14 since M1, chapter 4's show ntp (the firewall's own NTP through its service route), the
        # services and ingress subinterfaces (ae1.110, ae1.130, ae1.131), and the tunnels' SAs
        self.assertEqual(len(plans["fw"]), 20)
        self.assertEqual(plans["fw"][-1]["command"], "show ntp")
        self.assertIn("show vpn ike-sa", [r["command"] for r in plans["fw"]])
        self.assertEqual(len(plans["k8s-gpu1"]), 55, "with the BMC namespace's address and listeners")
        for n, p in plans.items():
            slugs = [r["slug"] for r in p]
            self.assertEqual(len(slugs), len(set(slugs)), n)
            self.assertEqual([r["nn"] for r in p], [f"{i:02d}" for i in range(1, len(p) + 1)])
            for r in p:
                self.assertNotIn("{", r["command"].replace("${", "").replace("$(", ""), f"{n}: {r['command']}")
        g = {r["slug"]: r["command"] for r in plans["k8s-gpu1"]}
        self.assertEqual(g["same_rail_3"], "ip netns exec gpu3 ping -c 3 -W 2 -M do -s 8972 10.21.3.12")
        self.assertEqual(g["cross_rail_8"], "ip netns exec gpu8 ping -c 3 -W 2 10.21.1.12")
        self.assertEqual(g["ping_oob_gw"], "sudo ip netns exec bmc ping -c 3 -W 2 10.20.9.254", "from the BMC stand-in's namespace")
        self.assertEqual(g["bmc_listen"], "sudo ip netns exec bmc ss -ltnH")
        self.assertEqual(g["table_mgmt"], "ip route show table 150")
        quick = judge.plan(inv, "fe-sw1", quick=True)
        self.assertTrue(0 < len(quick) < len(plans["fe-sw1"]))

    def _set(self, d, inv, role_override=None):
        """A result set where the pair is healthy."""
        for sw, me, peer, bme, bpeer, role in (("fe-sw1", "10.20.255.0", "10.20.255.1", "10.20.255.4", "10.20.255.5", "active"),
                                               ("fe-sw2", "10.20.255.1", "10.20.255.0", "10.20.255.5", "10.20.255.4", role_override or "standby")):
            p = Path(d) / sw
            p.mkdir(parents=True)
            text = MCLAG_BRIEF.replace("fe-sw1#", f"{sw}#")
            for a, b in (("10.20.255.0", "@ME"), ("10.20.255.1", "@PEER"), ("10.20.255.4", "@BME"), ("10.20.255.5", "@BPEER")):
                text = text.replace(a, b)
            for a, b in (("@ME", me), ("@PEER", peer), ("@BME", bme), ("@BPEER", bpeer)):
                text = text.replace(a, b)
            text = text.replace("Role                 : active", f"Role                 : {role}")
            (p / "18_mclag_brief.txt").write_text(text)
            (p / "19_portchannel_summary.txt").write_text(PC_SUMMARY.replace("fe-sw1#", f"{sw}#"))

    def _run(self, d, inv, group, nodes):
        invf = Path(d) / "inv.json"
        invf.write_text(json.dumps(inv))
        buf = io.StringIO()
        v = vocab.Vocab(verdict=None, known=set(inv["known"]), out=buf)
        j = judge.Judge(judge.ResultSet(d), inv, Path(d), v)
        getattr(j, judge.GROUPS[group])(nodes)
        return v.counts(), buf.getvalue()

    def test_mclag_pair_green_and_red(self):
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            self._set(d, inv)
            c, out = self._run(d, inv, "mclag-pair", ["fe-sw1", "fe-sw2"])
            self.assertEqual(c["fail"], 0, out)
            self.assertGreater(c["pass"], 20)
        with tempfile.TemporaryDirectory() as d:
            self._set(d, inv, role_override="active")
            c, out = self._run(d, inv, "mclag-pair", ["fe-sw1", "fe-sw2"])
            self.assertEqual(c["fail"], 1, out)
            self.assertIn("roles: one active, one standby", out)

    def _l2(self, d, inv, sw, tripped=(), mtu_off=(), storm_off=()):
        n = inv["nodes"][sw]
        p = Path(d) / sw
        p.mkdir(parents=True, exist_ok=True)
        (p / "30_running_stp.txt").write_text(f"{sw}# show running-configuration spanning-tree\nspanning-tree mode pvst\n")
        mtu = {}
        for name, pc in n["portchannels"].items():
            for mb in pc["members"]:
                mtu[mb] = pc["mtu"]
            mtu[name] = pc["mtu"]
        mtu[n["keepalive"]["port"]] = n["keepalive"]["mtu"]
        rows = [f"{k:<20}{'-':<30}{'up':<12}{'oper-up':<17}{'off':<10}{'25000':<15}{(9100 if k in mtu_off else v):<15}Eth1/1"
                for k, v in sorted(mtu.items())]
        (p / "13_interface_status.txt").write_text("\n".join([f"{sw}# show interface status", "-" * 134,
            "Name                Description                   Oper        Reason         AutoNeg   Speed          MTU            Alternate Name      ",
            "-" * 134] + rows) + "\n")
        (p / "31_bpdu_guard.txt").write_text("\n".join([f"{sw}# show spanning-tree bpdu-guard", "PortNum          Shutdown    Port shut          ",
            "                 Configured  due to BPDU guard  "] + [f"{e:<17}Y           {'Y' if e in tripped else 'N'}" for e in n["edge"]]) + "\n")
        st = [f"{pt:<20}{t:<20}{k}" for pt in n["storm"]["ports"] if pt not in storm_off for t, k in sorted(n["storm"]["kbps"].items())]
        (p / "32_storm_control.txt").write_text("\n".join([f"{sw}# show storm-control", "-" * 53,
            "Interface Name      Storm-type          Rate (kbps)    ", "-" * 53] + st) + "\n")

    def test_l2_hygiene_green_and_red(self):
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            self._l2(d, inv, "fe-sw1")
            c, out = self._run(d, inv, "l2-hygiene", ["fe-sw1"])
            self.assertEqual(c["fail"], 0, out)
            self.assertIn("  PASS  BPDU guard with port-shutdown on every edge port (2)", out)
            self.assertIn("  PASS  every used port (6) at its rendered MTU (9216)", out)
        with tempfile.TemporaryDirectory() as d:
            self._l2(d, inv, "fe-sw1", tripped=("PortChannel21",), mtu_off=("Ethernet6",), storm_off=("Ethernet7",))
            c, out = self._run(d, inv, "l2-hygiene", ["fe-sw1"])
            self.assertEqual(c["fail"], 3, out)
            self.assertIn("  FAIL  no port shut by BPDU guard -> PortChannel21", out)
            self.assertIn("Ethernet6 9100", out)
            self.assertIn("Ethernet7 broadcast absent", out)

    def test_mclag_pair_except_peers(self):
        # boot's wait_fabric runs while the guests are held: their PortChannels are down and set aside
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            self._set(d, inv)
            for sw in ("fe-sw1", "fe-sw2"):
                f = Path(d) / sw / "19_portchannel_summary.txt"
                f.write_text(f.read_text().replace("PortChannel21  (U)", "PortChannel21  (D)").replace("Ethernet6(P)", "Ethernet6(D)"))
            c, out = self._run(d, inv, "mclag-pair", ["fe-sw1", "fe-sw2"])
            self.assertEqual(c["fail"], 2, out)
            invf = Path(d) / "inv.json"
            buf = io.StringIO()
            v = vocab.Vocab(verdict=None, known=set(inv["known"]), out=buf)
            j = judge.Judge(judge.ResultSet(d), inv, Path(d), v, except_peers=["k8s-gpu1", "k8s-gpu2"])
            j.g_mclag(["fe-sw1", "fe-sw2"])
            self.assertEqual(v.counts()["fail"], 0, buf.getvalue())
            self.assertNotIn("PortChannel21", buf.getvalue())
            self.assertIn("PortChannel10 up with Ethernet2", buf.getvalue())
            self.assertTrue(invf.is_file())

    def test_missing_files_fail(self):
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "rail-sw1").mkdir()
            c, out = self._run(d, inv, "forwarding-only", ["rail-sw1"])
            self.assertGreater(c["fail"], 3, out)
            self.assertEqual(c["pass"], 0, out)
            self.assertIn("not collected", out)

    def test_vlans_and_mac_table(self):
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fe-sw1"
            p.mkdir()
            (p / "11_vlan.txt").write_text(SHOW_VLAN)
            mac = ("fe-sw1# show mac address-table\n"
                   "1           aa:c1:ab:00:00:01   DYNAMIC       PortChannel10\n"
                   "100         02:5a:6f:00:00:01   DYNAMIC       PortChannel21\n"
                   "100         0c:00:11:22:33:44   DYNAMIC       PortChannel10\n")
            (p / "12_mac_table.txt").write_text(mac)
            c, out = self._run(d, inv, "vlans", ["fe-sw1"])
            self.assertEqual(c["fail"], 0, out)
            c, out = self._run(d, inv, "mac-tables", ["fe-sw1"])
            self.assertEqual(c["fail"], 0, out)
            (p / "12_mac_table.txt").write_text(mac + "200         0c:00:99:99:99:99   DYNAMIC       PortChannel1\n")
            c, out = self._run(d, inv, "mac-tables", ["fe-sw1"])
            self.assertEqual(c["fail"], 1, out)

    def test_mac_table_sets_bond_slaves_own_macs_aside(self):
        # A container's bond slave shows its bond's MAC in ip link, but sends its LACPDUs from its
        # own (ip -d: linkinfo.info_slave_data.perm_hwaddr), which the switch learns (M2's bastion).
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "fe-sw1"
            p.mkdir()
            (p / "12_mac_table.txt").write_text("fe-sw1# show mac address-table\n"
                                                "300         aa:c1:ab:4d:33:d2   DYNAMIC       PortChannel21\n")
            c, out = self._run(d, inv, "mac-tables", ["fe-sw1"])
            self.assertEqual(c["fail"], 1, out)
            g = Path(d) / "k8s-gpu1"
            g.mkdir()
            (g / "10_container_links.json").write_text(json.dumps([
                {"ifname": "bond0", "address": "aa:c1:ab:6a:9b:e4"},
                {"ifname": "eth2", "address": "aa:c1:ab:6a:9b:e4",
                 "linkinfo": {"info_slave_kind": "bond", "info_slave_data": {"perm_hwaddr": "aa:c1:ab:4d:33:d2"}}}]))
            c, out = self._run(d, inv, "mac-tables", ["fe-sw1"])
            self.assertEqual(c["fail"], 0, out)
            self.assertIn("1 VLAN 1 or container veth entries set aside", out)

    def test_mac_table_knows_the_relay_macvlans(self):
        # A rail switch learns the relay namespaces' macvlan MACs, which only gen/expect names.
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "rail-sw1"
            p.mkdir()
            (p / "11_mac_table.txt").write_text("rail-sw1# show mac address-table\n"
                                               "101         02:5a:6f:00:00:04   DYNAMIC       Ethernet0\n"
                                               "101         02:5a:6f:01:00:04   DYNAMIC       Ethernet0\n")
            c, out = self._run(d, inv, "mac-tables", ["rail-sw1"])
            self.assertEqual(c["fail"], 1, out)
            (Path(d) / "gen" / "expect").mkdir(parents=True)
            (Path(d) / "gen" / "expect" / "rail-sw1.json").write_text(json.dumps(
                {"known_macs": {"02:5a:6f:01:00:04": {"node": "k8s-gpu1", "source": "relay-macvlan", "via": "Ethernet0", "vlan": 101}}}))
            c, out = self._run(d, inv, "mac-tables", ["rail-sw1"])
            self.assertEqual(c["fail"], 0, out)

    def test_rails(self):
        inv = m1_inventory()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "k8s-gpu1"
            p.mkdir()
            plan = {r["slug"]: r for r in judge.plan(inv, "k8s-gpu1")}

            def put(slug, text):
                r = plan[slug]
                (p / f"{r['nn']}_{slug}{r['ext']}").write_text(text)

            put("netns_list", "\n".join(f"gpu{r} (id: {r})" for r in range(1, 9)))
            for r in range(1, 9):
                nxt = r % 8 + 1
                put(f"ns_routes_{r}", f"10.21.{nxt}.0/24 via 10.21.250.{nxt} dev relay src 10.21.{r}.11\n10.21.{r}.0/24 dev rail{r} proto kernel")
                put(f"ns_rpf_{r}", f"all 0\ndefault 2\nlo 0\nrail{r} 2\nrelay 2")
                put(f"same_rail_{r}", "3 packets transmitted, 3 received, 0% packet loss")
                put(f"cross_rail_{r}", "3 packets transmitted, 3 received, +1 duplicates, 0% packet loss")
                put(f"cross_route_{r}", f"10.21.{nxt}.12 via 10.21.250.{nxt} dev relay src 10.21.{r}.11 uid 0")
            c, out = self._run(d, inv, "rails", ["k8s-gpu1"])
            self.assertEqual(c["fail"], 0, out)
            self.assertEqual(c["known"], 8, out)
            put("ns_routes_4", "default via 10.21.4.1 dev rail4")
            put("cross_route_2", "10.21.3.12 dev rail2 src 10.21.2.11 uid 0")
            c, out = self._run(d, inv, "rails", ["k8s-gpu1"])
            self.assertEqual(c["fail"], 2, out)


# ------------------------------------------------------------------------------------------------


# Stand-in values: every password, API key, token, hash, key block and redaction key in the redact
# tests below is made up for the test and was never a real credential.
STANDIN_REDACT_KEY = "0123456789abcdef" * 4


def write_redact_key(d, value=STANDIN_REDACT_KEY) -> Path:
    k = Path(d) / "secrets" / "redact.key"
    k.parent.mkdir(parents=True, exist_ok=True)
    k.write_text(value + "\n")
    return k


class RedactTest(unittest.TestCase):
    def test_redacts_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / "secrets.env"
            env.write_text("SFAB_SW_PASSWORD=Abc123Def456Ghi789Jk\nSFAB_SW_USER=admin\n")
            key = write_redact_key(d)
            s = Path(d) / "set"
            s.mkdir()
            f = s / "commands.txt"
            f.write_text("password Abc123Def456Ghi789Jk\nAuthorization: Bearer sk-tw-chat-0123456789abcdef0123\n"
                         "X-PAN-KEY: LUFRPT1abcdefghijklmnop==\nGET /api/?type=op&key=LUFRPTzzzz&cmd=x\n"
                         "set mgt-config users admin phash $5$abc$def\n"
                         "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\nadmin stays\n")
            redact.main(["--secrets", str(env), "--key", str(key), str(s)])
            t = f.read_text()
            for secret in ("Abc123Def456Ghi789Jk", "sk-tw-chat", "LUFRPT1", "LUFRPTzzzz", "$5$abc$def", "MIIEvQ"):
                self.assertNotIn(secret, t)
            self.assertIn("<redacted hmac:", t)
            self.assertNotIn("<redacted sha256:", t)
            self.assertIn("admin stays", t)
            once = t
            redact.main(["--secrets", str(env), "--key", str(key), str(s)])
            self.assertEqual(f.read_text(), once)

    def test_user_names_are_not_secrets(self):
        # SFAB_*_USER values are the platforms' administrators: a transcript keeps them
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / "secrets.env"
            env.write_text("SFAB_TRUENAS_USER=truenas_admin\nSFAB_TRUENAS_PASSWORD=Xyz123Def456Ghi789Jk\n")
            key = write_redact_key(d)
            s = Path(d) / "set"
            s.mkdir()
            f = s / "commands.txt"
            f.write_text("login truenas_admin with Xyz123Def456Ghi789Jk\n")
            redact.main(["--secrets", str(env), "--key", str(key), str(s)])
            t = f.read_text()
            self.assertIn("login truenas_admin with <redacted hmac:", t)
            self.assertNotIn("Xyz123Def456Ghi789Jk", t)

    def test_marks_are_keyed(self):
        # a mark is the value's HMAC under the lab's key: the same in every set of the lab, another
        # under another key, and never the value's plain sha256, which anyone could test a guess against
        pw = "Abc123Def456Ghi789Jk"
        plain = hashlib.sha256(pw.encode()).hexdigest()[:12]
        keyed = hmac.new(STANDIN_REDACT_KEY.encode(), pw.encode(), hashlib.sha256).hexdigest()[:12]
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / "secrets.env"
            env.write_text(f"SFAB_SW_PASSWORD={pw}\n")
            key = write_redact_key(Path(d) / "a")
            other = write_redact_key(Path(d) / "b", "fedcba9876543210" * 4)
            marks = {}
            for name, k in (("one", key), ("two", key), ("other", other), ("none", Path(d) / "absent.key"),
                            ("short", write_redact_key(Path(d) / "c", "0123456789"))):
                s = Path(d) / "sets" / name
                s.mkdir(parents=True)
                (s / "commands.txt").write_text(f"password {pw}\n")
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(redact.main(["--secrets", str(env), "--key", str(k), "--host-kernel", "", str(s)]), 0)
                t = (s / "commands.txt").read_text()
                self.assertNotIn(pw, t)
                m = re.fullmatch(r"password <redacted hmac:([0-9a-f]{12})>\n", t)
                self.assertIsNotNone(m, t)
                marks[name] = m.group(1)
                self.assertEqual("no redaction key" in err.getvalue(), name in ("none", "short"), err.getvalue())
            self.assertEqual(marks["one"], keyed)
            self.assertEqual(marks["two"], keyed, "the same key gives the same mark in every set")
            self.assertNotEqual(marks["other"], keyed)
            self.assertNotIn(plain, marks.values(), "no mark is the plain sha256 prefix")
            self.assertNotIn(marks["none"], (keyed, marks["other"]), "without a key the run uses one of its own")

    def test_stream_uses_the_key(self):
        pw = "Abc123Def456Ghi789Jk"
        with tempfile.TemporaryDirectory() as d:
            env = Path(d) / "secrets.env"
            env.write_text(f"SFAB_TRUENAS_PASSWORD={pw}\n")
            key = write_redact_key(d)
            r = subprocess.run([sys.executable, str(COMMON / "audit" / "redact.py"), "--secrets", str(env), "--key", str(key),
                                "--host-kernel", "", "--stream"], input=f"INFO PASSWORD: {pw}\n", capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout, f"INFO PASSWORD: {redact.mark(pw, STANDIN_REDACT_KEY.encode())}\n")
        self.assertEqual(r.stderr, "")

    def test_host_cpuid(self):
        # stand-in values: a made-up CPU signature
        with tempfile.TemporaryDirectory() as d:
            s = Path(d) / "audits" / "x_audit_20261021T000000Z"
            (s / "fw").mkdir(parents=True)
            f = s / "fw" / "04_system_info.txt"
            f.write_text("vm-mac-base: ba:db:ee:fb:ad:00\r\nvm-cpuid: KVM:0123456789ABCDEF\r\nvm-license: none\r\n")
            (s / "commands.txt").write_text("admin@fw> show system info\n\nvm-cpuid: KVM:0123456789ABCDEF\n")
            key = write_redact_key(d)
            self.assertEqual(redact.main(["--secrets", str(Path(d) / "absent.env"), "--key", str(key), "--host-kernel", "",
                                          str(s)]), 0)
            m = "[redacted: host-cpuid]"
            self.assertEqual(f.read_bytes().decode(), f"vm-mac-base: ba:db:ee:fb:ad:00\r\nvm-cpuid: {m}\r\nvm-license: none\r\n")
            self.assertEqual((s / "commands.txt").read_text(), f"admin@fw> show system info\n\nvm-cpuid: {m}\n")
            led = (s / "REDACTIONS.md").read_text()
            self.assertIn(redact.redact_tree_mod.INTRO["recorded"], led)
            self.assertIn("| fw/04_system_info.txt | 2 | host-cpuid |", led)
            self.assertIn("| commands.txt | 3 | host-cpuid |", led)
            self.assertNotIn("0123456789ABCDEF", led)
            self.assertEqual(redact.redact_text("<vm-cpuid>KVM:0123456789ABCDEF</vm-cpuid>\n", []),
                             f"<vm-cpuid>{m}</vm-cpuid>\n")
            self.assertEqual(redact.redact_text(f"vm-cpuid: {m}\n", []), f"vm-cpuid: {m}\n")


# a stand-in for the lab host's kernel release: a version and a two-part build suffix
HOST_KERNEL = "9.9.9-stand-in+"
# a VM's own kernel, which a recording keeps
GUEST_KERNEL = "6.8.0-138-generic"


class RedactHostKernelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.env = self.d / "secrets.env"
        self.env.write_text("SFAB_SW_PASSWORD=Abc123Def456Ghi789Jk\n")
        self.set = self.d / "audits" / "x_audit_20261021T000000Z"
        for n in ("bastion", "uplink-rtr", "k8s-gpu1"):
            (self.set / n).mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def redact(self, *extra):
        return redact.main(["--secrets", str(self.env), "--key", str(write_redact_key(self.d)), *extra, str(self.set)])

    def files(self):
        return {p: p.read_bytes() for p in self.set.rglob("*") if p.is_file()}

    def test_replaces_the_hosts_release_and_keeps_a_vms(self):
        bond = self.set / "bastion" / "02_bonding.txt"
        bond.write_text(f"Ethernet Channel Bonding Driver: v{HOST_KERNEL}\n\nBonding Mode: IEEE 802.3ad Dynamic link aggregation\n")
        frr = self.set / "uplink-rtr" / "01_frr_version.txt"
        frr.write_text(f"FRRouting 10.5.4_git (uplink-rtr) on Linux({HOST_KERNEL}).\nCopyright 1996-2005 Kunihiro Ishiguro, et al.\n")
        vm = self.set / "k8s-gpu1" / "02_bonding.txt"
        vm.write_text(f"Ethernet Channel Bonding Driver: v{GUEST_KERNEL}\n")
        other = self.set / "commands.txt"
        other.write_text(f"Linux bastion {HOST_KERNEL} #1 SMP x86_64\n/lib/modules/{HOST_KERNEL}/kernel\n"
                         f"{HOST_KERNEL}x stays\nabcv{HOST_KERNEL} stays\npassword Abc123Def456Ghi789Jk\n")
        self.assertEqual(self.redact("--host-kernel", HOST_KERNEL), 0)
        m = "[redacted: host-kernel]"
        self.assertEqual(bond.read_text().splitlines()[0], f"Ethernet Channel Bonding Driver: v{m}")
        self.assertEqual(bond.read_text().count("\n"), 3, "no line added or removed")
        self.assertEqual(frr.read_text().splitlines(), [f"FRRouting 10.5.4_git (uplink-rtr) on Linux({m}).",
                                                        "Copyright 1996-2005 Kunihiro Ishiguro, et al."])
        self.assertEqual(vm.read_text(), f"Ethernet Channel Bonding Driver: v{GUEST_KERNEL}\n", "a VM's kernel stays")
        self.assertEqual(other.read_text().splitlines()[:4], [f"Linux bastion {m} #1 SMP x86_64", f"/lib/modules/{m}/kernel",
                                                              f"{HOST_KERNEL}x stays", f"abcv{HOST_KERNEL} stays"])
        self.assertIn("<redacted hmac:", other.read_text(), "the secrets pass still runs")
        led = (self.set / "REDACTIONS.md").read_text()
        self.assertIn(redact.redact_tree_mod.INTRO["recorded"], led)
        for row in ("| bastion/02_bonding.txt | 1 | host-kernel |", "| uplink-rtr/01_frr_version.txt | 1 | host-kernel |",
                    "| commands.txt | 1 | host-kernel |", "| commands.txt | 2 | host-kernel |"):
            self.assertIn(row, led)
        self.assertNotIn("k8s-gpu1", led)
        self.assertNotIn(HOST_KERNEL, led)
        once = self.files()
        self.assertEqual(self.redact("--host-kernel", HOST_KERNEL), 0)
        self.assertEqual(self.files(), once, "a second run changes nothing, the ledger included")

    def test_the_release_and_switching_it_off(self):
        self.assertIsNone(redact.host_kernel(""))
        self.assertIsNone(redact.host_kernel("6"), "a string without a dot is not a release")
        self.assertEqual(redact.host_kernel(f" {HOST_KERNEL}\n"), HOST_KERNEL)
        with unittest.mock.patch.dict(os.environ, {"SFAB_HOST_KERNEL": HOST_KERNEL}):
            self.assertEqual(redact.host_kernel(), HOST_KERNEL)
            self.assertIsNone(redact.host_kernel(""), "--host-kernel '' wins over the environment")
        with unittest.mock.patch.dict(os.environ, {"SFAB_HOST_KERNEL": ""}):
            self.assertIsNone(redact.host_kernel())
        env = {k: v for k, v in os.environ.items() if k != "SFAB_HOST_KERNEL"}
        with unittest.mock.patch.dict(os.environ, env, clear=True):
            with unittest.mock.patch.object(redact.sys, "platform", "darwin"):
                self.assertIsNone(redact.host_kernel(), "no lab host kernel off Linux")
            with unittest.mock.patch.object(redact.sys, "platform", "linux"), \
                    unittest.mock.patch.object(redact.os, "uname", return_value=os.uname_result(("Linux", "h", HOST_KERNEL, "#1", "x86_64"))):
                self.assertEqual(redact.host_kernel(), HOST_KERNEL, "on Linux the running kernel's")
        f = self.set / "bastion" / "02_bonding.txt"
        f.write_text(f"Ethernet Channel Bonding Driver: v{HOST_KERNEL}\n")
        self.assertEqual(self.redact("--host-kernel", ""), 0)
        self.assertIn(HOST_KERNEL, f.read_text())
        self.assertFalse((self.set / "REDACTIONS.md").exists(), "no marker, no ledger")

    def test_stream_and_bytes(self):
        k = redact.kernel_rx(HOST_KERNEL)
        self.assertEqual(redact.redact_text(f"on Linux({HOST_KERNEL}).\n", [], k), "on Linux([redacted: host-kernel]).\n")
        self.assertEqual(redact.redact_text(f"on Linux({HOST_KERNEL}).\n", []), f"on Linux({HOST_KERNEL}).\n")
        f = self.set / "bastion" / "01_session.txt"
        f.write_bytes(b"caf\xe9 \xff\r\nEthernet Channel Bonding Driver: v" + HOST_KERNEL.encode() + b"\r\nend")
        self.assertEqual(self.redact("--host-kernel", HOST_KERNEL), 0)
        self.assertEqual(f.read_bytes(), b"caf\xe9 \xff\r\nEthernet Channel Bonding Driver: v[redacted: host-kernel]\r\nend",
                         "bytes that are not UTF-8 and CRLF endings are written back as they were")

    def test_after_a_hyphen_underscore_or_slash(self):
        # the boot image path a container reads from the host's /proc/cmdline, a package name and an
        # identifier: the release is replaced; a longer release that holds it is kept
        k = redact.kernel_rx(HOST_KERNEL)
        m = "[redacted: host-kernel]"
        for text, want in ((f"BOOT_IMAGE=/boot/vmlinuz-{HOST_KERNEL} root=UUID=x ro", f"BOOT_IMAGE=/boot/vmlinuz-{m} root=UUID=x ro"),
                           (f"ii  linux-image-{HOST_KERNEL}  amd64", f"ii  linux-image-{m}  amd64"),
                           (f"kver_{HOST_KERNEL}=1", f"kver_{m}=1"),
                           (f'{{"kernel": "{HOST_KERNEL}"}}', f'{{"kernel": "{m}"}}'),
                           (f"release={HOST_KERNEL}: x", f"release={m}: x"),
                           (f"1{HOST_KERNEL} stays", f"1{HOST_KERNEL} stays"),
                           (f"x.{HOST_KERNEL} stays", f"x.{HOST_KERNEL} stays"),
                           (f"{HOST_KERNEL}lts stays", f"{HOST_KERNEL}lts stays"),
                           (f"linux-image-{HOST_KERNEL}1 stays", f"linux-image-{HOST_KERNEL}1 stays")):
            self.assertEqual(redact.redact_text(text, [], k), want, text)

    def test_no_audit_records_a_kernel_log(self):
        # redact.py replaces the release only, never the rest of the host's /proc/version (its
        # builder's user@host): no command a lab runs may read it, or the kernel's log
        rx = re.compile(r"/proc/version|\bdmesg\b|journalctl\s+(?:-k|--dmesg)|/var/log/kern")
        skip = {COMMON / "audit" / "redact.py", Path(__file__).resolve()}
        for p in codefiles.files(ROOT, (".git", "audits")):
            if p.suffix not in (".list", ".sh", ".py", ".yaml", ".yml", "") or p.resolve() in skip:
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            with self.subTest(path=p.relative_to(ROOT).as_posix()):
                self.assertIsNone(rx.search(text))

    def test_compressed_file_redacted_and_written_back_compressed(self):
        import gzip
        f = self.set / "uplink-rtr" / "01_frr_version.json.gz"
        f.write_bytes(gzip.compress(f'{{"line": "on Linux({HOST_KERNEL})"}}\n'.encode(), mtime=0))
        self.assertEqual(self.redact("--host-kernel", HOST_KERNEL), 0)
        self.assertEqual(gzip.decompress(f.read_bytes()), b'{"line": "on Linux([redacted: host-kernel])"}\n')
        self.assertIn("| uplink-rtr/01_frr_version.json.gz | 1 | host-kernel |", (self.set / "REDACTIONS.md").read_text())

    def test_ledger_says_both_after_a_later_redaction(self):
        import redact_tree
        r = self.set / "ops-client"
        r.mkdir()
        (r / "07_resolv_conf.txt").write_text("search [redacted: host-search-domain]\n")
        (self.set / "REDACTIONS.md").write_text(redact_tree.ledger_text([("ops-client/07_resolv_conf.txt", 1, "host-search-domain")]))
        (self.set / "bastion" / "02_bonding.txt").write_text(f"Ethernet Channel Bonding Driver: v{HOST_KERNEL}\n")
        self.assertEqual(self.redact("--host-kernel", HOST_KERNEL), 0)
        led = (self.set / "REDACTIONS.md").read_text()
        self.assertIn(redact_tree.INTRO["both"], led)
        self.assertIn("| ops-client/07_resolv_conf.txt | 1 | host-search-domain |", led)
        self.assertIn("| bastion/02_bonding.txt | 1 | host-kernel |", led)


class TypescriptTest(unittest.TestCase):
    """common/tools/typescript.py: a typescript as a plain journal, through redact.py's rules."""

    TOOL = COMMON / "tools" / "typescript.py"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.set = self.d / "audits" / "x_rerecord-run_20261021T000000Z"
        self.set.mkdir(parents=True)
        self.env = self.d / "secrets.env"
        self.env.write_text("SFAB_SW_PASSWORD=Abc123Def456Ghi789Jk\n")  # stand-in values: a made-up password

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, src: Path, dst: Path):
        return subprocess.run([sys.executable, str(self.TOOL), "--secrets", str(self.env), "--key", str(write_redact_key(self.d)),
                               "--host-kernel", HOST_KERNEL, str(src), str(dst)], capture_output=True, text=True, timeout=60)

    def test_plain_journal_redacted(self):
        src = self.d / "rec-make-up.typescript"
        src.write_bytes(b"\x1b[1m== uplink-rtr: router\x1b[0m\r\n"
                        b"  FAIL  FRR 10.5.4 running -> FRRouting 10.4.1 (uplink-rtr) on Linux(" + HOST_KERNEL.encode() + b").\r\n"
                        b"progress 10%\rprogress 100%\r\n"
                        b"password Abc123Def456Ghi789Jk\r\n")
        dst = self.set / "rec-make-up.txt"
        r = self.run_tool(src, dst)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = dst.read_text().splitlines()
        self.assertEqual(lines[:3], ["== uplink-rtr: router",
                                     "  FAIL  FRR 10.5.4 running -> FRRouting 10.4.1 (uplink-rtr) on Linux([redacted: host-kernel]).",
                                     "progress 100%"])
        self.assertTrue(lines[3].startswith("password <redacted hmac:"), lines[3])
        self.assertNotIn(HOST_KERNEL, dst.read_text())
        led = (self.set / "REDACTIONS.md").read_text()
        self.assertIn(redact.redact_tree_mod.INTRO["recorded"], led)
        self.assertIn("| rec-make-up.txt | 2 | host-kernel |", led)
        self.assertNotIn(HOST_KERNEL, led)

    def test_outside_a_set_no_ledger(self):
        src = self.d / "t.typescript"
        src.write_bytes(b"plain line\r\n")
        r = self.run_tool(src, self.d / "t.txt")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.d / "t.txt").read_text(), "plain line\n")
        self.assertFalse(list(self.d.rglob("REDACTIONS.md")))


class RedactThroughputTest(unittest.TestCase):
    """A measured throughput figure becomes [redacted: throughput] while a set is recorded. The
    figures in these fixtures are made up."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.set = self.d / "audits" / "x_settle_20261021T000000Z"
        (self.set / "settle").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def redact(self):
        return redact.main(["--secrets", str(self.d / "absent.env"), "--key", str(write_redact_key(self.d)),
                            "--host-kernel", "", str(self.set)])

    def test_replaces_the_figures_and_keeps_the_rest(self):
        f = self.set / "settle" / "4-tcp-off-bond0.txt"
        f.write_text("[ ID] Interval           Transfer     Bitrate         Retr  Cwnd\n"
                     "[  5]   0.00-1.00   sec   111 MBytes  1.11 Gbits/sec  12     64.0 KBytes       \n"
                     "[  5]   0.00-3.00   sec  1.11 GBytes  2.22 Gbits/sec  34               sender\n"
                     "[  5]   0.00-3.00   sec  1.11 GBytes  2.22 Gbits/sec                  receiver\n"
                     "[  5]   0.00-3.00   sec  11.1 KBytes  22.2 Kbits/sec  0.010 ms  0/9 (0%)  receiver\n"
                     "10 seconds input rate 0 packets/sec, 888 bits/sec, 111 Bytes/sec\n"
                     "an 8-stream run printed 3.33 Gbit/s\n"
                     "Speed: 10000 Mbps\nthe members at 10000 Mb/s full duplex\n")
        v = self.set / "verdict.txt"
        v.write_text("  PASS  TCP k8s-gpu1 to k8s-gpu2 over bond0: iperf3 receiver 4.44 Gbits/sec, 56 retransmits\n")
        self.assertEqual(self.redact(), 0)
        m = "[redacted: throughput]"
        self.assertEqual(f.read_text().splitlines(), [
            "[ ID] Interval           Transfer     Bitrate         Retr  Cwnd",
            f"[  5]   0.00-1.00   sec   {m}  12     64.0 KBytes       ",
            f"[  5]   0.00-3.00   sec  {m}  34               sender",
            f"[  5]   0.00-3.00   sec  {m}                  receiver",
            f"[  5]   0.00-3.00   sec  {m}  0.010 ms  0/9 (0%)  receiver",
            f"10 seconds input rate 0 packets/sec, {m}, {m}",
            f"an 8-stream run printed {m}",
            "Speed: 10000 Mbps", "the members at 10000 Mb/s full duplex"],
            "retransmits, the window, packet rates and configured speeds are kept")
        self.assertEqual(v.read_text(), f"  PASS  TCP k8s-gpu1 to k8s-gpu2 over bond0: iperf3 receiver {m}, 56 retransmits\n")
        led = (self.set / "REDACTIONS.md").read_text()
        self.assertIn(redact.redact_tree_mod.INTRO["recorded"], led)
        for n in (2, 3, 4, 5, 6, 7):
            self.assertIn(f"| settle/4-tcp-off-bond0.txt | {n} | throughput |", led)
        self.assertIn("| verdict.txt | 1 | throughput |", led)
        for n in (1, 8, 9):
            self.assertNotIn(f"| settle/4-tcp-off-bond0.txt | {n} |", led)
        self.assertNotIn("bits/sec", led)
        once = {p: p.read_bytes() for p in self.set.rglob("*") if p.is_file()}
        self.assertEqual(self.redact(), 0)
        self.assertEqual({p: p.read_bytes() for p in self.set.rglob("*") if p.is_file()}, once,
                         "a second run changes nothing, the ledger included")

    def test_byte_rates_and_lowercase_forms(self):
        # the rates other tools print (dd, scp, apt, fio, rsync), made up; link speeds are kept
        m = "[redacted: throughput]"
        for text, want in (("copied, 2.1 GB/s", f"copied, {m}"), ("100%  512MB  11.2MB/s   00:45", f"100%  512MB  {m}   00:45"),
                           ("Fetched 61.5 MB in 10s (6150 kB/s)", f"Fetched 61.5 MB in 10s ({m})"),
                           ("bw=123MiB/s (129MB/s)", f"bw={m} ({m})"), ("2468.00 bytes/sec", m),
                           ("3.2 Gbits/s", m), ("12 kbit/s", m), ("5 B/s", m), ("22.2 Kbits/sec", m),
                           ("Speed: 10000Mb/s", "Speed: 10000Mb/s"), ("10000 Mb/s full duplex", "10000 Mb/s full duplex"),
                           ("a 10000 Mbps link", "a 10000 Mbps link"), ("0 packets/sec", "0 packets/sec"),
                           ("3 MB/sync", "3 MB/sync")):
            self.assertEqual(redact.redact_text(text, []), want, text)

    def test_firewall_session_info_throughput(self):
        # PAN-OS show session info's rate line; its packet and connection rates and a configured rate are kept
        m = "[redacted: throughput]"
        text = ("Packet rate:                                     6/s\nThroughput:                                      5 kbps\n"
                "New connection establish rate:                   0 cps\nInterface Name      Storm-type          Rate (kbps)\n")
        want = ("Packet rate:                                     6/s\nThroughput:                                      " + m + "\n"
                "New connection establish rate:                   0 cps\nInterface Name      Storm-type          Rate (kbps)\n")
        self.assertEqual(redact.redact_text(text, []), want)
        self.assertEqual(redact.redact_text(want, []), want, "a second run changes nothing")
        self.assertEqual(redact.redact_text("Throughput: 1.5 Mbps\r\n", []), f"Throughput: {m}\r\n")

    def test_never_joins_lines(self):
        self.assertEqual(redact.redact_text("111 MBytes\n1.11 Gbits/sec\n", []), "111 MBytes\n[redacted: throughput]\n")
        self.assertEqual(redact.redact_text("111 MBytes\r\n", []), "111 MBytes\r\n")


class SecretsTest(unittest.TestCase):
    def test_ensure_check_idempotent(self):
        if not shutil.which("ssh-keygen"):
            self.skipTest("no ssh-keygen")
        with tempfile.TemporaryDirectory() as d:
            st = os.path.join(d, "state")
            run = lambda *a: subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), *a, "--state", st],
                                            capture_output=True, text=True)
            self.assertEqual(run("ensure", "--lab", "sfab-m1").returncode, 0)
            env = Path(st) / "secrets.env"
            self.assertEqual(stat.S_IMODE(env.stat().st_mode), 0o600)
            first = env.read_text()
            vals = dict(l.split("=", 1) for l in first.splitlines() if "=" in l)
            self.assertRegex(vals["SFAB_KUBEADM_TOKEN"], r"^[a-z0-9]{6}\.[a-z0-9]{16}$")
            self.assertRegex(vals["SFAB_KUBEADM_CERT_KEY"], r"^[0-9a-f]{64}$")
            self.assertRegex(vals["SFAB_SW_PASSWORD"], r"^[A-Za-z0-9]{20}$")
            self.assertRegex(vals["SFAB_TRUENAS_PASSWORD"], r"^[A-Za-z0-9]{20}$")
            # the PA-VM keeps containerlab's paloalto_panos default login: no firewall credential is made
            self.assertEqual([k for k in vals if k.startswith("SFAB_FW_")], [])
            self.assertEqual(vals["SFAB_TRUENAS_USER"], "truenas_admin")
            self.assertEqual(vals["SFAB_ONTAP_USER"], "admin")
            key = Path(st) / "secrets" / "lab_ed25519"
            self.assertTrue(key.is_file())
            self.assertEqual(stat.S_IMODE(key.stat().st_mode), 0o600)
            rkey = Path(st) / "secrets" / "redact.key"
            self.assertRegex(rkey.read_text(), r"^[0-9a-f]{64}\n$")
            self.assertEqual(stat.S_IMODE(rkey.stat().st_mode), 0o600)
            self.assertIsNotNone(redact.read_key(str(rkey)))
            rfirst = rkey.read_text()
            self.assertEqual(run("ensure", "--lab", "sfab-m1").returncode, 0)
            self.assertEqual(env.read_text(), first)
            self.assertEqual(rkey.read_text(), rfirst, "ensure never replaces the redaction key")
            self.assertEqual(run("check").returncode, 0)
            # a lab made before the redaction key existed still passes check; ensure makes the key
            rkey.unlink()
            self.assertEqual(run("check").returncode, 0)
            self.assertEqual(run("ensure", "--lab", "sfab-m1").returncode, 0)
            self.assertTrue(rkey.is_file())
            os.chmod(rkey, 0o640)
            self.assertEqual(run("check").returncode, 1)
            os.chmod(rkey, 0o600)
            self.assertEqual(run("check").returncode, 0)
            names = run("names").stdout
            self.assertNotIn(vals["SFAB_SW_PASSWORD"], names)
            self.assertNotIn("SFAB_FW_", names)
            os.chmod(env, 0o644)
            self.assertEqual(run("check").returncode, 1)

    def test_authorized_keys(self):
        """state/secrets/authorized_keys: the lab key first, then each of the deploying user's own
        public keys once, rewritten at every ensure; nothing else from the user's files, and no
        path or comment printed."""
        if not shutil.which("ssh-keygen"):
            self.skipTest("no ssh-keygen")
        with tempfile.TemporaryDirectory() as d:
            st, ssh = os.path.join(d, "state"), Path(d) / "home" / ".ssh"
            ssh.mkdir(parents=True)
            # stand-in values in the key shapes, with no real key in them
            k1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOnlyAKeyShapedTestValueOne someone@laptop"
            k2 = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAKeyShapedTestValueTwo="
            (ssh / "id_ed25519.pub").write_text(k1 + "\n")
            (ssh / "id_ecdsa.pub").write_text("# a comment line\n" + k2 + "\nnot a key\n")
            (ssh / "zz-copy.pub").write_text("ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIOnlyAKeyShapedTestValueOne   another\n")
            (ssh / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            envr = dict(os.environ, SFAB_USER_SSH_DIRS=str(ssh))
            run = lambda: subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", st,
                                          "--lab", "sfab-m1"], capture_output=True, text=True, env=envr)
            r = run()
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertIn("the lab key and 2 of the deploying user's own public keys", r.stdout)
            self.assertNotIn("someone@laptop", r.stdout)
            self.assertNotIn(str(ssh), r.stdout)
            ak = Path(st) / "secrets" / "authorized_keys"
            lab = (Path(st) / "secrets" / "lab_ed25519.pub").read_text().strip()
            self.assertEqual(ak.read_text().splitlines(), [" ".join(lab.split()), k2, k1])
            self.assertEqual(stat.S_IMODE(ak.stat().st_mode), 0o644)
            (ssh / "id_ecdsa.pub").unlink()
            self.assertEqual(run().returncode, 0)
            self.assertEqual(ak.read_text().splitlines(), [" ".join(lab.split()), k1])
            envr["SFAB_USER_SSH_DIRS"] = ""
            self.assertIn("the lab key and 0 of", run().stdout)
            self.assertEqual(ak.read_text().splitlines(), [" ".join(lab.split())])


class PreflightGuestUserTest(unittest.TestCase):
    """pf_guest_user: cloud-init makes the login user once per disk, so preflight refuses guest
    disks made for another user, and records the user when no disk exists yet."""

    def pf(self, st: Path, guests: str, user: str = "admin", lib: str = "0") -> str:
        script = ('ok() { echo "PASS $*"; }; bad() { echo "FAIL $1 -> $2"; }; '
                  f'GUESTS=({guests}); GUEST_USER={user}; STATEDIR={st}; '
                  'SFAB_PF_LIB=1 . "$SFAB_COMMON/stages/preflight.sh"; SFAB_PF_LIB=$LIBMODE pf_guest_user')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                           env={**os.environ, "SFAB_COMMON": str(COMMON), "LIBMODE": lib})
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_guest_user(self):
        with tempfile.TemporaryDirectory() as d:
            st = Path(d)
            self.assertEqual(self.pf(st, ""), "PASS no VM guest: no login user to match\n")
            # no disk yet: the read-only form (the audit) records nothing, the deploy records the user
            self.assertEqual(self.pf(st, "k8s-gpu1 k8s-gpu2", lib="1"), "PASS guest login user admin (no guest disk yet)\n")
            self.assertFalse((st / "guest-user").exists())
            self.assertEqual(self.pf(st, "k8s-gpu1 k8s-gpu2"), "PASS guest login user admin (no guest disk yet)\n")
            self.assertEqual((st / "guest-user").read_text(), "admin\n")
            (st / "nodes" / "k8s-gpu2").mkdir(parents=True)
            (st / "nodes" / "k8s-gpu2" / "root.qcow2").write_text("")
            self.assertEqual(self.pf(st, "k8s-gpu1 k8s-gpu2"), "PASS guest login user admin, as the guests' disks were made for\n")
            self.assertIn("FAIL guest login user -> the guests' disks were made for admin, the render logs in as other: run make wipe",
                          self.pf(st, "k8s-gpu1 k8s-gpu2", user="other"))
            # a disk older than the record was made for sfab, the user before 2026-10-27
            (st / "guest-user").unlink()
            self.assertIn("FAIL guest login user -> the guests' disks were made for sfab, the render logs in as admin: run make wipe",
                          self.pf(st, "k8s-gpu1 k8s-gpu2"))


class TickTest(unittest.TestCase):
    def test_tick(self):
        p = subprocess.run([sys.executable, str(COMMON / "bin" / "tick.py")], capture_output=True, text=True)
        if sys.platform.startswith("linux") and p.returncode in (0, 1):
            self.assertRegex(p.stdout.strip(), r"^\d+$")
            self.assertEqual(p.returncode == 0, p.stdout.strip() == "10000")
        else:
            self.assertIn(p.returncode, (0, 1, 2))

    @staticmethod
    def load():
        import importlib.util  # noqa: PLC0415
        spec = importlib.util.spec_from_file_location("sfab_tick", COMMON / "bin" / "tick.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def fake_kernel(self, tick, errno=0):
        """A stand-in for adjtimex(2): reads give tick, ADJ_TICK sets it unless errno is set."""
        import ctypes  # noqa: PLC0415
        state = {"tick": tick, "calls": []}

        def adjtimex(ref):
            t = ref._obj
            state["calls"].append((t.modes, t.tick))
            if t.modes & 0x4000:
                if errno:
                    ctypes.set_errno(errno)
                    return -1
                state["tick"] = t.tick
            t.tick = state["tick"]
            return 0
        return adjtimex, state

    def run_main(self, mod, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = mod.main(list(argv))
        return rc, out.getvalue(), err.getvalue()

    def test_set_uses_adj_tick_then_reads_back(self):
        mod = self.load()
        fn, state = self.fake_kernel(9258)
        with unittest.mock.patch.object(mod, "_adjtimex", return_value=fn):
            self.assertEqual(self.run_main(mod)[:2], (1, "9258\n"), "a read changes nothing")
            self.assertEqual(state["calls"], [(0, 0)])
            rc, out, err = self.run_main(mod, "--set")
        self.assertEqual((rc, out, err), (0, "10000\n", ""))
        self.assertEqual(state["calls"][1:], [(mod.ADJ_TICK, 10000), (0, 0)], "ADJ_TICK with 10000, then a read")

    def test_set_without_root_says_so(self):
        import errno  # noqa: PLC0415
        mod = self.load()
        fn, state = self.fake_kernel(9258, errno=errno.EPERM)
        with unittest.mock.patch.object(mod, "_adjtimex", return_value=fn):
            rc, out, err = self.run_main(mod, "--set")
        self.assertEqual((rc, out), (2, ""))
        self.assertIn("cannot set the kernel tick to 10000", err)
        self.assertIn("needs root", err)
        self.assertEqual(state["tick"], 9258)

    def test_set_falls_back_to_the_adjtimex_tool(self):
        mod = self.load()
        calls = []

        def run(cmd, **kw):
            calls.append(cmd)
            if cmd[:2] == ["adjtimex", "--tick"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 0, "  tick: 10000\n  frequency: 0\n  status: 64\n", "")
        with unittest.mock.patch.object(mod, "_adjtimex", return_value=None), \
                unittest.mock.patch.object(mod.subprocess, "run", side_effect=run):
            rc, out, err = self.run_main(mod, "--set")
        self.assertEqual((rc, out), (0, "10000\n"), err)
        self.assertEqual(calls, [["adjtimex", "--tick", "10000"], ["adjtimex", "--print"]])


# ------------------------------------------------------------------------------------------------

# Stand-in values: a made-up scrub list in the private list's format. Every name, path and prefix
# in it is invented; its address prefixes are a private range no lab uses and a documentation
# range (RFC 5737).
LIST = """# fail: lab and project names
oldlab  "old cluster-1"  old-proj  corp.test
# fail: identifier prefixes at a token start
ol-  ol/
# fail: hosts, people, paths
/srv/oldlab  someone@  ~/vendor/
# fail: address prefixes (membership)
10.99.0.0/16  198.51.100.0/26 to 198.51.100.128/26
# fail: MAC prefixes
50:aa:01
# fail: committed credential literals
(kept elsewhere)
# warn: generic tokens
ab  vendor (path use only; the product name stays)
# rule: no decision or finding numbers (D or F and two digits)
"""


def lst_path(d) -> str:
    """The test list, written into d."""
    p = os.path.join(d, "list")
    Path(p).write_text(LIST)
    return p


class NamecheckTest(unittest.TestCase):
    TOOL = str(COMMON / "tools" / "namecheck.py")

    def setUp(self):
        self.entries = namecheck.parse_list(LIST)
        # an empty literals file: a named file that is missing is an error, not "no literals"
        fd, self.no_secrets = tempfile.mkstemp(prefix="sfab-test-empty-secrets-")
        os.close(fd)
        self.addCleanup(os.unlink, self.no_secrets)

    def hits(self, text, entries=None, literals=(), allow=None):
        c = namecheck.Checker(self.entries if entries is None else entries, list(literals), allow)
        return [(s, w.split()[0], x) for line in text.splitlines() for s, w, x in c.line_hits(line)]

    def run_tool(self, *args, env=None):
        e = {k: v for k, v in os.environ.items() if k not in ("SFAB_SCRUB_LIST", "SFAB_NAMECHECK_ALLOW", "SFAB_SCRUB_SECRETS")}
        e["SFAB_SCRUB_SECRETS"] = self.no_secrets
        e.update(env or {})
        return subprocess.run([sys.executable, self.TOOL, *args], capture_output=True, text=True, env=e)

    def test_parse(self):
        vals = {(e.cls, e.value) for e in self.entries}
        self.assertIn(("phr", "old cluster-1"), vals)
        self.assertIn(("pre", "ol-"), vals)
        self.assertIn(("net", "198.51.100.64/26"), vals)
        self.assertIn(("tok", "vendor"), vals)
        self.assertNotIn(("tok", "(kept"), vals)

    def test_matches(self):
        sev = lambda t: sorted({s for s, _w, _x in self.hits(t)})
        self.assertEqual(sev("clab-oldlab-fe1 up"), ["fail"])
        self.assertEqual(sev("OLD-PROJ"), ["fail"])
        self.assertEqual(sev("www.corp.test"), ["fail"])
        self.assertEqual(sev("see /srv/oldlab/x"), ["fail"])
        self.assertEqual(sev("mail someone@host"), ["fail"])
        self.assertEqual(sev("cd ~/vendor/bin"), ["fail", "warn"])
        self.assertEqual(sev("the old cluster-1 design"), ["fail"])
        self.assertEqual(sev("ol-fe1 and x/ol/y"), ["fail"])
        self.assertEqual(sev("addr 10.99.4.5 and 198.51.100.137/32"), ["fail"])
        self.assertEqual(sev("mac 50:aa:01:00:00:01"), ["fail"])
        self.assertEqual(sev("about the vendor"), ["warn"])
        self.assertEqual(sev("the " + "D" + "40 decision"), ["warn"])
        for clean in ("about every abc", "oldlabs", "pol-x and cool-x", "10.20.1.1 10.0.0.0/8 198.51.100.193",
                      "corp.tests", "the dec-policy-users id", "02:5a:6f:00:00:01"):
            self.assertEqual(sev(clean), [], clean)

    def test_variants(self):
        kinds = lambda t: [(s, w) for s, w, _x in namecheck.Checker(self.entries, []).line_hits(t)]
        for text in ("old_lab", "old lab", "the old  lab here", "old\t_lab", "oldlab2", "old_lab_01", "x.old_lab.y",
                     "old_proj", "old proj", "Old_Proj3", "oldproj", "old_cluster_1", "oldcluster1", "old-cluster_1",
                     # a domain's letters and digits, as an object name or a file name writes it
                     "corp_test", "corp-test", "corptest", "CORP test", "corp_test2"):
            self.assertEqual(kinds(text), [("fail", "name (variant)")], text)
        for clean in ("goldlab", "oldlabs", "old labs", "old.lab", "xold_lab", "old_cluster_12", "corp_tests",
                      "vend_or", "someone_at", "srv_oldlabx", "old, lab"):
            self.assertEqual(kinds(clean), [], clean)
        # an exact hit is not reported again as its own variant
        self.assertEqual(kinds("oldlab and old_lab"), [("fail", "name")])
        # a path, a MAC prefix and a user at a host have no variant; a dotted name has one
        self.assertEqual([namecheck.variant_key(v) for v in ("/srv/oldlab", "~/vendor/", "50:aa:01", "someone@", "corp.test")],
                         [None, None, None, None, "corptest"])

    def test_escape_codes(self):
        sev = lambda t: sorted({s for s, _w, _x in self.hits(t)})
        self.assertEqual(sev("\x1b[1mold\x1b[0mlab up"), ["fail"])
        self.assertEqual(sev("ol\x1b[0m-fe1"), ["fail"])
        self.assertEqual(sev("addr 10.99\x1b[0m.4.5"), ["fail"])
        self.assertEqual(sev("old\x1b[0m_\x1b[1mproj"), ["fail"])
        self.assertEqual(sev("\x1b[32mabout\x1b[0m the 10.20.1.1"), [])

    def test_literals_never_printed(self):
        got = self.hits("token=Zx9secretvalue", literals=["Zx9secretvalue"])
        self.assertEqual(got, [("fail", "credential", "a value from scrub-secrets.txt")])

    def test_allow_exempts_only_the_exact_chunk(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "allow")
            namecheck.add_allow(p, "ol-ep", "a made-up device word, for the test")
            namecheck.add_allow(p, "x_old_lab", "a made-up identifier, for the test")
            al = namecheck.read_allow(p)
            self.assertNotIn("ol-ep", Path(p).read_text(), "the allow list holds no plaintext")
            c = namecheck.Checker(self.entries, [], al)
            self.assertEqual(c.line_hits("a device prints ol-ep in its own output"), [])
            self.assertEqual(c.line_hits("the x_old_lab counter"), [], "a variant inside an allowed chunk")
            self.assertEqual(sorted({s for s, _w, _x in c.line_hits("ol-fe1 and OL-EP")}), ["fail"], "only the exact chunk, case folded")
            self.assertEqual(sorted({s for s, _w, _x in c.line_hits("y_old_lab")}), ["fail"])
            before = namecheck.read_allow(p)["set"]
            namecheck.add_allow(p, "OL-EP", "again")
            self.assertEqual(namecheck.read_allow(p)["set"], before)

    def test_scan_data_matches_every_line(self):
        # the file-level shortcut must find exactly what line_hits finds on every line
        import random
        rng = random.Random(13)
        frags = ["oldlab", "old", "lab", "proj", "old-proj", "OLD", "cluster-1", "corp.test", "ol-", "ol/", "about", "ab",
                 "vendor", "10.99.4.5", "10.99", ".4.5", "198.51.100.70/32", "10.20.1.1", "D" + "40", "F" + "07", "d40", "Zx9secret",
                 "someone@", "/srv/oldlab", "50:aa:01", "\x1b[0m", "\x1b[1;31m", "\x1b]0;t\x07", "_", "-", " ", "\t", ".",
                 "/", "2", "01", "\u00e9", "\u212a", "\ufffd", "x", "goldlab", "oldlabs", "corp", "test", "corp_test"]
        seps = ["\n", "\r\n", "\r", "\x0b", "\x0c", "\x1c", "\x85", "\u2028", "\u2029", "\n\n"]
        c = namecheck.Checker(self.entries, ["Zx9secret"])
        for _ in range(60):
            parts = []
            for _ in range(rng.randrange(1, 40)):
                parts.append("".join(rng.choice(frags) for _ in range(rng.randrange(0, 9))))
                parts.append(rng.choice(seps))
            data = "".join(parts).encode("utf-8")
            if rng.random() < 0.3:
                at = rng.randrange(len(data) + 1)
                data = data[:at] + rng.choice([b"\xff", b"\xe2\x80", b"\xc2", b"\x85", b"\xe2\xc2\x85"]) + data[at:]
            want = []
            for no, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
                got = c.line_hits(line)
                if got:
                    want.append((no, got))
            self.assertEqual(c.scan_data(data), want, data)

    def test_parallel_scan_matches_serial(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(80):
                Path(d, f"f{i:02d}.txt").write_text(f"line one\nclab-oldlab-{i} and old_proj{i}\nabout ab\n" * (i % 3 + 1))
            files = sorted(str(p) for p in Path(d).iterdir())
            c = namecheck.Checker(self.entries, [])
            outs = []
            for jobs in (1, 2):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    counts = namecheck.scan(c, files, d, mask=True, jobs=jobs)
                outs.append((counts, buf.getvalue()))
            self.assertEqual(outs[0], outs[1])
            reps = sum(i % 3 + 1 for i in range(80))
            self.assertEqual(outs[0][0], (80, 2 * reps, reps), "a name and a variant fail, and one warning, per block")

    def test_mask_prints_no_matched_text(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "x.txt")
            Path(f).write_text("clab-oldlab-fe1 up\nthe old_proj host\n")
            lst = os.path.join(d, "list")
            Path(lst).write_text(LIST)
            r = self.run_tool("--list", lst, "--mask", f)
            self.assertEqual(r.returncode, 1)
            self.assertIn(":1: fail name", r.stdout)
            self.assertIn(":2: fail name (variant)", r.stdout)
            self.assertNotIn("oldlab", r.stdout)
            self.assertNotIn("proj", r.stdout)

    def test_compressed_files_are_scanned_decompressed(self):
        import gzip
        with tempfile.TemporaryDirectory() as d:
            lst = os.path.join(d, "list")
            Path(lst).write_text(LIST)
            # over the 20 MiB a plain file may have, and compressed: still read, line by line
            big = os.path.join(d, "commands.txt.gz")
            Path(big).write_bytes(gzip.compress(b"x\n" * (11 * 1024 * 1024) + b"clab-oldlab-fe1 up\n", mtime=0))
            r = self.run_tool("--list", lst, "--mask", big)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn(f":{11 * 1024 * 1024 + 1}: fail name", r.stdout)
            self.assertNotIn("oldlab", r.stdout)
            Path(big).write_bytes(b"\x1f\x8b\x08\x00 not a gzip stream")
            r = self.run_tool("--list", lst, "--mask", big)
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn(":1: fail compressed file that does not decompress", r.stdout)

    def test_lists_come_from_the_environment(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "x.txt")
            Path(f).write_text("a device prints ol-ep here\n")
            lst, allow = os.path.join(d, "list"), os.path.join(d, "allow")
            Path(lst).write_text(LIST)
            r = self.run_tool("--mask", f, env={"SFAB_SCRUB_LIST": lst})
            self.assertEqual(r.returncode, 1, r.stdout)
            r = self.run_tool("--allow-add", "ol-ep", "--why", "a made-up device word", env={"SFAB_NAMECHECK_ALLOW": allow})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            r = self.run_tool("--mask", f, env={"SFAB_SCRUB_LIST": lst, "SFAB_NAMECHECK_ALLOW": allow})
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn("(scrub list, allow list)", r.stdout)
            self.assertEqual(self.run_tool("--allow-add", "ol-ep", "--why", "x").returncode, 2, "no allow list to add to")

    def test_skipped_without_a_list(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "x.txt")
            Path(f).write_text("clab-oldlab-fe1 up\ntoken=Zx9secretvalue\n")
            r = self.run_tool("--mask", f)
            self.assertEqual(r.returncode, namecheck.SKIPPED)
            self.assertEqual(r.stdout.strip(), "namecheck: skipped, no scrub list (set SFAB_SCRUB_LIST to check names)")
            # the local literals are still checked without a list, and a literal found fails
            sec = os.path.join(d, "secrets")
            Path(sec).write_text("# local\nZx9secretvalue\n")
            r = self.run_tool("--mask", f, env={"SFAB_SCRUB_SECRETS": sec})
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn(":2: fail credential literal", r.stdout)
            self.assertNotIn("Zx9", r.stdout)
            Path(sec).write_text("Yy8othervalue\n")
            r = self.run_tool("--mask", f, env={"SFAB_SCRUB_SECRETS": sec})
            self.assertEqual(r.returncode, namecheck.SKIPPED, r.stdout)
            self.assertIn("namecheck: skipped, no scrub list (1 files checked for local secrets only, 0 fail)", r.stdout)
            # a list that is named but missing is an error, not a skip: the scrub list, the allow list
            # and the literals file, by option or by variable. The path is not printed.
            missing = os.path.join(d, "missing")
            for args, env in (((f,), {"SFAB_SCRUB_LIST": missing}),
                              ((f,), {"SFAB_SCRUB_LIST": lst_path(d), "SFAB_NAMECHECK_ALLOW": missing}),
                              (("--allow", missing, f), {"SFAB_SCRUB_LIST": lst_path(d)}),
                              ((f,), {"SFAB_SCRUB_LIST": lst_path(d), "SFAB_SCRUB_SECRETS": missing}),
                              ((f,), {"SFAB_SCRUB_SECRETS": missing}),
                              (("--secrets", missing, f), {})):
                r = self.run_tool(*args, env=env)
                self.assertEqual(r.returncode, 2, (args, env, r.stdout, r.stderr))
                self.assertNotIn(missing, r.stdout + r.stderr)
            # only the default literals file may be missing
            e = {"HOME": d, "SFAB_SCRUB_SECRETS": ""}
            self.assertEqual(self.run_tool("--mask", f, env=e).returncode, namecheck.SKIPPED)

    def test_no_list_ships(self):
        tools = COMMON / "tools"
        for name in ("namecheck.digests", "namecheck.allow", "scrub-list.txt"):
            self.assertFalse((tools / name).exists(), name)

    def test_repo_is_clean(self):
        # masked, so a failure prints where, never what
        r = subprocess.run([sys.executable, self.TOOL, "--mask"], capture_output=True, text=True)
        self.assertIn(r.returncode, (0, namecheck.SKIPPED), r.stdout[-2000:] + r.stderr[-1000:])


if __name__ == "__main__":
    unittest.main()
