"""The drills and breaks renderer (sfab.render.drills; FRAMEWORK.md 4.6 and 4.7), on ch03's chapter.

- ch03's drills block resolves to gen/drills.json: the probes' addresses and captured ports with the
  switch each lands on, the shut's members and their KLISH (one interface, a contiguous range), the
  reboot by role, the bonded hosts, the timing with its defaults.
- breaks/3a.yaml resolves to gen/breaks.json, with its session, fallback and checks.
- A lab with neither renders neither file (M1 and M2 render byte for byte as before).
- Every malformed drill or break is refused with the file and the field named.
- sfab.klish_lint.action_problems refuses what a session must never type.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_drills_render -v
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from sfab import klish_lint as KL
from sfab.render import RenderError
from sfab.render import drills as RD

ROOT = Path(__file__).resolve().parents[3]
CH03 = ROOT / "ch03"

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch03_model():
    if "m" not in _CACHE:
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415
        from sfab.render.inventory import inventory  # noqa: PLC0415

        spec = load(ROOT)
        ch = load_chapter(CH03)
        m = select(spec, ch)
        _CACHE.update(m=m, spec=spec, ch=ch, inv=inventory(m))
    return _CACHE


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class DrillsPlanTest(unittest.TestCase):
    def setUp(self):
        c = ch03_model()
        self.inv, self.raw = c["inv"], c["ch"].drills
        self.plan = RD.drills(self.inv, self.raw)

    def test_committed_render_is_this_render(self):
        have = json.loads((CH03 / "gen" / "drills.json").read_text())
        self.assertEqual(have, json.loads(RD.dumps(self.plan)))

    def test_probes(self):
        p = self.plan["probes"]
        self.assertEqual((p["ping"]["src_addr"], p["ping"]["dst_addr"]), ("10.20.1.21", "10.20.1.22"))
        self.assertEqual([(c["node"], c["eth"], c["switch"]) for c in p["ping"]["capture"]],
                         [("k8s-gpu1", "eth1", "fe-sw1"), ("k8s-gpu1", "eth2", "fe-sw2"), ("k8s-gpu2", "eth1", "fe-sw1"), ("k8s-gpu2", "eth2", "fe-sw2")])
        self.assertEqual((p["tcp"]["client_addr"], p["tcp"]["dst_addr"], p["tcp"]["port"]), ("10.24.10.10", "10.20.11.210", 443))
        self.assertEqual([(c["ifname"], c["switch"], c["native"]) for c in p["tcp"]["capture"]],
                         [("ethernet1/1", "fe-sw1", "Ethernet2"), ("ethernet1/2", "fe-sw2", "Ethernet2")])
        self.assertNotIn("orphan", p, "TrueNAS's management address is dual-attached: no orphan port")

    def test_shuts_and_the_reboot(self):
        by = {d["id"]: d for d in self.plan["list"]}
        self.assertEqual(list(by), ["fw-leg", "server-member", "peer-link", "keepalive-link", "keepalive-and-peer-link", "standby-reboot"])
        self.assertEqual(by["fw-leg"]["klish"], ["configure terminal", "interface Ethernet2", "shutdown", "end"])
        self.assertEqual(by["fw-leg"]["restore"], ["configure terminal", "interface Ethernet2", "no shutdown", "end"])
        self.assertEqual((by["fw-leg"]["faces"], by["fw-leg"]["eths"]), ("fw", ["eth3"]))
        self.assertEqual(by["server-member"]["members"], ["Ethernet6"])
        self.assertEqual(by["peer-link"]["klish"], ["configure terminal", "interface range Ethernet0-1", "shutdown", "end"])
        self.assertTrue(by["peer-link"]["peer_link"])
        self.assertEqual((by["standby-reboot"]["kind"], by["standby-reboot"]["role"], by["standby-reboot"]["command"]),
                         ("reboot", "standby", "sudo reboot"))
        # revision 2: the dedicated keepalive link alone, and with the peer link, held past the
        # session timeout, then a wait for the standby's return
        ka = by["keepalive-link"]
        self.assertEqual((ka["klish"], ka["members"], ka["eths"], ka["hold_s"], ka["await_return"], ka["keepalive_link"], ka["peer_link"]),
                         (["configure terminal", "interface Ethernet12", "shutdown", "end"], ["Ethernet12"], ["eth13"], 70, True, True, False))
        both = by["keepalive-and-peer-link"]
        self.assertEqual(both["members"], ["Ethernet0", "Ethernet1", "Ethernet12"])
        self.assertEqual(both["restore"], ["configure terminal", "interface Ethernet0", "no shutdown", "exit", "interface Ethernet1",
                                           "no shutdown", "exit", "interface Ethernet12", "no shutdown", "end"])
        self.assertTrue(both["peer_link"] and both["keepalive_link"] and both["await_return"])
        self.assertFalse(by["peer-link"]["await_return"])
        self.assertNotIn("hold_s", by["peer-link"], "the peer-link drill keeps the lab's hold")

    def test_bonded_hosts_and_pair(self):
        self.assertEqual([b["node"] for b in self.plan["bonded"]], ["k8s-cp1", "k8s-cp2", "k8s-cp3", "k8s-gpu1", "k8s-gpu2", "k8s-ingress1", "k8s-ingress2", "bastion"])
        self.assertEqual(self.plan["pair"]["system_mac"], "02:5a:00:00:00:01")
        self.assertEqual(self.plan["pair"]["peer_link"]["fe-sw1"]["eths"], ["eth1", "eth2"])

    def test_timing_defaults_and_overrides(self):
        t = self.plan["timing"]
        self.assertEqual((t["hold_s"], t["late_ms"], t["cut_window_s"]), (30, 1000, 15))

    def test_non_contiguous_members_are_separate_blocks(self):
        self.assertEqual(RD._shut_session(["Ethernet0", "Ethernet2"], "shutdown"),
                         ["configure terminal", "interface Ethernet0", "shutdown", "exit", "interface Ethernet2", "shutdown", "end"])

    def refused(self, raw, needle):
        with self.assertRaises(RenderError) as e:
            RD.drills(self.inv, raw)
        self.assertIn(needle, str(e.exception))

    def test_refusals(self):
        r = copy.deepcopy(self.raw)
        r["probes"]["ping"]["from"] = "ent-client"
        self.refused(r, "bonded VM guest")
        r = copy.deepcopy(self.raw)
        r["list"][0]["shut"]["portchannel"] = 99
        self.refused(r, "has no PortChannel99")
        r = copy.deepcopy(self.raw)
        r["list"][1]["id"] = "fw-leg"
        self.refused(r, "appears twice")
        r = copy.deepcopy(self.raw)
        r["list"][0]["place"] = {"tcp": "somewhere"}
        self.refused(r, "must be one of")
        r = copy.deepcopy(self.raw)
        r["timing"]["hold"] = 3
        self.refused(r, "unknown key")
        r = copy.deepcopy(self.raw)
        r["list"][-1]["reboot"] = "both"
        self.refused(r, "standby or active")
        r = copy.deepcopy(self.raw)
        r["list"][-1]["hold_s"] = 70
        self.refused(r, "belong to a shut")
        r = copy.deepcopy(self.raw)
        r["list"][3]["shut"] = {"switch": "fe-sw1"}
        self.refused(r, "names no port")
        r = copy.deepcopy(self.raw)
        r["list"][3]["shut"] = {"switch": "rail-sw1", "keepalive": True}
        self.refused(r, "has no dedicated keepalive link")
        r = copy.deepcopy(self.raw)
        r["list"][3]["colour"] = "blue"
        self.refused(r, "unknown keys")
        r = copy.deepcopy(self.raw)
        del r["list"][0]["shut"]
        self.refused(r, "needs a fault")
        r = copy.deepcopy(self.raw)
        r["probes"]["tcp"]["gateway"] = "gw-nowhere"
        self.refused(r, "is not a Gateway")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class BreaksTest(unittest.TestCase):
    def setUp(self):
        self.inv = ch03_model()["inv"]

    def test_3a(self):
        b = RD.breaks(self.inv, CH03)["breaks"]["3a"]
        self.assertEqual(b["break"][0]["session"], ["configure terminal", "interface PortChannel 10",
                                                    "switchport trunk allowed Vlan remove 200", "end"])
        self.assertEqual(b["break"][0]["fallback"][2], "no switchport trunk allowed Vlan 200")
        self.assertEqual([a["kind"] for a in b["expect_broken"]], ["vlan_member", "vlan_member", "probe_share"])
        self.assertEqual(b["heal"], [{"kind": "restore", "node": "fe-sw2"}])
        pr = next(a for a in b["record"] if a["kind"] == "probe_tcp")
        self.assertEqual((pr["node"], pr["dst_addr"], pr["count"], pr["passes"]), ("bastion", "10.20.2.31", 60, 3))
        self.assertEqual(json.loads((CH03 / "gen" / "breaks.json").read_text())["breaks"]["3a"], b)

    def test_3b(self):
        b = RD.breaks(self.inv, CH03)["breaks"]["3b"]
        self.assertEqual(b["break"][0]["session"], ["configure terminal", "interface Ethernet11", "shutdown", "end"])
        self.assertEqual([(a["node"], a["portchannel"], a["status"]) for a in b["expect_broken"] if a["kind"] == "mclag_iface"],
                         [("fe-sw1", "PortChannel32", "down/up"), ("fe-sw2", "PortChannel32", "up/down")])
        self.assertEqual([a["status"] for a in b["expect_healed"] if a["kind"] == "mclag_iface"], ["up/up", "up/up"])
        self.assertEqual(json.loads((CH03 / "gen" / "breaks.json").read_text())["breaks"]["3b"], b)
        base = (CH03 / "breaks" / "3b.yaml").read_text()
        for text, needle in ((base.replace("portchannel: PortChannel32, local: down", "portchannel: PortChannel10, local: down"), None),
                             (base.replace("portchannel: PortChannel32, local: down", "portchannel: PortChannel1, local: down"),
                              "is no MCLAG interface of fe-sw1"),
                             (base.replace("local: down, remote: up", "local: shut, remote: up"), "local and remote are up or down"),
                             (base.replace("node: fe-sw2, portchannel", "node: rail-sw1, portchannel"), "is no MCLAG pair member")):
            with self.subTest(needle=needle):
                if needle is None:
                    RD.breaks(self.inv, self.write(text))
                    continue
                with self.assertRaises(RenderError) as e:
                    RD.breaks(self.inv, self.write(text))
                self.assertIn(needle, str(e.exception))

    def write(self, text):
        d = Path(tempfile.mkdtemp(prefix="sfab-test-breaks-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "breaks").mkdir()
        (d / "breaks" / "3z.yaml").write_text(text)
        return d

    def test_refusals(self):
        base = (CH03 / "breaks" / "3a.yaml").read_text()
        cases = [
            (base.replace("node: fe-sw2\n      context", "node: k8s-gpu1\n      context"), "is not a switch"),
            (base.replace("switchport trunk allowed Vlan remove 200", "show vlan | grep -E 200"), "grep -E"),
            (base.replace("restore: fe-sw2", "restore: k8s-gpu1"), "restore is written for switches"),
            (base.replace("probe: bastion-stor-mgmt, failing: some", "probe: other, failing: some"), "which record: does not run"),
            (base.replace("failing: none", "failing: half"), "must be some"),
            (base + "colour: blue\n", "unknown keys"),
            (base.replace("\nheal:\n  - restore: fe-sw2\n", "\n"), "heal: names no action"),
        ]
        for text, needle in cases:
            with self.subTest(needle=needle):
                with self.assertRaises(RenderError) as e:
                    RD.breaks(self.inv, self.write(text))
                self.assertIn(needle, str(e.exception))

    def test_a_lab_with_no_breaks_renders_none(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-test-breaks-"))
        self.addCleanup(shutil.rmtree, d, True)
        self.assertIsNone(RD.breaks(self.inv, d))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class MilestonesUnchangedTest(unittest.TestCase):
    def test_m1_and_m2_render_no_drill_file(self):
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415
        from sfab import render as R  # noqa: PLC0415

        spec = load(ROOT)
        for lab in ("dev/m1", "dev/m2"):
            d = ROOT / lab
            m = select(spec, load_chapter(d))
            out = R.render_all(m, R.Context(outdir=d, labdir=d, root=ROOT, spec=spec)).outputs
            self.assertNotIn("gen/drills.json", out)
            self.assertNotIn("gen/breaks.json", out)
            self.assertEqual(out["gen/inventory.json"], (d / "gen" / "inventory.json").read_bytes(), lab)


class ActionLintTest(unittest.TestCase):
    def test_refusals(self):
        self.assertEqual(KL.action_problems(["configure terminal", "interface Ethernet2", "shutdown", "end"]), [])
        for lines, needle in ((["show mclag brief ?"], "never type ?"), (["ip vrf mgmt", "exit"], "exit after ip vrf"),
                              (["description two words"], "description"), (["show vlan | grep -E 200"], "grep -E"),
                              (["show vlan | grep '200'"], "quoted"), (["no mclag domain 1"], "never delete"),
                              (["ip address 10.0.0.9/24"], "10.0.0.0/24")):
            with self.subTest(needle=needle):
                self.assertTrue(any(needle in p for p in KL.action_problems(lines)), KL.action_problems(lines))


if __name__ == "__main__":
    unittest.main()
