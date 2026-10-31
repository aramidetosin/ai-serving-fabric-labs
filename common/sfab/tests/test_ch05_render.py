"""Chapter 5's plans: the rail slice, gen/trace.json in its rails form (sfab.render.trace), the
dark-switch drill in gen/drills.json and break-5a in gen/breaks.json (sfab.render.drills).

- The committed renders under ch05/ are this render.
- The slice is the rail switches and both GPU nodes, with the pair and the out-of-band switch their
  links land on; no firewall, so no host is given a gateway, while every lab that holds the
  firewall keeps its gateways.
- The rail switches deploy whole and type plain VLANs with no address, every port no shutdown and
  no mtu line.
- The trace resolves every rail both nodes hold, each flow's request rail and reply rail and their
  switches, the reply's TTL and traceroute's hops, every point's expected requests and replies,
  and the DF matrix both ways; malformed blocks are refused, field named.
- The dark drill holds every port of the switch as one interface range, its rails dead and the
  rows it darkens; break-5a's relay actions resolve the rendered route and its source pin.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_ch05_render -v
"""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from sfab.render import RenderError
from sfab.render import drills as RD
from sfab.render import trace as RT

ROOT = Path(__file__).resolve().parents[3]
CH05 = ROOT / "ch05"

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch(path=CH05):
    key = str(path)
    if key not in _CACHE:
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415

        spec = load(ROOT)
        c = load_chapter(path)
        m = select(spec, c)
        _CACHE[key] = {"m": m, "spec": spec, "ch": c, "inv": inventory(m)}
    return _CACHE[key]


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class SliceTest(unittest.TestCase):
    def test_nodes_and_no_gateway(self):
        m = ch()["m"]
        self.assertEqual(sorted(m.nodes), ["fe-sw1", "fe-sw2", "k8s-gpu1", "k8s-gpu2", "oob-sw", "rail-sw1", "rail-sw2"])
        for g in ("k8s-gpu1", "k8s-gpu2"):
            h = m.nodes[g]
            self.assertEqual((h.gateway, h.bond.gateway, h.oob.gateway), (None, None, None))
        env = (CH05 / "bootstrap" / "k8s-gpu1" / "node.env").read_text()
        self.assertNotIn("BOND_GW=", env)
        self.assertNotIn("OOB_GW=", env)
        self.assertIn("MGMT_GW=172.21.40.1", env)

    def test_a_lab_with_the_firewall_keeps_its_gateways(self):
        m = ch(ROOT / "ch04")["m"]
        self.assertEqual((m.nodes["k8s-gpu1"].gateway, m.nodes["k8s-gpu1"].oob.gateway), ("10.20.1.1", "10.20.9.254"))

    def test_rail_switch_klish(self):
        text = (CH05 / "bootstrap" / "rail-sw1" / "startup-config.cfg").read_text().splitlines()
        self.assertEqual(text[1:4], ["configure terminal", "ip vrf mgmt", "end"])
        self.assertEqual([l for l in text if l.startswith("interface Vlan")], [f"interface Vlan {v}" for v in (101, 103, 105, 107)])
        self.assertEqual(sum(1 for l in text if l == "no shutdown"), 8)
        for word in ("address", "router", "PortChannel", "trunk"):
            self.assertFalse([l for l in text if word in l and not l.startswith("!")], word)
        # revision 2's l2 policy: every rail port at 9216, an edge port with BPDU guard and storm control
        self.assertEqual([l for l in text if l.startswith("mtu")], ["mtu 9216"] * 8)
        self.assertEqual(sum(1 for l in text if l == "spanning-tree bpduguard port-shutdown"), 8)
        self.assertEqual(sum(1 for l in text if l.startswith("storm-control ")), 24)
        self.assertIn("spanning-tree mode pvst", text)

    def test_committed_render_is_this_render(self):
        c = ch()
        self.assertEqual(json.loads((CH05 / "gen" / "trace.json").read_text()), json.loads(RT.dumps(RT.rails_plan(c["m"], c["ch"].trace["rails"]))))
        self.assertEqual(json.loads((CH05 / "gen" / "drills.json").read_text()), json.loads(RD.dumps(RD.drills(c["inv"], c["ch"].drills, c["m"]))))
        self.assertEqual(json.loads((CH05 / "gen" / "breaks.json").read_text()), json.loads(RD.dumps(RD.breaks(c["inv"], CH05, c["m"]))))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class RailTracePlanTest(unittest.TestCase):
    def setUp(self):
        c = ch()
        self.m, self.raw = c["m"], c["ch"].trace["rails"]
        self.plan = RT.rails_plan(self.m, self.raw)

    def test_rails_and_flows(self):
        p = self.plan
        self.assertEqual([r["r"] for r in p["rails"]], list(range(1, 9)))
        r2 = p["rails"][1]
        self.assertEqual((r2["switch"], r2["src_addr"], r2["dst_addr"], r2["src_ns"], r2["src_eth"], r2["src_native"], r2["dst_native"]),
                         ("rail-sw2", "10.21.2.11", "10.21.2.12", "gpu2", "eth5", "Ethernet0", "Ethernet4"))
        same, cross = p["flows"]
        self.assertEqual((same["request_switch"], same["reply_switch"], same["expect"]), ("rail-sw1", "rail-sw1", {"ttl": 64, "hops": ["10.21.1.12"]}))
        self.assertEqual((cross["src_addr"], cross["dst_addr"], cross["via"], cross["via_src"], cross["request_switch"], cross["reply_switch"]),
                         ("10.21.1.11", "10.21.2.12", "10.21.250.2", "10.21.1.11", "rail-sw2", "rail-sw1"))
        self.assertEqual(cross["expect"], {"ttl": 63, "hops": ["10.21.2.11", "10.21.2.12"]})
        self.assertEqual(len({f["icmp_id"] for f in p["flows"]} | {d["icmp_id"] for d in p["df"]}), 2 + 8)

    def test_points_expectations(self):
        pts = {x["id"]: x for x in self.plan["points"]}
        self.assertEqual(pts["1-k8s-gpu1-relay0"]["expect"], {"same-rail": {"request": None, "reply": None}, "cross-rail": {"request": 64, "reply": None}})
        self.assertEqual(pts["2-rail-sw2-Ethernet0"]["expect"]["cross-rail"], {"request": 63, "reply": None})
        self.assertEqual(pts["3-rail-sw1-Ethernet4"]["expect"], {"same-rail": {"request": 64, "reply": 64}, "cross-rail": {"request": None, "reply": 63}})
        self.assertEqual(pts["4-k8s-gpu2-relay0"]["expect"]["cross-rail"], {"request": None, "reply": 64})
        self.assertEqual((pts["3-rail-sw2-Ethernet4"]["faces"], pts["3-rail-sw2-Ethernet4"]["rail"], pts["3-rail-sw2-Ethernet4"]["eth"]), ("k8s-gpu2", 2, "eth5"))

    def test_df_matrix(self):
        rows = {d["id"]: d for d in self.plan["df"]}
        self.assertEqual(len(rows), 8)
        r = rows["cross-rail-reverse-9001"]
        self.assertEqual((r["node"], r["ns"], r["src_addr"], r["dst_addr"], r["payload"]), ("k8s-gpu2", "gpu2", "10.21.2.12", "10.21.1.11", 8973))
        self.assertEqual(rows["same-rail-reverse-9000"]["ns"], "gpu1")

    def test_refusals(self):
        for change, msg in ((lambda r: r.update(to="k8s-gpu1"), "names another node"),
                            (lambda r: r["flows"].append({"id": "x", "rail": 9}), "is not a rail both"),
                            (lambda r: r["flows"].append({"id": "same-rail", "rail": 2}), "id must be a new name"),
                            (lambda r: r.update(df_sizes=[9001, 9000]), "ascending"),
                            (lambda r: r["points"].append({"id": "5-fe-sw1-x", "node": "fe-sw1", "eth": "eth7"}), "a rail switch's port"),
                            (lambda r: r["points"].append({"id": "5-k8s-gpu1-bond0", "node": "k8s-gpu1", "iface": "bond0"}), "relay bridge"),
                            (lambda r: r.update(points=[r["points"][0]]), "sees both the request and the reply"),
                            (lambda r: r.update(extra=1), "unknown keys")):
            raw = copy.deepcopy(self.raw)
            change(raw)
            with self.assertRaises(RenderError) as e:
                RT.rails_plan(self.m, raw)
            self.assertIn(msg, str(e.exception))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class DarkDrillPlanTest(unittest.TestCase):
    def setUp(self):
        c = ch()
        self.inv, self.raw, self.m = c["inv"], c["ch"].drills, c["m"]
        self.plan = RD.drills(self.inv, self.raw, self.m)

    def test_dark_switch(self):
        d = self.plan["list"][0]
        self.assertEqual(d["klish"], ["configure terminal", "interface range Ethernet0-7", "shutdown", "end"])
        self.assertEqual(d["restore"], ["configure terminal", "interface range Ethernet0-7", "no shutdown", "end"])
        self.assertEqual((d["dead_rails"], d["live_rails"], d["live_switches"]), ([1, 3, 5, 7], [2, 4, 6, 8], ["rail-sw2"]))
        self.assertEqual({k for k, v in d["expect"].items() if v == "dark"}, {"same-1", "same-3", "same-5", "same-7", "cross-2-1", "cross-1-2"})
        self.assertEqual(self.plan["timing"], {"lead_s": 10, "hold_s": 30, "tail_s": 20, "whole_polls": 12, "late_ms": 1000})

    def test_rows_and_captures(self):
        pr = self.plan["probes"]["rails"]
        rows = {r["id"]: r for r in pr["rows"]}
        x = rows["cross-2-1"]
        self.assertEqual((x["ns"], x["src_addr"], x["dst_addr"], x["request_rail"], x["reply_rail"], x["request_switch"], x["reply_switch"]),
                         ("gpu2", "10.21.2.11", "10.21.1.12", 1, 2, "rail-sw1", "rail-sw2"))
        self.assertEqual(len({r["icmp_id"] for r in pr["rows"]}), 11)
        self.assertEqual(len(pr["capture"]), 16)
        self.assertEqual(self.plan["rail_switches"]["rail-sw2"]["natives"], [f"Ethernet{i}" for i in range(8)])

    def test_refusals(self):
        for change, msg in ((lambda r: r["list"][0].update(dark={"switch": "fe-sw1"}), "not a rail switch"),
                            (lambda r: r["probes"]["rails"].update(cross=[[1, 1]]), "two different rails"),
                            (lambda r: r["probes"]["rails"].update(to="k8s-gpu1"), "names another node"),
                            (lambda r: r["list"][0].update(probes=["ping"]), "runs the rails probe")):
            raw = copy.deepcopy(self.raw)
            change(raw)
            with self.assertRaises(RenderError) as e:
                RD.drills(self.inv, raw, self.m)
            self.assertIn(msg, str(e.exception))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Break5aPlanTest(unittest.TestCase):
    def setUp(self):
        c = ch()
        self.inv, self.m = c["inv"], c["m"]
        self.b = RD.breaks(self.inv, CH05, self.m)["breaks"]["5a"]

    def test_actions(self):
        br, heal = self.b["break"][0], self.b["heal"][0]
        self.assertEqual(br["command"], "ip -n gpu1 route replace 10.21.2.0/24 via 10.21.250.2 dev relay")
        self.assertEqual(heal["command"], "ip -n gpu1 route replace 10.21.2.0/24 via 10.21.250.2 dev relay src 10.21.1.11")
        rec = {a.get("id") or a["kind"]: a for a in self.b["record"]}
        self.assertEqual(rec["ns_show"]["lines"], ["ip -n gpu1 route show", "ip -n gpu1 route get 10.21.2.12", "ip -n gpu1 route get 10.21.3.12"])
        cap = rec["rail1-to-rail2"]["capture"]
        self.assertEqual((cap["node"], cap["ifaces"], cap["relay_prefix"], cap["src_addr"], cap["dst_addr"]),
                         ("k8s-gpu2", ["rail2", "relay0"], "10.21.250.0/24", "10.21.1.11", "10.21.2.12"))
        self.assertEqual(len(rec["same-rail-k8s-gpu1"]["rows"]), 8)
        self.assertEqual(rec["k8s-gpu2-rail1-to-rail2"]["rows"][0]["dst_addr"], "10.21.2.11")

    def test_refusals(self):
        for action, msg in (({"relay_route": {"node": "k8s-gpu1", "rail": 1, "to_rail": 1, "src": "none"}}, "another rail"),
                            ({"relay_route": {"node": "rail-sw1", "rail": 1, "to_rail": 2, "src": "none"}}, "VM guest with rails"),
                            ({"relay_route": {"node": "k8s-gpu1", "rail": 1, "to_rail": 2, "src": "maybe"}}, "none (the route"),
                            ({"probe_rail": {"id": "x", "from": "k8s-gpu1", "to": "k8s-gpu2", "rail": "all", "capture": True}}, "rail: all pings"),
                            ({"far_capture": {"probe": "x", "src": "elsewhere"}}, "relay or rail")):
            with self.assertRaises(RenderError) as e:
                RD._break_action(self.inv, action, "test", self.m)
            self.assertIn(msg, str(e.exception))

    def test_far_capture_needs_a_captured_probe(self):
        raw = {"title": "t", "break": [{"relay_route": {"node": "k8s-gpu1", "rail": 1, "to_rail": 2, "src": "none"}}],
               "record": [{"probe_rail": {"id": "p", "from": "k8s-gpu1", "to": "k8s-gpu2", "rail": 1, "to_rail": 2}}],
               "expect_broken": [{"far_capture": {"probe": "p", "src": "relay"}}],
               "heal": [{"relay_route": {"node": "k8s-gpu1", "rail": 1, "to_rail": 2, "src": "rendered"}}]}
        with self.assertRaises(RenderError) as e:
            RD._break(self.inv, "5z", raw, self.m)
        self.assertIn("no probe_rail with capture: true", str(e.exception))


if __name__ == "__main__":
    unittest.main()
