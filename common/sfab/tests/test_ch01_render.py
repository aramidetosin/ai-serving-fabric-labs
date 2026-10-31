"""Chapter 1's render: the request walk's plan (render/trace.py walk_plan) and break-1a (render/drills.py
panos_api edit, probe_syn, syn_at, tlog_rule).

- The walk resolves, from the spec alone, every table the request consults: the resolver's view that
  answers the client and the one that answers the resolver itself, the firewall's ingress zone, the
  connected route and egress toward the Gateway's VIP, the first security rule that matches (allow)
  and no NAT rule; the frontend's capture points from the client's port to the pair ports the
  bundle's legs land on; chapter 7's keyed points numbered after them; chapter 4's held session with
  the model's POST; and the three refusals, each with the device and layer that must refuse it.
- A walk the render would not carry is refused: a refusal missing, the key refusal naming the walked
  model, a port the rulebase allows, a node outside the bundle the walk captures, two refusals on
  one source port.
- break-1a edits the rule's destination (the element replaces the rendered one), probes from a
  client's pinned ports with the firewall's ports captured, and checks where the SYNs went and what
  the traffic log names; a break that moves the destination nowhere, checks an uncaptured port or
  names a rule the firewall does not carry is refused.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_ch01_render -v
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
CH01 = ROOT / "ch01"

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch01():
    if "m" not in _CACHE:
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, read_yaml, select  # noqa: PLC0415

        spec = load(ROOT)
        ch = load_chapter(CH01)
        m = select(spec, ch)
        _CACHE.update(m=m, ch=ch, inv=inventory(m), brk=read_yaml(CH01 / "breaks" / "1a.yaml"))
    return _CACHE


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class WalkPlan(unittest.TestCase):
    def setUp(self):
        self.c = ch01()
        self.raw = self.c["ch"].trace["walk"]
        self.p = RT.walk_plan(self.c["m"], self.raw)

    def test_committed_plan_is_the_render(self):
        self.assertEqual(json.loads((CH01 / "gen" / "trace.json").read_text()), json.loads(RT.dumps(self.p)))

    def test_tables(self):
        p = self.p
        self.assertEqual(p["kind"], "walk")
        self.assertEqual(p["depth_base"], RT.WALK_BASE)
        self.assertEqual(p["client"]["node"], "ent-client")
        self.assertEqual(p["gateway"]["vip"], "10.20.11.210")
        self.assertEqual(p["dns"]["view"], "enterprise")
        self.assertEqual(p["dns"]["answer"], "10.20.11.210")
        self.assertEqual(p["dns"]["contrast"], {"node": "dns-res1", "source": "10.20.13.21", "server": "10.20.13.21",
                                             "view": "internal", "answer": "10.20.11.200"})
        self.assertEqual(p["firewall"], {"node": "fw", "vr": "core", "ingress": "ethernet1/4", "ingress_zone": "enterprise",
                                         "egress": "ae1.110", "egress_zone": "ingress", "route": "10.20.11.0/24",
                                         "rule": "staff-to-users-gateway", "nat_rule": None, "bundle": "ae1", "tag": 110})
        s = p["sessions"][0]
        self.assertEqual((s["method"], s["sport"], s["dst_addr"], s["translated_addr"]), ("POST", 42106, "10.20.11.210", None))
        self.assertEqual(s["expect"]["rule"], "staff-to-users-gateway")
        self.assertTrue(s["header"].endswith("/hdr-chat"))
        self.assertEqual(p["tables"]["routes"]["key"], "apisix.yaml")
        self.assertEqual(p["rail_counters"]["switches"], ["rail-sw1", "rail-sw2"])

    def test_points(self):
        fe = self.p["frontend"]
        self.assertEqual([x["id"] for x in fe["points"]],
                         ["1-ent-client-eth1", "2-fw-ethernet1-4", "3-fw-ae1-leg1", "3-fw-ae1-leg2", "4-fe-sw1-Ethernet2", "4-fe-sw2-Ethernet2"])
        self.assertEqual([(x["switch"], x["native"]) for x in fe["legs"]], [("fe-sw1", "Ethernet2"), ("fe-sw2", "Ethernet2")])
        self.assertEqual(fe["pair"], ["fe-sw1", "fe-sw2"])
        self.assertEqual(fe["server_depth"], RT.WALK_BASE)
        self.assertEqual([x["vlan"] for x in fe["points"]], [None, None, 110, 110, 110, 110], "the users' VIP sits in the ingress VLAN")
        # the serving trace's points follow the frontend's five depths
        for cp in self.p["copies"]:
            self.assertTrue(all(x["id"].startswith(f"{6 + RT.WALK_BASE}-") for x in cp["switch_ports"]))
            self.assertTrue(cp["server"]["mac"].startswith("02:5a:"))
            self.assertIn(cp["vlan"], (100 + cp["rail"],))
        self.assertTrue(self.p["keys"]["capture"])

    def test_refusals(self):
        rf = self.p["refusals"]
        self.assertEqual((rf["hostname"]["hostname"], rf["hostname"]["expect"], rf["hostname"]["device"]), ("admin.ai.tarnwick.example", 404, "gw-users"))
        self.assertEqual((rf["key"]["model"], rf["key"]["route_model"], rf["key"]["expect"]), ("staff", "chat", 401))
        # one refusal message for any credential (multi-auth: a key, then a person's token)
        self.assertEqual(rf["key"]["message"], "Authorization Failed")
        self.assertEqual((rf["port"]["to"], rf["port"]["address"], rf["port"]["port"]), ("k8s-gpu1", "10.20.1.21", 22))
        self.assertEqual(rf["port"]["expect"], {"rule": "deny-all-log", "action": "deny", "from_zone": "enterprise", "to_zone": "k8s-nodes"})

    def refused(self, rx, change):
        raw = copy.deepcopy(self.raw)
        change(raw)
        with self.assertRaisesRegex(RenderError, rx):
            RT.walk_plan(self.c["m"], raw)

    def test_refused(self):
        self.refused("names all three refusals", lambda r: r["refuse"].pop("port"))
        self.refused("another model the lab serves", lambda r: r["refuse"]["key"].update(model="chat"))
        self.refused("another model the lab serves", lambda r: r["refuse"]["key"].update(model="nope"))
        # an enterprise client never reaches the authoritative servers itself: only the corporate
        # resolver does (ent-dns-to-platform-dns), so dns-auth1 on TCP 53 is a refusal the walk can use
        raw = copy.deepcopy(self.raw)
        raw["refuse"]["port"].update(to="dns-auth1", port=53)
        try:
            p = RT.walk_plan(self.c["m"], raw)
        except RenderError as e:
            self.assertNotIn("the render allows", str(e))
        else:
            self.assertEqual(p["refusals"]["port"]["expect"]["rule"], "deny-all-log")
        self.refused("is not behind the bundle", lambda r: r["refuse"]["port"].update(to="ops-dns"))
        self.refused("four unprivileged source ports", lambda r: r["refuse"]["port"].update(sport=r["sport"]))
        self.refused("unknown keys", lambda r: r.update(drills=1))

    def test_first_rule_and_nat(self):
        from sfab.render.panos import view  # noqa: PLC0415

        v = view(self.c["m"])
        self.assertEqual(RT.first_rule(v, "enterprise", "ingress", "10.24.10.10", "10.20.11.210", 443).name, "staff-to-users-gateway")
        self.assertEqual(RT.first_rule(v, "enterprise", "ingress", "10.24.10.10", "10.20.11.211", 443).name, "deny-all-log")
        self.assertEqual(RT.first_rule(v, "enterprise", "ingress", "10.24.10.10", "10.20.11.210", 80).name, "deny-all-log",
                         "application-default: ssl on 443 only")
        self.assertEqual(RT.first_rule(v, "services", "services", "10.20.13.21", "10.20.13.11", 53, "udp").name, "resolvers-to-auth")
        self.assertEqual(RT.first_rule(v, "k8s-nodes", "uplink", "10.20.1.21", "192.0.2.6", 5000).name, "nodes-to-registry")
        self.assertEqual(RT.first_rule(v, "k8s-nodes", "uplink", "10.20.1.21", "192.0.2.6", 443).name, "deny-all-log",
                         "the registry's rule names its one port")
        self.assertEqual(RT.first_rule(v, "k8s-nodes", "uplink", "10.20.1.21", "192.0.2.18", 443).name, "deny-all-log",
                         "no egress to an arbitrary internet host")
        self.assertIsNone(RT.first_nat(v, "enterprise", "ingress", "10.24.10.10", "10.20.11.210", 443))
        self.assertEqual(RT.first_nat(v, "k8s-nodes", "uplink", "10.20.1.11", "198.51.100.2", 443).name, "no-nat-public")
        self.assertEqual(RT.first_nat(v, "k8s-nodes", "uplink", "10.20.1.11", "198.51.100.1", 443).name, "internet-snat")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Break1a(unittest.TestCase):
    def setUp(self):
        self.c = ch01()
        self.raw = self.c["brk"]

    def b(self, raw=None):
        return RD._break(self.c["inv"], "1a", raw if raw is not None else self.raw, self.c["m"])

    def test_resolved(self):
        b = self.b()
        e = b["break"][0]
        self.assertEqual((e["kind"], e["op"], e["table"], e["rule"], e["field"]), ("panos_api", "edit", "security", "staff-to-users-gateway",
                                                                                   "destination"))
        self.assertEqual(e["element"], "<destination><member>10.20.11.211</member></destination>")
        self.assertEqual((e["members"], e["rendered"]), (["10.20.11.211"], ["10.20.11.210"]))
        self.assertTrue(e["xpath"].endswith("/rules/entry[@name='staff-to-users-gateway']/destination"))
        h = b["heal"][0]
        self.assertEqual((h["op"], h["members"], h["element"]), ("edit", ["10.20.11.210"], "<destination><member>10.20.11.210</member></destination>"))
        syn = next(a for a in b["record"] if a["kind"] == "probe_syn")
        self.assertEqual((syn["node"], syn["client_addr"], syn["dst_addr"], syn["port"], syn["sport"], syn["count"]),
                         ("ent-client", "10.24.10.10", "10.20.11.210", 443, 42150, 3))
        self.assertEqual([c["id"] for c in syn["capture"]], ["fw-ethernet1-4", "fw-ethernet1-1", "fw-ethernet1-2"])
        self.assertIn("vlan and (", syn["filter"])
        at = next(a for a in b["expect_broken"] if a["kind"] == "syn_at")
        self.assertEqual((at["seen"], at["unseen"]), (["fw-ethernet1-4"], ["fw-ethernet1-1", "fw-ethernet1-2"]))
        at = next(a for a in b["expect_healed"] if a["kind"] == "syn_at")
        self.assertEqual(at["seen_any"], ["fw-ethernet1-1", "fw-ethernet1-2"])
        tl = next(a for a in b["expect_broken"] if a["kind"] == "tlog_rule")
        self.assertEqual(tl, {"kind": "tlog_rule", "node": "fw", "probe": "syn", "rule": "deny-all-log", "action": "deny"})

    def refused(self, rx, change):
        raw = copy.deepcopy(self.raw)
        change(raw)
        with self.assertRaisesRegex(RenderError, rx):
            self.b(raw)

    def test_refused(self):
        self.refused("a break moves it elsewhere", lambda r: r["break"][0]["panos_api"].update(destination=["10.20.11.210"]))
        self.refused("an address or prefix, or rendered", lambda r: r["break"][0]["panos_api"].update(destination=["users-vip"]))
        self.refused("edit: security", lambda r: r["break"][0]["panos_api"].update({"edit": "nat"}))
        self.refused("one of del: or set:", lambda r: r["break"][0]["panos_api"].pop("destination"))
        self.refused("does not capture", lambda r: r["expect_broken"][2]["syn_at"].update(unseen=["fw:eth3"]))
        self.refused("is not a security rule", lambda r: r["expect_broken"][3]["tlog_rule"].update(rule="deny-all"))
        self.refused("must be a client container", lambda r: r["record"][1]["probe_syn"].update({"from": "k8s-gpu1"}))
        self.refused("a wired container port", lambda r: r["record"][1]["probe_syn"].update(capture=["k8s-gpu1:eth1"]))
        self.refused("no probe_syn of record", lambda r: r["expect_healed"][3]["tlog_rule"].update(probe="users"))


if __name__ == "__main__":
    unittest.main()
