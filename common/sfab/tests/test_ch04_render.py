"""Chapter 4's plans: gen/trace.json (sfab.render.trace), the firewall drills in gen/drills.json and
break-4a in gen/breaks.json (sfab.render.drills), and what the inventory carries for the harness.

- The committed renders under ch04/gen are this render.
- The trace's two sessions resolve to the client, the address the request goes to, the address
  the destination NAT translates it to, the rule and NAT rule, and whether the name is pinned; the
  pull resolves to the node, the image by digest, the registry and the source NAT's address, and
  its capture points to inside and outside.
- The land drill holds the NAT rule's xpath, its rendered entry and where it goes back; the
  ntp-uplink drill the service route's two entries, the server and the rules on each side, and the
  DNS route that moves with it (the same server address).
- break-4a's firewall actions, probes and checks; every malformed one is refused, field named.
- A lab whose trace block is chapter 3's renders no gen/trace.json; ch03's drills plan is unchanged.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_ch04_render -v
"""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from sfab.render import RenderError
from sfab.render import drills as RD
from sfab.render import trace as RT

ROOT = Path(__file__).resolve().parents[3]
CH04 = ROOT / "ch04"

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch04():
    if "m" not in _CACHE:
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415

        spec = load(ROOT)
        ch = load_chapter(CH04)
        m = select(spec, ch)
        _CACHE.update(m=m, spec=spec, ch=ch, inv=inventory(m))
    return _CACHE


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class TracePlanTest(unittest.TestCase):
    def setUp(self):
        c = ch04()
        self.m, self.raw = c["m"], c["ch"].trace
        self.plan = RT.plan(self.m, self.raw)

    def test_committed_render_is_this_render(self):
        self.assertEqual(json.loads((CH04 / "gen" / "trace.json").read_text()), json.loads(RT.dumps(self.plan)))

    def test_sessions(self):
        e, o = self.plan["sessions"]
        self.assertEqual((e["client_addr"], e["dst_addr"], e["translated_addr"], e["pin"], e["resolver"]),
                         ("10.24.10.10", "10.20.11.210", None, False, "ent-dns"))
        # the operator through the tunnel: the VIP itself, untranslated, pinned (no public name)
        self.assertEqual((o["client_addr"], o["dst_addr"], o["translated_addr"], o["pin"]), ("192.0.2.2", "10.20.11.200", None, True))
        self.assertEqual(o["expect"], {"status": 200, "rule": "operator-to-internal-gateway", "nat_rule": None, "from_zone": "operator-vpn",
                                       "to_zone": "ingress"})
        self.assertEqual((e["fqdn"], e["msg"], e["sport"], e["hold_s"]), ("llm.ai.tarnwick.example", "sfab-ch04-enterprise", 42443, 30))

    def test_pull(self):
        p = self.plan["pull"]
        self.assertEqual((p["node"], p["node_addr"], p["registry_addr"], p["registry_port"], p["translated_src"]),
                         ("k8s-gpu2", "10.20.1.22", "192.0.2.6", 5000, "198.51.100.2"))
        self.assertTrue(p["image"].startswith("docker.io/alpine/helm@sha256:"))
        self.assertEqual([(x["id"], x["side"], x["vlan"]) for x in p["points"]],
                         [("1-fw-ae1-leg1", "inside", 100), ("1-fw-ae1-leg2", "inside", 100), ("2-fw-ethernet1-5", "outside", None)])

    def test_refusals(self):
        cases = [
            (lambda r: r["sessions"][1].update(via="nowhere"), "via"),
            (lambda r: r["sessions"][0]["expect"].update(rule="no-such-rule"), "is not a security rule"),
            (lambda r: r["sessions"][0].update(client="k8s-gpu1"), "must be a client container"),
            (lambda r: r["sessions"][0].update(gateway="gw-none"), "is not a Gateway"),
            (lambda r: r["sessions"][0].update(sport=80), "unprivileged port"),
            (lambda r: r["sessions"][0].update(extra=1), "unknown keys"),
            (lambda r: r["pull"].update(node="k8s-cp1"), "already holds the image"),
            (lambda r: r["pull"].update(node="bastion"), "VM guest with a Kubernetes role"),
            (lambda r: r["pull"].update(image="test_backend"), "node_helm"),
            (lambda r: r["pull"]["expect"].update(nat_rule="no-nat-public"), "source NAT rule"),
            (lambda r: r["pull"].update(points=r["pull"]["points"][:2]), "both sides"),
            (lambda r: r["pull"]["points"][0].update(eth="eth9"), "has no wired eth9"),
        ]
        for change, want in cases:
            raw = copy.deepcopy(self.raw)
            change(raw)
            with self.assertRaisesRegex(RenderError, want):
                RT.plan(self.m, raw)

    def test_chapter_3_trace_renders_none(self):
        from sfab.render import Context  # noqa: PLC0415
        from sfab.spec import load_chapter, select  # noqa: PLC0415

        m3 = select(ch04()["spec"], load_chapter(ROOT / "ch03"))
        ctx = Context(outdir=Path(tempfile.gettempdir()), labdir=ROOT / "ch03", root=ROOT, spec=ch04()["spec"])
        self.assertEqual(RT.render(m3, ctx), {})


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class FwDrillsTest(unittest.TestCase):
    def setUp(self):
        c = ch04()
        self.m, self.inv, self.raw = c["m"], c["inv"], c["ch"].drills
        self.plan = RD.drills(self.inv, self.raw, self.m)

    def test_committed_render_is_this_render(self):
        self.assertEqual(json.loads((CH04 / "gen" / "drills.json").read_text()), json.loads(RD.dumps(self.plan)))

    def test_land(self):
        land = next(d for d in self.plan["list"] if d["id"] == "land")
        self.assertEqual((land["kind"], land["counter"], land["probe"]), ("fw_nat_removed", "flow_policy_nat_land", "public"))
        n = land["nat"]
        self.assertEqual(n["place"], {"where": "before", "dst": "internet-snat"})
        self.assertTrue(n["xpath"].endswith("/rulebase/nat/rules/entry[@name='no-nat-public']"))
        e = ET.fromstring(n["element"])
        self.assertEqual((e.get("name"), [x.text for x in e.findall("to/member")], e.find("source-translation")),
                         ("no-nat-public", ["uplink"], None))
        self.assertEqual(land["diag"], {"source": "10.20.1.12", "destination": "198.51.100.2", "stages": ["receive", "drop"]})
        self.assertEqual(land["capture"]["eths"], ["eth1", "eth2", "eth5"])
        self.assertEqual(self.plan["probes"]["public"]["src_kind"], "vm-node")
        self.assertEqual(self.plan["timing"], {"settle_s": 5, "ntp_wait_s": 300, "log_pause_s": 10})

    def test_ntp_uplink(self):
        d = next(x for x in self.plan["list"] if x["id"] == "ntp-uplink")
        self.assertEqual((d["server"], d["port"], d["expect_rule"], d["restore_rule"]), ("10.20.13.21", 123, "deny-all-log", "inside-to-ntp"))
        self.assertEqual((d["from"], d["to"]), ({"interface": "ae1.130", "address": "10.20.13.1", "zone": "services"},
                                                {"interface": "ethernet1/5", "address": "198.51.100.2", "zone": "uplink"}))
        self.assertEqual(ET.fromstring(d["element"]).findtext("source/interface"), "ethernet1/5")
        self.assertEqual(ET.fromstring(d["restore_element"]).findtext("source/address"), "10.20.13.1/24")
        self.assertEqual(d["server_zone"], "services")
        # the DNS route moves with it: its server is the same address
        (w,) = d["with"]
        self.assertEqual((w["service"], w["port"], w["server"], w["restore_rule"]), ("dns", 53, "10.20.13.21", "inside-to-resolvers"))
        self.assertTrue(w["xpath"].endswith("/route/service/entry[@name='dns']"))
        self.assertEqual(ET.fromstring(w["element"]).findtext("source/interface"), "ethernet1/5")
        self.assertEqual(ET.fromstring(w["restore_element"]).findtext("source/interface"), "ae1.130")
        self.assertEqual((d["domain"], d["capture"]["filter"]), ("ai.tarnwick.example", "udp port 123 or udp port 53"))

    def test_refusals(self):
        cases = [
            (lambda r: r["list"][0].update(nat_removed="no-such-rule"), "is not a NAT rule"),
            (lambda r: r["list"][0].update(counter="Flow-Policy"), "a global counter name"),
            (lambda r: r["list"][0].update(capture=["egress"]), "unknown stage"),
            (lambda r: r["list"][0].update(probe="ping"), "names the public probe"),
            (lambda r: r["list"][1]["service_route"].update(service="dns"), "ntp is the service"),
            (lambda r: r["list"][1]["service_route"].update(interface="ae1.130"), "already uses"),
            (lambda r: r["list"][1]["service_route"].update(interface="ethernet1/9"), "is not an addressed interface"),
            (lambda r: r["list"][1].update(expect_rule="nope"), "is not a security rule"),
            (lambda r: r["list"][1]["service_route"].pop("with"), "dns shares the server 10.20.13.21 and must move with ntp"),
            (lambda r: r["list"][1]["service_route"].update({"with": ["ntp"]}), "does not share the server"),
            (lambda r: r["list"][1]["service_route"].update(also=["dns"]), "unknown keys"),
            (lambda r: r["timing"].update(hold_s=3), "unknown key"),
            (lambda r: r["probes"]["public"].update(to="999.1"), "neither public, a node nor an address"),
        ]
        for change, want in cases:
            raw = copy.deepcopy(self.raw)
            change(raw)
            with self.assertRaisesRegex(RenderError, want):
                RD.drills(self.inv, raw, self.m)

    def test_chapter_3_plan_unchanged(self):
        from sfab.spec import load_chapter, select  # noqa: PLC0415
        from sfab.render.inventory import inventory  # noqa: PLC0415

        ch3 = load_chapter(ROOT / "ch03")
        m3 = select(ch04()["spec"], ch3)
        plan3 = RD.drills(inventory(m3), ch3.drills, m3)
        self.assertEqual(json.loads((ROOT / "ch03" / "gen" / "drills.json").read_text()), json.loads(RD.dumps(plan3)))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Break4aTest(unittest.TestCase):
    def setUp(self):
        c = ch04()
        self.m, self.inv = c["m"], c["inv"]
        from sfab.spec import read_yaml  # noqa: PLC0415

        self.raw = read_yaml(CH04 / "breaks" / "4a.yaml")

    def test_4a(self):
        b = RD._break(self.inv, "4a", self.raw, self.m)
        self.assertEqual([(a["kind"], a["op"], a["rule"]) for a in b["break"]], [("panos_api", "del", "no-nat-public")])
        self.assertNotIn("element", b["break"][0])
        h = b["heal"][0]
        self.assertEqual((h["op"], h["place"]), ("set", {"where": "before", "dst": "internet-snat"}))
        self.assertEqual(ET.fromstring(h["element"]).get("name"), "no-nat-public")
        rec = {a.get("id") or a["kind"]: a for a in b["record"]}
        self.assertEqual((rec["node-public"]["node"], rec["node-public"]["dst_addr"], rec["node-public"]["counters"]),
                         ("k8s-cp2", "198.51.100.2", ["flow_policy_nat_land"]))
        self.assertEqual(rec["users"]["url"], "https://llm.ai.tarnwick.example/echo?msg=sfab-break-4a")
        # the delta views bracket one ping run that reads no full counter table: every show counter
        # global read starts the next delta sampling
        self.assertEqual([(a["kind"], a.get("id") or a.get("lines")) for a in b["record"][:3]],
                         [("fw_show", ["show counter global filter delta yes severity drop"]), ("probe_ping", "node-delta"),
                          ("fw_show", ["show counter global filter delta yes severity drop", "show running nat-policy"])])
        self.assertEqual(rec["node-delta"]["counters"], [])
        self.assertEqual([(a["kind"], a.get("probe"), a.get("failing") or a.get("rise")) for a in b["expect_broken"]],
                         [("probe_share", "node-delta", "all"), ("probe_share", "node-public", "all"), ("counter", "node-public", True),
                          ("probe_share", "users", "none")])
        self.assertEqual(b["expect_healed"][0], {"kind": "rule_order", "node": "fw"})
        committed = json.loads((CH04 / "gen" / "breaks.json").read_text())["breaks"]["4a"]
        self.assertEqual(committed, json.loads(json.dumps(b)))

    def test_refusals(self):
        cases = [
            (lambda r: r["break"].__setitem__(0, {"panos_api": {"del": "nat", "set": "nat", "rule": "no-nat-public"}}), "one of del"),
            (lambda r: r["break"].__setitem__(0, {"panos_api": {"del": "routes", "rule": "x"}}), "nat or security"),
            (lambda r: r["break"].__setitem__(0, {"fw_show": {"lines": ["show running nat-policy"]}}), "does not belong"),
            (lambda r: r["record"].__setitem__(0, {"fw_show": {"lines": ["show log traffic"]}}), "time filter"),
            (lambda r: r["record"].__setitem__(0, {"fw_show": {"lines": ["clear counter global"]}}), "show lines only"),
            (lambda r: r["record"][3]["probe_ping"].update(counters=["Bad Name"]), "not a counter name"),
            (lambda r: r["record"][4]["probe_http"].update(**{"from": "k8s-gpu1"}), "must be a client container"),
            (lambda r: r["expect_broken"].__setitem__(2, {"counter": {"name": "flow_policy_nat_land", "probe": "users"}}), "reads no such counter"),
            (lambda r: r["expect_broken"].__setitem__(2, {"counter": {"name": "flow_policy_nat_land", "probe": "node-delta"}}), "reads no such counter"),
            (lambda r: r["expect_broken"].__setitem__(0, {"probe_share": {"probe": "node-public", "failing": "most"}}), "none or all"),
            (lambda r: r["expect_healed"].__setitem__(0, {"rule_order": {"strict": True}}), "takes no settings"),
        ]
        for change, want in cases:
            raw = copy.deepcopy(self.raw)
            change(raw)
            with self.assertRaisesRegex(RenderError, want):
                RD._break(self.inv, "4a", raw, self.m)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class InventoryTest(unittest.TestCase):
    def test_firewall_and_router_blocks(self):
        inv = ch04()["inv"]
        fw = inv["nodes"]["fw"]
        self.assertEqual(fw["nat"], ["no-nat-public", "internet-snat"])
        self.assertEqual(fw["rules"][-1], "deny-all-log")
        self.assertEqual(fw["system"]["service_routes"]["ntp"], {"interface": "ae1.130", "address": "10.20.13.1/24",
                                                                 "rule": "inside-to-ntp"})
        self.assertEqual(fw["admin"], {"interface": "ae1.300", "profile": "bastion-admin", "allow": ["https", "ssh", "ping"],
                                       "permitted": ["10.20.3.10/32"]})
        self.assertEqual([(r["dest"], r["via"]) for r in inv["nodes"]["uplink-rtr"]["routes"]],
                         [("192.0.2.0/30", "192.0.2.22")] +
                         [(p, "198.51.100.2") for p in ("10.20.1.0/24", "10.20.11.0/24", "10.20.2.0/24", "10.20.3.0/24", "10.20.13.0/24",
                                                       "10.20.14.0/24", "10.20.9.0/24", "10.24.10.0/24")])


if __name__ == "__main__":
    unittest.main()
