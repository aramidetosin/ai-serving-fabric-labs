"""Chapter 2's render: the decision table and the matrix (render/decisions.py), the decision labels a
decisions lab stamps on every object, the walk's row tags (render/trace.py) and break-2a
(render/drills.py dns_answer, restore of a DNS server, matrix_cells and cell_mode).

- The table holds the seven rows of Table 2-1, in order, each with the lab's objects that implement it
  and the decision id each carries; the switches are labeled forwarding only; an id the spec gives an
  object of no row must be listed with why.
- The matrix holds Table 2-2's 30 cells, every mode computed from the spec as the request meets the
  layers: 15 allowed, 14 log lines (deny-all-log) and one 404, none silent; the operator's internal
  Gateway cell is tried at the public address, and every operator cell refused at the firewall rides
  the uplink router's static route via the public address. A router without the route makes the cell
  silent there.
- A decisions lab labels every security and NAT rule (a derived id where the spec gives none), each
  zone file entry a view answers, each consumer group, each rail attachment and the recipe's route, and
  every switch; a lab without decisions: true renders as before (chapter 1's committed render).
- break-2a renders the enterprise view's zone with the admin names answering the internal Gateway's
  VIP, and its heal restores the bastion's render; a break that moves no answer, names a name the
  zone does not hold, or checks a cell no matrix_cells tries is refused.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_ch02_render -v
"""

from __future__ import annotations

import copy
import dataclasses
import json
import xml.etree.ElementTree as ET
import unittest
from pathlib import Path

from sfab.render import RenderError
from sfab.render import decisions as DC
from sfab.render import drills as RD

ROOT = Path(__file__).resolve().parents[3]
CH02 = ROOT / "ch02"

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch02():
    if "m" not in _CACHE:
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, read_yaml, select  # noqa: PLC0415

        spec = load(ROOT)
        ch = load_chapter(CH02)
        m = select(spec, ch)
        m1 = select(spec, load_chapter(ROOT / "ch01"))
        _CACHE.update(m=m, m1=m1, ch=ch, inv=inventory(m), brk=read_yaml(CH02 / "breaks" / "2a.yaml"))
    return _CACHE


def with_spec(m, **changes):
    s = copy.deepcopy(m.spec)
    for k, v in changes.items():
        cur = s
        parts = k.split("__")
        for p in parts[:-1]:
            cur = cur[p]
        cur[parts[-1]] = v
    return dataclasses.replace(m, spec=s)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Table(unittest.TestCase):
    def setUp(self):
        self.m = ch02()["m"]
        self.t = DC.table(self.m)

    def test_committed_files_are_the_render(self):
        t = json.loads((CH02 / "gen" / "decisions.json").read_text())
        self.assertEqual({k: v for k, v in t.items() if k != "plan"}, json.loads(DC.dumps(self.t)))
        self.assertEqual(json.loads((CH02 / "gen" / "matrix.json").read_text()), json.loads(DC.dumps(DC.matrix(self.m))))
        self.assertEqual(yaml.safe_load((CH02 / "gen" / "matrix.yaml").read_text()), json.loads((CH02 / "gen" / "matrix.json").read_text()))
        d = yaml.safe_load((CH02 / "gen" / "decisions.yaml").read_text())
        self.assertEqual(d, {k: v for k, v in t.items() if k != "plan"})

    def test_seven_rows_in_order(self):
        self.assertEqual([r["id"] for r in self.t["rows"]], list(DC.ROW_IDS))
        self.assertEqual([r["refusal"] for r in self.t["rows"]], ["none", "silence", "none", "log-line", "404", "401", "none"])
        objs = {r["id"]: r["objects"] for r in self.t["rows"]}
        self.assertEqual([o["name"] for o in objs["view"]], ["internal", "enterprise", "public-operator"])
        self.assertEqual(objs["policy"][-1]["name"], "deny-all-log")
        self.assertEqual(objs["policy"][-1]["decision"], "dec-policy-deny-all-log")
        self.assertEqual(next(o for o in objs["policy"] if o["name"] == "bastion-to-nodes")["decision"], "dec-policy-bastion-to-nodes")
        self.assertEqual(next(o for o in objs["policy"] if o["name"] == "operator-to-internal-gateway")["decision"], "dec-policy-operator-vpn")
        self.assertEqual([o["name"] for o in objs["nat"]], ["no-nat-public", "internet-snat"], "nothing is published on the uplink")
        # one consumer group per caller (inference.callers)
        self.assertEqual({o["name"]: o["decision"] for o in objs["key"]}, {"batch": "dec-key-batch", "helpdesk": "dec-key-helpdesk", "staff": "dec-key-staff"})
        self.assertEqual({o["name"] for o in objs["routeset"]}, {"models-gw-internal", "models-gw-users", "serving", "echo-gw-internal", "echo-gw-users"})
        up = [o for o in objs["routing"] if o["device"] == "uplink-rtr" and o["name"] != "operator-site"]
        self.assertEqual(len(up), 8)
        self.assertTrue(all(o["decision"] == "dec-route-inside-via-fw" and o["nexthop"] == "198.51.100.2" for o in up))
        site = next(o for o in objs["routing"] if o["device"] == "uplink-rtr" and o["name"] == "operator-site")
        self.assertEqual((site["dest"], site["nexthop"]), ("192.0.2.0/30", "192.0.2.22"), "the operator's site behind its VPN router")
        fw = {o["name"]: o for o in objs["routing"] if o["device"] == "fw"}
        self.assertEqual({k for k in fw if k.startswith("discard-")}, {"discard-10", "discard-172-16", "discard-192-168"})
        self.assertEqual(fw["operator-site"]["interface"], "tunnel.1")
        self.assertEqual(sorted(o["name"] for o in objs["placement"]), ["chat-a", "chat-b", "chat-c", "staff-a", "staff-b"])

    def test_switches_forwarding_only(self):
        f = self.t["forwarding"]
        self.assertEqual([s["name"] for s in f["switches"]], ["fe-sw1", "fe-sw2", "rail-sw1", "rail-sw2", "oob-sw"])
        self.assertTrue(all(s["decision"] == "dec-forwarding-only" for s in f["switches"]))
        self.assertEqual(self.t["other"][0]["decision"], "dec-storage-data-address")

    def test_an_unlisted_id_is_refused(self):
        m = with_spec(self.m, decisions__other=[])
        with self.assertRaises(RenderError) as e:
            DC.table(m)
        self.assertIn("dec-storage-data-address", str(e.exception))

    def test_rows_must_be_the_seven(self):
        rows = copy.deepcopy(self.m.spec["decisions"]["rows"])
        m = with_spec(self.m, decisions__rows=rows[1:])
        with self.assertRaises(RenderError):
            DC.table(m)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Matrix(unittest.TestCase):
    def setUp(self):
        self.m = ch02()["m"]
        self.x = DC.matrix(self.m)
        self.c = {c["id"]: c for c in self.x["cells"]}

    def test_table_2_2(self):
        n = self.x["counts"]
        self.assertEqual((n["cells"], n["allowed"], n["forbidden"], n["log-line"], n["404"], n["silence"], n["401"]), (44, 17, 27, 18, 1, 8, 6))
        modes = {k: v["mode"] for k, v in self.c.items()}
        staff = {k.split("/")[1]: v for k, v in modes.items() if k.startswith("enterprise/")}
        self.assertEqual(staff, {"gw-internal": "log-line", "gw-users": "allowed", "chat": "allowed", "staff": "allowed", "admin": "404",
                                 "api-server": "log-line", "node": "log-line", "bmc": "log-line", "stor-data": "silence",
                                 "stor-mgmt": "log-line", "egress": "log-line"})
        op = {k.split("/")[1]: v for k, v in modes.items() if k.startswith("operator/")}
        self.assertEqual({k: v for k, v in op.items() if v not in ("allowed",)},
                         {"gw-users": "log-line", "api-server": "silence", "node": "silence", "bmc": "silence", "stor-data": "silence",
                          "stor-mgmt": "silence"},
                         "inside the tunnel's proxy IDs a cell meets deny-all-log; outside them zone protection drops it silently")
        self.assertEqual([k for k, v in op.items() if v == "allowed"], ["gw-internal", "chat", "staff", "admin", "egress"],
                         "through the tunnel to the internal Gateway, and the internet outside the firewall")
        nodes = {k.split("/")[1]: v for k, v in modes.items() if k.startswith("nodes/")}
        self.assertEqual({k: v for k, v in nodes.items() if v != "allowed"},
                         {"bmc": "log-line", "stor-data": "silence", "egress": "log-line"})
        for cid in ("nodes/gw-internal", "nodes/gw-users", "nodes/chat", "nodes/admin"):
            h = [h for h in self.c[cid]["hops"] if h["row"] != "view"][0]
            self.assertEqual((h["row"], h["device"]), (None, "k8s-cp2"), f"{cid}: Cilium answers its own cluster's VIP on the node")
            self.assertNotIn("fw", self.c[cid], f"{cid}: no firewall rule on the path")
        web = {k.split("/")[1]: v for k, v in modes.items() if k.startswith("web/")}
        self.assertEqual({k for k, v in web.items() if v != "log-line"}, {"stor-data", "egress"},
                         "an internet host that is not the operator reaches nothing of the platform")
        self.assertEqual(web["chat"], "log-line")
        self.assertEqual(self.c["web/chat"]["address"], "198.51.100.2", "the public address, where nothing is published")
        self.assertTrue(all(c["expect"]["rule"] == "deny-all-log" for c in self.x["cells"] if c["mode"] == "log-line"))
        self.assertEqual(sorted(c for c in self.x["silence"]["cells"] if c.endswith("/stor-data")),
                         ["enterprise/stor-data", "nodes/stor-data", "operator/stor-data", "web/stor-data"],
                         "the storage VLAN has no gateway: the firewall discards it, the uplink router has no route to it")
        self.assertEqual(sorted(self.x["silence"]["strict_ip"]), ["operator/api-server", "operator/bmc", "operator/node", "operator/stor-mgmt"],
                         "the operator's cells outside the tunnel's proxy IDs: zone protection's strict IP check drops them")

    def test_where_each_cell_is_tried(self):
        c = self.c["operator/gw-internal"]
        self.assertEqual(c["address"], "10.20.11.200", "the operator asks the VIP itself, through the tunnel")
        self.assertEqual(c["hops"][0]["device"], "ops-gw")
        self.assertIn("IPsec tunnel", c["hops"][0]["what"])
        self.assertEqual(c["fw"], {"rule": "operator-to-internal-gateway", "from_zone": "operator-vpn", "to_zone": "ingress"})
        self.assertEqual(self.c["enterprise/gw-internal"]["address"], "10.20.11.200")
        self.assertEqual(self.c["enterprise/admin"]["address"], "10.20.11.210")
        self.assertEqual(self.c["enterprise/admin"]["gateway"], "gw-users")
        self.assertEqual(self.c["nodes/admin"]["route"], "echo-gw-internal")
        self.assertEqual(self.c["operator/chat"]["route"], "models-gw-internal")
        for cid in ("operator/api-server", "operator/stor-mgmt", "web/gw-internal"):
            h = next(h for h in self.c[cid]["hops"] if h["device"] == "uplink-rtr")
            self.assertEqual(h["via"], "198.51.100.2")
        self.assertEqual(self.c["operator/gw-users"]["expect"]["from_zone"], "operator-vpn",
                         "in the tunnel's selector, refused in the tunnel's zone")
        self.assertEqual(self.c["web/bmc"]["expect"]["to_zone"], "oob")
        sip = self.c["operator/node"]
        self.assertEqual((sip["mode"], sip["layer"], sip["expect"]["device"], sip["expect"]["drop"], sip["expect"]["counter"]),
                         ("silence", "routing", "fw", "strict-ip", "flow_dos_pf_strictip"))
        self.assertEqual(sip["expect"]["source_route"], "by 192.0.2.0/30 out tunnel.1 (operator-site)")
        self.assertIn("zone protection's strict IP check (zp-internet) drops it before any rule", sip["hops"][-1]["what"])
        self.assertEqual([h["device"] for h in sip["hops"]], ["ops-gw", "uplink-rtr", "fw"])
        self.assertNotIn("drop", self.c["web/node"]["expect"], "the internet host's own prefix is routed back over the uplink")
        self.assertEqual(self.c["nodes/node"]["hops"][0]["row"], None, "same segment: no routed hop")
        k = self.c["enterprise/chat"]["requests"]
        self.assertEqual([(q["id"], q["key"], q["expect"]["status"]) for q in k], [("own", "chat", 200), ("other", "staff", 401)])
        self.assertEqual(len({q["sport"] for c in self.x["cells"] for q in c["requests"]}), 50)

    def test_no_route_is_silence(self):
        # the uplink router without its route to the out-of-band segment
        m = self.m
        h = m.nodes["uplink-rtr"]
        h2 = dataclasses.replace(h, routes=tuple(r for r in h.routes if r.id != "inside-oob"))
        m2 = dataclasses.replace(m, nodes=dict(m.nodes, **{"uplink-rtr": h2}))
        x = {c["id"]: c for c in DC.matrix(m2)["cells"]}
        self.assertEqual(x["operator/bmc"]["mode"], "silence")
        self.assertEqual(x["operator/bmc"]["expect"]["device"], "uplink-rtr")
        self.assertIn("operator/bmc", DC.matrix(m2)["silence"]["cells"])
        self.assertIn("web/bmc", DC.matrix(m2)["silence"]["cells"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Labels(unittest.TestCase):
    def test_stamped_in_the_render(self):
        b = CH02 / "bootstrap"
        xml = (b / "fw" / "startup-config.xml").read_text()
        self.assertIn("<description>dec-policy-bastion-to-nodes</description>", xml)
        self.assertIn("<description>dec-nat-internet-snat</description>", xml)
        rules = ET.fromstring(xml).findall("devices/entry/vsys/entry/rulebase/security/rules/entry")
        nat = ET.fromstring(xml).findall("devices/entry/vsys/entry/rulebase/nat/rules/entry")
        self.assertEqual((len(rules), len(nat)), (24, 2))
        self.assertTrue(all(r.findtext("description") for r in rules + nat), "every rule carries its decision id")
        for sw in ("fe-sw1", "fe-sw2", "rail-sw1", "rail-sw2", "oob-sw"):
            self.assertTrue((b / sw / "startup-config.cfg").read_text().splitlines()[1].startswith("! decision dec-forwarding-only: "))
        z = (b / "dns-auth1" / "zones" / "db.enterprise.ai.tarnwick.example").read_text()
        self.assertIn("llm       IN A   10.20.11.210 ; decision dec-view-enterprise: a name users type", z)
        self.assertIn('desc: "dec-key-batch: application batch (owner data-platform, keys expire 2027-04-30); may call chat"',
                      (b / "k8s" / "62-inference.yaml").read_text())
        env = (b / "k8s" / "serving.env").read_text()
        self.assertIn("SERVING_NAD_DECISIONS='rail3=dec-place-chat rail4=dec-place-staff rail5=dec-place-staff rail6=dec-place-chat rail7=dec-place-chat'", env)
        self.assertIn("SERVING_ROUTE_DECISION=dec-routeset-internal", env)

    def test_chapter_1_renders_as_before(self):
        b = ROOT / "ch01" / "bootstrap"
        xml = (b / "fw" / "startup-config.xml").read_text()
        self.assertNotIn("dec-policy-bastion-to-nodes", xml)
        self.assertNotIn("dec-forwarding-only", (b / "rail-sw1" / "startup-config.cfg").read_text())
        self.assertNotIn("SERVING_NAD_DECISIONS", (b / "k8s" / "serving.env").read_text())
        self.assertFalse((ROOT / "ch01" / "gen" / "decisions.yaml").exists())
        self.assertFalse(DC.on(ch02()["m1"]))
        self.assertEqual(DC.render(ch02()["m1"], None), {})

    def test_recipe_stamps_the_attachments_and_its_route(self):
        import importlib.util  # noqa: PLC0415
        import sys  # noqa: PLC0415

        spec = importlib.util.spec_from_file_location("sfab_test_serving", ROOT / "serving-layer" / "serving.py")
        sv = importlib.util.module_from_spec(spec)
        sys.modules["sfab_test_serving"] = sv
        self.addCleanup(sys.modules.pop, "sfab_test_serving", None)
        spec.loader.exec_module(sv)
        s = sv.settings(sv.read_env(CH02 / "bootstrap" / "k8s" / "serving.env"))
        nad = sv.nad_doc(s, s.nads[0])
        self.assertEqual(nad["metadata"]["annotations"], {"decision.tarnwick.example/id": "dec-place-chat"})
        self.assertEqual(sv.route_labels(s)["decision.tarnwick.example/id"], "dec-routeset-internal")
        s1 = sv.settings(sv.read_env(ROOT / "ch01" / "bootstrap" / "k8s" / "serving.env"))
        self.assertNotIn("annotations", sv.nad_doc(s1, s1.nads[0])["metadata"])
        self.assertEqual(sv.route_labels(s1), {"app.kubernetes.io/name": sv.APP})


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Break2a(unittest.TestCase):
    def setUp(self):
        self.c = ch02()

    def b(self, raw):
        return RD._break(self.c["inv"], "2a", raw, self.c["m"])

    def test_committed_break_is_the_render(self):
        got = self.b(copy.deepcopy(self.c["brk"]))
        self.assertEqual(json.loads((CH02 / "gen" / "breaks.json").read_text())["breaks"]["2a"], json.loads(json.dumps(got)))
        a = got["break"][0]
        self.assertEqual((a["file"], a["address"], a["names"]), ("zones/db.enterprise.ai.tarnwick.example", "10.20.11.200",
                                                                 ["admin.ai.tarnwick.example", "grafana.ai.tarnwick.example"]))

    def test_refused(self):
        bad = copy.deepcopy(self.c["brk"])
        bad["break"][0]["dns_answer"]["answer"] = "vip:gw-users"
        with self.assertRaises(RenderError):
            self.b(bad)
        bad = copy.deepcopy(self.c["brk"])
        bad["break"][0]["dns_answer"]["names"] = ["nosuchname"]
        with self.assertRaises(RenderError):
            self.b(bad)
        bad = copy.deepcopy(self.c["brk"])
        bad["expect_broken"].append({"cell_mode": {"probe": "cells", "cell": "nodes/bmc", "mode": "log-line"}})
        with self.assertRaises(RenderError):
            self.b(bad)
        bad = copy.deepcopy(self.c["brk"])
        bad["heal"] = [{"restore": "fe-sw1"}]
        with self.assertRaises(RenderError):
            self.b(bad)
        bad = copy.deepcopy(self.c["brk"])
        bad["record"][1]["matrix_cells"]["cells"].append("enterprise/nowhere")
        with self.assertRaises(RenderError):
            self.b(bad)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class WalkRows(unittest.TestCase):
    def test_rows(self):
        p = json.loads((CH02 / "gen" / "trace.json").read_text())
        self.assertEqual(p["rows"]["hops"]["5"], "policy")
        self.assertEqual(p["rows"]["hops"]["9"], "routeset")
        self.assertEqual(p["rows"]["hops"]["7"], "forwarding")


if __name__ == "__main__":
    unittest.main()
