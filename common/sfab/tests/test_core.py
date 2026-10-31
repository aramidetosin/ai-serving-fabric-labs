"""Core tests: the when grammar, deep_merge, select and its closure, port mapping, addresses,
and every rejection validate() makes (FRAMEWORK.md section 2.5).

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_core -v
"""

from __future__ import annotations

import copy
import dataclasses
import unittest
from pathlib import Path

from sfab import addr, ports
from sfab.spec import SelectError, SpecError, check_whens, deep_merge, filter_when, parse_when, when

ROOT = Path(__file__).resolve().parents[3]

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def m1() -> dict:
    return {"lab": "sfab-m1", "profile": "a", "state": "one",
            "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2"]},
            "features": {"k8s": False, "serving": False, "storage_setup": False}}


OFF = {"k8s": False, "serving": False, "storage_setup": False}


class TestWhen(unittest.TestCase):
    def test_bare_state(self):
        self.assertTrue(when("one", "one", 3))
        self.assertFalse(when("one", "many", 9))

    def test_comparisons(self):
        self.assertTrue(when("many>=9", "many", 9))
        self.assertFalse(when("many>=9", "many", 8))
        self.assertTrue(when("many<=8", "many", 8))
        self.assertTrue(when("many==10", "many", 10))
        self.assertFalse(when("many!=10", "many", 10))
        self.assertTrue(when("many>8", "many", 9))
        self.assertTrue(when("many<9", "many", 8))
        self.assertFalse(when("many>=9", "one", 9))

    def test_disjunction(self):
        e = "one | many<=8"
        self.assertTrue(when(e, "one", 7))
        self.assertTrue(when(e, "many", 8))
        self.assertFalse(when(e, "many", 9))

    def test_empty_means_always(self):
        self.assertTrue(when(None, "one", 1))
        self.assertTrue(when("", "many", 11))
        self.assertEqual(parse_when(None), ())

    def test_bad_syntax(self):
        for bad in ("many >= x", "many=>9", "Many", "one || many", "one & many", "many>=9 extra", "|", "1one"):
            with self.subTest(expr=bad):
                with self.assertRaises(SpecError):
                    parse_when(bad)
        with self.assertRaises(SpecError):
            parse_when(9)

    def test_no_eval(self):
        with self.assertRaises(SpecError):
            when("__import__('os')", "one", 1)

    def test_check_whens_unknown_state(self):
        errs = check_whens({"hosts": {"x": {"when": "lots>=3"}}}, ["one", "many"])
        self.assertEqual(len(errs), 1)
        self.assertIn("unknown state", errs[0])

    def test_filter_when(self):
        tree = {"a": [{"id": 1, "when": "many>=9"}, {"id": 2}], "b": {"x": {"when": "one"}, "y": {"k": 1}}}
        self.assertEqual(filter_when(tree, "many", 8), {"a": [{"id": 2}], "b": {"y": {"k": 1}}})
        self.assertEqual(filter_when(tree, "many", 9), {"a": [{"id": 1}, {"id": 2}], "b": {"y": {"k": 1}}})
        self.assertEqual(filter_when(tree, "one", 7)["b"], {"x": {}, "y": {"k": 1}})


class TestLoad(unittest.TestCase):
    @unittest.skipUnless(HAVE_YAML, "PyYAML is not installed")
    def test_comma_in_flow_mapping(self):
        import tempfile

        from sfab.spec import _odd_keys, read_yaml

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("segments:\n  - {id: x, desc: one, two}\n")
        tree = read_yaml(Path(f.name))
        Path(f.name).unlink()
        self.assertEqual(list(_odd_keys({"a": {"b c": None}})), ["a.b c"])
        self.assertIn("two", tree["segments"][0])

    @unittest.skipUnless(HAVE_YAML, "PyYAML is not installed")
    def test_duplicate_key(self):
        import tempfile

        from sfab.spec import read_yaml

        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write("a: 1\na: 2\n")
        with self.assertRaises(SpecError):
            read_yaml(Path(f.name))
        Path(f.name).unlink()


class TestMerge(unittest.TestCase):
    def test_mappings(self):
        self.assertEqual(deep_merge({"a": {"b": 1, "c": 2}}, {"a": {"c": 3, "d": 4}}), {"a": {"b": 1, "c": 3, "d": 4}})

    def test_delete_key(self):
        self.assertEqual(deep_merge({"a": 1, "b": 2}, {"b": {"_delete": True}}), {"a": 1})

    def test_id_lists(self):
        base = [{"id": "x", "v": 1}, {"id": "y", "v": 2}]
        over = [{"id": "y", "v": 3}, {"id": "z", "v": 4}, {"id": "x", "_delete": True}]
        self.assertEqual(deep_merge(base, over), [{"id": "y", "v": 3}, {"id": "z", "v": 4}])

    def test_plain_lists_replace(self):
        self.assertEqual(deep_merge({"a": [1, 2]}, {"a": [3]}), {"a": [3]})

    def test_inputs_untouched(self):
        base = {"a": {"b": [1]}}
        over = {"a": {"c": 1}}
        deep_merge(base, over)
        self.assertEqual(base, {"a": {"b": [1]}})
        self.assertEqual(over, {"a": {"c": 1}})


class TestPorts(unittest.TestCase):
    def test_native(self):
        self.assertEqual(ports.native(1), "Ethernet0")
        self.assertEqual(ports.native("eth4"), "Ethernet3")
        self.assertEqual(ports.native(48), "Ethernet47")
        self.assertEqual(ports.native(49), "Ethernet48")
        self.assertEqual(ports.native(50), "Ethernet52")
        self.assertEqual(ports.native(56), "Ethernet76")

    def test_round_trip(self):
        for n in range(1, 57):
            self.assertEqual(ports.from_native(ports.native(n)), n)
        with self.assertRaises(ports.PortError):
            ports.from_native("Ethernet49")

    def test_out_of_range(self):
        for bad in (0, 57, "eth0", "eth57", "Ethernet3", True):
            with self.subTest(port=bad):
                with self.assertRaises(ports.PortError):
                    ports.native(bad)

    def test_num_nics(self):
        self.assertEqual(ports.num_nics([1, 2, 3, 12]), 12)
        self.assertEqual(ports.num_nics([1, 2], sflow=True), 56)
        self.assertEqual(ports.num_nics([]), 1)

    def test_range(self):
        self.assertEqual(ports.native_range([1, 2]), "Ethernet0-1")
        self.assertEqual(ports.native_range([5]), "Ethernet4")
        with self.assertRaises(ports.PortError):
            ports.native_range([1, 3])


class TestAddr(unittest.TestCase):
    def test_host(self):
        self.assertEqual(addr.host("10.20.1.0/24", 21), "10.20.1.21")
        self.assertEqual(addr.host_cidr("10.21.3.0/24", 11), "10.21.3.11/24")
        with self.assertRaises(addr.AddrError):
            addr.host("10.20.1.0/24", 0)
        with self.assertRaises(addr.AddrError):
            addr.host("10.20.1.0/24", 256)

    def test_classify(self):
        self.assertEqual(addr.classify("10.20.1.0/24"), "rfc1918")
        self.assertEqual(addr.classify("198.51.100.2"), "rfc5737")
        self.assertEqual(addr.classify("2001:db8:a::/48"), "rfc3849")
        self.assertEqual(addr.classify("8.8.8.8"), "other")
        self.assertTrue(addr.in_slirp("10.0.0.15"))
        self.assertFalse(addr.in_slirp("10.0.1.0/24"))

    def test_overlaps_and_mac(self):
        self.assertEqual(addr.overlaps([("a", "10.20.0.0/16"), ("b", "10.20.1.0/24"), ("c", "10.21.0.0/16")]), [("a", "b")])
        self.assertEqual(addr.mac("02:5a", 111, 1), "02:5a:6f:00:00:01")
        self.assertEqual(addr.subnet("192.0.2.0/26", 30, 2), "192.0.2.8/30")


@unittest.skipUnless(HAVE_YAML, "PyYAML is not installed")
class SpecCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from sfab.spec import load

        cls.spec = load(ROOT)

    def select(self, chapter: dict, mutate=None, spec=None):
        from sfab.spec import select

        sp = spec or self.spec
        if mutate:
            sp = copy.deepcopy(self.spec)
            mutate(sp.profiles["a"])
        return select(sp, chapter)


class TestSelect(SpecCase):
    def test_m1_nodes(self):
        m = self.select(m1())
        self.assertEqual(list(m.nodes), ["fe-sw1", "fe-sw2", "rail-sw1", "rail-sw2", "oob-sw", "fw", "k8s-gpu1", "k8s-gpu2"])
        self.assertEqual(m.lab, "sfab-m1")
        self.assertEqual((m.state, m.step), ("one", 7))
        self.assertEqual(m.container("fe-sw1"), "sfab-m1-fe-sw1")

    def test_disk_budget_is_growth_not_virtual_size(self):
        # FRAMEWORK.md 3.1: a guest's disk_gib is its root disk's virtual size (VM_DISK_GIB); the
        # budget is the expected growth under state/ and in the container layers.
        from sfab.render.inventory import inventory

        m = self.select(m1())
        g1, sw, fw = m.nodes["k8s-gpu1"], m.nodes["fe-sw1"], m.nodes["fw"]
        self.assertEqual(g1.disk_gib, 80)
        self.assertEqual((g1.budget.state_gib, g1.budget.layer_gib), (12.0, 0.0))
        self.assertEqual((sw.budget.state_gib, sw.budget.layer_gib), (0.0, 8.0))
        self.assertEqual((fw.budget.state_gib, fw.budget.layer_gib), (0.0, 16.0))
        self.assertFalse(hasattr(sw, "disk_gib"))
        b = inventory(m)["budget"]
        self.assertEqual((b["state_base_gib"], b["state_gib"], b["layer_gib"]), (1.0, 25.0, 56.0))
        self.assertNotIn("disk_gib", b)
        self.assertEqual(inventory(m)["nodes"]["k8s-gpu1"]["disk_gib"], 80)

    def test_guest_needs_its_disk_size_and_state_budget(self):
        for key in ("disk_gib", "state_gib"):
            with self.assertRaises(SpecError) as cm:
                self.select(m1(), mutate=lambda t, k=key: t["hosts"]["k8s-gpu1"].pop(k))
            self.assertIn(key, str(cm.exception))

    def test_m1_num_nics_and_portchannels(self):
        m = self.select(m1())
        sw = m.switches
        # the dedicated keepalive link on eth13 sets the pair's NUM_NICS in every lab that has the pair
        self.assertEqual(sw["fe-sw1"].num_nics, 13)
        self.assertEqual(sw["rail-sw1"].num_nics, 8)
        self.assertEqual(sw["rail-sw2"].num_nics, 8)
        self.assertEqual(sw["oob-sw"].num_nics, 3)
        self.assertEqual([p.id for p in sw["fe-sw1"].portchannels], [1, 10, 21, 22])
        pc10 = sw["fe-sw2"].portchannel(10)
        self.assertEqual((pc10.mode, pc10.vlans, pc10.mtu, pc10.mclag), ("trunk", (100, 110, 130, 131, 200, 300), 9216, True))
        self.assertEqual(sw["fe-sw1"].mclag.peer_ip, "10.20.255.1")
        self.assertEqual(sw["fe-sw2"].mclag.source_ip, "10.20.255.1")
        self.assertEqual((sw["fe-sw1"].mclag.session_vrf, sw["fe-sw1"].mclag.backup_source_ip, sw["fe-sw1"].mclag.backup_peer_ip),
                         ("VrfMclagKa", "10.20.255.4", "10.20.255.5"))
        ka = sw["fe-sw2"].keepalive
        self.assertEqual((ka.native, ka.address, ka.peer_address, ka.backup_vlan, ka.backup_address, ka.mtu),
                         ("Ethernet12", "10.20.255.1/31", "10.20.255.0", 3966, "10.20.255.5/31", 9216))
        self.assertEqual(sw["fe-sw1"].portchannel(1).vlans, (100, 110, 120, 130, 131, 200, 300, 3966), "the backup VLAN on the peer link")
        self.assertNotIn(3966, sw["fe-sw1"].vlans, "the backup VLAN is no served VLAN")
        self.assertEqual(sw["fe-sw1"].stp, "pvst")
        self.assertTrue(sw["fe-sw1"].portchannel(21).edge)
        self.assertFalse(sw["fe-sw1"].portchannel(10).edge, "the firewall's trunk is not an edge port")
        self.assertFalse(sw["fe-sw1"].portchannel(1).edge)
        self.assertEqual(sw["fe-sw1"].portchannel(21).mtu, 9216)
        self.assertIsNone(sw["oob-sw"].stp, "the out-of-band switch stays as it was")

    def test_full_port_plan(self):
        m = self.select({"lab": "sfab-ch03", "profile": "a", "state": "one"})
        # both switches the same 19 ports: the TrueNAS management bond has a leg on each, the
        # ingress nodes join the pair on eth14 and eth15, the keepalive link is eth13
        self.assertEqual(len(m.switches["fe-sw1"].nics), 19)
        self.assertEqual(len(m.switches["fe-sw2"].nics), 19)
        self.assertEqual(m.switches["fe-sw1"].access_ports, (), "no single-attached port: every host and appliance has two legs")
        pc32 = m.switches["fe-sw1"].portchannel(32)
        self.assertEqual((pc32.mode, pc32.vlans, [mb.native for mb in pc32.members]), ("access", (200,), ["Ethernet11"]))
        self.assertEqual(m.switches["fe-sw2"].portchannel(32).members[0].native, "Ethernet11")
        self.assertEqual(m.switches["fe-sw1"].portchannel(21).tagged, (120,), "the GPU nodes carry the storage VLAN tagged")
        self.assertEqual(m.switches["fe-sw1"].portchannel(14).tagged, (110,), "the ingress nodes carry the ingress VLAN tagged")
        self.assertEqual(m.switches["fe-sw1"].portchannel(31).vlans, (120,), "TrueNAS's data bond in the storage VLAN")
        self.assertEqual(m.switches["fe-sw1"].num_nics, 19)
        self.assertEqual(m.switches["fe-sw2"].num_nics, 19)
        self.assertEqual(len(m.switches["oob-sw"].nics), 8, "the bastion has no leg in the BMC VLAN; the ingress nodes have BMCs")
        self.assertEqual([len(p.members) for p in m.switches["fe-sw1"].portchannels if p.id == 31], [2])

    def test_ports_never_move(self):
        for ch in (m1(), {"lab": "sfab-ch03", "profile": "a", "state": "one"},
                   {"lab": "sfab-ch04", "profile": "a", "state": "one", "slice": ["fe", "k8s-cp1"], "features": OFF}):
            m = self.select(ch)
            for sw in ("fe-sw1", "fe-sw2"):
                n = m.switches[sw].port(4)
                if n is not None:
                    self.assertEqual((n.native, n.peer.node), ("Ethernet3", "k8s-cp1"))
                self.assertEqual(m.switches[sw].port(3).peer.node, "fw") if "fw" in m.nodes else None

    def test_host_pulls_its_switches(self):
        m = self.select({"lab": "sfab-ch05", "profile": "a", "state": "one", "slice": ["rail", "k8s-gpu1", "k8s-gpu2"], "features": OFF})
        self.assertEqual(set(m.nodes), {"rail-sw1", "rail-sw2", "k8s-gpu1", "k8s-gpu2", "fe-sw1", "fe-sw2", "oob-sw"})
        self.assertNotIn("fw", m.nodes)
        self.assertFalse(any(l.has("fw") for l in m.links))

    def test_pair_partner(self):
        m = self.select({"lab": "sfab-ch03", "profile": "a", "state": "one", "slice": ["fe-sw1"], "features": OFF})
        self.assertEqual(set(m.nodes), {"fe-sw1", "fe-sw2"})
        self.assertEqual([p.id for p in m.switches["fe-sw1"].portchannels], [1])
        self.assertEqual(m.switches["fe-sw1"].num_nics, 13, "the peer link and the keepalive link")

    def test_k8s_closure(self):
        m = self.select({"lab": "sfab-ch07", "profile": "a", "state": "one", "slice": ["k8s-cp1"],
                         "features": {"serving": False, "storage_setup": False}})
        for n in ("k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion", "inet-registry", "uplink-rtr", "fw", "fe-sw1", "fe-sw2", "oob-sw"):
            self.assertIn(n, m.nodes)
        self.assertNotIn("k8s-gpu1", m.nodes)
        self.assertIsNotNone(m.k8s)
        self.assertEqual(m.k8s.control, ("k8s-cp1", "k8s-cp2", "k8s-cp3"))

    def test_except_clash(self):
        with self.assertRaises(SelectError):
            self.select({"lab": "sfab-ch05", "profile": "a", "state": "one",
                         "slice": {"nodes": ["k8s-gpu1"], "except": ["oob-sw"]}, "features": OFF})

    def test_unknown_slice_token(self):
        with self.assertRaises(SelectError):
            self.select({"lab": "sfab-ch05", "profile": "a", "state": "one", "slice": ["nosuch"], "features": OFF})

    def test_features_only_off(self):
        with self.assertRaises(SelectError):
            self.select({"lab": "sfab-ch05", "profile": "a", "state": "one", "features": {"bogus": False}})
        with self.assertRaises(SelectError):
            self.select({"lab": "sfab-ch05", "profile": "a", "state": "one", "features": {"k8s": False}})  # serving needs k8s

    def test_prints_refusal(self):
        with self.assertRaises(SelectError) as cm:
            self.select({"lab": "sfab-ch03", "profile": "a", "state": "one", "slice": ["fe", "k8s-gpu1"], "features": OFF,
                         "prints": ["fe-sw1"]})
        self.assertIn("lost attachments", str(cm.exception))
        m = self.select({"lab": "sfab-ch05", "profile": "a", "state": "one", "slice": ["rail", "k8s-gpu1", "k8s-gpu2"],
                         "features": OFF, "prints": ["rail-sw1", "rail-sw2"]})
        self.assertIn("rail-sw1", m.nodes)

    def test_steps(self):
        self.assertEqual(self.select({"lab": "sfab-ch02", "profile": "a", "state": "one"}).step, 7)
        self.assertEqual(self.select({"lab": "sfab-ch09", "profile": "a", "state": "many"}).step, 9)
        self.assertEqual(self.select({"lab": "sfab-ch19", "profile": "a", "state": "many"}).step, 11)
        with self.assertRaises(SelectError):
            self.select({"lab": "sfab-ch09", "profile": "a", "state": "many", "step": 3})

    def test_many_additions(self):
        m8 = self.select({"lab": "sfab-ch08", "profile": "a", "state": "many"})
        m9 = self.select({"lab": "sfab-ch09", "profile": "a", "state": "many"})
        m10 = self.select({"lab": "sfab-ch10", "profile": "a", "state": "many"})
        self.assertIn("gw-inet", m8.gateways)
        self.assertNotIn("isp-rtr", m8.nodes)
        self.assertIn("isp-rtr", m9.nodes)
        rules9 = [r.name for r in m9.firewall.rules]
        for rules in (rules9, [r.name for r in m8.firewall.rules]):
            self.assertIn("ent-dns-to-platform-dns", rules, "the corporate resolver reaches the platform's servers in every state")
            self.assertFalse([r for r in rules if "bastion-dns" in r], "the bastion serves no DNS")
        self.assertNotIn("isp-to-internet-gateway", rules9)
        self.assertIn("isp-to-internet-gateway", [r.name for r in m10.firewall.rules])
        self.assertEqual(m10.firewall.nat[0].dnat, "10.20.11.220")
        self.assertEqual(m9.populations["enterprise"].resolver, "ent-dns")
        self.assertEqual(m9.populations["nodes"].resolvers, ("dns-res1", "dns-res2"))

    def test_relay_routes(self):
        m = self.select(m1())
        g = m.hosts["k8s-gpu2"]
        ns3 = next(x for x in g.relay.namespaces if x.rail == 3)
        self.assertEqual(ns3.rail_addr, "10.21.3.12/24")
        self.assertEqual(ns3.relay_addr, "10.21.250.3/24")
        self.assertEqual(len(ns3.routes), 7)
        self.assertEqual(ns3.routes[0].dest, "10.21.1.0/24")
        self.assertEqual((ns3.routes[0].via, ns3.routes[0].src), ("10.21.250.1", "10.21.3.12"))

    def test_placeholder_profile(self):
        with self.assertRaises(SelectError):
            self.select({"lab": "sfab-ch12", "profile": "b", "state": "one"})

    def test_deterministic(self):
        from sfab.render import Context, render_all

        outs = []
        for _ in range(2):
            m = self.select(m1())
            ctx = Context(outdir=ROOT / "dev" / "m1", labdir=ROOT / "dev" / "m1", root=ROOT, spec=self.spec)
            outs.append(render_all(m, ctx, only=("inventory",)).outputs)
        self.assertEqual(outs[0], outs[1])
        self.assertIn(b'"lab": "sfab-m1"', outs[0]["gen/inventory.json"])


class TestValidate(SpecCase):
    """Each rejection of FRAMEWORK 2.5, provoked by one change to profile a."""

    full = {"lab": "sfab-ch01", "profile": "a", "state": "one"}

    def assertRejected(self, mutate, needle, chapter=None):
        from sfab.validate import ValidationError

        with self.assertRaises(ValidationError) as cm:
            self.select(chapter or self.full, mutate=mutate)
        self.assertTrue(any(needle in p for p in cm.exception.problems), cm.exception.problems)

    def test_spec_is_clean(self):
        from sfab.validate import problems

        for ch in (self.full, m1(), {"lab": "sfab-ch11", "profile": "a", "state": "many"}):
            self.assertEqual(problems(self.select(ch)), [])

    @staticmethod
    def seg(t, sid):
        return next(s for s in t["segments"] if s["id"] == sid)

    def test_internal_outside_rfc1918(self):
        # a documentation prefix (RFC 5737): outside RFC 1918, and nobody's network
        self.assertRejected(lambda t: self.seg(t, "pods").update(prefix="203.0.113.0/24"), "must be RFC 1918")

    def test_external_outside_rfc5737(self):
        self.assertRejected(lambda t: self.seg(t, "operator").update(prefix="10.99.0.0/26"), "must be RFC 5737")

    def test_address_outside_segments(self):
        self.assertRejected(lambda t: t["hosts"]["ops-client"]["ifaces"]["eth1"].update(address="192.0.2.130/30"),
                            "outside every declared segment")

    def test_overlap(self):
        self.assertRejected(lambda t: t["segments"].append({"id": "extra", "prefix": "10.20.0.0/16", "scope": "internal"}),
                            "overlap")

    def test_slirp(self):
        self.assertRejected(lambda t: self.seg(t, "pods").update(prefix="10.0.0.0/16"), "10.0.0.0/24")

    def test_port_used_twice(self):
        self.assertRejected(lambda t: t["hosts"]["k8s-gpu2"]["bond"].update(eth=7), "used by 2 links")

    def test_num_nics_above_56(self):
        from sfab.validate import check_num_nics

        m = self.select(m1())
        sw = dataclasses.replace(m.switches["rail-sw1"], num_nics=57)
        m2 = dataclasses.replace(m, nodes={**m.nodes, "rail-sw1": sw})
        self.assertTrue(any("above 56" in p for p in check_num_nics(m2)))
        with self.assertRaises(ports.PortError):
            self.select(self.full, mutate=lambda t: t["hosts"]["k8s-gpu1"]["bond"].update(eth=57))

    def test_sflow_needs_eth56(self):
        self.assertRejected(lambda t: t["switches"]["rail-sw1"].update(sflow=True), "eth56 must be cabled")

    def test_unknown_zone(self):
        self.assertRejected(lambda t: t["firewall"]["rules"][0].update(to=["nowhere"]), "unknown zone")

    def test_audience_without_gateway(self):
        self.assertRejected(lambda t: t["audiences"][1].update(gateway="gw-missing"), "no Gateway")

    def test_same_parity_copies(self):
        # chat's copies a (rail 3), b (rail 6 moved to 5) and c (rail 7) all on rail-sw1's rails
        self.assertRejected(lambda t: t["models"][0]["copies"][1].update(rail=5), "the loss of that rail switch leaves no copy")

    def test_every_copy_on_one_node(self):
        def mut(t):
            for c in t["models"][1]["copies"]:
                c.update(server="k8s-gpu1", workers=["k8s-gpu1"])
        self.assertRejected(mut, "the loss of that node leaves no copy")

    def test_a_copy_across_nodes_says_so(self):
        self.assertRejected(lambda t: t["models"][0]["copies"][2].pop("spans"), "a copy across nodes must say spans: true")
        self.assertRejected(lambda t: t["models"][0]["copies"][0].update(spans=True), "says spans: true but sits on k8s-gpu1 alone")

    def test_long_label(self):
        self.assertRejected(lambda t: t["gateways"][0].update(decision="dec-" + "x" * 70), "more than 63")

    def test_domain_not_example(self):
        def mut(t):
            t["org"]["domain"] = "tarnwick.com"
            t["org"]["label_domain"] = "tarnwick.com"

        self.assertRejected(mut, "not under .example")

    def test_trunk_mtu_below_firewall(self):
        def mut(t):
            t["appliances"]["fw"]["attach"][0].pop("mtu")
            t.pop("l2")

        self.assertRejected(mut, "below the firewall's 9216")

    def test_pair_passthrough(self):
        """Required only of a pair whose keepalive would ride the management VRF (no keepalive: block)."""
        def mut(t):
            t["pairs"]["fe"].update(passthrough=False)
            t["pairs"]["fe"].pop("keepalive")

        self.assertRejected(mut, "CLAB_MGMT_PASSTHROUGH")

    def test_keepalive_refusals(self):
        def reserved(t):
            t["pairs"]["fe"]["keepalive"]["backup"]["vlan"] = 3999

        def wide(t):
            t["pairs"]["fe"]["keepalive"]["link"]["prefix"] = "10.20.255.0/30"

        def vrf(t):
            t["pairs"]["fe"]["keepalive"]["vrf"] = "ka"

        for mut, msg in ((reserved, "reserves VLANs 3967 to 4094"), (wide, "must be a /31"), (vrf, "start with Vrf")):
            with self.assertRaises(SpecError) as cm:
                self.select(self.full, mutate=mut)
            self.assertIn(msg, str(cm.exception))

    def test_deny_all_log_last(self):
        def mut(t):
            r = t["firewall"]["rules"]
            r.insert(0, r.pop())

        self.assertRejected(mut, "deny-all-log must be the last")

    def test_unknown_key(self):
        with self.assertRaises(SpecError) as cm:
            self.select(self.full, mutate=lambda t: t["gateways"][0].update(viip=201))
        self.assertIn("unknown key", str(cm.exception))

    def test_attach_to_missing_node(self):
        with self.assertRaises(SpecError):
            self.select(self.full, mutate=lambda t: t["hosts"]["ops-client"]["attach"][0].update(to="nosuch"))


if __name__ == "__main__":
    unittest.main()
