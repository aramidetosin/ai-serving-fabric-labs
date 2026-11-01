"""Part III's tool plans as the render makes them (chapters 8 to 11): gen/tenancy.json
(render/tenancy.py), the trace forms of render/trace.py (chapter 8's serving trace from a node of the
cluster with its also and refuse on another Gateway, chapter 9's dns form, chapter 10's nat form,
chapter 11's ladder), Part III's drills in gen/drills.json, the probe_syn break action across the
destination NAT, and what each refuses. Every outcome the plans carry is render/decisions.py's path,
so the tests assert the render's own facts, never a lab's.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_part3_tools_render -v
"""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from sfab.render import RenderError

from .test_part3_render import HAVE_YAML, lab

ROOT = Path(__file__).resolve().parents[3]


def with_chapter(name: str, edit):
    """A copy of lab name's model whose chapter.yaml (raw and parsed) edit(raw) changed."""
    import dataclasses  # noqa: PLC0415

    from sfab.spec import chapter_from_dict  # noqa: PLC0415

    c = lab(name)
    m = c["m"]
    raw = copy.deepcopy(m.meta.chapter.raw)
    edit(raw)
    ch = chapter_from_dict(raw)
    meta = dataclasses.replace(m.meta, chapter=ch)
    return dataclasses.replace(m, meta=meta)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TenancyPlanTest(unittest.TestCase):
    def plan(self, name):
        from sfab.render import tenancy  # noqa: PLC0415

        c = lab(name)
        return tenancy.plan(c["m"], c["ctx"])

    def test_ch08_audiences(self):
        p = self.plan("ch08")
        self.assertEqual(sorted(p), ["audiences", "lab", "schema", "step"])
        a = p["audiences"]
        self.assertEqual(sorted(a["gateways"]), ["gw-inet", "gw-internal", "gw-users"])
        self.assertEqual(a["gateways"]["gw-inet"]["models"], ["chat"])
        self.assertEqual(a["gateways"]["gw-inet"]["namespaces"], ["echo", "inference"])
        self.assertTrue(a["gateways"]["gw-internal"]["bare_prefix"])
        self.assertEqual(a["gateways"]["gw-internal"]["admin"], ["admin.ai.tarnwick.example", "grafana.ai.tarnwick.example"])
        self.assertEqual(a["refused_mint"], {"caller": "inetapp", "model": "staff", "id": "fe000000", "audience": "internet",
                                             "audience_models": ["chat"]})
        self.assertEqual(a["lease"]["config"], {"l2-announcements-lease-duration": "3s", "l2-announcements-renew-deadline": "1s",
                                                "l2-announcements-retry-period": "200ms"})
        self.assertEqual(a["ingress_nodes"], ["k8s-ingress1", "k8s-ingress2"])
        # the internet Gateway's column for the Part II rows; the internet host has no client in ch08
        col = {r["population"]: r for r in a["column"]["rows"]}
        self.assertEqual(a["column"]["address"], "10.20.11.220")
        self.assertEqual({k: (r["client"], r["outcome"], r.get("rule")) for k, r in col.items()},
                         {"enterprise": ("ent-client", "log-line", "deny-all-log"), "operator": ("ops-client", "log-line", "deny-all-log"),
                          "nodes": ("k8s-cp2", "reached", None)})
        self.assertEqual(a["column"]["no_client"], ["web"])
        # no population reaches gw-inet in ch08: its chain is read from k8s-cp2 at the VIP
        self.assertEqual(a["tls_from"]["gw-inet"], {"node": "k8s-cp2", "kind": "vm-node", "address": "10.20.11.220", "population": "nodes"})
        self.assertEqual(a["tls_from"]["gw-users"]["node"], "ent-client")
        self.assertEqual(sorted(r["population"] for r in a["reach"]), ["enterprise", "operator"])

    def test_reach_by_step(self):
        r9 = {r["population"]: r for r in self.plan("ch09")["audiences"]["reach"]}
        self.assertEqual((r9["internet"]["outcome"], r9["internet"]["rule"]), ("log-line", "deny-all-log"))
        a10 = self.plan("ch10")["audiences"]
        r10 = {r["population"]: r for r in a10["reach"]}
        self.assertEqual((r10["internet"]["outcome"], r10["internet"]["address"]), ("reached", "198.51.100.10"))
        self.assertEqual(a10["tls_from"]["gw-inet"], {"node": "inet-client", "kind": "client", "address": "198.51.100.10",
                                                     "population": "internet"})
        col11 = {r["population"]: r for r in self.plan("ch11")["audiences"]["column"]["rows"]}
        self.assertEqual((col11["web"]["client"], col11["web"]["rule"]), ("web-client", "deny-all-log"))
        self.assertNotIn("internet", col11)
        self.assertEqual(self.plan("ch09")["dns"]["envoy_certs"]["nodes"], ["k8s-ingress1", "k8s-ingress2", "k8s-cp1"])

    def test_ch09_dns(self):
        d = self.plan("ch09")["dns"]
        self.assertEqual(d["public"]["names"], {"llm.ai.tarnwick.example": "198.51.100.10"})
        self.assertIn("admin.ai.tarnwick.example", d["public"]["absent"])
        self.assertIn("id.ai.tarnwick.example", d["public"]["absent"])
        self.assertIn("k8s-cp1.ai.tarnwick.example", d["public"]["absent"])
        self.assertEqual(d["isp"]["outside"], {"node": "isp-rtr", "source": "198.51.100.9"})
        rows = {r["population"]: r for r in d["aaaa"]}
        self.assertEqual(rows["nodes"]["client"], "k8s-cp2", "the matrix's client for the nodes")
        self.assertEqual(rows["operator"]["names"], [], "the uplink side's server publishes no platform name")
        s = d["internet_syn"]
        self.assertEqual((s["outcome"], s["rule"], s["from_zone"], s["to_zone"]), ("log-line", "deny-all-log", "isp", "isp"))
        self.assertEqual(d["ops"]["server"], "ops-dns")

    def test_ch10_firewall_and_ch09_none(self):
        self.assertNotIn("firewall", self.plan("ch09"), "no published address before step 10")
        f = self.plan("ch10")["firewall"]
        self.assertEqual(f["nat_order"], ["dnat-internet-gateway", "no-nat-public", "internet-snat"])
        self.assertEqual(f["security_order"][-2:], ["isp-to-internet-gateway", "deny-all-log"])
        self.assertEqual(f["published"]["translated"], "10.20.11.220")
        self.assertEqual(f["isp_nat"], ["dnat-internet-gateway"])
        self.assertEqual(f["isp_rules"], ["isp-to-internet-gateway"])
        inside = {r["population"]: r for r in f["inside"]}
        self.assertEqual((inside["enterprise"]["rule"], inside["enterprise"]["to_zone"]), ("deny-all-log", "isp"))
        self.assertEqual((inside["operator"]["outcome"], inside["operator"]["device"]), ("silence", "uplink-rtr"))

    def test_ch10_hold(self):
        h = self.plan("ch10")["hold"]
        rows = {r["population"]: r for r in h["rows"]}
        self.assertEqual(sorted(rows), ["enterprise", "internet", "operator"])
        self.assertEqual(rows["internet"]["filter"], "from isp destination 198.51.100.10 destination-port 443")
        self.assertEqual(rows["internet"]["chat"]["caller"], "inetapp")
        self.assertEqual(rows["operator"]["resolve"], "llm.ai.tarnwick.example:443:10.20.11.200", "the operator's server publishes no name")
        self.assertEqual(rows["enterprise"]["bound"], {"min": 8, "max": 11})
        self.assertEqual(h["timeouts"]["discard_tcp"], 90)

    def test_ch11_isolation(self):
        i = self.plan("ch11")["isolation"]
        self.assertEqual(i["gateway"], "gw-inet")
        self.assertEqual(i["forbidden_models"], ["staff"])
        self.assertEqual(i["translated"], "10.20.11.220")

    def test_hold_refusals(self):
        from sfab.render import tenancy  # noqa: PLC0415

        c = lab("ch10")
        m = with_chapter("ch10", lambda r: r["tenancy"]["hold"].update(every_s=200))
        with self.assertRaisesRegex(RenderError, "every_s: shorter than hold_s"):
            tenancy.plan(m, c["ctx"])
        m = with_chapter("ch09", lambda r: r.setdefault("tenancy", {}).update(hold={"n": 2}))
        with self.assertRaisesRegex(RenderError, "needs the zone-keyed translation"):
            tenancy.plan(m, lab("ch09")["ctx"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TraceFormsTest(unittest.TestCase):
    def trace(self, m):
        from sfab.render import trace  # noqa: PLC0415
        import json  # noqa: PLC0415

        return json.loads(trace.render(m, None)["gen/trace.json"])

    def test_ch08_serving_from_a_node(self):
        t = self.trace(lab("ch08")["m"])
        self.assertTrue(t["client"]["local"])
        self.assertEqual([p["eth"] for p in t["client"]["ports"]], ["eth1", "eth2"])
        self.assertEqual(t["client"]["resolve"], "llm.ai.tarnwick.example:443:10.20.11.210")
        self.assertEqual(t["also"][0]["gateway"], "gw-inet")
        self.assertEqual(t["also"][0]["resolve"], "llm.ai.tarnwick.example:443:10.20.11.220")
        self.assertEqual((t["refuse"]["gateway"], t["refuse"]["vip"]), ("gw-inet", "10.20.11.220"))

    def test_ch07_serving_unchanged_keys(self):
        t = self.trace(lab("ch07")["m"])
        self.assertNotIn("also", t)
        self.assertNotIn("kind", t["client"])

    def test_serving_refusals(self):
        def node_unpinned(r):
            r["trace"]["serving"]["pin"] = False
        with self.assertRaisesRegex(RenderError, "or a node of the cluster with pin: true"):
            self.trace(with_chapter("ch08", node_unpinned))

        def also_same(r):
            r["trace"]["serving"]["also"] = [{"gateway": "gw-users", "sport": 42808}]
        with self.assertRaisesRegex(RenderError, "another Gateway of the lab"):
            self.trace(with_chapter("ch08", also_same))

        def also_carried(r):
            r["trace"]["serving"]["also"] = [{"gateway": "gw-internal", "sport": 42808}]
        with self.assertRaisesRegex(RenderError, "gw-internal's route carries staff"):
            self.trace(with_chapter("ch08", also_carried))

    def test_ch09_dns(self):
        t = self.trace(lab("ch09")["m"])
        rows = {r["population"]: r for r in t["rows"]}
        self.assertEqual(rows["enterprise"]["resolver"], "ent-dns")
        self.assertEqual(rows["enterprise"]["authorities"], ["10.20.13.11", "10.20.14.11"])
        self.assertEqual(rows["enterprise"]["syn"]["seen"], ["2-fw-ethernet1-4"])
        self.assertEqual(rows["enterprise"]["syn"]["seen_any"], ["3-fw-ae1-leg1", "3-fw-ae1-leg2"])
        self.assertTrue(rows["nodes"]["syn"]["local"])
        self.assertEqual(rows["nodes"]["syn"]["unseen"], ["0-k8s-cp2-eth1", "0-k8s-cp2-eth2"])
        self.assertEqual(rows["internet"]["syn"]["seen"], ["1-isp-rtr-eth1"])
        self.assertEqual(rows["internet"]["syn"]["rule"], "deny-all-log")
        self.assertEqual(rows["internet"]["dns_point"], "0-inet-dns-res-eth1")

    def test_dns_refusals(self):
        def bad_pop(r):
            r["trace"]["dns"]["populations"] = ["nobody"]
        with self.assertRaisesRegex(RenderError, "'nobody' is not a population"):
            self.trace(with_chapter("ch09", bad_pop))

    def test_ch10_nat(self):
        t = self.trace(lab("ch10")["m"])
        s = {x["id"]: x for x in t["sessions"]}
        self.assertEqual(s["internet"]["translated_addr"], "10.20.11.220")
        self.assertEqual(s["internet"]["expect"]["nat_rule"], "dnat-internet-gateway")
        self.assertEqual(s["internet"]["points"], ["1-isp-rtr-eth1", "3-fw-ae1-leg1", "3-fw-ae1-leg2"])
        self.assertIsNone(s["enterprise"]["translated_addr"])
        self.assertIsNone(s["operator"]["entry"], "the operator's uplink carries ESP: the legs alone")
        self.assertEqual(s["operator"]["expect"]["from_zone"], "operator-vpn")

    def test_nat_refusals(self):
        def node(r):
            r["trace"]["nat"]["populations"] = ["nodes"]
        with self.assertRaisesRegex(RenderError, "must be a client container"):
            self.trace(with_chapter("ch10", node))

        def before(r):
            r["trace"] = {"nat": {"populations": ["internet"]}}
        with self.assertRaisesRegex(RenderError, "does not reach gw-inet"):
            self.trace(with_chapter("ch09", before))

    def test_ch11_ladder(self):
        t = self.trace(lab("ch11")["m"])
        f = {x["id"]: x for x in t["flows"]}
        self.assertEqual(len(f), 15, "five populations by the three Gateways")
        self.assertEqual((f["internet/gw-users"]["mode"], f["internet/gw-users"]["refused_at"], f["internet/gw-users"]["may"]),
                         ("silence", "isp-rtr", []))
        self.assertEqual(f["enterprise/gw-inet"]["may"], ["2-fw-ethernet1-4"])
        self.assertEqual(f["internet/gw-inet"]["post_nat"], "10.20.11.220")
        self.assertTrue(f["nodes/gw-users"]["local"])
        self.assertEqual(f["internet/gw-users"]["tries"], 3)
        ids = [p["id"] for p in t["points"]]
        self.assertIn("5-k8s-ingress1-bond0.110", ids)
        self.assertIn("4-fe-sw2-Ethernet14", ids)
        self.assertEqual(t["pair"], ["fe-sw1", "fe-sw2"])

    def test_ladder_needs_the_matrix(self):
        def ladder(r):
            r["trace"] = {"ladder": {"sport": 44100}}
        with self.assertRaisesRegex(RenderError, "decisions: true"):
            self.trace(with_chapter("ch10", ladder))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class P3DrillsTest(unittest.TestCase):
    def drills(self, m, name):
        from sfab.render import drills  # noqa: PLC0415

        c = lab(name)
        return drills.drills(c["inv"], m.meta.chapter.drills, m, c["ctx"])

    def test_ch08_lease_loss(self):
        d = self.drills(lab("ch08")["m"], "ch08")
        self.assertEqual(d["kind"], "part3")
        x = d["list"][0]
        self.assertEqual(x["kind"], "lease-loss")
        self.assertEqual(sorted(x["candidates"]), ["k8s-ingress1", "k8s-ingress2"])
        self.assertEqual(x["candidates"]["k8s-ingress2"]["shut"]["fe-sw1"], ["configure terminal", "interface Ethernet14", "shutdown", "end"])
        self.assertEqual([e["client"] for e in x["echo"]], ["ent-client", "ops-client"])
        self.assertEqual(x["echo"][1]["resolve"], "llm.ai.tarnwick.example:443:10.20.11.200")
        self.assertEqual((x["prediction"]["min_ms"], x["prediction"]["max_ms"]), (2000, 4000))

    def test_ch11_isolation(self):
        d = self.drills(lab("ch11")["m"], "ch11")
        x = d["list"][0]
        self.assertEqual(x["factors"], [1, 2])
        rows = {r["population"]: r for r in x["rows"]}
        tries = {t["column"]: t["mode"] for t in rows["internet"]["tries"]}
        self.assertEqual(tries, {"gw-internal": "silence", "gw-users": "silence", "gw-inet": "allowed", "staff": "404", "admin": "404"})
        self.assertNotIn("chat", tries, "an allowed model cell needs a key: left out")

    def test_ch11_leaked_key(self):
        d = self.drills(lab("ch11")["m"], "ch11")
        x = next(i for i in d["list"] if i["id"] == "leaked-key")
        self.assertEqual((x["kind"], x["client"], x["gateway"], x["caller"], x["caller_audience"]),
                         ("leaked-key", "inet-client", "gw-inet", "batch", "enterprise"))

        def own(r):
            next(i for i in r["drills"]["list"] if i["id"] == "leaked-key")["leaked_key"]["caller"] = "inetapp"
        with self.assertRaisesRegex(RenderError, "in inet-client's own audience: its key is no leak"):
            self.drills(with_chapter("ch11", own), "ch11")

    def test_mixed_kinds_refused(self):
        m = with_chapter("ch08", lambda r: r["drills"]["list"].append({"id": "x", "key_lifecycle": {"model": "chat"}}))
        with self.assertRaisesRegex(RenderError, "Part III's drills run on their own"):
            self.drills(m, "ch08")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class SynProbeAcrossNatTest(unittest.TestCase):
    def test_break_10a_probe_counts_the_translated_address(self):
        from sfab.render import drills  # noqa: PLC0415

        c = lab("ch10")
        b = drills.breaks(c["inv"], c["dir"], c["m"])
        p = next(a for a in b["breaks"]["10a"]["record"] if a["kind"] == "probe_syn")
        self.assertEqual(p["translated_addr"], "10.20.11.220")
        self.assertIn("(host 198.51.100.10 or host 10.20.11.220)", p["filter"])

    def test_chapter_1_probe_unchanged(self):
        from sfab.render import drills  # noqa: PLC0415

        c = lab("ch01")
        b = drills.breaks(c["inv"], c["dir"], c["m"])
        for bk in b["breaks"].values():
            for a in bk["record"]:
                if a["kind"] == "probe_syn":
                    self.assertNotIn("translated_addr", a)


if __name__ == "__main__":
    unittest.main()
