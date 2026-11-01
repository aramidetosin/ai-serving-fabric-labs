"""Part III's render (chapters 8 to 11, state many): the spec's step-by-step additions and the render
rules they need.

- Chapter 8: a Gateway per audience; one announcement policy per audience (state one keeps one for
  every Gateway); the tuned lease timers behind one switch (tuned: false, or no lease block, keeps
  Cilium's defaults) and their sizing; every caller's audience, the internet caller, and the key
  tool sfab/keys:4 whose mint names the audience (state one keeps sfab/keys:3 and its mint).
- Chapter 9: the internet side (the ISP router with no static route, the public authoritative
  server answering the firewall's own isp address, the provider's resolver), the firewall's isp
  interface, zone and route with no rule and no NAT; the uplink side's server still publishes no
  platform name.
- Chapter 10: the destination NAT from isp to isp on the firewall's own isp address, first of the
  NAT rulebase, and the rule on the pre-NAT address, rule 24 before deny-all-log.
- Chapter 11: the 60-cell matrix with its counts, each forbidden cell's isolation depth, and each
  model cell's own caller per population; chapter 2's matrix renders as before.
- Breaks 8a to 11a and their new actions (k8s_patch, k8s_read, dnsmasq_pin, probe_lookup,
  lookup_answer), with what each refuses, and breakheal.py's lookup reader.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_part3_render -v
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sfab.render import RenderError
from sfab.render import drills as RD

ROOT = Path(__file__).resolve().parents[3]
COMMON = ROOT / "common"

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def lab(name: str) -> dict:
    """The model, inventory and context of a lab of the repository, rendered from its chapter.yaml."""
    if name not in _CACHE:
        from sfab.render import Context  # noqa: PLC0415
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415

        spec = load(ROOT)
        d = ROOT / name
        m = select(spec, load_chapter(d))
        ctx = Context(outdir=Path(tempfile.gettempdir()) / f"sfab-test-{name}", labdir=d, root=ROOT, spec=spec)
        _CACHE[name] = {"m": m, "inv": inventory(m), "ctx": ctx, "dir": d}
    return _CACHE[name]


def docs(text: str) -> list:
    return [d for d in yaml.safe_load_all(text) if d]


def k8s_out(name: str) -> dict:
    from sfab.render import k8s  # noqa: PLC0415

    c = lab(name)
    key = "k8s_out"
    if key not in c:
        c[key] = k8s.render(c["m"], c["ctx"])
    return c[key]


def with_spec(m, edit):
    """A copy of model m whose merged spec tree edit(tree) changed (the renderers read model.spec)."""
    tree = copy.deepcopy(m.spec)
    edit(tree)
    m2 = copy.copy(m)
    object.__setattr__(m2, "spec", tree)
    return m2


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Steps(unittest.TestCase):
    def test_nodes_per_step(self):
        n = {x: set(lab(x)["m"].nodes) for x in ("ch07", "ch08", "ch09", "ch10")}
        self.assertEqual(n["ch08"], n["ch07"])
        self.assertEqual(len(n["ch08"]), 26)
        self.assertEqual(n["ch09"] - n["ch08"], {"isp-rtr", "inet-client", "inet-dns-auth", "inet-dns-res"})
        self.assertEqual(n["ch10"], n["ch09"])
        self.assertEqual(len(lab("ch11")["m"].nodes), 32)
        self.assertNotIn("inet-dns", lab("ch09")["m"].nodes)
        for x, step in (("ch08", 8), ("ch09", 9), ("ch10", 10), ("ch11", 11)):
            self.assertEqual((lab(x)["m"].state, lab(x)["m"].step), ("many", step))

    def test_internet_population(self):
        p = lab("ch09")["m"].populations["internet"]
        self.assertEqual((p.resolver, p.answer_address, p.zones), ("inet-dns-res", "198.51.100.10", ("isp",)))
        self.assertNotIn("internet", lab("ch08")["m"].populations)

@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Chapter8(unittest.TestCase):
    def test_one_policy_per_audience(self):
        pols = docs(k8s_out("ch08")["bootstrap/k8s/31-l2-announcement.yaml"])
        self.assertEqual([d["metadata"]["name"] for d in pols], ["gateways-internal", "gateways-enterprise", "gateways-internet"])
        sel = {d["metadata"]["name"]: d["spec"]["serviceSelector"] for d in pols}
        self.assertEqual(sel["gateways-internet"], {"matchLabels": {"tarnwick.example/audience": "internet"}})
        for d in pols:
            self.assertEqual(d["spec"]["interfaces"], ["^bond0\\.110$"])
            self.assertEqual(d["spec"]["nodeSelector"], {"matchExpressions": [{"key": "node-role.tarnwick.example/ingress", "operator": "Exists"}]})
        # each Gateway's Service carries the audience label the policy selects, beside its pool label
        gws = {d["metadata"]["name"]: d for d in docs(k8s_out("ch08")["bootstrap/k8s/50-gateways.yaml"])}
        self.assertEqual(gws["gw-inet"]["spec"]["infrastructure"]["labels"],
                         {"tarnwick.example/lb-pool": "gw-inet", "tarnwick.example/audience": "internet"})
        kj = json.loads(k8s_out("ch08")["gen/k8s.json"])
        self.assertEqual(kj["l2_policies"]["by_gateway"], {"gw-internal": "gateways-internal", "gw-users": "gateways-enterprise",
                                                         "gw-inet": "gateways-internet"})
        self.assertIsNone(kj["l2_policy"])
        # state one keeps chapter 7's single policy for every Gateway
        one = docs(k8s_out("ch07")["bootstrap/k8s/31-l2-announcement.yaml"])
        self.assertEqual([d["metadata"]["name"] for d in one], ["gateways"])
        self.assertEqual(json.loads(k8s_out("ch07")["gen/k8s.json"])["l2_policy"], "gateways")
        self.assertNotIn("l2_policies", json.loads(k8s_out("ch07")["gen/k8s.json"]))

    def test_tuned_timers_one_switch(self):
        from sfab.render import k8s  # noqa: PLC0415

        m = lab("ch08")["m"]
        v = k8s.cilium_values_doc(m)["l2announcements"]
        self.assertEqual(v, {"enabled": True, "leaseDuration": "3s", "leaseRenewDeadline": "1s", "leaseRetryPeriod": "200ms"})
        s = k8s.lease_summary(m)
        self.assertEqual((s["tuned"], s["services"], s["renew_qps"], s["client_qps"], s["failover_ms"]), (True, 3, 3.0, 50, [2000, 4000]))
        self.assertEqual(json.loads(k8s_out("ch08")["gen/k8s.json"])["l2_lease"]["renew_qps"], 3.0)
        # chapter 7 keeps Cilium's defaults
        self.assertEqual(k8s.cilium_values_doc(lab("ch07")["m"])["l2announcements"], {"enabled": True})
        self.assertNotIn("l2_lease", json.loads(k8s_out("ch07")["gen/k8s.json"]))
        # the one switch: tuned false renders the defaults again
        saved = dict(m.k8s.l2_announce)
        try:
            m.k8s.l2_announce["lease"] = dict(saved["lease"], tuned=False)
            self.assertEqual(k8s.cilium_values_doc(m)["l2announcements"], {"enabled": True})
            self.assertEqual(k8s.lease_summary(m)["failover_ms"], [10000, 20000])
            m.k8s.l2_announce["lease"] = dict(saved["lease"], retry_period="1s")
            with self.assertRaisesRegex(RenderError, "retry_period < renew_deadline < duration"):
                k8s.cilium_values_doc(m)
            m.k8s.l2_announce["lease"] = dict(saved["lease"], duration="3 seconds")
            with self.assertRaisesRegex(RenderError, "is not a duration"):
                k8s.cilium_values_doc(m)
            m.k8s.l2_announce["policies"] = {"mode": "per-gateway"}
            with self.assertRaisesRegex(RenderError, "not one of single, per-audience"):
                k8s.l2_policies(m)
        finally:
            m.k8s.l2_announce.clear()
            m.k8s.l2_announce.update(saved)

    def test_internet_gateway_routes_and_labels(self):
        out = k8s_out("ch08")
        ns = {d["metadata"]["name"]: d["metadata"].get("labels") or {} for d in docs(out["bootstrap/k8s/05-namespaces.yaml"])}
        self.assertEqual(ns["echo"].get("routes.tarnwick.example/gw-inet"), "true")
        kj = json.loads(out["gen/k8s.json"])
        self.assertEqual(kj["gateways"]["gw-inet"]["allowed_routes"]["namespaces"], ["echo", "inference"])
        self.assertEqual(kj["gateways"]["gw-inet"]["vip"], "10.20.11.220")
        inf = docs(out["bootstrap/k8s/62-inference.yaml"])
        rt = next(d for d in inf if d["kind"] == "HTTPRoute" and d["metadata"]["name"] == "models-gw-inet")
        chat = lab("ch08")["m"].models["chat"].route_id
        self.assertEqual([r["matches"][0]["path"]["value"] for r in rt["spec"]["rules"]], [f"/models/{chat}"])
        self.assertEqual(rt["spec"]["hostnames"], ["llm.ai.tarnwick.example"])
        echo = docs(out["bootstrap/k8s/55-test-backend.yaml"])
        self.assertIn("echo-gw-inet", [d["metadata"]["name"] for d in echo if d["kind"] == "HTTPRoute"])
        certs = {d["metadata"]["name"]: d for d in docs(out["bootstrap/k8s/40-pki.yaml"]) if d["kind"] == "Certificate"}
        self.assertEqual(certs["gw-inet"]["spec"]["secretName"], "gw-inet-tls")
        # no identity provider route on the internet Gateway
        idp = docs(out["bootstrap/k8s/57-identity.yaml"])
        self.assertNotIn("gw-inet", [p["name"] for d in idp if d["kind"] == "HTTPRoute" for p in d["spec"]["parentRefs"]])

    def test_callers_and_the_key_tool(self):
        from sfab.render import inference  # noqa: PLC0415

        s = inference.settings(lab("ch08")["m"])
        c = {x["id"]: x for x in s["callers"]}
        self.assertEqual(sorted(c), ["batch", "helpdesk", "inetapp", "staff"])
        self.assertEqual({k: (v["audience"], v["audience_models"]) for k, v in c.items()},
                         {"batch": ("enterprise", ["chat", "staff"]), "helpdesk": ("enterprise", ["chat", "staff"]),
                          "staff": ("enterprise", ["chat", "staff"]), "inetapp": ("internet", ["chat"])})
        self.assertEqual(s["keys_image"], "192.0.2.6:5000/sfab/keys:4")
        cmd = inference.keys_command(s)
        self.assertIn("--model inetapp --if-none --for chat --audience internet --audience-models chat", cmd)
        self.assertIn("--model batch --if-none --for chat --audience enterprise --audience-models chat,staff", cmd)
        # state one: sfab/keys:3, no caller audience, the mint as chapter 7 recorded it
        s7 = inference.settings(lab("ch07")["m"])
        self.assertEqual(s7["keys_image"], "192.0.2.6:5000/sfab/keys:3")
        self.assertNotIn("audience", s7["callers"][0])
        self.assertNotIn("--audience", inference.keys_command(s7))
        # a caller whose models lie outside its audience is refused at render
        m2 = with_spec(lab("ch08")["m"], lambda t: next(x for x in t["inference"]["callers"] if x["id"] == "inetapp").update(models=["chat", "staff"]))
        with self.assertRaisesRegex(RenderError, "staff lies outside audience internet"):
            inference.settings(m2)
        m3 = with_spec(lab("ch08")["m"], lambda t: next(x for x in t["inference"]["callers"] if x["id"] == "batch").pop("audience"))
        with self.assertRaisesRegex(RenderError, "needs every caller's audience"):
            inference.settings(m3)

    def test_keys_image_list(self):
        from sfab.render import k8s  # noqa: PLC0415

        self.assertEqual(k8s.keys_image_key("keys"), "keys")
        self.assertEqual(k8s.keys_image_key([{"id": "keys_audience"}]), "keys_audience")
        with self.assertRaisesRegex(RenderError, "exactly one entry"):
            k8s.keys_image_key([{"id": "keys"}, {"id": "keys_audience"}])
        with self.assertRaisesRegex(RenderError, "exactly one entry"):
            k8s.keys_image_key([])

    def test_keyprobe_job_names_the_audience(self):
        kj = Path(tempfile.mkdtemp(prefix="sfab-test-ch08-kp-")) / "k8s.json"
        kj.write_text(k8s_out("ch08")["gen/k8s.json"])
        kp = COMMON / "trace" / "keyprobe.py"
        r = subprocess.run([sys.executable, str(kp), "job", "--k8s", str(kj), "--name", "refused-mint", "--mint", "--model", "staff",
                            "--id", "fe000001", "--caller", "inetapp"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        cmd = json.loads(r.stdout)["spec"]["template"]["spec"]["containers"][0]["command"]
        self.assertEqual(cmd[-8:], ["--id", "fe000001", "--for", "staff", "--audience", "internet", "--audience-models", "chat"])
        self.assertIn("sfab/keys:4", json.loads(r.stdout)["spec"]["template"]["spec"]["containers"][0]["image"])
        r = subprocess.run([sys.executable, str(kp), "job", "--k8s", str(kj), "--name", "x", "--mint", "--model", "chat", "--id",
                            "fe000002", "--caller", "staff"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0, "a people caller has no keys")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Chapter9(unittest.TestCase):
    def setUp(self):
        from sfab.render import dns, frr  # noqa: PLC0415

        c = lab("ch09")
        self.m = c["m"]
        self.dns = dns.render(c["m"], c["ctx"])
        self.frr = frr.render(c["m"], c["ctx"])

    def test_isp_router_holds_no_static_route(self):
        conf = self.frr["bootstrap/isp-rtr/frr.conf"]
        self.assertNotIn("ip route", conf)
        for a in ("198.51.100.9/30", "203.0.113.1/30", "203.0.113.5/30", "203.0.113.9/30"):
            self.assertIn(f"ip address {a}", conf)

    def test_public_server_and_provider_resolver(self):
        zone = self.dns["bootstrap/inet-dns-auth/zones/db.public-internet.ai.tarnwick.example"]
        a = [x.split() for x in zone.splitlines() if " IN A " in x]
        self.assertEqual([(x[0], x[3]) for x in a], [("inet-dns-auth", "203.0.113.6"), ("llm", "198.51.100.10")])
        for n in ("admin", "grafana", "serve", "id", "*"):
            self.assertNotIn(f"\n{n} ", zone)
        self.assertNotIn("AAAA", zone)
        auth = self.dns["bootstrap/inet-dns-auth/named.conf"]
        self.assertIn("recursion no;", auth)
        self.assertIn("acl public-internet-clients { 203.0.113.0/26; };", auth)
        res = self.dns["bootstrap/inet-dns-res/named.conf"]
        self.assertIn("allow-recursion { 127.0.0.1; isp-clients; };", res)
        self.assertIn("acl isp-clients { 203.0.113.0/26; };", res)
        self.assertIn('zone "ai.tarnwick.example" { type static-stub; server-addresses { 203.0.113.6; }; };', res)
        self.assertIn("a recursive resolver for its customers' segments outside the platform", res)
        self.assertIn("a recursive resolver for the inside segments", self.dns["bootstrap/dns-res1/named.conf"])

    def test_uplink_side_publishes_nothing(self):
        ops = self.dns["bootstrap/ops-dns/zones/db.public-operator.ai.tarnwick.example"]
        self.assertNotIn("\nllm ", ops)
        self.assertEqual(len([v for v in self.m.dns.views if v.name == "public-operator"]), 1)

    def test_firewall_isp_side_without_rule_or_nat(self):
        from sfab.render import panos  # noqa: PLC0415

        v = panos.view(self.m)
        isp = next(i for i in v.interfaces if i.name == "ethernet1/6")
        self.assertEqual((isp.zone, isp.address), ("isp", "198.51.100.10/30"))
        r = next(x for x in v.routes if x.name == "isp-customers")
        self.assertEqual((r.dest, r.nexthop, r.interface), ("203.0.113.0/26", "198.51.100.9", "ethernet1/6"))
        self.assertNotIn("isp-to-internet-gateway", [x.name for x in v.rules])
        self.assertNotIn("dnat-internet-gateway", [x.name for x in v.nat])
        self.assertEqual(next(z for z in v.zones if z.name == "isp").zone_protection, "zp-internet")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Chapter10(unittest.TestCase):
    def test_zone_keyed_nat_and_rule_order(self):
        from sfab.render import panos  # noqa: PLC0415

        v = panos.view(lab("ch10")["m"])
        rules = [r.name for r in v.rules]
        self.assertEqual(len(rules), 25)
        self.assertEqual(rules[23:], ["isp-to-internet-gateway", "deny-all-log"])
        self.assertNotIn("nodes-to-public-ping", rules)
        r = next(x for x in v.rules if x.name == "isp-to-internet-gateway")
        self.assertEqual((r.from_zones, r.to_zones, r.dst_cidrs, r.applications), (("isp",), ("ingress",), ("198.51.100.10/32",), ("ssl",)))
        self.assertEqual([n.name for n in v.nat], ["dnat-internet-gateway", "no-nat-public", "internet-snat"])
        n = v.nat[0]
        self.assertEqual((n.from_zones, n.to_zones, n.dst_cidrs, n.service, n.dnat), (("isp",), ("isp",), ("198.51.100.10/32",), "tcp-443",
                                                                                      "10.20.11.220"))

    def test_internet_path_translated(self):
        from sfab.render import decisions, panos  # noqa: PLC0415

        m = lab("ch10")["m"]
        p = decisions.path(m, panos.view(m), m.nodes["inet-client"], "198.51.100.10", 443, "test")
        self.assertEqual((p["outcome"], p["at"], p["rule"], p["nat_rule"], p["from_zone"], p["to_zone"]),
                         ("reached", "10.20.11.220", "isp-to-internet-gateway", "dnat-internet-gateway", "isp", "ingress"))
        # the staff client sent to the published address is not translated (the NAT rule is keyed on isp)
        p = decisions.path(m, panos.view(m), m.nodes["ent-client"], "198.51.100.10", 443, "test")
        self.assertEqual((p["outcome"], p["rule"], p["from_zone"], p["to_zone"]), ("log-line", "deny-all-log", "enterprise", "isp"))
        # in chapter 9 the same SYN meets deny-all-log from isp to isp
        m9 = lab("ch09")["m"]
        p = decisions.path(m9, panos.view(m9), m9.nodes["inet-client"], "198.51.100.10", 443, "test")
        self.assertEqual((p["outcome"], p["rule"], p["from_zone"], p["to_zone"]), ("log-line", "deny-all-log", "isp", "isp"))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Chapter11(unittest.TestCase):
    def setUp(self):
        from sfab.render import decisions  # noqa: PLC0415

        self.mx = decisions.matrix(lab("ch11")["m"])
        self.cells = {c["id"]: c for c in self.mx["cells"]}

    def test_sixty_cells(self):
        c = self.mx["counts"]
        self.assertEqual((c["cells"], c["allowed"], c["log-line"], c["404"], c["silence"]), (60, 20, 21, 3, 16))
        self.assertEqual([r["id"] for r in self.mx["rows"]], ["enterprise", "operator", "nodes", "web", "internet"])
        self.assertEqual([x["id"] for x in self.mx["columns"]][:3], ["gw-internal", "gw-users", "gw-inet"])

    def test_modes_of_the_new_cells(self):
        want = {"internet/gw-inet": "allowed", "internet/chat": "allowed", "internet/staff": "404", "internet/admin": "404",
                "internet/gw-users": "silence", "internet/egress": "silence", "enterprise/gw-inet": "log-line",
                "operator/gw-inet": "log-line", "nodes/gw-inet": "allowed", "web/gw-inet": "log-line"}
        self.assertEqual({k: self.cells[k]["mode"] for k in want}, want)
        self.assertEqual(self.cells["internet/gw-users"]["expect"]["device"], "isp-rtr")
        self.assertEqual(self.cells["internet/gw-inet"]["address"], "198.51.100.10")

    def test_depth(self):
        def layers(cid):
            return [(x["row"], x["device"]) for x in self.cells[cid]["depth_layers"]]

        self.assertEqual(layers("internet/gw-users"), [("routing", "isp-rtr"), ("policy", "fw")])
        self.assertEqual(layers("web/gw-users"), [("policy", "fw")])
        self.assertEqual(layers("enterprise/gw-inet"), [("policy", "fw")])
        self.assertEqual(layers("internet/staff"), [("routeset", "gw-inet"), ("key", "api-gateway")])
        self.assertEqual(layers("internet/admin"), [("routeset", "gw-inet")])
        self.assertEqual(self.cells["internet/chat"]["depth"], 0)
        self.assertEqual(sum(self.mx["counts"]["depth"].values()), 40)

    def test_own_caller_per_population(self):
        own = self.cells["internet/chat"]["requests"][0]
        self.assertEqual((own["id"], own["key"], own["key_caller"]), ("own", "chat", "inetapp"))
        self.assertNotIn("key_caller", self.cells["enterprise/chat"]["requests"][0])

    def test_chapter2_matrix_as_before(self):
        from sfab.render import decisions  # noqa: PLC0415

        mx = decisions.matrix(lab("ch02")["m"])
        self.assertEqual(mx["counts"]["cells"], 44)
        self.assertNotIn("depth", mx["counts"])
        for c in mx["cells"]:
            self.assertNotIn("depth", c)
            for q in c.get("requests") or []:
                self.assertNotIn("key_caller", q)

    def test_decision_rows_for_state_many(self):
        from sfab.render import decisions  # noqa: PLC0415

        t = decisions.table(lab("ch11")["m"])
        rows = {r["id"]: r["object"] for r in t["rows"]}
        self.assertIn("a public server on the internet side that publishes the users' name from Chapter 9", rows["view"])
        self.assertIn("the internet users' destination NAT", rows["nat"])
        self.assertIn("the ISP router", rows["routing"])
        t2 = decisions.table(lab("ch02")["m"])
        self.assertIn("publishes no platform name in state one", t2["rows"][0]["object"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Refusals(unittest.TestCase):
    """The render's refusals Part III added, each made to fire once."""

    def test_an_answer_on_a_firewall_interface_without_an_address(self):
        import dataclasses  # noqa: PLC0415

        from sfab.spec import SpecError, load, load_chapter, select  # noqa: PLC0415

        spec = load(ROOT)
        bad = json.loads(json.dumps(spec.profiles["a"]))
        v = next(x for x in bad["dns"]["views"] if x["id"] == "public-internet")
        v["answer"] = "fw:ethernet1/9"
        with self.assertRaisesRegex(SpecError, "the firewall has no interface 'ethernet1/9' with an address"):
            select(dataclasses.replace(spec, profiles=dict(spec.profiles, a=bad)), load_chapter(ROOT / "ch09"))

    def test_a_policy_per_audience_needs_one_audience_a_gateway(self):
        import dataclasses  # noqa: PLC0415

        from sfab.render import k8s  # noqa: PLC0415

        m = lab("ch08")["m"]
        gws = dict(m.gateways)
        try:
            object.__setattr__(m, "gateways", dict(gws, **{"gw-inet": dataclasses.replace(gws["gw-inet"], audience="")}))
            with self.assertRaisesRegex(RenderError, "gateway gw-inet: a policy per audience needs the Gateway's audience"):
                k8s.l2_policies(m)
            object.__setattr__(m, "gateways", dict(gws, **{"gw-inet": dataclasses.replace(gws["gw-inet"], audience="enterprise")}))
            with self.assertRaisesRegex(RenderError, "per-audience: two Gateways share an audience"):
                k8s.l2_policies(m)
        finally:
            object.__setattr__(m, "gateways", gws)
        self.assertEqual(k8s.l2_policies(m)["gw-inet"], "gateways-internet")

    def test_lease_block_takes_its_own_keys_only(self):
        from sfab.render import k8s  # noqa: PLC0415

        m = lab("ch08")["m"]
        saved = dict(m.k8s.l2_announce)
        try:
            m.k8s.l2_announce["lease"] = dict(saved["lease"], jitter="1s")
            with self.assertRaisesRegex(RenderError, "spec k8s.l2_announce.lease: tuned and duration, renew_deadline, retry_period only"):
                k8s.lease_timers(m)
        finally:
            m.k8s.l2_announce.clear()
            m.k8s.l2_announce.update(saved)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class Breaks(unittest.TestCase):
    def load(self, name, bid):
        from sfab.spec import read_yaml  # noqa: PLC0415

        c = lab(name)
        raw = read_yaml(c["dir"] / "breaks" / f"{bid}.yaml")
        return c, raw

    def test_8a(self):
        c, raw = self.load("ch08", "8a")
        b = RD._break(c["inv"], "8a", raw, c["m"])
        p, h = b["break"][0], b["heal"][0]
        self.assertEqual((p["kind"], p["resource"], p["name"], p["patch"]),
                         ("k8s_patch", "ciliuml2announcementpolicies.cilium.io", "gateways-internet", {"spec": {"interfaces": ["^bond0\\.111$"]}}))
        self.assertTrue(h["rendered"])
        self.assertEqual(h["patch"], {"spec": {"interfaces": ["^bond0\\.110$"]}})
        rd = b["record"][0]
        self.assertEqual([o["id"] for o in rd["objects"]][:3], ["l2_policy:gw-inet", "lease:gw-inet", "gateway:gw-inet"])
        lease = rd["objects"][1]
        self.assertEqual((lease["namespace"], lease["name"]), ("kube-system", "cilium-l2announce-gateways-cilium-gateway-gw-inet"))
        # the symptom where chapter 8 shows it: ARP for the VIP on VLAN 110, the staff's requests answered
        arp = b["expect_broken"][0]
        self.assertEqual((arp["kind"], arp["vip"], arp["answered"], arp["ingress"], arp["ifaces"]),
                         ("vip_arp", "10.20.11.220", False, ["k8s-ingress1", "k8s-ingress2"],
                          {"k8s-ingress1": "bond0.110", "k8s-ingress2": "bond0.110"}))
        self.assertEqual(arp["lease"], "cilium-l2announce-gateways-cilium-gateway-gw-inet")
        self.assertEqual([(x["kind"], x.get("gateway"), x.get("answered")) for x in b["expect_healed"]],
                         [("vip_arp", "gw-inet", True), ("probe_share", None, None)])
        bad = copy.deepcopy(raw)
        bad["expect_broken"] = [{"vip_arp": {"gateway": "gw-inet"}}]
        with self.assertRaisesRegex(RenderError, "answered: true"):
            RD._break(c["inv"], "8a", bad, c["m"])
        bad = copy.deepcopy(raw)
        bad["heal"] = [{"l2_policy": {"gateway": "gw-users", "interfaces": "rendered"}}]
        with self.assertRaisesRegex(RenderError, "puts no patched object back"):
            RD._break(c["inv"], "8a", bad, c["m"])
        bad = copy.deepcopy(raw)
        bad["break"] = [{"l2_policy": {"gateway": "gw-inet", "interfaces": ["^bond0\\.110$"]}}]
        with self.assertRaisesRegex(RenderError, "would change nothing"):
            RD._break(c["inv"], "8a", bad, c["m"])
        # state one has one policy for every Gateway: no per-audience break
        c7 = lab("ch07")
        with self.assertRaisesRegex(RenderError, "one for every Gateway"):
            RD._break(c7["inv"], "8a", {"break": [{"l2_policy": {"gateway": "gw-users", "interfaces": ["^x$"]}}],
                                        "heal": [{"l2_policy": {"gateway": "gw-users", "interfaces": "rendered"}}]}, c7["m"])

    def test_9a(self):
        c, raw = self.load("ch09", "9a")
        b = RD._break(c["inv"], "9a", raw, c["m"])
        pin = b["break"][0]
        self.assertEqual((pin["kind"], pin["node"], pin["address"]), ("dnsmasq_pin", "ent-dns", "10.20.11.210"))
        self.assertNotIn("server=/ai.tarnwick.example/", pin["content"])
        self.assertIn("address=/llm.ai.tarnwick.example/10.20.11.210\n", pin["content"])
        self.assertIn("address=/id.ai.tarnwick.example/10.20.11.210\n", pin["content"])
        # no local= over the platform's zone while the break is applied (the corporate domain's goes)
        self.assertFalse([x for x in pin["content"].splitlines() if x.startswith("local=")])
        self.assertEqual(pin["local_removed"], ["local=/tarnwick.example/"])
        self.assertEqual(b["expect_broken"][1], {"kind": "lookup_answer", "probe": "staff", "type": "AAAA", "rcode": "NOERROR", "answers": 0,
                                                 "not": True})
        bad = copy.deepcopy(raw)
        bad["expect_broken"] = [{"lookup_answer": {"probe": "staff", "tool": "curl", "ok": True, "not": True}}]
        with self.assertRaisesRegex(RenderError, "tool: getaddrinfo or curl"):
            RD._break(c["inv"], "9a", bad, c["m"])
        lk = b["record"][0]
        self.assertEqual((lk["kind"], lk["name"], lk["tools"]), ("probe_lookup", "llm.ai.tarnwick.example", ["dig-a", "dig-aaaa", "getaddrinfo", "curl"]))
        self.assertEqual(b["heal"][0], {"kind": "restore", "node": "ent-dns", "what": "dns"})
        bad = copy.deepcopy(raw)
        bad["heal"] = [{"restore": "dns-auth1"}]
        with self.assertRaisesRegex(RenderError, "restore names no DNS server the break moved"):
            RD._break(c["inv"], "9a", bad, c["m"])
        bad = copy.deepcopy(raw)
        bad["expect_broken"] = [{"lookup_answer": {"probe": "nope", "type": "A", "rcode": "NOERROR"}}]
        with self.assertRaisesRegex(RenderError, "no probe_lookup"):
            RD._break(c["inv"], "9a", bad, c["m"])
        bad = copy.deepcopy(raw)
        bad["break"] = [{"dnsmasq_pin": {"node": "ent-dns", "names": ["admin"]}}]
        with self.assertRaisesRegex(RenderError, "is no name view enterprise answers"):
            RD._break(c["inv"], "9a", bad, c["m"])

    def test_10a(self):
        c, raw = self.load("ch10", "10a")
        b = RD._break(c["inv"], "10a", raw, c["m"])
        self.assertEqual(b["break"][0]["kind"], "panos_api")
        syn = next(a for a in b["record"] if a["kind"] == "probe_syn")
        self.assertEqual((syn["node"], syn["dst_addr"], [x["id"] for x in syn["capture"]]),
                         ("inet-client", "198.51.100.10", ["isp-rtr-eth1", "fw-ethernet1-1", "fw-ethernet1-2"]))

    def test_11a(self):
        c, raw = self.load("ch11", "11a")
        b = RD._break(c["inv"], "11a", raw, c["m"])
        p = b["break"][0]
        m = c["m"]
        paths = [r["matches"][0]["path"]["value"] for r in p["patch"]["spec"]["rules"]]
        self.assertEqual(paths, [f"/models/{m.models['chat'].route_id}", f"/models/{m.models['staff'].route_id}"])
        self.assertEqual((p["resource"], p["namespace"], p["name"]), ("httproutes.gateway.networking.k8s.io", "inference", "models-gw-inet"))
        self.assertEqual(len(b["heal"][0]["patch"]["spec"]["rules"]), 1)
        self.assertEqual(b["expect_broken"][0], {"kind": "cell_mode", "probe": "cells", "cell": "internet/staff", "mode": "404", "not": True})
        rs = b["expect_broken"][1]
        self.assertEqual((rs["kind"], rs["route"], rs["paths"], rs["rendered"]),
                         ("route_set", "models-gw-inet", [f"/models/{m.models['chat'].route_id}"], False))
        self.assertTrue(b["expect_healed"][-1]["rendered"])
        bad = copy.deepcopy(raw)
        bad["expect_broken"] = [{"cell_mode": {"probe": "cells", "cell": "internet/staff", "mode": "log-line", "rule": "deny-all-log", "not": True}}]
        with self.assertRaisesRegex(RenderError, "no rule to name"):
            RD._break(c["inv"], "11a", bad, c["m"])
        bad["expect_broken"] = [{"route_set": {"route": "models-gw-nowhere", "rendered": True}}]
        with self.assertRaisesRegex(RenderError, "is not one of"):
            RD._break(c["inv"], "11a", bad, c["m"])
        bad = copy.deepcopy(raw)
        bad["break"] = [{"route_rules": {"route": "models-gw-inet", "add": ["chat"]}}]
        with self.assertRaisesRegex(RenderError, "does not carry"):
            RD._break(c["inv"], "11a", bad, c["m"])
        bad["break"] = [{"route_rules": {"route": "models-gw-internal", "add": ["staff"]}}]
        with self.assertRaisesRegex(RenderError, "bare prefix"):
            RD._break(c["inv"], "11a", bad, c["m"])


class LookupReader(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(COMMON))
        import breakheal  # noqa: PLC0415

        self.bh = breakheal
        self.d = Path(tempfile.mkdtemp(prefix="sfab-test-lookup-"))
        (self.d / "dig-a.txt").write_text(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n"
                                          ";; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1\n"
                                          "exit 0 start 100.00 end 100.02\n")
        (self.d / "dig-aaaa.txt").write_text(";; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 2\n"
                                             ";; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1\n"
                                             "exit 0 start 100.00 end 100.01\n")
        (self.d / "getaddrinfo.txt").write_text("gaierror -3 [Errno -3] Try again\nexit 2 start 100.00 end 140.50\n")
        (self.d / "curl.txt").write_text("http 200 remote 10.20.11.210\nexit 0 start 100.00 end 100.40\n")

    def test_read(self):
        r = self.bh.read_lookup(self.d)
        self.assertEqual((r["dig-a"]["rcode"], r["dig-a"]["answers"]), ("NOERROR", 1))
        self.assertEqual((r["dig-aaaa"]["rcode"], r["dig-aaaa"]["answers"]), ("REFUSED", 0))
        self.assertEqual((r["getaddrinfo"]["ok"], r["getaddrinfo"]["seconds"]), (False, 40.5))
        self.assertEqual((r["curl"]["ok"], r["curl"]["http"]), (True, "200"))

    def test_checks(self):
        def run(check):
            with contextlib.redirect_stdout(io.StringIO()):
                return self.bh.main(["lookup", "--dir", str(self.d), "--check", json.dumps(check)])

        self.assertEqual(run({"probe": "x", "type": "A", "rcode": "NOERROR", "answers": 1}), 0)
        self.assertEqual(run({"probe": "x", "type": "AAAA", "rcode": "NOERROR", "answers": 0}), 1)
        self.assertEqual(run({"probe": "x", "type": "AAAA", "rcode": "REFUSED"}), 0)
        self.assertEqual(run({"probe": "x", "tool": "getaddrinfo", "ok": False}), 0)
        self.assertEqual(run({"probe": "x", "tool": "curl", "ok": False}), 1)
        # not: any answer but the healthy NODATA
        self.assertEqual(run({"probe": "x", "type": "AAAA", "rcode": "NOERROR", "answers": 0, "not": True}), 0)
        self.assertEqual(run({"probe": "x", "type": "AAAA", "rcode": "REFUSED", "answers": 0, "not": True}), 1)
        (self.d / "dig-a.txt").write_text(";; connection timed out; no servers could be reached\nexit 9 start 1.0 end 6.0\n")
        self.assertEqual(run({"probe": "x", "type": "A", "rcode": "timeout"}), 0)

    def test_route_set(self):
        f = self.d / "route.json"
        f.write_text(json.dumps({"spec": {"rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/models/a"}}]},
                                                    {"matches": [{"path": {"type": "PathPrefix", "value": "/models/b"}}]}]}}))

        def run(check):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                rc = self.bh.main(["routeset", "--file", str(f), "--check", json.dumps(check)])
            return rc, out.getvalue()

        base = {"route": "r", "models": ["chat"], "paths": ["/models/a"]}
        rc, out = run(dict(base, rendered=False))
        self.assertEqual(rc, 0)
        self.assertIn("beyond its audience's row: /models/b", out)
        self.assertEqual(run(dict(base, rendered=True))[0], 1)
        self.assertEqual(run(dict(base, paths=["/models/a", "/models/b"], rendered=True))[0], 0)
        f.write_text("not json")
        self.assertEqual(run(dict(base, rendered=False))[0], 1)


if __name__ == "__main__":
    unittest.main()
