"""DNS, time and CA tests: render/dns.py (the authoritative pair's views and zones and their transfers,
the recursive resolvers, the corporate resolver's dnsmasq, chrony on the resolvers and the time
reference), render/ca.py (the CA configuration, the node leaves and the proof plan), and the scripts
that consume them: common/ca/sfab-ca (against the local openssl), images/resolver's sfab-dns
(against stand-ins for BIND), its init and sfab-ntp (dry runs), and images/bastion's bastion-init.sh
(dry runs of the jump host).

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_dns_ca -v

Nothing here reaches a device or the network. Every script run has docker, ssh and sshpass
shadowed by stand-ins (standins.check proves it first), BIND's programs are stand-ins too, and
sfab-ca runs on a temporary directory with the local OpenSSL 3. Tests that need bash 4, OpenSSL 3,
jq or dnsmasq are skipped without them.
"""

from __future__ import annotations

import dataclasses
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from sfab.tests import standins

ROOT = Path(__file__).resolve().parents[3]
BASTION_DIR = ROOT / "images" / "bastion"
RESOLVER_DIR = ROOT / "images" / "resolver"
BASTION_INIT = BASTION_DIR / "bastion-init.sh"
SFAB_CA = ROOT / "common" / "ca" / "sfab-ca"
SFAB_DNS = RESOLVER_DIR / "sfab-dns"
SFAB_NTP = RESOLVER_DIR / "sfab-ntp"
RESOLVER_INIT = RESOLVER_DIR / "resolver-init.sh"
RESOLVER_RUN = RESOLVER_DIR / "resolver-run.sh"
CLIENT_INIT = ROOT / "images" / "client" / "init.sh"
DASHES = (chr(0x2014), chr(0x2013))  # the em and en dash
ZONE = "ai.tarnwick.example"

M2 = {"lab": "sfab-m2", "profile": "a", "state": "one",
      "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2", "k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion",
                          "inet-registry", "uplink-rtr", "ops-client", "ent-client", "truenas1"]},
      "features": {"k8s": True, "serving": False, "storage_setup": True}}
ONE = {"lab": "sfab-ch07", "profile": "a", "state": "one"}
MANY = {"lab": "sfab-ch09", "profile": "a", "state": "many"}
M1 = {"lab": "sfab-m1", "profile": "a", "state": "one",
      "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2"]},
      "features": {"k8s": False, "serving": False, "storage_setup": False}}

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def _bash() -> str | None:
    b = shutil.which("bash")
    if not b:
        return None
    try:
        v = subprocess.run([b, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return b if v.strip().isdigit() and int(v) >= 4 else None


def _openssl3() -> bool:
    o = shutil.which("openssl")
    if not o:
        return False
    try:
        v = subprocess.run([o, "version"], capture_output=True, text=True, timeout=10).stdout
    except OSError:
        return False
    return v.startswith("OpenSSL 3")


BASH = _bash()
HAVE_CA_TOOLS = bool(BASH and _openssl3() and shutil.which("jq") and shutil.which("sha256sum"))
DNSMASQ = shutil.which("dnsmasq")

_SPEC = None
_MODELS: dict = {}


def spec():
    global _SPEC
    if _SPEC is None:
        from sfab.spec import load

        _SPEC = load(ROOT)
    return _SPEC


def model(name: str):
    if name not in _MODELS:
        from sfab.spec import select

        _MODELS[name] = select(spec(), {"m2": M2, "one": ONE, "many": MANY, "m1": M1}[name])
    return _MODELS[name]


def ctx():
    from sfab.render import Context

    return Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-dns-ca", labdir=ROOT / "dev" / "m2", root=ROOT, spec=spec())


def render_dns(m):
    from sfab.render import dns

    c = ctx()
    return dns.render(m, c), c.warnings


def render_ca(m):
    from sfab.render import ca

    c = ctx()
    return ca.render(m, c), c.warnings


def write_tree(base: Path, files: dict, strip: str = "") -> None:
    for p, text in files.items():
        if strip and not p.startswith(strip):
            continue
        f = base / p[len(strip):]
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")


def with_node_names_permitted(m):
    """The model with the control nodes' names in the kubernetes intermediate's constraints (the
    spec writes them; a test that removes them shows the render's warning)."""
    inters = []
    for i in m.ca.intermediates:
        if i.name == "kubernetes":
            extra = tuple(n for n in m.k8s.control if n not in i.dns)
            i = dataclasses.replace(i, dns=tuple(i.dns) + extra)
        inters.append(i)
    return dataclasses.replace(m, ca=dataclasses.replace(m.ca, intermediates=tuple(inters)))


def without_node_names(m):
    inters = tuple(dataclasses.replace(i, dns=tuple(d for d in i.dns if d not in m.k8s.control)) if i.name == "kubernetes" else i
                   for i in m.ca.intermediates)
    return dataclasses.replace(m, ca=dataclasses.replace(m.ca, intermediates=inters))


# --------------------------------------------------------------------------------------------
# a small zone-file reader


def parse_zone(text: str) -> dict:
    """{origin, ttl, soa: [mname, rname, serial, refresh, retry, expire, negative], records:
    [(owner, type, value)]} with every name absolute and lower case, no trailing dot."""
    origin = ""
    ttl = None
    soa = None
    records = []
    lines = iter(text.splitlines())

    def absname(n: str) -> str:
        if n == "@":
            return origin
        if n.endswith("."):
            return n[:-1].lower()
        return f"{n}.{origin}".lower() if origin else n.lower()

    for raw in lines:
        line = raw.split(";", 1)[0].rstrip()
        if not line.strip():
            continue
        if line.startswith("$ORIGIN"):
            origin = line.split()[1].rstrip(".").lower()
            continue
        if line.startswith("$TTL"):
            ttl = int(line.split()[1])
            continue
        parts = line.split()
        if "SOA" in parts and "(" in line:
            body = line.split("(", 1)[1]
            while ")" not in body:
                body += " " + next(lines).split(";", 1)[0]
            nums = body.split(")", 1)[0].split()
            mname, rname = parts[3], parts[4]
            soa = [absname(mname), absname(rname)] + [int(x) for x in nums]
            continue
        owner, cls, rtype, value = parts[0], parts[1], parts[2], parts[3]
        assert cls == "IN", raw
        if rtype in ("NS", "PTR"):
            value = absname(value)
        records.append((absname(owner), rtype, value))
    return {"origin": origin, "ttl": ttl, "soa": soa, "records": records}


def views_of(conf: str) -> list:
    """[(view name, match-clients text, body)] in file order."""
    return [(m.group(1), m.group(2).strip().rstrip(";"), m.group(3)) for m in
            re.finditer(r'view "([^"]+)" \{\n    match-clients \{ ([^}]*) \};\n(.*?)\n\};', conf, re.S)]


def statements(conf: str) -> str:
    """The configuration without its // comment lines."""
    return "\n".join(x for x in conf.splitlines() if not x.lstrip().startswith("//"))


def zones_in(body: str) -> list:
    """(zone, file) of every primary zone statement."""
    return re.findall(r'zone "([^"]+)" \{ type primary; file "([^"]+)";', body)


def secondaries_in(body: str) -> list:
    return re.findall(r'zone "([^"]+)" \{ type secondary; primaries \{ ([^}]*) \}; file "([^"]+)";', body)


# --------------------------------------------------------------------------------------------


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestDnsRender(unittest.TestCase):
    """The platform's names in sfab-m2: the authoritative pair, its views and transfers."""

    @classmethod
    def setUpClass(cls):
        cls.m = model("m2")
        cls.out, cls.warnings = render_dns(cls.m)
        cls.conf = cls.out["bootstrap/dns-auth1/named.conf"]
        cls.conf2 = cls.out["bootstrap/dns-auth2/named.conf"]

    def zone(self, view: str, name: str) -> dict:
        return parse_zone(self.out[f"bootstrap/dns-auth1/zones/db.{view}.{name or 'root'}"])

    def test_m2_files(self):
        rev = ("1.20.10.in-addr.arpa", "2.20.10.in-addr.arpa", "3.20.10.in-addr.arpa", "11.20.10.in-addr.arpa", "12.20.10.in-addr.arpa",
               "13.20.10.in-addr.arpa", "14.20.10.in-addr.arpa")
        want = {"bootstrap/dns-auth1/named.conf", "bootstrap/dns-auth2/named.conf", "bootstrap/ent-dns/dnsmasq.conf",
                "bootstrap/inet-ntp/chrony.conf"}
        want |= {f"bootstrap/dns-auth1/zones/db.internal.{z}" for z in (ZONE,) + rev}
        want |= {f"bootstrap/dns-auth1/zones/db.enterprise.{ZONE}"}
        for r in ("dns-res1", "dns-res2"):
            want |= {f"bootstrap/{r}/named.conf", f"bootstrap/{r}/zones/db.{r}.root", f"bootstrap/{r}/chrony.conf"}
        self.assertEqual(set(self.out), want)
        self.assertFalse([p for p in self.out if p.startswith("bootstrap/bastion/")], "the bastion serves no DNS and no time")
        self.assertFalse([p for p in self.out if p.startswith("bootstrap/dns-auth2/zones/")], "the secondary takes its zones by transfer")
        self.assertEqual(self.warnings, [], "ops-dns is not in M2, and nothing else should warn")

    def test_views_in_spec_order_matched_by_resolver_and_key(self):
        v = views_of(self.conf)
        self.assertEqual([x[0] for x in v], ["internal", "enterprise"], "the first matching view wins, so order is the spec's")
        self.assertIn("acl internal-clients { 10.20.13.21/32; 10.20.14.21/32; };", self.conf, "the two resolvers")
        self.assertIn("acl enterprise-clients { 10.24.10.53/32; };", self.conf, "the corporate resolver")
        self.assertEqual(v[0][1], 'key "internal-xfr"; !key "enterprise-xfr"; 127.0.0.1; internal-clients')
        self.assertEqual(v[1][1], 'key "enterprise-xfr"; !key "internal-xfr"; enterprise-clients')
        self.assertEqual(views_of(self.conf2)[0][1], v[0][1], "the secondary matches its views the same way")
        from sfab.render import dns

        self.assertEqual(dns.tsig_keys(self.m), ["internal-xfr", "enterprise-xfr"])
        for conf in (self.conf, self.conf2):
            self.assertIn(f'include "{dns.KEY_DIR}/internal-xfr.key";', conf)
            self.assertIn(f'include "{dns.KEY_DIR}/enterprise-xfr.key";', conf)
            self.assertNotIn("secret", statements(conf), "no TSIG secret is ever rendered")

    def test_listens_on_its_own_address_and_localhost_only(self):
        self.assertIn("listen-on port 53 { 127.0.0.1; 10.20.13.11; };", self.conf)
        self.assertIn("listen-on port 53 { 127.0.0.1; 10.20.14.11; };", self.conf2)
        for conf in (self.conf, self.conf2):
            self.assertIn("listen-on-v6 { none; };", conf)
            self.assertNotIn("172.21.40.", conf, "named never listens on, or answers, the management network")
            self.assertNotIn("localhost", statements(conf), "BIND's localhost ACL would match the management address too")

    def test_authoritative_only(self):
        for conf in (self.conf, self.conf2):
            for word in ("forward", "type hint", "root.hints", "recursion yes", "static-stub"):
                self.assertNotIn(word, statements(conf))
            for _n, _m, body in views_of(conf):
                self.assertIn("recursion no;", body)
                self.assertNotIn('zone "."', body)
            self.assertIn("allow-recursion { none; };", conf.split("logging {")[0])

    def test_primary_notifies_and_transfers_by_key_to_its_secondary(self):
        for name, _m, body in views_of(self.conf):
            self.assertIn(f'server 10.20.14.11 {{ keys "{name}-xfr"; }};', body)
            for z, _f in zones_in(body):
                line = next(x for x in body.splitlines() if f'zone "{z}"' in x)
                self.assertIn("notify explicit; also-notify { 10.20.14.11; };", line)
                self.assertIn(f'allow-transfer {{ key "{name}-xfr"; }};', line)
        sec = dict((x[0], x[2]) for x in views_of(self.conf2))
        for name, _m, body in views_of(self.conf):
            want = [z for z, _f in zones_in(body)]
            got = secondaries_in(sec[name])
            self.assertEqual([z for z, _p, _f in got], want, name)
            for z, prim, f in got:
                self.assertEqual(prim.strip().rstrip(";"), "10.20.13.11")
                self.assertTrue(f.startswith("secondary/"), f)
            self.assertIn(f'server 10.20.13.11 {{ keys "{name}-xfr"; }};', sec[name])
        self.assertIn("allow-transfer { none; };", self.conf.split("logging {")[0], "nothing transfers without its view's key")

    def test_internal_view_holds_every_platform_node_the_api_vip_and_the_internal_answer(self):
        z = self.zone("internal", ZONE)
        a = {o: v for o, t, v in z["records"] if t == "A"}
        for n, h in self.m.hosts.items():
            seg = self.m.segment_of(h.primary) if h.primary else None
            if seg is not None and seg.scope == "internal" and n not in ("ent-client", "ent-dns"):
                self.assertEqual(a.get(f"{n}.{ZONE}"), h.primary, n)
        self.assertEqual(a[f"truenas1.{ZONE}"], "10.20.12.31", "the storage data address, on its own VLAN")
        self.assertEqual(a[f"truenas1-mgmt.{ZONE}"], "10.20.2.31")
        self.assertEqual(a[f"k8s.{ZONE}"], "10.20.1.10", "the API VIP")
        for n in ("llm", "admin", "grafana", "serve"):
            self.assertEqual(a[f"{n}.{ZONE}"], "10.20.11.200", f"{n}: the internal Gateway's VIP in the ingress VLAN, an explicit record")
        self.assertNotIn(f"*.{ZONE}", a, "no wildcard")
        self.assertNotIn(f"registry.{ZONE}", a, "the registry is the internet's, not the platform's")
        self.assertNotIn(f"ent-client.{ZONE}", a, "the enterprise's hosts are under its own domain")
        self.assertFalse([o for o, t, v in z["records"] if not o.endswith(ZONE)], "nothing outside the platform's zone")

    def test_enterprise_view_holds_the_users_name_only(self):
        z = self.zone("enterprise", ZONE)
        a = {o: v for o, t, v in z["records"] if t == "A"}
        self.assertEqual(a, {f"dns-auth1.{ZONE}": "10.20.13.11", f"dns-auth2.{ZONE}": "10.20.14.11", f"llm.{ZONE}": "10.20.11.210"},
                         "the users' VIP for the users' name, the name servers' own addresses, nothing else")
        self.assertEqual([zn for zn, _f in zones_in(dict((x[0], x[2]) for x in views_of(self.conf))["enterprise"])], [ZONE],
                         "no reverse zone: no infrastructure address resolves backwards from the enterprise")

    def test_one_reverse_zone_per_lab_24_and_every_ptr_has_its_a(self):
        fwd = self.zone("internal", ZONE)
        a = {(v, o) for o, t, v in fwd["records"] if t == "A"}
        internal = {ad for ad, _ in a if self.m.segment_of(ad) and self.m.segment_of(ad).scope == "internal"}
        nets = {str(ipaddress.ip_network(f"{x}/24", strict=False)) for x in internal}
        want = {".".join(reversed(n.split("/")[0].split(".")[:3])) + ".in-addr.arpa" for n in nets}
        have = {zname for zname, _ in zones_in(dict((x[0], x[2]) for x in views_of(self.conf))["internal"]) if zname.endswith(".in-addr.arpa")}
        self.assertEqual(have, want)
        for rz in want:
            for o, t, v in self.zone("internal", rz)["records"]:
                if t == "PTR":
                    address = ".".join(reversed(o.split(".")[:4]))
                    self.assertIn((address, v), a, f"PTR {o} names {v}, whose A is not {address}")

    def test_both_servers_are_named_in_every_zone(self):
        for view in ("internal", "enterprise"):
            body = dict((x[0], x[2]) for x in views_of(self.conf))[view]
            for zname, f in zones_in(body):
                z = parse_zone(self.out["bootstrap/dns-auth1/zones/" + f.rsplit("/", 1)[1]])
                self.assertEqual(z["soa"][0], f"dns-auth1.{ZONE}", "the primary is the SOA's MNAME")
                self.assertEqual(z["ttl"], 300)
                ns = [v for o, t, v in z["records"] if t == "NS"]
                self.assertEqual(ns, [f"dns-auth1.{ZONE}", f"dns-auth2.{ZONE}"], f"{view} {zname}")

    def test_zone_paths_are_the_live_copy(self):
        from sfab.render import dns

        for _view, _match, body in views_of(self.conf):
            for _z, f in zones_in(body):
                self.assertTrue(f.startswith(dns.ZONE_DIR + "/db."), f)
        for conf in (self.conf, self.conf2):
            self.assertIn(f'include "{dns.RNDC_KEY}";', conf)
            self.assertIn("controls { inet 127.0.0.1 port 953 allow { 127.0.0.1; }", conf)

    def test_serial_comes_from_the_data_not_the_comments(self):
        from sfab.render import dns

        zm = dns.zone_model(self.m, self.m.dns.views[1])[0]
        hm = f"hostmaster.{ZONE}."
        s = dns.serial(zm, hm)
        self.assertEqual(s, self.zone("enterprise", ZONE)["soa"][2])
        renamed = dataclasses.replace(zm, view="another")
        self.assertEqual(dns.serial(renamed, hm), s, "the view's name is not data")
        changed = dataclasses.replace(zm, records=zm.records[:-1])
        self.assertNotEqual(dns.serial(changed, hm), s)
        self.assertTrue(1 <= s < 2 ** 31)

    def test_resolvers_recurse_for_the_inside_and_stub_the_platform_zones(self):
        from sfab.render import dns

        internal = [z for z, _f in zones_in(dict((x[0], x[2]) for x in views_of(self.conf))["internal"])]
        for r, addr in (("dns-res1", "10.20.13.21"), ("dns-res2", "10.20.14.21")):
            c = self.out[f"bootstrap/{r}/named.conf"]
            st = statements(c)
            self.assertIn(f"listen-on port 53 {{ 127.0.0.1; {addr}; }};", st)
            self.assertIn("recursion yes;", st)
            self.assertIn("allow-recursion { 127.0.0.1; inside-clients; };", st)
            self.assertIn("allow-query { 127.0.0.1; inside-clients; };", st)
            self.assertIn("acl inside-clients { 10.20.1.0/24; 10.20.11.0/24; 10.20.2.0/24; 10.20.3.0/24; 10.20.9.0/24; 10.20.13.0/24; 10.20.14.0/24; };", st)
            stubs = re.findall(r'zone "([^"]+)" \{ type static-stub; server-addresses \{ 10\.20\.13\.11; 10\.20\.14\.11; \}; \};', st)
            self.assertEqual(stubs, internal, "the internal view's zones, sent to both authoritative servers")
            self.assertIn(f'zone "." {{ type primary; file "{dns.ZONE_DIR}/db.{r}.root"; }};', st, "its own empty root")
            for word in ("forwarders", "forward only", "type hint"):
                self.assertNotIn(word, st)
            root = parse_zone(self.out[f"bootstrap/{r}/zones/db.{r}.root"])
            self.assertEqual(root["records"], [("", "NS", f"{r}.{ZONE}"), (f"{r}.{ZONE}", "A", addr)])
            self.assertEqual(root["soa"][0], f"{r}.{ZONE}")

    def test_the_corporate_resolver_forwards_the_platform_zone_only(self):
        lines = self.out["bootstrap/ent-dns/dnsmasq.conf"].splitlines()
        for want in ("no-resolv", "no-hosts", "bind-interfaces", "listen-address=127.0.0.1,10.24.10.53",
                     "local=/tarnwick.example/", f"server=/{ZONE}/10.20.13.11", f"server=/{ZONE}/10.20.14.11",
                     "host-record=ent-client.tarnwick.example,10.24.10.10", "host-record=ent-dns.tarnwick.example,10.24.10.53"):
            self.assertIn(want, lines)
        self.assertEqual([x for x in lines if x.startswith("server=")], [f"server=/{ZONE}/10.20.13.11", f"server=/{ZONE}/10.20.14.11"],
                         "no upstream but the platform's two servers, for its zone only")
        self.assertFalse([x for x in lines if x.startswith("address=")], "no wildcard")
        if DNSMASQ:
            with tempfile.TemporaryDirectory() as t:
                f = Path(t) / "dnsmasq.conf"
                f.write_text("\n".join(lines) + "\n", encoding="utf-8")
                r = subprocess.run([DNSMASQ, "--test", "-C", str(f)], capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 0, r.stderr)

    def test_chrony_on_the_resolvers_follows_the_reference_over_nts(self):
        for r, addr in (("dns-res1", "10.20.13.21"), ("dns-res2", "10.20.14.21")):
            body = [x for x in self.out[f"bootstrap/{r}/chrony.conf"].splitlines() if x and not x.startswith("#")]
            self.assertEqual(body, ["server 192.0.2.14 iburst nts", "ntstrustedcerts /shared/ca/root.crt", "ntsdumpdir /var/lib/chrony",
                                    "local stratum 10", f"bindaddress {addr}", "allow 10.20.1.0/24", "allow 10.20.11.0/24", "allow 10.20.2.0/24",
                                    "allow 10.20.3.0/24", "allow 10.20.9.0/24", "allow 10.20.13.0/24", "allow 10.20.14.0/24",
                                    "cmdport 0"])
        ref = [x for x in self.out["bootstrap/inet-ntp/chrony.conf"].splitlines() if x and not x.startswith("#")]
        self.assertEqual(ref, ["local stratum 2", "bindaddress 192.0.2.14", "allow all", "ntsserverkey /run/sfab/tls/tls.key",
                               "ntsservercert /run/sfab/tls/chain.crt", "cmdport 0"])
        for p in ("bootstrap/dns-res1/chrony.conf", "bootstrap/inet-ntp/chrony.conf"):
            for word in ("makestep", "rtcsync", "refclock", "pool "):
                self.assertNotIn(word, self.out[p], "no chronyd steps or disciplines the host clock")

    def test_nts_off_is_plain_ntp(self):
        m = dataclasses.replace(self.m, spec=dict(self.m.spec, ntp=dict(self.m.spec["ntp"], nts=False)))
        out, _ = render_dns(m)
        self.assertIn("server 192.0.2.14 iburst\n", out["bootstrap/dns-res1/chrony.conf"])
        self.assertNotIn("nts", out["bootstrap/inet-ntp/chrony.conf"].split("\n", 4)[-1])

    def test_render_is_byte_stable(self):
        again, _ = render_dns(model("m2"))
        self.assertEqual(again, self.out)

    def test_headers_and_prose(self):
        for p, text in self.out.items():
            node = p.split("/")[1]
            first = text.splitlines()[0]
            self.assertIn(f"sfab-m2 {node}", first, p)
            self.assertIn("edit the spec and run make render", first, p)
            for d in DASHES:
                self.assertNotIn(d, text, p)
            self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"), p)

    def test_no_dns_without_its_servers(self):
        out, warnings = render_dns(model("m1"))
        self.assertEqual(out, {}, "sfab-m1 has no DNS or time server")
        self.assertEqual(warnings, [])

    def test_client_views(self):
        from sfab.render import dns

        m = self.m
        self.assertEqual([(r, v.name if v else None) for r, v in [dns.client_view(m, m.nodes[n]) for n in ("k8s-cp1", "bastion", "ent-client")]],
                         [("dns-res1", "internal"), ("dns-res1", "internal"), ("ent-dns", "enterprise")])
        self.assertEqual(dns.view_for(m, "10.20.14.21").name, "internal")
        self.assertIsNone(dns.view_for(m, "10.20.1.11"), "the platform's servers answer resolvers, never a node directly")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestPublicServers(unittest.TestCase):
    """The public servers: the operator's (state one) and, from step 9, the internet's."""

    def test_operator_public_server(self):
        out, _ = render_dns(model("one"))
        conf = out["bootstrap/ops-dns/named.conf"]
        self.assertIn("listen-on port 53 { 127.0.0.1; 192.0.2.10; };", conf)
        v = views_of(conf)
        self.assertEqual([x[0] for x in v], ["public-operator"])
        self.assertEqual(v[0][1], "127.0.0.1; public-operator-clients", "one server, no transfer, no key")
        self.assertIn("recursion no;", v[0][2])
        z = parse_zone(out[f"bootstrap/ops-dns/zones/db.public-operator.{ZONE}"])
        a = {o: val for o, t, val in z["records"] if t == "A"}
        self.assertEqual(a, {f"ops-dns.{ZONE}": "192.0.2.10"},
                         "outside, no platform name in state one (the operator comes in through the tunnel): no admin name, no wildcard")
        self.assertEqual(sorted(p for p in out if p.startswith("bootstrap/ops-dns/")),
                         ["bootstrap/ops-dns/named.conf", f"bootstrap/ops-dns/zones/db.public-operator.{ZONE}"],
                         "no reverse zone: every address in it is outside")

    def test_the_two_public_servers_answer_the_same(self):
        out, _ = render_dns(model("many"))
        a = parse_zone(out[f"bootstrap/ops-dns/zones/db.public-operator.{ZONE}"])
        b = parse_zone(out[f"bootstrap/inet-dns/zones/db.public-internet.{ZONE}"])
        self.assertEqual(a, b, "the same records, SOA and serial on both")
        ns = [v for o, t, v in a["records"] if t == "NS"]
        self.assertEqual(ns, [f"ops-dns.{ZONE}", f"inet-dns.{ZONE}"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestCaRender(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.m = model("m2")
        cls.out, cls.warnings = render_ca(cls.m)
        cls.proof = json.loads(cls.out["bootstrap/ca/proof.json"])

    def cnf(self, name: str) -> dict:
        sec, out = None, {}
        for line in self.out[f"bootstrap/ca/{name}.cnf"].splitlines():
            if line.startswith("#") or not line.strip():
                continue
            if line.startswith("["):
                sec = line.strip("[]")
                continue
            k, _, v = line.partition("=")
            out[(sec, k.strip())] = v.strip()
        return out

    def test_files(self):
        self.assertEqual(sorted(self.out), [f"bootstrap/ca/{n}" for n in
                                            ("internet.cnf", "kubernetes.cnf", "leaf-inet-ntp.cnf", "leaf-inet-registry.cnf", "platform.cnf",
                                             "proof.json", "root.cnf")])
        self.assertFalse([p for p in self.out if "bastion" in p], "the CA lives on the lab host, not in the bastion")

    def test_root(self):
        c = self.cnf("root")
        self.assertEqual((c[("dn", "O")], c[("dn", "CN")]), ("Tarnwick", "Tarnwick Lab Root CA"))
        self.assertEqual(c[("ext", "basicConstraints")], "critical,CA:TRUE,pathlen:1")
        self.assertEqual(c[("sfab", "role")], "root")

    def test_intermediates_are_name_constrained(self):
        p = self.cnf("platform")
        self.assertEqual(p[("dn", "CN")], "Tarnwick Platform CA")
        self.assertEqual(p[("ext", "nameConstraints")],
                         f"critical,permitted;DNS:{ZONE},permitted;IP:10.20.0.0/255.252.0.0,permitted;IP:10.24.10.0/255.255.255.0")
        self.assertEqual(p[("ext", "basicConstraints")], "critical,CA:TRUE,pathlen:0")
        self.assertEqual((p[("sfab", "role")], p[("sfab", "key")]), ("gateways", "ec-p256"))
        k = self.cnf("kubernetes")
        self.assertEqual(k[("dn", "CN")], "Tarnwick Kubernetes CA")
        self.assertTrue(k[("ext", "nameConstraints")].startswith(f"critical,permitted;DNS:{ZONE},"))
        self.assertEqual((k[("sfab", "role")], k[("sfab", "key")]), ("kubeadm", "rsa-2048"))
        i = self.cnf("internet")
        self.assertEqual(i[("ext", "nameConstraints")], "critical,permitted;DNS:upstream.example,permitted;IP:192.0.2.0/255.255.255.0")
        self.assertEqual(i[("sfab", "role")], "upstream")
        self.assertEqual(self.proof["roles"], {"kubernetes": "kubeadm", "platform": "gateways", "internet": "upstream"})

    def test_node_leaves(self):
        r = self.cnf("leaf-inet-registry")
        self.assertEqual((r[("sfab", "ca")], r[("sfab", "node")], r[("dn", "CN")]), ("internet", "inet-registry", "registry.upstream.example"))
        self.assertEqual(r[("ext", "subjectAltName")], "DNS:registry.upstream.example,IP:192.0.2.6")
        self.assertEqual(r[("ext", "basicConstraints")], "critical,CA:FALSE")
        self.assertEqual(r[("ext", "extendedKeyUsage")], "serverAuth")
        n = self.cnf("leaf-inet-ntp")
        self.assertEqual(n[("ext", "subjectAltName")], "DNS:ntp.upstream.example,IP:192.0.2.14")
        self.assertEqual(self.proof["node_leaves"], [{"ca": "internet", "dir": "state/tls/inet-registry", "id": "inet-registry", "node": "inet-registry"},
                                                     {"ca": "internet", "dir": "state/tls/inet-ntp", "id": "inet-ntp", "node": "inet-ntp"}])
        self.assertTrue(self.proof["kubeadm"])

    def test_proof_plan(self):
        from sfab.render import ca

        ids = [lf["id"] for lf in self.proof["leaves"]]
        for x in ("platform-inside-cert-gw-users", "platform-outside-public", "internet-inside-leaf-inet-registry", "internet-inside-leaf-inet-ntp",
                  "internet-outside-1", "internet-outside-2", "internet-outside-public"):
            self.assertIn(x, ids)
        for c in self.m.k8s.control:
            self.assertIn(f"kubernetes-inside-apiserver-{c}", ids)
        by = {i.name: i for i in self.m.ca.intermediates}
        for lf in self.proof["leaves"]:
            if lf["expect"] == "reject":
                self.assertTrue(any(not ca.permits(by[lf["ca"]], s) for s in lf["san"]), lf["id"])
        wild = next(lf for lf in self.proof["leaves"] if lf["id"] == "platform-inside-cert-gw-users")
        self.assertEqual(wild["san"], [f"DNS:*.{ZONE}"], "a certificate name only: the zone publishes no wildcard record")
        out = {lf["id"]: lf["san"] for lf in self.proof["leaves"] if lf["ca"] == "internet" and lf["expect"] == "reject"}
        self.assertEqual(out["internet-outside-1"], [f"DNS:llm.{ZONE}"], "the internet CA can sign no platform name")
        api = next(lf for lf in self.proof["leaves"] if lf["id"] == "kubernetes-inside-apiserver-k8s-cp1")
        for s in ("DNS:kubernetes.default.svc.cluster.local", "DNS:k8s-cp1", f"DNS:k8s.{ZONE}", "IP:10.23.0.1", "IP:10.20.1.11", "IP:10.20.1.10"):
            self.assertIn(s, api["san"])

    def test_warnings_name_exactly_the_leaves_the_constraints_refuse(self):
        from sfab.render import ca

        self.assertEqual(self.warnings, [], "the spec's constraints hold every leaf the lab issues")
        m = without_node_names(self.m)
        _, warnings = render_ca(m)
        by = {i.name: i for i in m.ca.intermediates}
        want = sorted(lf["id"] for lf in ca.proof_leaves(m)
                      if lf["expect"] == "verify" and any(not ca.permits(by[lf["ca"]], s) for s in lf["san"]))
        have = sorted(re.match(r"ca: proof leaf (\S+) ", w).group(1) for w in warnings)
        self.assertEqual(have, want)
        self.assertEqual(have, [f"kubernetes-inside-apiserver-{c}" for c in m.k8s.control])

    def test_permits(self):
        from sfab.model import CaIntermediate
        from sfab.render import ca

        i = CaIntermediate(name="x", cn="X", key="ec-p256", dns=(ZONE, "kubernetes"), ip=("10.20.0.0/14",))
        self.assertTrue(ca.permits(i, f"DNS:{ZONE}"))
        self.assertTrue(ca.permits(i, f"DNS:a.b.{ZONE}"))
        self.assertTrue(ca.permits(i, f"DNS:*.{ZONE}"))
        self.assertFalse(ca.permits(i, "DNS:tarnwick.example"), "the corporate apex is outside the platform's zone")
        self.assertFalse(ca.permits(i, "DNS:kubernetes.default"), "a constraint covers names below it, never beside it")
        self.assertTrue(ca.permits(i, "IP:10.23.255.1"))
        self.assertFalse(ca.permits(i, "IP:10.24.0.1"))

    def test_bad_specs_are_refused(self):
        from sfab.render import ca

        bad = dataclasses.replace(self.m.ca.intermediates[0], dns=(f"*.{ZONE}",))
        with self.assertRaises(ca.CaRenderError):
            ca.name_constraints(bad)
        with self.assertRaises(ca.CaRenderError):
            ca.name_constraints(dataclasses.replace(bad, dns=(), ip=()))
        m = dataclasses.replace(self.m, spec=dict(self.m.spec, ca=dict(self.m.spec["ca"], issuer={"intermediate": "nope"})))
        with self.assertRaises(ca.CaRenderError):
            render_ca(m)

    def test_no_ca_without_kubernetes_or_a_leaf(self):
        out, _ = render_ca(model("m1"))
        self.assertEqual(out, {})

    def test_render_is_byte_stable_and_holds_no_key(self):
        again, _ = render_ca(model("m2"))
        self.assertEqual(again, self.out)
        for p, text in self.out.items():
            self.assertNotIn("PRIVATE KEY", text, p)
            for d in DASHES:
                self.assertNotIn(d, text, p)


# --------------------------------------------------------------------------------------------
# scripts


class ScriptCase(unittest.TestCase):
    """A temporary directory with docker, ssh and sshpass shadowed, plus any extra stand-ins."""

    extra: dict = {}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.bin = standins.make_bin(self.tmp / "bin", dict(self.extra))
        self.env = dict(os.environ, PATH=standins.path_with(self.bin), LC_ALL="C")
        for k in list(self.env):
            if k.startswith("SFAB_") or k in ("FORCE", "ROLE"):
                del self.env[k]
        standins.check(self.env, self.bin)

    def tearDown(self):
        self._tmp.cleanup()

    def run_script(self, args, env=None, stdin=None):
        e = dict(self.env, **(env or {}))
        return subprocess.run([BASH, *map(str, args)], env=e, capture_output=True, text=True, input=stdin,
                              timeout=standins.SCRIPT_TIMEOUT_S)


@unittest.skipUnless(BASH, "bash 4 or later is needed")
class TestScriptsParse(unittest.TestCase):
    def test_bash_syntax(self):
        for s in (BASTION_INIT, SFAB_CA, SFAB_DNS, SFAB_NTP, RESOLVER_INIT, RESOLVER_RUN):
            r = subprocess.run([BASH, "-n", str(s)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{s.name}: {r.stderr}")
        r = subprocess.run(["sh", "-n", str(BASTION_DIR / "operator-shell.sh")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


# The stand-ins for BIND's programs: each logs its call; named and pgrep share a state file.
FAKE_CHECKCONF = """#!/bin/sh
echo "checkconf $*" >> "$FAKE_LOG"
for f in $(sed -n 's/^include "\\(.*\\)";.*$/\\1/p' "$1"); do
  [ -r "$f" ] || { echo "checkconf: $f: file not found" >&2; exit 1; }
done
exit "${FAKE_CHECKCONF_RC:-0}"
"""
FAKE_CHECKZONE = """#!/bin/sh
[ "$1" = -q ] && shift
echo "checkzone $1 $2" >> "$FAKE_LOG"
[ -n "${FAKE_BAD_ZONE:-}" ] && [ "$1" = "$FAKE_BAD_ZONE" ] && exit 1
exit 0
"""
FAKE_RNDC_CONFGEN = """#!/bin/sh
while [ $# -gt 0 ]; do case $1 in -c) f=$2; shift ;; esac; shift; done
printf 'key "rndc-key" { };\\n' > "$f"
"""
FAKE_NAMED = """#!/bin/sh
echo "named $*" >> "$FAKE_LOG"
: > "$FAKE_STATE/named.running"
"""
FAKE_PGREP = """#!/bin/sh
[ "$1" = -x ] && [ "$2" = named ] && [ -f "$FAKE_STATE/named.running" ]
"""
FAKE_RNDC = """#!/bin/sh
echo "rndc $*" >> "$FAKE_LOG"
case "$*" in
  *reload*) exit "${FAKE_RNDC_RC:-0}" ;;
  *stop*) rm -f "$FAKE_STATE/named.running" ;;
esac
"""


@unittest.skipUnless(BASH and HAVE_YAML, "bash 4 and PyYAML are needed")
class TestSfabDns(ScriptCase):
    """sfab-dns on the authoritative primary's render (its zones and its views' TSIG keys), the
    secondary's (zones by transfer only) and a resolver's."""

    extra = {"named-checkconf": FAKE_CHECKCONF, "named-checkzone": FAKE_CHECKZONE, "rndc-confgen": FAKE_RNDC_CONFGEN,
             "named": FAKE_NAMED, "pgrep": FAKE_PGREP, "rndc": FAKE_RNDC}

    def setUp(self):
        super().setUp()
        standins.check(self.env, self.bin, tuple(self.extra))
        out, _ = render_dns(model("m2"))
        self.render = out
        self.src = self.tmp / "boot"
        write_tree(self.src, out, "bootstrap/dns-auth1/")
        self.tsig = self.tmp / "tsig"
        self.tsig.mkdir()
        for k in ("internal-xfr", "enterprise-xfr"):
            # a stand-in key: the shape BIND reads, with no key material in it
            (self.tsig / f"{k}.key").write_text(f'key "{k}" {{ algorithm hmac-sha256; secret "c3RhbmQtaW4="; }};\n')
        (self.tmp / "state").mkdir()
        self.live = self.tmp / "etc" / "dns"
        self.log = self.tmp / "calls.log"
        self.env.update({"FAKE_LOG": str(self.log), "FAKE_STATE": str(self.tmp / "state"), "ROLE": "bind-auth",
                         "SFAB_DNS_LIVE": str(self.live), "SFAB_RNDC_KEY": str(self.tmp / "run" / "rndc.key"),
                         "SFAB_TSIG_DIR": str(self.tsig),
                         "SFAB_NAMED_DIRS": " ".join(str(self.tmp / d) for d in ("run", "log", "cache"))})

    def calls(self) -> list:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_check_runs_named_checkzone_on_every_primary_zone_and_changes_nothing(self):
        r = self.run_script([SFAB_DNS, "check", self.src])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("checked: named.conf, 9 zone files, 0 secondary and 0 static-stub zones", r.stdout)
        zones = sorted(c.split()[1] for c in self.calls() if c.startswith("checkzone"))
        want = sorted(z for _v, _m, body in views_of(self.render["bootstrap/dns-auth1/named.conf"]) for z, _f in zones_in(body))
        self.assertEqual(zones, want)
        self.assertFalse(self.live.exists(), "check installs nothing")
        self.assertTrue(any(c.startswith("checkconf ") for c in self.calls()), "named-checkconf read the staged keys")

    def test_the_keys_are_needed_and_never_rendered(self):
        r = self.run_script([SFAB_DNS, "check", self.src], env={"SFAB_TSIG_DIR": str(self.tmp / "no-keys")})
        self.assertEqual(r.returncode, 1)
        self.assertIn("holds none (preflight makes them in state/secrets/tsig)", r.stdout)
        r = self.run_script([SFAB_DNS, "start", self.src])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue((self.live / "keys" / "internal-xfr.key").exists(), "installed beside the render")
        self.assertEqual(oct((self.live / "keys" / "internal-xfr.key").stat().st_mode & 0o777), "0o640")
        self.assertIn(f'include "{self.live}/keys/internal-xfr.key";', (self.live / "named.conf").read_text())

    def test_the_secondary_and_a_resolver_check(self):
        sec = self.tmp / "dns-auth2"
        write_tree(sec, self.render, "bootstrap/dns-auth2/")
        r = self.run_script([SFAB_DNS, "check", sec])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("checked: named.conf, 0 zone files, 9 secondary and 0 static-stub zones", r.stdout)
        res = self.tmp / "dns-res1"
        write_tree(res, self.render, "bootstrap/dns-res1/")
        r = self.run_script([SFAB_DNS, "check", res], env={"ROLE": "bind-recursive"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("checked: named.conf, 1 zone files, 0 secondary and 8 static-stub zones", r.stdout)

    def test_a_refused_zone_installs_nothing(self):
        r = self.run_script([SFAB_DNS, "start", self.src], env={"FAKE_BAD_ZONE": ZONE})
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"named-checkzone refused zone {ZONE}", r.stdout)
        self.assertFalse(self.live.exists())
        self.assertFalse([c for c in self.calls() if c.startswith("named ")], "named never sees a refused zone")

    def test_start_reload_and_a_failed_reload_put_back(self):
        r = self.run_script([SFAB_DNS, "start", self.src])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        conf = (self.live / "named.conf").read_text()
        self.assertIn(f'file "{self.live}/zones/db.internal.{ZONE}"', conf, "the installed copy names the live zones")
        self.assertIn(f'include "{self.tmp}/run/rndc.key";', conf)
        self.assertEqual(len([c for c in self.calls() if c.startswith("named ")]), 1)
        self.assertTrue((self.tmp / "run" / "rndc.key").exists(), "the rndc key is made at the first start")

        r = self.run_script([SFAB_DNS, "start", self.src])
        self.assertIn("live configuration current; server running", r.stdout)
        self.assertEqual(len([c for c in self.calls() if c.startswith("named ")]), 1, "a current server is left alone")

        zone = self.src / "zones" / f"db.enterprise.{ZONE}"
        zone.write_text(zone.read_text() + "extra   IN A   10.20.1.210\n")
        r = self.run_script([SFAB_DNS, "reload", self.src])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("reloaded from", r.stdout)
        self.assertIn("extra", (self.live / "zones" / f"db.enterprise.{ZONE}").read_text())

        zone.write_text(zone.read_text() + "again   IN A   10.20.1.210\n")
        r = self.run_script([SFAB_DNS, "reload", self.src], env={"FAKE_RNDC_RC": "1"})
        self.assertEqual(r.returncode, 1)
        live_zone = (self.live / "zones" / f"db.enterprise.{ZONE}").read_text()
        self.assertIn("extra", live_zone)
        self.assertNotIn("again", live_zone, "the previous configuration serves again")
        self.assertIn("again", (Path(f"{self.live}.failed") / "zones" / f"db.enterprise.{ZONE}").read_text())

        r = self.run_script([SFAB_DNS, "running", self.src])
        self.assertEqual(r.returncode, 0)
        r = self.run_script([SFAB_DNS, "stop", self.src])
        self.assertEqual(r.returncode, 0)
        r = self.run_script([SFAB_DNS, "running", self.src])
        self.assertEqual(r.returncode, 1)

    def test_role_comes_from_init_env(self):
        env = dict(self.env)
        del env["ROLE"]
        r = subprocess.run([BASH, str(SFAB_DNS), "check", str(self.src)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, "no role, no install")
        self.assertIn("no DNS role", r.stdout)
        (self.src / "init.env").write_text("# test\nDNS_ROLE=bind-auth\n")
        r = subprocess.run([BASH, str(SFAB_DNS), "check", str(self.src)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stdout)
        (self.src / "init.env").write_text("# test\nDNS_ROLE=bind-views\n")
        r = subprocess.run([BASH, str(SFAB_DNS), "check", str(self.src)], env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1, "the bastion's old role is no role any more")

    @unittest.skipUnless(DNSMASQ, "dnsmasq is not installed")
    def test_dnsmasq_check(self):
        src = self.tmp / "corp"
        write_tree(src, self.render, "bootstrap/ent-dns/")
        r = self.run_script([SFAB_DNS, "check", src], env={"ROLE": "dnsmasq"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        (src / "dnsmasq.conf").write_text("no-such-option=1\n")
        r = self.run_script([SFAB_DNS, "check", src], env={"ROLE": "dnsmasq"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("dnsmasq --test refused", r.stdout)


@unittest.skipUnless(HAVE_CA_TOOLS and HAVE_YAML, "bash 4, OpenSSL 3, jq and sha256sum are needed")
class TestSfabCa(ScriptCase):
    """The lab CA on the lab host: the root, the intermediates, the node leaves, the publication, the
    proof, the retract, and the Secret written only to a pipe."""

    def setUp(self):
        super().setUp()
        self.conf = self.tmp / "conf"
        out, _ = render_ca(model("m2"))
        write_tree(self.conf, out, "bootstrap/ca/")
        self.state = self.tmp / "state"
        self.shared = self.tmp / "shared"
        self.tls = self.tmp / "tls"
        self.env.update({"SFAB_CA_CONF": str(self.conf), "SFAB_CA_STATE": str(self.state),
                         "SFAB_SHARED": str(self.shared), "SFAB_TLS_DIR": str(self.tls)})

    def ca(self, *args, env=None, stdin=None):
        return self.run_script([SFAB_CA, *args], env=env, stdin=stdin)

    def digest(self, d: Path) -> dict:
        return {p.relative_to(d).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(d.rglob("*")) if p.is_file() and "proof" not in p.parts and p.name != ".lock"}

    def openssl(self, *args) -> str:
        return subprocess.run(["openssl", *map(str, args)], capture_output=True, text=True, timeout=30).stdout

    def test_init_makes_publishes_and_proves(self):
        r = self.ca("init")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        p = json.loads((self.conf / "proof.json").read_text())
        n = len(p["leaves"]) + len(p["node_leaves"])
        self.assertIn(f"== RESULT: {n} passed, 0 failed, 0 known platform limitation(s), 0 skipped", r.stdout)
        for k in ("root.key", "platform.key", "kubernetes.key", "internet.key", "leaves/inet-registry.key", "leaves/inet-ntp.key"):
            self.assertEqual(oct((self.state / k).stat().st_mode & 0o777), "0o600", k)
        self.assertEqual(oct(self.state.stat().st_mode & 0o777), "0o700")
        for f in ("root.crt", "platform.crt", "kubernetes.crt", "internet.crt"):
            self.assertEqual((self.shared / "ca" / f).read_bytes(), (self.state / f).read_bytes(), f)
            self.assertEqual(oct((self.shared / "ca" / f).stat().st_mode & 0o777), "0o644", f)
        cl = self.shared / "cluster" / "ca"
        self.assertEqual((cl / "ca.crt").read_bytes(), (self.state / "kubernetes.crt").read_bytes())
        self.assertEqual((cl / "ca.key").read_bytes(), (self.state / "kubernetes.key").read_bytes())
        self.assertEqual(oct((cl / "ca.key").stat().st_mode & 0o777), "0o600")
        self.assertEqual((cl / "chain.crt").read_bytes(), (self.state / "kubernetes.crt").read_bytes() + (self.state / "root.crt").read_bytes())
        keys = [p for p in self.shared.rglob("*") if p.is_file() and b"PRIVATE KEY" in p.read_bytes()]
        self.assertEqual([p.relative_to(self.shared).as_posix() for p in keys], ["cluster/ca/ca.key"],
                         "the kubeadm intermediate's key is the only key under shared/: the root's never leaves state/ca")
        for node, name, ip in (("inet-registry", "registry.upstream.example", "192.0.2.6"), ("inet-ntp", "ntp.upstream.example", "192.0.2.14")):
            d = self.tls / node
            self.assertEqual(oct((d / "tls.key").stat().st_mode & 0o777), "0o600", node)
            self.assertEqual((d / "chain.crt").read_bytes(), (d / "tls.crt").read_bytes() + (self.state / "internet.crt").read_bytes())
            self.assertEqual((d / "ca.crt").read_bytes(), (self.state / "root.crt").read_bytes())
            v = subprocess.run(["openssl", "verify", "-CAfile", d / "ca.crt", "-untrusted", d / "chain.crt", d / "tls.crt"],
                               capture_output=True, text=True)
            self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
            text = self.openssl("x509", "-in", d / "tls.crt", "-noout", "-text")
            self.assertIn(f"DNS:{name}, IP Address:{ip}", text)
            self.assertIn("CA:FALSE", text)
            self.assertIn("TLS Web Server Authentication", text)
        self.assertIn("CN=Tarnwick Lab Root CA", self.openssl("x509", "-in", self.state / "root.crt", "-noout", "-subject", "-nameopt", "RFC2253"))
        for i in ("platform", "kubernetes", "internet"):
            v = subprocess.run(["openssl", "verify", "-CAfile", self.state / "root.crt", self.state / f"{i}.crt"],
                               capture_output=True, text=True)
            self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        text = self.openssl("x509", "-in", self.state / "platform.crt", "-noout", "-text")
        self.assertIn("X509v3 Name Constraints: critical", text)
        self.assertIn(f"DNS:{ZONE}", text)
        self.assertIn("pathlen:0", text)

    def test_init_again_changes_nothing(self):
        self.assertEqual(self.ca("init").returncode, 0)
        before = self.digest(self.state), self.digest(self.shared), self.digest(self.tls)
        r = self.ca("init")
        self.assertEqual(r.returncode, 0, r.stdout)
        for x in ("root: kept", "platform: kept", "kubernetes: kept", "internet: kept", "leaf-inet-registry: kept", "leaf-inet-ntp: kept"):
            self.assertIn(x, r.stdout)
        self.assertEqual((self.digest(self.state), self.digest(self.shared), self.digest(self.tls)), before)

    def test_new_names_resign_with_the_same_key(self):
        self.assertEqual(self.ca("init").returncode, 0)
        key = (self.state / "platform.key").read_bytes()
        old = (self.state / "platform.crt").read_bytes()
        cnf = self.conf / "platform.cnf"
        cnf.write_text(cnf.read_text().replace(f"permitted;DNS:{ZONE}", f"permitted;DNS:{ZONE},permitted;DNS:other.example"))
        leaf = self.conf / "leaf-inet-registry.cnf"
        leaf.write_text(leaf.read_text().replace("IP:192.0.2.6", "IP:192.0.2.6,DNS:mirror.upstream.example"))
        r = self.ca("init")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("platform: signed (platform.cnf changed", r.stdout)
        self.assertIn("leaf-inet-registry: signed (leaf-inet-registry.cnf changed", r.stdout)
        self.assertIn("kubernetes: kept", r.stdout)
        self.assertIn("leaf-inet-ntp: kept", r.stdout)
        self.assertEqual((self.state / "platform.key").read_bytes(), key)
        self.assertNotEqual((self.state / "platform.crt").read_bytes(), old)
        self.assertIn("mirror.upstream.example", self.openssl("x509", "-in", self.tls / "inet-registry" / "tls.crt", "-noout", "-ext", "subjectAltName"))

    def test_a_comment_change_resigns_nothing(self):
        self.assertEqual(self.ca("init").returncode, 0)
        cnf = self.conf / "kubernetes.cnf"
        cnf.write_text("# another header\n" + cnf.read_text())
        r = self.ca("init")
        self.assertIn("kubernetes: kept", r.stdout)

    def test_force_resigns_and_the_root_is_never_remade(self):
        self.assertEqual(self.ca("init").returncode, 0)
        root = (self.state / "root.crt").read_bytes()
        cnf = self.conf / "root.cnf"
        cnf.write_text(cnf.read_text().replace("CN = Tarnwick Lab Root CA", "CN = Another Root"))
        r = self.ca("init", env={"FORCE": "1"})
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("WARNING: root.cnf changed since the root was made; the root is kept", r.stdout)
        self.assertIn("platform: signed (FORCE=1)", r.stdout)
        self.assertIn("leaf-inet-registry: signed (FORCE=1)", r.stdout)
        self.assertEqual((self.state / "root.crt").read_bytes(), root)

    def test_an_outside_leaf_the_constraints_permit_fails_the_proof(self):
        self.assertEqual(self.ca("init").returncode, 0)
        p = json.loads((self.conf / "proof.json").read_text())
        p["leaves"].append({"id": "platform-outside-wrong", "ca": "platform", "san": [f"DNS:llm.{ZONE}"],
                            "expect": "reject", "source": "a test"})
        (self.conf / "proof.json").write_text(json.dumps(p))
        r = self.ca("proof")
        self.assertEqual(r.returncode, 1)
        self.assertIn(f"FAIL  platform: DNS:llm.{ZONE} refused -> verified", r.stdout)

    def test_a_tampered_node_leaf_fails_the_proof(self):
        self.assertEqual(self.ca("init").returncode, 0)
        other = self.tmp / "other.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", other], check=True,
                       capture_output=True)
        shutil.copy(other, self.tls / "inet-registry" / "tls.key")
        r = self.ca("proof")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL  leaf inet-registry: published for inet-registry -> the key does not match the certificate", r.stdout)

    def test_the_spec_as_written_proves_what_the_render_warns(self):
        from sfab.render import ca

        m = without_node_names(model("m2"))
        out, warnings = render_ca(m)
        conf = self.tmp / "conf-as-written"
        write_tree(conf, out, "bootstrap/ca/")
        r = self.ca("init", env={"SFAB_CA_CONF": str(conf)})
        fails = [x for x in r.stdout.splitlines() if x.startswith("  FAIL")]
        self.assertEqual(len(fails), len(warnings), r.stdout)
        self.assertEqual(r.returncode, 1 if warnings else 0)
        for x in fails:
            self.assertIn("permitted subtree violation", x)
        self.assertEqual(len(warnings), len(ca.check_leaves(m, ca.proof_leaves(m))))

    def test_retract_and_republish(self):
        self.assertEqual(self.ca("init").returncode, 0)
        key = self.shared / "cluster" / "ca" / "ca.key"
        pki = self.shared / "cluster" / "pki"
        pki.mkdir(parents=True)
        # stand-in values: a key file's shape with no key material in it
        (pki / "sa.key").write_text("-----BEGIN PRIVATE KEY-----\nstand-in\n-----END PRIVATE KEY-----\n")
        (pki / "front-proxy-ca.crt").write_text("a certificate\n")
        r = self.ca("retract")
        self.assertIn("cluster/pki/sa.key", r.stdout)
        self.assertTrue((pki / "front-proxy-ca.crt").exists())
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertFalse(key.exists())
        self.assertFalse([p for p in self.shared.rglob("*") if p.is_file() and b"PRIVATE KEY" in p.read_bytes()])
        self.assertIn("kubeadm key: not under", self.ca("status").stdout)
        self.assertIn("nothing to retract", self.ca("retract").stdout)
        self.assertEqual(self.ca("init").returncode, 0)
        self.assertTrue(key.exists())

    def test_no_kubeadm_no_cluster_files(self):
        p = json.loads((self.conf / "proof.json").read_text())
        p["kubeadm"] = False
        (self.conf / "proof.json").write_text(json.dumps(p))
        self.assertEqual(self.ca("init").returncode, 0)
        self.assertFalse((self.shared / "cluster").exists(), "a lab without the cluster gets no kubeadm key")

    def test_verify_and_status(self):
        self.assertEqual(self.ca("init").returncode, 0)
        leaf = self.state / "proof" / "platform-inside-cert-gw-users.crt"
        r = self.ca("verify", leaf)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("issuer   CN=Tarnwick Platform CA,O=Tarnwick", r.stdout)
        self.assertIn("verify   OK", r.stdout)
        foreign = self.tmp / "foreign"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", f"{foreign}.key", "-out", f"{foreign}.crt", "-subj", "/CN=elsewhere", "-days", "1"],
                       capture_output=True, check=True)
        r = self.ca("verify", stdin=Path(f"{foreign}.crt").read_text())
        self.assertEqual(r.returncode, 1)
        self.assertIn("verify   FAIL", r.stdout)
        s = self.ca("status")
        self.assertEqual(s.returncode, 0)
        self.assertIn("platform: CN=Tarnwick Platform CA,O=Tarnwick", s.stdout)
        self.assertIn("role     gateways", s.stdout)
        self.assertIn("role     upstream", s.stdout)
        self.assertIn("chains   yes", s.stdout)
        self.assertIn("leaf inet-registry (inet-registry): CN=registry.upstream.example", s.stdout)
        self.assertNotIn("PRIVATE KEY", s.stdout)

    def test_k8s_secret_goes_to_a_pipe_only(self):
        self.assertEqual(self.ca("init").returncode, 0)
        r = self.ca("k8s-secret", "platform", "cert-manager/lab-ca")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        doc = r.stdout
        self.assertNotIn("PRIVATE KEY", doc, "the key is base64 in the manifest, never PEM text on the pipe")
        self.assertNotIn("PRIVATE KEY", r.stderr)
        self.assertIn("written to the pipe", r.stderr)
        import base64

        data = dict(re.findall(r"^  (tls\.crt|tls\.key|ca\.crt): (\S+)$", doc, re.M))
        self.assertIn("kind: Secret", doc)
        self.assertIn("type: kubernetes.io/tls", doc)
        self.assertIn("namespace: cert-manager", doc)
        self.assertEqual(base64.b64decode(data["tls.key"]), (self.state / "platform.key").read_bytes())
        self.assertEqual(base64.b64decode(data["tls.crt"]), (self.state / "platform.crt").read_bytes() + (self.state / "root.crt").read_bytes())
        self.assertEqual(base64.b64decode(data["ca.crt"]), (self.state / "root.crt").read_bytes())
        r = self.ca("k8s-secret", "platform", "no-slash")
        self.assertEqual(r.returncode, 1)
        if shutil.which("script"):
            # on a terminal it refuses (util-linux script on the lab host, BSD script elsewhere)
            cmd = f"SFAB_CA_CONF={self.conf} SFAB_CA_STATE={self.state} {BASH} {SFAB_CA} k8s-secret platform cert-manager/lab-ca"
            t = subprocess.run(["script", "-q", "-c", cmd, "/dev/null"] if os.uname().sysname == "Linux"
                               else ["script", "-q", "/dev/null", "sh", "-c", cmd], stdin=subprocess.DEVNULL, capture_output=True,
                               text=True, timeout=60)
            self.assertIn("never to a terminal", t.stdout)
            self.assertNotIn("tls.key:", t.stdout)

    def test_no_render_no_ca(self):
        r = self.ca("init", env={"SFAB_CA_CONF": str(self.tmp / "nothing")})
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL:", r.stdout)

    def test_a_lab_directory(self):
        lab = self.tmp / "lab"
        write_tree(lab / "bootstrap" / "ca", {p.name: p.read_text() for p in self.conf.iterdir()})
        env = {k: "" for k in ("SFAB_CA_CONF", "SFAB_CA_STATE", "SFAB_SHARED", "SFAB_TLS_DIR")}
        e = {k: v for k, v in self.env.items() if k not in env}
        r = subprocess.run([BASH, str(SFAB_CA), "-C", str(lab), "init"], env=e, capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for f in ("state/ca/root.key", "state/shared/ca/root.crt", "state/tls/inet-registry/tls.key"):
            self.assertTrue((lab / f).exists(), f)


def bastion_boot(tmp: Path, m=None) -> Path:
    from sfab.render import host

    m = m or model("m2")
    boot = tmp / "boot"
    write_tree(boot, host.render(m, ctx()), "bootstrap/bastion/")
    return boot


@unittest.skipUnless(BASH and HAVE_YAML, "bash 4 and PyYAML are needed")
class TestBastionInit(ScriptCase):
    def dry(self, boot: Path, **env):
        e = {"SFAB_DRY_RUN": "1", "SFAB_BOOTSTRAP": str(boot), "SFAB_OPERATOR_DIR": str(self.tmp / "operators"),
             "SFAB_CA_ROOT": str(self.tmp / "ca" / "root.crt")}
        e.update(env)
        return self.run_script([BASTION_INIT], env=e)

    def test_dry_run_builds_the_jump_host(self):
        boot = bastion_boot(self.tmp)
        r = self.dry(boot)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout.splitlines()
        want = [
            "+ sysctl -qw net.ipv6.conf.default.disable_ipv6=1",
            "+ ip link add bond0 type bond mode 802.3ad lacp_rate fast miimon 100 xmit_hash_policy layer3+4",
            "+ ip link set eth1 master bond0",
            "+ ip link set eth2 master bond0",
            "+ ip link set bond0 mtu 1500",
            "+ ip addr replace 10.20.3.10/24 dev bond0",
            "+ ip route replace 172.21.40.0/24 dev eth0 src 172.21.40.50 table 150",
            "+ ip route replace default via 172.21.40.1 dev eth0 table 150",
            "+ ip rule add from 172.21.40.50 lookup 150",
            "+ ip route replace default via 10.20.3.1 dev bond0",
            "+ ethtool -K eth1 tx off", "+ ethtool -K eth2 tx off", "+ ethtool -K bond0 tx off",
            f"+ write /etc/resolv.conf: search {ZONE}; nameserver 10.20.13.21; nameserver 10.20.14.21",
            "+ operator user admin, key-only, sudo",
            "+ lldpd -I eth1,eth2",
        ]
        for w in want:
            self.assertIn(w, out)
        self.assertLess(out.index(want[0]), out.index(want[1]), "IPv6 goes off before anything else")
        wait = next(i for i, x in enumerate(out) if x.startswith("+ wait for links"))
        self.assertLess(out.index(want[13]), wait, "resolv.conf is written before the wait for links")
        self.assertIn("+ wait for links: eth1 eth2 (at most 600s)", out, "one leg: no out-of-band NIC")
        for word in ("eth3", "sfab-dns", "chronyd", "named", "sfab-ca", "lookup 100"):
            self.assertFalse([x for x in out if word in x], f"the jump host runs no {word}")

    def test_operator_kubeconfig_pickup_for_the_operator_only(self):
        boot = bastion_boot(self.tmp)
        r = self.dry(boot)
        self.assertNotIn("+ kubeconfig", r.stdout, "no kubeconfig issued yet, no pickup")
        (self.tmp / "operators" / "admin").mkdir(parents=True)
        (self.tmp / "operators" / "admin" / "kubeconfig").write_text("apiVersion: v1\n")
        r = self.dry(boot)
        self.assertIn(f"+ kubeconfig from {self.tmp}/operators/admin/kubeconfig for admin only", r.stdout)
        self.assertNotIn("for root", r.stdout)

    def test_the_lab_root_is_trusted_once_published(self):
        boot = bastion_boot(self.tmp)
        self.assertNotIn("+ trust", self.dry(boot).stdout)
        (self.tmp / "ca").mkdir()
        (self.tmp / "ca" / "root.crt").write_text("a certificate\n")
        self.assertIn(f"+ trust {self.tmp}/ca/root.crt", self.dry(boot).stdout)

    def test_a_missing_env_is_fatal(self):
        r = self.dry(self.tmp / "nowhere")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FATAL: no", r.stdout)

    def test_health_before_setup(self):
        r = self.run_script([BASTION_INIT, "--health"], env={"SFAB_READY_FILE": str(self.tmp / "none")})
        self.assertEqual(r.returncode, 1)
        self.assertIn("setup has not finished", r.stdout)


@unittest.skipUnless(BASH and HAVE_YAML, "bash 4 and PyYAML are needed")
class TestResolverInit(ScriptCase):
    def boot(self, node: str, lab: str = "m2") -> Path:
        from sfab.render import host

        m = model(lab)
        boot = self.tmp / node
        write_tree(boot, host.render(m, ctx()), f"bootstrap/{node}/")
        write_tree(boot, render_dns(m)[0], f"bootstrap/{node}/")
        return boot

    def dry(self, boot: Path):
        return self.run_script([RESOLVER_INIT, boot / "init.env"],
                               env={"SFAB_DRY_RUN": "1", "SFAB_NET_INIT": str(CLIENT_INIT), "SFAB_READY_FILE": str(self.tmp / "ready")})

    def test_dry_run_public_server(self):
        boot = self.boot("ops-dns", "one")
        r = self.dry(boot)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("+ ip addr replace 192.0.2.10/30 dev eth1", r.stdout, "the client's init builds the port")
        self.assertIn("+ ip route replace default via 192.0.2.9 dev eth1", r.stdout)
        self.assertIn(f"+ ROLE=bind-auth TSIG_DIR=/sfab/tsig sfab-dns start {boot}", r.stdout)
        self.assertNotIn("sfab-ntp", r.stdout)
        self.assertFalse((self.tmp / "ready").exists())

    def test_dry_run_authoritative_on_the_pair(self):
        boot = self.boot("dns-auth2")
        r = self.dry(boot)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for w in ("+ ip link add bond0 type bond mode 802.3ad lacp_rate fast miimon 100 xmit_hash_policy layer3+4",
                  "+ ip link set bond0 mtu 1500", "+ ip addr replace 10.20.14.11/24 dev bond0",
                  "+ ip route replace default via 10.20.14.1 dev bond0",
                  f"+ ROLE=bind-auth TSIG_DIR=/sfab/tsig sfab-dns start {boot}"):
            self.assertIn(w, r.stdout)

    def test_dry_run_resolver_with_time(self):
        boot = self.boot("dns-res1")
        r = self.dry(boot)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"+ ROLE=bind-recursive TSIG_DIR=/sfab/tsig sfab-dns start {boot}", r.stdout)
        self.assertIn(f"+ TLS_DIR= sfab-ntp start {boot}", r.stdout, "a time server, no NTS key of its own")

    def test_dry_run_time_reference(self):
        boot = self.boot("inet-ntp")
        r = self.dry(boot)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("sfab-dns", r.stdout, "the reference serves no DNS")
        self.assertIn(f"+ TLS_DIR=/sfab/tls sfab-ntp start {boot}", r.stdout)

    def test_nothing_to_serve_is_fatal(self):
        boot = self.boot("ops-dns", "one")
        env_file = boot / "init.env"
        env_file.write_text("".join(x + "\n" for x in env_file.read_text().splitlines() if not x.startswith("DNS_ROLE=")))
        r = self.run_script([RESOLVER_INIT, env_file], env={"SFAB_DRY_RUN": "1", "SFAB_NET_INIT": str(CLIENT_INIT)})
        self.assertEqual(r.returncode, 1)
        self.assertIn("nothing to serve", r.stdout)

    def test_health_before_init(self):
        r = self.run_script([RESOLVER_RUN, "--health"], env={"SFAB_READY_FILE": str(self.tmp / "none")})
        self.assertEqual(r.returncode, 1)
        self.assertIn("sfab-init.sh has not run", r.stdout)


FAKE_CHRONYD = """#!/bin/sh
echo "chronyd $*" >> "$FAKE_LOG"
case " $* " in *" -p "*) exit "${FAKE_CHRONYD_PARSE_RC:-0}" ;; esac
: > "$FAKE_STATE/chronyd.running"
"""
FAKE_PGREP_CHRONY = """#!/bin/sh
[ "$1" = -x ] && [ "$2" = chronyd ] && [ -f "$FAKE_STATE/chronyd.running" ]
"""
FAKE_INSTALL = """#!/bin/sh
echo "install $*" >> "$FAKE_LOG"
while [ $# -gt 2 ]; do shift; done
cp "$1" "$2"
"""


@unittest.skipUnless(BASH and HAVE_YAML, "bash 4 and PyYAML are needed")
class TestSfabNtp(ScriptCase):
    extra = {"chronyd": FAKE_CHRONYD, "pgrep": FAKE_PGREP_CHRONY, "install": FAKE_INSTALL, "chown": "#!/bin/sh\nexit 0\n"}

    def setUp(self):
        super().setUp()
        standins.check(self.env, self.bin, tuple(self.extra))
        out, _ = render_dns(model("m2"))
        (self.tmp / "state").mkdir()
        self.log = self.tmp / "calls.log"
        self.env.update({"FAKE_LOG": str(self.log), "FAKE_STATE": str(self.tmp / "state"), "SFAB_NTP_LIVE": str(self.tmp / "live"),
                         "SFAB_TLS_LIVE": str(self.tmp / "tls-live"),
                         "SFAB_CHRONY_DIRS": f"{self.tmp}/run-chrony {self.tmp}/lib-chrony"})
        self.res = self.tmp / "dns-res1"
        write_tree(self.res, out, "bootstrap/dns-res1/")
        self.ref = self.tmp / "inet-ntp"
        write_tree(self.ref, out, "bootstrap/inet-ntp/")

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_start_parses_then_runs_with_minus_x(self):
        r = self.run_script([SFAB_NTP, "start", self.res])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        c = self.calls()
        self.assertTrue(c[0].startswith("chronyd -p -f "), "the file is checked first")
        self.assertRegex(c[1], r"^chronyd -x -u \S+ -f ", "chronyd never adjusts the host's clock")
        self.assertEqual((self.tmp / "live" / "chrony.conf").read_text(), (self.res / "chrony.conf").read_text())
        r = self.run_script([SFAB_NTP, "start", self.res])
        self.assertIn("already running", r.stdout)

    def test_a_refused_file_starts_nothing(self):
        r = self.run_script([SFAB_NTP, "start", self.res], env={"FAKE_CHRONYD_PARSE_RC": "1"})
        self.assertEqual(r.returncode, 1)
        self.assertIn("chronyd refused", r.stdout)
        self.assertFalse([x for x in self.calls() if " -x " in x])

    def test_the_reference_installs_its_nts_key(self):
        tls = self.tmp / "tls"
        tls.mkdir()
        (tls / "tls.key").write_text("stand-in\n")
        (tls / "chain.crt").write_text("a chain\n")
        r = self.run_script([SFAB_NTP, "start", self.ref], env={"TLS_DIR": str(tls)})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual((self.tmp / "tls-live" / "chain.crt").read_text(), "a chain\n")
        self.assertTrue([x for x in self.calls() if x.startswith("install -m 0640") and x.endswith("tls.key")])
        r = self.run_script([SFAB_NTP, "start", self.ref], env={"TLS_DIR": str(self.tmp / "none")})
        self.assertEqual(r.returncode, 1, "a reference with NTS and no key does not start")


# --------------------------------------------------------------------------------------------
# images


def _pins_in(mk: Path) -> list:
    return re.findall(r"\$\(call PIN,([a-z0-9_.]+)\)", mk.read_text())


class TestImages(unittest.TestCase):
    def test_every_pin_the_images_read_is_set(self):
        import importlib.util

        spec_ = importlib.util.spec_from_file_location("versions", ROOT / "images" / "versions.py")
        v = importlib.util.module_from_spec(spec_)
        spec_.loader.exec_module(v)
        tree = v.load()
        pins = _pins_in(BASTION_DIR / "image.mk") + _pins_in(RESOLVER_DIR / "image.mk")
        self.assertIn("kubernetes.helm.sha256", pins)
        self.assertIn("images.resolver.packages.chrony", pins)
        for p in pins:
            val = v.get(tree, p)
            self.assertTrue(val, f"{p} is not pinned in spec/versions.yaml")
            if p.endswith(".sha256"):
                self.assertRegex(str(val), r"^[0-9a-f]{64}$", p)
        self.assertEqual(v.image(tree, "bastion"), "sfab/bastion:4")
        self.assertEqual(v.image(tree, "resolver"), "sfab/resolver:3")
        self.assertEqual(v.image(tree, "registry"), "sfab/registry:3")
        self.assertTrue(v.image(tree, "ubuntu_base").split("@")[1].startswith("sha256:"), "the bases are pinned by digest")
        self.assertTrue(v.image(tree, "alpine_base").split("@")[1].startswith("sha256:"))

    def test_bastion_dockerfile(self):
        d = (BASTION_DIR / "Dockerfile").read_text()
        for arg in ("UBUNTU_BASE", "UBUNTU_SNAPSHOT", "KUBECTL_VERSION", "KUBECTL_SHA256", "HELM_VERSION",
                    "HELM_SHA256", "CILIUM_CLI_VERSION", "CILIUM_CLI_SHA256"):
            self.assertIn(f"ARG {arg}", d)
            self.assertIn(f"--build-arg {arg}=", (BASTION_DIR / "image.mk").read_text())
        self.assertIn("sha256sum -c -", d, "every download is checked against its pin")
        self.assertIn("RUN rm -f /etc/ssh/ssh_host_*", d, "no package-made key stays in the image")
        self.assertIn('ENTRYPOINT ["/usr/local/sbin/bastion-init.sh"]', d)
        pkgs = re.search(r'pkgs="([^"]+)"', d, re.S).group(1).split()
        for gone in ("bind9", "bind9-utils", "chrony"):
            self.assertNotIn(gone, pkgs, "the jump host serves no DNS and no time")
        for f in ("sfab-ca", "sfab-dns"):
            self.assertNotIn(f, d, "the CA lives on the lab host, the DNS tool in the resolver image")
        self.assertFalse((BASTION_DIR / "sfab-ca").exists() or (BASTION_DIR / "sfab-dns").exists())

    def test_resolver_dockerfile(self):
        d = (RESOLVER_DIR / "Dockerfile").read_text()
        for p in ('"bind=${BIND_VERSION}"', '"dnsmasq=${DNSMASQ_VERSION}"', '"chrony=${CHRONY_VERSION}"'):
            self.assertIn(p, d)
        self.assertIn("COPY sfab-dns sfab-ntp /usr/local/bin/", d, "both tools live in the resolver's own context")
        self.assertIn("COPY --from=client init.sh /usr/local/sbin/sfab-net-init.sh", d)
        self.assertIn("COPY resolver-init.sh /usr/local/sbin/sfab-init.sh", d, "the topology's exec (render/clab.py)")
        mk = (RESOLVER_DIR / "image.mk").read_text()
        self.assertIn("--build-context client=$(IMG)/client", mk)
        self.assertNotIn("bastion", mk)

    def test_labels_and_secrets(self):
        for d in (BASTION_DIR, RESOLVER_DIR):
            text = (d / "Dockerfile").read_text()
            labels = re.findall(r"(\S+)=\"", text.split("LABEL", 1)[1].split("\n\n")[0]) if "LABEL" in text else []
            self.assertTrue(labels)
            for lab in labels:
                self.assertTrue(lab.startswith("org.opencontainers.image."), f"{d.name}: label {lab}")
            for p in d.iterdir():
                # What goes into the image: the .dockerignore keeps the docs and the make fragment out.
                if p.is_file() and p.suffix not in (".md", ".mk") and not p.name.startswith("."):
                    t = p.read_text()
                    self.assertNotRegex(t.lower(), r"password\s*=", p.name)
                    self.assertNotIn("PRIVATE KEY-----\n", t, p.name)
                    for x in ("tarnwick", "corvane"):
                        self.assertNotIn(x, t.lower(), f"{p.name}: the images hold no organization name")

    def test_prose(self):
        files = [Path(__file__), ROOT / "common" / "sfab" / "render" / "dns.py", ROOT / "common" / "sfab" / "render" / "ca.py", SFAB_CA]
        files += [p for d in (BASTION_DIR, RESOLVER_DIR) for p in d.iterdir() if p.is_file() and p.name != ".DS_Store"]
        for f in files:
            text = f.read_text(encoding="utf-8")
            for d in DASHES:
                self.assertNotIn(d, text, f.name)


if __name__ == "__main__":
    unittest.main()
