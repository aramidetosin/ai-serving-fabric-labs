"""Firewall tests: the PA-VM renderer (golden XML and enforced lines for dev/m1, the full state one
rulebase, the many state, the slice rules), and the scripts in common/fw against stand-ins: a
small fake of the PAN-OS XML API for fw-startup.py and fw-api.sh, and stand-ins for sshpass, ssh
and docker (standins.py) for panos.sh and fw-api.sh, so no test opens a real session.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_firewall -v
Refresh the golden files after a deliberate change:  SFAB_UPDATE_GOLDEN=1 (same command).
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from sfab.tests import standins

ROOT = Path(__file__).resolve().parents[3]
FW_DIR = ROOT / "common" / "fw"
# The renderer's own golden set for dev/m1 (the switch renderers keep theirs under golden/m1).
GOLDEN = Path(__file__).resolve().parent / "golden" / "m1-panos"
UPDATE = os.environ.get("SFAB_UPDATE_GOLDEN") == "1"

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

# Stand-in values: the firewall password, the API key (in the LUFRPT form PAN-OS keys take) and the
# password hashes in this module are made up for the tests and were never real credentials.
PASSWORD = "pw-Correct-Horse-41"
KEY = "LUFRPT1sfabTESTKEY0123456789abcdefXYZ=="

# A docker stand-in for the credential source "the firewall container's launcher arguments":
# `docker inspect -f '{{json .Config}}' sfab-m1-fw` prints the file FAKE_DOCKER_CONFIG names; any
# other call, or no such file, fails as docker does for an unknown container.
FAKE_DOCKER = r"""#!/usr/bin/env bash
if [ "${1:-}" = inspect ] && [ "${2:-}" = -f ] && [ "${3:-}" = '{{json .Config}}' ] &&
    [ "${4:-}" = sfab-m1-fw ] && [ $# -eq 4 ] && [ -n "${FAKE_DOCKER_CONFIG:-}" ] && [ -r "$FAKE_DOCKER_CONFIG" ]; then
    cat "$FAKE_DOCKER_CONFIG"
    exit 0
fi
echo "Error: No such object: ${4:-}" >&2
exit 1
"""


def launcher_config(path: Path, password: str | None = PASSWORD, env_password: str | None = None) -> Path:
    """What docker inspect shows for the PA-VM container: containerlab's paloalto_panos kind puts
    the launcher's login on its command line; the topology passes no USERNAME or PASSWORD."""
    cmd = ["--username", "admin"] + (["--password", password] if password is not None else []) + ["--hostname", "fw"]
    env = ["QEMU_CPU=host", "QEMU_SMP=8", "QEMU_MEMORY=16384"]
    if env_password is not None:
        env.append(f"PASSWORD={env_password}")
    path.write_text(json.dumps({"Cmd": cmd, "Env": env}), encoding="utf-8")
    return path


def m1_chapter() -> dict:
    return {"lab": "sfab-m1", "profile": "a", "state": "one",
            "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2"]},
            "features": {"k8s": False, "serving": False, "storage_setup": False}}


_SPEC = None


def spec():
    global _SPEC
    if _SPEC is None:
        from sfab.spec import load

        _SPEC = load(ROOT)
    return _SPEC


def model(chapter):
    from sfab.spec import select

    return select(spec(), chapter)


def ctx_for(labdir: Path):
    from sfab.render import Context

    return Context(outdir=labdir, labdir=labdir, root=ROOT, spec=spec())


def render_fw(chapter, labdir: Path | None = None) -> dict:
    from sfab.render import panos

    m = model(chapter)
    return panos.render(m, ctx_for(labdir or ROOT / "dev" / "m1"))


def load_fw_startup():
    s = importlib.util.spec_from_file_location("fw_startup", FW_DIR / "fw-startup.py")
    mod = importlib.util.module_from_spec(s)
    s.loader.exec_module(mod)
    t = mod.Timing
    for name in ("keygen_pause", "idle_pause", "job_pause", "commit_pause", "restart_down_pause", "restart_back_wait"):
        setattr(t, name, 0.0)
    t.keygen_tries, t.refused_tries, t.idle_tries, t.job_tries = 5, 2, 5, 10
    t.commit_tries, t.commit_poll_tries, t.restart_down_tries, t.http_timeout = 5, 10, 5, 5.0
    return mod


# --------------------------------------------------------------------------------------------
# set format from the XML, the way PAN-OS prints it (a check on enforced.txt's own generator)


def _fmt(v: str) -> str:
    return f'"{v}"' if (" " in v or not v) else v


def xml_to_set(root: ET.Element) -> list[str]:
    out: list[str] = []

    def emit(words, value=None):
        out.append(" ".join(["set"] + words + ([value] if value is not None else [])))

    def walk(el, prefix):
        for c in el:
            if c.tag == "entry":
                name = c.get("name")
                if len(c) == 0:
                    emit(prefix + [_fmt(name)])
                else:
                    walk(c, prefix + [name])
            elif len(c) and all(g.tag == "member" for g in c):
                vals = [_fmt(g.text or "") for g in c]
                emit(prefix + [c.tag], vals[0] if len(vals) == 1 else "[ " + " ".join(vals) + " ]")
            elif len(c) == 0:
                # an empty element (nexthop <discard/>) prints as its bare keyword
                emit(prefix + [c.tag], _fmt(c.text) if c.text is not None else None)
            else:
                walk(c, prefix + [c.tag])

    dev = root.find("devices/entry")
    walk(dev.find("deviceconfig"), ["deviceconfig"])
    walk(dev.find("network"), ["network"])
    for v in dev.findall("vsys/entry"):
        walk(v, [])
    return out


# --------------------------------------------------------------------------------------------
# Renderer


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class TestPanosM1(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = render_fw(m1_chapter())
        cls.xml = cls.out["bootstrap/fw/startup-config.xml"]
        cls.enf = cls.out["bootstrap/fw/enforced.txt"]
        cls.root = ET.fromstring(cls.xml)
        cls.vsys = cls.root.find("devices/entry/vsys/entry")

    def test_golden(self):
        if UPDATE:
            if GOLDEN.exists():
                shutil.rmtree(GOLDEN)
            for name, text in self.out.items():
                p = GOLDEN / name
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(text, encoding="utf-8")
        have = sorted(p.relative_to(GOLDEN).as_posix() for p in GOLDEN.rglob("*") if p.is_file())
        self.assertEqual(have, sorted(self.out), "the set of rendered files differs from the golden set")
        for name, text in sorted(self.out.items()):
            self.assertEqual((GOLDEN / name).read_text(encoding="utf-8"), text,
                             f"{name} differs from tests/golden/m1-panos/{name} (SFAB_UPDATE_GOLDEN=1 refreshes it)")

    def test_paths(self):
        self.assertEqual(sorted(self.out), ["bootstrap/fw/enforced.txt", "bootstrap/fw/startup-config.xml"])

    def test_launcher_contract(self):
        b = self.xml.encode()
        self.assertIn(b"<config", b[:200], "the launcher looks for <config in the first 200 bytes")
        self.assertTrue(self.xml.startswith('<config version="12.1.0" urldb="paloaltonetworks" detail-version="12.1.2">'))
        self.assertIn(b"<jumbo-frame>", b, "an MTU above 1500 needs the launcher's jumbo-frame phase")
        self.assertNotIn("<?xml", self.xml)
        self.assertNotIn("<!--", self.xml)
        self.assertEqual(self.root.find("devices/entry").get("name"), "localhost.localdomain")
        self.assertIsNone(self.root.find("shared"))

    def test_no_secrets_or_management_address(self):
        for text in (self.xml, self.enf):
            low = text.lower()
            for word in ("mgt-config", "phash", "password", "<key>", "${", "ip-address 10.0.0"):
                self.assertNotIn(word, low)
            # no address in the vrnetlab slirp network: 10.0.0.0/8 appears only as the discard route
            self.assertNotIn("10.0.0.", low.replace("10.0.0.0/8", ""))
        self.assertIsNone(self.root.find(".//mgt-config"))

    def test_plain_prose(self):
        for text in (self.xml, self.enf):
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)
            self.assertTrue(text.endswith("\n"))
            self.assertNotIn("\r", text)

    def test_bundle_and_units(self):
        dev = self.root.find("devices/entry")
        eths = {e.get("name"): e for e in dev.findall("network/interface/ethernet/entry")}
        self.assertEqual(sorted(eths), ["ethernet1/1", "ethernet1/2", "ethernet1/3"])
        for n in ("ethernet1/1", "ethernet1/2"):
            self.assertEqual(eths[n].findtext("aggregate-group"), "ae1")
        ae = dev.find("network/interface/aggregate-ethernet/entry[@name='ae1']/layer3")
        self.assertEqual(ae.findtext("mtu"), "9216")
        self.assertEqual((ae.findtext("lacp/enable"), ae.findtext("lacp/mode"), ae.findtext("lacp/transmission-rate")),
                         ("yes", "active", "fast"))
        units = {u.get("name"): u for u in ae.findall("units/entry")}
        self.assertEqual(list(units), ["ae1.100", "ae1.110", "ae1.200", "ae1.300", "ae1.130", "ae1.131"])
        m = model(m1_chapter())
        for vid in (100, 110, 200, 300, 130, 131):
            u = units[f"ae1.{vid}"]
            self.assertEqual(u.findtext("tag"), str(vid))
            self.assertEqual(u.find("ip/entry").get("name"), f"{m.vlans[vid].gw}/24")
            self.assertTrue(m.vlans[vid].gw.endswith(".1"))
            # each unit at its VLAN's one IP MTU: 9000 for the nodes, 1500 everywhere else
            self.assertEqual(u.findtext("mtu"), "9000" if vid == 100 else "1500", f"VLAN {vid}'s IP MTU")
            # administrative access on the bastion VLAN's unit only (chapter 4, firewall.admin), for the jump host
            self.assertEqual(u.findtext("interface-management-profile"), "bastion-admin" if vid == 300 else "ping-only")
        oob = eths["ethernet1/3"].find("layer3")
        self.assertEqual(oob.find("ip/entry").get("name"), "10.20.9.254/24")
        self.assertEqual(oob.findtext("interface-management-profile"), "ping-only", "nothing administrative on the BMC VLAN")
        prof = dev.find("network/profiles/interface-management-profile/entry[@name='ping-only']")
        self.assertEqual([c.tag for c in prof], ["ping"])
        adm = dev.find("network/profiles/interface-management-profile/entry[@name='bastion-admin']")
        self.assertEqual([(c.tag, c.text) for c in adm if c.tag != "permitted-ip"], [("https", "yes"), ("ssh", "yes"), ("ping", "yes")])
        self.assertEqual([e.get("name") for e in adm.findall("permitted-ip/entry")], ["10.20.3.10/32"], "the jump host only")
        self.assertEqual(dev.findtext("deviceconfig/setting/jumbo-frame/mtu"), "9216")

    def test_one_virtual_router_zones_and_import(self):
        dev = self.root.find("devices/entry")
        vrs = dev.findall("network/virtual-router/entry")
        self.assertEqual([v.get("name") for v in vrs], ["core"])
        l3 = ["ae1.100", "ae1.110", "ae1.200", "ae1.300", "ae1.130", "ae1.131", "ethernet1/3"]
        self.assertEqual([x.text for x in vrs[0].findall("interface/member")], l3)
        self.assertEqual([x.text for x in self.vsys.findall("import/network/interface/member")], l3)
        zones = {z.get("name"): [x.text for x in z.findall("network/layer3/member")] for z in self.vsys.findall("zone/entry")}
        self.assertEqual(zones, {"k8s-nodes": ["ae1.100"], "ingress": ["ae1.110"], "stor-mgmt": ["ae1.200"], "bastion": ["ae1.300"],
                                 "services": ["ae1.130", "ae1.131"], "oob": ["ethernet1/3"]})
        statics = vrs[0].findall("routing-table/ip/static-route/entry")
        self.assertEqual([(e.get("name"), e.findtext("destination")) for e in statics],
                         [("discard-10", "10.0.0.0/8"), ("discard-172-16", "172.16.0.0/12"), ("discard-192-168", "192.168.0.0/16")],
                         "M1 has no uplink: only the RFC 1918 discard routes, no default route and no tunnel route")
        for e in statics:
            self.assertIsNotNone(e.find("nexthop/discard"))
            self.assertIsNone(e.find("interface"))

    def test_rulebase(self):
        rules = self.vsys.findall("rulebase/security/rules/entry")
        names = [r.get("name") for r in rules]
        # M1 holds no bastion, no services host and no client: the rules naming only those are out,
        # bastion-to-bmc keeps the named collector, and no zone has an allow-any intrazone rule
        self.assertEqual(names, ["bastion-to-bmc", "inside-to-gateway-ping", "nodes-to-internal-gateway", "csi-to-storage-api", "deny-all-log"])
        for r in rules:
            self.assertEqual(r.findtext("log-end"), "yes", r.get("name"))
        last = rules[-1]
        self.assertEqual(last.findtext("action"), "deny")
        for f in ("from", "to", "source", "destination", "application", "service"):
            self.assertEqual([x.text for x in last.findall(f"{f}/member")], ["any"], f)
        self.assertEqual(last.findtext("description"), "dec-policy-deny-all-log")
        self.assertIsNone(last.find("profile-setting"), "a deny rule carries no profile group")
        for r in rules[:-1]:
            self.assertEqual(r.findtext("action"), "allow")
            self.assertNotIn("any", [x.text for x in r.findall("application/member")], r.get("name"))
            self.assertEqual([x.text for x in r.findall("service/member")], ["application-default"], r.get("name"))
            self.assertEqual(r.findtext("profile-setting/group/member"), "bp-default", r.get("name"))
        bmc = rules[0]
        self.assertEqual([x.text for x in bmc.findall("source/member")], ["collector"])
        self.assertEqual([x.text for x in bmc.findall("application/member")], ["ssh", "ssl"])
        self.assertEqual(self.vsys.findtext("address/entry[@name='collector']/ip-netmask"), "10.20.3.20/32")
        self.assertIsNone(self.vsys.find("address-group"), "no rule here names the admins group")
        defaults = {e.get("name"): (e.findtext("action"), e.findtext("log-end")) for e in self.vsys.findall("rulebase/default-security-rules/rules/entry")}
        self.assertEqual(defaults, {"intrazone-default": ("deny", "yes"), "interzone-default": ("deny", "yes")})
        self.assertIsNone(self.vsys.find("rulebase/nat"), "M1 has no uplink zone, so no NAT")
        self.assertIsNone(self.vsys.find("service"))

    def test_enforced_matches_xml(self):
        lines = [x for x in self.enf.splitlines() if x and not x.startswith("#")]
        self.assertTrue(all(x.startswith("set ") for x in lines))
        self.assertEqual(len(lines), len(set(lines)))
        self.assertEqual(set(lines), set(xml_to_set(self.root)))
        self.assertIn("#   rule bastion-to-nodes: node bastion is not in this lab", self.enf)
        self.assertIn("#   interface ethernet1/5: its wire is not in this lab", self.enf)
        self.assertIn("#   vpn ops-gw: interface ethernet1/5 is not in this lab", self.enf)

    def test_byte_stable(self):
        again = render_fw(m1_chapter())
        self.assertEqual(again, self.out)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class TestPanosStates(unittest.TestCase):
    def test_the_land_probe_rule_only_where_the_land_drill_runs(self):
        # chapter 4's audit and land drill ping the public address from a node: the rule that allows it
        # exists only in a lab whose drills plan runs the land drill, so no other lab's rulebase changes
        from sfab.spec import load_chapter

        names4 = [r.name for r in model(load_chapter(ROOT / "ch04")).firewall.rules]
        self.assertEqual(len(names4), 25)
        i = names4.index("nodes-to-public-ping")
        self.assertEqual(names4[i - 1], "inside-to-gateway-ping")
        r = model(load_chapter(ROOT / "ch04")).firewall.rules[i]
        self.assertEqual((r.from_zones, r.to_zones, r.src_cidrs, r.dst_cidrs, r.applications, r.action),
                         (("k8s-nodes",), ("uplink",), ("10.20.1.0/24",), ("198.51.100.2/32",), ("ping",), "allow"))
        for lab in ("ch01", "ch02", "ch03", "ch07"):
            names = [r.name for r in model(load_chapter(ROOT / lab)).firewall.rules]
            self.assertNotIn("nodes-to-public-ping", names, lab)
            self.assertEqual([n for n in names4 if n != "nodes-to-public-ping"], names, lab)

    def test_state_one_whole(self):
        out = render_fw({"lab": "sfab-ch04", "profile": "a", "state": "one"})
        root = ET.fromstring(out["bootstrap/fw/startup-config.xml"])
        vsys = root.find("devices/entry/vsys/entry")
        m = model({"lab": "sfab-ch04", "profile": "a", "state": "one"})
        names = [r.get("name") for r in vsys.findall("rulebase/security/rules/entry")]
        self.assertEqual(names, [r.name for r in m.firewall.rules])
        self.assertEqual(len(names), 24)
        for r in ("ent-dns-to-platform-dns", "inside-to-resolvers", "inside-to-ntp", "resolvers-to-auth", "auth-zone-transfer",
                  "ntp-upstream", "nts-ke-upstream", "bastion-to-services-admin", "nodes-to-registry", "csi-to-storage-api",
                  "operator-ike", "operator-to-internal-gateway", "admins-to-bastion", "bastion-to-firewall-admin", "bastion-to-bmc"):
            self.assertIn(r, names)
        self.assertFalse([r for r in names if "bastion-dns" in r], "the bastion serves no DNS and no time")
        self.assertFalse([r for r in names if r.endswith("-intrazone") or r == "inside-to-internet" or r == "uplink-to-internal-gateway"],
                         "no allow-any intrazone rule, no open egress, no public path to the internal Gateway")
        self.assertEqual(names[-1], "deny-all-log")
        for r in vsys.findall("rulebase/security/rules/entry")[:-1]:
            self.assertNotIn("any", [x.text for x in r.findall("application/member")], r.get("name"))
            self.assertNotIn("any", [x.text for x in r.findall("service/member")], r.get("name"))
            self.assertEqual(r.findtext("profile-setting/group/member"), "bp-default", r.get("name"))
        nat = [n.get("name") for n in vsys.findall("rulebase/nat/rules/entry")]
        self.assertEqual(nat, ["no-nat-public", "internet-snat"], "no destination NAT: nothing is published on the uplink")
        nn = vsys.find("rulebase/nat/rules/entry[@name='no-nat-public']")
        self.assertIsNone(nn.find("source-translation"))
        self.assertIsNone(nn.find("destination-translation"))
        sn = vsys.find("rulebase/nat/rules/entry[@name='internet-snat']")
        self.assertEqual(sn.findtext("source-translation/dynamic-ip-and-port/interface-address/interface"), "ethernet1/5")
        self.assertEqual([x.text for x in sn.findall("from/member")], ["k8s-nodes", "services"], "only the allowlisted egress is translated")
        op = vsys.find("rulebase/security/rules/entry[@name='operator-to-internal-gateway']")
        self.assertEqual([x.text for x in op.findall("from/member")], ["operator-vpn"], "the operator arrives through the tunnel")
        self.assertEqual([x.text for x in op.findall("to/member")], ["ingress"])
        self.assertEqual([x.text for x in op.findall("source/member")], ["192.0.2.0/30"])
        self.assertEqual([x.text for x in op.findall("destination/member")], ["10.20.11.200"])
        ike = vsys.find("rulebase/security/rules/entry[@name='operator-ike']")
        self.assertEqual(([x.text for x in ike.findall("from/member")], [x.text for x in ike.findall("to/member")]), (["uplink"], ["uplink"]))
        self.assertEqual([x.text for x in ike.findall("source/member")], ["192.0.2.22"], "the operator's VPN router only")
        self.assertEqual([x.text for x in ike.findall("application/member")], ["ike", "ipsec-esp", "ipsec-esp-udp"])
        adm = vsys.find("rulebase/security/rules/entry[@name='admins-to-bastion']")
        self.assertEqual([x.text for x in adm.findall("source/member")], ["admins"])
        self.assertEqual([x.text for x in vsys.findall("address-group/entry[@name='admins']/static/member")], ["ent-client", "operator-site"])
        ent = vsys.find("rulebase/security/rules/entry[@name='staff-to-users-gateway']")
        self.assertEqual([x.text for x in ent.findall("destination/member")], ["10.20.11.210"])
        self.assertEqual([x.text for x in ent.findall("application/member")], ["ssl"])
        self.assertEqual([x.text for x in ent.findall("service/member")], ["application-default"])
        reg = vsys.find("rulebase/security/rules/entry[@name='nodes-to-registry']")
        self.assertEqual(([x.text for x in reg.findall("application/member")], [x.text for x in reg.findall("service/member")]),
                         (["ssl"], ["tcp-5000"]), "a non-default port takes an explicit service")
        svcs = [s.get("name") for s in vsys.findall("service/entry")]
        self.assertEqual(svcs, ["tcp-5000", "tcp-6443", "tcp-4460"])
        up = vsys.find("zone/entry[@name='uplink']/network")
        self.assertEqual(up.findtext("zone-protection-profile"), "zp-internet")
        zp = root.find("devices/entry/network/profiles/zone-protection-profile/entry[@name='zp-internet']")
        self.assertEqual(zp.findtext("flood/tcp-syn/enable"), "yes")
        self.assertIsNotNone(zp.find("flood/tcp-syn/syn-cookies"))
        self.assertEqual(vsys.findtext("zone/entry[@name='operator-vpn']/network/layer3/member"), "tunnel.1")
        tun = root.find("devices/entry/network/interface/tunnel/units/entry[@name='tunnel.1']")
        self.assertEqual(tun.findtext("interface-management-profile"), "ping-only")
        self.assertIsNone(root.find("devices/entry/network/ike/gateway"), "the gateway, which needs the key, is set by boot")
        self.assertIsNotNone(root.find("devices/entry/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='op-ike']"))
        vpn = json.loads(out["bootstrap/fw/vpn.json"])
        self.assertEqual([x["what"] for x in vpn["steps"]], ["IKE gateway ops-gw", "IPsec tunnel ops-gw"])
        self.assertIn(vpn["steps"][0]["placeholder"], vpn["steps"][0]["element"])
        self.assertEqual(vpn["tunnels"][0]["proxy_ids"], [["ingress", "10.20.11.0/24", "192.0.2.0/30"], ["bastion", "10.20.3.0/24", "192.0.2.0/30"]])
        sysd = root.find("devices/entry/deviceconfig/system")
        self.assertEqual(sysd.findtext("dns-setting/servers/primary"), "10.20.13.21")
        self.assertEqual(sysd.findtext("dns-setting/servers/secondary"), "10.20.14.21")
        self.assertEqual(sysd.findtext("ntp-servers/primary-ntp-server/ntp-server-address"), "10.20.13.21")
        self.assertEqual(sysd.findtext("ntp-servers/secondary-ntp-server/ntp-server-address"), "10.20.14.21")
        for svc in ("dns", "ntp"):
            e = sysd.find(f"route/service/entry[@name='{svc}']/source")
            self.assertEqual((e.findtext("interface"), e.findtext("address")), ("ae1.130", "10.20.13.1/24"),
                             "out of the services interface, which carries no management profile")
        st = root.find("devices/entry/network/virtual-router/entry/routing-table/ip/static-route/entry[@name='default-uplink']")
        self.assertEqual((st.findtext("destination"), st.findtext("interface"), st.findtext("nexthop/ip-address")),
                         ("0.0.0.0/0", "ethernet1/5", "198.51.100.1"))
        ot = root.find("devices/entry/network/virtual-router/entry/routing-table/ip/static-route/entry[@name='operator-site']")
        self.assertEqual((ot.findtext("destination"), ot.findtext("interface"), ot.find("nexthop")), ("192.0.2.0/30", "tunnel.1", None))
        enf = out["bootstrap/fw/enforced.txt"]
        lines = {x for x in enf.splitlines() if x.startswith("set ")}
        vpn_lines = {x for x in lines if x.startswith(("set network ike gateway", "set network tunnel ipsec"))}
        self.assertIn("set network ike gateway ops-gw peer-address ip 192.0.2.22", vpn_lines)
        self.assertFalse([x for x in vpn_lines if "pre-shared-key" in x], "the key line is never rendered")
        self.assertEqual(lines - vpn_lines, set(xml_to_set(root)))
        self.assertNotIn("# Not in this lab:", enf)

    def test_admin_profile(self):
        out = render_fw({"lab": "sfab-ch04", "profile": "a", "state": "one"})
        root = ET.fromstring(out["bootstrap/fw/startup-config.xml"])
        dev = root.find("devices/entry")
        profiles = {e.get("name"): e for e in dev.findall("network/profiles/interface-management-profile/entry")}
        self.assertEqual(list(profiles), ["ping-only", "bastion-admin"])
        took = {}
        for e in dev.findall("network/interface/ethernet/entry"):
            if e.find("layer3/interface-management-profile") is not None:
                took[e.get("name")] = e.findtext("layer3/interface-management-profile")
        for u in dev.findall("network/interface/aggregate-ethernet/entry/layer3/units/entry"):
            took[u.get("name")] = u.findtext("interface-management-profile")
        for u in dev.findall("network/interface/tunnel/units/entry"):
            took[u.get("name")] = u.findtext("interface-management-profile")
        self.assertEqual(took, {"ethernet1/3": "ping-only", "ethernet1/4": "ping-only", "ethernet1/5": "ping-only", "ethernet1/7": "ping-only",
                                "ae1.100": "ping-only", "ae1.110": "ping-only", "ae1.200": "ping-only", "ae1.300": "bastion-admin",
                                "ae1.130": "ping-only", "ae1.131": "ping-only", "tunnel.1": "ping-only"})
        enf = out["bootstrap/fw/enforced.txt"]
        for line in ("set network profiles interface-management-profile bastion-admin https yes",
                     "set network profiles interface-management-profile bastion-admin ssh yes",
                     "set network profiles interface-management-profile bastion-admin ping yes",
                     "set network profiles interface-management-profile bastion-admin permitted-ip 10.20.3.10/32",
                     "set network interface aggregate-ethernet ae1 layer3 units ae1.300 interface-management-profile bastion-admin",
                     "set network interface ethernet ethernet1/3 layer3 interface-management-profile ping-only",
                     "set network interface ethernet ethernet1/5 layer3 interface-management-profile ping-only"):
            self.assertIn(line + "\n", enf)
        self.assertEqual({x for x in enf.splitlines() if x.startswith("set ") and not x.startswith(("set network ike gateway", "set network tunnel ipsec"))},
                         set(xml_to_set(root)))

    def test_admin_left_out_without_its_interface(self):
        # a lab whose firewall has no wire for the administrative interface renders no administrative
        # profile, and says so
        from sfab.render import panos
        m = model({"lab": "sfab-ch04", "profile": "a", "state": "one"})
        fw = m.firewall
        ifs = tuple(dataclasses.replace(i, connected=False) if i.name == "ae1.300" else i for i in fw.interfaces)
        nodes = dict(m.nodes, fw=dataclasses.replace(fw, interfaces=ifs))
        v = panos.view(dataclasses.replace(m, nodes=nodes))
        self.assertIsNone(v.admin)
        self.assertIn("admin profile bastion-admin: interface ae1.300 is not in this lab", v.omitted)
        self.assertNotIn("bastion-admin", panos.fw_xml(dataclasses.replace(m, nodes=nodes), v))

    def test_admin_validation(self):
        from sfab.model import FwAdmin
        from sfab.validate import check_firewall
        m = model({"lab": "sfab-ch04", "profile": "a", "state": "one"})
        for admin, want in ((FwAdmin("ethernet1/9", "oob-admin", ("ssh",), (), ()), "not an addressed layer 3 interface"),
                            (FwAdmin("ethernet1/3", "oob-admin", ("telnet",), (), ()), "unknown service"),
                            (FwAdmin("ethernet1/3", "ping-only", ("ssh",), (), ()), "the ping-only profile"),
                            (FwAdmin("ethernet1/3", "oob-admin", ("ssh",), ("public",), ("198.51.100.2/32",)), "nothing administrative is published")):
            fw = dataclasses.replace(m.firewall, admin=admin)
            probs = check_firewall(dataclasses.replace(m, nodes=dict(m.nodes, fw=fw)))
            self.assertTrue(any(want in p for p in probs), (want, probs))

    def test_many_step_10(self):
        ch = {"lab": "sfab-ch10", "profile": "a", "state": "many"}
        out = render_fw(ch)
        root = ET.fromstring(out["bootstrap/fw/startup-config.xml"])
        vsys = root.find("devices/entry/vsys/entry")
        nat = [n.get("name") for n in vsys.findall("rulebase/nat/rules/entry")]
        self.assertEqual(nat, ["dnat-internet-gateway", "no-nat-public", "internet-snat"])
        rules = [r.get("name") for r in vsys.findall("rulebase/security/rules/entry")]
        self.assertIn("isp-to-internet-gateway", rules)
        self.assertNotIn("enterprise-to-bastion-dns", rules)
        self.assertIn("isp", [z.get("name") for z in vsys.findall("zone/entry")])
        r = root.find("devices/entry/network/virtual-router/entry/routing-table/ip/static-route/entry[@name='isp-customers']")
        self.assertEqual(r.findtext("nexthop/ip-address"), "198.51.100.9")
        self.assertEqual(vsys.find("rulebase/nat/rules/entry[@name='dnat-internet-gateway']").findtext(
            "destination-translation/translated-address"), "10.20.11.220")

    def test_many_step_9_routes_the_isp_customers(self):
        # the route comes with the isp link in step 9 (zone isp's strict IP
        # check drops a source not routable over its arrival interface), and step 9 has no NAT or
        # rule for isp yet; step 8 has neither the interface nor the route
        out = render_fw({"lab": "sfab-ch09", "profile": "a", "state": "many"})
        root = ET.fromstring(out["bootstrap/fw/startup-config.xml"])
        names = [e.get("name") for e in root.findall("devices/entry/network/virtual-router/entry/routing-table/ip/static-route/entry")]
        self.assertEqual(names, ["default-uplink", "operator-site", "isp-customers", "discard-10", "discard-172-16", "discard-192-168"])
        text = out["bootstrap/fw/enforced.txt"]
        self.assertNotIn("dnat-internet-gateway", text)
        self.assertNotIn("isp-to-internet-gateway", text)
        out8 = render_fw({"lab": "sfab-ch08", "profile": "a", "state": "many"})
        self.assertNotIn("isp-customers", out8["bootstrap/fw/enforced.txt"])
        self.assertNotIn("ethernet1/6", out8["bootstrap/fw/enforced.txt"])

    def test_many_step_10_publishes_the_firewalls_own_isp_address(self):
        # the DNAT from isp to isp on 198.51.100.10 tcp/443 to gw-inet's VIP, first in the NAT
        # rulebase; the security rule on the pre-NAT address and the post-NAT zone as the 24th rule, then
        # deny-all-log as the 25th rule
        text = render_fw({"lab": "sfab-ch10", "profile": "a", "state": "many"})["bootstrap/fw/enforced.txt"]
        sec = list(dict.fromkeys(re.findall(r"^set rulebase security rules (\S+) ", text, re.M)))
        nat = list(dict.fromkeys(re.findall(r"^set rulebase nat rules (\S+) ", text, re.M)))
        self.assertEqual(sec[-2:], ["isp-to-internet-gateway", "deny-all-log"])
        self.assertEqual(len(sec), 25)
        self.assertEqual(nat, ["dnat-internet-gateway", "no-nat-public", "internet-snat"])
        for ln in ("set rulebase nat rules dnat-internet-gateway from isp", "set rulebase nat rules dnat-internet-gateway to isp",
                   "set rulebase nat rules dnat-internet-gateway destination 198.51.100.10",
                   "set rulebase nat rules dnat-internet-gateway service tcp-443",
                   "set rulebase nat rules dnat-internet-gateway destination-translation translated-address 10.20.11.220",
                   "set rulebase security rules isp-to-internet-gateway to ingress",
                   "set rulebase security rules isp-to-internet-gateway destination 198.51.100.10",
                   "set rulebase security rules isp-to-internet-gateway application ssl"):
            self.assertIn(ln + "\n", text)

    def test_no_firewall_in_slice(self):
        out = render_fw({"lab": "sfab-ch05", "profile": "a", "state": "one", "slice": {"nodes": ["rail", "k8s-gpu1", "k8s-gpu2"]},
                         "features": {"k8s": False, "serving": False, "storage_setup": False}})
        self.assertEqual(out, {})

    def test_partial_slice_keeps_what_the_lab_carries(self):
        # The pair, the firewall and the services hosts: their rules appear, the bastion's and the
        # enterprise's do not.
        ch = {"lab": "sfab-ch03", "profile": "a", "state": "one", "slice": {"nodes": ["fe", "fw", "services"]},
              "features": {"k8s": False, "serving": False, "storage_setup": False}}
        out = render_fw(ch)
        root = ET.fromstring(out["bootstrap/fw/startup-config.xml"])
        rules = [r.get("name") for r in root.findall("devices/entry/vsys/entry/rulebase/security/rules/entry")]
        for r in ("resolvers-to-auth", "auth-zone-transfer", "ntp-upstream"):
            self.assertIn(r, rules)
        for r in ("bastion-to-data", "ent-dns-to-platform-dns", "staff-to-users-gateway"):
            self.assertNotIn(r, rules)
        self.assertEqual(rules[-1], "deny-all-log")
        self.assertEqual(root.findtext("devices/entry/deviceconfig/system/dns-setting/servers/primary"), "10.20.13.21")

    def test_rule_helpers_match_the_file(self):
        from sfab.render import panos

        m = model({"lab": "sfab-ch04", "profile": "a", "state": "one"})
        v = panos.view(m)
        root = ET.fromstring(panos.fw_xml(m, v))
        for r in v.rules:
            want = ET.tostring(ET.fromstring(panos.xml(panos.rule(r))))
            got = root.find(f"devices/entry/vsys/entry/rulebase/security/rules/entry[@name='{r.name}']")
            self.assertEqual(_canon(got), _canon(ET.fromstring(want)), r.name)
        for n in v.nat:
            got = root.find(f"devices/entry/vsys/entry/rulebase/nat/rules/entry[@name='{n.name}']")
            self.assertEqual(_canon(got), _canon(ET.fromstring(panos.xml(panos.nat_rule(n)))), n.name)

    def test_config_version(self):
        from sfab.render import panos

        self.assertEqual(panos.config_version("vrnetlab/paloalto_pa-vm:12.1.2"), ("12.1.0", "12.1.2"))
        self.assertEqual(panos.config_version("localhost:5000/pa-vm:11.2.4"), ("11.2.0", "11.2.4"))
        with self.assertRaises(ValueError):
            panos.config_version("vrnetlab/paloalto_pa-vm:latest")


def _canon(e: ET.Element) -> str:
    def strip(x):
        x.text = (x.text or "").strip() or None
        x.tail = None
        for c in x:
            strip(c)
        return x

    return ET.tostring(strip(e), encoding="unicode")


# --------------------------------------------------------------------------------------------
# A small stand-in for the PAN-OS XML API


class FakePan:
    def __init__(self, password=PASSWORD, key=KEY, busy_commits=1, drop_polls=1, autocommit_polls=1, jumbo="on",
                 no_changes=False):
        self.password, self.key = password, key
        self.busy_commits, self.drop_polls, self.autocommit_polls = busy_commits, drop_polls, autocommit_polls
        self.jumbo, self.no_changes = jumbo, no_changes
        self.rulebase = None  # the <rulebase> text a config show of the rulebase returns
        self.down = 0
        self.calls: list[tuple] = []
        self.violations: list[str] = []
        self.imported: dict = {}
        self.lock = threading.Lock()
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                fake.handle(self)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

    @staticmethod
    def reply(h, body: str, code: int = 200):
        b = body.encode()
        h.send_response(code)
        h.send_header("Content-Type", "application/xml")
        h.send_header("Content-Length", str(len(b)))
        h.end_headers()
        h.wfile.write(b)

    def handle(self, h):
        with self.lock:
            self._handle(h)

    def _handle(self, h):
        q = urllib.parse.urlsplit(h.path).query
        raw = h.rfile.read(int(h.headers.get("Content-Length") or 0))
        ctype = h.headers.get("Content-Type") or ""
        if self.password in q or self.key in q:
            self.violations.append(f"secret in the query string: {h.path}")
        fields = dict(urllib.parse.parse_qsl(q))
        if ctype.startswith("multipart/"):
            m = re.search(rb'filename="([^"]+)"\r\n[^\r]*\r\n\r\n(.*)\r\n--', raw, re.S)
            fields["file"] = (m.group(1).decode(), m.group(2)) if m else None
        else:
            fields.update(dict(urllib.parse.parse_qsl(raw.decode())))
        if "key" in fields:
            self.violations.append("a key sent as a parameter")
        typ = fields.get("type")
        if self.down > 0:
            self.down -= 1
            self.calls.append(("dropped", typ))
            h.close_connection = True
            return
        if typ == "keygen":
            self.calls.append(("keygen",))
            if fields.get("password") == self.password:
                return self.reply(h, f'<response status="success"><result><key>{self.key}</key></result></response>')
            return self.reply(h, '<response status="error" code="403"><result><msg>Invalid Credential</msg></result></response>', 403)
        if self.password.encode() in raw:
            self.violations.append(f"the password outside keygen ({typ})")
        if h.headers.get("X-PAN-KEY") != self.key:
            self.calls.append(("unkeyed", typ))
            return self.reply(h, '<response status="error" code="403"><result><msg>Invalid key</msg></result></response>', 403)
        if typ == "import":
            name, data = fields.get("file") or ("?", b"")
            self.imported[name] = data
            self.calls.append(("import", fields.get("category"), name))
            return self.reply(h, '<response status="success"><msg>imported</msg></response>')
        if typ == "commit":
            self.calls.append(("commit",))
            if self.busy_commits > 0:
                self.busy_commits -= 1
                return self.reply(h, '<response status="error"><msg><line>Commit job was not queued since auto-commit not '
                                     'yet finished successfully.</line></msg></response>')
            if self.no_changes:
                return self.reply(h, '<response status="success" code="19"><msg>There are no changes to commit.</msg></response>')
            return self.reply(h, '<response status="success" code="19"><result><msg><line>Commit job enqueued with jobid 11'
                                 '</line></msg><job>11</job></result></response>')
        if typ == "config":
            self.calls.append(("config", fields.get("action"), fields.get("xpath"), fields.get("element"), fields.get("where"),
                               fields.get("dst")))
            if fields.get("action") == "show" and str(fields.get("xpath")).endswith("/rulebase") and self.rulebase:
                return self.reply(h, f'<response status="success"><result>{self.rulebase}</result></response>')
            if fields.get("action") in ("get", "show"):
                return self.reply(h, '<response status="success"><result><entry name="admin"><phash>$5$notshown</phash>'
                                     '</entry></result></response>')
            return self.reply(h, '<response status="success" code="20"><msg>command succeeded</msg></response>')
        if typ == "op":
            cmd = fields.get("cmd", "")
            self.calls.append(("op", cmd))
            if cmd.startswith("<show><jobs><all>"):
                if self.autocommit_polls > 0:
                    self.autocommit_polls -= 1
                    return self.reply(h, '<response status="success"><result><job><id>1</id><type>AutoCom</type>'
                                         '<status>ACT</status></job></result></response>')
                return self.reply(h, '<response status="success"><result><job><id>1</id><type>AutoCom</type>'
                                     '<status>FIN</status><result>OK</result></job></result></response>')
            if cmd.startswith("<show><system><setting><jumbo-frame>"):
                return self.reply(h, f'<response status="success"><result>Device Jumbo-Frame mode:   {self.jumbo}\n'
                                     'Current device mtu size: 1500</result></response>')
            if cmd.startswith("<set><system><setting><jumbo-frame>on"):
                self.jumbo = "on"
                return self.reply(h, '<response status="success"><result>Device is now in Jumbo-Frame mode, please reboot'
                                     '</result></response>')
            if cmd.startswith("<request><restart><system>"):
                self.down = 1
                return self.reply(h, '<response status="success"><result>restarting</result></response>')
            if cmd.startswith("<show><system><info>"):
                return self.reply(h, '<response status="success"><result><system><hostname>fw</hostname></system></result></response>')
            if cmd.startswith("<load><config><partial>"):
                return self.reply(h, '<response status="success"><result><msg><line>Config loaded</line></msg></result></response>')
            if cmd.startswith("<validate><full>"):
                return self.reply(h, '<response status="success" code="19"><result><msg><line>Validate job enqueued with '
                                     'jobid 10</line></msg><job>10</job></result></response>')
            m = re.match(r"<show><jobs><id>(\d+)</id>", cmd)
            if m:
                jid = m.group(1)
                if jid == "11" and self.drop_polls > 0:
                    self.drop_polls -= 1
                    h.close_connection = True
                    return
                return self.reply(h, f'<response status="success"><result><job><id>{jid}</id><status>FIN</status>'
                                     '<result>OK</result><details><line>Configuration committed successfully</line></details>'
                                     '</job></result></response>')
            return self.reply(h, '<response status="success"><result>ok</result></response>')
        self.calls.append(("unknown", typ))
        return self.reply(h, '<response status="error"><msg>unknown request</msg></response>', 400)

    def ops(self, prefix: str) -> list:
        return [c for c in self.calls if c[0] == "op" and c[1].startswith(prefix)]


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class TestFwStartup(unittest.TestCase):
    def setUp(self):
        self.mod = load_fw_startup()
        self.mod._SECRETS.clear()
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-fwtest-"))
        self.cfg = self.tmp / "startup-config.xml"
        self.cfg.write_text(render_fw(m1_chapter())["bootstrap/fw/startup-config.xml"], encoding="utf-8")
        self.env = mock.patch.dict(os.environ, {"PASSWORD": PASSWORD, "USERNAME": "admin"})
        self.env.start()
        for k in ("SFAB_FW_PASSWORD", "SFAB_FW_USER"):
            os.environ.pop(k, None)

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_main(self, fake, *extra):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = self.mod.main(["--api", fake.url, "--config", str(self.cfg), "--marker", str(self.tmp / "marker"), *extra])
        return rc, buf.getvalue()

    def test_full_flow_with_the_race_and_a_restarting_web_server(self):
        with FakePan() as fake:
            rc, out = self.run_main(fake)
        self.assertEqual(rc, 0, out)
        self.assertEqual(fake.violations, [])
        self.assertNotIn(PASSWORD, out)
        self.assertNotIn(KEY, out)
        self.assertTrue((self.tmp / "marker").is_file())
        self.assertIn("result OK", (self.tmp / "marker").read_text())
        self.assertEqual(fake.imported, {"sfab-startup-config.xml": self.cfg.read_bytes()})
        loads = [re.search(r"<mode>(\w+)</mode><from-xpath>([^<]+)</from-xpath>", c[1]).groups() for c in fake.ops("<load><config>")]
        dev = "/config/devices/entry[@name='localhost.localdomain']"
        self.assertEqual(loads, [("merge", f"{dev}/deviceconfig"), ("merge", f"{dev}/network"), ("merge", f"{dev}/vsys"),
                                 ("replace", f"{dev}/vsys/entry[@name='vsys1']/rulebase")])
        self.assertEqual(len(fake.ops("<validate>")), 1)
        self.assertEqual(len([c for c in fake.calls if c[0] == "commit"]), 2, "one busy answer, then queued")
        self.assertIn("polling on", out)
        self.assertEqual(fake.ops("<request><restart>"), [], "the box was already in jumbo-frame mode")
        order = [c[0] if c[0] != "op" else c[1][:16] for c in fake.calls]
        self.assertLess(order.index("import"), order.index("<validate><full>"))

    def test_jumbo_off_restarts_first(self):
        with FakePan(jumbo="off", busy_commits=0, drop_polls=0) as fake:
            rc, out = self.run_main(fake)
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(fake.ops("<set><system><setting><jumbo-frame>on")), 1)
        self.assertEqual(len(fake.ops("<request><restart>")), 1)
        restart = [i for i, c in enumerate(fake.calls) if c[0] == "op" and c[1].startswith("<request><restart>")][0]
        imp = [i for i, c in enumerate(fake.calls) if c[0] == "import"][0]
        self.assertLess(restart, imp)

    def test_nothing_to_commit_is_success(self):
        with FakePan(busy_commits=0, no_changes=True) as fake:
            rc, out = self.run_main(fake)
        self.assertEqual(rc, 0, out)
        self.assertIn("no changes to commit", out)

    def test_refused_credentials_exit_5(self):
        os.environ["PASSWORD"] = "wrong-password-value"
        with FakePan() as fake:
            rc, out = self.run_main(fake)
        self.assertEqual(rc, 5, out)
        self.assertNotIn("wrong-password-value", out)
        self.assertEqual(fake.imported, {})

    def test_merge_only(self):
        with FakePan(busy_commits=0, drop_polls=0) as fake:
            rc, out = self.run_main(fake, "--rulebase", "merge", "--jumbo", "skip")
        self.assertEqual(rc, 0, out)
        self.assertEqual([c for c in fake.ops("<load><config>") if "<mode>replace" in c[1]], [])
        self.assertEqual(fake.ops("<show><system><setting>"), [])

    def test_refuses_mgt_config_and_non_config_files(self):
        bad = self.tmp / "bad.xml"
        bad.write_text('<config><mgt-config/><devices><entry name="localhost.localdomain"/></devices></config>')
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf), contextlib.redirect_stdout(buf):
            self.assertEqual(self.mod.main(["--api", "http://127.0.0.1:9", "--config", str(bad)]), 2)
            bad.write_text("<other/>")
            self.assertEqual(self.mod.main(["--api", "http://127.0.0.1:9", "--config", str(bad)]), 2)

    def test_expect_sha256(self):
        import hashlib

        good = hashlib.sha256(self.cfg.read_bytes()).hexdigest()
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            self.assertEqual(self.mod.main(["--plan", "--config", str(self.cfg), "--expect-sha256", good]), 0)
            self.assertEqual(self.mod.main(["--plan", "--config", str(self.cfg), "--expect-sha256", "0" * 64]), 2)
        self.assertIn("is not the rendered file", buf.getvalue())

    def test_plan(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.mod.main(["--plan", "--config", str(self.cfg)])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("merge: deviceconfig, network, vsys", out)
        self.assertIn("replace: vsys1 rulebase", out)
        self.assertIn("jumbo-frame: asked for", out)
        self.assertIn("marker: /tmp/lab-startup-committed", out)

    def fake_docker(self) -> str:
        bin_ = standins.make_bin(self.tmp / "bin", {"docker": FAKE_DOCKER})
        standins.check(dict(os.environ, PATH=standins.path_with(bin_)), bin_, ("docker",))
        return str(bin_ / "docker")

    def test_host_credentials_are_the_containers_launcher_arguments(self):
        # From the host the login is the one containerlab gave the firewall container's launcher
        # (the paloalto_panos kind's default), read with docker inspect; SFAB_FW_PASSWORD, when the
        # operator exports it, overrides it. No file is read: --env-file is gone.
        docker = self.fake_docker()
        os.environ.pop("PASSWORD", None)
        os.environ.pop("USERNAME", None)
        cfg = launcher_config(self.tmp / "config.json", password="kind-default")
        with mock.patch.dict(os.environ, {"FAKE_DOCKER_CONFIG": str(cfg)}):
            self.assertEqual(self.mod.credentials(False, "sfab-m1-fw", docker=docker), ("admin", "kind-default"))
            with mock.patch.dict(os.environ, {"SFAB_FW_PASSWORD": "override"}):
                self.assertEqual(self.mod.credentials(False, "sfab-m1-fw", docker=docker), ("admin", "override"))
            launcher_config(cfg, password=None, env_password="from-env-var")
            self.assertEqual(self.mod.credentials(False, "sfab-m1-fw", docker=docker), ("admin", "from-env-var"))
            launcher_config(cfg, password=None)
            with self.assertRaises(self.mod.NoCredentials):
                self.mod.credentials(False, "sfab-m1-fw", docker=docker)
            with self.assertRaises(self.mod.NoCredentials):
                self.mod.credentials(False, "sfab-m1-other", docker=docker)
            with self.assertRaises(ValueError):
                self.mod.credentials(False, "--format", docker=docker)
        with self.assertRaises(self.mod.NoCredentials):
            self.mod.credentials(False, None)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.mod.parse_args(["--env-file", str(self.tmp / "secrets.env")])

    def test_host_run_with_container(self):
        # The whole run from the host with --container, the password never printed
        docker_dir = os.path.dirname(self.fake_docker())
        os.environ.pop("PASSWORD", None)
        cfg = launcher_config(self.tmp / "config.json")
        env = {"PATH": standins.path_with(Path(docker_dir)), "FAKE_DOCKER_CONFIG": str(cfg)}
        with mock.patch.dict(os.environ, env), mock.patch.object(self.mod, "launcher_args", return_value=(None, None)):
            with FakePan(busy_commits=0, drop_polls=0) as fake:
                rc, out = self.run_main(fake, "--container", "sfab-m1-fw")
            self.assertEqual(rc, 0, out)
            self.assertNotIn(PASSWORD, out)
            with FakePan(busy_commits=0, drop_polls=0) as fake:
                rc, out = self.run_main(fake)
            self.assertEqual(rc, 2, out)
            self.assertIn("pass --container NAME", out)
            self.assertEqual(fake.calls, [])

    def test_container_credentials_are_the_launchers(self):
        # Inside the container the launcher's own --username and --password win over the env:
        # containerlab's paloalto_panos kind passes its defaults there and the launcher ignores env.
        # An exported SFAB_FW_PASSWORD is the operator's override and comes first.
        cmd = self.tmp / "cmdline"
        cmd.write_bytes(b"/usr/bin/python3\0/launch.py\0--username\0admin\0--password\0kind-default\0--hostname\0fw\0")
        with mock.patch.dict(os.environ, {"USERNAME": "admin", "PASSWORD": "stale"}):
            self.assertEqual(self.mod.credentials(True, None, str(cmd)), ("admin", "kind-default"))
            self.assertEqual(self.mod.credentials(True, None, str(self.tmp / "absent")), ("admin", "stale"))
            with mock.patch.dict(os.environ, {"SFAB_FW_PASSWORD": "override"}):
                self.assertEqual(self.mod.credentials(True, None, str(cmd)), ("admin", "override"))
        with mock.patch.dict(os.environ, {"SFAB_FW_PASSWORD": "host-side"}):
            self.assertEqual(self.mod.credentials(False, None, str(cmd)), ("admin", "host-side"))

    def test_redact(self):
        self.mod.remember("s3cret-pw", "K-123")
        s = self.mod.redact("https://x/api/?type=op&key=K-123 X-PAN-KEY: K-123 <key>K-123</key> password=s3cret-pw")
        self.assertNotIn("K-123", s)
        self.assertNotIn("s3cret-pw", s)


# --------------------------------------------------------------------------------------------
# The shell scripts, against the same fake API and fake ssh


def _write_lab(tmp: Path, secrets: str | None = None) -> Path:
    from sfab.render import inventory

    lab = tmp / "lab"
    (lab / "gen").mkdir(parents=True)
    (lab / "gen" / "inventory.json").write_text(inventory.dumps(inventory.inventory(model(m1_chapter()))), encoding="utf-8")
    out = render_fw(m1_chapter())
    (lab / "bootstrap" / "fw").mkdir(parents=True)
    (lab / "bootstrap" / "fw" / "enforced.txt").write_text(out["bootstrap/fw/enforced.txt"], encoding="utf-8")
    if secrets is not None:
        (lab / "state").mkdir()
        (lab / "state" / "secrets.env").write_text(secrets, encoding="utf-8")
        os.chmod(lab / "state" / "secrets.env", 0o600)
    return lab


def _script_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SFAB_", "EVID", "PANOS_")) and k not in ("PASSWORD", "USERNAME")}
    env.update(extra)
    return env


@unittest.skipUnless(HAVE_YAML and shutil.which("bash") and shutil.which("curl"), "needs PyYAML, bash and curl")
class TestFwApi(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-fwapi-"))
        self.lab = _write_lab(self.tmp)
        # curl stays real (it talks to FakePan on localhost); sshpass, ssh and docker are
        # stand-ins, so the container credential source never reads a real firewall's password:
        # the stand-in docker shows a launcher whose --password is the fake API's.
        self.bin = standins.make_bin(self.tmp / "bin", {"docker": FAKE_DOCKER})
        self.path = standins.path_with(self.bin)
        self.cfg = launcher_config(self.tmp / "config.json")
        standins.check(_script_env(PATH=self.path), self.bin)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def api(self, fake, *args, lab=None, **env):
        e = _script_env(**{"SFAB_FW_API": f"{fake.url}/api/", "FWA_COMMIT_PAUSE": "0", "FWA_POLL_PAUSE": "0",
                           "PATH": self.path, "FAKE_DOCKER_CONFIG": str(self.cfg), **env})
        return subprocess.run(["bash", str(FW_DIR / "fw-api.sh"), "--lab", str(lab or self.lab), *args], env=e,
                              capture_output=True, text=True, timeout=standins.SCRIPT_TIMEOUT_S)

    def test_set_file_reads_the_element_from_a_file(self):
        # a gateway with its pre-shared key goes through a 0600 file, never on the command line
        xp = "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
        el = Path(self.tmp) / "gw.xml"
        el.write_text('<entry name="ops-gw"><authentication><pre-shared-key><key>NotARealKey0123</key></pre-shared-key></authentication></entry>')
        os.chmod(el, 0o600)
        with FakePan(drop_polls=0) as fake:
            r = self.api(fake, "set-file", xp, str(el))
            bad = self.api(fake, "set-file", xp, str(Path(self.tmp) / "missing.xml"))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("success", r.stdout)
        self.assertNotIn("NotARealKey0123", r.stdout + r.stderr)
        cfg = [c for c in fake.calls if c[0] == "config"]
        self.assertEqual(cfg[0][1:3], ("set", xp))
        self.assertIn("NotARealKey0123", cfg[0][3], "the element the firewall got is the file's")
        self.assertEqual(bad.returncode, 2)

    def test_set_move_commit_get(self):
        xp = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/security/rules"
        with FakePan(drop_polls=0) as fake:
            r1 = self.api(fake, "set", xp, '<entry name="x"><action>allow</action></entry>', SFAB_FW_PASSWORD="wrong")
            r2 = self.api(fake, "move", f"{xp}/entry[@name='x']")
            r3 = self.api(fake, "commit", "break 4a")
            r4 = self.api(fake, "get", "/config/mgt-config")
        for r in (r1, r2, r3, r4):
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn(PASSWORD, r.stdout + r.stderr)
            self.assertNotIn(KEY, r.stdout + r.stderr)
        self.assertEqual(fake.violations, [])
        self.assertIn("success", r1.stdout)
        cfg = [c for c in fake.calls if c[0] == "config"]
        self.assertEqual(cfg[0][1:4], ("set", xp, '<entry name="x"><action>allow</action></entry>'))
        self.assertEqual(cfg[1][1], "move")
        self.assertEqual(cfg[1][4:], ("before", "deny-all-log"))
        self.assertIn("commit job 11: OK", r3.stdout)
        self.assertIn("not queued yet", r3.stdout)
        self.assertIn("<phash>hidden</phash>", r4.stdout)
        self.assertNotIn("notshown", r4.stdout)
        self.assertEqual([c for c in fake.calls if c[0] == "unkeyed"], [])

    def test_order(self):
        xml = (self.lab / "bootstrap" / "fw" / "startup-config.xml")
        xml.write_text(render_fw(m1_chapter())["bootstrap/fw/startup-config.xml"], encoding="utf-8")
        rb = ET.fromstring(xml.read_text()).find("devices/entry/vsys/entry/rulebase")
        with FakePan() as fake:
            fake.rulebase = ET.tostring(rb, encoding="unicode")
            ok = self.api(fake, "order")
            sec = rb.find("security/rules")
            last = sec[-1]
            sec.remove(last)
            sec.insert(0, last)
            fake.rulebase = ET.tostring(rb, encoding="unicode")
            bad = self.api(fake, "order")
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("order: security 5 rules as rendered", ok.stdout)
        self.assertIn("order: nat 0 rules as rendered", ok.stdout)
        self.assertEqual(bad.returncode, 1, bad.stdout + bad.stderr)
        self.assertIn("order: security differs; rendered: bastion-to-bmc", bad.stdout)

    def test_no_credentials_taken_exit_5(self):
        op = "<show><system><info></info></system></show>"
        launcher_config(self.cfg, password="not-the-api-password")
        with FakePan() as fake:
            r = self.api(fake, "op", op, SFAB_FW_PASSWORD="nope")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertNotIn("not-the-api-password", r.stdout + r.stderr)

    def test_state_env_password_is_never_read(self):
        # the generated firewall credentials are gone: a state/secrets.env holding the right
        # password is never read, and with no container to read the launcher from nothing is taken
        lab = _write_lab(self.tmp / "b", secrets=f"SFAB_FW_USER=admin\nSFAB_FW_PASSWORD={PASSWORD}\n")
        with FakePan() as fake:
            r = self.api(fake, "op", "<show><system><info></info></system></show>", lab=lab, FAKE_DOCKER_CONFIG="")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("the container's launcher arguments", r.stderr)
        self.assertNotIn("secrets.env", r.stdout + r.stderr)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)
        self.assertEqual(fake.calls, [], "no source held a password, so nothing was sent")

    def test_usage(self):
        r = subprocess.run(["bash", str(FW_DIR / "fw-api.sh"), "set", "relative/xpath", "<x/>"], env=_script_env(PATH=self.path),
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)


FAKE_SSHPASS = """#!/usr/bin/env bash
[ "$1" = "-e" ] || exit 3
shift
[ "${SSHPASS:-}" = "$FAKE_GOOD_PASS" ] || exit 5
exec "$@"
"""

FAKE_SSH = """#!/usr/bin/env python3
import os, sys
w = sys.stdout.write
w("Last login: Tue Oct 13 10:00:00 2026 from 172.21.40.1\\r\\n")
w("Number of failed attempts since last successful login: 0\\r\\n\\r\\n")
mode = ">"
for line in sys.stdin:
    cmd = line.rstrip("\\n")
    w(f"admin@fw{mode} {cmd}\\r\\n")
    if cmd == "configure":
        mode = "#"
        w("Entering configuration mode\\r\\n")
    elif cmd == "exit":
        if mode == "#":
            mode = ">"
            w("Exiting configuration mode\\r\\n")
        else:
            break
    elif cmd == "show" and mode == "#":
        w(open(os.environ["FAKE_SET_FILE"]).read().replace("\\n", "\\r\\n"))
    elif cmd == "show system info":
        w("\\r\\nhostname: fw\\r\\nsw-version: 12.1.2\\r\\n\\r\\n")
"""

@unittest.skipUnless(HAVE_YAML and shutil.which("bash"), "needs PyYAML and bash")
class TestPanosSh(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-panos-"))
        # sshpass, ssh and docker are all stand-ins: nothing here may open a real session.
        self.bin = standins.make_bin(self.tmp / "bin", {"sshpass": FAKE_SSHPASS, "ssh": FAKE_SSH, "docker": FAKE_DOCKER})
        standins.check(_script_env(PATH=standins.path_with(self.bin)), self.bin)
        self.lab = _write_lab(self.tmp)
        # the firewall container as docker inspect shows it: the launcher's --password is the login
        self.cfg = launcher_config(self.tmp / "config.json")
        enforced = (self.lab / "bootstrap" / "fw" / "enforced.txt").read_text()
        lines = [x for x in enforced.splitlines() if x.startswith("set ")]
        # PAN-OS prints address entries with a trailing space, and more than the render holds.
        shown = [x + " " if " ip " in x else x for x in lines]
        shown += ["set mgt-config users admin phash $5$notshown", "set deviceconfig setting config rematch yes"]
        self.full = self.tmp / "full.set"
        self.full.write_text("\n".join(shown) + "\n")
        self.short = self.tmp / "short.set"
        self.short.write_text("\n".join(shown[1:]) + "\n")
        self.missing = lines[0]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def sh(self, *args, set_file=None, **env):
        base = {"PATH": standins.path_with(self.bin), "FAKE_GOOD_PASS": PASSWORD, "FAKE_DOCKER_CONFIG": str(self.cfg),
                "FAKE_SET_FILE": str(set_file or self.full), "PANOS_PAUSE": "0", **standins.SESSION_ENV}
        e = _script_env(**{**base, **env})
        return subprocess.run(["bash", str(FW_DIR / "panos.sh"), "--lab", str(self.lab), *args], env=e,
                              capture_output=True, text=True, timeout=standins.SCRIPT_TIMEOUT_S)

    def test_cli_output_is_clean(self):
        r = self.sh("cli", "show system info", SFAB_FW_PASSWORD="wrong-first")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip().splitlines(), ["hostname: fw", "sw-version: 12.1.2"])
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)

    def test_session_keeps_prompts(self):
        r = self.sh("session", "show system info")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("admin@fw> show system info", r.stdout)
        self.assertNotIn("\r", r.stdout)

    def test_guards(self):
        for cmd in ("show log traffic direction equal backward", "configure", "commit", "show interface ?"):
            r = self.sh("cli", cmd)
            self.assertEqual(r.returncode, 2, cmd)
            self.assertIn("refusing", r.stderr)
        r = self.sh("cli", "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_running_set_hides_secrets(self):
        r = self.sh("running-set")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("set mgt-config users admin phash <hidden>", r.stdout)
        self.assertNotIn("notshown", r.stdout)
        self.assertNotIn("set cli ", r.stdout)
        self.assertTrue(all(x.startswith("set ") for x in r.stdout.splitlines()))

    def test_enforced_pass_and_fail(self):
        r = self.sh("enforced")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        n = len([x for x in (self.lab / "bootstrap/fw/enforced.txt").read_text().splitlines() if x.startswith("set ")])
        self.assertIn(f"enforced: {n} of {n} lines present (read 1)", r.stdout)
        r = self.sh("enforced", set_file=self.short, PANOS_TRIES="2")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("after 2 reads; missing:", r.stdout)
        self.assertIn(self.missing, r.stdout)

    def test_login_names_the_source_and_refusal_is_5(self):
        # a refused override falls through to the launcher's own login
        r = self.sh("login", SFAB_FW_PASSWORD="wrong-first")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("'container' credential source", r.stdout)
        r = self.sh("login")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("'container' credential source", r.stdout)
        # an override the firewall takes is used first
        r = self.sh("login", SFAB_FW_PASSWORD=PASSWORD, FAKE_DOCKER_CONFIG="")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("'env' credential source", r.stdout)
        r = self.sh("login", FAKE_GOOD_PASS="nothing-matches")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)

    def test_container_source_reads_the_launcher_first(self):
        # the launcher's --password wins over a PASSWORD in the container's environment, which is
        # read only when the command line has none (as lib.sh's _creds and session.sh read it)
        launcher_config(self.cfg, password=PASSWORD, env_password="stale-env-value")
        r = self.sh("cli", "show system info")
        self.assertEqual(r.returncode, 0, r.stderr)
        launcher_config(self.cfg, password=None, env_password=PASSWORD)
        r = self.sh("login")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("'container' credential source", r.stdout)
        launcher_config(self.cfg, password="kind-default-value", env_password=PASSWORD)
        r = self.sh("login")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        for v in (PASSWORD, "kind-default-value", "stale-env-value"):
            self.assertNotIn(v, r.stdout + r.stderr)

    def test_state_env_password_is_never_read(self):
        # a state/secrets.env with the right SFAB_FW_PASSWORD is never read
        lab = _write_lab(self.tmp / "b", secrets=f"SFAB_FW_USER=admin\nSFAB_FW_PASSWORD={PASSWORD}\n")
        e = _script_env(PATH=standins.path_with(self.bin), FAKE_GOOD_PASS=PASSWORD, FAKE_DOCKER_CONFIG="",
                        FAKE_SET_FILE=str(self.full), **standins.SESSION_ENV)
        r = subprocess.run(["bash", str(FW_DIR / "panos.sh"), "--lab", str(lab), "login"], env=e,
                           capture_output=True, text=True, timeout=standins.SCRIPT_TIMEOUT_S)
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("the container's launcher arguments", r.stderr)
        self.assertNotIn("secrets.env", r.stderr)
        self.assertNotIn(PASSWORD, r.stdout + r.stderr)

    def test_transcript(self):
        ev = self.tmp / "commands.txt"
        r = self.sh("cli", "show system info", EVID=str(ev))
        self.assertEqual(r.returncode, 0, r.stderr)
        t = ev.read_text()
        self.assertRegex(t.splitlines()[0], r"^### \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ fw panos-cli$")
        self.assertIn("admin@fw> show system info", t)
        self.assertNotIn("Last login", t)
        ev.unlink()
        r = self.sh("cli", "show system info", EVID=str(ev), EVID_OFF="1")
        self.assertFalse(ev.exists())


class TestScriptsLint(unittest.TestCase):
    def test_bash_syntax_and_prose(self):
        for name in ("fw-api.sh", "panos.sh"):
            p = FW_DIR / name
            if shutil.which("bash"):
                r = subprocess.run(["bash", "-n", str(p)], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, r.stderr)
            t = p.read_text()
            self.assertTrue(t.startswith("#!/usr/bin/env bash\n"))
            self.assertTrue(os.access(p, os.X_OK), f"{name} is not executable")
        for p in (FW_DIR / "fw-api.sh", FW_DIR / "panos.sh", FW_DIR / "fw-startup.py", ROOT / "common/sfab/render/panos.py",
                  Path(__file__)):
            t = p.read_text()
            self.assertNotIn("\u2014", t, p.name)
            self.assertNotIn("\u2013", t, p.name)

    def test_fw_startup_is_stdlib_only(self):
        t = (FW_DIR / "fw-startup.py").read_text()
        for mod in ("requests", "urllib3", "yaml"):
            self.assertNotRegex(t, rf"(?m)^\s*(import|from) {mod}\b")
        r = subprocess.run([sys.executable, "-I", str(FW_DIR / "fw-startup.py"), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
