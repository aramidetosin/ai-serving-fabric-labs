"""Switch and topology renderer tests (FRAMEWORK.md sections 2.2 to 2.4 and 3.3).

- Golden renders of dev/m1: every KLISH startup file, gen/expect, gen/klish-normalize.json,
  topo.clab.yml and gen/clab-state.json, byte for byte.
- Every line the KLISH renderer emits is a form KLISH accepted on SONiC 4.6.0.
- The KLISH order of an MCLAG member, and the full A/one port plan.
- Every rejection of the KLISH lint.
- Parity against running configurations printed the way the switch prints them, the
  normalization rows, and the replay blocks.
- The topology: names, management addresses, kinds, passthrough, NUM_NICS, binds, links, no
  secrets, startup-delay waves.
- session.sh and replay.sh against stand-ins for sshpass, ssh and docker (standins.py), so
  no test opens a real session.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_switches -v
After a deliberate change, refresh the golden files with SFAB_UPDATE_GOLDEN=1 and review the diff.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sfab import ports
from sfab.tests import standins
from sfab import klish_lint as KL
from sfab.render import Context, RenderError
from sfab.render import clab, expect, klish

ROOT = Path(__file__).resolve().parents[3]
GOLDEN = Path(__file__).resolve().parent / "golden" / "m1"
PARITY = ROOT / "common" / "klish" / "parity.py"
SESSION = ROOT / "common" / "klish" / "session.sh"
REPLAY = ROOT / "common" / "klish" / "replay.sh"

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

sys.path.insert(0, str(ROOT / "common" / "klish"))
import parity  # noqa: E402


def _spec():
    from sfab.spec import load  # noqa: PLC0415

    return load(ROOT)


def _select(chapter):
    from sfab.spec import select  # noqa: PLC0415

    spec = _spec()
    return spec, select(spec, chapter)


def _ctx(spec, labdir: Path, outdir: Path | None = None) -> Context:
    return Context(outdir=outdir or labdir, labdir=labdir, root=ROOT, spec=spec)


FULL_ONE = {"lab": "sfab-ch03", "profile": "a", "state": "one"}

# Every form the KLISH renderer may emit, with the part of a switch's configuration where KLISH
# accepted it on SONiC 4.6.0.
ACCEPTED = [
    (r"^configure terminal$", "session rules"),
    (r"^end$", "session rules"),
    (r"^exit$", "session rules: exit returns one mode level"),
    (r"^ip vrf mgmt$", "every switch first: configure terminal, ip vrf mgmt, end"),
    (r"^interface Vlan [0-9]+$", "the MCLAG pair and the rail switch: interface Vlan N with no address"),
    (r"^interface PortChannel [0-9]+$", "the MCLAG pair"),
    (r"^interface Ethernet[0-9]+$", "native names: container ethN is Ethernet(N-1)"),
    (r"^description [A-Za-z0-9._-]+$", "the MCLAG pair: one-word descriptions (peer-link, peer-link-1, srv, fw)"),
    (r"^fast_rate$", "the MCLAG pair"),
    (r"^mtu 9216$", "MTU 9216 on a PortChannel, and on a native-named member before channel-group"),
    (r"^mclag [0-9]+$", "the MCLAG pair, once the domain exists"),
    (r"^switchport trunk allowed Vlan [0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$", "the MCLAG pair: peer link and firewall trunk"),
    (r"^switchport access Vlan [0-9]+$", "the MCLAG pair and the rail switch"),
    (r"^no shutdown$", "every port: the factory profile leaves them down"),
    (r"^channel-group [0-9]+$", "the MCLAG pair's members"),
    (r"^mclag domain [0-9]+$", "the MCLAG pair"),
    (r"^source-ip [0-9]+(\.[0-9]+){3}$", "the MCLAG pair"),
    (r"^peer-ip [0-9]+(\.[0-9]+){3}$", "the MCLAG pair"),
    (r"^peer-link PortChannel [0-9]+$", "the MCLAG pair"),
    (r"^mclag-system-mac ([0-9a-f]{2}:){5}[0-9a-f]{2}$", "the MCLAG pair"),
    (r"^session-vrf (mgmt|VrfMclagKa)$", "the MCLAG pair: the keepalive in its own VRF (revision 2; mgmt before it)"),
    # build A revision 2: each accepted on SONiC 4.6.0 by chapter 3's lab
    (r"^ip vrf VrfMclagKa$", "the MCLAG pair: the keepalive VRF"),
    (r"^ip vrf forwarding VrfMclagKa$", "the keepalive link and the backup VLAN interface, before the address"),
    (r"^ip address 10\.20\.255\.[0-9]+/31$", "the keepalive addresses, the pair's only ones"),
    (r"^mclag-separate-ip$", "the backup keepalive's VLAN interface: its own MAC on the standby"),
    (r"^backup-keepalive (source-ip|peer-ip) [0-9]+(\.[0-9]+){3}$", "the MCLAG domain: the backup keepalive session"),
    (r"^backup-keepalive session-vrf VrfMclagKa$", "the MCLAG domain: the backup keepalive in the keepalive VRF"),
    (r"^backup-keepalive interval [0-9]+$", "the MCLAG domain: 1 to 60 s"),
    (r"^spanning-tree mode pvst$", "the pair and the rail switches: PVST, proven on both pair members"),
    (r"^spanning-tree portfast$", "an edge PortChannel or access port under PVST"),
    (r"^spanning-tree bpduguard port-shutdown$", "an edge PortChannel or access port: shut on a BPDU (tripped on both pair members)"),
    (r"^storm-control (broadcast|unknown-unicast|unknown-multicast) [0-9]+$", "a PortChannel member or an access port, kbps after the type"),
]

DEFAULT_ETH = [" mtu 9100", " speed 25000", " unreliable-los auto"]
DEFAULT_DOMAIN = [" keepalive-interval 1", " session-timeout 30", " delay-restore 300", " backup-keepalive interval 30"]


def running_from(rendered: str, host: str = "sw", drop: tuple = (), split_domain: bool = True,
                 crlf: bool = True) -> str:
    """A running configuration printed the way the switch prints it, for a rendered file.

    Headers lose the space before the number (interface Vlan100, interface PortChannel10), other
    lines keep their spelling except interface references (peer-link PortChannel1), Ethernet
    blocks gain their defaults, the MCLAG domain is printed in two parts, and the capture holds
    prompt lines and carriage returns. drop holds (header or None, line) pairs to leave out.
    """
    items, _ = KL.parse_rendered(rendered.splitlines())
    blocks: dict = {}
    order: list = []
    top: list = []
    for it in items:
        if it.header:
            h = KL.canonical(it.text)
            if h not in blocks:
                blocks[h] = []
                order.append(h)
            continue
        if not it.context:
            top.append(it.text)
            continue
        line = it.text
        if line.startswith("peer-link PortChannel "):
            line = line.replace("PortChannel ", "PortChannel")
        blocks[it.context[-1]].append(line)
    out = [f"{host}# show running-configuration", "!", f"hostname {host}", " ", "port-group 1 speed 25000",
           "factory default profile l3 confirm"]
    for t in top:
        if (None, t) not in drop:
            out += [t, "! ", "!"]
    late = []
    for h in order:
        if (h, None) in drop:
            continue
        lines = [ln for ln in blocks[h] if (h, ln) not in drop]
        if h.startswith("mclag domain"):
            first = [ln for ln in lines if not ln.startswith("peer-link")]
            second = [ln for ln in lines if ln.startswith("peer-link")]
            out.append(h)
            out += [" " + ln for ln in first] + DEFAULT_DOMAIN
            out.append("!")
            if split_domain:
                late += [h] + [" " + ln for ln in second] + ["!"]
            else:
                out[-1:-1] = [" " + ln for ln in second]
            continue
        out.append(h)
        body = [" " + ln for ln in lines]
        if h.startswith("interface Ethernet"):
            desc = [b for b in body if b.startswith(" description")]
            mtu = [b for b in body if b.startswith(" mtu ")] or DEFAULT_ETH[:1]
            rest = [b for b in body if not b.startswith((" description", " mtu "))]
            body = desc + mtu + DEFAULT_ETH[1:] + rest
        out += body + ["!"]
    out += ["interface Ethernet40", " mtu 9100", " speed 25000", " shutdown", "!"]
    out += late
    out += ["qos scheduler-policy copp-scheduler-policy", " !", " queue 0", "  type wrr", "!"]
    out.append(f"{host}# exit")
    sep = "\r\n" if crlf else "\n"
    return sep.join(out) + sep


class M1:
    """dev/m1 rendered once."""

    _cache: dict = {}

    @classmethod
    def get(cls):
        if not cls._cache:
            spec, model = _select(ROOT / "dev" / "m1")
            ctx = _ctx(spec, ROOT / "dev" / "m1")
            out = {}
            for mod in (clab, klish, expect):
                out.update(mod.render(model, ctx))
            cls._cache.update(spec=spec, model=model, ctx=ctx, out=out)
        return cls._cache


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestGolden(unittest.TestCase):
    def test_m1_golden(self):
        out = M1.get()["out"]
        update = os.environ.get("SFAB_UPDATE_GOLDEN") == "1"
        if update:
            if GOLDEN.exists():
                shutil.rmtree(GOLDEN)
            for p, data in out.items():
                f = GOLDEN / p
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(data, encoding="utf-8")
        have = sorted(p.relative_to(GOLDEN).as_posix() for p in GOLDEN.rglob("*") if p.is_file())
        self.assertEqual(have, sorted(out), "the set of rendered files differs from the golden set")
        for p, data in sorted(out.items()):
            want = (GOLDEN / p).read_text(encoding="utf-8")
            self.assertEqual(data, want, f"{p} differs from tests/golden/m1/{p} (SFAB_UPDATE_GOLDEN=1 refreshes it)")

    def test_render_is_stable(self):
        spec, model = _select(ROOT / "dev" / "m1")
        with tempfile.TemporaryDirectory() as tmp:
            ctx = _ctx(spec, ROOT / "dev" / "m1", Path(tmp))
            again = {}
            for mod in (clab, klish, expect):
                again.update(mod.render(model, ctx))
        self.assertEqual(again, M1.get()["out"], "a render into another output directory must give the same bytes")

    def test_text_rules(self):
        for p, data in M1.get()["out"].items():
            self.assertTrue(data.endswith("\n"), p)
            self.assertNotIn("\r", data, p)
            self.assertNotIn("\u2014", data, p)
            self.assertNotIn("\u2013", data, p)
            if p.endswith(".json"):
                obj = json.loads(data)
                self.assertEqual(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n", data, p)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestKlishRender(unittest.TestCase):
    def setUp(self):
        self.out = M1.get()["out"]
        self.model = M1.get()["model"]

    def cfg(self, sw: str) -> list:
        return self.out[f"bootstrap/{sw}/startup-config.cfg"].splitlines()

    def test_every_line_is_an_accepted_form(self):
        rx = [(re.compile(p), why) for p, why in ACCEPTED]
        for sw in self.model.switches:
            for n, line in enumerate(self.cfg(sw), 1):
                if KL.is_comment(line):
                    continue
                self.assertTrue(any(r.match(line) for r, _ in rx), f"{sw} line {n}: {line!r} is not a form KLISH accepted on 4.6.0")

    def test_head_first_and_header_comment(self):
        for sw in self.model.switches:
            lines = self.cfg(sw)
            self.assertEqual(lines[0], f"! sfab-m1 {sw}: rendered from spec/profile-a.yaml; edit the spec and run make render")
            body = [ln for ln in lines if not KL.is_comment(ln)]
            self.assertEqual(body[:4], ["configure terminal", "ip vrf mgmt", "end", "configure terminal"], sw)
            self.assertEqual(body[-1], "end", sw)
            self.assertNotIn("write memory", body, "the launcher types write memory itself")

    def test_lint_clean(self):
        for sw in self.model.switches:
            self.assertEqual(klish.lint(self.cfg(sw)), [], sw)

    def test_mclag_order(self):
        lines = [ln for ln in self.cfg("fe-sw1") if not KL.is_comment(ln)]
        i_pc1 = lines.index("interface PortChannel 1")
        i_dom = lines.index("mclag domain 1")
        i_first_mclag = min(i for i, ln in enumerate(lines) if ln == "mclag 1")
        self.assertLess(i_pc1, i_dom)
        self.assertLess(lines.index("interface Ethernet1"), i_dom, "peer-link members join before the domain")
        self.assertLess(i_dom, i_first_mclag)
        self.assertLess(lines.index("interface Vlan 300"), i_pc1)
        self.assertLess(lines.index("interface PortChannel 10"), lines.index("interface PortChannel 21"))
        dom = lines[i_dom:lines.index("exit", i_dom) + 1]
        self.assertEqual(dom, ["mclag domain 1", "source-ip 10.20.255.0", "peer-ip 10.20.255.1", "peer-link PortChannel 1",
                               "mclag-system-mac 02:5a:00:00:00:01", "session-vrf VrfMclagKa",
                               "backup-keepalive source-ip 10.20.255.4", "backup-keepalive peer-ip 10.20.255.5",
                               "backup-keepalive session-vrf VrfMclagKa", "backup-keepalive interval 1", "exit"])
        dom2 = [ln for ln in self.cfg("fe-sw2") if ln.startswith(("source-ip", "peer-ip", "backup-keepalive source-ip", "backup-keepalive peer-ip"))]
        self.assertEqual(dom2, ["source-ip 10.20.255.1", "peer-ip 10.20.255.0", "backup-keepalive source-ip 10.20.255.5",
                                "backup-keepalive peer-ip 10.20.255.4"])
        # the backup VLAN interface (and its VRF) before the peer link that carries it and the domain
        # that names it; the keepalive link before the domain
        i_vlan = lines.index("interface Vlan 3966")
        self.assertLess(lines.index("ip vrf VrfMclagKa"), i_vlan)
        self.assertLess(i_vlan, i_pc1)
        self.assertEqual(lines[i_vlan:i_vlan + 5], ["interface Vlan 3966", "description mclag-backup-keepalive",
                                                    "ip vrf forwarding VrfMclagKa", "ip address 10.20.255.4/31", "exit"])
        # mclag-separate-ip only once the domain exists (4.6.0: "%Error: mclag not configured" before it)
        i_end = lines.index("exit", i_dom)
        self.assertEqual(lines[i_end + 1:i_end + 4], ["interface Vlan 3966", "mclag-separate-ip", "exit"])
        self.assertLess(i_end, i_first_mclag)
        i_ka = lines.index("interface Ethernet12")
        self.assertLess(i_pc1, i_ka)
        self.assertLess(i_ka, i_dom)
        self.assertEqual(lines[i_ka:i_ka + 7], ["interface Ethernet12", "description mclag-keepalive", "mtu 9216",
                                                "ip vrf forwarding VrfMclagKa", "ip address 10.20.255.0/31", "no shutdown", "exit"])
        self.assertEqual(lines[lines.index("configure terminal", 1) + 1], "spanning-tree mode pvst")

    def test_firewall_bundle_mtu(self):
        text = self.out["bootstrap/fe-sw1/startup-config.cfg"]
        self.assertIn("! mtu-floor 9216: fw ae1.100 ae1.110 ae1.200 ae1.300 ae1.130 ae1.131\ninterface PortChannel 10\ndescription fw-ae1\nmtu 9216\n", text)
        self.assertIn("switchport trunk allowed Vlan 100,110,130-131,200,300\n", text, "the firewall trunk carries every gatewayed VLAN, never 120")
        self.assertIn("interface PortChannel 21\ndescription k8s-gpu1-bond\nmtu 9216\nfast_rate\nmclag 1\nswitchport access Vlan 100\n"
                      "switchport trunk allowed Vlan 120\nspanning-tree portfast\nspanning-tree bpduguard port-shutdown\nno shutdown\n", text,
                      "the GPU nodes' bonds carry the storage VLAN tagged, at 9216, edge ports with BPDU guard")
        # the firewall's trunk is not an edge port and its members carry no storm control
        self.assertIn("interface Ethernet2\ndescription fw-eth1\nmtu 9216\nchannel-group 10\nno shutdown\nexit\n", text)
        self.assertNotIn("spanning-tree", text.split("interface PortChannel 10")[1].split("exit")[0])
        self.assertIn("interface Ethernet6\ndescription k8s-gpu1-eth1\nmtu 9216\nchannel-group 21\nstorm-control broadcast 10000\n"
                      "storm-control unknown-unicast 10000\nstorm-control unknown-multicast 10000\nno shutdown\nexit\n", text)
        # the peer link at 9216 too, not an edge port
        self.assertIn("interface PortChannel 1\ndescription peer-link\nmtu 9216\nfast_rate\n"
                      "switchport trunk allowed Vlan 100,110,120,130-131,200,300,3966\nno shutdown\nexit\n", text)

    def test_decisions_ride_as_comments(self):
        text = self.out["bootstrap/fe-sw1/startup-config.cfg"]
        self.assertIn("! decision dec-pair-l2-only: PortChannel1, peer-link\n", text)
        self.assertIn("! decision dec-fw-every-gateway: PortChannel10, fw-ae1\n", text)

    def test_no_address_anywhere(self):
        """No address but the pair's four keepalive addresses, each in the keepalive VRF."""
        ka = []
        for sw in self.model.switches:
            for line in self.cfg(sw):
                if KL.is_comment(line) or line.startswith(("source-ip", "peer-ip", "backup-keepalive")):
                    continue
                if line.startswith("ip address 10.20.255."):
                    ka.append((sw, line))
                    continue
                self.assertIsNone(re.search(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", line), f"{sw}: {line}")
                self.assertFalse(line.startswith(("ip address", "router", "ip route")), f"{sw}: {line}")
        self.assertEqual(sorted(ka), [("fe-sw1", "ip address 10.20.255.0/31"), ("fe-sw1", "ip address 10.20.255.4/31"),
                                      ("fe-sw2", "ip address 10.20.255.1/31"), ("fe-sw2", "ip address 10.20.255.5/31")])

    def test_rail_and_oob(self):
        r1 = self.cfg("rail-sw1")
        self.assertEqual([ln for ln in r1 if ln.startswith("interface Vlan")],
                         ["interface Vlan 101", "interface Vlan 103", "interface Vlan 105", "interface Vlan 107"])
        i = r1.index("interface Ethernet1")
        self.assertEqual(r1[i:i + 11], ["interface Ethernet1", "description k8s-gpu1-rail3", "mtu 9216", "switchport access Vlan 103",
                                        "spanning-tree portfast", "spanning-tree bpduguard port-shutdown", "storm-control broadcast 10000",
                                        "storm-control unknown-unicast 10000", "storm-control unknown-multicast 10000", "no shutdown", "exit"])
        self.assertIn("spanning-tree mode pvst", r1)
        oob = self.cfg("oob-sw")
        self.assertEqual([ln for ln in oob if ln.startswith("interface ")],
                         ["interface Vlan 90", "interface Ethernet0", "interface Ethernet1", "interface Ethernet2"])

    def test_full_state_one_port_plan(self):
        spec, model = _select(FULL_ONE)
        out = klish.render(model, _ctx(spec, ROOT / "dev" / "m1"))
        fe1 = out["bootstrap/fe-sw1/startup-config.cfg"].splitlines()
        fe2 = out["bootstrap/fe-sw2/startup-config.cfg"].splitlines()
        eth1 = [ln for ln in fe1 if ln.startswith("interface Ethernet")]
        eth2 = [ln for ln in fe2 if ln.startswith("interface Ethernet")]
        # the services hosts (dns-auth1, dns-res1, dns-auth2, dns-res2) on eth16 to eth19 of both switches, the ingress
        # nodes on eth14 and eth15, TrueNAS's management bond on eth12 of both, the keepalive link on eth13
        self.assertEqual(len(eth1), 19)
        self.assertEqual(len(eth2), 19)
        self.assertEqual(max(eth1, key=lambda x: int(x.rsplit("Ethernet", 1)[1])), "interface Ethernet18")
        self.assertIn("interface Ethernet12", eth1)
        for fe, leg in ((fe1, "truenas1-eth5"), (fe2, "truenas1-eth6")):
            i = fe.index("interface Ethernet11")
            self.assertEqual(fe[i:i + 4], ["interface Ethernet11", f"description {leg}", "mtu 9216", "channel-group 32"])
        pcs = [ln for ln in fe1 if ln.startswith("interface PortChannel")]
        self.assertEqual(pcs, [f"interface PortChannel {n}" for n in (1, 10, 11, 12, 13, 14, 15, 21, 22, 30, 31, 32, 41, 42, 43, 44)])
        i = fe1.index("interface PortChannel 32")
        self.assertIn("switchport access Vlan 200", fe1[i:i + 7])
        for pc, tag in ((14, 110), (15, 110), (21, 120), (22, 120)):
            i = fe1.index(f"interface PortChannel {pc}")
            self.assertEqual(fe1[i + 5:i + 7], ["switchport access Vlan 100", f"switchport trunk allowed Vlan {tag}"])
        i = fe1.index("interface PortChannel 30")
        self.assertIn("switchport access Vlan 300", fe1[i:i + 7])
        for pc, vlan in ((41, 130), (42, 130), (43, 131), (44, 131)):
            i = fe1.index(f"interface PortChannel {pc}")
            self.assertIn(f"switchport access Vlan {vlan}", fe1[i:i + 7])
        self.assertEqual(sum(1 for ln in fe1 if ln == "channel-group 31"), 2)
        self.assertEqual(model.node("fe-sw1").num_nics, 19)
        self.assertEqual(model.node("fe-sw2").num_nics, 19)
        oob = out["bootstrap/oob-sw/startup-config.cfg"].splitlines()
        self.assertEqual(sum(1 for ln in oob if ln == "switchport access Vlan 90"), 8, "the bastion has no leg in the BMC VLAN; the ingress nodes have BMCs")
        for name, text in out.items():
            self.assertEqual(klish.lint(text.splitlines()), [], name)

    def test_helpers(self):
        self.assertEqual(klish.vlans([300, 100]), ["interface Vlan 100", "exit", "interface Vlan 300", "exit"])
        self.assertEqual(klish.access_port(49, 90, "x"), ["interface Ethernet48", "description x", "switchport access Vlan 90", "no shutdown", "exit"])
        self.assertEqual(klish.member("eth50", 7, "y")[0], "interface Ethernet52")
        with self.assertRaises(RenderError):
            klish.portchannel(5, "two words", "access", [100])
        with self.assertRaises(RenderError):
            klish.portchannel(5, "x", "access", [100, 200])
        with self.assertRaises(RenderError):
            klish.portchannel(5, "x", "hybrid", [100])


class TestLint(unittest.TestCase):
    GOOD = [
        "! header",
        "configure terminal",
        "ip vrf mgmt",
        "end",
        "configure terminal",
        "interface Vlan 100",
        "exit",
        "interface PortChannel 1",
        "description peer-link",
        "fast_rate",
        "switchport trunk allowed Vlan 100",
        "no shutdown",
        "exit",
        "interface Ethernet0",
        "description peer-link-1",
        "channel-group 1",
        "no shutdown",
        "exit",
        "mclag domain 1",
        "source-ip 172.21.40.11",
        "peer-ip 172.21.40.12",
        "peer-link PortChannel 1",
        "mclag-system-mac 02:5a:00:00:00:01",
        "session-vrf mgmt",
        "exit",
        "! mtu-floor 9216: fw ae1.100",
        "interface PortChannel 10",
        "description fw-ae1",
        "mtu 9216",
        "fast_rate",
        "mclag 1",
        "switchport trunk allowed Vlan 100",
        "no shutdown",
        "exit",
        "interface Ethernet2",
        "description fw-eth1",
        "mtu 9216",
        "channel-group 10",
        "no shutdown",
        "exit",
        "end",
    ]

    def lint(self, lines):
        return KL.lint(lines)

    def edit(self, old=None, new=None, insert_after=None, remove=None):
        lines = list(self.GOOD)
        if remove is not None:
            lines.remove(remove)
        if old is not None:
            lines[lines.index(old)] = new
        if insert_after is not None:
            at, extra = insert_after
            i = lines.index(at) + 1
            lines[i:i] = extra
        return lines

    def assertRejects(self, lines, fragment):
        probs = self.lint(lines)
        self.assertTrue(any(fragment in p for p in probs), f"expected a problem with {fragment!r}, got {probs}")

    def test_good_is_clean(self):
        self.assertEqual(self.lint(self.GOOD), [])

    def test_head(self):
        lines = [ln for ln in self.GOOD if ln != "ip vrf mgmt"]
        self.assertRejects(lines, "must open with configure terminal, ip vrf mgmt, end")
        self.assertRejects(self.GOOD[0:1] + self.GOOD[4:], "must open with")

    def test_question_mark(self):
        self.assertRejects(self.edit(insert_after=("fast_rate", ["mclag ?"])), "never type ?")

    def test_exit_after_ip_vrf(self):
        lines = self.edit(insert_after=("ip vrf mgmt", ["exit"]))
        self.assertRejects(lines, "exit after ip vrf")

    def test_description_with_space(self):
        self.assertRejects(self.edit("description fw-ae1", "description fw ae1"), "must not contain a space")
        self.assertRejects(self.edit("description fw-ae1", 'description "fw ae1"'), "must not contain a space")

    def test_grep(self):
        self.assertRejects(self.edit(insert_after=("end", ["show running-configuration | grep -E router"])), "grep -E")
        self.assertRejects(self.edit(insert_after=("end", ["show running-configuration | grep 'router'"])), "quoted patterns")
        self.assertEqual(self.lint(self.GOOD + ["show running-configuration | grep router"]), [])

    def test_no_mclag_domain(self):
        self.assertRejects(self.edit(insert_after=("session-vrf mgmt", ["exit", "no mclag domain 1", "mclag domain 1"])), "never delete an MCLAG domain")

    def test_mclag_before_domain(self):
        lines = self.edit(insert_after=("description peer-link", ["mclag 1"]))
        self.assertRejects(lines, "mclag 1 typed before mclag domain 1")
        lines = self.edit("mclag 1", "mclag 2")
        self.assertRejects(lines, "mclag 2 typed before mclag domain 2")

    def test_slirp_addresses(self):
        self.assertRejects(self.edit("source-ip 172.21.40.11", "source-ip 10.0.0.15"), "10.0.0.0/24")
        lines = self.edit(insert_after=("description fw-ae1", ["ip address 10.0.0.0/16"]))
        self.assertRejects(lines, "10.0.0.0/24")
        self.assertEqual(self.lint(self.edit("source-ip 172.21.40.11", "source-ip 10.0.1.15")), [])

    def test_used_port_needs_no_shutdown(self):
        lines = list(self.GOOD)
        i = lines.index("channel-group 1")
        del lines[i + 1]
        self.assertRejects(lines, "Ethernet0 is used but not admin up")
        lines = list(self.GOOD)
        i = lines.index("channel-group 10")
        lines[i + 1] = "shutdown"
        self.assertRejects(lines, "Ethernet2 is used but not admin up")
        lines = list(self.GOOD)
        j = lines.index("switchport trunk allowed Vlan 100")
        del lines[j + 1]
        self.assertRejects(lines, "PortChannel1 is used but not admin up")

    def test_range_counts(self):
        lines = [ln for ln in self.GOOD if ln != "no shutdown"]
        extra = ["configure terminal", "interface range Ethernet0-2", "no shutdown", "exit",
                 "interface PortChannel 1", "no shutdown", "exit", "interface PortChannel 10", "no shutdown", "exit", "end"]
        self.assertEqual(self.lint(lines + extra), [])

    def test_mtu_floor(self):
        lines = [ln for ln in self.GOOD if ln != "mtu 9216"]
        self.assertRejects(lines, "PortChannel10 runs mtu 9100, below the 9216")
        lines = list(self.GOOD)
        lines[lines.index("mtu 9216")] = "mtu 9000"
        self.assertRejects(lines, "below the 9216")

    def test_member_mtu_matches(self):
        lines = list(self.GOOD)
        i = lines.index("description fw-eth1")
        del lines[i + 1]
        self.assertRejects(lines, "Ethernet2 runs mtu 9100 but its PortChannel10 runs 9216")

    def test_member_mtu_order(self):
        lines = list(self.GOOD)
        i = lines.index("description fw-eth1")
        lines[i + 1], lines[i + 2] = lines[i + 2], lines[i + 1]
        self.assertEqual(lines[i + 1:i + 3], ["channel-group 10", "mtu 9216"])
        self.assertRejects(lines, "mtu typed after channel-group")

    def test_mtu_range(self):
        lines = list(self.GOOD)
        lines[lines.index("mtu 9216")] = "mtu 9217"
        self.assertRejects(lines, "outside 1312 to 9216")

    def test_structure(self):
        self.assertRejects(self.GOOD + ["interface Vlan 200"], "outside configure terminal")
        lines = self.edit(insert_after=("description peer-link-1", ["interface Ethernet9"]))
        self.assertRejects(lines, "without an exit first")

    def test_comments_and_blanks_ignored(self):
        lines = []
        for ln in self.GOOD:
            lines += [ln, "", "!   a comment with ? and grep -E inside"]
        self.assertEqual(self.lint(lines), [])


class TestCanonical(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(KL.canonical("interface  Vlan 100"), "interface Vlan100")
        self.assertEqual(KL.canonical("peer-link PortChannel 1"), "peer-link PortChannel1")
        self.assertEqual(KL.canonical("interface Ethernet0"), "interface Ethernet0")
        self.assertEqual(KL.canonical("switchport access Vlan 100"), KL.canonical("switchport access Vlan100"))
        self.assertEqual(KL.canonical("interface Management 0"), "interface Management0")

    def test_parse_running_merges_and_skips_prompts(self):
        text = "\x1b[?2004hsw# show running-configuration\r\n!\r\nip vrf mgmt\r\n!\r\nmclag domain 1\r\n source-ip 1.1.1.1\r\n!\r\n" \
               "interface Vlan100\r\n!\r\nmclag domain 1\r\n peer-link PortChannel1\r\n!\r\nsw# exit\r\n"
        run = KL.parse_running(text)
        self.assertTrue(run.has((), "ip vrf mgmt"))
        self.assertTrue(run.has((), "interface Vlan100"))
        self.assertEqual(run.lines(("mclag domain 1",)), ["source-ip 1.1.1.1", "peer-link PortChannel1"])
        self.assertFalse(any("show" in ln for ln in run.lines(())))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestParity(unittest.TestCase):
    def setUp(self):
        self.out = M1.get()["out"]
        self.fe1 = self.out["bootstrap/fe-sw1/startup-config.cfg"]

    def test_every_switch_clean(self):
        for name, text in self.out.items():
            if not name.endswith("startup-config.cfg"):
                continue
            res = parity.compare(text.splitlines(), running_from(text), [])
            self.assertEqual(res["missing"], [], name)
            self.assertEqual(res["problems"], [], name)

    def test_missing_lines_found(self):
        run = running_from(self.fe1, drop=(("interface PortChannel21", "mclag 1"), ("mclag domain 1", "session-vrf VrfMclagKa"),
                                           ("interface Vlan300", None)))
        res = parity.compare(self.fe1.splitlines(), run, [])
        got = [(tuple(r["context"]), r["line"]) for r in res["missing"]]
        self.assertEqual(got, [((), "interface Vlan 300"), (("mclag domain 1",), "session-vrf VrfMclagKa"),
                               (("interface PortChannel21",), "mclag 1")])

    def test_replay_blocks(self):
        run = running_from(self.fe1, drop=(("interface PortChannel21", "mclag 1"), ("mclag domain 1", "session-vrf VrfMclagKa"),
                                           ("interface Vlan300", None), (None, "ip vrf mgmt")))
        res = parity.compare(self.fe1.splitlines(), run, [])
        blocks = parity.replay_blocks(res["items"], res["missing"])
        self.assertEqual(blocks, [["ip vrf mgmt"], ["interface Vlan 300", "exit"], ["mclag domain 1", "session-vrf VrfMclagKa", "exit"],
                                  ["interface PortChannel 21", "mclag 1", "exit"]])

    def test_unsplit_domain_and_lf(self):
        res = parity.compare(self.fe1.splitlines(), running_from(self.fe1, split_domain=False, crlf=False), [])
        self.assertEqual(res["missing"], [])

    def test_rows(self):
        lines = self.fe1.splitlines()
        run = running_from(self.fe1, drop=(("interface PortChannel1", "fast_rate"),))
        res = parity.compare(lines, run, [])
        self.assertEqual([r["line"] for r in res["missing"]], ["fast_rate"])
        absent = parity.Row({"id": "n1", "context": r"^interface PortChannel1$", "rendered": r"^fast_rate$", "action": "absent"})
        res = parity.compare(lines, run, [absent])
        self.assertEqual(res["missing"], [])
        self.assertEqual(len(res["absent"]), 1)
        default = parity.Row({"id": "n2", "rendered": r"^fast_rate$", "action": "default"})
        res = parity.compare(lines, run, [default])
        self.assertEqual(res["missing"], [])
        self.assertEqual(len(res["default"]), 1)
        run2 = run.replace(" description peer-link\r\n", " description peer-link\r\n lacp fast-rate\r\n", 1)
        rewrite = parity.Row({"id": "n3", "context": r"^interface PortChannel1$", "rendered": r"^fast_(rate)$",
                              "running": r"^lacp fast-\1$", "action": "rewrite"})
        res = parity.compare(lines, run2, [rewrite])
        self.assertEqual(res["missing"], [])
        res = parity.compare(lines, run, [rewrite])
        self.assertEqual([r["line"] for r in res["missing"]], ["fast_rate"])
        with self.assertRaises(parity.TableError):
            parity.Row({"id": "x", "rendered": "a", "action": "absent"})
        with self.assertRaises(parity.TableError):
            parity.Row({"id": "n4", "rendered": "a", "action": "rewrite"})

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "r.cfg").write_text(self.fe1)
            (t / "run.txt").write_text(running_from(self.fe1, drop=(("interface PortChannel22", "mclag 1"),)))
            (t / "norm.json").write_text(self.out["gen/klish-normalize.json"])
            p = subprocess.run([sys.executable, str(PARITY), str(t / "r.cfg"), str(t / "run.txt"), "--switch", "fe-sw1",
                                "--normalize", str(t / "norm.json"), "--json", str(t / "p.json"), "--replay", str(t / "b.txt"),
                                "--reverse"], capture_output=True, text=True)
            self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
            self.assertIn("FAIL  parity fe-sw1 -> 1 of", p.stdout)
            self.assertEqual((t / "b.txt").read_text(), "interface PortChannel 22\nmclag 1\nexit\n")
            data = json.loads((t / "p.json").read_text())
            self.assertEqual(len(data["missing"]), 1)
            self.assertIn({"context": ["interface Ethernet0"], "line": "speed 25000"}, data["extra"])
            (t / "run.txt").write_text(running_from(self.fe1))
            p = subprocess.run([sys.executable, str(PARITY), str(t / "r.cfg"), str(t / "run.txt"), "--switch", "fe-sw1",
                                "--normalize", str(t / "norm.json")],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertIn("PASS  parity fe-sw1", p.stdout)
            (t / "empty.txt").write_text("")
            p = subprocess.run([sys.executable, str(PARITY), str(t / "r.cfg"), str(t / "empty.txt")], capture_output=True, text=True)
            self.assertEqual(p.returncode, 2)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestExpect(unittest.TestCase):
    def test_fe_sw1(self):
        e = json.loads(M1.get()["out"]["gen/expect/fe-sw1.json"])
        self.assertEqual(e["vlans"]["100"], {"tagged": ["PortChannel1", "PortChannel10"], "untagged": ["PortChannel21", "PortChannel22"]})
        self.assertEqual(e["vlans"]["200"]["tagged"], ["PortChannel1", "PortChannel10"])
        self.assertEqual(e["portchannels"]["PortChannel10"]["mtu"], 9216)
        self.assertEqual(e["portchannels"]["PortChannel1"]["members"], ["Ethernet0", "Ethernet1"])
        self.assertEqual(e["mclag"]["interfaces"], ["PortChannel10", "PortChannel21", "PortChannel22"])
        self.assertEqual(e["mclag"]["session_vrf"], "VrfMclagKa")
        self.assertEqual(e["mclag"]["backup"], {"source_ip": "10.20.255.4", "peer_ip": "10.20.255.5", "vrf": "VrfMclagKa",
                                                "interval": 1, "session": "up"})
        self.assertEqual(e["addresses"]["ip_interfaces"], [
            {"interface": "Management0", "address": "172.21.40.11/24", "gateway": "172.21.40.1", "vrf": "mgmt", "source": "passthrough"},
            {"interface": "Ethernet12", "address": "10.20.255.0/31", "vrf": "VrfMclagKa", "source": "keepalive"},
            {"interface": "Vlan3966", "address": "10.20.255.4/31", "vrf": "VrfMclagKa", "source": "backup-keepalive"}])
        self.assertEqual(e["addresses"]["data"], [])
        self.assertEqual(e["routes"], {"default": [], "VrfMclagKa": ["10.20.255.0/31", "10.20.255.4/31"]})
        self.assertEqual(e["vlans"]["3966"], {"tagged": ["PortChannel1"], "untagged": []}, "the backup VLAN rides the peer link only")
        self.assertEqual(e["known_macs"]["02:5a:6f:00:00:01"], {"node": "k8s-gpu1", "vlan": 100, "via": "PortChannel21", "source": "bond"})
        self.assertEqual(e["num_nics"], 13)

    def test_rail_and_oob(self):
        r = json.loads(M1.get()["out"]["gen/expect/rail-sw2.json"])
        self.assertEqual(sorted(r["vlans"], key=int), ["102", "104", "106", "108"])
        self.assertEqual(r["vlans"]["104"]["untagged"], ["Ethernet1", "Ethernet5"])
        self.assertIsNone(r["mclag"])
        self.assertEqual(r["addresses"]["ip_interfaces"][0]["source"], "slirp")
        self.assertEqual(r["known_macs"]["02:5a:6f:01:00:07"], {"node": "k8s-gpu1", "vlan": 104, "via": "Ethernet1", "source": "relay-macvlan"})
        self.assertEqual(r["known_macs"]["02:5a:6f:00:00:07"]["source"], "nic")
        o = json.loads(M1.get()["out"]["gen/expect/oob-sw.json"])
        self.assertEqual(sorted(o["known_macs"]), ["02:5a:6f:00:00:03", "02:5a:70:00:00:03"])
        self.assertEqual(o["vlans"], {"90": {"tagged": [], "untagged": ["Ethernet0", "Ethernet1", "Ethernet2"]}})
        self.assertEqual(o["num_nics"], 3)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the topology back")
class TestTopology(unittest.TestCase):
    def setUp(self):
        self.text = M1.get()["out"]["topo.clab.yml"]
        self.topo = yaml.safe_load(self.text)
        self.model = M1.get()["model"]

    def test_lab_wide(self):
        t = self.topo
        self.assertEqual(t["name"], "sfab-m1")
        self.assertEqual(t["prefix"], "__lab-name")
        self.assertEqual(t["mgmt"], {"network": "sfab-a-mgmt", "bridge": "sfab-a-mgmt", "ipv4-subnet": "172.21.40.0/24", "ipv4-gw": "172.21.40.1"})
        self.assertEqual(list(t["topology"]["nodes"]), list(self.model.nodes))
        for name, n in t["topology"]["nodes"].items():
            self.assertEqual(n["mgmt-ipv4"], self.model.node(name).mgmt, name)
            self.assertNotIn("startup-delay", n, "build A uses no startup-delay")

    def test_switches(self):
        nodes = self.topo["topology"]["nodes"]
        for name, sw in self.model.switches.items():
            n = nodes[name]
            self.assertEqual(n["kind"], "dell_sonic")
            self.assertEqual(n["image"], "vrnetlab/dell_sonic:4.6.0")
            self.assertEqual(n["env"]["NUM_NICS"], str(ports.num_nics(sw)))
            self.assertEqual(n["binds"], [f"bootstrap/{name}/startup-config.cfg:/config/startup-config.cfg:ro"])
            if sw.pair:
                self.assertEqual(n["env"]["CLAB_MGMT_PASSTHROUGH"], "true", name)
            else:
                self.assertNotIn("CLAB_MGMT_PASSTHROUGH", n["env"], name)
        self.assertEqual(nodes["rail-sw1"]["env"]["NUM_NICS"], "8")
        self.assertEqual(nodes["oob-sw"]["env"]["NUM_NICS"], "3")

    def test_firewall_and_guests(self):
        nodes = self.topo["topology"]["nodes"]
        fw = nodes["fw"]
        self.assertEqual(fw["kind"], "paloalto_panos")
        self.assertEqual(fw["startup-config"], "bootstrap/fw/startup-config.xml")
        # QEMU sizing only: the PA-VM keeps containerlab's paloalto_panos default login, which its
        # launcher takes from its command line and never from USERNAME or PASSWORD in the env
        self.assertEqual(fw["env"], {"QEMU_CPU": "host", "QEMU_SMP": "8", "QEMU_MEMORY": "16384"})
        g = nodes["k8s-gpu1"]
        self.assertEqual(g["restart-policy"], "no")
        self.assertEqual(g["devices"], ["/dev/kvm", "/dev/net/tun"])
        self.assertEqual(g["env"]["VM_NICS"], " ".join(f"eth{i}" for i in range(1, 12)))
        self.assertEqual(g["env"]["VM_MEMORY_MB"], "16384")
        self.assertIn("bootstrap/k8s-gpu1:/sfab/bootstrap:ro", g["binds"])
        for name, n in nodes.items():
            for k, v in (n.get("env") or {}).items():
                self.assertIsInstance(v, str, f"{name} env {k} must be a string")

    def test_guest_nic_link(self):
        # bridge, the spec's value, renders nothing: vm-init.sh then takes the bridge where the
        # host kernel lets it. tc gives every VM node SFAB_NIC_LINK=tc and no other node anything.
        import copy

        nodes = self.topo["topology"]["nodes"]
        self.assertFalse([n for n, d in nodes.items() if "SFAB_NIC_LINK" in (d.get("env") or {})])
        spec = copy.deepcopy(M1.get()["spec"])
        guests = sorted(n for n, d in nodes.items() if d.get("devices") == ["/dev/kvm", "/dev/net/tun"])
        self.assertEqual(guests, ["k8s-gpu1", "k8s-gpu2"], "dev/m1's VM nodes")
        spec.common["guest"]["nic_link"] = "tc"
        from sfab.spec import select

        model = select(spec, ROOT / "dev" / "m1")
        topo = yaml.safe_load(clab.render(model, _ctx(spec, ROOT / "dev" / "m1"))["topo.clab.yml"])
        got = {n: (d.get("env") or {}).get("SFAB_NIC_LINK") for n, d in topo["topology"]["nodes"].items()}
        self.assertEqual({n: v for n, v in got.items() if v is not None}, {g: "tc" for g in guests})
        spec.common["guest"]["nic_link"] = "mirred"
        model = select(spec, ROOT / "dev" / "m1")
        with self.assertRaises(RenderError) as cm:
            clab.render(model, _ctx(spec, ROOT / "dev" / "m1"))
        self.assertIn("guest.nic_link", str(cm.exception))

    def test_links_match_model(self):
        got = [tuple(l["endpoints"]) for l in self.topo["topology"]["links"]]
        want = [(str(l.a), str(l.b)) for l in self.model.links]
        self.assertEqual(got, want)
        used = [e for pair in got for e in pair]
        self.assertEqual(len(used), len(set(used)), "a port is used twice")
        self.assertIn('- endpoints: ["fw:eth1", "fe-sw1:eth3"]  # fw.ae1, fe-sw1 Ethernet2', self.text)

    def test_no_secret_literals(self):
        for line in self.text.splitlines():
            if re.search(r"PASSWORD|USER", line.split(":")[0]):
                self.assertRegex(line, r'"\$\{SFAB_[A-Z_]+\}"$')
            if "$" in line:
                # containerlab expands the whole file: a dollar sign anywhere else (a comment
                # included) would be expanded or refused
                self.assertRegex(line, r'^ +[A-Z_]+: "\$\{SFAB_[A-Z0-9_]+\}"$')
        state = json.loads(M1.get()["out"]["gen/clab-state.json"])
        # the switches and the PA-VM keep their kinds' default logins: M1 references no credential
        self.assertEqual(state["env"], [])
        self.assertNotIn("${", self.text)
        self.assertIn("# No credential is referenced here", self.text)
        self.assertEqual(state["max_workers"], 8)
        self.assertIn("state/nodes/k8s-gpu1", state["dirs"])

    def test_full_state_one(self):
        spec, model = _select(FULL_ONE)
        ctx = _ctx(spec, ROOT / "dev" / "m1")
        text, state = clab.build(model, ctx)
        t = yaml.safe_load(text)
        nodes = t["topology"]["nodes"]
        self.assertEqual(nodes["fe-sw1"]["env"]["NUM_NICS"], "19")
        self.assertEqual(nodes["fe-sw2"]["env"]["NUM_NICS"], "19")
        self.assertEqual(nodes["oob-sw"]["env"]["NUM_NICS"], "8")
        tn = nodes["truenas1"]
        self.assertEqual(tn["kind"], "generic_vm")
        self.assertEqual(tn["binds"], ["state/nodes/truenas1/persist:/persist"])
        self.assertEqual(tn["env"]["TRUENAS_RAM"], "16384")
        self.assertEqual(tn["env"]["TRUENAS_POOL"], "tank")
        self.assertEqual(tn["env"]["PASSWORD"], "${SFAB_TRUENAS_PASSWORD}")
        self.assertEqual(nodes["ent-client"]["exec"], [clab.CONTAINER_INIT])
        self.assertNotIn("exec", nodes["bastion"])
        self.assertNotIn("exec", nodes["uplink-rtr"])
        self.assertIn("../../images/registry/data:/var/lib/registry:ro", nodes["inet-registry"]["binds"])
        self.assertEqual(state["max_workers"], len(model.nodes))
        self.assertIn("SFAB_TRUENAS_PASSWORD", state["env"])
        # a topology that references credentials says where containerlab expands them from
        self.assertIn("# Credentials are SFAB_ environment references", text)
        self.assertNotIn("No credential is referenced here", text)
        self.assertEqual(len(t["topology"]["links"]), len(model.links))
        # the containers whose init.env names the lab root CA see only state/shared/ca, read-only
        for n in ("ent-client", "ops-client", "ops-dns", "inet-registry", "bastion", "dns-auth1", "dns-res1", "ent-dns", "inet-ntp"):
            self.assertIn("state/shared/ca:/shared/ca:ro", nodes[n]["binds"], n)
            self.assertNotIn("state/shared:/shared", nodes[n]["binds"], n)
        self.assertIn("state/shared/ca", state["dirs"])
        # the jump host: the lab root and the operators' kubeconfigs, read-only, and no CA or cluster state
        self.assertEqual(nodes["bastion"]["binds"], ["bootstrap/bastion:/sfab/bootstrap:ro",
                                                     "state/secrets/authorized_keys:/sfab/authorized_keys:ro",
                                                     "state/operators:/sfab/operators:ro", "state/shared/ca:/shared/ca:ro"])
        self.assertFalse([b for v in nodes.values() for b in v.get("binds") or [] if b.startswith("state/ca")],
                         "the CA's keys reach no node")
        # each node leaf reaches its own node only; the TSIG keys the authoritative pair only
        self.assertIn("state/tls/inet-registry:/sfab/tls:ro", nodes["inet-registry"]["binds"])
        self.assertIn("state/tls/inet-ntp:/sfab/tls:ro", nodes["inet-ntp"]["binds"])
        self.assertEqual(sorted(n for n, v in nodes.items() if any("/sfab/tls" in b for b in v.get("binds") or [])), ["inet-ntp", "inet-registry"])
        self.assertEqual(sorted(n for n, v in nodes.items() if any("/sfab/tsig" in b for b in v.get("binds") or [])), ["dns-auth1", "dns-auth2"])
        self.assertEqual(state["tsig"], ["enterprise-xfr", "internal-xfr"])
        self.assertIn("state/secrets/tsig/internal-xfr.key", state["files"])
        # the containers bonded to the pair keep IPv6 off from the start
        for n in ("bastion", "dns-auth1", "dns-auth2", "dns-res1", "dns-res2"):
            self.assertEqual(nodes[n]["sysctls"], {"net.ipv6.conf.default.disable_ipv6": "1"}, n)

    def test_secrets_cover_every_reference(self):
        # every SFAB_ name a topology expands has a value made by common/bin/secrets.py, or the
        # up stage refuses to deploy (gen/clab-state.json "env")
        import importlib.util  # noqa: PLC0415

        spec_ = importlib.util.spec_from_file_location("sfab_secrets", ROOT / "common" / "bin" / "secrets.py")
        mod = importlib.util.module_from_spec(spec_)
        spec_.loader.exec_module(mod)
        made = set(mod.wanted())
        spec, model = _select(FULL_ONE)
        _text, state = clab.build(model, _ctx(spec, ROOT / "dev" / "m1"))
        self.assertTrue(state["env"])
        self.assertEqual(sorted(set(state["env"]) - made), [])
        self.assertEqual(sorted(set(clab.credential_names()) - made), [])
        # the PA-VM keeps the kind's default login: nothing references or makes a firewall password
        self.assertEqual([n for n in state["env"] if n.startswith("SFAB_FW_")], [])
        self.assertEqual([n for n in made if n.startswith("SFAB_FW_")], [])
        fw_env = yaml.safe_load(_text)["topology"]["nodes"]["fw"]["env"]
        self.assertNotIn("USERNAME", fw_env)
        self.assertNotIn("PASSWORD", fw_env)

    def test_passthrough_is_asserted(self):
        """Passthrough is required only of a pair member whose keepalive would ride the management
        VRF; with the dedicated keepalive link (revision 2) it is the harness's choice."""
        model = M1.get()["model"]
        sw = model.node("fe-sw2")
        nodes = dict(model.nodes)
        nodes["fe-sw2"] = dataclasses.replace(sw, passthrough=False)
        clab.topology(dataclasses.replace(model, nodes=nodes), M1.get()["ctx"])
        nodes["fe-sw2"] = dataclasses.replace(sw, passthrough=False, keepalive=None)
        bad = dataclasses.replace(model, nodes=nodes)
        with self.assertRaises(RenderError):
            clab.topology(bad, M1.get()["ctx"])

    def test_boot_waves(self):
        names = [f"s{i}" for i in range(20)]
        w = clab.boot_waves(names, 8, 180)
        self.assertNotIn("s0", w)
        self.assertNotIn("s7", w)
        self.assertEqual(w["s8"], 180)
        self.assertEqual(w["s15"], 180)
        self.assertEqual(w["s16"], 360)
        with self.assertRaises(RenderError):
            clab.boot_waves(names, 0, 180)

    def test_scalar(self):
        for v in ("no", "yes", "true", "8", "1.5", "", "a: b", "${X}", "x#y"):
            self.assertEqual(yaml.safe_load(f"k: {clab.scalar(v)}")["k"], v, v)
        self.assertEqual(clab.scalar("vrnetlab/dell_sonic:4.6.0"), "vrnetlab/dell_sonic:4.6.0")


FAKE_SSHPASS = r"""#!/usr/bin/env bash
# stand-in for sshpass in the tests: records the session, answers from fixture files
payload="$(cat)"
{
    echo "=== args: $*"
    if [ -n "${FAKE_EXPECT_PW:-}" ] && [ "${SSHPASS:-}" = "$FAKE_EXPECT_PW" ]; then echo "SSHPASS_MATCH=yes"; fi
    echo "SSHPASS_SET=${SSHPASS:+yes}"
    printf '%s\n' "$payload"
} >> "$FAKE_LOG"
case "$payload" in
    *"show running-configuration"*) cat "$FAKE_RUNNING" ;;
esac
case "$payload" in
    *"show mclag brief"*) cat "$FAKE_MCLAG" ;;
esac
if [ -n "${FAKE_ERROR_ON:-}" ]; then
    case "$payload" in
        *"$FAKE_ERROR_ON"*) printf '%% Error: Invalid input detected at "^" marker.\r\n' ;;
    esac
fi
exit 0
"""

# Stand-in for docker in the script tests: `docker inspect` answers with FAKE_DOCKER_CONFIG (a
# container's .Config as JSON) when it is set, and fails otherwise, so a real docker on the host
# running the tests (with a real lab up) never reaches them.
FAKE_DOCKER = r"""#!/usr/bin/env bash
if [ "${1:-}" = inspect ] && [ -n "${FAKE_DOCKER_CONFIG:-}" ]; then cat "$FAKE_DOCKER_CONFIG"; exit 0; fi
exit 1
"""


@unittest.skipUnless(shutil.which("bash"), "bash is needed")
class TestStandins(unittest.TestCase):
    """The stand-ins shadow the real commands, and a stand-in that cannot run fails the check at
    once instead of letting a script reach a real device."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-standins-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_shadow_and_refuse(self):
        bin_ = standins.make_bin(self.tmp / "bin", {})
        env = dict(os.environ, PATH=standins.path_with(bin_))
        standins.check(env, bin_)
        r = subprocess.run(["bash", "-c", "ssh admin@172.21.40.11 true"], env=env, capture_output=True, text=True,
                           timeout=standins.SCRIPT_TIMEOUT_S)
        self.assertEqual(r.returncode, 255)
        self.assertIn("never reach a real device", r.stderr)

    def test_a_stand_in_that_cannot_run_fails_the_check(self):
        bin_ = standins.make_bin(self.tmp / "bin", {})
        (bin_ / "sshpass").chmod(0o644)
        env = dict(os.environ, PATH=standins.path_with(bin_, base="/usr/bin:/bin"))
        with self.assertRaises(AssertionError) as cm:
            standins.check(env, bin_)
        self.assertIn("sshpass resolves to", str(cm.exception))


@unittest.skipUnless(HAVE_YAML and shutil.which("bash"), "PyYAML and bash are needed")
class TestScripts(unittest.TestCase):
    def setUp(self):
        from sfab.render import inventory  # noqa: PLC0415

        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-test-"))
        self.lab = self.tmp / "lab"
        out = dict(M1.get()["out"])
        out.update(inventory.render(M1.get()["model"], M1.get()["ctx"]))
        for p, data in out.items():
            f = self.lab / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(data)
        (self.lab / "state").mkdir()
        (self.lab / "state" / "secrets.env").write_text("SFAB_SW_PASSWORD=not-a-real-one\n")
        # sshpass, ssh and docker are all stand-ins: nothing here may open a real session.
        bin_ = standins.make_bin(self.tmp / "bin", {"sshpass": FAKE_SSHPASS, "docker": FAKE_DOCKER})
        self.log = self.tmp / "log.txt"
        self.running = self.tmp / "running.txt"
        self.mclag = self.tmp / "mclag.txt"
        self.mclag.write_text("\r\nDomain ID            : 1\r\nRole                 : active\r\nSession Status       : up\r\n")
        fe1 = out["bootstrap/fe-sw1/startup-config.cfg"]
        self.fe1 = fe1
        self.running.write_text(running_from(fe1, host="fe-sw1"))
        self.env = dict(os.environ, PATH=standins.path_with(bin_), FAKE_LOG=str(self.log),
                        FAKE_RUNNING=str(self.running), FAKE_MCLAG=str(self.mclag), SFAB_LABDIR=str(self.lab),
                        SFAB_INV=str(self.lab / "gen" / "inventory.json"), **standins.SESSION_ENV)
        self.env.pop("SFAB_SW_PASSWORD", None)
        standins.check(self.env, bin_)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def session(self, text: str, *args, env=None):
        return subprocess.run(["bash", str(SESSION), *args, "fe-sw1"], input=text, capture_output=True, text=True,
                              env=env or self.env, cwd=self.lab, timeout=standins.SCRIPT_TIMEOUT_S)

    def logged(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def test_session_payload(self):
        p = self.session("! a comment\n\nconfigure terminal\ninterface Vlan 100\nexit\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        log = self.logged()
        self.assertIn("SSHPASS_SET=yes", log)
        self.assertIn("-tt", log)
        self.assertIn("admin@172.21.40.11 sonic-cli", log)
        self.assertNotIn("not-a-real-one", log)
        body = log.split("SSHPASS_SET=yes\n", 1)[1]
        self.assertEqual(body, "terminal length 0\nconfigure terminal\ninterface Vlan 100\nexit\nend\nexit\n")

    def test_session_refusals(self):
        for bad in ("show mclag ?\n", "show running-configuration | grep -E mclag\n",
                    "show running-configuration | grep \"mclag\"\n", "configure terminal\nno mclag domain 1\nend\n",
                    "configure terminal\nip vrf mgmt\nexit\n"):
            p = self.session(bad)
            self.assertEqual(p.returncode, 2, bad)
            self.assertIn("refused", p.stderr, bad)
        self.assertEqual(self.logged(), "", "nothing reaches the switch when a line is refused")

    def test_session_strict_and_password(self):
        env = dict(self.env, FAKE_ERROR_ON="interface Vlan 100")
        p = self.session("configure terminal\ninterface Vlan 100\nexit\nend\n", "--strict", env=env)
        self.assertEqual(p.returncode, 4)
        self.assertIn("% Error", p.stdout)
        self.assertNotIn("\r", p.stdout)
        p = self.session("configure terminal\ninterface Vlan 100\nexit\nend\n", env=env)
        self.assertEqual(p.returncode, 0)
        (self.lab / "state" / "secrets.env").unlink()
        p = self.session("show version\n")
        self.assertEqual(p.returncode, 3)
        p = self.session("show version\n", env=dict(self.env, SFAB_SW_PASSWORD="from-env"))
        self.assertEqual(p.returncode, 0)

    def test_session_password_from_the_container(self):
        # the switches keep the kind's default credentials, so the password containerlab gave the
        # switch container wins over the generated one in state/secrets.env
        cfg = self.tmp / "config.json"
        cfg.write_text(json.dumps({"Cmd": ["--username", "admin", "--password", "kind-default"], "Env": []}))
        env = dict(self.env, FAKE_DOCKER_CONFIG=str(cfg), FAKE_EXPECT_PW="kind-default")
        p = self.session("show version\n", env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("SSHPASS_MATCH=yes", self.logged())
        self.assertNotIn("kind-default", self.logged().replace("FAKE", ""))
        cfg.write_text(json.dumps({"Cmd": [], "Env": ["PASSWORD=from-env-var"]}))
        self.log.unlink()
        p = self.session("show version\n", env=dict(env, FAKE_EXPECT_PW="from-env-var"))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("SSHPASS_MATCH=yes", self.logged())
        # an explicit SFAB_SW_PASSWORD still comes first
        self.log.unlink()
        p = self.session("show version\n", env=dict(env, SFAB_SW_PASSWORD="explicit", FAKE_EXPECT_PW="explicit"))
        self.assertIn("SSHPASS_MATCH=yes", self.logged())

    def replay(self, *args, env=None):
        return subprocess.run(["bash", str(REPLAY), *args, "fe-sw1"], capture_output=True, text=True,
                              env=env or self.env, cwd=self.lab, timeout=standins.SCRIPT_TIMEOUT_S)

    def test_replay_nothing_missing(self):
        p = self.replay()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("nothing missing", p.stdout)
        self.assertNotIn("configure terminal", self.logged())

    def test_replay_types_missing_and_skips_live_domain(self):
        self.running.write_text(running_from(self.fe1, host="fe-sw1", drop=(("interface PortChannel21", "mclag 1"),
                                                                           ("mclag domain 1", "session-vrf VrfMclagKa"))))
        p = self.replay()
        self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
        self.assertIn("SKIP  replay fe-sw1: mclag domain 1 is live", p.stdout)
        log = self.logged()
        self.assertIn("configure terminal\ninterface PortChannel 21\nmclag 1\nexit\nend\nexit\n", log)
        self.assertNotIn("session-vrf VrfMclagKa", log)
        self.assertIn("write memory", log)

    def test_replay_stops_on_error(self):
        self.running.write_text(running_from(self.fe1, host="fe-sw1", drop=(("interface PortChannel21", "mclag 1"),
                                                                           ("interface PortChannel22", "mclag 1"))))
        env = dict(self.env, FAKE_ERROR_ON="interface PortChannel 21")
        p = self.replay(env=env)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("FAIL  replay fe-sw1", p.stdout)
        log = self.logged()
        self.assertNotIn("interface PortChannel 22", log, "replay stops at the first error")
        self.assertNotIn("write memory", log)

    def test_replay_dry_run(self):
        self.running.write_text(running_from(self.fe1, host="fe-sw1", drop=(("interface PortChannel22", "mclag 1"),)))
        p = self.replay("--dry-run")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("interface PortChannel 22\nmclag 1\nexit", p.stdout)
        self.assertNotIn("configure terminal", self.logged())


if __name__ == "__main__":
    unittest.main()
