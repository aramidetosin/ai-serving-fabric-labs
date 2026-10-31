"""Chapter 4's lab harness (ch04/): the PAN-OS readers (common/audit/panos_parse.py), the audit's fw-edge
group, the firewall trace's judgment (common/trace/fwtrace.py), the drills' analysis
(common/drill/fwdrill.py) and break-4a's counter helper (common/breakheal.py). Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_ch04*.py'

Hermetic: every file judged here is a stand-in built from the committed ch04 inventory and plans by
common/tests/ch04_world.py, in the shapes the readers expect; the figures are made up, never a lab's.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(HERE))

import ch04_world as W  # noqa: E402
import judge  # noqa: E402
import panos_parse as PP  # noqa: E402
import runscope  # noqa: E402
import vocab  # noqa: E402

CH04 = ROOT / "ch04"
FWT = COMMON / "trace" / "fwtrace.py"
FWD = COMMON / "drill" / "fwdrill.py"
BH = COMMON / "breakheal.py"


def inv() -> dict:
    return json.loads((CH04 / "gen" / "inventory.json").read_text())


def load(p) -> dict:
    return json.loads(Path(p).read_text())


# --------------------------------------------------------------------------------------------


class ParsersTest(unittest.TestCase):
    def test_counters(self):
        cli = W.counters_cli({"pkt_recv": 1200, "flow_policy_nat_land": 0})
        xml = W.counters_xml({"pkt_recv": 1210, "flow_policy_nat_land": 3})
        c = PP.counters_cli(cli)
        self.assertEqual((c["pkt_recv"]["value"], c["flow_policy_nat_land"]["severity"]), (1200, "drop"))
        self.assertEqual(PP.counters_xml(xml)["flow_policy_nat_land"]["value"], 3)
        self.assertEqual(PP.counters(cli, xml)["pkt_recv"]["value"], 1210, "the XML form wins where both parsed")
        self.assertEqual(PP.delta(PP.counters(cli), PP.counters("", xml)), {"flow_policy_nat_land": 3, "pkt_recv": 10})
        self.assertEqual(PP.delta(PP.counters(cli), PP.counters(cli), "flow_policy_nat_land"), {"flow_policy_nat_land": 0})
        self.assertEqual(PP.delta({}, {}, "flow_policy_nat_land"), {}, "a name in neither table is absent")

    def test_tlog_as_chapter_3_recorded_it(self):
        e = PP.tlog_find(PP.read(ROOT / "common" / "tests" / "recorded" / "ch03-rev1" / "fw-traffic-log.txt"), sport=35130)
        self.assertEqual([(x["from"], x["src"], x["rule"], x["to"], x["dst"], x["dport"]) for x in e],
                         [("uplink", "192.0.2.2", "uplink-to-internal-", "data", "198.51.100.2", "443")])
        t = W.tlog([("2026/10/20 10:00:09", "ntp", "uplink", 123, "198.51.100.2", "deny-all-log", "deny", "bastion", 123, "10.20.3.10")])
        self.assertEqual(PP.tlog_find(t, src="198.51.100.2", dport=123, rule="deny-all-log")[0]["to"], "bastion")

    def test_sessions(self):
        rows = PP.sessions(W.session_all(4567, "ssl", "192.0.2.2", 42444, "uplink", "192.0.2.2", 42444, "198.51.100.2", 443, "data",
                                         "10.20.1.200", 443, "ND"))
        self.assertEqual(rows[0] | {}, rows[0])
        r = rows[0]
        self.assertEqual((r["id"], r["flag"], r["from"], r["to"], r["dst"], r["xdst"], r["xsrc"]),
                         ("4567", "ND", "uplink", "data", "198.51.100.2", "10.20.1.200", "192.0.2.2"))
        d = PP.session(W.session_detail(4567, "192.0.2.2", 42444, "uplink", "198.51.100.2", 443, "10.20.1.200", "data",
                                        "uplink-to-internal-gateway", "dnat-operator-gateway", "ethernet1/5", "ae1.100"))
        self.assertEqual((d["rule"], d["nat_rule"], d["ingress"], d["egress"], d["c2s"]["zone"], d["s2c"]["source"]),
                         ("uplink-to-internal-gateway", "dnat-operator-gateway", "ethernet1/5", "ae1.100", "uplink", "10.20.1.200"))
        self.assertEqual(d["c2s"]["sport"], 42444)

    def test_policy_as_chapter_3_recorded_it(self):
        t = PP.read(ROOT / "common" / "tests" / "recorded" / "ch03-rev1" / "12_running_nat.txt")
        self.assertEqual(PP.policy(t), ["dnat-operator-gateway", "no-nat-public", "internet-snat"])

    def test_ntp_and_ping(self):
        self.assertEqual(PP.ntp(W.ntp("10.20.3.10")), {"servers": ["10.20.3.10"], "synched": True, "synched_to": "10.20.3.10"})
        self.assertIsNone(PP.ntp(W.ntp("10.20.3.10", synched=False))["synched_to"])
        self.assertFalse(PP.ntp(W.ntp("10.20.3.10", synched=False))["synched"])
        self.assertEqual(PP.ping(W.ping("198.51.100.2", 5, 0)), {"sent": 5, "received": 0})
        self.assertEqual(PP.ping("5 packets transmitted, 5 packets received, 0% packet loss"), {"sent": 5, "received": 5})


# --------------------------------------------------------------------------------------------
# the audit's fw-edge group, on saved files

# the operator's forbidden cells of chapter 2's Table 2-2, as audit_fw_edge plans them for ch04
# revision 2: the storage data VLAN has no gateway, so its cell is left out of the refusals
CELLS = [("users-vip", "10.20.11.210", 443), ("api-server", "10.20.1.10", 6443), ("node-ssh", "10.20.1.21", 22),
         ("bmc", "10.20.9.21", 443), ("stor-mgmt", "10.20.2.31", 443)]
ZONE = {"users-vip": "ingress", "api-server": "k8s-nodes", "node-ssh": "k8s-nodes", "bmc": "oob", "stor-mgmt": "stor-mgmt"}


class FwEdgeTest(unittest.TestCase):
    def setUp(self):
        self.rs = Path(tempfile.mkdtemp(prefix="sfab-test-ch04rs-"))
        self.addCleanup(shutil.rmtree, self.rs, True)
        self.inv = inv()
        sys.path.insert(0, str(HERE / "shims"))
        os.environ.setdefault("SHIM_INV", str(CH04 / "gen" / "inventory.json"))
        os.environ.setdefault("SHIM_LOG", os.devnull)
        import _devices
        self.dev = _devices

    def save(self, node, slug, text, ext="txt"):
        d = self.rs / node
        d.mkdir(exist_ok=True)
        n = len(list(d.iterdir())) + 1
        (d / f"{n:02d}_{slug}.{ext}").write_text(text + "\n")

    def edge(self, name, text):
        d = self.rs / "fw-edge"
        d.mkdir(exist_ok=True)
        (d / name).write_text(text + "\n")

    def healthy(self, land=0, rise=0):
        fw = self.inv["nodes"]["fw"]
        os.environ["SHIM_INV"] = str(CH04 / "gen" / "inventory.json")
        self.save("fw", "interface_all", "admin@fw> show interface all\n" + self.dev.panos_interface_all("fw"))
        self.save("fw", "running_security", "admin@fw> show running security-policy\n"
                  + W.running_policy(fw["rules"] + ["intrazone-default", "interzone-default"]))
        self.save("fw", "running_nat", "admin@fw> show running nat-policy\n" + W.running_policy(fw["nat"], "nat"))
        enf = [l for l in (CH04 / "bootstrap" / "fw" / "enforced.txt").read_text().splitlines() if l.startswith("set ")]
        self.save("fw", "config_set", "admin@fw# show\n" + "\n".join(enf))
        self.save("fw", "ntp", "admin@fw> show ntp\n" + W.ntp("10.20.13.21"))
        self.save("uplink-rtr", "frr_routes", W.frr_routes(self.inv["nodes"]["uplink-rtr"]["routes"]), "json")
        plan = {"node": "k8s-cp2", "node_addr": "10.20.1.12", "node_kind": "vm-node", "public": "198.51.100.2",
                "counter": "flow_policy_nat_land", "admin_addr": "10.20.3.1", "bastion": "bastion", "bastion_addr": "10.20.3.10",
                "bastion_oob": None, "bastion_fqdn": "bastion.ai.tarnwick.example", "operator": "ops-client",
                "operator_addr": "192.0.2.2", "cells": [dict(zip(("id", "addr", "port"), c)) for c in CELLS],
                "svc_src": "10.20.13.1", "dns_rule": "inside-to-resolvers", "ntp_rule": "inside-to-ntp",
                "egress": {"client": "web-client", "addr": "192.0.2.18", "port": 443, "rule": "deny-all-log", "from_zone": "k8s-nodes",
                           "to_zone": "uplink"}}
        self.edge("plan.json", json.dumps(plan))
        self.edge("counters-before.txt", W.counters_cli({"pkt_recv": 100, "flow_policy_nat_land": land}))
        self.edge("counters-before.xml", W.counters_xml({"pkt_recv": 100, "flow_policy_nat_land": land}))
        self.edge("counters-after.txt", W.counters_cli({"pkt_recv": 110, "flow_policy_nat_land": land + rise}))
        self.edge("counters-after.xml", W.counters_xml({"pkt_recv": 110, "flow_policy_nat_land": land + rise}))
        self.edge("node-public-ping.txt", W.ping("198.51.100.2", 5, 5))
        self.edge("egress-connect.txt", "failed: timed out after 4 s")
        self.edge("egress-tlog-443.txt", W.tlog([("2026/10/20 10:00:01", "incomplete", "k8s-nodes", 45000, "10.20.1.12", "deny-all-log", "deny",
                                                   "uplink", 443, "192.0.2.18")]))
        self.edge("bastion-admin-https.txt", "200")
        self.edge("bastion-admin-ssh.txt", "SSH-2.0-OpenSSH_9.9")
        self.edge("other-admin-https.txt", "000")
        self.edge("operator-public-ssh.txt", "")
        self.edge("operator-public-https.txt", "")  # nothing is published on the uplink in revision 2
        for i, (cid, addr, port) in enumerate(CELLS):
            self.edge(f"operator-cells-{cid}.txt", "failed: timed out after 4 s")
        for port in sorted({c[2] for c in CELLS}):
            self.edge(f"operator-cells-tlog-{port}.txt", W.tlog([
                (f"2026/10/20 10:00:0{i}", "incomplete", "operator-vpn", 40000 + i, "192.0.2.2", "deny-all-log", "deny", ZONE[cid], p, addr)
                for i, (cid, addr, p) in enumerate(CELLS) if p == port]))
        self.edge("fw-dns.txt", "PING bastion.ai.tarnwick.example (10.20.3.10) from 10.20.13.1 : 56(84) bytes of data.")
        self.edge("svc-tlog.txt", W.tlog([
            ("2026/10/20 10:00:03", "dns", "services", 33000, "10.20.13.1", "inside-to-resolvers", "allow", "services", 53, "10.20.13.21"),
            ("2026/10/20 09:50:03", "ntp", "services", 123, "10.20.13.1", "inside-to-ntp", "allow", "services", 123, "10.20.13.21")]))

    def run_judge(self):
        buf = io.StringIO()
        v = vocab.Vocab(verdict="", known=set(self.inv["known"]), out=buf)
        j = judge.Judge(judge.ResultSet(self.rs), self.inv, CH04, v)
        j.g_fw_edge(["fw"])
        return buf.getvalue(), v.counts()

    def test_green(self):
        self.healthy()
        out, c = self.run_judge()
        self.assertEqual(c["fail"], 0, out)
        for line in ("  PASS  ethernet1/5 in zone uplink with 198.51.100.2/29",
                     "  PASS  ae1.130 in zone services with 10.20.13.1/24",
                     f"  PASS  the {len(self.inv['nodes']['fw']['rules'])} security rules run in the render's order: " + ", ".join(self.inv["nodes"]["fw"]["rules"]),
                     "  PASS  deny-all-log is the last rule before the predefined defaults",
                     "  PASS  no-nat-public sits above internet-snat",
                     "  PASS  flow_policy_nat_land is in this firewall's own show counter global table",
                     "  PASS  flow_policy_nat_land reads 0",
                     "  PASS  k8s-cp2 (10.20.1.12) reaches the public address 198.51.100.2: 5 of 5 requests answered",
                     "  PASS  flow_policy_nat_land did not rise while k8s-cp2 (10.20.1.12) sent them (no-nat-public keeps the source)",
                     "  PASS  profile bastion-admin: https, ssh, ping, permitted only from 10.20.3.10/32",
                     "  PASS  ae1.300 takes bastion-admin; the other 9 interfaces answer ping only",
                     "  PASS  the bastion from its own address 10.20.3.10 reaches HTTPS on 10.20.3.1 (HTTP 200)",
                     "  PASS  the bastion from 10.20.3.10 reaches SSH on 10.20.3.1",
                     "  PASS  HTTPS on 10.20.3.1 does not answer another inside host, k8s-cp2 (10.20.1.12) (HTTP 000)",
                     "  PASS  ops-client: HTTPS on 198.51.100.2 answers nothing: nothing is published on the uplink",
                     "  PASS  ntp to 10.20.13.21 leaves from ae1.130 (10.20.13.1/24)",
                     "  PASS  show ntp: synched to 10.20.13.21, one of its NTP servers (10.20.13.21, 10.20.14.21)",
                     "  PASS  the traffic log has the firewall's own ntp from 10.20.13.1 to 10.20.13.21:123 allowed by inside-to-ntp",
                     "  PASS  the firewall resolved bastion.ai.tarnwick.example through its DNS service route",
                     "  PASS  10.24.10.0/24 via 198.51.100.2 (dec-route-inside-via-fw): static, selected",
                     "  PASS  ops-client to 10.20.11.210:443 (users-vip) refused: failed: timed out after 4 s",
                     "  PASS  ... and the firewall logged it under deny-all-log, zone operator-vpn to ingress",
                     "  PASS  ops-client to 10.20.2.31:443 (stor-mgmt) refused: failed: timed out after 4 s",
                     "  PASS  ... and the firewall logged it under deny-all-log, zone operator-vpn to stor-mgmt",
                     "  PASS  ops-client to 10.20.9.21:443 (bmc) refused: failed: timed out after 4 s",
                     "  PASS  ... and the firewall logged it under deny-all-log, zone operator-vpn to oob",
                     "  PASS  k8s-cp2 (10.20.1.12) to web-client, an internet host, on 192.0.2.18:443: refused (failed: timed out after 4 s)",
                     "  PASS  ... logged under deny-all-log, deny, zone k8s-nodes to uplink (no rule admits the inside to an internet host "
                     "but the registry and the time source)"):
            self.assertIn(line, out)
        self.assertNotIn("(stor-data)", out)

    def test_ntp_names_the_server_it_synched_to(self):
        # chapter 4's recorded make audit: the firewall synched to dns-res2, its second server; the line
        # names that one, not the first configured; a server outside the configuration fails
        self.healthy()
        self.edge("ntp.txt", W.ntp("10.20.14.21"))
        out, c = self.run_judge()
        self.assertEqual(c["fail"], 0, out)
        self.assertIn("  PASS  show ntp: synched to 10.20.14.21, one of its NTP servers (10.20.13.21, 10.20.14.21)", out)
        self.edge("ntp.txt", W.ntp("192.0.2.14"))
        out, c = self.run_judge()
        self.assertIn("  FAIL  show ntp: synched to 192.0.2.14, one of its NTP servers (10.20.13.21, 10.20.14.21)", out)

    def test_an_egress_that_got_out(self):
        self.healthy()
        self.edge("egress-connect.txt", "failed: exit 1, bash: connect: Connection refused")
        self.edge("egress-tlog-443.txt", W.tlog([("2026/10/20 10:00:01", "incomplete", "k8s-nodes", 45000, "10.20.1.12", "nodes-to-anywhere",
                                                   "allow", "uplink", 443, "192.0.2.18")]))
        out, c = self.run_judge()
        self.assertIn("refused (failed: exit 1, bash: connect: Connection refused) -> refused by the far host, so the firewall let it out", out)
        self.assertIn("-> rule nodes-to-anywhere, allow, zone k8s-nodes to uplink", out)
        for line in ():
            self.assertIn(line, out)

    def test_a_raised_counter_and_a_wrong_order(self):
        self.healthy(land=7, rise=2)
        nat = [f for f in (self.rs / "fw").iterdir() if "running_nat" in f.name][0]
        nat.write_text("admin@fw> show running nat-policy\n" + W.running_policy(["dnat-operator-gateway", "internet-snat", "no-nat-public"], "nat"))
        out, c = self.run_judge()
        self.assertIn("  SKIP  flow_policy_nat_land reads 0 (it reads 7: it counts since the counters were last cleared", out)
        self.assertIn("  FAIL  flow_policy_nat_land did not rise while k8s-cp2 (10.20.1.12) sent them (no-nat-public keeps the source) -> rose by 2", out)
        self.assertIn("  FAIL  no-nat-public sits above internet-snat -> running: dnat-operator-gateway, internet-snat, no-nat-public", out)

    def test_the_name_must_be_the_firewalls_own(self):
        self.healthy()
        for n in ("counters-before.txt", "counters-after.txt"):
            self.edge(n, W.counters_cli({"pkt_recv": 100}))
        for n in ("counters-before.xml", "counters-after.xml"):
            self.edge(n, W.counters_xml({"pkt_recv": 100}))
        out, c = self.run_judge()
        self.assertIn("  FAIL  flow_policy_nat_land is in this firewall's own show counter global table -> 1 counters read, "
                      "flow_policy_nat_land not among them", out)
        self.assertNotIn("flow_policy_nat_land reads 0", out, "nothing relies on a name the firewall has not printed")

    def test_an_operator_cell_without_its_log_line(self):
        self.healthy()
        self.edge("operator-cells-tlog-443.txt", W.tlog([]))
        self.edge("operator-cells-users-vip.txt", "connected")
        out, c = self.run_judge()
        self.assertIn("  FAIL  ops-client to 10.20.11.210:443 (users-vip) refused: connected -> it connected", out)
        self.assertIn("-> no deny-all-log entry for it in the log read", out)


# --------------------------------------------------------------------------------------------
# the firewall trace


class FwTraceTest(unittest.TestCase):
    def setUp(self):
        self.rs = Path(tempfile.mkdtemp(prefix="sfab-test-ch04tr-"))
        self.addCleanup(shutil.rmtree, self.rs, True)
        self.plan = load(CH04 / "gen" / "trace.json")

    def write(self, rel, text):
        p = self.rs / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n")

    def healthy(self, op_xdst="10.20.11.200"):
        e, o = self.plan["sessions"]
        # revision 2: the enterprise client reaches the users' VIP on the ingress VLAN, the operator
        # arrives over the IPsec tunnel (tunnel.1, zone operator-vpn) at the internal VIP; no NAT
        for s, xdst, rule, nat, ing, eg, frm in ((e, "10.20.11.210", "staff-to-users-gateway", None, "ethernet1/4", "ae1.110", "enterprise"),
                                                (o, op_xdst, "operator-to-internal-gateway", None, "tunnel.1", "ae1.110", "operator-vpn")):
            d = f"sessions/{s['id']}"
            self.write(f"{d}/request.txt", f"HTTP/1.1 200 OK\ncontent-length: 20\nserver: envoy\n\n{s['msg']}\nHELD 1.0\nCLOSED 31.0")
            self.write(f"{d}/session-all.txt", W.session_all(100 + s["sport"] % 7, "ssl", s["client_addr"], s["sport"], frm, s["client_addr"],
                                                             s["sport"], s["dst_addr"], 443, "ingress", xdst, 443, "ND" if nat else ""))
            self.write(f"{d}/session-detail.txt", W.session_detail(100, s["client_addr"], s["sport"], frm, s["dst_addr"], 443, xdst, "ingress",
                                                                   rule, nat, ing, eg))
            self.write(f"{d}/traffic-log.txt", W.tlog([("2026/10/20 10:00:31", "ssl", frm, s["sport"], s["client_addr"], rule, "allow",
                                                        "ingress", 443, s["dst_addr"])]))
        p = self.plan["pull"]
        self.write("pull/pull.txt", "Image is up to date for sha256:" + "a" * 64)
        self.write("pull/rmi.txt", "Deleted: " + p["image"])
        self.write("pull/points.tsv", "\n".join("\t".join(str(x) for x in (pt["id"], pt["node"], pt["eth"], pt["vlan"] or "none", pt["group"] or "-",
                                                                       pt["side"], pt["depth"])) for pt in p["points"]))
        self.write("pull/captures/1-fw-ae1-leg1.txt", "")
        self.write("pull/captures/1-fw-ae1-leg2.txt", "\n".join([
            W.tcp_syn("01.000100", "10.20.1.22", 51000, "192.0.2.6", 5000, 777000, vlan=100),
            W.tcp_data("01.100000", "192.0.2.6", 5000, "10.20.1.22", 51000, 1, 1500, vlan=100)]))
        self.write("pull/captures/2-fw-ethernet1-5.txt", "\n".join([
            W.tcp_syn("01.000300", "198.51.100.2", 18011, "192.0.2.6", 5000, 777000),
            W.tcp_data("01.099000", "192.0.2.6", 5000, "198.51.100.2", 18011, 1, 1500)]))
        self.write("pull/traffic-log.txt", W.tlog([("2026/10/20 10:00:40", "ssl", "k8s-nodes", 51000, "10.20.1.22", "nodes-to-registry", "allow",
                                                    "uplink", 5000, "192.0.2.6")]))

    def judge(self):
        env = dict(os.environ, SFAB_VERDICT=str(self.rs / "verdict.txt"))
        return subprocess.run([sys.executable, str(FWT), "judge", "--set", str(self.rs), "--plan", str(CH04 / "gen" / "trace.json"),
                               "--inv", str(CH04 / "gen" / "inventory.json")], capture_output=True, text=True, env=env)

    def test_green(self):
        self.healthy()
        r = self.judge()
        self.assertEqual(r.returncode, 0, r.stdout)
        for line in ("  PASS  show session all lists it: 192.0.2.2[42444] to 10.20.11.200[443] (id 103)",
                     "  PASS  ... zone operator-vpn to zone ingress, state ACTIVE",
                     "  PASS  ... destination after translation 10.20.11.200 (none), source unchanged 192.0.2.2",
                     "  PASS  show session id names the security rule operator-to-internal-gateway",
                     "  PASS  ... and no NAT rule",
                     "  PASS  the traffic log line: operator-to-internal-gateway (shown as operator-to-interna), allow, zone operator-vpn to zone ingress, "
                     "the pre-NAT destination 10.20.11.200",
                     "  PASS  the same SYN (seq 777000) seen on the uplink at 2-fw-ethernet1-5",
                     "  PASS  ... its source rewritten to 198.51.100.2 (port 51000 became 18011), its destination 192.0.2.6:5000 unchanged",
                     "  PASS  the traffic log has the pull's session (source port 51000) under nodes-to-registry, allow, zone k8s-nodes to zone uplink"):
            self.assertIn(line, r.stdout)
        md = (self.rs / "TRACE.md").read_text()
        self.assertIn("## Session operator", md)
        self.assertIn("`sessions/operator/traffic-log.txt:", md)
        for ch in (chr(0x2014), chr(0x2013)):
            self.assertNotIn(ch, md)

    def test_an_earlier_pulls_log_line_is_not_this_ones(self):
        # chapter 4's revision 2 traces read the log before the pull's session had ended: the only
        # lines were an earlier pull's, from another source port, which must not pass for this one
        self.healthy()
        self.write("pull/traffic-log.txt", W.tlog([("2026/10/20 09:45:31", "ssl", "k8s-nodes", 60212, "10.20.1.22", "nodes-to-registry", "allow",
                                                    "uplink", 5000, "192.0.2.6")]))
        r = self.judge()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("  FAIL  the traffic log has the pull's session (source port 51000) under nodes-to-registry, allow, zone k8s-nodes "
                      "to zone uplink -> no entry from 10.20.1.22[51000] to the registry", r.stdout)
        ps = subprocess.run([sys.executable, str(FWT), "pull-sport", "--set", str(self.rs), "--plan", str(CH04 / "gen" / "trace.json")],
                            capture_output=True, text=True)
        self.assertEqual((ps.returncode, ps.stdout.strip()), (0, "51000"), ps.stderr)

    def test_the_header_says_when_the_tree_had_uncommitted_changes(self):
        self.healthy()
        commit = "a" * 40
        for dirty, note in ((True, " (with uncommitted changes)"), (False, ""), (None, "")):
            (self.rs / "RUN.json").write_text(json.dumps({"labs_repo": {"commit": commit, "dirty": dirty, "source": "git"},
                                                          "utc_start": "2026-10-21T00:00:00Z"}))
            r = self.judge()
            self.assertEqual(r.returncode, 0, r.stdout)
            self.assertIn(f"; labs repo commit `{commit}`{note}; UTC 2026-10-21T00:00:00Z\n", (self.rs / "TRACE.md").read_text())

    def test_a_translation_that_should_not_happen(self):
        # the operator arrives over the tunnel at the internal VIP itself: a destination NAT on the
        # way (a leftover public DNAT) is a failure
        self.healthy(op_xdst="10.20.1.200")
        r = self.judge()
        self.assertEqual(r.returncode, 1)
        self.assertIn("  FAIL  ... destination after translation 10.20.11.200 (none), source unchanged 192.0.2.2 -> "
                      "translated destination 10.20.1.200, source 192.0.2.2", r.stdout)


# --------------------------------------------------------------------------------------------
# the drills' analysis


class FwDrillAnalysisTest(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="sfab-test-ch04dr-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.plan = load(CH04 / "gen" / "drills.json")

    def write(self, rel, text):
        p = self.d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n")

    def land(self, seen=True, broken_answered=0):
        vals = lambda x: ({"pkt_recv": 100, "flow_policy_nat_land": x} if seen else {"pkt_recv": 100})  # noqa: E731
        for tag, v in (("base0", 0), ("base1", 0), ("before", 0), ("after", 5), ("restored0", 5), ("restored1", 5)):
            self.write(f"counters-{tag}.txt", W.counters_cli(vals(v)))
            self.write(f"counters-{tag}.xml", W.counters_xml(vals(v)))
        self.write("ping-baseline.txt", W.ping("198.51.100.2", 5, 5))
        self.write("ping-broken.txt", W.ping("198.51.100.2", 5, broken_answered))
        self.write("ping-restored.txt", W.ping("198.51.100.2", 5, 5))
        self.write("diag/drop.decode.txt", "\n".join(W.icmp_frame(f"0{i}.000000", "10.20.1.12", "198.51.100.2", "request", i) for i in range(1, 6)))
        self.write("diag/receive.decode.txt", "\n".join(W.icmp_frame(f"0{i}.000000", "10.20.1.12", "198.51.100.2", "request", i) for i in range(1, 6)))
        self.write("captures/eth1.txt", "\n".join(W.icmp_frame(f"0{i}.000000", "10.20.1.12", "198.51.100.2", "request", i, vlan=100) for i in range(1, 6)))
        self.write("captures/eth2.txt", "")
        self.write("captures/eth5.txt", "")
        self.write("order-after.txt", "order: security 25 rules as rendered\norder: nat 2 rules as rendered")
        self.write("drop-delta-after.txt", W.counters_cli({"flow_policy_nat_land": 5} if seen else {}))

    def analyze(self, drill):
        env = dict(os.environ, SFAB_VERDICT=str(self.d / "verdict.txt"))
        return subprocess.run([sys.executable, str(FWD), "analyze", "--plan", str(CH04 / "gen" / "drills.json"), "--dir", str(self.d),
                               "--drill", drill, "--pass", "1"], capture_output=True, text=True, env=env)

    def test_land_green(self):
        self.land()
        r = self.analyze("land")
        self.assertEqual(r.returncode, 0, r.stdout)
        for line in ("  PASS  pass 1 land: flow_policy_nat_land is in this firewall's own show counter global table (2 counters read)",
                     "  PASS  pass 1 land: without it, 0 of 5 answered: the firewall discards every request",
                     "  PASS  pass 1 land: ... and flow_policy_nat_land rose by 5 while 5 requests were sent",
                     "  PASS  pass 1 land: drop counters that moved during it: flow_policy_nat_land +5 (recorded; not judged)",
                     "  PASS  pass 1 land: the drop stage captured 5 frame(s) from 10.20.1.12 to 198.51.100.2 (diag/drop.decode.txt)",
                     "  PASS  pass 1 land: the host-side captures saw 5 requests arrive at the firewall (eth1 5) and 0 replies leave it",
                     "  PASS  pass 1 land: nothing of it left on the uplink (eth5: 0 frames)",
                     "  PASS  pass 1 land: show counter global filter delta yes severity drop, read after the probe, lists "
                     "flow_policy_nat_land +5 (drop-delta-after.txt)"):
            self.assertIn(line, r.stdout)
        a = load(self.d / "analysis.json")
        self.assertEqual((a["deltas"], a["diag"]["drop"]), ({"baseline": 0, "broken": 5, "restored": 0}, 5))
        self.assertIn("discards every request", (self.d / "analysis.txt").read_text())

    def test_land_name_not_seen(self):
        self.land(seen=False)
        r = self.analyze("land")
        self.assertEqual(r.returncode, 1)
        self.assertIn("  FAIL  pass 1 land: flow_policy_nat_land is in this firewall's own show counter global table (1 counters read) -> "
                      "not among the 1 counters read: every figure below that names it is unproven", r.stdout)
        self.assertNotIn("rose by", r.stdout)

    def test_ntp_uplink(self):
        new = PP.tlog(W.tlog([("2026/10/20 10:01:00", "ntp", "uplink", 123, "198.51.100.2", "deny-all-log", "deny", "services", 123, "10.20.13.21")]))
        back = PP.tlog(W.tlog([("2026/10/20 10:03:00", "ntp", "services", 123, "10.20.13.1", "inside-to-ntp", "allow", "services", 123, "10.20.13.21")]))
        self.write("new-entries.json", json.dumps(new))
        self.write("restored-entries.json", json.dumps(back))
        self.write("captures/eth1.txt", "")
        self.write("captures/eth2.txt", "")
        self.write("captures/eth5.txt", "")
        self.write("route-after.xml", "<response status=\"success\"><result><entry name=\"ntp\"><source><interface>ae1.130</interface>"
                                      "<address>10.20.13.1/24</address></source></entry></result></response>")
        # the DNS route moved with it: its server is the same address
        dnew = PP.tlog(W.tlog([("2026/10/20 10:01:05", "not-applicable", "uplink", 41000, "198.51.100.2", "deny-all-log", "deny", "services", 53,
                                "10.20.13.21")]))
        dback = PP.tlog(W.tlog([("2026/10/20 10:03:05", "dns-base", "services", 41001, "10.20.13.1", "inside-to-resolvers", "allow", "services", 53,
                                 "10.20.13.21")]))
        self.write("dns-new-entries.json", json.dumps(dnew))
        self.write("dns-restored-entries.json", json.dumps(dback))
        self.write("route-after-dns.xml", "<response status=\"success\"><result><entry name=\"dns\"><source><interface>ae1.130</interface>"
                                          "<address>10.20.13.1/24</address></source></entry></result></response>")
        r = self.analyze("ntp-uplink")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("  PASS  pass 1 ntp-uplink: the firewall's own DNS from 198.51.100.2 to 10.20.13.21:53 (a name looked up through it) "
                      "logged under deny-all-log, deny, zone uplink to zone services", r.stdout)
        self.assertIn("  PASS  pass 1 ntp-uplink: the dns service route reads ae1.130 again", r.stdout)
        self.assertIn("  PASS  pass 1 ntp-uplink: the firewall's own NTP from 198.51.100.2 (ethernet1/5) to 10.20.13.21:123 logged under "
                      "deny-all-log, deny, zone uplink to zone services", r.stdout)
        self.assertIn("  PASS  pass 1 ntp-uplink: with the route back, the firewall's NTP from 10.20.13.1 allowed again by inside-to-ntp", r.stdout)

    def test_newlog_keeps_only_new_entries(self):
        old = W.tlog([("2026/10/20 10:00:00", "ntp", "oob", 123, "10.20.9.254", "oob-to-bastion-dns-ntp", "allow", "bastion", 123, "10.20.3.10")])
        new = W.tlog([("2026/10/20 10:01:00", "ntp", "uplink", 123, "198.51.100.2", "deny-all-log", "deny", "bastion", 123, "10.20.3.10"),
                      ("2026/10/20 10:00:00", "ntp", "oob", 123, "10.20.9.254", "oob-to-bastion-dns-ntp", "allow", "bastion", 123, "10.20.3.10")])
        self.write("a.txt", old)
        self.write("b.txt", new)
        r = subprocess.run([sys.executable, str(FWD), "newlog", "--before", str(self.d / "a.txt"), "--after", str(self.d / "b.txt"),
                            "--dst", "10.20.3.10", "--dport", "123"], capture_output=True, text=True)
        self.assertEqual([e["src"] for e in json.loads(r.stdout)], ["198.51.100.2"])


class BreakCounterTest(unittest.TestCase):
    def test_rise_and_absence(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-test-ch04bh-"))
        self.addCleanup(shutil.rmtree, d, True)
        for p, (b, a) in enumerate(((0, 10), (10, 20), (20, 30)), 1):
            pre = d / f"node-public-break-pass{p}-counters"
            Path(f"{pre}-before.txt").write_text(W.counters_cli({"flow_policy_nat_land": b}))
            Path(f"{pre}-after.txt").write_text(W.counters_cli({"flow_policy_nat_land": a}))
        r = subprocess.run([sys.executable, str(BH), "counter", "--dir", str(d), "--probe", "node-public", "--mode", "break",
                            "--name", "flow_policy_nat_land"], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "rise 30")
        r = subprocess.run([sys.executable, str(BH), "counter", "--dir", str(d), "--probe", "node-public", "--mode", "break",
                            "--name", "flow_policy_other"], capture_output=True, text=True)
        self.assertTrue(r.stdout.startswith("absent "), r.stdout)
        log = d / "ping.log"
        log.write_text(W.ping("198.51.100.2", 10, 0))
        r = subprocess.run([sys.executable, str(BH), "pingshare", "--log", str(log)], capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), "10 10")


# --------------------------------------------------------------------------------------------
# break-4a, the drills, the trace and the audit's fw-edge reads end to end, against the stand-in world

SHIMS, SHIMS_M2, SHIMS_CH03, SHIMS_CH04 = HERE / "shims", HERE / "shims-m2", HERE / "shims-ch03", HERE / "shims-ch04"
CH04_NODES = ("fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw fw truenas1 k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2 bastion uplink-rtr "
              "ops-client inet-registry ent-client")


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


_RENDER = None


def ch04_render() -> Path:
    global _RENDER
    if _RENDER is None:
        out = Path(tempfile.mkdtemp(prefix="sfab-test-ch04-"))
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(CH04), "--out", str(out), "-q"], check=True, capture_output=True)
        _RENDER = out
    return _RENDER


def tearDownModule():
    if _RENDER is not None:
        shutil.rmtree(_RENDER, ignore_errors=True)


class Ch04LabTest(unittest.TestCase):
    def setUp(self):
        if not have_yaml():
            self.skipTest("PyYAML is needed to render ch04")
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-ch04lab-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        self.scope = runscope.Scope(self)
        self.lab = self.t / "ch04"
        self.lab.mkdir()
        r = ch04_render()
        for part in ("gen", "bootstrap"):
            shutil.copytree(r / part, self.lab / part)
        shutil.copy(r / "topo.clab.yml", self.lab / "topo.clab.yml")
        for f in ("chapter.yaml", "audit.sh", "trace.sh", "drills.sh"):
            shutil.copy(CH04 / f, self.lab / f)
        os.symlink(COMMON, self.t / "common")
        os.symlink(ROOT / "spec", self.t / "spec")
        tr = load(self.lab / "gen" / "trace.json")
        # the trace reads the session table four times while the client holds its connection; 6 s
        # holds it past those reads on a machine busy with other tests (make test runs them at once)
        for s in tr["sessions"]:
            s["hold_s"] = 6
        (self.lab / "gen" / "trace.json").write_text(json.dumps(tr, indent=2, sort_keys=True) + "\n")
        dr = load(self.lab / "gen" / "drills.json")
        # ntp_wait_s bounds the traffic-log reads after a commit, which stop at the first new entry:
        # 30 s costs nothing when the entry comes at once, and outlasts a machine busy with other tests
        dr["timing"].update({"settle_s": 0.1, "ntp_wait_s": 30, "log_pause_s": 0.2})
        (self.lab / "gen" / "drills.json").write_text(json.dumps(dr, indent=2, sort_keys=True) + "\n")
        self.inv = load(self.lab / "gen" / "inventory.json")
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS_CH04}:{SHIMS_CH03}:{SHIMS_M2}:{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab), "SHIM_STATE": str(self.state), "SHIM_LOG": str(self.log), "SHIM_NODES": CH04_NODES,
            "SFAB_HOST_LOCK": str(self.t / "sfab.lock"), "SFAB_TICK_OVERRIDE": "1", "SHIM_INV": str(self.lab / "gen" / "inventory.json"),
            "SHIM_RENDER": str(self.lab), "SHIM_CH03_STATE": str(self.t / "ch03-world.json"), "SHIM_CH04_STATE": str(self.t / "ch04-world.json"),
            "SHIM_FW_ENFORCED": str(self.lab / "bootstrap" / "fw" / "enforced.txt"), "PYTHONDONTWRITEBYTECODE": "1",
            "SFAB_DRILL_AUDIT": "0", "SFAB_BREAK_SETTLE_S": "0", "SFAB_HEAL_AUDIT": "0", "SFAB_RETRY_PAUSE": "0",
            "SFAB_TRACE_SETTLE_S": "0", "SFAB_TRACE_TAIL_S": "0", "SFAB_TRACE_TLOG_PAUSE_S": "0", "SFAB_FWE_LOG_PAUSE_S": "0",
            "SFAB_DRILL_CAP_SETTLE_S": "0", "SFAB_DRILL_CAP_TAIL_S": "0.2", "SFAB_DRILL_SETTLE_S": "0",
        })
        self.env.pop("VARIANT", None)
        cs = {}
        for i, n in enumerate(self.inv["order"]):
            node = self.inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            if node.get("passthrough"):
                env.append("CLAB_MGMT_PASSTHROUGH=true")
            cmd = ["--username", "admin", "--password", "shimpw"] if node["kind"] in ("dell_sonic", "paloalto_panos") else []
            cs[node["container"]] = {"running": True, "started": f"2026-10-20T09:00:{i:02d}Z", "pid": 4000 + i,
                                     "health": "healthy", "env": env, "cmd": cmd}
        self.state.write_text(json.dumps({"containers": cs}))
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-ch04"], check=True, capture_output=True)

    def run_cmd(self, argv, timeout=900, env=None):
        e = dict(self.env)
        e.update(env or {})
        return self.scope.run([str(x) for x in argv], env=e, capture_output=True, text=True, cwd=self.lab, timeout=timeout)

    def leftover_shims(self, wait_s=10.0) -> list:
        """The stand-in processes this test's commands left running, after waiting up to wait_s for
        any that are exiting (a capture stopped with SIGINT writes its file before it exits)."""
        return self.scope.left("shims-ch04/_ch04.py", wait_s)

    def world(self):
        return load(self.t / "ch04-world.json")

    def last_set(self, kind):
        return sorted((self.lab / "audits").glob(f"sfab-ch04_{kind}_*"))[-1]


class Break4aShTest(Ch04LabTest):
    def bh(self, *args):
        return self.run_cmd([sys.executable, COMMON / "breakheal.py", *args])

    def test_break_then_heal(self):
        r = self.bh("break", "4a")
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-2000:])
        verdict = (self.last_set("break-4a") / "verdict.txt").read_text()
        for line in ("  PASS  fw: nat rule no-nat-public deleted through the XML API (success: command succeeded)",
                     "  PASS  node-public, break, pass 3: 10 of 10 pings from k8s-cp2 to 198.51.100.2 unanswered (recorded)",
                     "  PASS  node-public: every ping fails (30 of 30 across the passes)",
                     "  PASS  fw: flow_policy_nat_land rose by 30 across node-public's passes",
                     "  PASS  users: every request succeeds (10 of 10)"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  fw: committed \(commit job \d+: OK")
        self.assertNotIn("no-nat-public", self.world()["running"]["nat"])
        rec = self.last_set("break-4a") / "record"
        self.assertIn("flow_policy_nat_land", (rec / "broken-fw2-show_counter_global_filter_delta_yes_severity_drop.txt").read_text())
        r = self.bh("heal", "4a")
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-2000:])
        verdict = (self.last_set("heal-4a") / "verdict.txt").read_text()
        for line in ("  PASS  fw: nat rule no-nat-public set from the render and moved before internet-snat",
                     "  PASS  node-public: every ping succeeds (10 of 10)",
                     "  PASS  fw: flow_policy_nat_land did not rise across node-public's passes"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  fw: the running rulebase in the render's order \(order: security 25 rules as rendered;order: nat 2 rules as rendered\)")
        self.assertEqual(self.world()["running"]["nat"], ["no-nat-public", "internet-snat"])
        self.assertNotIn("  FAIL  ", verdict)


class FwDrillsShTest(Ch04LabTest):
    def test_both_drills_one_pass(self):
        r = self.run_cmd([self.lab / "drills.sh", "--passes", "1"])
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict)
        for line in ("  PASS  pass 1 land: without it, 0 of 5 answered: the firewall discards every request",
                     "  PASS  pass 1 land: ... and flow_policy_nat_land rose by 5 while 5 requests were sent",
                     "  PASS  pass 1 land: the drop stage captured 5 frame(s) from 10.20.1.12 to 198.51.100.2 (diag/drop.decode.txt)",
                     "  PASS  pass 1 land: the host-side captures saw 5 requests arrive at the firewall (eth1 5) and 0 replies leave it",
                     "  PASS  pass 1 land: with it back, 5 of 5 answered",
                     "  PASS  pass 1 ntp-uplink: the firewall's own NTP from 198.51.100.2 (ethernet1/5) to 10.20.13.21:123 logged under "
                     "deny-all-log, deny, zone uplink to zone services",
                     "  PASS  pass 1 ntp-uplink: with the route back, the firewall's NTP from 10.20.13.1 allowed again by inside-to-ntp",
                     "  PASS  pass 1 ntp-uplink: the dns service route set to ethernet1/5 (198.51.100.2) with it: its server is the same address",
                     "  PASS  pass 1 ntp-uplink: the firewall's own DNS from 198.51.100.2 to 10.20.13.21:53 (a name looked up through it) "
                     "logged under deny-all-log, deny, zone uplink to zone services",
                     "  PASS  pass 1 ntp-uplink: with the route back, the firewall's DNS from 10.20.13.1 allowed again by inside-to-resolvers"):
            self.assertIn(line, verdict)
        w = self.world()
        self.assertEqual((w["running"]["nat"], w["running"]["ntp_if"], w["running"]["dns_if"]),
                         (["no-nat-public", "internet-snat"], "ae1.130", "ae1.130"))
        self.assertTrue(all(c["stopped"] for c in w["captures"].values()))
        self.assertEqual(w["pcaps"], {}, "packet-diag's files deleted again")
        md = (rs / "DRILLS.md").read_text()
        self.assertIn("## land: ", md)
        self.assertIn("| 1 | yes | 5 of 5 | 0 | 0 of 5 | 5 | 5 | 5 of 5 | 0 |", md)
        self.assertEqual(self.leftover_shims(), [])

    def test_a_refused_commit_still_restores(self):
        # the commit that would remove the rule is refused: the drill stops there, and the restore it
        # pushed first sets the rendered rule back, moves it and commits
        r = self.run_cmd([self.lab / "drills.sh", "--drills", "land", "--passes", "1"], env={"SHIM_CH04_COMMIT_FAIL": "removed"})
        self.assertEqual(r.returncode, 1, r.stdout[-3000:])
        verdict = (self.last_set("drills") / "verdict.txt").read_text()
        self.assertIn("  FAIL  pass 1 land: committed: sfab drill land: no-nat-public removed -> commit refused: shim: commit refused", verdict)
        self.assertRegex(verdict, r"  PASS  pass 1 land: committed: sfab drill land: no-nat-public back where the render puts it")
        w = self.world()
        self.assertEqual(w["running"]["nat"], ["no-nat-public", "internet-snat"])
        self.assertEqual(w["candidate"]["nat"], w["running"]["nat"])


class FwTraceShTest(Ch04LabTest):
    def test_trace_green(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-5000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("FAIL", verdict, verdict)
        for line in ("  PASS  show session all lists it: 192.0.2.2[42444] to 10.20.11.200[443] (id 43444)",
                     "  PASS  show session id names the security rule operator-to-internal-gateway",
                     "  PASS  ... its source rewritten to 198.51.100.2 (port 51000 became 18011), its destination 192.0.2.6:5000 unchanged"):
            self.assertIn(line, verdict)
        for f in ("TRACE.md", "sessions/operator/session-detail.txt", "pull/captures/2-fw-ethernet1-5.txt", "trace.json"):
            self.assertTrue((rs / f).is_file(), f)
        self.assertEqual(self.leftover_shims(), [])


class FwEdgeShTest(Ch04LabTest):
    def test_collect_and_fw_edge(self):
        rs = self.t / "set"
        rs.mkdir()
        script = (f". {COMMON}/lib.sh; sfab_init audit --set {rs}; . {COMMON}/audit/lib-audit.sh; "
                  "audit_collect fw uplink-rtr; audit_fw_edge k8s-cp2; summary")
        r = self.run_cmd(["bash", "-c", script], timeout=600)
        out = r.stdout
        self.assertIn("== fw: rule order (chapter 4)", out, out[-4000:] + r.stderr[-2000:])
        for line in ("  PASS  no-nat-public sits above internet-snat",
                     "  PASS  flow_policy_nat_land is in this firewall's own show counter global table",
                     "  PASS  flow_policy_nat_land did not rise while k8s-cp2 (10.20.1.12) sent them (no-nat-public keeps the source)",
                     "  PASS  the bastion from its own address 10.20.3.10 reaches HTTPS on 10.20.3.1 (HTTP 200)",
                     "  PASS  HTTPS on 10.20.3.1 does not answer another inside host, k8s-cp2 (10.20.1.12) (HTTP 000)",
                     "  PASS  ntp to 10.20.13.21 leaves from ae1.130 (10.20.13.1/24)",
                     "  PASS  the firewall resolved bastion.ai.tarnwick.example through its DNS service route",
                     "  PASS  10.20.9.0/24 via 198.51.100.2 (dec-route-inside-via-fw): static, selected",
                     "  PASS  ... and the firewall logged it under deny-all-log, zone operator-vpn to ingress",
                     "  PASS  k8s-cp2 (10.20.1.12) to web-client, an internet host, on 192.0.2.18:443: refused (failed: timed out after 4 s)",
                     "  PASS  ... logged under deny-all-log, deny, zone k8s-nodes to uplink (no rule admits the inside to an internet host "
                     "but the registry and the time source)"):
            self.assertIn(line, out)
        fails = [l for l in out.splitlines() if l.startswith("  FAIL  ") and ("fw-edge" in l or "chapter 4" in l)]
        self.assertEqual(fails, [])
        # the operator's traffic log reads, one per destination port, and the client's view of each
        # forbidden cell, under their own names; no read is named for a numbered decision
        names = sorted(p.name for p in (rs / "fw-edge").iterdir())
        tl = [n for n in names if "tlog-" in n and not n.startswith("egress-")]
        self.assertTrue(tl)
        self.assertEqual([n for n in tl if not n.startswith("operator-cells-tlog-")], [], tl)
        self.assertIn("egress-tlog-443.txt", names)
        self.assertEqual(plan_egress := load(rs / "fw-edge" / "plan.json")["egress"],
                         {"client": "web-client", "addr": "192.0.2.18", "port": 443, "rule": "deny-all-log", "from_zone": "k8s-nodes",
                          "to_zone": "uplink"}, plan_egress)
        plan = load(rs / "fw-edge" / "plan.json")
        self.assertEqual(len(plan["cells"]), len(CELLS))
        cells = {n for n in names if n.startswith("operator-cells-") and n not in tl}
        self.assertEqual(cells, {f"operator-cells-{c['id']}.txt" for c in plan["cells"]}, names)
        self.assertEqual([n for n in names if re.search(r"[Dd]ecisions?[ _-]?\d", n)], [], names)
        edge = [l for l in out.split("== fw: zone bindings (chapter 4)", 1)[1].splitlines() if l.startswith("  FAIL  ")]
        self.assertEqual(edge, [], out[-4000:])


if __name__ == "__main__":
    unittest.main()
