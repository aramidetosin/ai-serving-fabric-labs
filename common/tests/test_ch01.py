"""Chapter 1's lab harness (ch01/): the request walk's tools (common/trace/walktrace.py and
lib-walktrace.sh, syn_connect.py, hold_request.py's POST) and break-1a's checks (common/breakheal.py
synat, tlogcmd and tlogrule). Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_ch01*.py'

The judge is fed made-up evidence in the shapes the lab's devices print (the firewall's routing
table, rulebases and traffic log as chapter 4's and 7's sets recorded them, KLISH's counters and MAC
tables, dig, and tcpdump -nn -tt -e -v -S decodes), built from ch01's committed plan and inventory,
so the figures asserted here are the fixtures', never the lab's. No device, no lab and no PyYAML are
needed: the plan and the inventory are the committed render's JSON.
"""

from __future__ import annotations

import contextlib
import io
import json
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
CH01 = ROOT / "ch01"
sys.path.insert(0, str(COMMON / "trace"))
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ch04_world as W4  # noqa: E402
import hold_request as HR  # noqa: E402
import vocab  # noqa: E402
import walktrace as WT  # noqa: E402

PLAN = json.loads((CH01 / "gen" / "trace.json").read_text())
INV = json.loads((CH01 / "gen" / "inventory.json").read_text())
HOLDER = "k8s-ingress1"
HMAC = INV["nodes"][HOLDER]["bond"]["mac"]
C_MAC, FW4_MAC, AE_MAC = "02:42:ac:15:28:51", "aa:c1:ab:00:00:04", "ba:db:ee:fb:ad:f0"

ROUTES = """admin@fw> show routing route

flags: A:active, ?:loose, C:connect, H:host, S:static, ~:internal, R:rip, O:ospf, B:bgp,
       Oi:ospf intra-area, Oo:ospf inter-area, O1:ospf ext-type-1, O2:ospf ext-type-2, E:ecmp, M:multicast


VIRTUAL ROUTER: core (id 2)
  ==========
destination                                 nexthop                                 metric flags      age   interface          next-AS
0.0.0.0/0                                   198.51.100.1                            10     A S              ethernet1/5
10.0.0.0/8                                  discard                                 10     A S
10.20.1.0/24                                10.20.1.1                               0      A C              ae1.100
10.20.1.1/32                                0.0.0.0                                 0      A H
10.20.11.0/24                               10.20.11.1                              0      A C              ae1.110
10.20.11.1/32                               0.0.0.0                                 0      A H
10.24.10.8/30                               10.24.10.9                              0      A C              ethernet1/4
10.24.10.9/32                               0.0.0.0                                 0      A H
total routes shown: 8
"""


def policy(name, index, frm, src, to, dst, svc, action):
    return (f'"{name}; index: {index}" {{\n        from {frm};\n        source {src};\n        source-region none;\n        to {to};\n'
            f"        destination {dst};\n        destination-region none;\n        user any;\n        category any;\n"
            f"        application/service {svc};\n        action {action};\n        icmp-unreachable: no\n        terminal yes;\n}}\n")


SECURITY = ("admin@fw> show running security-policy\n\n"
            + policy("staff-to-users-gateway", 1, "enterprise", "10.24.10.0/24", "ingress", "10.20.11.210", "0:ssl/tcp/any/443", "allow") + "\n"
            + policy("ent-dns-to-platform-dns", 2, "enterprise", "10.24.10.53", "services", "[ 10.20.13.11 10.20.14.11 ]",
                     "[0:dns/tcp/any/53 1:dns/udp/any/53 ]", "allow") + "\n"
            + policy("deny-all-log", 21, "any", "any", "any", "any", "0:any/any/any/any", "deny"))
NAT = """admin@fw> show running nat-policy

Nat policy configured on vsys1:
"no-nat-public; index: 1" {
        nat-type ipv4;
        from [ k8s-nodes services ];
        source any;
        to uplink;
        destination 198.51.100.2;
        service 0:any/any/any;
        terminal no;
}

"internet-snat; index: 2" {
        nat-type ipv4;
        from [ k8s-nodes services ];
        source any;
        to uplink;
        destination any;
        service 0:any/any/any;
        terminal no;
}
"""
COUNTERS = """rail-sw1# show interface counters
------------------------------------------------------------------------------------------------
Interface      State     RX_OK                 RX_ERR                RX_DRP                RX_OVERSIZE           TX_OK                 TX_ERR                TX_DRP                TX_OVERSIZE
------------------------------------------------------------------------------------------------
Ethernet1      U         {a1}                    0                     0                     0                     {b1}                     0                     0                     0
Ethernet5      U         {a5}                    0                     0                     0                     {b5}                     0                     0                     0
"""


def mac_table(rows):
    return ("rail-sw1# show mac address-table\n" + "-" * 59 + "\nVLAN         MAC-ADDRESS         TYPE         INTERFACE\n" + "-" * 59 + "\n"
            + "".join(f"{v:<12}{m}   DYNAMIC       {i}\n" for v, m, i in rows))


def dig(name, server, address):
    return (f"; <<>> DiG 9.18 <<>> {name}\n;; global options: +cmd\n;; Got answer:\n\n;; QUESTION SECTION:\n;{name}.\t\t\tIN\tA\n\n"
            f";; ANSWER SECTION:\n{name}.\t300\tIN\tA\t{address}\n\n;; Query time: 1 msec\n;; SERVER: {server}#53({server}) (UDP)\n")


T0 = 1761000000.0


def frame(t, smac, dmac, src, sport, dst, dport, seq, ttl, ipid, vlan=None, flags="S", length=0):
    eth = (f"ethertype 802.1Q (0x8100), length 78: vlan {vlan}, p 0, ethertype IPv4 (0x0800), " if vlan
           else "ethertype IPv4 (0x0800), length 74: ")
    return (f"{T0 + t:.6f} {smac} > {dmac}, {eth}(tos 0x0, ttl {ttl}, id {ipid}, offset 0, flags [DF], proto TCP (6), length {60 + length})\n"
            f"    {src}.{sport} > {dst}.{dport}: Flags [{flags}], cksum 0x1c2d (incorrect -> 0x5e6f), seq {seq}, win 64240, "
            f"options [mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7], length {length}\n")


def run_judge(fn, *args):
    out = io.StringIO()
    v = vocab.Vocab(verdict="", known=set(), out=out)
    res = fn(v, *args)
    return res, out.getvalue()


def fails(text):
    return [line for line in text.splitlines() if line.startswith("  FAIL  ")]


class SetTest(unittest.TestCase):
    def setUp(self):
        self.rs = Path(tempfile.mkdtemp(prefix="sfab-test-ch01-"))
        self.addCleanup(shutil.rmtree, self.rs, True)
        for d in ("cluster", "captures", "dns", "fw", "pair", "rail", "request", "refuse", "sessions/walk"):
            (self.rs / d).mkdir(parents=True)
        (self.rs / "cluster" / "lease.json").write_text(json.dumps({"spec": {"holderIdentity": HOLDER}}))

    def put(self, rel, text):
        p = self.rs / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


class Parsers(unittest.TestCase):
    def test_routes(self):
        rt = WT.fw_routes(ROUTES)
        best = WT.longest(rt, "10.20.11.210")
        self.assertEqual((best["dest"], best["flags"], best["iface"]), ("10.20.11.0/24", ["A", "C"], "ae1.110"))
        self.assertEqual(WT.longest(rt, "8.8.8.8")["iface"], "ethernet1/5")
        self.assertEqual(WT.longest(rt, "10.20.1.1")["flags"], ["A", "H"])

    def test_policies(self):
        sec = WT.policy_blocks(SECURITY)
        self.assertEqual(sec["staff-to-users-gateway"]["index"], 1)
        f = sec["staff-to-users-gateway"]["fields"]
        self.assertEqual((f["from"][0], f["to"][0], f["destination"][0], f["action"][0], f["application/service"][0]),
                         ("enterprise", "ingress", "10.20.11.210", "allow", "0:ssl/tcp/any/443"))
        self.assertNotIn("icmp-unreachable:", f)
        nat = WT.policy_blocks(NAT)
        self.assertEqual(nat["internet-snat"]["fields"]["from"][0], "[ k8s-nodes services ]")

    def test_counters_and_dig(self):
        c = WT.counters_table(COUNTERS.format(a1=10, b1=12, a5=7, b5=9))
        self.assertEqual(c["Ethernet5"]["rx_ok"], 7)
        self.assertEqual(c["Ethernet1"]["tx_ok"], 12)
        d = WT.dig(dig("llm.tarnwick.example", "10.20.3.10", "10.20.1.210"))
        self.assertEqual((d["server"], d["answers"][0]["address"], d["answers"][0]["name"]), ("10.20.3.10", "10.20.1.210", "llm.tarnwick.example"))

    def test_packets(self):
        text = frame(1.5, AE_MAC, HMAC, "10.24.10.10", 42106, "10.20.11.210", 443, 1000, 63, 77, vlan=110)
        text += frame(1.6, HMAC, AE_MAC, "10.20.11.210", 443, "10.24.10.10", 42106, 5000, 64, 0, vlan=110, flags="S.")
        pk = WT.packets(text)
        self.assertEqual((pk[0]["vlan"], pk[0]["ttl"], pk[0]["ipid"], pk[0]["seq"], pk[0]["flags"], pk[0]["line"]), (110, 63, 77, 1000, "S", 1))
        self.assertEqual(len(WT.syns(pk)), 1)
        self.assertEqual(len(WT.syns(pk, seq=1000, sport=42106)), 1)
        self.assertEqual(WT.syns(pk, sport=1), [])

    def test_dechunk_and_yaml_block(self):
        self.assertEqual(WT.dechunk('5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n'), "hello world")
        self.assertEqual(WT.dechunk('{"a": 1}'), '{"a": 1}')
        text = "routes:\n  - id: chat\n    uris: [/x]\n    plugins:\n      consumer-restriction:\n        whitelist:\n          - chat\n  - id: staff\n    uris: [/y]\n"
        line, block = WT.yaml_block(text, r"^\s*- id: chat\s*$")
        self.assertEqual(line, 2)
        self.assertEqual(block[-1].strip(), "- chat")


class Points(SetTest):
    def test_frontend_then_serving(self):
        rows = WT.frontend_rows(PLAN, self.rs, INV)
        ids = [r[0] for r in rows]
        self.assertEqual(ids, ["1-ent-client-eth1", "2-fw-ethernet1-4", "3-fw-ae1-leg1", "3-fw-ae1-leg2", "4-fe-sw1-Ethernet2",
                               "4-fe-sw2-Ethernet2", "5-fe-sw1-Ethernet13", "5-fe-sw2-Ethernet13"])
        self.assertTrue(all(r[1] == "host" and r[6].startswith("(host 10.24.10.10 and") and "or (vlan and (" in r[6] for r in rows))
        r = subprocess.run([sys.executable, str(COMMON / "trace" / "walktrace.py"), "points", "--plan", str(CH01 / "gen" / "trace.json"),
                            "--set", str(self.rs), "--inv", str(CH01 / "gen" / "inventory.json")], capture_output=True, text=True, check=True)
        ids = [line.split("\t")[0] for line in r.stdout.splitlines()]
        self.assertEqual(ids[8], "6-k8s-ingress1-bond0")
        self.assertIn("11-rail-sw1-Ethernet7", ids, "the port facing k8s-gpu2 on rail 7, where chat c's worker0 runs")


class Wire(SetTest):
    SEQ = 3141592653

    def caps(self, legs=(1,), ttl_leg=63):
        c, v, s = "10.24.10.10", "10.20.11.210", 42106
        out = {"1-ent-client-eth1": frame(10.0, C_MAC, FW4_MAC, c, s, v, 443, self.SEQ, 64, 4242),
               "2-fw-ethernet1-4": frame(10.0001, C_MAC, FW4_MAC, c, s, v, 443, self.SEQ, 64, 4242)}
        for k in (1, 2):
            sw = f"fe-sw{k}"
            f = frame(10.001, AE_MAC, HMAC, c, s, v, 443, self.SEQ, ttl_leg, 4242, vlan=110) if k in legs else ""
            out[f"3-fw-ae1-leg{k}"] = f
            out[f"4-{sw}-Ethernet2"] = f
            # the ingress node's bond carries the Gateway VLAN tagged (its bond0.110 unit)
            out[f"5-{sw}-Ethernet13"] = f
        out["6-k8s-ingress1-bond0"] = frame(10.002, AE_MAC, HMAC, c, s, v, 443, self.SEQ, ttl_leg, 4242, vlan=110)
        return {k: WT.packets(t) for k, t in out.items()}

    def test_green(self):
        res, out = run_judge(WT.judge_wire, self.rs, PLAN, INV, self.caps(), HOLDER)
        self.assertEqual(fails(out), [], out)
        self.assertIn("  PASS  the same SYN (seq 3141592653) on exactly one leg of ae1: 3-fw-ae1-leg1 (ethernet1/1), captured on both", out)
        self.assertIn("TTL 63: one lower, the firewall's routed hop", out)
        self.assertEqual(res["server_port"]["id"], "5-fe-sw1-Ethernet13")
        self.assertEqual(res["bond"], "6-k8s-ingress1-bond0")
        self.assertIn("tagged 110, the same frame", out)

    def test_both_legs_or_ttl_kept_fail(self):
        _, out = run_judge(WT.judge_wire, self.rs, PLAN, INV, self.caps(legs=(1, 2)), HOLDER)
        self.assertTrue(any("exactly one leg" in x for x in fails(out)), out)
        _, out = run_judge(WT.judge_wire, self.rs, PLAN, INV, self.caps(ttl_leg=64), HOLDER)
        self.assertTrue(any("one lower" in x for x in fails(out)), out)


class Tables(SetTest):
    def test_names_firewall_pair_rail(self):
        self.put("dns/client-dig.txt", dig("llm.ai.tarnwick.example", "10.24.10.53", "10.20.11.210"))
        self.put("dns/resolver-dig.txt", dig("llm.ai.tarnwick.example", "10.20.13.21", "10.20.11.200"))
        _, out = run_judge(WT.judge_names, self.rs, PLAN)
        self.assertEqual(fails(out), [], out)
        self.assertIn("the view, not the name, picks the Gateway", out)

        self.put("fw/routing-route.txt", ROUTES)
        self.put("fw/running-security-policy.txt", SECURITY)
        self.put("fw/running-nat-policy.txt", NAT)
        saved = WT.FT.judge_session
        WT.FT.judge_session = lambda *a, **k: {}
        try:
            _, out = run_judge(WT.judge_firewall, self.rs, PLAN)
        finally:
            WT.FT.judge_session = saved
        self.assertEqual(fails(out), [], out)
        self.assertIn("  PASS  show running nat-policy: 2 NAT rules, none from zone enterprise: no translation", out)
        self.put("fw/running-nat-policy.txt", NAT.replace("from [ k8s-nodes services ];", "from enterprise;", 1))
        WT.FT.judge_session = lambda *a, **k: {}
        try:
            _, out = run_judge(WT.judge_firewall, self.rs, PLAN)
        finally:
            WT.FT.judge_session = saved
        self.assertTrue(any("no translation" in x for x in fails(out)), out)

        pc = INV["nodes"][HOLDER]["bond"]["pc"]
        for sw in ("fe-sw1", "fe-sw2"):
            self.put(f"pair/{sw}-mac-table.txt", mac_table([(110, HMAC, f"PortChannel{pc}"), (110, AE_MAC, "PortChannel10")]))
        _, out = run_judge(WT.judge_pair, self.rs, PLAN, INV, HOLDER, {})
        self.assertEqual(fails(out), [], out)

        # the copy that spans the nodes (chat c): its worker on k8s-gpu2 is reached across rail-sw1
        copy = next(c for c in PLAN["copies"] if any(x["remote"] for x in c["workers"]))
        w = next(x for x in copy["workers"] if x["remote"])
        far = next(p for p in copy["switch_ports"] if p["faces"] == w["node"])
        near = next(p for p in copy["switch_ports"] if p["faces"] == copy["server"]["node"])
        cnt = COUNTERS.replace("Ethernet5 ", far["native"].ljust(9)).replace("Ethernet1 ", near["native"].ljust(9))
        self.put("rail/stamps.tsv", f"rail-sw1\tbefore\t{T0 + 100}\t{T0 + 101}\nrail-sw1\tafter\t{T0 + 200}\t{T0 + 201}\n")
        self.put("rail/rail-sw1-counters-before.txt", cnt.format(a1=1, b1=1, a5=2, b5=3))
        self.put("rail/rail-sw1-counters-after.txt", cnt.format(a1=40, b1=41, a5=32, b5=33))
        self.put("rail/rail-sw1-mac-table.txt", mac_table([(copy["vlan"], w["mac"], far["native"])]))
        rpc = PLAN["serving"]["rpc_port"]
        dec = "".join(frame(150.0 + i, "02:5a:fe:07:00:64", w["mac"], copy["server"]["address"], 40000, w["address"], rpc, 9 + i, 64, i,
                            flags="P.", length=100) for i in range(20))
        decs = {far["id"]: WT.ST.frames(dec), near["id"]: []}
        res, out = run_judge(WT.judge_rail, self.rs, PLAN, {"copy": copy}, decs)
        self.assertEqual(fails(out), [], out)
        self.assertEqual((res["port"], res["rx"], res["tx"], res["frames"]), (far["native"], 30, 30, 20))
        # fewer frames counted than the capture saw between the reads: the counters were not read right
        self.put("rail/rail-sw1-counters-after.txt", cnt.format(a1=40, b1=41, a5=5, b5=6))
        _, out = run_judge(WT.judge_rail, self.rs, PLAN, {"copy": copy}, decs)
        self.assertEqual(len(fails(out)), 1, out)
        # a node-local copy (chat a): its RPC stays inside its node, and the port facing it carries none
        local = next(c for c in PLAN["copies"] if not any(x["remote"] for x in c["workers"]))
        lp = local["switch_ports"][0]
        res, out = run_judge(WT.judge_rail, self.rs, PLAN, {"copy": local}, {lp["id"]: []})
        self.assertEqual(fails(out), [], out)
        self.assertTrue(res["local"])
        self.assertIn(f"copy {local['copy']} sits inside {local['server']['node']}", out)
        # TRACE.md's hop table takes the node-local result too (chapter 1's first revision 2 trace
        # stopped on a KeyError here and wrote no TRACE.md): its last row names the port facing the node
        names = {"client": {"answers": [], "server_line": 1}}
        rows = WT.hop_table(self.rs, PLAN, HOLDER, names, {}, {}, {}, {"copy": local, "hops": []}, [], {}, res)
        self.assertEqual(rows[-1][0], "14")
        self.assertIn(f"its port {res['port']}, facing {local['server']['node']}", rows[-1][2])
        self.assertIn("no RPC frame", rows[-1][3])
        stray ="".join(frame(150.0, "02:5a:fe:03:00:64", "02:5a:fe:03:00:65", local["server"]["address"], 40000,
                              local["workers"][0]["address"], rpc, 9, 64, 0, flags="P.", length=100))
        _, out = run_judge(WT.judge_rail, self.rs, PLAN, {"copy": local}, {lp["id"]: WT.ST.frames(stray)})
        self.assertEqual(len(fails(out)), 1, out)


class ClusterTables(SetTest):
    ROUTES = ("- id: chat\n  name: chat\n  uris:\n  - {path}\n  plugins:\n    multi-auth:\n      auth_plugins:\n      - key-auth:\n"
              "          header: Authorization\n    consumer-restriction:\n      type: consumer_group_id\n      whitelist:\n"
              "      - batch\n      - staff\n      rejected_code: 401\n- id: staff\n  name: staff\n")

    def lines(self, holder, key_field):
        self.put("cluster/lease.txt", f"NAME   HOLDER   AGE\n{PLAN['gateway']['lease'].split('/')[-1]}   {holder}   5m\n")
        self.put("cluster/api-gateway-routes.yaml", self.ROUTES.format(path=PLAN["path"]))
        self.put("request/key.txt", f"{key_field} sha256:0123456789ab <redacted hmac:0123456789ab>\n")
        _, out = run_judge(WT.judge_cluster, self.rs, PLAN, INV, holder, {})
        return [x for x in out.splitlines() if "held by" in x or "the API gateway's route for" in x]

    def test_lease_on_an_ingress_node_and_the_callers_group(self):
        # revision 2: the L2 announcement policy selects the ingress nodes, and chat's route admits
        # the consumer groups of every caller of chat, the walked key's caller (batch) among them
        got = self.lines(HOLDER, "batch.8d033d03")
        self.assertEqual(len(got), 2, got)
        self.assertTrue(all(x.startswith("  PASS  ") for x in got), got)
        self.assertIn("an ingress node", got[0])
        self.assertIn("the consumer groups batch, staff, the walked key's caller batch among them", got[1])
        got = self.lines("k8s-cp1", "ops.0000")
        self.assertTrue(all(x.startswith("  FAIL  ") for x in got), got)


class PortRefusal(SetTest):
    def test_port_refused_at_the_firewall(self):
        p = PLAN["refusals"]["port"]
        c = PLAN["client"]["address"]
        self.put("refuse/port-result.txt", f"1761000000.000000 0 0 {p['sport']} TIMEOUT 5.004\n")
        syn = frame(20.0, C_MAC, FW4_MAC, c, p["sport"], p["address"], p["port"], 777, 64, 9)
        pk = {"1-ent-client-eth1": WT.packets(syn), "2-fw-ethernet1-4": WT.packets(syn)}
        tl = W4.tlog([("2026/10/26 10:00:00", "incomplete", "enterprise", p["sport"], c, "deny-all-log", "deny", "k8s-nodes", p["port"],
                       p["address"], "policy-deny")])
        self.put(f"fw/traffic-log-{p['port']}.txt", tl)
        rows = WT.frontend_rows(PLAN, self.rs, INV) + WT.ST.point_rows(PLAN, self.rs)
        _, out = run_judge(WT.judge_refusals, self.rs, PLAN, INV, pk, {"pi": {}}, rows)
        part = out.split("refused at the firewall")[1]
        self.assertEqual(fails(part), [], part)
        self.assertIn("the traffic log names deny-all-log (shown as deny-all-log), deny, zone enterprise to zone k8s-nodes", part)
        # the same SYN past the firewall, on a leg: the refusal did not hold there
        pk["3-fw-ae1-leg1"] = WT.packets(syn)
        _, out = run_judge(WT.judge_refusals, self.rs, PLAN, INV, pk, {"pi": {}}, rows)
        self.assertTrue(any("nothing past the firewall" in x for x in fails(out.split("refused at the firewall")[1])), out)


class Cli(SetTest):
    def wt(self, *args, stdin=None):
        return subprocess.run([sys.executable, str(COMMON / "trace" / "walktrace.py"), *map(str, args)], input=stdin, capture_output=True, text=True)

    def test_cmdata_split_tlog(self):
        r = self.wt("cmdata", "--key", "config.yaml", stdin=json.dumps({"data": {"config.yaml": "model_list: []"}}))
        self.assertEqual((r.returncode, r.stdout), (0, "model_list: []\n"))
        self.assertEqual(self.wt("cmdata", "--key", "x", stdin="{}").returncode, 1)
        shutil.copy(CH01 / "gen" / "trace.json", self.rs / "trace.json")
        self.put("sessions/walk/request.txt", "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n"
                 "b\r\n{\"id\": \"x\"}\r\n0\r\n\r\n\nHELD 1761000000.5\nCLOSED 1761000030.5\n")
        self.assertEqual(self.wt("split-reply", "--set", self.rs).returncode, 0)
        self.assertEqual((self.rs / "request" / "result.txt").read_text(), f"200 {PLAN['sport']}\n")
        self.assertEqual(json.loads((self.rs / "request" / "body.json").read_text()), {"id": "x"})
        tl = W4.tlog([("2026/10/26 10:00:00", "ssl", "enterprise", 42107, "10.24.10.10", "staff-to-users-gateway", "allow", "ingress", 443,
                       "10.20.11.210")])
        self.put("fw/tl.txt", tl)
        self.assertEqual(self.wt("tlog-has", "--file", self.rs / "fw" / "tl.txt", "--src", "10.24.10.10", "42107").returncode, 0)
        self.assertEqual(self.wt("tlog-has", "--file", self.rs / "fw" / "tl.txt", "--src", "10.24.10.10", "42107", "42108").returncode, 1)


class Break1aChecks(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="sfab-test-ch01-break-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        self.breaks = CH01 / "gen" / "breaks.json"
        b = json.loads(self.breaks.read_text())["breaks"]["1a"]
        self.p = next(a for a in b["record"] if a["kind"] == "probe_syn")
        self.broken = {a["kind"]: a for a in b["expect_broken"] if a["kind"] in ("syn_at", "tlog_rule")}
        self.healed = {a["kind"]: a for a in b["expect_healed"] if a["kind"] in ("syn_at", "tlog_rule")}

    def bh(self, *args):
        return subprocess.run([sys.executable, str(COMMON / "breakheal.py"), *map(str, args)], capture_output=True, text=True)

    def probe(self, mode, at, first):
        p = self.p
        log = "".join(f"1761000000.{i:06d} {i} 0 {first + i} TIMEOUT 5.001\n" for i in range(p["count"]))
        (self.d / f"syn-{mode}-pass1.log").write_text(log)
        for c in p["capture"]:
            text = "".join(frame(30.0 + i, C_MAC, FW4_MAC, p["client_addr"], first + i, p["dst_addr"], p["port"], 100 + i, 64, i,
                                 vlan=100 if c["id"] != "fw-ethernet1-4" else None)
                           for i in range(p["count"])) if c["id"] in at else ""
            (self.d / f"syn-{mode}-pass1-{c['id']}.txt").write_text(text)

    def test_synat(self):
        self.probe("break", {"fw-ethernet1-4"}, self.p["sport"])
        r = self.bh("synat", "--breaks", self.breaks, "--id", "1a", "--dir", self.d, "--mode", "break", "--check", json.dumps(self.broken["syn_at"]))
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("fw-ethernet1-4 3, fw-ethernet1-1 0, fw-ethernet1-2 0", r.stdout)
        self.probe("break", {"fw-ethernet1-4", "fw-ethernet1-2"}, self.p["sport"])
        r = self.bh("synat", "--breaks", self.breaks, "--id", "1a", "--dir", self.d, "--mode", "break", "--check", json.dumps(self.broken["syn_at"]))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.probe("heal", {"fw-ethernet1-4", "fw-ethernet1-2"}, self.p["sport"] + 3)
        r = self.bh("synat", "--breaks", self.breaks, "--id", "1a", "--dir", self.d, "--mode", "heal", "--check", json.dumps(self.healed["syn_at"]))
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_tlog(self):
        r = self.bh("tlogcmd", "--breaks", self.breaks, "--id", "1a", "--probe", "syn")
        self.assertEqual(r.stdout.strip(), "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443")
        p, sp = self.p, self.p["sport"]
        self.probe("break", {"fw-ethernet1-4"}, sp)
        f = self.d / "tl.txt"
        f.write_text(W4.tlog([("2026/10/26 10:00:00", "incomplete", "enterprise", sp + i, p["client_addr"], "deny-all-log", "deny", "ingress", 443,
                               p["dst_addr"]) for i in range(2)]))
        chk = json.dumps(self.broken["tlog_rule"])
        r = self.bh("tlogrule", "--breaks", self.breaks, "--id", "1a", "--dir", self.d, "--mode", "break", "--file", f, "--check", chk)
        self.assertEqual((r.returncode, r.stdout.split()[0]), (1, "missing"))
        f.write_text(W4.tlog([("2026/10/26 10:00:00", "incomplete", "enterprise", sp + i, p["client_addr"], "deny-all-log", "deny", "ingress", 443,
                               p["dst_addr"]) for i in range(3)]))
        r = self.bh("tlogrule", "--breaks", self.breaks, "--id", "1a", "--dir", self.d, "--mode", "break", "--file", f, "--check", chk)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("logged 3 connects", r.stdout)
        f.write_text(W4.tlog([("2026/10/26 10:00:00", "ssl", "enterprise", sp + i, p["client_addr"], "staff-to-users-gateway", "allow",
                               "ingress", 443, p["dst_addr"]) for i in range(3)]))
        r = self.bh("tlogrule", "--breaks", self.breaks, "--id", "1a", "--dir", self.d, "--mode", "break", "--file", f, "--check", chk)
        self.assertEqual((r.returncode, r.stdout.split()[0]), (1, "wrong"))


class ClientTools(unittest.TestCase):
    def test_syn_connect(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        threading.Thread(target=lambda: [srv.accept()[0].close() for _ in range(1)], daemon=True).start()
        def free_port():
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            n = s.getsockname()[1]
            s.close()
            return n

        closed = free_port()
        sp = free_port()
        while sp in (port, closed) or sp + 2 in (port, closed):
            sp = free_port()
        r = subprocess.run([sys.executable, str(COMMON / "trace" / "syn_connect.py"), "127.0.0.1", str(port), str(sp), "1", "2", "0"],
                           capture_output=True, text=True, check=True)
        f = r.stdout.split()
        self.assertEqual((f[1], f[2], f[3], f[4]), ("0", "1", str(sp), "CONNECTED"))
        r = subprocess.run([sys.executable, str(COMMON / "trace" / "syn_connect.py"), "127.0.0.1", str(closed), str(sp + 1), "2", "2", "0"],
                           capture_output=True, text=True, check=True)
        lines = r.stdout.splitlines()
        self.assertEqual([x.split()[4] for x in lines], ["REFUSED", "REFUSED"])
        self.assertEqual([x.split()[3] for x in lines], [str(sp + 1), str(sp + 2)])
        srv.close()

    def test_hold_request_post(self):
        d = Path(tempfile.mkdtemp(prefix="sfab-test-ch01-hold-"))
        self.addCleanup(shutil.rmtree, d, True)
        (d / "body.json").write_text('{"model": "chat"}\n')
        (d / "hdr").write_text("Authorization: Bearer sk-made-up\n\n")
        b = HR.request_bytes("llm.tarnwick.example", "/models/x/v1/chat/completions", "POST", str(d / "body.json"), str(d / "hdr"))
        head, _, body = b.partition(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        self.assertEqual(lines[0], "POST /models/x/v1/chat/completions HTTP/1.1")
        self.assertIn("Content-Length: 18", lines)
        self.assertIn("Authorization: Bearer sk-made-up", lines)
        self.assertEqual(lines[-1], "Connection: keep-alive")
        self.assertEqual(body, b'{"model": "chat"}\n')
        self.assertTrue(HR.request_bytes("h", "/p").startswith(b"GET /p HTTP/1.1\r\nHost: h\r\n"))


class ModelListPolls(SetTest):
    def test_a_routers_model_list_read_is_set_aside(self):
        # the router's own GET /v1/models, as the walk's keyed router capture decodes it with -A
        sys.path.insert(0, str(COMMON / "trace"))
        import servetrace as ST  # noqa: PLC0415

        req = ("{t:.6f} be:07:01:d9:f5:f0 > 0a:96:bd:07:b7:34, ethertype IPv4 (0x0800), length 299: (tos 0x0, ttl 64, id 51088, offset 0, "
               "flags [DF], proto TCP (6), length 285)\n"
               "    10.22.1.109.{sport} > 10.22.1.194.8080: Flags [P.], cksum 0x186a (incorrect -> 0x9213), seq 1:234, ack 1, win 488, "
               "options [nop,nop,TS val 2 ecr 1], length 233: HTTP, length: 233\n"
               "\t{method} {path} HTTP/1.1\n\thost: chat.serving.svc.cluster.local:8080\n\tuser-agent: litellm/1.104.0\n\n")
        router = ST.pid(PLAN, 3, "router-x-eth0")
        self.put(f"captures/{router}-payload.txt", req.format(t=T0, sport=45644, method="GET", path="/v1/models")
                 + req.format(t=T0 + 1, sport=45650, method="POST", path="/v1/chat/completions"))
        self.put("captures/7-api-gateway-x-eth0-payload.txt", req.format(t=T0, sport=1, method="GET", path="/v1/models"))
        rows = [[router, "", "", "", "", "", "", "", "1"], ["7-api-gateway-x-eth0", "", "", "", "", "", "", "", "1"],
                [ST.pid(PLAN, 4, "chat-a-server-eth0"), "", "", "", "", "", "", "", ""]]
        self.assertEqual(ST.model_list_polls(self.rs, PLAN, rows), {("10.22.1.109", 45644)})


class Scripts(unittest.TestCase):
    def test_shell_parses(self):
        for f in (COMMON / "trace" / "lib-walktrace.sh", CH01 / "trace.sh", CH01 / "audit.sh"):
            r = subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{f}: {r.stderr}")
        if shutil.which("shellcheck"):
            r = subprocess.run(["shellcheck", "-x", "-P", str(ROOT), str(COMMON / "trace" / "lib-walktrace.sh")], capture_output=True, text=True,
                               cwd=ROOT)
            self.assertEqual(r.returncode, 0, r.stdout[-3000:])

    # the session's stand-in prints each line it reads with the wall clock it read it at; the test takes
    # its own reading first, so a stand-in slow to start (a busy machine) shortens no measured interval
    STANDIN = ("import sys, time\n"
               "for l in sys.stdin:\n    print('%.3f %s' % (time.time(), l.strip()), flush=True)\n")

    def _session_lines(self, pace):
        script = r'''
            . "$1/lib.sh"
            _SESSION_PACE="$2" _session sw klish $'terminal length 0\nclear counters interface all\ny\nexit' python3 -c "$3"
        '''
        start = time.time()
        r = subprocess.run(["bash", "-c", script, "x", str(COMMON), pace, self.STANDIN], capture_output=True, text=True,
                           check=True, timeout=60)
        return [(float(l.split(" ", 1)[0]) - start, l.split(" ", 1)[1]) for l in r.stdout.splitlines() if l]

    def test_paced_session_types_each_line_after_the_last(self):
        # the counter clear's exit must reach KLISH after the confirmation is answered (lib.sh _paced).
        # _paced sleeps a full pace before each line after the first, so line n cannot be read sooner
        # than n paces after the session started, however late the stand-in reads; the gaps between
        # reads are not compared, since a stand-in that starts late reads the waiting lines together
        lines = self._session_lines("1")
        self.assertEqual([l for _, l in lines], ["terminal length 0", "clear counters interface all", "y", "exit"])
        for n, (t, line) in enumerate(lines):
            self.assertGreaterEqual(t, n * 1.0 - 0.01, f"line {n + 1} ({line!r}) read before {n} paces had passed")
        # unpaced, the lines are written at once and read together
        lines = self._session_lines("")
        self.assertEqual(len(lines), 4)
        self.assertLess(lines[-1][0] - lines[0][0], 0.8)

    def test_walk_paces_the_clear_and_containerlab_checks_no_release(self):
        src = (COMMON / "trace" / "lib-walktrace.sh").read_text()
        self.assertIn('_SESSION_PACE="${WT_CLEAR_PACE_S:-5}" SW "$sw" "clear counters interface all" "y"', src)
        r = subprocess.run(["bash", "-c", '. "$1/lib.sh"; printf %s "$CLAB_VERSION_CHECK"', "x", str(COMMON)],
                           capture_output=True, text=True, check=True)
        self.assertEqual(r.stdout, "disable")


if __name__ == "__main__":
    unittest.main()
