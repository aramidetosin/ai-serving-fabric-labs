"""Chapter 2's lab harness (ch02/): the matrix's tools (common/matrix/matrix.py and matrix.sh), the
label run's judge (common/matrix/label.py and label.sh), break-2a's cell_mode check (common/breakheal.py
cellmode) and the walk's row tags (common/trace/walktrace.py). Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_ch02*.py'

The judges are fed made-up evidence in the shapes the lab's devices print (dig and getent, the
firewall's traffic log and rulebases as chapter 4's sets recorded them, FRR's show ip route, curl's
write-out line and the answers' headers and bodies, kubectl's JSON), built from ch02's committed plan,
so the figures asserted here are the fixtures', never the lab's. No device, no lab and no PyYAML are
needed: the plans are the committed render's JSON.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
CH02 = ROOT / "ch02"
sys.path.insert(0, str(COMMON / "matrix"))
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ch04_world as W4  # noqa: E402
import label as LB  # noqa: E402
import matrix as MX  # noqa: E402

PLAN = json.loads((CH02 / "gen" / "matrix.json").read_text())
DEC = json.loads((CH02 / "gen" / "decisions.json").read_text())
MXPY = COMMON / "matrix" / "matrix.py"
T0 = "1761000000.000000"


INV = json.loads((CH02 / "gen" / "inventory.json").read_text())


def zone_of(a: str) -> str:
    """The firewall zone whose interface subnet holds address a (the zone a denied flow is logged to)."""
    import ipaddress  # noqa: PLC0415
    fwn = INV["nodes"][INV["stages"]["fw"]]
    for i in fwn["interfaces"].values():
        if i.get("address") and i.get("zone") and ipaddress.ip_address(a) in ipaddress.ip_interface(i["address"]).network:
            return i["zone"]
    return "uplink"


def dig(name: str, a: str, server: str) -> str:
    return (f"; <<>> DiG 9.18 <<>> {name}\n;; ANSWER SECTION:\n{name}.\t\t300\tIN\tA\t{a}\n\n"
            f";; SERVER: {server}#53({server}) (UDP)\n")


class World:
    """A matrix run's evidence, every cell as the plan computes it unless told otherwise."""

    def __init__(self, d: Path, plan=PLAN, override=None, answers=None, gwlog=True, drops=True):
        self.d, self.plan, self.ov, self.answers = d, plan, override or {}, answers or {}
        for x in ("lookups", "requests", "fw", "routers", "api-gateway"):
            (d / x).mkdir(parents=True, exist_ok=True)
        rows = {r["id"]: r for r in plan["rows"]}
        tsv, tl = [], {}
        # a name the population's view holds no record for has no answer (NXDOMAIN), unless told otherwise
        nx = {(c["row"], c.get("hostname")) for c in plan["cells"] if (c.get("lookup") or {}).get("expect") == "nxdomain"}
        for r, c, k, h in MX.lookups(plan):
            row = rows[r]
            a = self.answers.get((r, h), None if (r, h) in nx else row["answer"])
            if a is None:
                text = "" if k == "vm-node" else (f"; <<>> DiG 9.18 <<>> {h}\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n"
                                                    f";; SERVER: {row['resolver_address']}#53({row['resolver_address']}) (UDP)\n")
            else:
                text = f"{a}      STREAM {h}\n{a}      DGRAM  \n" if k == "vm-node" else dig(h, a, row["resolver_address"])
            (d / "lookups" / f"{MX.slug(r)}-{MX.slug(h)}.txt").write_text(text)
        for c in plan["cells"]:
            mode = self.ov.get(c["id"], c["mode"])
            for q in c["requests"]:
                t = MX.tag(c["id"], q["id"], 1)
                kind = "connect" if q["id"] == "connect" else "http"
                tsv.append("\t".join((t, c["id"], q["id"], "1", str(q["sport"]), kind)))
                dst = self.answers.get((c["row"], c.get("hostname")), c.get("address"))
                if kind == "connect":
                    ok = mode == "allowed"
                    line = f"{T0} 0 {1 if ok else 0} {q['sport']} {'CONNECTED' if ok else 'TIMEOUT'} {'0.002' if ok else '4.004'}\n"
                    (d / "requests" / f"{t}.txt").write_text(line)
                else:
                    st = {"allowed": 200, "404": 404}.get(mode) if q["id"] != "other" else 401
                    if mode in ("log-line", "silence"):
                        st = None
                    if st:
                        (d / "requests" / f"{t}.txt").write_text(f"{st} {dst} 0.120\nexit 0\n")
                        (d / "requests" / f"{t}-headers.txt").write_text(f"HTTP/1.1 {st} x\nserver: envoy\n")
                        # the API gateway's one refusal of a credential, as the render configures it
                        body = json.dumps({"message": PLAN["api_gateway"]["rejected"]["message"]}) if st == 401 else '{"choices": []}'
                        (d / "requests" / f"{t}-body.txt").write_text(body)
                    else:
                        (d / "requests" / f"{t}.txt").write_text("000  4.005\ncurl: (28) Connection timed out after 4004 milliseconds\nexit 28\n")
                if mode == "log-line":
                    fw = c.get("fw") or c["expect"]
                    rule = c["expect"].get("rule", "deny-all-log") if c["mode"] == "log-line" else "deny-all-log"
                    frm = fw.get("from_zone", "enterprise")
                    to = fw.get("to_zone") or zone_of(dst)
                    if c["mode"] != "log-line":
                        to = zone_of(dst)
                    tl.setdefault(c["port"], []).append(("2026/10/27 10:00:00", "incomplete", frm, q["sport"], c["client_addr"], rule, "deny", to,
                                                         c["port"], dst))
        (d / "requests.tsv").write_text("\n".join(tsv) + "\n")
        for port, es in tl.items():
            (d / "fw" / f"traffic-log-{port}.txt").write_text(W4.tlog(es))
        rt = ["Codes: K - kernel route, C - connected, S - static", ""]
        for c in plan["cells"]:
            for h in c["hops"]:
                if h.get("via") and h["device"] in plan["routers"]:
                    rt.append(f"S>* {h['dest']} [1/0] via {h['via']}, eth1, weight 1, 00:10:00")
        for r in plan["routers"]:
            (d / "routers" / f"{r}-ip-route.txt").write_text("\n".join(dict.fromkeys(rt)) + "\n")
        # the firewall's routing table as show routing route prints it: the RFC 1918 discard routes
        (d / "fw" / "routing-route.txt").write_text(
            "VIRTUAL ROUTER: core (id 2)\n  ==========\n"
            "destination                                 nexthop                                 metric flags      age   interface          next-AS\n"
            "0.0.0.0/0                                   198.51.100.1                            10     A S              ethernet1/5\n"
            "10.0.0.0/8                                  discard                                 10     A S\n"
            "10.20.1.0/24                                10.20.1.1                               0      A C              ae1.100\n"
            "172.16.0.0/12                               discard                                 10     A S\n"
            "192.0.2.0/30                                0.0.0.0                                 10     A S              tunnel.1\n"
            "192.168.0.0/16                              discard                                 10     A S\n")
        # the drop counters' delta view over the run, as show counter global filter delta yes
        # severity drop prints it: the strict IP check's drops of the operator's cells outside the tunnel
        if drops:
            (d / "fw" / "drops.txt").write_text(
                "Global counters:\nElapsed time since last sampling: 61.204 seconds\n\n"
                "name                                   value     rate severity  category  aspect    description\n"
                "--------------------------------------------------------------------------------\n"
                "flow_policy_deny                          28        0 drop      flow      session   Session setup: denied by policy\n"
                "flow_dos_pf_strictip                      12        0 drop      flow      dos       "
                "Packets dropped: Zone protection option 'strict-ip-check'\n"
                "--------------------------------------------------------------------------------\nTotal counters shown: 2\n")
        if gwlog:
            (d / "api-gateway" / "access.txt").write_text(
                '[pod/api-gateway-1/apisix] 10.22.0.5 - - [27/Oct/2026:10:00:00 +0000] llm.ai.tarnwick.example "POST /models/x/v1/chat/completions HTTP/1.1" 200\n')

    def judge(self, *only):
        r = subprocess.run([sys.executable, str(MXPY), "judge", "--plan", str(self.d / "plan.json"), "--dir", str(self.d), *(["--only", *only] if only else [])],
                           capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
        return r


class Tmp(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp(prefix="sfab-test-ch02-"))
        self.addCleanup(shutil.rmtree, self.d, True)
        (self.d / "plan.json").write_text(json.dumps(PLAN))


class Plan(unittest.TestCase):
    def test_counts_are_table_2_2s(self):
        c = PLAN["counts"]
        self.assertEqual((c["cells"], c["allowed"], c["forbidden"], c["log-line"], c["404"], c["silence"]), (44, 17, 27, 18, 1, 8))
        self.assertEqual([r["id"] for r in PLAN["rows"]], ["enterprise", "operator", "nodes", "web"])
        self.assertEqual(sorted(PLAN["silence"]["cells"]),
                         ["enterprise/stor-data", "nodes/stor-data", "operator/api-server", "operator/bmc", "operator/node",
                          "operator/stor-data", "operator/stor-mgmt", "web/stor-data"])
        self.assertEqual(sorted(PLAN["silence"]["strict_ip"]), ["operator/api-server", "operator/bmc", "operator/node", "operator/stor-mgmt"])
        self.assertEqual(MX.strict_ip(PLAN, ["operator/node", "operator/gw-users"]), ["operator/node"])

    def test_requests_and_lookups(self):
        reqs = MX.requests(PLAN)
        self.assertEqual(len(reqs), 44 + 6)
        self.assertEqual(len({r[8] for r in reqs}), len(reqs), "every request its own source port")
        self.assertTrue(all(len(r) == 17 for r in reqs), "the request columns, the pin, then the cell's own caller (Part III)")
        self.assertTrue(all(r[16] == "-" for r in reqs), "chapter 2's cells name no own caller: the model's first key")
        op = next(r for r in reqs if r[0] == "operator/gw-internal")
        self.assertEqual(op[6], "10.20.11.200", "the operator asks the internal VIP through the tunnel")
        names = {(r[0], r[3]) for r in MX.lookups(PLAN)}
        self.assertIn(("enterprise", "admin.ai.tarnwick.example"), names)
        self.assertIn(("nodes", "llm.ai.tarnwick.example"), names)

    def test_matrix_sh_reads_every_column_of_a_request(self):
        # the shell loop names one variable a column: one too few shifts the client into the kind
        import re
        line = next(l for l in (COMMON / "matrix" / "matrix.sh").read_text().splitlines() if "read -r -u 3 cell " in l)
        names = re.search(r"read -r -u 3 (.*?); do", line).group(1).split()
        self.assertEqual(len(names), len(MX.requests(PLAN)[0]))
        self.assertEqual(names[3], "c")

    def test_label_sets_aside_the_predefined_rules(self):
        self.assertEqual(LB.PREDEFINED, ("intrazone-default", "interzone-default"))


class Judge(Tmp):
    def test_green(self):
        World(self.d)
        r = World(self.d).judge()
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        self.assertIn("44 of 44 cells in their mode (17 allowed, 18 log lines, 1 404, 8 silent)", r.stdout)
        self.assertIn("PASS  [allowed] Nodes / Users' Gateway: answered on k8s-cp2 itself, no line in the firewall's traffic log for port", r.stdout)
        self.assertIn("fw discards 10.20.12.31 by its route 10.0.0.0/8, before any rule", r.stdout)
        self.assertIn("PASS  [routing] Operator / API server: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), "
                      "not over the interface the request arrived on", r.stdout)
        self.assertIn("PASS  [routing] Operator / API server: zone protection's strict IP check dropped it before any rule "
                      "(flow_dos_pf_strictip 12 over the run, fw/drops.txt)", r.stdout)
        self.assertIn("uplink-rtr holds no route to 10.20.12.31", r.stdout)
        md = (self.d / "MATRIX.md").read_text()
        self.assertIn("| Admin hostnames |", md)
        self.assertIn("PASS 404, gw-users (route set)", md)
        self.assertIn("log line, deny-all-log (policy); timed out, at its connect timeout", md)

    def test_404_that_times_out_fails(self):
        w = World(self.d, override={"enterprise/admin": "log-line"})
        r = w.judge()
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL  [routeset] Staff / Admin hostnames: mode 404 -> got log-line", r.stdout)

    def test_404_with_an_api_gateway_line_fails(self):
        w = World(self.d)
        marker = next(c for c in PLAN["cells"] if c["id"] == "enterprise/admin")["requests"][0]["marker"]
        with open(self.d / "api-gateway" / "access.txt", "a") as f:
            f.write(f'[pod/api-gateway-2/apisix] x "GET /echo?msg={marker} HTTP/1.1" 404\n')
        r = w.judge("enterprise/admin")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no API gateway line for", r.stdout)

    def test_404_needs_the_gateway_log(self):
        w = World(self.d, gwlog=False)
        r = w.judge("enterprise/admin")
        self.assertEqual(r.returncode, 1)
        self.assertIn("its absence proves nothing", r.stdout)

    def test_log_line_names_its_rule_and_router(self):
        World(self.d)
        f = self.d / "routers" / "uplink-rtr-ip-route.txt"
        f.write_text("\n".join(l for l in f.read_text().splitlines() if "10.20.2.0/24" not in l) + "\n")
        r = World.judge(type("W", (), {"d": self.d})(), "web/stor-mgmt", "web/api-server")
        self.assertEqual(r.returncode, 1)
        self.assertIn("PASS  [routing] Internet host / API server: uplink-rtr routes 10.20.1.0/24 via 198.51.100.2", r.stdout)
        self.assertIn("FAIL  [policy] Internet host / Storage management: uplink-rtr's route to 10.20.2.0/24", r.stdout)

    def test_strict_ip_silence_needs_the_counter_and_the_route_back(self):
        World(self.d, drops=False)
        r = World.judge(type("W", (), {"d": self.d})(), "operator/node")
        self.assertEqual(r.returncode, 1)
        self.assertIn("flow_dos_pf_strictip not in fw/drops.txt", r.stdout)
        World(self.d)
        f = self.d / "fw" / "routing-route.txt"
        f.write_text("\n".join(l for l in f.read_text().splitlines() if "tunnel.1" not in l) + "\n")
        r = World.judge(type("W", (), {"d": self.d})(), "operator/node")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL  [routing] Operator / A node, k8s-gpu1: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1", r.stdout)
        World(self.d, override={"operator/node": "log-line"})
        r = World.judge(type("W", (), {"d": self.d})(), "operator/node")
        self.assertEqual(r.returncode, 1, "a deny-all-log line where the strict IP check drops it is another mode")

    def test_the_other_key_needs_the_message(self):
        World(self.d)
        q = next(c for c in PLAN["cells"] if c["id"] == "nodes/chat")["requests"][1]
        (self.d / "requests" / f"{MX.tag('nodes/chat', q['id'], 1)}-body.txt").write_text('{"message":"Missing API key"}')
        r = World.judge(type("W", (), {"d": self.d})(), "nodes/chat")
        self.assertEqual(r.returncode, 1)
        self.assertIn("message absent", r.stdout)

    def test_tlog_missing(self):
        World(self.d)
        out = subprocess.run([sys.executable, str(MXPY), "tlog-missing", "--plan", str(self.d / "plan.json"), "--dir", str(self.d)],
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "0")
        (self.d / "fw" / "traffic-log-443.txt").unlink()
        out = subprocess.run([sys.executable, str(MXPY), "tlog-missing", "--plan", str(self.d / "plan.json"), "--dir", str(self.d)],
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, str(sum(1 for c in PLAN["cells"] if c["mode"] == "log-line" and c["port"] == 443)))
        ports = subprocess.run([sys.executable, str(MXPY), "tlog-ports", "--plan", str(self.d / "plan.json"), "--dir", str(self.d)],
                               capture_output=True, text=True).stdout.split()
        self.assertEqual(ports, ["22", "443", "2049", "6443"])


class Break2a(Tmp):
    def setUp(self):
        super().setUp()
        b = json.loads((CH02 / "gen" / "breaks.json").read_text())["breaks"]["2a"]
        self.b = b
        self.broken = next(a for a in b["expect_broken"] if a.get("cell") == "enterprise/admin")
        self.healed = next(a for a in b["expect_healed"] if a.get("cell") == "enterprise/admin")

    def cellmode(self, chk):
        return subprocess.run([sys.executable, str(COMMON / "breakheal.py"), "cellmode", "--dir", str(self.d), "--plan", str(self.d / "plan.json"),
                               "--check", json.dumps(chk)], capture_output=True, text=True)

    def test_render(self):
        a = self.b["break"][0]
        self.assertEqual((a["kind"], a["node"], a["view"], a["address"], a["rendered"]), ("dns_answer", "dns-auth1", "enterprise", "10.20.11.200", "10.20.11.210"))
        self.assertIn("admin     IN A   10.20.11.200 ; added by the break", a["content"])
        self.assertIn("llm       IN A   10.20.11.210", a["content"])
        self.assertEqual(self.b["heal"], [{"kind": "restore", "node": "dns-auth1", "what": "dns"}])

    def test_broken_then_healed(self):
        World(self.d, override={"enterprise/admin": "log-line"}, answers={("enterprise", "admin.ai.tarnwick.example"): "10.20.11.200"})
        r = self.cellmode(self.broken)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("mode log-line, deny-all-log (deny), zone enterprise to ingress", r.stdout)
        self.assertIn("asked at 10.20.11.200", r.stdout)
        r = self.cellmode(self.healed)
        self.assertEqual(r.returncode, 1)
        shutil.rmtree(self.d / "requests")
        World(self.d)
        r = self.cellmode(self.healed)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(r.stdout.split(";")[0], "mode 404")


class Labels(Tmp):
    def world(self):
        d, plan = self.d, DEC["plan"]
        rows = {r["id"]: r for r in DEC["rows"]}
        for x in ("view", "fw", "routing", "routeset", "key", "placement", "forwarding"):
            (d / x).mkdir(parents=True, exist_ok=True)
        for lk in plan["view"]["lookups"]:
            if lk["answer"] is None:
                # the public view publishes no platform name: dig prints the NXDOMAIN status
                text = (f"; <<>> DiG 9.18 <<>> {lk['name']}\n;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n"
                        f";; SERVER: {lk['server']}#53({lk['server']}) (UDP)\n")
            elif lk["kind"] == "vm-node":
                text = f"{lk['answer']}      STREAM {lk['name']}\n"
            else:
                text = dig(lk["name"], lk["answer"], lk["server"])
            (d / "view" / f"{LB.slug(lk['population'])}-lookup.txt").write_text(text)
        for z in plan["view"]["zones"]:
            entry = f"llm     IN A   10.20.11.210 ; decision {z['decision']}: a name users type\n" if z["holds"] else ""
            (d / "view" / f"{z['server']}-{z['file']}.txt").write_text(f"; sfab-ch02 {z['server']}\n; decision {z['decision']}\n$ORIGIN ai.tarnwick.example.\n{entry}")
        rr = [o for o in rows["routing"]["objects"] if o["device"] == "fw"]
        (d / "fw" / "routing-route.txt").write_text("VIRTUAL ROUTER: core (id 2)\n" + "".join(
            f"{o['dest']:<44}{o.get('nexthop') or ('discard' if o['kind'] == 'static route' and not o.get('interface') else '0.0.0.0'):<40}0      A "
            f"{'S' if o['kind'] == 'static route' else 'C'}              {o.get('interface') or o['name']}\n" for o in rr))
        for kind, f in (("nat", "running-nat-policy.txt"), ("policy", "running-security-policy.txt")):
            # the security rulebase as PAN-OS prints it: the two predefined rules after the policy's
            # (as <vsys>+<name>, since build A revision 2 overrides them to log)
            names = plan[kind]["rules"] + (["vsys1+intrazone-default", "vsys1+interzone-default"] if kind == "policy" else [])
            (d / "fw" / f).write_text("".join(f'"{n}; index: {i}" {{\n        action allow;\n}}\n' for i, n in enumerate(names, 1)))
        xml = "<response status=\"success\"><result><rulebase><security><rules>" + "".join(
            f'<entry name="{n}"><description>{plan["policy"]["decisions"][n]}</description></entry>' for n in plan["policy"]["rules"]) + \
            "</rules></security><nat><rules>" + "".join(
            f'<entry name="{n}"><description>{plan["nat"]["decisions"][n]}</description></entry>' for n in plan["nat"]["rules"]) + \
            "</rules></nat></rulebase></result></response>"
        (d / "fw" / "rulebase.xml").write_text(xml)
        for r in plan["routing"]["routers"]:
            objs = [o for o in rows["routing"]["objects"] if o["device"] == r["node"]]
            (d / "routing" / f"{r['node']}-frr.conf").write_text("".join(f"! {o['name']}: {o['decision']}\nip route {o['dest']} {o['nexthop']}\n" for o in objs))
            (d / "routing" / f"{r['node']}-ip-route.txt").write_text("".join(f"S>* {o['dest']} [1/0] via {o['nexthop']}, eth1, weight 1, 00:10:00\n" for o in objs))
        lk = plan["routeset"]["label"]
        (d / "routeset" / "httproutes.json").write_text(json.dumps({"items": [
            {"metadata": {"name": o["name"], "namespace": o["namespace"], "labels": {lk: o["decision"]}}} for o in plan["routeset"]["routes"]]}))
        (d / "routeset" / "httproutes.txt").write_text("NAMESPACE NAME\n" + "".join(f"{o['namespace']}   {o['name']}   x\n" for o in plan["routeset"]["routes"]))
        # the standalone routes as the API gateway holds them: each caller's group with its labelled desc
        # and its limit, then the people's consumers by identity; the applications' keys are composed in
        apps = [g for g in plan["key"]["groups"] if g != "staff"]
        (d / "key" / "api-gateway-routes.yaml").write_text("upstreams:\n- id: router\n  timeout:\n    read: 600\nconsumer_groups:\n" + "".join(
            f"- id: {g}\n  desc: \"{dec}: application {g}; may call chat\"\n  plugins:\n    limit-count:\n      count: 3000\n"
            for g, dec in plan["key"]["groups"].items()) +
            "consumers:\n- username: staff_ent_client\n  group_id: staff\n  plugins:\n    oidc-consumer:\n      subject: ent-client@tarnwick.example\n#END\n")
        (d / "key" / "api-gateway-5d-abc-keys.txt").write_text(
            f"composed /standalone/apisix.yaml: {len(apps)} key(s) from /keys: " + " ".join(f"{g}.0123abcd sha256:0123456789ab" for g in apps) + "\n")
        pods = []
        for cp, dec in plan["placement"]["copies"].items():
            for role in ("server", "worker0", "worker1"):
                pods.append({"metadata": {"name": f"{cp}-{role}", "labels": {plan["placement"]["label"]: dec}}})
        (d / "placement" / "pods.json").write_text(json.dumps({"items": pods}))
        (d / "placement" / "nads.json").write_text(json.dumps({"items": [
            {"metadata": {"name": n, "annotations": {plan["placement"]["label"]: v}}} for n, v in plan["placement"]["nads"].items()]}))
        shutil.copy(CH02 / "bootstrap" / "k8s" / "serving.env", d / "placement" / "serving.env")
        for sw in plan["forwarding"]["switches"]:
            (d / "forwarding" / f"{sw}-startup.txt").write_text(f"! sfab-ch02 {sw}: rendered\n! decision {plan['forwarding']['decision']}: x\nconfigure terminal\n")
            (d / "forwarding" / f"{sw}-ip-route.txt").write_text("")

    def judge(self):
        (self.d / "decisions.json").write_text(json.dumps(DEC))
        return subprocess.run([sys.executable, str(COMMON / "matrix" / "label.py"), "judge", "--plan", str(self.d / "decisions.json"), "--dir", str(self.d)],
                              capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})

    def test_green(self):
        self.world()
        r = self.judge()
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        self.assertIn("PASS  [policy] the rulebase closes with deny-all-log", r.stdout)
        self.assertIn("PASS  [view] enterprise (ent-client): llm.ai.tarnwick.example answers 10.20.11.210 through 10.24.10.53, view enterprise", r.stdout)
        self.assertIn("PASS  [view] operator (ops-client): llm.ai.tarnwick.example answers NXDOMAIN through 192.0.2.10, view public-operator", r.stdout)
        self.assertIn("PASS  [view] ops-dns, view public-operator: the zone file is labelled dec-view-public and holds no entry for llm.ai.tarnwick.example", r.stdout)
        self.assertIn("PASS  [key] consumer group staff: its consumer staff_ent_client in the routes", r.stdout)
        self.assertIn("PASS  [key] consumer group batch: desc labelled dec-key-batch", r.stdout)
        md = (self.d / "LABELS.md").read_text()
        self.assertIn("| Security policy | security rule deny-all-log | `dec-policy-deny-all-log` |", md)
        self.assertIn("| forwarding only | fe-sw1's startup file | `dec-forwarding-only` |", md)
        self.assertIn("| Caller | consumer group staff in ", md)
        self.assertRegex(md, r"\| Placement \| copy chat-a's row of the placement table \| `dec-place-chat` \| `placement/serving.env:\d+` \|")

    def test_a_missing_description_and_a_route_fail(self):
        self.world()
        f = self.d / "fw" / "rulebase.xml"
        f.write_text(f.read_text().replace("<description>dec-policy-bastion-to-nodes</description>", ""))
        f = self.d / "forwarding" / "rail-sw1-ip-route.txt"
        f.write_text("C 10.21.1.0/24 is directly connected, Vlan101\n")
        r = self.judge()
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL  [policy] bastion-to-nodes: description dec-policy-bastion-to-nodes -> got ''", r.stdout)
        self.assertIn("FAIL  [forwarding] rail-sw1: show ip route prints nothing", r.stdout)


class WalkRows(unittest.TestCase):
    def test_plan_tags_every_hop(self):
        p = json.loads((CH02 / "gen" / "trace.json").read_text())
        self.assertEqual(set(p["rows"]["hops"]), {str(i) for i in range(1, 15)})
        self.assertEqual(p["rows"]["refusals"], {"hostname": "routeset", "key": "key", "port": "policy"})
        self.assertEqual(p["rows"]["layers"]["policy"], "Security policy")
        ch01 = json.loads((ROOT / "ch01" / "gen" / "trace.json").read_text())
        self.assertNotIn("rows", ch01, "chapter 1's plan stays as recorded")


class Scripts(unittest.TestCase):
    def test_shell_parses(self):
        for f in (COMMON / "matrix" / "matrix.sh", COMMON / "matrix" / "label.sh", COMMON / "break" / "breakheal.sh",
                  CH02 / "matrix.sh", CH02 / "label.sh", CH02 / "trace.sh", CH02 / "audit.sh"):
            r = subprocess.run(["bash", "-n", str(f)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{f}: {r.stderr}")
        if shutil.which("shellcheck"):
            r = subprocess.run(["shellcheck", "-x", "-P", str(ROOT), str(COMMON / "matrix" / "matrix.sh"), str(COMMON / "matrix" / "label.sh")],
                               capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(r.returncode, 0, r.stdout[-3000:])

    def test_a_heal_behind_the_breaks_serial_is_retransferred(self):
        # break-2a's zone serial follows its data: the heal's rendered serial can be behind the
        # break's in RFC 1982 arithmetic, and the secondary then needs rndc retransfer
        sh = (COMMON / "break" / "breakheal.sh").read_text()
        fn = sh[sh.index("serial_behind() {"):]
        fn = fn[:fn.index("\n}\n") + 3]
        for a, b, want in (("261946292", "756238120", 0), ("756238120", "261946292", 1), ("5", "5", 1), ("4294967295", "1", 0)):
            r = subprocess.run(["bash", "-c", fn + f"serial_behind {a} {b}"], capture_output=True, text=True)
            self.assertEqual(r.returncode, want, (a, b))
        self.assertIn('rndc -k /run/named/rndc.key retransfer "$zone" IN "$v"', sh)


if __name__ == "__main__":
    unittest.main()
