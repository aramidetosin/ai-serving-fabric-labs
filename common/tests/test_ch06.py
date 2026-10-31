"""Chapter 6's lab harness (ch06/): the placement group the audit adds, the serving trace, the three
drills and break-6a with its heal. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_ch06*.py'

Hermetic: ch06 is rendered into a temporary directory (PyYAML) and every device is a stand-in
(common/tests/shims/, shims-ch06/). The stand-in world is a simple deterministic model of the
serving layer (shims-ch06/_ch06.py), so the figures asserted here are the model's, never the lab's.
Fixtures use the book's own addressing plan and made-up names and keys only.
"""

from __future__ import annotations

import json
import re
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
CH06 = ROOT / "ch06"
HERE = Path(__file__).resolve().parent
SHIMS, SHIMS_CH06 = HERE / "shims", HERE / "shims-ch06"
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(COMMON / "trace"))
sys.path.insert(0, str(COMMON / "drill"))
sys.path.insert(0, str(HERE))

import runscope  # noqa: E402

NODES = "fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw fw k8s-cp1 k8s-cp2 k8s-cp3 k8s-gpu1 k8s-gpu2 bastion uplink-rtr ops-client inet-registry ent-client"
KEYS = ("5" * 32, "6" * 32)   # the stand-in world's made-up model keys
STUB_AUDIT = """#!/usr/bin/env bash
# a stand-in for ch06/audit.sh in these tests: the placement group alone, as the quick audit runs it
set -euo pipefail
. "$(dirname "$0")/../common/lib.sh"
sfab_init audit "$@"
. "$SFAB_COMMON/audit/lib-audit.sh"
audit_placement
summary
"""


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


def load(p):
    return json.loads(Path(p).read_text())


_RENDER = None


def ch06_render() -> Path:
    global _RENDER
    if _RENDER is None:
        out = Path(tempfile.mkdtemp(prefix="sfab-test-ch06-"))
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(CH06), "--out", str(out), "-q"], check=True, capture_output=True)
        _RENDER = out
    return _RENDER


def tearDownModule():
    if _RENDER is not None:
        shutil.rmtree(_RENDER, ignore_errors=True)


class Parsers(unittest.TestCase):
    def test_a_router_connection_outside_the_request_is_set_aside(self):
        import servetrace as ST

        def seg(t, src, sport, dst, dport, n):
            return {"t": t, "src": src, "sport": sport, "dst": dst, "dport": dport, "flags": "P.", "length": n, "line": 1}
        ag, ro, ro2 = "10.22.1.32", "10.22.1.36", "10.22.2.37"
        router = [seg(100.0, ag, 5000, ro, 4000, 700), seg(103.0, ro, 4000, ag, 5000, 800)]
        life = ST.request_life(router, ag, ro, 4000)
        self.assertEqual(life, (100.0, 103.0))
        # the router's own read of a model's list 5 s after it answered, from both router pods; a
        # connection inside the request's life stays counted, and so does one that is not a router's
        got = [seg(108.0, ro, 45848, "10.22.0.33", 8080, 233), seg(108.6, ro2, 39830, "10.22.0.33", 8080, 233),
               seg(101.5, ro, 45850, "10.22.0.33", 8080, 743), seg(108.0, "10.22.9.9", 1, "10.22.0.33", 8080, 233),
               seg(103.5, ro, 45852, "10.22.0.33", 8080, 233)]
        self.assertEqual(ST.outside_life(got, life, {ro, ro2}), {(ro, 45848), (ro2, 39830)})
        self.assertEqual(ST.outside_life(got, None, {ro, ro2}), set())
        self.assertIsNone(ST.request_life(router[:1], ag, ro, 4000))

    def test_the_routers_upstream_is_read_inside_the_request(self):
        import servetrace as ST

        def seg(t, src, sport, dst, dport, n):
            return {"t": t, "src": src, "sport": sport, "dst": dst, "dport": dport, "flags": "P.", "length": n, "line": 1}
        ag, ro = "10.22.3.214", "10.22.3.73"
        # chapter 1's record trace: the router read chat c's and another copy's model list 8.4 s
        # before the request arrived, then sent the request to copy a's server
        router = [seg(325.375, ro, 54502, "10.22.1.29", 8080, 233), seg(325.376, ro, 45434, "10.22.2.15", 8080, 234),
                  seg(333.802, ag, 39320, ro, 4000, 637), seg(333.821, ro, 38316, "10.22.1.252", 8080, 743),
                  seg(337.316, ro, 4000, ag, 39320, 1990)]
        life = ST.request_life(router, ag, ro, 4000)
        up = ST.data(router, src=ro, dport=8080)
        self.assertEqual([f["dst"] for f in ST.in_life(up, life)], ["10.22.1.252"])
        self.assertEqual(len(ST.in_life(up, None)), 3)

    def test_frames_and_epline(self):
        import servetrace as ST
        text = ("1792611812.120000 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype IPv4 (0x0800), length 66: (tos 0x0, ttl 64, id 1, "
                "offset 0, flags [DF], proto TCP (6), length 452)\n    10.22.1.11.41010 > 10.22.1.12.9080: Flags [P.], seq 1:401, ack 1, "
                "win 502, options [nop,nop,TS val 1 ecr 1], length 400\n"
                "1792611812.130000 02:00:00:00:00:01 > 02:00:00:00:00:02, ethertype IPv4 (0x0800), length 74: 10.22.9.1.41000 > "
                "10.22.1.12.9080: Flags [S], seq 1, win 64240, length 0\n")
        fr = ST.frames(text)
        self.assertEqual([(f["src"], f["dport"], f["flags"], f["length"], f["line"]) for f in fr],
                         [("10.22.1.11", 9080, "P.", 400, 1), ("10.22.9.1", 9080, "S", 0, 3)])
        self.assertEqual(len(ST.data(fr, dport=9080)), 1)
        import servedrill as SD
        doc = {"items": [{"metadata": {"labels": {"kubernetes.io/service-name": "chat"}},
                          "endpoints": [{"addresses": ["10.22.1.5"], "conditions": {"ready": True}},
                                        {"addresses": ["10.22.2.5"], "conditions": {"ready": False}}]}]}
        self.assertEqual(SD.ready_by_service(doc), {"chat": ["10.22.1.5"]})

    def test_servekeys(self):
        import base64
        import io
        import contextlib
        import servekeys as SK
        doc = {"data": {"chat.0a1b2c3d": base64.b64encode(b"sk-tw-chat-" + b"5" * 32).decode(),
                        "staff.0a1b2c3e": base64.b64encode(b"sk-tw-staff-" + b"6" * 32).decode()}}
        self.assertEqual(SK.first_key(doc, "staff")[0], "staff.0a1b2c3e")
        out, err = io.StringIO(), io.StringIO()
        import sys as _s
        old = _s.stdin
        try:
            _s.stdin = io.StringIO(json.dumps(doc))
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(SK.main(["which", "--model", "chat"]), 0)
        finally:
            _s.stdin = old
        self.assertNotIn("5" * 32, out.getvalue() + err.getvalue())
        self.assertRegex(out.getvalue(), r"^chat\.0a1b2c3d sha256:[0-9a-f]{12}$")


class Ch06LabTest(unittest.TestCase):
    def setUp(self):
        if not have_yaml():
            self.skipTest("PyYAML is needed to render ch06")
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-ch06lab-"))
        self.addCleanup(shutil.rmtree, self.t, True)
        self.scope = runscope.Scope(self)
        self.lab = self.t / "ch06"
        self.lab.mkdir()
        r = ch06_render()
        for part in ("gen", "bootstrap"):
            shutil.copytree(r / part, self.lab / part)
        shutil.copy(r / "topo.clab.yml", self.lab / "topo.clab.yml")
        for f in ("chapter.yaml", "audit.sh", "trace.sh", "drills.sh"):
            shutil.copy(CH06 / f, self.lab / f)
        (self.lab / "audit.sh").write_text(STUB_AUDIT)
        (self.lab / "audit.sh").chmod(0o755)
        for d in ("common", "spec", "serving-layer"):
            os.symlink(ROOT / d, self.t / d)
        dr = load(self.lab / "gen" / "drills.json")
        dr["timing"].update({"lead_s": 2, "hold_s": 5, "tail_s": 1, "return_max_s": 20, "whole_polls": 3})
        dr["probes"]["endpoints"]["interval_s"] = 0.5
        (self.lab / "gen" / "drills.json").write_text(json.dumps(dr, indent=2, sort_keys=True) + "\n")
        self.inv = load(self.lab / "gen" / "inventory.json")
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS_CH06}:{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab), "SHIM_STATE": str(self.state), "SHIM_LOG": str(self.log), "SHIM_NODES": NODES,
            "SFAB_HOST_LOCK": str(self.t / "sfab.lock"), "SFAB_TICK_OVERRIDE": "1", "SHIM_INV": str(self.lab / "gen" / "inventory.json"),
            "SHIM_RENDER": str(self.lab), "SHIM_CH06_STATE": str(self.t / "ch06-world.json"), "PYTHONDONTWRITEBYTECODE": "1",
            "SFAB_DRILL_AUDIT": "0", "SFAB_BREAK_SETTLE_S": "0", "SFAB_HEAL_AUDIT": "0", "SFAB_RETRY_PAUSE": "0",
            "SFAB_RAILCAP_SETTLE_S": "0", "SFAB_RAILCAP_TAIL_S": "0.2", "SFAB_DRILL_POLL_S": "0.5", "SFAB_MAC_POLL_S": "0",
        })
        self.env.pop("VARIANT", None)
        cs = {}
        for i, n in enumerate(self.inv["order"]):
            node = self.inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            cmd = ["--username", "admin", "--password", "shimpw"] if node["kind"] in ("dell_sonic", "paloalto_panos") else []
            cs[node["container"]] = {"running": True, "started": f"2026-10-22T09:00:{i:02d}Z", "pid": 6000 + i, "health": "healthy",
                                     "env": env, "cmd": cmd}
        self.state.write_text(json.dumps({"containers": cs}))
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-ch06"], check=True, capture_output=True)

    def run_cmd(self, argv, timeout=900, env=None):
        e = dict(self.env)
        e.update(env or {})
        return self.scope.run([str(x) for x in argv], env=e, capture_output=True, text=True, cwd=self.lab, timeout=timeout)

    def leftover_shims(self) -> list:
        """The stand-in captures this test's commands left running."""
        return self.scope.left("shims-ch06/_ch06.py tcpdump")

    def world(self):
        try:
            return load(self.t / "ch06-world.json")
        except (OSError, ValueError):
            return {}

    def set_world(self, w):
        (self.t / "ch06-world.json").write_text(json.dumps(w))

    def last_set(self, kind):
        return sorted((self.lab / "audits").glob(f"sfab-ch06_{kind}_*"))[-1]

    def no_key_in(self, d: Path):
        for p in d.rglob("*"):
            if p.is_file():
                b = p.read_bytes()
                for k in KEYS:
                    self.assertNotIn(k.encode(), b, str(p))
        b = self.log.read_bytes()
        for k in KEYS:
            self.assertNotIn(k.encode(), b, "the stand-ins' command log")


class PlacementAuditTest(Ch06LabTest):
    def audit(self, *args):
        rs = self.t / "set"
        shutil.rmtree(rs, ignore_errors=True)
        rs.mkdir()
        script = f". {COMMON}/lib.sh; sfab_init audit --set {rs} {' '.join(args)}; . {COMMON}/audit/lib-audit.sh; audit_placement; summary"
        r = self.run_cmd(["bash", "-c", script], timeout=600)
        return r.stdout, r

    def test_green(self):
        out, r = self.audit()
        self.assertIn("== placement: the serving pods read back against the table (chapter 6)", out, out[-4000:] + r.stderr[-3000:])
        part = out.split("== placement: the serving pods read back against the table (chapter 6)", 1)[1]
        self.assertEqual([l for l in part.splitlines() if l.startswith("  FAIL  ")], [], part[-5000:])
        for line in ("  PASS  the table: 11 pods of 5 copies of 2 models; every copy on one rail with one server and 1 or more workers, every "
                     "rail address inside its rail's prefix and given once",
                     "  PASS  each model keeps a copy through the loss of either rail switch and of any one GPU node: chat: a rail 3 (rail-sw1) on "
                     "k8s-gpu1, b rail 6 (rail-sw2) on k8s-gpu2, c rail 7 (rail-sw1) on k8s-gpu1+k8s-gpu2; staff: a rail 4 (rail-sw2) on k8s-gpu1, "
                     "b rail 5 (rail-sw1) on k8s-gpu2",
                     "  PASS  chat-a-worker0-0 (chat copy a, worker): on k8s-gpu1, rail 3 as rail3 10.21.3.101 02:5a:fe:03:00:65, Ready",
                     "  PASS  one StatefulSet a row (11), each of one replica that updates on delete, so a pod made again keeps its row's name, node, "
                     "rail address and MAC",
                     "  PASS  no StatefulSet the table does not name",
                     "  PASS  chat-a-server-0: llama-server --rpc 10.21.3.101:50052, its workers' rail addresses",
                     "  PASS  chat-c-server-0: llama-server --rpc 10.21.7.101:50052,10.21.7.102:50052, its workers' rail addresses",
                     "  PASS  chat-a-server-0: llama-server bound to the pod's own cluster address (--host $(POD_IP), POD_IP from status.podIP)",
                     "  PASS  chat-a-server-0: its model /models/LFM2.5-24B-A2B-Q4_K_M.gguf from the models volume of k8s-gpu1, read-only (claim "
                     "models-k8s-gpu1)",
                     "  PASS  staff-b-server-0: its model /models/Qwen3.8-27B-UD-Q4_K_M.gguf from the models volume of k8s-gpu2, read-only (claim "
                     "models-k8s-gpu2)",
                     "  PASS  chat-a-server-0: readiness over the rail (sfab-ready server, every worker), every 2 s, out after 2 failures, each probe up to 2 s",
                     "  PASS  chat-a-worker0-0: ggml-rpc-server bound to its rail address 10.21.3.101:50052",
                     "  PASS  chat-a-worker0-0: listening on 10.21.3.101:50052 alone (ggml-rpc only on the rail; the pod's cluster interface answers nothing)",
                     "  PASS  k8s-gpu1: claim models-k8s-gpu1 Bound to a local PersistentVolume of /srv/models on k8s-gpu1, read-only many",
                     "  PASS  one macvlan attachment per rail the table uses (rail3, rail4, rail5, rail6, rail7): the rail NIC as master, bridge mode, "
                     "MTU 9000, the static IPAM plugin and no route",
                     "  PASS  no rail attachment the table does not use",
                     "  PASS  no server or worker pod the table does not name",
                     "  PASS  chat through gw-users from ent-client: HTTP 200, answered by the router's openai/chat deployment",
                     "  PASS  staff through gw-internal from ops-client: HTTP 200, answered by the router's openai/staff deployment"):
            self.assertIn(line, out)
        self.assertRegex(out, r"  PASS  Service chat: its ready endpoints are its servers \(chat-a-server-0, chat-b-server-0, chat-c-server-0: "
                              r"10\.22\.\d+\.\d+ 10\.22\.\d+\.\d+ 10\.22\.\d+\.\d+\)")
        self.assertRegex(out, r"  PASS  chat-a-server-0: listening on 10\.22\.\d+\.\d+:8080 alone, nothing on the rail or every address")
        self.assertRegex(out, r"  PASS  in every pod the default route on eth0, and on its rail attachment only the rail's connected prefix \(11 pods read")
        self.assertTrue((self.t / "set" / "placement" / "pod-chat-a-server-0-route.txt").is_file())
        self.assertTrue((self.t / "set" / "placement" / "pod-chat-a-server-0-listen.txt").is_file())
        self.no_key_in(self.t / "set")

    def test_a_moved_table_fails_first(self):
        env = (self.lab / "bootstrap" / "k8s" / "serving.env").read_text()
        moved = self.t / "moved.env"
        row = next(l for l in env.splitlines() if " chat-a-worker0-0 " in f" {l.split('=', 1)[-1].strip(chr(39))} ")
        k, v = row.split("=", 1)
        v2 = v.replace(" 3 rail3 10.21.3.101/24 ", " 5 rail5 10.21.5.103/24 ").replace("02:5a:fe:03:00:65", "02:5a:fe:05:00:67")
        moved.write_text(env.replace(row, f"{k}={v2}"))
        out, r = self.audit("--table", str(moved))
        self.assertIn("  FAIL  the table keeps the recipe's rules (every pod of a copy on one rail, one server and a worker a copy, every address "
                      "once) -> copy chat-a spans the attachments ['rail3', 'rail5']: every pod of a copy sits on one rail", out, out[-4000:])
        self.assertRegex(out, r"  FAIL  chat-a-worker0-0 \(chat copy a, worker\): on k8s-gpu1, rail 5 as rail5 10\.21\.5\.103 02:5a:fe:05:00:67, Ready -> "
                              r"network-status names serving/rail3 10\.21\.3\.101")
        self.assertIn("  PASS  chat-c-server-0: llama-server --rpc 10.21.7.101:50052,10.21.7.102:50052, its workers' rail addresses", out)


class ServeTraceTest(Ch06LabTest):
    def test_trace_green(self):
        r = self.run_cmd([self.lab / "trace.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        rs = self.last_set("trace")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("FAIL", verdict, verdict)
        rid = load(self.lab / "gen" / "trace.json")["route_id"]
        for line in (f"  PASS  HTTP 200 for POST https://llm.ai.tarnwick.example/models/{rid}/v1/chat/completions with chat's key",
                     "  PASS  answered by the router's openai/chat deployment, on the model's Service http://chat.serving.svc.cluster.local:8080/v1, "
                     "with no retry",
                     "  PASS  the request landed on copy c, the one the plan pins (try 3 of at most 12; the captures of each miss discarded)",
                     "  PASS  chat-c-server-0's RPC on rail7 (10.21.7.100) to chat-c-worker0-0 at 10.21.7.101:50052, the table's rail 7: 1 data "
                     "segments out, 1 back",
                     "  PASS  ... and no frame of the RPC to chat-c-worker1-0 (10.21.7.102), beside its server on k8s-gpu1: macvlan's bridge mode "
                     "keeps it inside the node",
                     "  PASS  copy a on rail 3 carried none of it: no data to chat-a-server-0, no RPC on rail3 at its server, its workers or "
                     "rail-sw1's ports",
                     "  PASS  copy b on rail 6 carried none of it: no data to chat-b-server-0, no RPC on rail6 at its server, its workers or "
                     "rail-sw2's ports"):
            self.assertIn(line, verdict)
        self.assertRegex(verdict, r"  PASS  k8s-cp2, which holds gw-users's lease: the client's SYN from 10\.24\.10\.10 port 42608 to 10\.20\.11\.210:443 on "
                                  r"bond0, and data both ways")
        self.assertRegex(verdict, r"  PASS  one API gateway pod took it: api-gateway-6c9f-a1 on k8s-gpu1 \(10\.22\.\d+\.\d+:9080\), data from the Gateway's "
                                  r"proxy at 10\.22\.9\.7, sent on to the router pod router-7d4b-a1 \(10\.22\.\d+\.\d+:4000\); api-gateway-6c9f-b2 took none")
        self.assertRegex(verdict, r"  PASS  rail-sw1 Ethernet7 \(facing k8s-gpu2\) carried the RPC between 10\.21\.7\.100 and 10\.21\.7\.101, the worker on "
                                  r"the other node")
        self.assertEqual((rs / "request" / "attempts.txt").read_text().splitlines()[-1], "try 3 source port 42608: chat-c-server-0 took it")
        self.assertEqual((rs / "request" / "sport.txt").read_text().strip(), "42608")
        md = (rs / "TRACE.md").read_text()
        for x in ("## The path", "| API gateway | `2-api-gateway-6c9f-a1-eth0` |", "The copy that served it: chat-c, rail 7 (rail7) on rail-sw1",
                  "## Frames per point"):
            self.assertIn(x, md)
        for ch in (chr(0x2014), chr(0x2013)):
            self.assertNotIn(ch, md)
        self.assertTrue((rs / "request" / "key.txt").read_text().strip().endswith(tuple("0123456789abcdef")))
        self.no_key_in(rs)
        self.assertEqual(self.leftover_shims(), [])
        w = self.world()
        self.assertFalse([k for k, f in (w.get("files") or {}).get("sfab-ch06-ent-client", {}).items() if "/sfab-trace/" in k],
                         "the key's files are removed from the client")


class ServeDrillTest(Ch06LabTest):
    def test_three_drills_one_pass(self):
        r = self.run_cmd([self.lab / "drills.sh", "--passes", "1"], timeout=900)
        self.assertEqual(r.returncode, 0, r.stdout[-8000:] + r.stderr[-3000:])
        rs = self.last_set("drills")
        verdict = (rs / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        for line in ("  PASS  pass 1 dark-switch: KLISH interface range Ethernet0-7, shutdown accepted on rail-sw1 "
                     "(Ethernet0,Ethernet1,Ethernet2,Ethernet3,Ethernet4,Ethernet5,Ethernet6,Ethernet7)",
                     "  PASS  pass 1 worker-port: KLISH interface Ethernet7, shutdown accepted on rail-sw1 (Ethernet7)",
                     "  PASS  pass 1 dark-switch: rail-sw1 after the restore: parity, 0 missing lines"):
            self.assertIn(line, verdict)
        # bracketed by the reads around it, or, when the read before it came before the shut, bounded by
        # the read that no longer listed it (a busy machine spaces the reads out)
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: Service chat-c: chat-c-server-0 left it (by [\d.]+|[\d.]+ to [\d.]+) s after the shut "
                                  r"session began")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: Service chat: chat-a-server-0, chat-b-server-0 stayed in it throughout")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: Service chat-a: chat-a-server-0 stayed in it throughout")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: Service staff-b: staff-b-server-0 stayed in it throughout")
        self.assertRegex(verdict, r"  PASS  pass 1 worker-port: Service staff: staff-a-server-0, staff-b-server-0 stayed in it throughout")
        self.assertIn("  KNOWN pass 1 dark-switch: chat-a, staff-b on rail-sw1's rails stayed in their Services: each copy's RPC runs inside its node", verdict)
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: chat through gw-users: 0 of \d+ requests failed")
        self.assertRegex(verdict, r"  PASS  pass 1 dark-switch: \.\.\. the router tried \d+ of them again")
        self.assertRegex(verdict, r"  PASS  pass 1 worker-port: every Service held all its servers again [\d.]+ s after the restore's session began")
        self.assertIn("  KNOWN pass 1 dark-switch: a KLISH shutdown drops no carrier at the GPU NICs", verdict)
        self.assertRegex(verdict, r"  PASS  pass 1 rail-move: chat-a-worker0-0's row moved in the table from rail 3 to rail 5")
        self.assertRegex(verdict, r"  PASS  pass 1 rail-move: the recipe refuses to render the manifests from it: serving\.py: copy chat-a spans")
        self.assertRegex(verdict, r"  PASS  pass 1 rail-move: audit\.sh against the moved table fails first, nothing in the cluster having moved")
        self.assertRegex(verdict, r"  PASS  pass 1 rail-move: audit\.sh against the table as rendered, restored: RESULT: \d+ passed, 0 failed")
        a = load(rs / "pass1" / "dark-switch" / "analysis.json")
        self.assertEqual(a["dead_copies"], ["chat-c"])
        self.assertEqual(a["in_node"], ["chat-a", "staff-b"])
        ev = {e["service"]: e for e in a["services"]}
        self.assertEqual(sorted(ev["chat"]["left"]), ["chat-c-server-0"])
        self.assertEqual(ev["chat-a"]["lost_live"], [])
        md = (rs / "DRILLS.md").read_text()
        self.assertIn("## dark-switch: serve-dark on rail-sw1, copies out chat-c", md)
        self.assertIn("Every pass agrees on which servers left which Services.", md)
        self.assertTrue((rs / "pass1" / "rail-move" / "serving-moved.env").is_file())
        self.no_key_in(rs)
        w = self.world()
        self.assertTrue(all(x.get("until") for x in w["dark"]["rail-sw1"]), "the switch is restored")
        self.assertEqual(self.leftover_shims(), [])


class FinishInferenceTest(Ch06LabTest):
    def test_the_inference_step(self):
        # every other step of finish marked done, so finish runs the inference step alone
        steps = ("cluster", "ready", "retract", "cilium", "apply", "ca-secrets", "idp-secret", "operators", "charts", "apply-late", "serving",
                 "settle", "events")
        script = (f". {COMMON}/lib.sh; sfab_init finish; mkdir -p \"$STATEDIR/stage\"; "
                  + "; ".join(f"marker_text >\"$STATEDIR/stage/finish.{x}.ok\"" for x in steps))
        r = self.run_cmd(["bash", "-c", script])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self.run_cmd([COMMON / "stages" / "finish.sh"], timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        self.assertIn("  PASS  the router's master key, the first key of each application caller and the router's backend key, made or copied in the cluster by "
                      "the key Job (no value printed)", r.stdout)
        self.assertIn("  PASS  2 Deployments in inference rolled out (the API gateway and the router), with the model routes on 2 Gateway(s)",
                      r.stdout)
        calls = [json.loads(l) for l in self.log.read_text().splitlines()]
        # the harness's kubectl on the init node over SSH (lib.sh K): the remote command's words
        import shlex  # noqa: PLC0415
        kube = [shlex.split(c[-1]) for c in calls if c[0] == "ssh-ch06" and c[-1].startswith("sudo env KUBECONFIG=")]
        kube = [w for w in kube if "kubectl" in w]
        applied = [c[c.index("-f") + 1].rsplit("/", 1)[-1] for c in kube if "apply" in c]
        # then the network policy of the API gateway's and the recipe's namespaces (63), last
        self.assertEqual(applied, ["60-inference-base.yaml", "61-inference-keys.yaml", "62-inference.yaml", "63-inference-policy.yaml"])
        self.assertRegex(r.stdout, r"  PASS  network policy for inference and serving: default deny, then the request path \(63-inference-policy\.yaml, \d+ policies\)")
        rolled = [c[-2] for c in kube if "rollout" in c and "status" in c]
        self.assertEqual(rolled, ["deployment/api-gateway", "deployment/router"])
        self.assertTrue((self.lab / "state" / "stage" / "finish.inference.ok").is_file())


class PreflightModelsTest(unittest.TestCase):
    """pf_models: a lab that serves binds images/models into its GPU nodes; each model file serving.env
    names must be there at its pinned size before containerlab binds it."""

    def pf(self, root: Path, serving: str = "1") -> str:
        script = ('ok() { echo "PASS $*"; }; bad() { echo "FAIL $1 -> $2"; }; py() { python3 "$@"; }; '
                  'SFAB_PF_LIB=1 . "$SFAB_COMMON/stages/preflight.sh"; pf_models')
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                           env={**os.environ, "SFAB_ROOT": str(root), "SFAB_COMMON": str(COMMON), "RENDERDIR": str(ROOT / "ch06"),
                                "STAGE_SERVING": serving})
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_models_at_their_sizes(self):
        root = Path(tempfile.mkdtemp(prefix="sfab-test-pfmodels-"))
        self.addCleanup(shutil.rmtree, root, True)
        self.assertIn("FAIL models in images/models -> no images/models", self.pf(root))
        d = root / "images" / "models"
        d.mkdir(parents=True)
        out = self.pf(root)
        self.assertIn("LFM2.5-24B-A2B-Q4_K_M.gguf missing; Qwen3.8-27B-UD-Q4_K_M.gguf missing: make -C images models-fetch", out)
        env = (ROOT / "ch06" / "bootstrap" / "k8s" / "serving.env").read_text()
        sizes = dict(re.findall(r"SERVING_MODEL_\d+='\S+ \S+ \S+ (\S+) (\d+)'", env))
        for f, n in sizes.items():
            with open(d / f, "wb") as fh:  # a sparse file of the pinned size
                fh.truncate(int(n))
        self.assertIn("PASS models in images/models: 2 model file(s): LFM2.5-24B-A2B-Q4_K_M.gguf, Qwen3.8-27B-UD-Q4_K_M.gguf, each at its "
                      "pinned size", self.pf(root))
        with open(d / "LFM2.5-24B-A2B-Q4_K_M.gguf", "wb") as fh:
            fh.truncate(10)
        self.assertIn("LFM2.5-24B-A2B-Q4_K_M.gguf is 10 bytes, not 14526258464", self.pf(root))
        self.assertEqual(self.pf(root, serving="0"), "", "a lab without serving says nothing")


class Break6aTest(Ch06LabTest):
    def bh(self, *args):
        return self.run_cmd([sys.executable, COMMON / "breakheal.py", *args])

    def test_break_then_heal(self):
        r = self.bh("break", "6a")
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        verdict = (self.last_set("break-6a") / "verdict.txt").read_text()
        for line in ("  PASS  chat-b-worker0-0 deleted and made again on rail 8 at 10.21.8.100/24 (rail6 10.21.6.101/24 in the table), with a rail8 "
                     "attachment the table does not use",
                     "  PASS  chat-b-worker0-0's network-status names rail 8, while the table places it on rail 6 (serving/rail8 rail8 10.21.8.100)",
                     "  PASS  Service chat-b holds 0 ready endpoint(s) of its servers chat-b-server-0",
                     "  PASS  Service chat holds 2 ready endpoint(s)",
                     "  PASS  Service staff holds 2 ready endpoint(s)"):
            self.assertTrue(any(l.startswith(line) for l in verdict.splitlines()), line + "\n" + verdict)
        self.assertRegex(verdict, r"  PASS  users: every request succeeds \(22 of 22\)")
        rec = self.last_set("break-6a") / "record"
        self.assertIn("chat-b-worker0-0: serving/rail8 rail8 10.21.8.100", (rec / "broken-network-status.txt").read_text())
        r = self.bh("heal", "6a")
        self.assertEqual(r.returncode, 0, r.stdout[-6000:] + r.stderr[-3000:])
        verdict = (self.last_set("heal-6a") / "verdict.txt").read_text()
        self.assertNotIn("  FAIL  ", verdict, verdict)
        for line in ("  PASS  make serve: every pod where the table places it, chat-b-server-0 removed first and made again",
                     "  PASS  chat-b-worker0-0's network-status names rail 6, as the table places it",
                     "  PASS  Service chat holds 3 ready endpoint(s)",
                     "  PASS  rail-sw2 no longer holds 02:5a:fe:08:00:64 (the moved chat-b-worker0-0's MAC on Vlan108, Ethernet7)"):
            self.assertTrue(any(l.startswith(line) for l in verdict.splitlines()), line + "\n" + verdict)
        w = self.world()
        self.assertNotIn("rail8", w["nads"])
        self.assertEqual(w["broken"], [])
        self.no_key_in(self.last_set("break-6a"))
        self.no_key_in(self.last_set("heal-6a"))


if __name__ == "__main__":
    unittest.main()
