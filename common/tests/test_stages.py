"""Stage and guard tests: the real lib.sh and stage scripts against stand-in docker, containerlab
and nsenter (common/tests/shims/), in a throwaway copy of dev/m1. Nothing here touches a real
container. Needs bash 4.4 or later and PyYAML (to render the inventory).

    python3 -m unittest discover -s common/tests -t common/tests
"""

from __future__ import annotations

import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
SHIMS = Path(__file__).resolve().parent / "shims"
M1_NODES = "fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw fw k8s-gpu1 k8s-gpu2"
# a stand-in for the lab host's kernel release, which the containers print as their own
HOST_KERNEL = "9.9.9-stand-in+"
KERNEL_MARK = "[redacted: host-kernel]"


def host_tick_is_10000() -> bool:
    """On a host whose tick reads 10000 (the lab host), a result set carries no host-tick stamp."""
    r = subprocess.run([sys.executable, str(COMMON / "bin" / "tick.py")], capture_output=True, text=True, timeout=60)
    return r.returncode == 0 and r.stdout.strip() == "10000"


TICK_OK = host_tick_is_10000()


def have_yaml() -> bool:
    try:
        import yaml  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(have_yaml(), "PyYAML renders the M1 inventory")
class StageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.render = tempfile.mkdtemp(prefix="sfab-test-render-")
        subprocess.run([str(COMMON / "bin" / "sfab"), "render", str(ROOT / "dev" / "m1"), "--out", cls.render, "-q"],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.render, ignore_errors=True)

    def setUp(self):
        self.t = Path(tempfile.mkdtemp(prefix="sfab-test-lab-"))
        self.lab = self.t / "dev" / "m1"
        self.lab.mkdir(parents=True)
        shutil.copy(ROOT / "dev" / "m1" / "chapter.yaml", self.lab / "chapter.yaml")
        for part in ("gen", "bootstrap"):
            if (Path(self.render) / part).is_dir():
                shutil.copytree(Path(self.render) / part, self.lab / part)
        if (Path(self.render) / "topo.clab.yml").is_file():
            shutil.copy(Path(self.render) / "topo.clab.yml", self.lab / "topo.clab.yml")
        else:
            (self.lab / "topo.clab.yml").write_text("name: sfab-m1\nprefix: __lab-name\ntopology: {}\n")
        self.state = self.t / "shim-state.json"
        self.log = self.t / "shim-log.jsonl"
        self.log.write_text("")
        self.world({})
        self.env = dict(os.environ)
        self.env.update({
            "PATH": f"{SHIMS}:{os.environ['PATH']}",
            "SFAB_LABDIR": str(self.lab),
            "SHIM_STATE": str(self.state),
            "SHIM_LOG": str(self.log),
            "SHIM_NODES": M1_NODES,
            "SFAB_HOST_LOCK": str(self.t / "sfab.lock"),
            "SFAB_TICK_OVERRIDE": "1",
        })
        self.env.pop("VARIANT", None)
        # a reader's host: no scrub list, no literals and no author flag, so the audit's namecheck
        # is skipped (an empty literals file: a named file that is missing is an error)
        for k in ("SFAB_SCRUB_LIST", "SFAB_NAMECHECK_ALLOW", "SFAB_REQUIRE_NAMECHECK"):
            self.env.pop(k, None)
        (self.t / "empty-scrub-secrets").write_text("")
        self.env["SFAB_SCRUB_SECRETS"] = str(self.t / "empty-scrub-secrets")

    def tearDown(self):
        shutil.rmtree(self.t, ignore_errors=True)

    def world(self, s):
        self.state.write_text(json.dumps(s))

    def containers(self) -> dict:
        return json.loads(self.state.read_text()).get("containers") or {}

    def calls(self, tool) -> list:
        out = []
        for line in self.log.read_text().splitlines():
            if line.startswith("["):
                c = json.loads(line)
                if c[0] == tool:
                    out.append(c[1:])
        return out

    def bash(self, script, *args, cwd=None):
        return subprocess.run(["bash", "-c", script, "test", *args], env=self.env, capture_output=True, text=True,
                              cwd=cwd or self.lab, timeout=120)

    def run_stage(self, name, *args, env=None):
        return subprocess.run([str(COMMON / "stages" / name), *args], env={**self.env, **(env or {})}, capture_output=True,
                              text=True, cwd=self.lab, timeout=300)

    def lab_world(self, extra=None, running=True):
        cs = {}
        for i, n in enumerate(M1_NODES.split()):
            cs[f"sfab-m1-{n}"] = {"running": running, "started": f"2026-10-14T09:00:{i:02d}Z", "pid": 4000 + i,
                                  "health": "healthy", "env": ["NUM_NICS=8"], "cmd": ["--password", "shimpw"]}
        cs.update(extra or {})
        self.world({"containers": cs})

    # -- the identity guard ------------------------------------------------------------------

    def test_identity_holds(self):
        r = self.bash('. "$1/lib.sh"; sfab_init x; echo "$LAB $PREFIX ${#NODES[@]} ${NODE_CTR[fw]}"', str(COMMON))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "sfab-m1 sfab-m1- 8 sfab-m1-fw")

    def test_identity_refuses_wrong_directory(self):
        other = self.t / "dev" / "m2"
        shutil.copytree(self.lab, other)
        self.env["SFAB_LABDIR"] = str(other)
        r = self.bash('. "$1/lib.sh"; sfab_init x', str(COMMON))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("identity guard refuses", r.stderr)
        self.assertIn("expected sfab-m2", r.stderr)

    def test_identity_refuses_foreign_topology(self):
        (self.lab / "topo.clab.yml").write_text("name: sfab-ch03\nprefix: __lab-name\n")
        r = self.bash('. "$1/lib.sh"; sfab_init x', str(COMMON))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("topo.clab.yml names lab 'sfab-ch03'", r.stderr)

    # -- dk and clab ---------------------------------------------------------------------------

    def guard(self, cmd):
        return self.bash(f'. "$1/lib.sh"; sfab_init x; {cmd}', str(COMMON))

    def test_dk_refuses_foreign_containers(self):
        self.lab_world({"sfab-m10-fe-sw1": {"running": True}, "web": {"running": True}})
        for cmd in ("dk rm -f web", "dk rm -f sfab-m10-fe-sw1", "dk stop sfab-m1-fe-sw1 web", "dk exec -e A=1 web true",
                    "dk pause sfab-m1-fe-sw1", "dk network rm sfab-a-mgmt", "dk cp x web:/tmp", "dk system prune -f",
                    "dk inspect -f '{{.Name}}' sfab-m1x-fw", "dk update --restart no web"):
            r = self.guard(cmd)
            self.assertEqual(r.returncode, 97, f"{cmd}: {r.stderr}")
            self.assertIn("refusing", r.stderr)
        self.assertEqual(self.calls("docker"), [], "a refused call must never reach docker")
        self.assertIn("web", self.containers())

    def test_dk_allows_own_containers(self):
        self.lab_world()
        for cmd in ("dk exec -e A=1 -u root sfab-m1-k8s-gpu1 true", "dk rm -f sfab-m1-k8s-gpu1", "dk cp x sfab-m1-fw:/tmp/x",
                    "dk update --restart no sfab-m1-fe-sw1", "dk inspect -f '{{.Name}}' sfab-m1-fw", "dk ps -a"):
            r = self.guard(cmd)
            self.assertEqual(r.returncode, 0, f"{cmd}: {r.stderr}")
        self.assertNotIn("sfab-m1-k8s-gpu1", self.containers())

    def test_clab_refuses(self):
        for cmd in ('clab destroy -t "$TOPO" --cleanup', 'clab destroy -t "$TOPO" -c', 'clab deploy -t "$TOPO" --all',
                    'clab destroy -t /tmp/other.clab.yml', "clab destroy", 'clab save -t "$TOPO"'):
            r = self.guard(cmd)
            self.assertEqual(r.returncode, 97, f"{cmd}: {r.stderr}")
        self.assertEqual(self.calls("containerlab"), [])

    # -- down ------------------------------------------------------------------------------------

    def test_down_fast_touches_only_this_lab(self):
        self.lab_world({"sfab-m1-stray": {"running": False}, "sfab-m10-fe-sw1": {"running": True},
                        "other-lab-x": {"running": True}})
        (self.lab / "clab-sfab-m1" / "fe-sw1").mkdir(parents=True)
        (self.lab / "state" / "nodes" / "k8s-gpu1").mkdir(parents=True)
        (self.lab / "state" / "nodes" / "k8s-gpu1" / "disk.qcow2").write_text("x")
        r = self.run_stage("down.sh", "fast")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        left = sorted(self.containers())
        self.assertEqual(left, ["other-lab-x", "sfab-m10-fe-sw1"])
        destroys = [c for c in self.calls("containerlab") if c and c[0] == "destroy"]
        self.assertEqual(len(destroys), 1)
        self.assertEqual(destroys[0], ["destroy", "-t", str(self.lab.resolve() / "topo.clab.yml")])
        for c in self.calls("docker"):
            if c[0] == "rm":
                self.assertTrue(all(a.startswith("sfab-m1-") for a in c[1:] if not a.startswith("-")), c)
        self.assertFalse((self.lab / "clab-sfab-m1").exists())
        self.assertTrue((self.lab / "state" / "nodes" / "k8s-gpu1" / "disk.qcow2").exists())
        self.assertIn("  PASS  no sfab-m1-* container remains", r.stdout)
        self.assertIn("  PASS  state/ disks kept until wipe", r.stdout)
        self.assertIn("  PASS  the memory watchdog unit sfab-m1-memwatch is not running", r.stdout)
        self.assertIn("== RESULT: 4 passed, 0 failed", r.stdout)

    def test_down_redacts_containerlab_output(self):
        # containerlab destroy prints an exited container's output; the TrueNAS launcher's lists its
        # PASSWORD. clab() passes containerlab's output through redact.py --stream.
        self.lab_world()
        pw = "Tn0123456789abcdefgh"  # stand-in values: a made-up password and redaction key
        key = "5a" * 32
        (self.lab / "state" / "secrets").mkdir(parents=True, exist_ok=True)
        (self.lab / "state" / "secrets.env").write_text(f"SFAB_TRUENAS_PASSWORD={pw}\nSFAB_TRUENAS_USER=truenas_admin\n")
        (self.lab / "state" / "secrets" / "redact.key").write_text(key + "\n")
        r = self.run_stage("down.sh", "fast", env={"SHIM_CLAB_EXITED_OUTPUT": f"INFO PASSWORD: {pw}\nINFO USERNAME: truenas_admin"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn(pw, r.stdout + r.stderr)
        # clab() passes the lab's key: the mark is the one that key gives, and no run fell back to its own
        sys.path.insert(0, str(COMMON / "audit"))
        import redact  # noqa: PLC0415
        self.assertIn(f"INFO PASSWORD: {redact.mark(pw, key.encode())}", r.stdout)
        self.assertNotIn("no redaction key", r.stderr)
        self.assertIn("INFO USERNAME: truenas_admin", r.stdout, "user names are not secrets")
        self.assertIn("  PASS  no sfab-m1-* container remains", r.stdout)

    def test_down_redacts_the_host_kernel_in_containerlab_output(self):
        # clab()'s --stream filter applies the host-kernel rule, with the release from the environment
        self.lab_world()
        out = f"FRRouting 10.5.4_git (uplink-rtr) on Linux({HOST_KERNEL}).\nEthernet Channel Bonding Driver: v{HOST_KERNEL}"
        r = self.run_stage("down.sh", "fast", env={"SHIM_CLAB_EXITED_OUTPUT": out, "SFAB_HOST_KERNEL": HOST_KERNEL})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn(HOST_KERNEL, r.stdout + r.stderr)
        self.assertIn(f"on Linux({KERNEL_MARK}).", r.stdout)
        self.assertIn(f"Bonding Driver: v{KERNEL_MARK}", r.stdout)

    def test_redact_closes_a_set_with_the_host_kernel_rule(self):
        # lib.sh's redact(), which rs_close runs on every set, applies the rule and writes the ledger,
        # with the lab's own redaction key
        rs = self.lab / "audits" / "sfab-m1_audit_20261021T000000Z"
        (rs / "bastion").mkdir(parents=True)
        (rs / "bastion" / "02_bonding.txt").write_text(f"Ethernet Channel Bonding Driver: v{HOST_KERNEL}\n\nBonding Mode: x\n")
        pw, key = "Rr0123456789abcdefgh", "6b" * 32  # stand-in values: a made-up password and redaction key
        (rs / "commands.txt").write_text(f"### t bastion exec\nLinux bastion {HOST_KERNEL} #1 SMP x86_64\npassword {pw}\n")
        (self.lab / "state" / "secrets").mkdir(parents=True, exist_ok=True)
        (self.lab / "state" / "secrets.env").write_text(f"SFAB_SW_PASSWORD={pw}\n")
        (self.lab / "state" / "secrets" / "redact.key").write_text(key + "\n")
        self.env["SFAB_HOST_KERNEL"] = HOST_KERNEL
        r = self.bash('. "$1/lib.sh"; sfab_init x; redact "$2"', str(COMMON), str(rs))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("no redaction key", r.stderr)
        sys.path.insert(0, str(COMMON / "audit"))
        import redact  # noqa: PLC0415
        self.assertEqual((rs / "commands.txt").read_text().splitlines()[2], f"password {redact.mark(pw, key.encode())}")
        self.assertEqual((rs / "bastion" / "02_bonding.txt").read_text().splitlines()[0], f"Ethernet Channel Bonding Driver: v{KERNEL_MARK}")
        self.assertEqual((rs / "commands.txt").read_text().splitlines()[1], f"Linux bastion {KERNEL_MARK} #1 SMP x86_64")
        led = (rs / "REDACTIONS.md").read_text()
        self.assertIn("replaced while the set was recorded", led)
        self.assertIn("| bastion/02_bonding.txt | 1 | host-kernel |", led)
        self.assertIn("| commands.txt | 2 | host-kernel |", led)
        self.assertNotIn(HOST_KERNEL, led)

    def test_down_wipe_and_verify_records_a_set(self):
        self.lab_world(running=False)
        (self.lab / "state" / "nodes" / "k8s-gpu1").mkdir(parents=True)
        (self.lab / "state" / "nodes" / "k8s-gpu1" / "disk.qcow2").write_text("x")
        # stand-in values: a made-up password
        (self.lab / "state" / "secrets.env").write_text("SFAB_SW_PASSWORD=Xx1234567890abcdefgh\n")
        r = self.run_stage("down.sh", "wipe", "--verify")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertFalse((self.lab / "state" / "secrets.env").exists())
        self.assertFalse((self.lab / "state" / "nodes" / "k8s-gpu1").exists())
        sets = sorted((self.lab / "audits").glob("sfab-m1_teardown_*"))
        self.assertEqual(len(sets), 1)
        for f in ("RESULT.txt", "verdict.txt", "RUN.json", "commands.txt"):
            self.assertTrue((sets[0] / f).exists(), f)
        self.assertIn("0 failed", (sets[0] / "RESULT.txt").read_text())
        if not TICK_OK:
            self.assertIn("host-tick:", (sets[0] / "RESULT.txt").read_text())

    # -- up --------------------------------------------------------------------------------------

    def secrets(self):
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-m1"], check=True, capture_output=True)

    def test_up_deploys_once_then_reports_its_marker(self):
        self.secrets()
        r = self.run_stage("up.sh")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        deploys = [c for c in self.calls("containerlab") if c and c[0] == "deploy"]
        self.assertEqual(deploys, [["deploy", "-t", str(self.lab.resolve() / "topo.clab.yml"), "--reconfigure", "--max-workers", "8"]])
        self.assertEqual(len(self.containers()), 8)
        self.assertTrue((self.lab / "state" / "stage" / "up.deploy.ok").exists())
        self.assertFalse((self.lab / "state" / "shared" / "hold-guests").exists(), "a standalone up removes its hold")
        self.assertTrue(any("systemd-run" in l or "memwatch" in l for l in self.log.read_text().splitlines()) or
                        "memory watchdog is not running" in r.stderr)
        r = self.run_stage("up.sh")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("marker  up.deploy matches", r.stdout)
        self.assertEqual(len([c for c in self.calls("containerlab") if c and c[0] == "deploy"]), 1)

    def test_up_redeploys_a_partial_lab(self):
        self.secrets()
        self.lab_world()
        del_state = json.loads(self.state.read_text())
        del del_state["containers"]["sfab-m1-k8s-gpu1"]
        self.state.write_text(json.dumps(del_state))
        r = self.run_stage("up.sh")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("down fast first", r.stdout)
        ops = [c[0] for c in self.calls("containerlab") if c and c[0] in ("deploy", "destroy")]
        self.assertEqual(ops, ["destroy", "deploy"])

    def test_links_intact_sees_a_lost_link(self):
        self.lab_world()
        r = self.bash('. "$1/lib.sh"; sfab_init x; links_intact && echo intact', str(COMMON))
        self.assertIn("intact", r.stdout, r.stderr)
        s = json.loads(self.state.read_text())
        s["down_links"] = ["4006:eth3"]
        self.state.write_text(json.dumps(s))
        r = self.bash('. "$1/lib.sh"; sfab_init x; links_intact || echo broken', str(COMMON))
        self.assertIn("broken", r.stdout)
        self.assertIn("k8s-gpu1 eth3 is missing or down", r.stderr)

    # -- preflight and run -------------------------------------------------------------------------

    def test_preflight_refuses_another_lab(self):
        self.lab_world({"sfab-ch03-fw": {"running": True}})
        s = json.loads(self.state.read_text())
        s["networks"] = [{"Name": "othernet", "IPAM": {"Config": [{"Subnet": "172.21.40.0/23"}]}, "Containers": {}}]
        self.state.write_text(json.dumps(s))
        r = self.run_stage("preflight.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("  FAIL  no other sfab lab's container running -> sfab-ch03-fw", r.stdout)
        self.assertIn("docker network othernet holds 172.21.40.0/23", r.stdout)
        self.assertIn("  PASS  identity: lab sfab-m1", r.stdout)
        self.assertIn("  PASS  containerlab at the pinned 0.82.0", r.stdout)
        # The override turns a tick other than 10000 into a SKIP; a host whose tick is 10000 passes.
        self.assertRegex(r.stdout, r"  (SKIP  host tick|PASS  host tick 10000)")
        last = (self.lab / "state" / "preflight.last").read_text()
        self.assertIn("FAIL  no other sfab lab's container running", last)

    def test_preflight_sets_probes_aside(self):
        # A throwaway probe's containers (sfab-probe-*) are not a lab: the guard passes and says so.
        self.lab_world({"sfab-probe-x-worker": {"running": True}, "sfab-probe-x-control-plane": {"running": True}})
        r = self.run_stage("preflight.sh")
        self.assertIn("  PASS  no other sfab lab's container running (2 sfab-probe-* container(s) set aside", r.stdout)
        self.assertNotIn("FAIL  no other sfab lab's container running", r.stdout)
        self.lab_world({"sfab-probe-x-worker": {"running": True}, "sfab-ch03-fw": {"running": True}})
        r = self.run_stage("preflight.sh")
        self.assertIn("  FAIL  no other sfab lab's container running -> sfab-ch03-fw", r.stdout)

    def test_preflight_wants_the_pinned_containerlab(self):
        self.lab_world()
        self.env["SHIM_CLAB_VERSION"] = "0.81.0"
        r = self.run_stage("preflight.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("  FAIL  containerlab at the pinned 0.82.0 -> want 0.82.0, got 0.81.0", r.stdout)

    def set_disk_budgets(self, state=None, layer=None, base=0.0):
        """Give the throwaway lab's inventory these disk budgets (GiB), every other node 0."""
        p = self.lab / "gen" / "inventory.json"
        inv = json.loads(p.read_text())
        for n, nd in inv["nodes"].items():
            nd["budget"]["state_gib"] = (state or {}).get(n, 0.0)
            nd["budget"]["layer_gib"] = (layer or {}).get(n, 0.0)
        inv["budget"]["state_base_gib"] = base
        p.write_text(json.dumps(inv, indent=2, sort_keys=True) + "\n")

    def disk_lines(self, out):
        return [l for l in out.splitlines() if l.startswith(("  PASS  disk", "  FAIL  disk"))]

    def test_preflight_disk_budget(self):
        # FRAMEWORK.md 3.1: what a deploy writes, where it writes it. The growth under state/ and
        # the container layers of the nodes not yet running are judged together on one
        # filesystem (the shim's data root is the test's own directory); the guests' virtual disk
        # sizes are not the budget.
        self.lab_world(running=False)
        self.set_disk_budgets(state={"k8s-gpu1": 0.5, "k8s-gpu2": 0.25}, layer={"fe-sw1": 0.5, "fw": 1.0}, base=0.25)
        lines = self.disk_lines(self.run_stage("preflight.sh").stdout)
        self.assertEqual(len(lines), 1, lines)
        self.assertRegex(lines[0], r"^  PASS  disk: [0-9.]+ GiB free covers 1\.0 GiB under state/ \(budget 1\.0 GiB, 0\.0 GiB "
                                   r"of it already there\) and 1\.5 GiB of container layers under \S+ for the nodes not "
                                   r"yet running, one filesystem \(2\.5 GiB\)$")
        # A running node's layer is already written: only the nodes not yet running count.
        self.lab_world(running=True)
        self.set_disk_budgets(layer={"fe-sw1": 1e7})
        lines = self.disk_lines(self.run_stage("preflight.sh").stdout)
        self.assertRegex(lines[0], r"^  PASS  disk: .* and 0\.0 GiB of container layers ")
        # More growth than the filesystem holds refuses the deploy.
        self.lab_world(running=False)
        self.set_disk_budgets(state={"k8s-gpu1": 1e7})
        r = self.run_stage("preflight.sh")
        self.assertNotEqual(r.returncode, 0)
        lines = self.disk_lines(r.stdout)
        self.assertRegex(lines[0], r"^  FAIL  disk -> [0-9.]+ GiB free, need 10000000\.0 GiB under state/ ")

    def test_preflight_disk_counts_what_state_already_holds(self):
        # A node's directory under state/nodes/ counts toward its own budget (allocated blocks),
        # never below 0 and never toward another node's.
        self.lab_world(running=False)
        d = self.lab / "state" / "nodes" / "k8s-gpu1"
        d.mkdir(parents=True)
        (d / "root.qcow2").write_bytes(os.urandom(1 << 20) * 120)
        self.set_disk_budgets(state={"k8s-gpu1": 0.1, "k8s-gpu2": 0.2})
        lines = self.disk_lines(self.run_stage("preflight.sh").stdout)
        self.assertRegex(lines[0], r"covers 0\.2 GiB under state/ \(budget 0\.3 GiB, 0\.1 GiB of it already there\)")

    def test_preflight_disk_needs_the_docker_data_root(self):
        self.lab_world(running=False)
        s = json.loads(self.state.read_text())
        s["docker_root"] = str(self.t / "no-such-root")
        self.state.write_text(json.dumps(s))
        r = self.run_stage("preflight.sh")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("  FAIL  disk -> docker info gives no data root", r.stdout)

    def test_run_status_and_unknown_stage(self):
        self.lab_world()
        r = subprocess.run([str(COMMON / "stages" / "run.sh"), "status"], env=self.env, capture_output=True, text=True, cwd=self.lab)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("sfab-m1-fe-sw1", r.stdout)
        r = subprocess.run([str(COMMON / "stages" / "run.sh"), "teleport"], env=self.env, capture_output=True, text=True, cwd=self.lab)
        self.assertNotEqual(r.returncode, 0)

    def test_run_wipe_records_its_duration(self):
        # wipe removes state/stage with the markers; the run still records the stage's duration
        # (ch04's first make wipe exited 1 there)
        self.lab_world(running=False)
        r = subprocess.run([str(COMMON / "stages" / "run.sh"), "wipe"], env=self.env, capture_output=True, text=True, cwd=self.lab)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-2000:])
        self.assertIn("== stage wipe done in ", r.stdout)
        d = json.loads((self.lab / "state" / "stage" / "durations.json").read_text())
        self.assertIn("wipe", d)

    def test_stage_markers(self):
        self.lab_world()
        script = '. "$1/lib.sh"; sfab_init x; f() { echo ran; }; stage_step t s f; stage_step t s f; g() { return 3; }; stage_step t g g; ls "$STATEDIR/stage"'
        r = self.bash(script, str(COMMON))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count("ran\n"), 1)
        self.assertIn("marker  t.s matches", r.stdout)
        self.assertIn("ran without a verdict; no marker written", r.stdout)
        self.assertIn("t.s.ok", r.stdout)
        self.assertNotIn("t.g.ok", r.stdout)
        s = json.loads(self.state.read_text())
        s["containers"]["sfab-m1-k8s-gpu2"]["started"] = "2026-10-14T11:11:11Z"
        self.state.write_text(json.dumps(s))
        r = self.bash('. "$1/lib.sh"; sfab_init x; f() { echo ran; }; stage_step t s f', str(COMMON))
        self.assertIn("ran", r.stdout, "a restarted container invalidates the marker")

    # -- the M1 audit, end to end against a healthy stand-in lab ------------------------------------

    def healthy_lab(self):
        os.symlink(COMMON, self.t / "common")
        os.symlink(ROOT / "spec", self.t / "spec")
        shutil.copy(ROOT / "dev" / "m1" / "audit.sh", self.lab / "audit.sh")
        inv = json.loads((self.lab / "gen" / "inventory.json").read_text())
        cs = {}
        for i, n in enumerate(inv["order"]):
            node = inv["nodes"][n]
            env = [f"NUM_NICS={node['num_nics']}"] if node.get("num_nics") else []
            if node.get("passthrough"):
                env.append("CLAB_MGMT_PASSTHROUGH=true")
            # The login is on the launcher's command line only, as containerlab's dell_sonic and
            # paloalto_panos kinds give it: the topology passes no USERNAME or PASSWORD env.
            cs[node["container"]] = {"running": True, "started": f"2026-10-14T09:00:{i:02d}Z", "pid": 4000 + i,
                                     "health": "healthy", "env": env, "cmd": ["--username", "admin", "--password", "shimpw"]}
        self.world({"containers": cs})
        fw = self.lab / "bootstrap" / "fw"
        if not (fw / "startup-config.xml").is_file():
            fw.mkdir(parents=True, exist_ok=True)
            (fw / "startup-config.xml").write_text("<config version='12.1.0'><devices/></config>\n")
            (fw / "enforced.txt").write_text("set deviceconfig system hostname fw\nset zone data network layer3 ae1.100\n")
        self.env.update({"SHIM_INV": str(self.lab / "gen" / "inventory.json"), "SHIM_FW_XML": str(fw / "startup-config.xml"),
                         "SHIM_FW_ENFORCED": str(fw / "enforced.txt"), "SHIM_RENDER": str(self.lab)})
        subprocess.run([sys.executable, str(COMMON / "bin" / "secrets.py"), "ensure", "--state", str(self.lab / "state"),
                        "--lab", "sfab-m1"], check=True, capture_output=True)
        (self.lab / "state" / "preflight.last").write_text("# preflight 2026-10-14T09:00:00Z\n== preflight\n  PASS  host tick 10000\n")

    def audit(self, *args):
        # no scrub list here (setUp), so the audit's namecheck is skipped and does not scan the repository
        return subprocess.run([str(self.lab / "audit.sh"), *args], env=self.env, capture_output=True, text=True,
                              cwd=self.lab, timeout=600)

    def test_m1_audit_green(self):
        self.healthy_lab()
        r = self.audit()
        self.assertEqual(r.returncode, 0, r.stdout[-4000:] + r.stderr[-2000:])
        self.assertNotIn("  FAIL  ", r.stdout)
        sets = sorted((self.lab / "audits").glob("sfab-m1_audit_*"))
        self.assertEqual(len(sets), 1)
        rs = sets[0]
        for f in ("RUN.json", "RESULT.txt", "verdict.txt", "commands.txt",
                  "fe-sw1/18_mclag_brief.txt", "repo/namecheck.txt", "repo/sfab-check.txt"):
            self.assertTrue((rs / f).is_file(), f)
        # numbered by each node's plan, which grows with the render: found by slug
        for node, slug in (("fw", "config_set.txt"), ("k8s-gpu1", "same_rail_3.txt")):
            self.assertEqual(len(list((rs / node).glob(f"[0-9][0-9]_{slug}"))), 1, f"{node}/NN_{slug}")
        # each output is saved once: no per-node or whole-set concatenation (FRAMEWORK.md 4.4)
        self.assertEqual(sorted(p.name for p in rs.rglob("*ALL*OUTPUT*")), [])
        self.assertTrue((rs / "fe-sw1" / "18_mclag_brief.txt").read_text().startswith("fe-sw1# show mclag brief"))
        self.assertTrue((rs / "fe-sw1" / "15_kernel_addr.json").is_file())
        verdict = (rs / "verdict.txt").read_text()
        for line in ("  PASS  launcher log: KLISH startup config applied", "  PASS  roles: one active, one standby",
                     "  PASS  NUM_NICS in the container env is 3", "  PASS  show ip interfaces lists only Management0",
                     "  PASS  commit marker present", "  PASS  delivered /config/startup-config.cfg matches the render byte for byte",
                     "  PASS  LACP partner is the pair's mclag-system-mac 02:5a:00:00:00:01",
                     "  PASS  bond0 partner MAC is the mclag-system-mac", "  PASS  8 relay namespaces (gpu1,gpu2,gpu3,gpu4,gpu5,gpu6,gpu7,gpu8)",
                     "  SKIP  namecheck (no scrub list)", "  PASS  sfab check clean"):
            self.assertIn(line, verdict)
        self.assertIn("namecheck: skipped, no scrub list", (rs / "repo" / "namecheck.txt").read_text())
        if (COMMON / "klish" / "parity.py").is_file():
            self.assertEqual(verdict.count("  PASS  parity: 0 missing lines"), 5, verdict)
        result = (rs / "RESULT.txt").read_text()
        self.assertRegex(result, r"== RESULT: \d+ passed, 0 failed, 0 known platform limitation\(s\), \d+ skipped")
        if not TICK_OK:
            self.assertIn("host-tick:", result)
        run = json.loads((rs / "RUN.json").read_text())
        for k in ("lab", "labs_repo", "spec_sha256", "render_sha256", "containerlab", "utc_start", "utc_end"):
            self.assertIn(k, run)
        self.assertEqual(sorted(run["labs_repo"]), ["commit", "dirty", "source"])
        self.assertIn(run["labs_repo"]["source"], ("git", "environment", "stamp", None))
        self.assertEqual(run["containerlab"], "0.82.0")
        cmds = (rs / "commands.txt").read_text()
        self.assertRegex(cmds, r"(?m)^### \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ fe-sw1 klish$")
        self.assertIn("fe-sw1# show mclag brief", cmds)
        self.assertIn("admin@fw> show interface all", cmds)
        self.assertLess(cmds.index("fe-sw1 klish"), cmds.index("k8s-gpu2 guest"), "transcript blocks in node order")
        secrets = [l.split("=", 1)[1] for l in (self.lab / "state" / "secrets.env").read_text().splitlines()
                   if "=" in l and "PASSWORD" in l]
        for p in rs.rglob("*"):
            if p.is_file():
                data = p.read_bytes()
                for v in secrets + ["shimpw", "LUFRPTshimkey"]:
                    self.assertNotIn(v.encode(), data, f"{p}: a credential leaked")
        g = subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)], env=self.env, capture_output=True, text=True, cwd=self.lab)
        self.assertEqual(g.returncode, 0, g.stdout + g.stderr)
        self.assertIn("  PASS  RESULT shows 0 failed", g.stdout)
        self.assertIn("  PASS  secret scan clean", g.stdout)
        self.assertIn("  SKIP  namecheck in the set (no scrub list)", g.stdout)
        self.assertIn("  SKIP  namecheck in the repo (no scrub list)", g.stdout)
        self.assertRegex(g.stdout, r"  PASS  set size: [0-9.]+ MiB in \d+ files, within 64\.0 MiB")
        self.assertIn("  PASS  no plain text file over the text cap", g.stdout)
        self.assertIn("  PASS  large XML and JSON stored compressed", g.stdout)
        # a compressed file that sorts before the other files of its directory, as a committed set's
        # do: the gate reads it and goes on to every other file and line
        (rs / "fw" / "00_extra.xml.gz").write_bytes(gzip.compress(b"<v>plain</v>\n", mtime=0))
        g = subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)], env=self.env, capture_output=True, text=True, cwd=self.lab)
        self.assertEqual(g.returncode, 0, g.stdout + g.stderr)
        self.assertNotIn("Traceback", g.stderr)
        self.assertIn("  PASS  secret scan clean", g.stdout)
        self.assertRegex(g.stdout, r"  PASS  set size: [0-9.]+ MiB in \d+ files, within 64\.0 MiB")
        self.assertIn("  PASS  RESULT shows 0 failed", g.stdout)
        # a secret inside a compressed file fails the secret scan; the size caps fail their lines
        (rs / "fw" / "00_extra.xml.gz").write_bytes(gzip.compress(f"<v>{secrets[0]}</v>\n".encode(), mtime=0))
        (rs / "big.json").write_bytes(b"[" + b"0," * 140000 + b"0]\n")
        (rs / "captures").mkdir(exist_ok=True)
        (rs / "captures" / "1-x.txt").write_text("12:00:00.000000 IP 10.0.0.1 > 10.0.0.2: ICMP echo request\n" * 1200)
        g = subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)],
                           env={**self.env, "SFAB_TEXT_MAX_MIB": "0.05", "SFAB_SET_MAX_MIB": "0.1"},
                           capture_output=True, text=True, cwd=self.lab)
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertIn("  FAIL  secret scan clean -> fw/00_extra.xml.gz: the value of", g.stdout)
        self.assertRegex(g.stdout, r"  FAIL  set size: [0-9.]+ MiB in \d+ files, within 0\.1 MiB -> over the set cap")
        self.assertRegex(g.stdout, r"  FAIL  no plain text file over the text cap -> .*captures/1-x\.txt \(0\.1 MiB\)")
        self.assertIn("  FAIL  large XML and JSON stored compressed -> big.json (common/audit/setsize.py pack)", g.stdout)
        (rs / "fw" / "00_extra.xml.gz").unlink()
        (rs / "big.json").unlink()
        shutil.rmtree(rs / "captures")
        # a file written into the set by hand that holds the lab host's kernel release fails the scan
        (rs / "host-readings.txt").write_text(f"uname -r: {HOST_KERNEL}\n")
        g = subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)], env={**self.env, "SFAB_HOST_KERNEL": HOST_KERNEL},
                           capture_output=True, text=True, cwd=self.lab)
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertIn("  FAIL  secret scan clean -> host-readings.txt: the lab host's kernel release", g.stdout)
        self.assertNotIn(HOST_KERNEL, g.stdout + g.stderr)
        (rs / "host-readings.txt").unlink()
        # with a scrub list the gate's namecheck runs, over the set and the whole repository
        absent = "zq" + uuid.uuid4().hex[:12]
        (self.t / "scrub-list.txt").write_text(f"# fail: names\n{absent}\n")
        g = subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)], env={**self.env, "SFAB_SCRUB_LIST": str(self.t / "scrub-list.txt")},
                           capture_output=True, text=True, cwd=self.lab, timeout=600)
        self.assertEqual(g.returncode, 0, g.stdout[-3000:] + g.stderr[-1000:])
        self.assertIn("  PASS  namecheck clean in the set", g.stdout)
        self.assertIn("  PASS  namecheck clean in the repo", g.stdout)

    def test_gate_reads_a_committed_set_with_compressed_files(self):
        # a set as committed, its pods JSON stored compressed with files after it in its directory
        src = ROOT / "dev" / "m2" / "audits" / "sfab-m2_audit_20261020T092038Z"
        if not (src / "bastion" / "18_pods.json.gz").is_file():
            self.skipTest("the committed set is not in this checkout")
        rs = self.lab / "audits" / src.name
        shutil.copytree(src, rs)
        self.assertTrue(sorted(p.name for p in (rs / "bastion").iterdir())[-1] != "18_pods.json.gz")
        g = subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)], env=self.env, capture_output=True, text=True,
                           cwd=self.lab, timeout=600)
        self.assertNotIn("Traceback", g.stderr)
        self.assertIn("  PASS  secret scan clean", g.stdout)
        self.assertRegex(g.stdout, r"  PASS  set size: [0-9.]+ MiB in \d+ files, within 64\.0 MiB")
        self.assertIn("  PASS  RESULT shows 0 failed", g.stdout)
        self.assertEqual(g.returncode, 0, g.stdout[-3000:] + g.stderr[-1000:])

    # -- the gate's literal scan and the author's flag ------------------------------------------

    def gate_set(self) -> Path:
        """A small green result set, as the gate reads one."""
        rs = self.lab / "audits" / "x_drills_20261022T000000Z"
        (rs / "captures").mkdir(parents=True)
        (rs / "client").mkdir()
        (rs / "RESULT.txt").write_text("== RESULT: 1 passed, 0 failed, 0 known platform limitation(s), 0 skipped\n")
        (rs / "verdict.txt").write_text("  PASS  a check\n")
        (rs / "client" / "07_resolv_conf.txt").write_text("nameserver 127.0.0.11\nsearch lab.test\n")
        (rs / "captures" / "1-dns.pcap").write_bytes(b"\xd4\xc3\xb2\xa1\0\0\x03www\x04zone\x04test\0")
        return rs

    def gate(self, rs, **env):
        return subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)], env={**self.env, **env}, capture_output=True,
                              text=True, cwd=self.lab, timeout=600)

    def test_gate_scans_every_file_for_the_literals(self):
        rs = self.gate_set()
        # stand-in literals, made here so that no file of the repository holds them: a domain, and
        # a value whose lower-case form namecheck's exact match would miss
        label = "zq" + uuid.uuid4().hex[:10]
        domain = f"{label}.zone.test"
        other = "Zq" + uuid.uuid4().hex[:10] + "Q"
        lits = self.t / "literals.txt"
        lits.write_text(f"# stand-in literals\n{domain}\n{other}\n")
        g = self.gate(rs, SFAB_SCRUB_SECRETS=str(lits))
        self.assertEqual(g.returncode, 0, g.stdout + g.stderr)
        self.assertIn("  PASS  literal scan clean", g.stdout)
        # in another case in a text file, by its first label in a capture's DNS name, and in a
        # compressed file: namecheck finds none of them, the literal scan finds each
        (rs / "client" / "07_resolv_conf.txt").write_text(f"nameserver 127.0.0.11\nsearch {domain.upper()}\n")
        (rs / "captures" / "1-dns.pcap").write_bytes(b"\xd4\xc3\xb2\xa1\0\0" + bytes([len(label)]) + label.encode() + b"\xc0\x0c")
        (rs / "fw").mkdir()
        (rs / "fw" / "00_extra.xml.gz").write_bytes(gzip.compress(f"<v>\n{other.lower()}\n</v>\n".encode(), mtime=0))
        g = self.gate(rs, SFAB_SCRUB_SECRETS=str(lits))
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertIn("  SKIP  namecheck in the set (no scrub list)", g.stdout)
        self.assertIn("  FAIL  literal scan clean -> 3 found: captures/1-dns.pcap: a literal (binary, as text or in DNS "
                      "wire form);client/07_resolv_conf.txt:2: a literal;fw/00_extra.xml.gz:2: a literal", g.stdout)
        self.assertNotIn(label, (g.stdout + g.stderr).lower(), "a hit never prints the literal")
        self.assertNotIn(other.lower(), (g.stdout + g.stderr).lower())
        # the default file, ~/.config/sfab/scrub-secrets.txt, when $SFAB_SCRUB_SECRETS is empty
        home = self.t / "home"
        (home / ".config" / "sfab").mkdir(parents=True)
        shutil.copy(lits, home / ".config" / "sfab" / "scrub-secrets.txt")
        g = self.gate(rs, SFAB_SCRUB_SECRETS="", HOME=str(home))
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertIn("  FAIL  literal scan clean -> 3 found: ", g.stdout)
        # no literals file: a reader's gate skips the scan
        (home / ".config" / "sfab" / "scrub-secrets.txt").unlink()
        g = self.gate(rs, SFAB_SCRUB_SECRETS="", HOME=str(home))
        self.assertEqual(g.returncode, 0, g.stdout + g.stderr)
        self.assertIn("  SKIP  literal scan (no literals file)", g.stdout)
        # a file $SFAB_SCRUB_SECRETS names that is not there fails, and its path is not printed
        g = self.gate(rs, SFAB_SCRUB_SECRETS=str(self.t / "no-such-literals.txt"))
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertIn("  FAIL  literal scan clean -> the literals file that $SFAB_SCRUB_SECRETS names does not exist",
                      g.stdout)
        self.assertNotIn("no-such-literals", g.stdout + g.stderr)

    def test_gate_with_the_author_flag_fails_a_skipped_check(self):
        rs = self.gate_set()
        # a reader's host (setUp): no scrub list and an empty literals file, so both checks skip
        for flag in (None, "0"):
            g = self.gate(rs, **({} if flag is None else {"SFAB_REQUIRE_NAMECHECK": flag}))
            self.assertEqual(g.returncode, 0, g.stdout + g.stderr)
            self.assertIn("  SKIP  namecheck in the set (no scrub list)", g.stdout)
            self.assertIn("  SKIP  literal scan (no literal in the literals file)", g.stdout)
            self.assertIn("  SKIP  namecheck in the repo (no scrub list)", g.stdout)
        g = self.gate(rs, SFAB_REQUIRE_NAMECHECK="1")
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertIn("  FAIL  namecheck clean in the set -> no scrub list, and SFAB_REQUIRE_NAMECHECK is set", g.stdout)
        self.assertIn("  FAIL  literal scan clean -> no literal in the literals file, and SFAB_REQUIRE_NAMECHECK is set",
                      g.stdout)
        self.assertIn("  FAIL  namecheck clean in the repo -> no scrub list, and SFAB_REQUIRE_NAMECHECK is set", g.stdout)
        self.assertNotIn("  SKIP  ", g.stdout)
        home = self.t / "home"
        home.mkdir()
        g = self.gate(rs, SFAB_REQUIRE_NAMECHECK="1", SFAB_SCRUB_SECRETS="", HOME=str(home))
        self.assertEqual(g.returncode, 1, g.stdout + g.stderr)
        self.assertIn("  FAIL  literal scan clean -> no literals file, and SFAB_REQUIRE_NAMECHECK is set", g.stdout)
        # with both lists the flag changes nothing: every check runs, and a clean set passes
        absent = "zq" + uuid.uuid4().hex[:12]
        (self.t / "scrub-list.txt").write_text(f"# fail: names\n{absent}\n")
        (self.t / "literals.txt").write_text("zq" + uuid.uuid4().hex[:12] + "\n")
        g = self.gate(rs, SFAB_REQUIRE_NAMECHECK="1", SFAB_SCRUB_LIST=str(self.t / "scrub-list.txt"),
                      SFAB_SCRUB_SECRETS=str(self.t / "literals.txt"))
        self.assertEqual(g.returncode, 0, g.stdout[-3000:] + g.stderr[-1000:])
        for line in ("  PASS  namecheck clean in the set", "  PASS  literal scan clean", "  PASS  namecheck clean in the repo"):
            self.assertIn(line, g.stdout)

    def test_m1_audit_red_and_quick(self):
        self.healthy_lab()
        self.env["SHIM_BREAK"] = "session-down"
        r = self.audit()
        self.assertEqual(r.returncode, 1, r.stdout[-3000:])
        self.assertIn("  FAIL  fe-sw2: session up -> want up, got down", r.stdout)
        rs = sorted((self.lab / "audits").glob("sfab-m1_audit_*"))[-1]
        self.assertRegex((rs / "RESULT.txt").read_text(), r"[1-9]\d* failed")
        g = subprocess.run([str(COMMON / "audit" / "gate.sh"), str(rs)], env=self.env, capture_output=True, text=True, cwd=self.lab)
        self.assertNotEqual(g.returncode, 0)
        del self.env["SHIM_BREAK"]
        before = sorted((self.lab / "audits").glob("sfab-m1_audit_*"))
        r = self.audit("--quick")
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        self.assertEqual(sorted((self.lab / "audits").glob("sfab-m1_audit_*")), before, "a quick audit records nothing")
        self.assertNotIn("k8s-gpu1: guest", r.stdout)


if __name__ == "__main__":
    unittest.main()
