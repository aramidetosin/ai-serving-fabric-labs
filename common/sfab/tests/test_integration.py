"""Integration tests: the contracts between the renderers, the stages and the images, checked on
the M1 render (dev/m1/chapter.yaml) rendered fresh from the spec.

- gen/RENDER.json keeps the renderer list inside its generator block, which `sfab check` and the
  stage markers leave out, so a renderer landing that writes nothing for a lab is no drift.
- Every state/ path the topology binds is one gen/clab-state.json tells the up stage to make or
  check, and every bootstrap/ path it binds is a rendered file or directory.
- The topology, gen/inventory.json and gen/expect agree on NUM_NICS, management addresses and
  container names; each VM guest's node.env agrees with the topology env vm-init.sh checks.
- The firewall XML's sha256 in gen/RENDER.json is the one boot.sh hands fw-startup.py.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_integration -v
"""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / "dev" / "m1"

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def _render():
    from sfab import render as R  # noqa: PLC0415
    from sfab.spec import load, load_chapter, select  # noqa: PLC0415

    spec = load(ROOT)
    model = select(spec, load_chapter(LAB))
    ctx = R.Context(outdir=LAB, labdir=LAB, root=ROOT, spec=spec)
    res = R.render_all(model, ctx)
    return model, {p: b.decode("utf-8") for p, b in res.outputs.items()}


_CACHE: dict = {}


def m1():
    if not _CACHE:
        _CACHE["model"], _CACHE["out"] = _render()
    return _CACHE["model"], _CACHE["out"]


def _env_file(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            out[k] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] == "'" else v
    return out


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class TestRenderJson(unittest.TestCase):
    def test_renderer_list_is_not_compared(self):
        from sfab.cli import _render_json_core  # noqa: PLC0415

        _model, out = m1()
        rj = json.loads(out["gen/RENDER.json"])
        self.assertNotIn("renderers", rj, "the renderer list belongs to the generator block")
        self.assertIn("renderers", rj["generator"])
        other = copy.deepcopy(rj)
        # a renderer that lands, or one that goes, while writing nothing for this lab
        other["generator"]["renderers"]["present"].append("later")
        other["generator"]["renderers"]["skipped"] = ["gone"]
        other["generator"]["sha256"] = "0" * 64
        self.assertEqual(_render_json_core(json.dumps(rj).encode()), _render_json_core(json.dumps(other).encode()))
        other["files"]["bootstrap/x"] = "0" * 64
        self.assertNotEqual(_render_json_core(json.dumps(rj).encode()), _render_json_core(json.dumps(other).encode()))

    def test_firewall_sha_for_boot(self):
        _model, out = m1()
        rj = json.loads(out["gen/RENDER.json"])
        xml = out["bootstrap/fw/startup-config.xml"].encode("utf-8")
        self.assertEqual(rj["files"]["bootstrap/fw/startup-config.xml"], hashlib.sha256(xml).hexdigest())
        self.assertIn("<config", xml[:200].decode())


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class TestTopologyContracts(unittest.TestCase):
    def setUp(self):
        self.model, self.out = m1()
        self.topo = yaml.safe_load(self.out["topo.clab.yml"])
        self.state = json.loads(self.out["gen/clab-state.json"])
        self.inv = json.loads(self.out["gen/inventory.json"])

    def test_binds_are_prepared_or_rendered(self):
        dirs, files = set(self.state["dirs"]), set(self.state["files"])
        rendered = set(self.out)
        for name, node in self.topo["topology"]["nodes"].items():
            for b in node.get("binds") or []:
                src = b.split(":", 1)[0]
                if src.startswith("state/"):
                    self.assertTrue(src in dirs or src in files, f"{name}: {src} is not in gen/clab-state.json")
                elif src.startswith("bootstrap/"):
                    self.assertTrue(src in rendered or any(p.startswith(src + "/") for p in rendered),
                                    f"{name}: {src} is not rendered")
                else:
                    self.fail(f"{name}: bind source {src} is neither under state/ nor bootstrap/")
            sc = node.get("startup-config")
            if sc:
                self.assertIn(sc, rendered, name)
        for d in self.state["bootstrap_dirs"]:
            self.assertTrue(any(p.startswith(d + "/") for p in rendered), d)

    def test_env_references_are_listed(self):
        refs = set()
        for node in self.topo["topology"]["nodes"].values():
            for v in (node.get("env") or {}).values():
                if v.startswith("${"):
                    refs.add(v[2:-1])
        self.assertEqual(sorted(refs), self.state["env"])
        self.assertEqual(self.state["max_workers"], len(self.topo["topology"]["nodes"]))

    def test_nodes_agree(self):
        nodes = self.topo["topology"]["nodes"]
        self.assertEqual(sorted(nodes), sorted(self.inv["nodes"]))
        for name, node in nodes.items():
            inv = self.inv["nodes"][name]
            self.assertEqual(node["mgmt-ipv4"], inv["mgmt"], name)
            self.assertEqual(inv["container"], f"sfab-m1-{name}", name)
        for sw in self.model.switches:
            ex = json.loads(self.out[f"gen/expect/{sw}.json"])
            self.assertEqual(int(nodes[sw]["env"]["NUM_NICS"]), ex["num_nics"], sw)
            self.assertEqual(ex["mgmt"], nodes[sw]["mgmt-ipv4"], sw)
            self.assertIn(f"bootstrap/{sw}/startup-config.cfg", self.out, sw)
        for sw in ("fe-sw1", "fe-sw2"):
            self.assertEqual(nodes[sw]["env"].get("CLAB_MGMT_PASSTHROUGH"), "true", sw)
        # FRAMEWORK 6.2: the rail switches 8 NICs, the out-of-band switch 3, the pair per slice and at
        # least 13 (its dedicated keepalive link is eth13 in every lab that has the pair)
        self.assertEqual({sw: nodes[sw]["env"]["NUM_NICS"] for sw in self.model.switches},
                         {"fe-sw1": "13", "fe-sw2": "13", "rail-sw1": "8", "rail-sw2": "8", "oob-sw": "3"})

    def test_judge_inventory_matches_expect(self):
        # boot's wait_fabric and the audit judge read the pair from gen/inventory.json; FRAMEWORK
        # 3.3 names gen/expect. Both are rendered from one model, and this keeps them equal.
        for sw in self.model.switches:
            inv = self.inv["nodes"][sw]
            ex = json.loads(self.out[f"gen/expect/{sw}.json"])
            self.assertEqual(sorted(inv.get("portchannels") or {}), sorted(ex["portchannels"]), sw)
            for name, pc in (inv.get("portchannels") or {}).items():
                e = ex["portchannels"][name]
                self.assertEqual(pc["members"], e["members"], f"{sw} {name}")
                self.assertEqual(pc["mclag"], e["mclag"], f"{sw} {name}")
                self.assertEqual(pc["vlans"], e["vlans"], f"{sw} {name}")
                self.assertEqual(pc["mode"], e["mode"], f"{sw} {name}")
            mc, emc = inv.get("mclag"), ex["mclag"]
            if mc:
                for k in ("domain", "peer_ip", "peer_link", "session_vrf", "source_ip", "system_mac"):
                    self.assertEqual(mc[k], emc[k], f"{sw} mclag {k}")
            else:
                self.assertIsNone(emc, sw)
            self.assertEqual(sorted(inv.get("access") or {}), sorted(ex["access"]), sw)

    def test_links_use_connected_nics(self):
        nodes = self.topo["topology"]["nodes"]
        used: dict = {}
        for l in self.topo["topology"]["links"]:
            for end in l["endpoints"]:
                n, eth = end.split(":")
                self.assertNotIn(eth, used.setdefault(n, set()), f"{end} used twice")
                used[n].add(eth)
        for sw in self.model.switches:
            top = max(int(e[3:]) for e in used[sw])
            self.assertEqual(int(nodes[sw]["env"]["NUM_NICS"]), top, sw)

    def test_guest_env_matches_node_env(self):
        nodes = self.topo["topology"]["nodes"]
        for g in ("k8s-gpu1", "k8s-gpu2"):
            ne = _env_file(self.out[f"bootstrap/{g}/node.env"])
            env = nodes[g]["env"]
            for k in ("VM_MEMORY_MB", "VM_SMP", "VM_DISK_GIB", "VM_NICS", "VM_TX_OFF"):
                self.assertEqual(env[k], ne[k], f"{g} {k}")
            self.assertEqual(env["SFAB_NODE"], ne["NODE_NAME"])
            self.assertEqual(env["SFAB_LAB"], ne["LAB"])
            self.assertEqual(ne["MGMT_ADDR"].split("/")[0], nodes[g]["mgmt-ipv4"])
            used = {e.split(":")[1] for l in self.topo["topology"]["links"] for e in l["endpoints"] if e.startswith(g + ":")}
            self.assertEqual(set(env["VM_NICS"].split()), used, g)


if __name__ == "__main__":
    unittest.main()
