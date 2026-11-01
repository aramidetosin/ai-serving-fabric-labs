"""The serving foundation (chapters 6 and 7): render/k8s.py's Multus manifest and serving.env,
render/host.py's hosts.toml for the images built here, images/registry/seed.py's local images,
images/fetch.py, and the agreement between the generator's serving.env and
serving-layer/serving.py, which reads it.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_serving_render -v

No cluster, no Docker and no network: the registry and the downloads are stand-ins in memory.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import shutil
import sys
import tarfile
import tempfile
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DASHES = (chr(0x2014), chr(0x2013))

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

SERVING_LAB = {"lab": "sfab-ch06", "profile": "a", "state": "one",
               "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2", "k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion",
                                   "inet-registry", "uplink-rtr", "ops-client", "ent-client", "truenas1"]},
               "features": {"k8s": True, "serving": True, "storage_setup": True}}
NO_SERVING = dict(SERVING_LAB, lab="sfab-m2", features={"k8s": True, "serving": False, "storage_setup": True})


def _mod(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


seed = _mod("sfab_registry_seed_serving", ROOT / "images" / "registry" / "seed.py")
fetch = _mod("sfab_fetch", ROOT / "images" / "fetch.py")
serving = _mod("sfab_serving_recipe", ROOT / "serving-layer" / "serving.py")


def sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


class Labs:
    _cache: dict = {}

    @classmethod
    def get(cls) -> dict:
        if not cls._cache:
            from sfab.render import Context, host, k8s
            from sfab.spec import load, select

            spec = load(ROOT)
            out = {"spec": spec}
            for key, sel in (("serving", SERVING_LAB), ("plain", NO_SERVING)):
                m = select(spec, sel)
                ctx = Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-serving", labdir=ROOT / "dev" / "m2", root=ROOT, spec=spec)
                out[key] = {"model": m, "ctx": ctx, "k8s": k8s.render(m, ctx), "host": host.render(m, ctx)}
            cls._cache = out
        return cls._cache


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class ServingRender(unittest.TestCase):
    def setUp(self):
        self.lab = Labs.get()["serving"]
        self.out = self.lab["k8s"]

    def test_files_only_with_serving(self):
        self.assertIn("bootstrap/k8s/12-multus-daemonset-thick.yaml", self.out)
        self.assertIn("bootstrap/k8s/serving.env", self.out)
        plain = Labs.get()["plain"]["k8s"]
        self.assertFalse([p for p in plain if "multus" in p or "serving" in p])
        self.assertNotIn("12-multus", plain["bootstrap/k8s/apply.list"])
        lines = [l for l in self.out["bootstrap/k8s/apply.list"].splitlines() if not l.startswith("#")]
        self.assertEqual(lines[:4], ["05-namespaces.yaml", "07-operators.yaml", "10-gateway-api-crds.yaml", "12-multus-daemonset-thick.yaml"])

    def test_multus_is_upstream_with_two_changes(self):
        text = self.out["bootstrap/k8s/12-multus-daemonset-thick.yaml"]
        body = "".join(l + "\n" for l in text.splitlines()[text.splitlines().index("# Note:"):])
        up = (ROOT / "common/sfab/render/upstream/multus-v4.3.0-daemonset-thick.yml").read_text()
        plat = self.lab["model"].meta.versions["kubernetes"]["multus"]["image"]["platform_digest"]
        want = up.replace("image: ghcr.io/k8snetworkplumbingwg/multus-cni:snapshot-thick\n",
                          f"image: ghcr.io/k8snetworkplumbingwg/multus-cni@{plat}\n")
        from sfab.render import k8s

        want = want.replace(k8s.MULTUS_RESOURCES_UPSTREAM, k8s.MULTUS_RESOURCES)
        self.assertEqual(body, want)
        docs = [d for d in yaml.safe_load_all(text) if d]
        ds = next(d for d in docs if d["kind"] == "DaemonSet")
        self.assertEqual(ds["metadata"]["name"], "kube-multus-ds")
        c = ds["spec"]["template"]["spec"]["containers"][0]
        self.assertEqual(c["resources"], {"requests": {"cpu": "100m", "memory": "100Mi"}, "limits": {"memory": "512Mi"}})
        self.assertNotIn("snapshot", text.split("# Note:")[1])

    def test_tampered_multus_refused(self):
        from sfab.render import RenderError, k8s
        from sfab.render import Context

        d = Path(tempfile.mkdtemp(prefix="sfab-multus-"))
        try:
            f = d / "common/sfab/render/upstream/multus-v4.3.0-daemonset-thick.yml"
            f.parent.mkdir(parents=True)
            f.write_text((ROOT / "common/sfab/render/upstream/multus-v4.3.0-daemonset-thick.yml").read_text() + "# x\n")
            ctx = Context(outdir=d, labdir=d, root=d, spec=Labs.get()["spec"])
            with self.assertRaises(RenderError):
                k8s.multus(self.lab["model"], ctx)
        finally:
            shutil.rmtree(d)

    def env(self) -> dict:
        d = Path(tempfile.mkdtemp(prefix="sfab-serving-env-"))
        try:
            p = d / "serving.env"
            p.write_text(self.out["bootstrap/k8s/serving.env"])
            return serving.read_env(p)
        finally:
            shutil.rmtree(d)

    def test_serving_env_reads_in_the_recipe(self):
        """The generator writes what serving-layer/serving.py reads, and its placement rules pass."""
        s = serving.settings(self.env())
        self.assertEqual(s.lab, "sfab-ch06")
        self.assertTrue(s.kubectl[0].endswith("common/bin/sfab-kubectl"), "kubectl runs on the init node, not the bastion")
        self.assertEqual(len(s.kubectl), 2)
        self.assertEqual(s.image, "192.0.2.6:5000/sfab/serving:b11382-2")
        self.assertEqual(s.keys_image, "192.0.2.6:5000/sfab/keys:3")
        self.assertEqual(s.key_prefix, "sk-tw-serving")
        self.assertEqual(sorted(s.copies), [("chat", "a"), ("chat", "b"), ("chat", "c"), ("staff", "a"), ("staff", "b")])
        self.assertEqual([n["name"] for n in s.nads], ["rail3", "rail4", "rail5", "rail6", "rail7"])
        rails = {k: c["server"]["rail"] for k, c in s.copies.items()}
        self.assertEqual(rails, {("chat", "a"): "3", ("chat", "b"): "6", ("chat", "c"): "7", ("staff", "a"): "4", ("staff", "b"): "5"})
        self.assertEqual(s.models_path, "/srv/models")
        self.assertEqual([(m["name"], m["file"], m["bytes"]) for m in s.models],
                         [("chat", "LFM2.5-24B-A2B-Q4_K_M.gguf", "14526258464"), ("staff", "Qwen3.8-27B-UD-Q4_K_M.gguf", "16464440224")])
        # every node-local copy inside one node, the spanning copy c across both
        nodes = {k: {c["server"]["node"]} | {w["node"] for w in c["workers"]} for k, c in s.copies.items()}
        self.assertEqual(nodes[("chat", "c")], {"k8s-gpu1", "k8s-gpu2"})
        self.assertTrue(all(len(v) == 1 for k, v in nodes.items() if k != ("chat", "c")), nodes)
        self.assertEqual(s.route["gateway"], "gw-internal")
        self.assertEqual(s.route["hostname"], "serve.ai.tarnwick.example")
        self.assertEqual(s.load["exec"], ["docker", "exec", "-i", "sfab-ch06-ops-client"])
        self.assertEqual(s.load["resolve"], "serve.ai.tarnwick.example:443:10.20.11.200", "the operator's VIP, through the tunnel")
        self.assertEqual(s.decision_label, "decision.tarnwick.example/id")
        # every rail address inside the rail's pod range, clear of the nodes' own .11 and .12
        for p in s.pods:
            last = int(p["address"].split("/")[0].rsplit(".", 1)[1])
            self.assertTrue(100 <= last <= 199, p)
        # the manifests render, and each model has a copy on each rail parity, so on each rail switch
        files = serving.manifests(s)
        self.assertIn("ggml-rpc-server", files["20-workers.yaml"])
        self.assertIn("kind: StatefulSet", files["30-servers.yaml"])
        for model in ("chat", "staff"):
            par = {int(c["server"]["rail"]) % 2 for k, c in s.copies.items() if k[0] == model}
            self.assertEqual(par, {0, 1}, model)

    def test_placement_matches_the_spec(self):
        m = self.lab["model"]
        s = serving.settings(self.env())
        want = [(r.pod, r.model, r.copy, r.role, r.node, str(r.rail)) for r in m.placement]
        got = [(p["pod"], p["model"], p["copy"], p["role"], p["node"], p["rail"]) for p in s.pods]
        self.assertEqual(got, want)

    def test_summary(self):
        k = json.loads(self.out["gen/k8s.json"])
        self.assertEqual(k["multus"]["daemonset"], "kube-system/kube-multus-ds")
        self.assertEqual(k["serving"]["route"]["request"], "900s")
        self.assertEqual(len(k["serving"]["placement"]), 11)
        self.assertEqual(k["serving"]["weights"], {"dir": "images/models", "tag": "models", "guest": "/srv/models",
                                                   "nodes": ["k8s-gpu1", "k8s-gpu2"]})
        self.assertNotIn("serving", json.loads(Labs.get()["plain"]["k8s"]["gen/k8s.json"]))

    def test_plain_and_no_secret(self):
        for p in ("bootstrap/k8s/serving.env",):
            text = self.out[p]
            self.assertTrue(text.startswith("# sfab-ch06 serving: rendered from spec/profile-a.yaml by render/k8s.py"))
            self.assertNotRegex(text, r"sk-[a-z]+-[a-z0-9]+-[0-9a-f]{32}")
            for d in DASHES:
                self.assertNotIn(d, text)
        head = [l for l in self.out["bootstrap/k8s/12-multus-daemonset-thick.yaml"].splitlines() if l.startswith("# sfab-ch06")]
        self.assertEqual(len(head), 1)

    def test_every_image_the_serving_lab_names_is_seeded(self):
        images, _ = seed.collect(self.lab["model"].meta.versions)
        local = seed.collect_local(self.lab["model"].meta.versions)
        served_one = {f"{im.host}/{im.repo}": im for im in images if im.platform}
        text = "\n".join(self.out.values())
        for ref in re.findall(r"\b((?:[a-z0-9-]+\.)+[a-z]+/[a-z0-9./_-]+@sha256:[0-9a-f]{64})", text):
            repo = ref.split("@")[0]
            if repo in served_one:
                pin = self.lab["model"].meta.versions["kubernetes"]
                plats = {str((v.get("image") or {}).get("platform_digest")) for v in pin.values() if isinstance(v, dict)}
                self.assertIn(ref.split("@")[1], plats, ref)
        env = self.env()
        for key in ("SERVING_IMAGE", "SERVING_KEYS_IMAGE"):
            mirror, _, path = env[key].partition("/")
            self.assertEqual(mirror, "192.0.2.6:5000")
            self.assertIn(path, {im.mirror_path for im in local})

    def test_validation(self):
        from sfab.render import RenderError, k8s

        m = self.lab["model"]
        bad = dict(m.spec["serving"], route=dict(m.spec["serving"]["route"], backend_request_s=901))
        m2 = type(m).__new__(type(m))
        m2.__dict__.update(m.__dict__)
        object.__setattr__(m2, "spec", dict(m.spec, serving=bad))
        with self.assertRaises(RenderError):
            k8s.serving_settings(m2)
        self.assertTrue(k8s._covered("serve.ai.tarnwick.example", ["*.ai.tarnwick.example"]))
        self.assertFalse(k8s._covered("a.serve.tarnwick.example", ["*.ai.tarnwick.example"]))
        self.assertFalse(k8s._covered("serve.corvane.example", ["*.ai.tarnwick.example"]))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to load the spec")
class MirrorHosts(unittest.TestCase):
    def test_hosts_toml_for_the_images_built_here(self):
        lab = Labs.get()["serving"]
        h = lab["host"]
        mirror = lab["model"].registry.mirror
        for n in ("k8s-cp1", "k8s-cp2", "k8s-cp3", "k8s-gpu1", "k8s-gpu2"):
            p = f"bootstrap/{n}/containerd/{mirror}/hosts.toml"
            self.assertEqual(h[p], seed.hosts_toml_local(mirror, "https", "/shared/ca/root.crt"), p)
        self.assertFalse([p for p in Labs.get()["plain"]["host"] if f"/containerd/{mirror}/" in p])


# ------------------------------------------------------------------------------------------
# The seed's images built here


def saved_archive(path: Path, config: bytes, layers: list) -> None:
    """A docker save archive in the OCI layout Docker 25 and later writes, with manifest.json."""
    with tarfile.open(path, "w") as t:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))

        cfg = f"blobs/sha256/{hashlib.sha256(config).hexdigest()}"
        add(cfg, config)
        names = []
        for l in layers:
            n = f"blobs/sha256/{hashlib.sha256(l).hexdigest()}"
            add(n, l)
            names.append(n)
        add("manifest.json", json.dumps([{"Config": cfg, "RepoTags": ["sfab/x:1"], "Layers": names}]).encode())
        add("index.json", b"{}")


class Resp:
    def __init__(self, status, headers=None, body=b""):
        self.status, self.headers, self._b = status, headers or {}, io.BytesIO(body)

    def read(self, n=-1):
        return self._b.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeRegistry:
    def __init__(self):
        self.blobs, self.tags, self.writes = {}, {}, 0

    def __call__(self, req):
        u = urllib.parse.urlsplit(req.full_url)
        path, method = u.path, req.get_method()
        m = re.match(r"^/v2/(.+)/manifests/([^/]+)$", path)
        if m:
            repo, ref = m.groups()
            if method in ("GET", "HEAD"):
                body = self.tags.get((repo, ref))
                if body is None:
                    return Resp(404)
                return Resp(200, {"Docker-Content-Digest": sha(body)}, body if method == "GET" else b"")
            self.writes += 1
            self.tags[(repo, ref)] = req.data
            return Resp(201, {"Docker-Content-Digest": sha(req.data)})
        m = re.match(r"^/v2/(.+)/blobs/(sha256:[0-9a-f]{64})$", path)
        if m and method == "HEAD":
            return Resp(200 if m.group(2) in self.blobs else 404)
        if re.match(r"^/v2/(.+)/blobs/uploads/$", path) and method == "POST":
            return Resp(202, {"Location": path + "u1"})
        if re.match(r"^/v2/(.+)/blobs/uploads/u1$", path) and method == "PUT":
            self.writes += 1
            data = req.data.read() if hasattr(req.data, "read") else req.data
            want = urllib.parse.parse_qs(u.query)["digest"][0]
            if sha(data) != want:
                return Resp(400)
            self.blobs[want] = data
            return Resp(201)
        return Resp(405)


class SeedLocal(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-seed-local-"))
        self.reg = FakeRegistry()
        self.http = seed.Http("http://127.0.0.1:5099", opener=self.reg)
        self.im = seed.Local(id="images.x", ref="sfab/x:1", repo="sfab/x", tag="1")
        self.config = b'{"architecture":"amd64","os":"linux","rootfs":{"type":"layers"}}'
        self.layers = [b"layer one" * 1000, b"layer two"]

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def save(self, im):
        p = self.tmp / "x.tar"
        saved_archive(p, self.config, self.layers)
        return p

    def test_collect_local(self):
        tree = {"images": {"serving": {"ref": "sfab/serving:b1-1", "mirror": "local"}, "client": {"ref": "sfab/client:2"},
                           "up": {"ref": "ghcr.io/o/m:1", "digest": "sha256:" + "a" * 64, "mirror": True}}}
        self.assertEqual([x.ref for x in seed.collect_local(tree)], ["sfab/serving:b1-1"])
        for bad in ({"ref": "ghcr.io/sfab/x:1", "mirror": "local"}, {"ref": "sfab/x", "mirror": "local"},
                    {"ref": "sfab/x:1", "mirror": "local", "digest": "sha256:" + "a" * 64}, {"ref": "sfab/X:1", "mirror": "local"}):
            with self.subTest(bad=bad), self.assertRaises(seed.SeedError):
                seed.collect_local({"images": {"b": bad}})
        real = seed.collect_local(seed.load_tree(None)[0])
        self.assertEqual([x.mirror_path for x in real], ["sfab/keys:3", "sfab/keys:4", "sfab/serving:b11382-2"])

    def test_push_is_byte_stable_and_once(self):
        res = seed.seed_local([self.im], self.http, lambda ref: sha(self.config), self.save)
        (im, served, iid, cfg, action) = res[0]
        self.assertEqual(action, "pushed")
        self.assertEqual(cfg, sha(self.config))
        man = json.loads(self.reg.tags[("sfab/x", "1")])
        self.assertEqual(man["mediaType"], seed.OCI_MANIFEST)
        self.assertEqual([l["digest"] for l in man["layers"]], [sha(l) for l in self.layers])
        self.assertEqual({l["mediaType"] for l in man["layers"]}, {seed.OCI_LAYER_TAR})
        self.assertEqual(served, sha(seed.local_manifest(sha(self.config), len(self.config), [(sha(l), len(l)) for l in self.layers])))
        self.assertFalse((self.tmp / "x.tar").exists(), "the archive is removed after the push")
        rec = json.loads(seed.seed_record(seed.Result(local=res), "v" * 64))
        self.assertEqual(rec["local"][0]["served"], served)
        writes = self.reg.writes

        def no_save(im):
            raise AssertionError("an image whose id and manifest match SEED.json is not saved again")

        second = seed.seed_local([self.im], self.http, lambda ref: sha(self.config), no_save, record=rec)
        self.assertEqual(second[0][4], "present")
        self.assertEqual(self.reg.writes, writes)
        # a rebuilt image is pushed again
        res3 = seed.seed_local([self.im], self.http, lambda ref: "sha256:" + "f" * 64, self.save, record=rec)
        self.assertEqual(res3[0][4], "pushed")

    def test_check_data_local(self):
        store = self.tmp / "data" / "docker" / "registry" / "v2"

        def blob(b: bytes) -> str:
            d = sha(b)
            p = store / "blobs" / "sha256" / d[7:9] / d[7:] / "data"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b)
            return d

        man = seed.local_manifest(blob(self.config), len(self.config), [(blob(l), len(l)) for l in self.layers])
        d = blob(man)
        link = store / "repositories" / "sfab/x" / "_manifests" / "tags" / "1" / "current" / "link"
        link.parent.mkdir(parents=True)
        link.write_text(d)
        data = self.tmp / "data"
        self.assertTrue(seed.check_data(data, [], [], record={}, local=[self.im]))
        rec = {"local": [{"ref": "sfab/x:1", "served": d}]}
        self.assertEqual(seed.check_data(data, [], [], record=rec, local=[self.im]), [])
        lay = sha(self.layers[0])
        (store / "blobs" / "sha256" / lay[7:9] / lay[7:] / "data").unlink()
        self.assertTrue(any("missing" in p for p in seed.check_data(data, [], [], record=rec, local=[self.im])))

    def test_hosts_toml_local_cli(self):
        import subprocess

        r = subprocess.run([sys.executable, str(ROOT / "images/registry/seed.py"), "hosts-toml", "--mirror", "192.0.2.6:5000", "--local"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.stdout, 'server = "http://192.0.2.6:5000"\n\n[host."http://192.0.2.6:5000"]\n  capabilities = ["pull", "resolve"]\n')
        r = subprocess.run([sys.executable, str(ROOT / "images/registry/seed.py"), "hosts-toml", "--mirror", "m:1"],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1)


# ------------------------------------------------------------------------------------------
# images/fetch.py


class Fetch(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-fetch-"))
        self.data = b"pinned bytes"
        self.pin = {"name": "f.bin", "url": "https://files.example/f.bin", "sha256": hashlib.sha256(self.data).hexdigest(),
                    "size": len(self.data)}
        self.calls = []

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def opener(self, data):
        def op(req):
            self.calls.append(req.full_url)
            return Resp(200, {}, data)
        return op

    def test_download_once(self):
        msg = fetch.fetch(self.pin, self.tmp, opener=self.opener(self.data))
        self.assertIn("downloaded and checked", msg)
        self.assertEqual((self.tmp / "f.bin").read_bytes(), self.data)
        msg = fetch.fetch(self.pin, self.tmp, opener=self.opener(b"never read"))
        self.assertIn("nothing to download", msg)
        self.assertEqual(len(self.calls), 1)

    def test_wrong_bytes_refused(self):
        with self.assertRaises(fetch.FetchError):
            fetch.fetch(self.pin, self.tmp, opener=self.opener(b"other bytes"))
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_real_pins(self):
        tree = fetch.pins.load()
        for k in ("serving.llama_cpp", "serving.models.chat", "serving.models.staff", "serving.debs.libgomp1", "serving.debs.libssl3", "keys.pyyaml"):
            p = fetch.pin_of(tree, k)
            self.assertRegex(p["sha256"], r"^[0-9a-f]{64}$", k)
            self.assertTrue(p["url"].startswith(("https://", "http://deb.debian.org/")), k)
            self.assertTrue(urllib.parse.unquote(p["url"]).endswith("/" + p["name"]), k)
            self.assertIsInstance(p["size"], int, k)


class Docs(unittest.TestCase):
    def test_no_dashes(self):
        for f in ("images/fetch.py", "images/keys/sfab-keys", "images/keys/README.md", "serving-layer/image/Dockerfile",
                  "serving-layer/image/image.mk", "common/sfab/render/k8s.py", "images/registry/seed.py", "spec/versions.yaml"):
            text = (ROOT / f).read_text(encoding="utf-8")
            for d in DASHES:
                self.assertNotIn(d, text, f)


if __name__ == "__main__":
    unittest.main()
