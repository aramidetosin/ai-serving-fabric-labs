"""The gateway probe's schedule (common/drill/probe_gateway.py), each request answered by a stand-in for
its HTTPS exchange: --every sends a model's request on every K-th interval only, numbered among that
model's own requests."""
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

PROBE = Path(__file__).resolve().parents[1] / "drill" / "probe_gateway.py"


def load():
    spec = importlib.util.spec_from_file_location("probe_gateway", PROBE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Every(unittest.TestCase):
    def setUp(self):
        self.url = "https://gw.example/v1/chat/completions"
        self.dir = tempfile.mkdtemp(prefix="probe-")
        self.addCleanup(shutil.rmtree, self.dir, True)
        for m in ("chat", "staff"):
            Path(self.dir, f"key-{m}").write_text("k\n")

    def run_probe(self, *extra):
        mod = load()
        mod.one = lambda url, key, model, *a: {"status": 200, "outcome": "answered", "why": "", "model": f"openai/{model}",
                                               "base": None, "retries": 0}
        out = io.StringIO()
        with redirect_stdout(out):
            rc = mod.main(["--dir", self.dir, "--target", "chat", self.url, "--target", "staff", self.url,
                           "--interval", "0.01", "--count", "7", *extra])
        recs = {m: [json.loads(l) for l in Path(self.dir, f"records-{m}.jsonl").read_text().splitlines()]
                for m in ("chat", "staff")}
        return rc, out.getvalue(), recs

    def test_every(self):
        rc, out, recs = self.run_probe("--every", "staff", "3")
        self.assertEqual(rc, 0)
        self.assertEqual(len(recs["chat"]), 7)
        # intervals 1, 4 and 7
        self.assertEqual(sorted(r["n"] for r in recs["staff"]), [1, 2, 3])
        self.assertIn("staff: sent 3, answered 3, failed 0", out)
        self.assertTrue(all(r["outcome"] == "answered" for r in recs["chat"] + recs["staff"]))

    def test_without_every(self):
        rc, out, recs = self.run_probe()
        self.assertEqual((rc, len(recs["chat"]), len(recs["staff"])), (0, 7, 7))

    def test_refusals(self):
        for bad in (["--every", "nope", "2"], ["--every", "staff", "0"], ["--every", "staff", "x"]):
            with self.subTest(bad=bad), redirect_stdout(io.StringIO()):
                self.assertEqual(load().main(["--dir", self.dir, "--target", "staff", self.url, "--count", "1", *bad]), 2)


if __name__ == "__main__":
    unittest.main()
