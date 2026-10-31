"""load.py against a stand-in OpenAI-compatible server on the loopback: answered, failed and cut
requests, the --resolve pin, the records and the report. No model and no network beyond 127.0.0.1.

Run from serving-layer/:  python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import importlib.util
import io
import json
import shutil
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sfab_load", HERE / "load.py")
ld = importlib.util.module_from_spec(spec)
sys.modules["sfab_load"] = ld
spec.loader.exec_module(ld)

KEY = "sk-test-0123"   # a made-up key: the stand-in server checks it, nothing else sees it


class Handler(BaseHTTPRequestHandler):
    mode = "ok"
    seen: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        Handler.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "host": self.headers.get("Host"),
                             "stream": body.get("stream"), "model": body.get("model")})
        if self.headers.get("Authorization") != f"Bearer {KEY}":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if Handler.mode == "500":
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()

        def chunk(d):
            self.wfile.write(b"data: " + json.dumps(d).encode() + b"\n\n")
            self.wfile.flush()

        if Handler.mode == "silent":
            time.sleep(0.6)
            return
        chunk({"choices": [{"delta": {"content": "Hello"}, "finish_reason": None}]})
        chunk({"choices": [{"delta": {"content": " there"}, "finish_reason": None}]})
        if Handler.mode == "cut" or (Handler.mode == "cut-some" and len(Handler.seen) % 2 == 0):
            self.wfile.flush()
            self.close_connection = True
            return
        chunk({"choices": [{"delta": {}, "finish_reason": "stop"}]})
        self.wfile.write(b"data: [DONE]\n\n")


class LoadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        cls.t = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Handler.mode = "ok"
        Handler.seen = []
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-load-"))
        self.keyfile = self.tmp / "key"
        self.keyfile.write_text(KEY + "\n")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def args(self, **kw):
        a = dict(url=f"http://llm.example.com:{self.port}/chat/v1", key_file=str(self.keyfile), users=2, seconds=1,
                 resolve=f"llm.example.com:{self.port}:127.0.0.1", model="", max_tokens=8, timeout=0.3, cafile="",
                 records=str(self.tmp / "rec.jsonl"), cut_ok=False, pause=0.1)
        a.update(kw)
        return type("A", (), a)()

    def run_load(self, **kw):
        out = io.StringIO()
        rc = ld.run(self.args(**kw), KEY, out)
        return rc, out.getvalue()

    def test_answered(self):
        rc, out = self.run_load()
        self.assertEqual(rc, 0, out)
        self.assertRegex(out, r"requests (\d+), answered \1, failed 0, cut mid-answer 0")
        self.assertIn(f"(llm.example.com pinned to 127.0.0.1)", out)
        self.assertIn("== RESULT: 3 passed, 0 failed", out)
        s = Handler.seen[0]
        self.assertEqual((s["path"], s["stream"], s["model"]), ("/chat/v1/chat/completions", True, "chat"))
        self.assertEqual(s["host"], f"llm.example.com:{self.port}")
        recs = [json.loads(l) for l in (self.tmp / "rec.jsonl").read_text().splitlines()]
        self.assertTrue(recs)
        for r in recs:
            self.assertEqual(sorted(r), ["n", "outcome", "start_s", "status", "user", "why"])
            self.assertEqual(r["outcome"], "answered")
        self.assertNotIn(KEY, out)
        self.assertNotIn(KEY, (self.tmp / "rec.jsonl").read_text())

    def test_failed_by_status(self):
        Handler.mode = "500"
        rc, out = self.run_load()
        self.assertEqual(rc, 1)
        self.assertIn("failed by what ended them: http 500", out)
        self.assertIn("FAIL  no failed request", out)

    def test_wrong_key_fails(self):
        out = io.StringIO()
        rc = ld.run(self.args(users=1), "sk-wrong", out)
        self.assertEqual(rc, 1)
        self.assertIn("http 401", out.getvalue())

    def test_cut_mid_answer(self):
        Handler.mode = "cut"
        rc, out = self.run_load()
        self.assertEqual(rc, 1)
        self.assertRegex(out, r"failed 0, cut mid-answer [1-9]")
        self.assertIn("FAIL  no stream cut mid-answer", out)
        Handler.mode = "cut-some"
        rc, out = self.run_load(cut_ok=True)
        self.assertEqual(rc, 0, out)
        self.assertIn("(reported, not judged)", out)
        self.assertRegex(out, r"answered [1-9][0-9]*, failed 0, cut mid-answer [1-9]")

    def test_silence_before_the_first_token_is_a_failure(self):
        Handler.mode = "silent"
        rc, out = self.run_load(users=1)
        self.assertEqual(rc, 1)
        self.assertIn("timeout", out)
        self.assertRegex(out, r"cut mid-answer 0")

    def test_refused_is_paced(self):
        out = io.StringIO()
        a = self.args(url="http://127.0.0.1:9/chat/v1", resolve="", users=1, seconds=1, pause=0.4)
        rc = ld.run(a, KEY, out)
        self.assertEqual(rc, 1)
        m = int(out.getvalue().split("requests ")[1].split(",")[0])
        self.assertLessEqual(m, 4, out.getvalue())

    def test_main_reads_the_key_file(self):
        self.keyfile.write_text("")
        self.assertEqual(ld.main(["--url", "http://127.0.0.1:9/v1", "--key-file", str(self.keyfile)]), 2)
        self.assertEqual(ld.main(["--url", "http://127.0.0.1:9/v1", "--key-file", str(self.tmp / "none")]), 2)

    def test_no_rate_in_the_report(self):
        rc, out = self.run_load()
        for word in ("per second", "/s", "tok/s", "ms", "latency", "throughput"):
            self.assertNotIn(word, out)


if __name__ == "__main__":
    unittest.main()
