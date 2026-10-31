"""client.py against a stand-in OpenAI-compatible server on the loopback: the request it sends (the
path under the base URL, the bearer key, the body), the answer it prints, a refusal, and that no
key, timing or token count reaches its output. No model and no network beyond 127.0.0.1.

Run from serving-layer/:  python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sfab_client", HERE / "client.py")
cl = importlib.util.module_from_spec(spec)
sys.modules["sfab_client"] = cl
spec.loader.exec_module(cl)

KEY = "sk-test-4567"   # a made-up key: the stand-in server checks it, nothing else sees it


class Handler(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n) or b"{}")
        Handler.seen.append({"path": self.path, "auth": self.headers.get("Authorization"), "body": body,
                             "type": self.headers.get("Content-Type")})
        if self.headers.get("Authorization") != f"Bearer {KEY}":
            out, code = {"error": {"message": "Invalid API Key", "type": "authentication_error"}}, 401
        else:
            out, code = {"model": body.get("model"), "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": " It routes requests to models. "}}],
                         "usage": {"prompt_tokens": 12, "completion_tokens": 7},
                         "timings": {"predicted_per_second": 123.4}}, 200
        data = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Handler.seen = []
        fd, self.kf = tempfile.mkstemp(prefix="sfab-client-key-")
        with os.fdopen(fd, "w") as f:
            f.write(KEY + "\n")

    def tearDown(self):
        os.unlink(self.kf)

    def run_main(self, *extra):
        out = io.StringIO()
        old = sys.stdout
        sys.stdout = out
        try:
            rc = cl.main(["--base-url", f"http://chat.example.test:{self.port}/chat/v1", "--key-file", self.kf,
                          "--resolve", f"chat.example.test:{self.port}:127.0.0.1", *extra])
        finally:
            sys.stdout = old
        return rc, out.getvalue()

    def test_answered(self):
        rc, out = self.run_main()
        self.assertEqual(rc, 0)
        s = Handler.seen[0]
        self.assertEqual(s["path"], "/chat/v1/chat/completions")
        self.assertEqual(s["auth"], f"Bearer {KEY}")
        self.assertEqual(s["type"], "application/json")
        self.assertEqual(s["body"]["model"], "chat")
        self.assertEqual(s["body"]["messages"], [{"role": "user", "content": cl.PROMPT}])
        self.assertNotIn("stream", s["body"])
        self.assertIn("-> HTTP 200, application/json; charset=utf-8", out)
        self.assertIn("  model: chat\n", out)
        self.assertIn("  finish_reason: stop\n", out)
        self.assertIn("  answer: It routes requests to models.\n", out)
        self.assertIn("  PASS  an OpenAI-compatible chat completion at", out)
        self.assertIn("== RESULT: 1 passed, 0 failed, 0 known platform limitation(s), 0 skipped", out)

    def test_no_key_timing_or_count_printed(self):
        rc, out = self.run_main()
        self.assertEqual(rc, 0)
        self.assertNotIn(KEY, out)
        for word in ("per_second", "123.4", "tokens", "usage", "timings"):
            self.assertNotIn(word, out)

    def test_refused(self):
        with open(self.kf, "w") as f:
            f.write("sk-test-wrong\n")
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertIn("-> HTTP 401, application/json; charset=utf-8 (http 401: Invalid API Key)", out)
        self.assertIn("  FAIL  an OpenAI-compatible chat completion at", out)
        self.assertIn("== RESULT: 0 passed, 1 failed", out)
        self.assertNotIn("sk-test-wrong", out)

    def test_model_named(self):
        rc, _ = self.run_main("--model", "staff")
        self.assertEqual(rc, 0)
        self.assertEqual(Handler.seen[0]["body"]["model"], "staff")

    def test_empty_key_file(self):
        with open(self.kf, "w") as f:
            f.write("")
        self.assertEqual(cl.main(["--base-url", "http://x.test/v1", "--key-file", self.kf]), 2)


if __name__ == "__main__":
    unittest.main()
