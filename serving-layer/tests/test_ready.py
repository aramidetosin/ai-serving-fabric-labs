"""sfab-ready, the serving image's readiness probes, run by bash against a stand-in /proc/net/tcp,
a stand-in health endpoint on the loopback and a closed loopback port. No model and no network
beyond 127.0.0.1. Needs bash and timeout (GNU coreutils), as the image has.

Run from serving-layer/:  python3 -m unittest discover -s tests -t .
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
READY = HERE / "image" / "sfab-ready"
BASH = shutil.which("bash")
TIMEOUT = shutil.which("timeout")
HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def row(local: str, remote: str, st: str, retr: str = "00000000") -> str:
    return f"   0: {local} {remote} {st} 00000000:00000000 00:00000000 {retr} 65532        0 1 1 0 100 0 0 10 0\n"


class Health(BaseHTTPRequestHandler):
    status = 200

    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(Health.status if self.path == "/health" else 404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(BASH and TIMEOUT, "bash and timeout are needed")
class Ready(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), Health)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def setUp(self):
        Health.status = 200
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-ready-"))
        self.tcp = self.tmp / "tcp"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_ready(self, *args) -> subprocess.CompletedProcess:
        env = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin", "SFAB_READY_TCP": str(self.tcp),
               "SFAB_READY_HOST": "127.0.0.1", "SFAB_READY_WAIT_S": "1"}
        return subprocess.run([BASH, str(READY), *args], capture_output=True, text=True, env=env, timeout=30)

    def test_hexaddr_form(self):
        # 10.21.3.101:50052 as /proc/net/tcp writes it: the address's bytes reversed, then the port
        self.tcp.write_text(HEADER + row("6503150A:C384", "00000000:0000", "0A"))
        r = self.run_ready("worker", "10.21.3.101")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout, "ready: ggml-rpc-server listens on 10.21.3.101:50052\n")

    def test_worker_not_listening(self):
        self.tcp.write_text(HEADER + row("6503150A:C384", "6403150A:9C40", "01"))
        r = self.run_ready("worker", "10.21.3.101")
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not listen", r.stdout)

    def server(self, retr: str = "00000000", *extra):
        # an established session from the server to 127.0.0.1:50052, the worker on the loopback
        self.tcp.write_text(HEADER + row("0100007F:9C40", "0100007F:C384", "01", retr))
        return self.run_ready("server", "--port", str(self.port), "--probe-port", str(closed_port()), *extra, "127.0.0.1")

    def test_server_ready(self):
        r = self.server()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(r.stdout, "ready: llama-server answers, RPC sessions to 127.0.0.1 established, the rail answers\n")

    def test_server_loading(self):
        Health.status = 503
        r = self.server()
        self.assertEqual(r.returncode, 1)
        self.assertIn("answered GET /health with 503", r.stdout)

    def test_server_down(self):
        r = self.run_ready("server", "--port", str(closed_port()), "127.0.0.1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("does not accept connections", r.stdout)

    def test_no_session(self):
        self.tcp.write_text(HEADER)
        r = self.run_ready("server", "--port", str(self.port), "127.0.0.1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("no RPC session to the worker 127.0.0.1:50052", r.stdout)

    def test_stalled_session(self):
        r = self.server("00000003")
        self.assertEqual(r.returncode, 1)
        self.assertIn("stalled (3 retransmission timeouts)", r.stdout)
        self.assertEqual(self.server("00000002").returncode, 0)

    def test_probe_port_that_answers_is_refused_as_a_probe(self):
        self.tcp.write_text(HEADER + row("0100007F:9C40", "0100007F:C384", "01"))
        r = self.run_ready("server", "--port", str(self.port), "--probe-port", str(self.port), "127.0.0.1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("the probe needs a port where nothing listens", r.stdout)

    def test_usage(self):
        for args in ([], ["worker"], ["worker", "not-an-address"], ["server", "--port", "x", "1.2.3.4"], ["other", "1.2.3.4"]):
            with self.subTest(args=args):
                self.assertEqual(self.run_ready(*args).returncode, 2)

    @unittest.skipUnless(shutil.which("shellcheck"), "shellcheck is not installed")
    def test_shellcheck(self):
        r = subprocess.run(["shellcheck", "-s", "bash", str(READY)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
