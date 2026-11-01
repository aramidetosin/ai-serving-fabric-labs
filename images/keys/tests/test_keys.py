"""sfab-keys against a stand-in Kubernetes API on the loopback (Secrets and pods in memory) and a
stand-in API gateway: ensure, mint, revoke, list, compose and probe, and that no key is ever
printed. No cluster and no network beyond 127.0.0.1.

Run from the repo root:  python3 -m unittest discover -s images/keys/tests -t images/keys
"""

from __future__ import annotations

import base64
import contextlib
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader("sfab_keys", str(HERE / "sfab-keys"))
spec = importlib.util.spec_from_loader("sfab_keys", loader)
keys = importlib.util.module_from_spec(spec)
loader.exec_module(keys)

try:
    import yaml  # noqa: F401

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

TOKEN = "stand-in-token"  # a made-up service account token for the stand-in API


class FakeApi(BaseHTTPRequestHandler):
    secrets: dict = {}
    pods: list = []
    calls: list = []

    def log_message(self, *a):
        pass

    def _send(self, status: int, doc: dict) -> None:
        body = json.dumps(doc).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def _auth(self) -> bool:
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self._send(401, {"message": "Unauthorized"})
            return False
        return True

    def do_GET(self):
        FakeApi.calls.append(("GET", self.path))
        if not self._auth():
            return
        m = re.match(r"^/api/v1/namespaces/([^/]+)/secrets/([^/?]+)$", self.path)
        if m:
            s = FakeApi.secrets.get(m.groups())
            return self._send(200, s) if s else self._send(404, {"message": "not found"})
        if re.match(r"^/api/v1/namespaces/[^/]+/pods\?labelSelector=", self.path):
            return self._send(200, {"items": FakeApi.pods})
        self._send(404, {})

    def do_POST(self):
        FakeApi.calls.append(("POST", self.path))
        if not self._auth():
            return
        m = re.match(r"^/api/v1/namespaces/([^/]+)/secrets$", self.path)
        doc = self._body()
        k = (m.group(1), doc["metadata"]["name"])
        if k in FakeApi.secrets:
            return self._send(409, {"message": "exists"})
        FakeApi.secrets[k] = doc
        self._send(201, doc)

    def do_PATCH(self):
        FakeApi.calls.append(("PATCH", self.path, self.headers.get("Content-Type")))
        if not self._auth():
            return
        m = re.match(r"^/api/v1/namespaces/([^/]+)/secrets/([^/]+)$", self.path)
        s = FakeApi.secrets.get(m.groups())
        if not s:
            return self._send(404, {})
        for k, v in (self._body().get("data") or {}).items():
            if v is None:
                s["data"].pop(k, None)
            else:
                s["data"][k] = v
        self._send(200, s)


class Gateway(BaseHTTPRequestHandler):
    """A stand-in API gateway: GET answers 200 for an accepted key; POST takes only a JSON body and
    answers 200 for an accepted key, else 401 with key authentication's message; the accepted set
    may grow after a number of POSTs (a key loading)."""
    accept: set = set()
    later: dict = {}
    posts = 0
    bodies: list = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        ok = self.headers.get("Authorization", "").removeprefix("Bearer ") in Gateway.accept
        self.send_response(200 if ok else 401)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        Gateway.bodies.append((self.headers.get("Content-Type"), self.rfile.read(n).decode()))
        Gateway.posts += 1
        for k, after in list(Gateway.later.items()):
            if Gateway.posts > after:
                Gateway.accept.add(k)
        ok = self.headers.get("Authorization", "").removeprefix("Bearer ") in Gateway.accept
        body = b'{"choices": []}' if ok else b'{"message":"Invalid API key in request"}'
        self.send_response(200 if ok else 401)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def serve(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


class Keys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api_srv = serve(FakeApi)
        cls.gw_srv = serve(Gateway)
        cls.tmp = Path(tempfile.mkdtemp(prefix="sfab-keys-"))
        (cls.tmp / "token").write_text(TOKEN)
        cls.env = {"SFAB_KEYS_API": f"http://127.0.0.1:{cls.api_srv.server_address[1]}",
                   "SFAB_KEYS_TOKEN_FILE": str(cls.tmp / "token")}

    @classmethod
    def tearDownClass(cls):
        for s in (cls.api_srv, cls.gw_srv):
            s.shutdown()
            s.server_close()
        shutil.rmtree(cls.tmp)

    def setUp(self):
        FakeApi.secrets = {}
        FakeApi.pods = []
        FakeApi.calls = []
        self._old = {k: os.environ.get(k) for k in self.env}
        os.environ.update(self.env)

    def tearDown(self):
        for k, v in self._old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def run_keys(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = keys.main(list(argv))
        return rc, out.getvalue() + err.getvalue()

    def value(self, ns, name, field):
        return base64.b64decode(FakeApi.secrets[(ns, name)]["data"][field]).decode()

    def test_ensure_once_and_never_printed(self):
        rc, out = self.run_keys("ensure", "--namespace", "serving", "--secret", "llm-api-key", "--field", "key", "--prefix", "sk-tw-serving")
        self.assertEqual(rc, 0, out)
        key = self.value("serving", "llm-api-key", "key")
        self.assertRegex(key, r"^sk-tw-serving-[0-9a-f]{32}$")
        self.assertNotIn(key, out)
        self.assertIn(f"created, key {keys.fingerprint(key)}", out)
        rc, out = self.run_keys("ensure", "--namespace", "serving", "--secret", "llm-api-key", "--field", "key", "--prefix", "sk-tw-serving")
        self.assertEqual(rc, 0)
        self.assertEqual(self.value("serving", "llm-api-key", "key"), key)
        self.assertIn("kept as it is", out)
        self.assertEqual([c[0] for c in FakeApi.calls], ["GET", "POST", "GET"])

    def test_ensure_refuses_a_secret_without_the_field(self):
        FakeApi.secrets[("serving", "llm-api-key")] = {"data": {"other": base64.b64encode(b"x").decode()}}
        rc, out = self.run_keys("ensure", "--namespace", "serving", "--secret", "llm-api-key", "--field", "key", "--prefix", "sk-tw-serving")
        self.assertEqual(rc, 1)
        self.assertIn("never replaced", out)

    def test_mint_revoke_list(self):
        rc, out = self.run_keys("mint", "--namespace", "gw", "--secret", "keys-minted", "--prefix", "sk-tw", "--model", "chat", "--id", "0a1b2c3d")
        self.assertEqual(rc, 0, out)
        key = self.value("gw", "keys-minted", "chat.0a1b2c3d")
        self.assertRegex(key, r"^sk-tw-chat-[0-9a-f]{32}$")
        self.assertNotIn(key, out)
        rc, out = self.run_keys("mint", "--namespace", "gw", "--secret", "keys-minted", "--prefix", "sk-tw", "--model", "staff")
        self.assertEqual(rc, 0)
        self.assertEqual(FakeApi.calls[-1][2], "application/merge-patch+json")
        rc, out = self.run_keys("list", "--namespace", "gw", "--secret", "keys-minted")
        self.assertIn(f"chat.0a1b2c3d {keys.fingerprint(key)}", out)
        self.assertEqual(len(out.strip().splitlines()), 2)
        rc, out = self.run_keys("mint", "--namespace", "gw", "--secret", "keys-minted", "--prefix", "sk-tw", "--model", "chat", "--id", "0a1b2c3d")
        self.assertEqual(rc, 1)
        rc, out = self.run_keys("revoke", "--namespace", "gw", "--secret", "keys-minted", "--model", "chat", "--id", "0a1b2c3d")
        self.assertEqual(rc, 0, out)
        self.assertIn(keys.fingerprint(key), out)
        self.assertNotIn("chat.0a1b2c3d", FakeApi.secrets[("gw", "keys-minted")]["data"])
        rc, out = self.run_keys("revoke", "--namespace", "gw", "--secret", "keys-minted", "--model", "chat", "--id", "0a1b2c3d")
        self.assertEqual(rc, 1)

    def test_mint_refused_outside_the_audience(self):
        # sfab/keys:4: a key for a model outside the caller's audience is refused before the Secret is
        # read, with its own exit status, and the Secret is left as it was
        FakeApi.secrets[("inference", "api-keys")] = {"data": {"inetapp.0a1b2c3d": base64.b64encode(b"sk-tw-inetapp-x").decode()}}
        before = repr(sorted(FakeApi.secrets.items()))
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "inetapp",
                                "--for", "staff", "--audience", "internet", "--audience-models", "chat")
        self.assertEqual(rc, keys.REFUSED, out)
        self.assertIn("refused: caller inetapp is in audience internet, which may call chat; staff is outside it", out)
        self.assertEqual(FakeApi.calls, [])
        self.assertEqual(repr(sorted(FakeApi.secrets.items())), before)
        # inside the audience the key is minted, and the line names the audience
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "inetapp",
                                "--id", "0b1c2d3e", "--for", "chat", "--audience", "internet", "--audience-models", "chat")
        self.assertEqual(rc, 0, out)
        self.assertIn("caller inetapp, audience internet (may call chat): a key for chat", out)
        self.assertRegex(self.value("inference", "api-keys", "inetapp.0b1c2d3e"), r"^sk-tw-inetapp-[0-9a-f]{32}$")
        # one model outside the audience refuses the whole key
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "batch",
                                "--for", "chat,staff", "--audience", "internet", "--audience-models", "chat")
        self.assertEqual(rc, keys.REFUSED, out)
        # the audience's flags come together, or not at all
        for extra in (["--for", "chat"], ["--audience", "internet"], ["--audience", "internet", "--for", "chat"],
                      ["--audience-models", "chat"]):
            rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "batch", *extra)
            self.assertEqual(rc, 1, (extra, out))
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "batch",
                                "--for", "chat", "--audience", "Internet!", "--audience-models", "chat")
        self.assertEqual(rc, 1, out)
        # the refusal needs no Kubernetes API: it is decided before the tool reaches one
        os.environ.pop("SFAB_KEYS_API")
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "inetapp",
                                "--for", "staff", "--audience", "internet", "--audience-models", "chat")
        self.assertEqual(rc, keys.REFUSED, out)
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "api-keys", "--prefix", "sk-tw", "--model", "inetapp",
                                "--for", "chat", "--audience", "internet", "--audience-models", "chat")
        self.assertEqual(rc, 1, out)
        self.assertIn("no Kubernetes API", out)

    def test_mint_if_none_once_per_model(self):
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "model-keys", "--prefix", "sk-tw", "--model", "chat", "--if-none")
        self.assertEqual(rc, 0, out)
        data = FakeApi.secrets[("inference", "model-keys")]["data"]
        self.assertEqual([f.split(".")[0] for f in data], ["chat"])
        field = next(iter(data))
        key = self.value("inference", "model-keys", field)
        self.assertRegex(key, r"^sk-tw-chat-[0-9a-f]{32}$")
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "model-keys", "--prefix", "sk-tw", "--model", "chat", "--if-none")
        self.assertEqual(rc, 0, out)
        self.assertIn(f"chat holds 1 key(s), kept as they are: {field} {keys.fingerprint(key)}", out)
        self.assertNotIn(key, out)
        rc, out = self.run_keys("mint", "--namespace", "inference", "--secret", "model-keys", "--prefix", "sk-tw", "--model", "staff", "--if-none")
        self.assertEqual(rc, 0, out)
        self.assertEqual(sorted(f.split(".")[0] for f in FakeApi.secrets[("inference", "model-keys")]["data"]), ["chat", "staff"])
        self.assertEqual(self.value("inference", "model-keys", field), key)

    def test_copy_create_keep_update(self):
        FakeApi.secrets[("serving", "llm-api-key")] = {"data": {"key": base64.b64encode(b"sk-tw-serving-" + b"6" * 32).decode()}}
        argv = ("copy", "--from-namespace", "serving", "--from-secret", "llm-api-key", "--field", "key",
                "--namespace", "inference", "--secret", "backend-key")
        rc, out = self.run_keys(*argv)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.value("inference", "backend-key", "key"), "sk-tw-serving-" + "6" * 32)
        self.assertIn("created", out)
        self.assertNotIn("6" * 32, out)
        rc, out = self.run_keys(*argv)
        self.assertIn("kept, the same as serving/llm-api-key", out)
        FakeApi.secrets[("serving", "llm-api-key")]["data"]["key"] = base64.b64encode(b"sk-tw-serving-" + b"7" * 32).decode()
        rc, out = self.run_keys(*argv)
        self.assertEqual(rc, 0, out)
        self.assertIn("updated", out)
        self.assertEqual(self.value("inference", "backend-key", "key"), "sk-tw-serving-" + "7" * 32)
        self.assertNotIn("7" * 32, out)
        del FakeApi.secrets[("serving", "llm-api-key")]
        rc, out = self.run_keys(*argv)
        self.assertEqual(rc, 1)
        self.assertIn("holds no key to copy", out)

    def test_names_are_checked(self):
        for argv in (["mint", "--namespace", "gw", "--secret", "k", "--prefix", "sk-tw", "--model", "Chat"],
                     ["mint", "--namespace", "gw", "--secret", "k", "--prefix", "sk tw", "--model", "chat"],
                     ["revoke", "--namespace", "gw", "--secret", "k", "--model", "chat", "--id", "xyz"],
                     ["ensure", "--namespace", "Bad_NS", "--secret", "k", "--field", "key", "--prefix", "sk-tw"]):
            with self.subTest(argv=argv):
                self.assertEqual(self.run_keys(*argv)[0], 1)

    def test_probe(self):
        port = self.gw_srv.server_address[1]
        good, bad = "sk-tw-chat-" + "1" * 32, "sk-tw-chat-" + "2" * 32
        Gateway.accept = {good}
        FakeApi.pods = [{"metadata": {"name": "apisix-b"}, "status": {"phase": "Running", "podIP": "127.0.0.1"}},
                        {"metadata": {"name": "apisix-a"}, "status": {"phase": "Running", "podIP": "127.0.0.1"}},
                        {"metadata": {"name": "apisix-c"}, "status": {"phase": "Pending"}}]
        kf = self.tmp / "k"
        kf.write_text(good)
        rc, out = self.run_keys("probe", "--namespace", "gw", "--selector", "app=apisix", "--port", str(port),
                                "--path", "/models/x/v1/models", "--key-file", str(kf), "--expect", "200")
        self.assertEqual(rc, 0, out)
        self.assertEqual(re.findall(r"apisix-[a-c]", out), ["apisix-a", "apisix-b"])
        self.assertIn("2 of 2 pod(s) answered HTTP 200", out)
        self.assertNotIn(good, out)
        kf.write_text(bad)
        rc, out = self.run_keys("probe", "--namespace", "gw", "--selector", "app=apisix", "--port", str(port),
                                "--path", "/models/x/v1/models", "--key-file", str(kf), "--expect", "200")
        self.assertEqual(rc, 1)
        self.assertIn("HTTP 401", out)

    def test_probe_post_rounds_jsonl(self):
        port = self.gw_srv.server_address[1]
        key = "sk-tw-chat-" + "3" * 32
        Gateway.accept, Gateway.posts, Gateway.bodies = set(), 0, []
        Gateway.later = {key: 3}
        FakeApi.pods = [{"metadata": {"name": "apisix-a"}, "status": {"phase": "Running", "podIP": "127.0.0.1"}},
                        {"metadata": {"name": "apisix-b"}, "status": {"phase": "Running", "podIP": "127.0.0.1"}}]
        kf = self.tmp / "k3"
        kf.write_text(key)
        body = '{"model": "chat", "max_tokens": 1, "messages": [{"role": "user", "content": "Say yes."}]}'
        rc, out = self.run_keys("probe", "--namespace", "gw", "--selector", "app=apisix", "--port", str(port), "--path", "/models/x/v1/chat/completions",
                                "--key-file", str(kf), "--json", body, "--jsonl", "--label", "accept", "--expect", "200", "--repeat",
                                "--interval", "0.05", "--max-s", "5")
        self.assertEqual(rc, 0, out)
        rows = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
        per = [r for r in rows if "pod" in r]
        self.assertEqual(per[0], {"label": "accept", "round": 1, "t": per[0]["t"], "pod": "apisix-a", "ip": "127.0.0.1", "status": 401,
                                  "message": "Invalid API key in request"})
        self.assertEqual([r["status"] for r in per if r["round"] == per[-1]["round"]], [200, 200])
        self.assertTrue(rows[-1]["summary"]["all"])
        self.assertEqual(Gateway.bodies[0], ("application/json", body))
        self.assertNotIn(key, out)
        Gateway.later = {}
        Gateway.accept = set()
        rc, out = self.run_keys("probe", "--namespace", "gw", "--selector", "app=apisix", "--port", str(port), "--path", "/p", "--key-file",
                                str(kf), "--json", body, "--jsonl", "--label", "never", "--expect", "200", "--repeat", "--interval", "0.05",
                                "--max-s", "0.2")
        self.assertEqual(rc, 1)
        self.assertFalse(json.loads(out.strip().splitlines()[-1])["summary"]["all"])
        self.assertEqual(self.run_keys("probe", "--namespace", "gw", "--selector", "a=b", "--port", "1", "--path", "/p", "--key-file",
                                       str(kf), "--json", "{not json", "--expect", "200")[0], 1)
        self.assertEqual(self.run_keys("probe", "--namespace", "gw", "--selector", "a=b", "--port", "1", "--path", "/p", "--key-file",
                                       str(kf), "--repeat")[0], 1)

    def test_wrong_token_is_an_error(self):
        (self.tmp / "token2").write_text("other")
        os.environ["SFAB_KEYS_TOKEN_FILE"] = str(self.tmp / "token2")
        rc, out = self.run_keys("list", "--namespace", "gw", "--secret", "keys-minted")
        self.assertEqual(rc, 1)
        self.assertIn("HTTP 401", out)

    def test_https_trusts_an_intermediate_alone(self):
        # a service account's ca.crt may hold the cluster's intermediate CA alone
        import ssl  # noqa: PLC0415

        api = keys.Api(base="https://127.0.0.1:1", token="t")
        self.assertTrue(api.ctx.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN)
        self.assertEqual(api.ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertIsNone(keys.Api(base="http://127.0.0.1:1", token="t").ctx)


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed for compose")
class Compose(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="sfab-compose-"))
        self.base = self.tmp / "apisix.yaml"
        self.base.write_text("consumer_groups:\n  - id: chat\n    plugins: {}\n  - id: staff\n    plugins: {}\n"
                             "routes: []\nconsumers:\n  - username: chat\n    group_id: chat\n    plugins:\n"
                             "      key-auth:\n        key: \"$ENV://KEYAUTH_CHAT\"\n#END\n")
        self.keys = self.tmp / "keys"
        self.keys.mkdir()
        self.out = self.tmp / "out.yaml"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def compose(self, *extra):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = keys.main(["compose", "--base", str(self.base), "--keys", str(self.keys), "--out", str(self.out),
                            "--format", "Bearer {key}", "--once", *extra])
        return rc, out.getvalue()

    def test_no_line_is_folded(self):
        # APISIX's YAML reader cannot read a plain scalar folded onto a second line (a consumer
        # group's long desc was, in the first chapter 7 deploy of revision 2): nothing is folded
        long_desc = "application batch (owner data-platform, keys expire 2027-04-30); may call chat, staff and every other model"
        self.base.write_text(f"consumer_groups:\n  - id: chat\n    desc: \"{long_desc}\"\n    plugins: {{}}\nroutes: []\n#END\n")
        (self.keys / "chat.0a1b2c3d").write_text("sk-tw-chat-" + "3" * 32)
        rc, _ = self.compose()
        self.assertEqual(rc, 0)
        text = self.out.read_text()
        line = next(x for x in text.splitlines() if "desc:" in x)
        self.assertIn("every other model", line)

    def test_compose_in_place(self):
        import yaml

        k = "sk-tw-chat-" + "3" * 32
        (self.keys / "chat.0a1b2c3d").write_text(k)
        (self.keys / "..data").mkdir()
        (self.keys / "README").write_text("not a key")
        self.out.write_text("old\n")
        ino = self.out.stat().st_ino
        rc, out = self.compose()
        self.assertEqual(rc, 0)
        text = self.out.read_text()
        self.assertEqual(self.out.stat().st_ino, ino, "rewritten in place, not replaced")
        self.assertTrue(text.endswith("#END\n"))
        doc = yaml.safe_load(text)
        self.assertEqual(doc["consumers"][0]["username"], "chat")
        self.assertEqual(doc["consumers"][1], {"username": "chat_key_0a1b2c3d", "group_id": "chat",
                                               "plugins": {"key-auth": {"key": f"Bearer {k}"}}})
        self.assertNotIn(k, out)
        self.assertIn(f"chat.0a1b2c3d {keys.fingerprint(k)}", out)
        rc, out = self.compose()
        self.assertEqual(out, "", "unchanged content is not written again")

    def test_hold(self):
        hold = self.tmp / "hold"
        rc, _ = self.compose()
        first = self.out.read_text()
        hold.write_text("")
        (self.keys / "chat.0a1b2c3d").write_text("sk-tw-chat-" + "4" * 32)
        rc, out = self.compose("--hold", str(hold))
        self.assertIn("held:", out)
        self.assertEqual(self.out.read_text(), first)
        hold.unlink()
        rc, out = self.compose("--hold", str(hold))
        self.assertIn("composed", out)
        self.assertIn("chat_key_0a1b2c3d", self.out.read_text())

    def test_unknown_group_refused(self):
        (self.keys / "other.0a1b2c3d").write_text("sk-tw-other-" + "5" * 32)
        rc, out = self.compose()
        self.assertEqual(rc, 1)


class Image(unittest.TestCase):
    def test_dockerfile_and_make(self):
        df = (HERE / "Dockerfile").read_text()
        self.assertIn("FROM ${CLIENT_IMAGE}", df)
        self.assertIn('sha256sum -c -', df)
        self.assertIn("USER 65532:65532", df)
        self.assertNotIn("pip install", df)
        mk = (HERE / "image.mk").read_text()
        self.assertIn("fetch.py keys.pyyaml", mk)
        self.assertIn("--build-context vendor=$(KEYS_VENDOR)", mk)
        for d in (chr(0x2014), chr(0x2013)):
            for f in ("Dockerfile", "image.mk", "sfab-keys", "README.md"):
                self.assertNotIn(d, (HERE / f).read_text(), f)


if __name__ == "__main__":
    unittest.main()
