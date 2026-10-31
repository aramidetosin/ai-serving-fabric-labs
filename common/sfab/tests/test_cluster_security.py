"""Build A revision 2's cluster protections and identity (sign-in through an identity provider, WireGuard
between nodes, one certificate a Gateway), rendered for chapter 7's lab, and the tools that go with them.

- Secrets at rest: the API server's flag and volume in the ClusterConfiguration, and the control
  nodes' cluster.env naming the provider; WireGuard in Cilium's values.
- Network policy: default deny in every policed namespace, then exactly the request path's allows.
- The edge: the API gateway, the router and the identity provider on the ingress nodes.
- Identity: Dex's configuration names no secret, trusts the people's client for the API gateway's
  audience, and the API gateway's routes run multi-auth with key-auth first; callers are refused
  when they name no model, a people caller without the identity provider, an application without
  its owner or expiry.
- common/bin/idp-secret.py: a Secret of bcrypt hashes, the same at every run, refused on a terminal.
- common/audit/clustersec.py: the two judge groups pass a healthy set and fail a broken one.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_cluster_security -v
"""

from __future__ import annotations

import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CH07 = ROOT / "ch07"
COMMON = ROOT / "common"

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False

_CACHE: dict = {}


def ch07():
    if "m" not in _CACHE:
        from sfab.render import Context  # noqa: PLC0415
        from sfab.render import k8s  # noqa: PLC0415
        from sfab.render.inventory import inventory  # noqa: PLC0415
        from sfab.spec import load, load_chapter, select  # noqa: PLC0415

        spec = load(ROOT)
        m = select(spec, load_chapter(CH07))
        ctx = Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-clsec", labdir=CH07, root=ROOT, spec=spec)
        out = k8s.render(m, ctx)
        _CACHE.update(m=m, spec=spec, ctx=ctx, out=out, inv=inventory(m), k8s=json.loads(out["gen/k8s.json"]))
    return _CACHE


def docs(text: str) -> list:
    return [d for d in yaml.safe_load_all(text) if d]


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to render")
class ClusterRender(unittest.TestCase):
    def setUp(self):
        self.c = ch07()

    def test_secrets_at_rest(self):
        init = docs(self.c["out"]["bootstrap/k8s-cp1/k8s/kubeadm.yaml"])
        cc = next(d for d in init if d["kind"] == "ClusterConfiguration")
        self.assertEqual(cc["apiServer"]["extraArgs"], [{"name": "encryption-provider-config", "value": "/etc/kubernetes/enc/config.yaml"}])
        self.assertEqual(cc["apiServer"]["extraVolumes"], [{"name": "encryption", "hostPath": "/etc/kubernetes/enc", "mountPath": "/etc/kubernetes/enc",
                                                            "readOnly": True, "pathType": "DirectoryOrCreate"}])
        for n in ("k8s-cp1", "k8s-cp2", "k8s-cp3"):
            env = self.c["out"][f"bootstrap/{n}/k8s/cluster.env"]
            self.assertIn("CLUSTER_ENCRYPTION_PROVIDER=secretbox\n", env)
            self.assertIn("CLUSTER_ENCRYPTION_CONFIG=/etc/kubernetes/enc/config.yaml\n", env)
        self.assertNotIn("CLUSTER_ENCRYPTION", self.c["out"]["bootstrap/k8s-gpu1/k8s/cluster.env"], "workers run no API server")
        self.assertEqual(self.c["k8s"]["secrets_encryption"]["provider"], "secretbox")

    def test_wireguard(self):
        (v,) = docs(self.c["out"]["bootstrap/k8s/20-cilium-values.yaml"])
        self.assertEqual(v["encryption"], {"enabled": True, "type": "wireguard"})
        self.assertEqual(self.c["k8s"]["pod_encryption"], "wireguard")

    def test_default_deny_then_the_request_path(self):
        base = docs(self.c["out"]["bootstrap/k8s/58-network-policy.yaml"])
        inf = docs(self.c["out"]["bootstrap/k8s/63-inference-policy.yaml"])
        by = {(d["metadata"]["namespace"], d["metadata"]["name"]): d["spec"] for d in base + inf}
        for ns in ("echo", "identity", "inference", "serving"):
            self.assertEqual(by[(ns, "default-deny")], {"description": f"every pod in {ns}: no ingress and no egress but what an allow names",
                                                        "endpointSelector": {}, "ingress": [{}], "egress": [{}]})
        gw = by[("inference", "allow-api-gateway")]
        self.assertEqual(gw["ingress"][0], {"fromEntities": ["ingress"], "toPorts": [{"ports": [{"port": "9080", "protocol": "TCP"}]}]})
        self.assertEqual([e.get("toPorts")[0]["ports"][0]["port"] for e in gw["egress"]], ["4000", "5556", "53"])
        ro = by[("inference", "allow-router")]
        self.assertEqual(ro["egress"][0]["toEndpoints"][0]["matchLabels"],
                         {"k8s:app.kubernetes.io/name": "serving", "k8s:app.kubernetes.io/component": "server",
                          "k8s:io.kubernetes.pod.namespace": "serving"})
        srv = by[("serving", "allow-to-servers")]
        self.assertEqual(srv["ingress"][1], {"fromEntities": ["ingress"], "toPorts": [{"ports": [{"port": "8080", "protocol": "TCP"}]}]})
        # the workers get no allow: their RPC is on the rails, outside Cilium
        self.assertFalse([k for k in by if k[0] == "serving" and "worker" in k[1]])
        self.assertEqual(self.c["k8s"]["network_policy"]["files"], {"base": "58-network-policy.yaml", "inference": "63-inference-policy.yaml"})
        self.assertIn("58-network-policy.yaml", self.c["out"]["bootstrap/k8s/apply.list"])
        self.assertNotIn("63-inference-policy.yaml", self.c["out"]["bootstrap/k8s/apply.list"], "finish applies it after the recipe")

    def test_edge_placement(self):
        sel = {"node-role.tarnwick.example/ingress": ""}
        tol = [{"key": "node-role.tarnwick.example/ingress", "operator": "Exists", "effect": "NoSchedule"}]
        deps = [d for d in docs(self.c["out"]["bootstrap/k8s/62-inference.yaml"]) + docs(self.c["out"]["bootstrap/k8s/57-identity.yaml"])
                if d["kind"] == "Deployment"]
        self.assertEqual(sorted(d["metadata"]["name"] for d in deps), ["api-gateway", "idp", "router"])
        for d in deps:
            self.assertEqual(d["spec"]["template"]["spec"]["nodeSelector"], sel, d["metadata"]["name"])
            self.assertEqual(d["spec"]["template"]["spec"]["tolerations"], tol, d["metadata"]["name"])
        self.assertEqual(self.c["k8s"]["edge"]["nodes"], ["k8s-ingress1", "k8s-ingress2"])

    def test_per_gateway_certificates(self):
        gws = {d["metadata"]["name"]: d for d in docs(self.c["out"]["bootstrap/k8s/50-gateways.yaml"])}
        refs = {g: d["spec"]["listeners"][0]["tls"]["certificateRefs"][0]["name"] for g, d in gws.items()}
        self.assertEqual(refs, {"gw-internal": "gw-internal-tls", "gw-users": "gw-users-tls"})
        certs = [d for d in docs(self.c["out"]["bootstrap/k8s/40-pki.yaml"]) if d["kind"] == "Certificate"]
        self.assertEqual(sorted(c["spec"]["secretName"] for c in certs), ["gw-internal-tls", "gw-users-tls"])

    def test_identity_provider(self):
        d = docs(self.c["out"]["bootstrap/k8s/57-identity.yaml"])
        kinds = [x["kind"] for x in d]
        self.assertEqual(kinds, ["Namespace", "ConfigMap", "Deployment", "Service", "HTTPRoute", "HTTPRoute"])
        cfg = yaml.safe_load(d[1]["data"]["config.yaml"])
        self.assertEqual(cfg["issuer"], "https://id.ai.tarnwick.example")
        self.assertEqual(cfg["oauth2"]["passwordConnector"], "local")
        gw = next(c for c in cfg["staticClients"] if c["id"] == "ai-gateway")
        self.assertEqual((gw["public"], gw["trustedPeers"]), (True, ["staff-cli"]))
        cli = next(c for c in cfg["staticClients"] if c["id"] == "staff-cli")
        self.assertEqual(cli["secretEnv"], "SFAB_IDP_CLIENT_STAFF_CLI")
        self.assertNotIn("secret", cli)
        (p,) = cfg["staticPasswords"]
        self.assertEqual((p["email"], p["hashFromEnv"]), ("ent-client@tarnwick.example", "SFAB_IDP_HASH_ENT_CLIENT"))
        self.assertNotIn("hash", p)
        dep = d[2]["spec"]["template"]["spec"]
        self.assertEqual(dep["containers"][0]["envFrom"], [{"secretRef": {"name": "idp-credentials"}}])
        self.assertTrue(dep["containers"][0]["securityContext"]["readOnlyRootFilesystem"])
        self.assertTrue(dep["containers"][0]["image"].startswith("docker.io/dexidp/dex@sha256:fd4ab5d1"))
        rts = {r["spec"]["parentRefs"][0]["name"]: r["spec"]["hostnames"] for r in d if r["kind"] == "HTTPRoute"}
        self.assertEqual(rts, {"gw-internal": ["id.ai.tarnwick.example"], "gw-users": ["id.ai.tarnwick.example"]})
        idp = self.c["k8s"]["identity"]
        self.assertEqual(idp["secrets"], ["SFAB_IDP_CLIENT_STAFF_CLI", "SFAB_IDP_PASSWORD_ENT_CLIENT"])
        self.assertEqual(idp["scope"], "openid email profile audience:server:client_id:ai-gateway")
        # both views answer the identity provider's name, each with its own Gateway
        dns = self.c["inv"]["dns"]
        self.assertIn("id.ai.tarnwick.example", dns["views"]["enterprise"]["names"])
        self.assertIn("id.ai.tarnwick.example", dns["views"]["internal"]["names"])

    def test_no_identity_name_without_serving(self):
        from sfab.spec import load, select  # noqa: PLC0415

        m = select(load(ROOT), {"lab": "sfab-ch04", "profile": "a", "state": "one",
                                "slice": {"nodes": ["fe", "fw", "k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion", "inet-registry", "uplink-rtr", "ent-client"]},
                                "features": {"k8s": True, "serving": False, "storage_setup": False}})
        self.assertEqual(m.dns.identity, ())

    def test_callers_refused(self):
        from sfab.render import RenderError, inference  # noqa: PLC0415

        cases = {
            "no model": {"id": "x", "kind": "application", "models": ["nope"], "owner": "o", "expires": "2027-01-01"},
            "no owner": {"id": "x", "kind": "application", "models": ["chat"], "expires": "2027-01-01"},
            "a bad date": {"id": "x", "kind": "application", "models": ["chat"], "owner": "o", "expires": "soon"},
            "an unknown person": {"id": "x", "kind": "people", "audience": "enterprise", "people": ["nobody"]},
            "a hyphen": {"id": "x-y", "kind": "application", "models": ["chat"], "owner": "o", "expires": "2027-01-01"},
        }
        for why, extra in cases.items():
            m = copy.deepcopy(self.c["m"])
            m.spec["inference"]["callers"] = list(m.spec["inference"]["callers"]) + [extra]
            with self.assertRaises(RenderError, msg=why):
                inference.settings(m)

    def test_oidc_plugin_source(self):
        text = (COMMON / "sfab" / "render" / "apisix" / "oidc-consumer.lua").read_text()
        for part in ('token_signing_alg_values_expected = {"RS256"}', "jwt_verification_cache_ignore = true", "accept_none_alg = false",
                     'type = "auth"', "has_audience(claims.aud, conf.audience)", "claims.iss ~= conf.issuer", "email_verified ~= true"):
            self.assertIn(part, text)
        cm = next(d for d in docs(self.c["out"]["bootstrap/k8s/62-inference.yaml"]) if d["metadata"]["name"] == "api-gateway-plugins")
        self.assertEqual(cm["data"]["oidc-consumer.lua"], text)


class IdpSecret(unittest.TestCase):
    def setUp(self):
        self.t = Path(tempfile.mkdtemp(prefix="sfab-idp-"))
        self.k8s = self.t / "k8s.json"
        self.k8s.write_text(json.dumps({"identity": {
            "namespace": "identity", "name": "idp", "secret": "idp-credentials",
            "clients": [{"id": "staff-cli", "secret_env": "SFAB_IDP_CLIENT_STAFF_CLI"}],
            "people": [{"id": "ent-client", "password_env": "SFAB_IDP_PASSWORD_ENT_CLIENT", "hash_env": "SFAB_IDP_HASH_ENT_CLIENT"}]}}))
        self.env = self.t / "secrets.env"
        self.env.write_text("SFAB_IDP_CLIENT_STAFF_CLI=Abcdefghijklmnopqrstuvwxyz012345\nSFAB_IDP_PASSWORD_ENT_CLIENT=Pw0123456789abcdefgh\n")

    def run_tool(self, stdout=subprocess.PIPE):
        return subprocess.run([sys.executable, str(COMMON / "bin" / "idp-secret.py"), "--k8s", str(self.k8s), "--env", str(self.env)],
                              stdout=stdout, stderr=subprocess.PIPE, text=True)

    def test_hashes_and_the_same_secret_twice(self):
        r = self.run_tool()
        if r.returncode != 0 and "no bcrypt" in r.stderr:
            self.skipTest("no bcrypt on this host (Python's crypt module and htpasswd both missing)")
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(r.stdout)
        data = {k: base64.b64decode(v).decode() for k, v in doc["data"].items()}
        self.assertEqual(sorted(data), ["SFAB_IDP_CLIENT_STAFF_CLI", "SFAB_IDP_HASH_ENT_CLIENT"])
        self.assertTrue(data["SFAB_IDP_HASH_ENT_CLIENT"].startswith(("$2b$10$", "$2y$10$")))
        self.assertNotIn("Pw0123456789abcdefgh", r.stdout + r.stderr, "the password never leaves the lab host")
        self.assertNotIn("Abcdefghijklmnopqrstuvwxyz012345", r.stderr)
        try:
            import warnings  # noqa: PLC0415

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                import crypt  # noqa: PLC0415  (Python 3.12 and older)
        except ImportError:
            crypt = None
        if crypt is None or not (crypt.crypt("x", "$2b$10$" + "." * 22) or "").startswith("$2b$"):
            return  # htpasswd made it, with a salt of its own: the Secret differs at every run
        self.assertEqual(self.run_tool().stdout, r.stdout, "the same password gives the same Secret")
        self.assertEqual(crypt.crypt("Pw0123456789abcdefgh", data["SFAB_IDP_HASH_ENT_CLIENT"]), data["SFAB_IDP_HASH_ENT_CLIENT"])

    def test_refuses_a_terminal_and_a_missing_value(self):
        self.env.write_text("SFAB_IDP_CLIENT_STAFF_CLI=x\n")
        r = self.run_tool()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SFAB_IDP_PASSWORD_ENT_CLIENT", r.stderr)


class Judges(unittest.TestCase):
    """clustersec.py's groups on a set written here: green as a healthy lab reads, red when broken."""

    def setUp(self):
        sys.path.insert(0, str(COMMON / "audit"))
        import judge  # noqa: PLC0415
        import vocab  # noqa: PLC0415

        self.judge, self.vocab = judge, vocab
        self.t = Path(tempfile.mkdtemp(prefix="sfab-clsec-"))
        self.render = self.t / "render"
        (self.render / "gen").mkdir(parents=True)
        self.k = {"api": {"control": ["k8s-cp1"]}, "secrets_encryption": {"provider": "secretbox", "config": "/etc/kubernetes/enc/config.yaml"},
                  "pod_encryption": "wireguard", "nodes": {"k8s-cp1": {}, "k8s-ingress1": {}},
                  "certificates": [{"secret": "gw-a-tls", "gateway": "gw-a", "dns": ["*.ai.tarnwick.example"]},
                                   {"secret": "gw-b-tls", "gateway": "gw-b", "dns": ["*.ai.tarnwick.example"]}],
                  "issuer": {"intermediate": "platform"},
                  "network_policy": {"base": [{"namespace": "echo", "name": "default-deny"}], "inference": []},
                  "edge": {"nodes": ["k8s-ingress1"]}, "inference": {"namespace": "inference", "gateway": {"name": "api-gateway"}, "router": {"name": "router"}}}
        (self.render / "gen" / "k8s.json").write_text(json.dumps(self.k))
        self.inv = {"nodes": {}, "ca": {"intermediates": {"platform": {"cn": "Tarnwick Platform CA"}}}}
        self.rs = self.t / "set"
        d = self.rs / "cluster-security"
        d.mkdir(parents=True)
        (d / "encryption-k8s-cp1.txt").write_text("1\n600 root\n1\n")
        (d / "etcd-secret.txt").write_text("cert-manager/lab-ca\n")
        (d / "etcd-prefix.txt").write_text("k8s:enc:secretbox:v1:key1:\n")
        (d / "api-secret-type.txt").write_text("kubernetes.io/tls\n")
        (d / "cilium-config.json").write_text(json.dumps({"data": {"enable-wireguard": "true"}}))
        (d / "wireguard.txt").write_text("== cilium-a k8s-cp1\nEncryption: Wireguard\nNumber of peers: 1\n== cilium-b k8s-ingress1\nEncryption: Wireguard\nNumber of peers: 1\n")
        cert = "== {s}\nsubject=\nissuer=CN=Tarnwick Platform CA,O=Tarnwick\nX509v3 Subject Alternative Name: \n    DNS:*.ai.tarnwick.example\nspki sha256 {k}\n"
        (d / "gateway-certs.txt").write_text(cert.format(s="gw-a-tls", k="a" * 64) + cert.format(s="gw-b-tls", k="b" * 64))
        (d / "cnp.json").write_text(json.dumps({"items": [{"metadata": {"namespace": "echo", "name": "default-deny"}}]}))
        (d / "targets.txt").write_text("echo\techo\techo\t8080\trefused\ncluster-dns\tkube-system\tkube-dns\t53\tconnected\n")
        (d / "probe.txt").write_text("== echo echo/echo 10.23.0.9:8080\nTIMEOUT\nrc=1\n== cluster-dns kube-system/kube-dns 10.23.0.10:53\nrc=0\n")
        pod = lambda n, node: {"metadata": {"namespace": "inference", "name": n, "labels": {"app.kubernetes.io/name": n.split("-x")[0]}},  # noqa: E731
                               "spec": {"nodeName": node}}
        (d / "pods.json").write_text(json.dumps({"items": [pod("api-gateway-x1", "k8s-ingress1"), pod("router-x1", "k8s-ingress1")]}))
        (d / "policy-routing-k8s-ingress1.txt").write_text("0: from all lookup local\n100: from 10.20.11.11 lookup 110\n==\ndefault via 10.20.11.1 dev bond0.110\n")
        (d / "reply-plan.txt").write_text("10.20.11.210 k8s-ingress1 ent-client\n")
        (d / "reply-capture.txt").write_text("05:00:00 02:5a > 02:5b, ethertype 802.1Q, vlan 110, p 0, ethertype IPv4, 10.20.11.210.443 > 10.24.10.10.4242: Flags [S.]\n")

    def run_group(self):
        out = __import__("io").StringIO()
        v = self.vocab.Vocab(out=out)
        j = self.judge.Judge(self.judge.ResultSet(self.rs), self.inv, self.render, v)
        j.g_cluster_security([])
        return out.getvalue()

    def test_green(self):
        out = self.run_group()
        self.assertNotIn("FAIL", out, out)
        for line in ("PASS  etcd stores the Secret cert-manager/lab-ca encrypted: its value starts k8s:enc:secretbox:v1:",
                     "PASS  k8s-ingress1: the agent reports WireGuard encryption with 1 peers",
                     "PASS  the 2 Gateways' certificates hold 2 different keys",
                     "PASS  a pod outside every policed namespace to echo/echo:8080: refused",
                     "PASS  the API gateway's 1 pod(s) on the ingress nodes only (k8s-ingress1)",
                     "PASS  k8s-ingress1, the lease holder of 10.20.11.210: the Gateway's SYN-ACK to ent-client leaves bond0 tagged vlan 110"):
            self.assertIn(line, out)

    def test_red(self):
        d = self.rs / "cluster-security"
        (d / "etcd-prefix.txt").write_text("k8s\x00\n\x0cv1Secret\n")
        (d / "gateway-certs.txt").write_text((d / "gateway-certs.txt").read_text().replace("b" * 64, "a" * 64))
        (d / "probe.txt").write_text("== echo echo/echo 10.23.0.9:8080\nrc=0\n== cluster-dns kube-system/kube-dns 10.23.0.10:53\nrc=0\n")
        (d / "reply-capture.txt").write_text("")
        out = self.run_group()
        for line in ("FAIL  etcd stores the Secret", "FAIL  the 2 Gateways' certificates hold 2 different keys",
                     "FAIL  a pod outside every policed namespace to echo/echo:8080", "FAIL  k8s-ingress1, the lease holder"):
            self.assertIn(line, out)


if __name__ == "__main__":
    unittest.main()
