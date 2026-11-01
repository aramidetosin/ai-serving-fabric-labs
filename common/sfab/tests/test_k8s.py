"""Kubernetes tests: render/k8s.py (bootstrap/k8s/, bootstrap/<node>/k8s/ and gen/k8s.json), the pins
it reads from spec/versions.yaml, and images/vm-node/node-files/cluster-bootstrap.sh run against
stand-ins for kubeadm, kubectl, crictl, ctr, curl and helm, with a real lab CA made by openssl.

Run from the repo root:  PYTHONPATH=common python3 -m unittest sfab.tests.test_k8s -v

Nothing here reaches a real device or the network: the script runs with a directory of stand-ins
first on PATH, ssh, sshpass and docker among them (standins.check proves each one resolves to its
stand-in), and every directory it touches is a temporary one.
"""

from __future__ import annotations

import hashlib
import importlib.util
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sfab.tests import standins

ROOT = Path(__file__).resolve().parents[3]
NODE_FILES = ROOT / "images" / "vm-node" / "node-files"
BOOTSTRAP = NODE_FILES / "cluster-bootstrap.sh"
UNIT = NODE_FILES / "sfab-cluster.service"
K8S_PY = ROOT / "common" / "sfab" / "render" / "k8s.py"
DASHES = (chr(0x2014), chr(0x2013))  # the em and en dash
# Stand-in values: the placeholder token kubeadm config print init-defaults prints, in the
# [a-z0-9]{6}.[a-z0-9]{16} form, never a live one. The tests pass it only to fake kubeadm, kubectl
# and helm shims.
TOKEN = "abcdef.0123456789abcdef"

M2 = {"lab": "sfab-m2", "profile": "a", "state": "one",
      "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2", "k8s-cp1", "k8s-cp2", "k8s-cp3", "bastion",
                          "inet-registry", "uplink-rtr", "ops-client", "ent-client", "truenas1"]},
      "features": {"k8s": True, "serving": False, "storage_setup": True}}
M1 = {"lab": "sfab-m1", "profile": "a", "state": "one",
      "slice": {"nodes": ["fe", "rail", "oob", "fw", "k8s-gpu1", "k8s-gpu2"]},
      "features": {"k8s": False, "serving": False, "storage_setup": False}}
MANY = {"lab": "sfab-ch09", "profile": "a", "state": "many"}

try:
    import yaml

    HAVE_YAML = True
except ImportError:
    HAVE_YAML = False


def _bash() -> str | None:
    b = shutil.which("bash")
    if not b:
        return None
    try:
        v = subprocess.run([b, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    return b if v.strip().isdigit() and int(v) >= 4 else None


BASH = _bash()
OPENSSL = shutil.which("openssl")


class Labs:
    """The spec loaded once, and the k8s renders of M2, M1 and an A/many lab."""

    _cache: dict = {}

    @classmethod
    def get(cls) -> dict:
        if not cls._cache:
            from sfab.render import Context, k8s
            from sfab.spec import load, select

            spec = load(ROOT)
            out = {"spec": spec}
            for key, sel in (("m2", M2), ("m1", M1), ("many", MANY)):
                m = select(spec, sel)
                ctx = Context(outdir=Path(tempfile.gettempdir()) / "sfab-test-k8s", labdir=ROOT / "dev" / "m2", root=ROOT, spec=spec)
                out[key] = {"model": m, "ctx": ctx, "out": k8s.render(m, ctx)}
            cls._cache = out
        return cls._cache


def m2() -> dict:
    return Labs.get()["m2"]


def docs(text: str) -> list:
    return [d for d in yaml.safe_load_all(text) if d is not None]


def versions() -> dict:
    return m2()["model"].meta.versions


# --------------------------------------------------------------------------------------------
# The YAML writer


class TestWriter(unittest.TestCase):
    def test_scalars(self):
        from sfab.render.k8s import scalar

        self.assertEqual(scalar("bond0"), "bond0")
        self.assertEqual(scalar("k8s.tarnwick.example:6443"), "k8s.tarnwick.example:6443")
        self.assertEqual(scalar("oci://192.0.2.6:5000/charts/cilium"), "oci://192.0.2.6:5000/charts/cilium")
        for v in ("true", "on", "No", "y", "10.20.1.10", "6443", "*.tarnwick.example", "^bond0$", "", "a b", "10m0s", "=", "x: y"):
            with self.subTest(v=v):
                self.assertTrue(scalar(v).startswith('"'), scalar(v))
        self.assertEqual(scalar(True), "true")
        self.assertEqual(scalar(None), "null")
        self.assertEqual(scalar(443), "443")

    @unittest.skipUnless(HAVE_YAML, "PyYAML is needed")
    def test_round_trip(self):
        from sfab.render.k8s import dump, dump_all

        obj = {"a": [{"name": "x", "value": "true"}, {"name": "y", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}}],
               "b": {"c": [], "d": {}, "e": ["^bond0$", "10.20.1.10", 1, False, None]}, "f": "node-role.tarnwick.example/control=",
               "g": [["nested", "list"], {}], "h": "*.tarnwick.example"}
        self.assertEqual(yaml.safe_load(dump(obj)), obj)
        self.assertEqual(list(yaml.safe_load_all(dump_all([obj, {"k": "v"}]))), [obj, {"k": "v"}])


# --------------------------------------------------------------------------------------------
# What is rendered


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestOutputs(unittest.TestCase):
    def test_off_when_k8s_is_off(self):
        self.assertEqual(Labs.get()["m1"]["out"], {})

    def test_files(self):
        out = m2()["out"]
        k = ["05-namespaces.yaml", "10-gateway-api-crds.yaml", "07-operators.yaml", "20-cilium-values.yaml", "21-cert-manager-values.yaml",
             "30-lb-pools.yaml", "31-l2-announcement.yaml", "40-pki.yaml", "50-gateways.yaml", "55-test-backend.yaml",
             "58-network-policy.yaml", "apply.list", "charts.list", "ca-secrets.list"]
        want = {f"bootstrap/k8s/{f}" for f in k}
        for n in ("k8s-cp1", "k8s-cp2", "k8s-cp3", "k8s-gpu1", "k8s-gpu2", "k8s-ingress1", "k8s-ingress2"):
            want |= {f"bootstrap/{n}/k8s/cluster.env", f"bootstrap/{n}/k8s/kubeadm.yaml"}
        for n in ("k8s-cp1", "k8s-cp2", "k8s-cp3"):
            want.add(f"bootstrap/{n}/k8s/kube-vip.yaml")
        want |= {"bootstrap/k8s-cp1/k8s/kube-vip-init.yaml", "bootstrap/k8s-cp1/k8s/kubeadm-user.yaml", "bootstrap/k8s-cp1/k8s/10-gateway-api-crds.yaml",
                 "bootstrap/k8s-cp1/k8s/20-cilium-values.yaml", "gen/k8s.json"}
        self.assertEqual(set(out), want)
        # The init node's copies are the bastion's, byte for byte.
        for f in ("10-gateway-api-crds.yaml", "20-cilium-values.yaml"):
            self.assertEqual(out[f"bootstrap/k8s-cp1/k8s/{f}"], out[f"bootstrap/k8s/{f}"])

    def test_operators_read_the_cluster(self):
        # view reads namespaced objects only; the companion role lets an operator list the nodes, and
        # neither role reads a Secret.
        d = docs(m2()["out"]["bootstrap/k8s/07-operators.yaml"])
        self.assertEqual([x["kind"] for x in d], ["ClusterRoleBinding", "ClusterRole", "ClusterRoleBinding"])
        self.assertEqual(d[0]["roleRef"]["name"], "view")
        self.assertEqual(d[2]["roleRef"]["name"], d[1]["metadata"]["name"])
        self.assertEqual(d[2]["subjects"], d[0]["subjects"])
        rules = {(g, r) for x in d[1]["rules"] for g in x["apiGroups"] for r in x["resources"]}
        self.assertIn(("", "nodes"), rules)
        self.assertNotIn("secrets", {r for _, r in rules})
        self.assertEqual({v for x in d[1]["rules"] for v in x["verbs"]}, {"get", "list", "watch"})

    def test_deterministic(self):
        from sfab.render import k8s

        lab = m2()
        self.assertEqual(k8s.render(lab["model"], lab["ctx"]), lab["out"])

    def test_plain_english(self):
        for p, text in m2()["out"].items():
            if p.endswith("10-gateway-api-crds.yaml"):
                text = "\n".join(l for l in text.splitlines() if l.startswith("# sfab-m2") or l.startswith("# The upstream"))
            for d in DASHES:
                self.assertNotIn(d, text, p)
        for f in (K8S_PY, BOOTSTRAP, UNIT, Path(__file__)):
            text = f.read_text(encoding="utf-8")
            for d in DASHES:
                self.assertNotIn(d, text, f.name)

    def test_headers(self):
        for p, text in m2()["out"].items():
            if p.endswith((".yaml", ".list", ".env")):
                self.assertTrue(text.startswith("# sfab-m2 "), p)
                self.assertIn("render/k8s.py", text.splitlines()[0], p)

    def test_no_secret(self):
        for p, text in m2()["out"].items():
            self.assertNotRegex(text, r"[a-z0-9]{6}\.[a-z0-9]{16}(?![a-z0-9])", p)
            self.assertNotIn("PRIVATE KEY", text, p)
            self.assertNotRegex(text, r"(?i)password\s*[:=]\s*\S", p)

    def test_many(self):
        """The A/many lab: three Gateways, the test backend behind each (gw-inet's from step 8)."""
        out = Labs.get()["many"]["out"]
        if not HAVE_YAML:
            self.skipTest("PyYAML is needed")
        pools = docs(out["bootstrap/k8s/30-lb-pools.yaml"])
        self.assertEqual([p["metadata"]["name"] for p in pools], ["gw-internal", "gw-users", "gw-inet"])
        routes = [d["metadata"]["name"] for d in docs(out["bootstrap/k8s/55-test-backend.yaml"]) if d["kind"] == "HTTPRoute"]
        self.assertEqual(routes, ["echo-gw-internal", "echo-gw-users", "echo-gw-inet"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the rendered files")
class TestKubeadm(unittest.TestCase):
    def test_init(self):
        d = docs(m2()["out"]["bootstrap/k8s-cp1/k8s/kubeadm.yaml"])
        self.assertEqual([x["kind"] for x in d], ["InitConfiguration", "ClusterConfiguration", "KubeletConfiguration"])
        init, cl, kl = d
        self.assertEqual(init["apiVersion"], "kubeadm.k8s.io/v1beta4")
        self.assertEqual(init["localAPIEndpoint"], {"advertiseAddress": "10.20.1.11", "bindPort": 6443})
        nr = init["nodeRegistration"]
        self.assertEqual(nr["name"], "k8s-cp1")
        self.assertIn({"name": "node-ip", "value": "10.20.1.11"}, nr["kubeletExtraArgs"])
        self.assertIn({"name": "node-labels", "value": "node-role.tarnwick.example/control="}, nr["kubeletExtraArgs"])
        self.assertNotIn("bootstrapTokens", init)
        self.assertNotIn("certificateKey", init)
        self.assertEqual(cl["controlPlaneEndpoint"], "k8s.ai.tarnwick.example:6443")
        self.assertEqual(cl["kubernetesVersion"], "v1.35.8")
        self.assertEqual(cl["networking"], {"dnsDomain": "cluster.local", "podSubnet": "10.22.0.0/16", "serviceSubnet": "10.23.0.0/16"})
        self.assertEqual(cl["apiServer"]["certSANs"], ["k8s.ai.tarnwick.example", "10.20.1.10"])
        self.assertEqual(cl["proxy"], {"disabled": True})
        self.assertEqual(cl["clusterName"], "sfab-m2")
        self.assertEqual(kl["cgroupDriver"], "systemd")
        self.assertEqual(kl["resolvConf"], "/etc/resolv.conf")

    def test_absolute_eviction_thresholds(self):
        kl = docs(m2()["out"]["bootstrap/k8s-cp1/k8s/kubeadm.yaml"])[2]
        ev = kl["evictionHard"]
        self.assertEqual(set(ev), {"memory.available", "nodefs.available", "nodefs.inodesFree", "imagefs.available", "imagefs.inodesFree"})
        for k in ("memory.available", "nodefs.available", "imagefs.available"):
            self.assertRegex(ev[k], r"^\d+(Mi|Gi)$", k)

    def test_joins(self):
        from sfab.render.k8s import JOIN_TAIL

        out = m2()["out"]
        for n, role, addr in (("k8s-cp2", "join-control", "10.20.1.12"), ("k8s-cp3", "join-control", "10.20.1.13"),
                              ("k8s-gpu1", "join-worker", "10.20.1.21"), ("k8s-gpu2", "join-worker", "10.20.1.22")):
            with self.subTest(node=n):
                text = out[f"bootstrap/{n}/k8s/kubeadm.yaml"]
                self.assertEqual(text.splitlines()[-1], JOIN_TAIL)
                (j,) = docs(text)
                self.assertEqual(j["kind"], "JoinConfiguration")
                self.assertEqual(j["nodeRegistration"]["name"], n)
                self.assertIn({"name": "node-ip", "value": addr}, j["nodeRegistration"]["kubeletExtraArgs"])
                self.assertEqual(j["discovery"], {"bootstrapToken": {"apiServerEndpoint": "k8s.ai.tarnwick.example:6443"}})
                self.assertEqual(list(j)[-1], "discovery")
                if role == "join-control":
                    self.assertEqual(j["controlPlane"], {"localAPIEndpoint": {"advertiseAddress": addr, "bindPort": 6443}})
                    self.assertIn({"name": "node-labels", "value": "node-role.tarnwick.example/control="}, j["nodeRegistration"]["kubeletExtraArgs"])
                else:
                    self.assertNotIn("controlPlane", j)
                    self.assertIn({"name": "node-labels", "value": "node-role.tarnwick.example/gpu="}, j["nodeRegistration"]["kubeletExtraArgs"])
                # What cluster-bootstrap.sh appends continues the bootstrapToken mapping.
                pin = "a" * 64
                (j2,) = docs(text + f'    token: "{TOKEN}"\n    caCertHashes:\n    - "sha256:{pin}"\n')
                self.assertEqual(j2["discovery"]["bootstrapToken"],
                                 {"apiServerEndpoint": "k8s.ai.tarnwick.example:6443", "token": TOKEN, "caCertHashes": [f"sha256:{pin}"]})

    def test_cluster_env(self):
        out = m2()["out"]
        env = dict(l.split("=", 1) for l in out["bootstrap/k8s-cp1/k8s/cluster.env"].splitlines()[1:])
        self.assertEqual(env["CLUSTER_ROLE"], "init")
        self.assertEqual(env["CLUSTER_CILIUM_CHART"], "oci://192.0.2.6:5000/charts/cilium")
        self.assertEqual(env["CLUSTER_CILIUM_VERSION"], str(versions()["kubernetes"]["cilium"]["chart"]["version"]))
        helm = versions()["kubernetes"]["node_helm"]["image"]
        self.assertEqual(env["CLUSTER_HELM_IMAGE"], f"docker.io/alpine/helm@{helm['platform_digest']}")
        self.assertEqual(env["CLUSTER_HELM_IMAGE_NAME"], env["CLUSTER_HELM_IMAGE"])
        self.assertEqual(env["CLUSTER_HELM_VERSION"], versions()["kubernetes"]["helm"]["version"], "the node's helm is the bastion's")
        self.assertEqual(env["CLUSTER_CHAIN_SERVER"], "https://10.20.1.10:6443")
        self.assertNotIn("CLUSTER_PUBLISH_SERVER", env, "no kubeconfig leaves the init node")
        gpu = out["bootstrap/k8s-gpu1/k8s/cluster.env"]
        self.assertIn("CLUSTER_ROLE=join-worker", gpu)
        self.assertNotIn("CLUSTER_KUBE_VIP", gpu)
        self.assertNotIn("HELM", gpu)
        self.assertIn("CLUSTER_KUBE_VIP=kube-vip.yaml", out["bootstrap/k8s-cp2/k8s/cluster.env"])


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the rendered files")
class TestKubeVip(unittest.TestCase):
    def test_pods(self):
        out = m2()["out"]
        pin = versions()["kubernetes"]["kube_vip"]["image"]
        for f, conf in (("bootstrap/k8s-cp1/k8s/kube-vip-init.yaml", "/etc/kubernetes/super-admin.conf"),
                        ("bootstrap/k8s-cp1/k8s/kube-vip.yaml", "/etc/kubernetes/admin.conf"),
                        ("bootstrap/k8s-cp3/k8s/kube-vip.yaml", "/etc/kubernetes/admin.conf")):
            with self.subTest(file=f):
                (pod,) = docs(out[f])
                spec = pod["spec"]
                self.assertTrue(spec["hostNetwork"])
                self.assertEqual(spec["hostAliases"], [{"ip": "127.0.0.1", "hostnames": ["kubernetes"]}])
                (c,) = spec["containers"]
                self.assertEqual(c["image"], f"{pin['ref']}@{pin['digest']}")
                env = {e["name"]: e.get("value") for e in c["env"]}
                self.assertEqual(env["address"], "10.20.1.10")
                self.assertEqual(env["vip_interface"], "bond0")
                self.assertEqual(env["vip_arp"], "true")
                self.assertEqual(env["cp_enable"], "true")
                self.assertEqual(env["svc_enable"], "false")
                self.assertEqual(env["vip_leasename"], "plndr-cp-lock")
                self.assertEqual(spec["volumes"], [{"name": "kubeconfig", "hostPath": {"path": conf, "type": "File"}}])
                self.assertEqual(c["volumeMounts"][0]["mountPath"], "/etc/kubernetes/admin.conf")


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the rendered files")
class TestCluster(unittest.TestCase):
    def test_cilium_values(self):
        (v,) = docs(m2()["out"]["bootstrap/k8s/20-cilium-values.yaml"])
        model = m2()["model"]
        self.assertEqual(v["devices"], list(model.spec["k8s"]["cilium_devices"]))
        self.assertEqual(v["devices"], ["bond0", "bond0.110"], "the node VLAN and, on the ingress nodes, the VIPs' VLAN unit")
        self.assertEqual(v["bpf"]["vlanBypass"], [110, 120], "Cilium passes the tagged ingress and storage VLANs")
        self.assertIs(v["kubeProxyReplacement"], True)
        self.assertEqual((v["k8sServiceHost"], v["k8sServicePort"]), ("10.20.1.10", 6443))
        self.assertEqual(v["ipam"]["operator"]["clusterPoolIPv4PodCIDRList"], ["10.22.0.0/16"])
        self.assertIs(v["l2announcements"]["enabled"], True)
        self.assertIs(v["gatewayAPI"]["enabled"], True)
        self.assertIs(v["cni"]["exclusive"], False)
        imgs = versions()["kubernetes"]["cilium"]["images"]
        self.assertEqual(v["image"]["override"], f"{imgs['agent']['ref']}@{imgs['agent']['digest']}")
        self.assertEqual(v["operator"]["image"]["override"], f"{imgs['operator']['ref']}@{imgs['operator']['digest']}")
        self.assertEqual(v["envoy"]["image"]["override"], f"{imgs['envoy']['ref']}@{imgs['envoy']['digest']}")
        self.assertNotIn("streamIdleTimeoutDurationSeconds", v["envoy"], "chapter 7 records the default first")

    def test_pools_and_policy(self):
        out = m2()["out"]
        pools = {p["metadata"]["name"]: p for p in docs(out["bootstrap/k8s/30-lb-pools.yaml"])}
        self.assertEqual(pools["gw-internal"]["spec"]["blocks"], [{"start": "10.20.11.200", "stop": "10.20.11.209"}])
        self.assertEqual(pools["gw-users"]["spec"]["blocks"], [{"start": "10.20.11.210", "stop": "10.20.11.214"}])
        self.assertEqual(pools["gw-users"]["spec"]["serviceSelector"], {"matchLabels": {"tarnwick.example/lb-pool": "gw-users"}})
        self.assertEqual(pools["gw-users"]["apiVersion"], "cilium.io/v2")
        (pol,) = docs(out["bootstrap/k8s/31-l2-announcement.yaml"])
        self.assertEqual(pol["spec"]["interfaces"], ["^bond0\\.110$"], "announced on the ingress VLAN's unit only")
        self.assertEqual(pol["spec"]["nodeSelector"],
                         {"matchExpressions": [{"key": "node-role.tarnwick.example/ingress", "operator": "Exists"}]},
                         "from the ingress nodes, never the control plane")
        self.assertEqual(pol["spec"]["serviceSelector"]["matchExpressions"][0]["values"], ["gw-internal", "gw-users"])
        self.assertIs(pol["spec"]["loadBalancerIPs"], True)

    def test_gateways(self):
        gws = {g["metadata"]["name"]: g for g in docs(m2()["out"]["bootstrap/k8s/50-gateways.yaml"])}
        self.assertEqual(sorted(gws), ["gw-internal", "gw-users"])
        for name, vip in (("gw-internal", "10.20.11.200"), ("gw-users", "10.20.11.210")):
            g = gws[name]
            self.assertEqual(g["metadata"]["namespace"], "gateways")
            self.assertEqual(g["spec"]["gatewayClassName"], "cilium")
            self.assertEqual(g["spec"]["addresses"], [{"type": "IPAddress", "value": vip}])
            self.assertEqual(g["spec"]["infrastructure"]["labels"]["tarnwick.example/lb-pool"], name)
            (ls,) = g["spec"]["listeners"]
            self.assertEqual((ls["protocol"], ls["port"], ls["hostname"]), ("HTTPS", 443, "*.ai.tarnwick.example"))
            # each Gateway its own certificate and key
            self.assertEqual(ls["tls"]["certificateRefs"], [{"group": "", "kind": "Secret", "name": f"{name}-tls"}])
        self.assertEqual(gws["gw-users"]["metadata"]["labels"]["decision.tarnwick.example/id"], "dec-routeset-enterprise")

    def test_pki(self):
        out = m2()["out"]
        # one certificate per Gateway of the state (the internet Gateway's comes with it, in state many)
        iss, *certs = docs(out["bootstrap/k8s/40-pki.yaml"])
        self.assertEqual((iss["kind"], iss["metadata"]["name"], iss["spec"]), ("ClusterIssuer", "lab-ca", {"ca": {"secretName": "lab-ca"}}))
        self.assertEqual([c["metadata"] for c in certs], [{"name": "gw-internal", "namespace": "gateways"}, {"name": "gw-users", "namespace": "gateways"}])
        for cert in certs:
            self.assertEqual(cert["spec"]["secretName"], f"{cert['metadata']['name']}-tls")
            self.assertEqual(cert["spec"]["dnsNames"], ["*.ai.tarnwick.example"])
            self.assertEqual(cert["spec"]["privateKey"]["rotationPolicy"], "Always")
            self.assertEqual((cert["spec"]["duration"], cert["spec"]["renewBefore"]), ("2160h", "360h"))
            self.assertEqual(cert["spec"]["issuerRef"], {"group": "cert-manager.io", "kind": "ClusterIssuer", "name": "lab-ca"})
        rows = [l for l in out["bootstrap/k8s/ca-secrets.list"].splitlines() if l and not l.startswith("#")]
        self.assertEqual(rows, ["platform cert-manager/lab-ca"])

    def test_cert_manager_values(self):
        (v,) = docs(m2()["out"]["bootstrap/k8s/21-cert-manager-values.yaml"])
        imgs = versions()["kubernetes"]["cert_manager"]["images"]
        self.assertEqual(v["crds"], {"enabled": True, "keep": True})
        got = {"controller": v["image"], **{k: v[k]["image"] for k in ("webhook", "cainjector", "startupapicheck", "acmesolver")}}
        for k, img in got.items():
            ref = f"{img['repository']}:{img['tag']}"
            self.assertEqual(ref, imgs[k]["ref"], k)
            self.assertEqual(img["digest"], imgs[k]["digest"], k)

    def test_test_backend(self):
        d = docs(m2()["out"]["bootstrap/k8s/55-test-backend.yaml"])
        kinds = [x["kind"] for x in d]
        self.assertEqual(kinds, ["Deployment", "Service", "HTTPRoute", "HTTPRoute"])
        dep, svc, r_int, r_users = d
        (c,) = dep["spec"]["template"]["spec"]["containers"]
        pin = versions()["kubernetes"]["test_backend"]["image"]
        self.assertEqual(c["image"], f"{pin['ref']}@{pin['digest']}")
        self.assertEqual(c["args"], ["netexec", "--http-port=8080"])
        self.assertEqual(dep["spec"]["replicas"], 2)
        self.assertEqual(svc["spec"]["ports"][0]["port"], 8080)
        self.assertEqual(r_int["spec"]["hostnames"], ["llm.ai.tarnwick.example", "admin.ai.tarnwick.example", "grafana.ai.tarnwick.example"])
        self.assertEqual(r_users["spec"]["hostnames"], ["llm.ai.tarnwick.example"], "the users' Gateway carries no admin name")
        for r, gw in ((r_int, "gw-internal"), (r_users, "gw-users")):
            self.assertEqual(r["spec"]["parentRefs"][0]["name"], gw)
            self.assertEqual(r["spec"]["parentRefs"][0]["namespace"], "gateways")
            self.assertEqual(r["spec"]["rules"][0]["matches"], [{"path": {"type": "PathPrefix", "value": "/echo"}}])
            self.assertEqual(r["spec"]["rules"][0]["backendRefs"], [{"name": "echo", "port": 8080}])
        ns = {n["metadata"]["name"]: n for n in docs(m2()["out"]["bootstrap/k8s/05-namespaces.yaml"])}
        self.assertEqual(ns["echo"]["metadata"]["labels"], {"pod-security.kubernetes.io/enforce": "restricted"})
        sc = c["securityContext"]
        self.assertTrue(sc["runAsNonRoot"] and not sc["allowPrivilegeEscalation"] and sc["capabilities"]["drop"] == ["ALL"])

    def test_lists(self):
        out = m2()["out"]
        apply = [l for l in out["bootstrap/k8s/apply.list"].splitlines() if l and not l.startswith("#")]
        self.assertEqual(apply, ["05-namespaces.yaml", "07-operators.yaml", "10-gateway-api-crds.yaml", "30-lb-pools.yaml", "31-l2-announcement.yaml",
                                 "40-pki.yaml", "50-gateways.yaml", "55-test-backend.yaml", "58-network-policy.yaml"])
        for f in apply:
            self.assertIn(f"bootstrap/k8s/{f}", out)
        rows = [l.split() for l in out["bootstrap/k8s/charts.list"].splitlines() if l and not l.startswith("#")]
        cm = versions()["kubernetes"]["cert_manager"]["chart"]
        csi = versions()["kubernetes"]["democratic_csi"]["chart"]
        self.assertEqual(rows[0], ["cert-manager", "cert-manager", cm["name"], str(cm["version"]), "21-cert-manager-values.yaml", "k8s"])
        self.assertEqual(rows[1:], [["truenas-nvmeof", "democratic-csi", "democratic-csi", str(csi["version"]), "60-democratic-csi-nvmeof.yaml", "storage"],
                                    ["truenas-nfs", "democratic-csi", "democratic-csi", str(csi["version"]), "60-democratic-csi-nfs.yaml", "storage"]])
        self.assertFalse([r for r in rows if r[0] == "cilium"], "the init node installs Cilium")

    def test_summary(self):
        s = json.loads(m2()["out"]["gen/k8s.json"])
        self.assertEqual(s["api"]["kube_vip_lease"], "kube-system/plndr-cp-lock")
        g = s["gateways"]["gw-users"]
        self.assertEqual(g["service"], "cilium-gateway-gw-users")
        self.assertEqual(g["l2_lease"], "kube-system/cilium-l2announce-gateways-cilium-gateway-gw-users")
        self.assertEqual(s["test_backend"]["routes"], {"gw-internal": "echo-gw-internal", "gw-users": "echo-gw-users"})
        self.assertEqual(s["nodes"]["k8s-gpu2"]["labels"], {"node-role.tarnwick.example/gpu": ""})
        self.assertEqual(s["nodes"]["k8s-ingress1"]["labels"], {"node-role.tarnwick.example/ingress": ""})
        self.assertEqual(s["cilium"]["devices"], ["bond0", "bond0.110"])

    def test_ingress_nodes_are_tainted_workers(self):
        out = m2()["out"]
        for n in ("k8s-ingress1", "k8s-ingress2"):
            regs = [d["nodeRegistration"] for d in docs(out[f"bootstrap/{n}/k8s/kubeadm.yaml"]) if "nodeRegistration" in d]
            self.assertEqual([r["taints"] for r in regs], [[{"key": "node-role.tarnwick.example/ingress", "effect": "NoSchedule"}]])
        for n in ("k8s-gpu1", "k8s-cp2"):
            for d in docs(out[f"bootstrap/{n}/k8s/kubeadm.yaml"]):
                self.assertNotIn("taints", d.get("nodeRegistration") or {}, n)

    def test_crds(self):
        out = m2()["out"]["bootstrap/k8s/10-gateway-api-crds.yaml"]
        gw = versions()["kubernetes"]["gateway_api"]
        upstream = (ROOT / gw["manifest"]["file"]).read_bytes()
        self.assertEqual(hashlib.sha256(upstream).hexdigest(), gw["manifest"]["sha256"])
        self.assertTrue(out.endswith(upstream.decode()))
        names = sorted(d["metadata"]["name"] for d in docs(out))
        self.assertEqual(names, sorted(f"{x}.gateway.networking.k8s.io" for x in
                                       ("backendtlspolicies", "gatewayclasses", "gateways", "grpcroutes", "httproutes", "referencegrants")))

    def test_crds_ship_their_licence(self):
        # LICENSE.gateway-api sits beside the pinned file: a preface naming the release, the file and
        # the rendered copies, then Gateway API's LICENSE between two rules, unchanged. The body's
        # git blob id is that LICENSE's at the v1.4.1 tag, so a changed byte fails here.
        gw = versions()["kubernetes"]["gateway_api"]
        upstream = ROOT / gw["manifest"]["file"]
        text = (upstream.parent / "LICENSE.gateway-api").read_text()
        rule = "-" * 80 + "\n"
        preface, body, rest = text.split(rule)
        self.assertEqual(rest, "")
        for want in (upstream.name, f"release\n{gw['version']}", "spec/versions.yaml", "render/k8s.py",
                     "bootstrap/<init node>/k8s/10-gateway-api-crds.yaml", "bootstrap/k8s/10-gateway-api-crds.yaml",
                     "https://github.com/kubernetes-sigs/gateway-api", "Apache License 2.0", "no NOTICE file"):
            self.assertIn(want, preface)
        # the labs it names are those whose render holds both copies: milestones first, then chapters
        labs = sorted((str(d.relative_to(ROOT)) for d in [*ROOT.glob("ch[0-9][0-9]"), *ROOT.glob("dev/*")]
                       if (d / "bootstrap" / "k8s" / "10-gateway-api-crds.yaml").is_file()
                       and list(d.glob("bootstrap/*/k8s/10-gateway-api-crds.yaml"))),
                      key=lambda lab: (not lab.startswith("dev/"), lab))
        self.assertGreater(len(labs), 1)
        self.assertIn(f"Kubernetes ({', '.join(labs[:-1])} and {labs[-1]})", " ".join(preface.split()))
        blob = hashlib.sha1(f"blob {len(body.encode())}\0".encode() + body.encode()).hexdigest()
        self.assertEqual(blob, "a5949bd7a2f7892f215c10ce55399b527fb3dbd1")
        for want in ("Apache License\n", "Version 2.0, January 2004", "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION",
                     "END OF TERMS AND CONDITIONS", "Copyright 2020 The Kubernetes Authors"):
            self.assertIn(want, body)
        self.assertFalse([d for d in DASHES if d in preface])
        readme = (ROOT / "README.md").read_text()
        self.assertIn("`LICENSE.gateway-api` beside it", readme)
        self.assertIn("Licence: LICENSE.gateway-api.", (ROOT / "spec" / "versions.yaml").read_text())

    def test_multus_ships_its_licence_and_notice(self):
        # LICENSE.multus and NOTICE.multus sit beside the pinned manifest: a preface, then Multus's
        # LICENSE or NOTICE at the v4.3.0 tag between two rules, unchanged (git blob ids checked).
        upstream = ROOT / "common/sfab/render/upstream"
        rule = "-" * 80 + "\n"
        for name, blob in (("LICENSE.multus", "8f71f43fee3f78649d238238cbde51e6d7055c82"),
                           ("NOTICE.multus", "251a004bcb6fde9913a5100e2a6d8328b5db41ad")):
            preface, body, rest = (upstream / name).read_text().split(rule)
            self.assertEqual(rest, "")
            self.assertIn("db30741512795c258b3ba383a571a66850e8baac", preface)
            self.assertFalse([d for d in DASHES if d in preface])
            got = hashlib.sha1(f"blob {len(body.encode())}\0".encode() + body.encode()).hexdigest()
            self.assertEqual(got, blob, name)
        self.assertIn("`LICENSE.multus` and `NOTICE.multus` beside it", (ROOT / "README.md").read_text())

    def test_tampered_crds_refuse(self):
        from sfab.render import Context, RenderError, k8s

        gw = versions()["kubernetes"]["gateway_api"]
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / gw["manifest"]["file"]
            f.parent.mkdir(parents=True)
            f.write_bytes((ROOT / gw["manifest"]["file"]).read_bytes() + b"# changed\n")
            ctx = Context(outdir=Path(d) / "out", labdir=ROOT / "dev" / "m2", root=Path(d), spec=Labs.get()["spec"])
            with self.assertRaises(RenderError):
                k8s.render(m2()["model"], ctx)


# --------------------------------------------------------------------------------------------
# The pins


def _seed():
    sys.path.insert(0, str(ROOT / "images"))
    try:
        spec = importlib.util.spec_from_file_location("sfab_seed_for_k8s", ROOT / "images" / "registry" / "seed.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod  # its dataclasses look their module up
        spec.loader.exec_module(mod)
        return mod
    finally:
        sys.path.remove(str(ROOT / "images"))


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed")
class TestPins(unittest.TestCase):
    def test_every_image_the_cluster_pulls_is_seeded(self):
        """Every image a rendered file names (by tag and digest, or by digest) is one the in-lab
        registry's seed copies, and every chart the cluster installs is one it pushes."""
        seed = _seed()
        images, charts = seed.collect(versions())
        by_index = {f"{im.ref}@{im.digest}" for im in images}
        by_repo = {f"{im.host}/{im.repo}" for im in images}
        found = set()
        for p, text in m2()["out"].items():
            for ref in re.findall(r"\b((?:[a-z0-9-]+\.)+[a-z]+/[a-z0-9./_-]+(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64})", text):
                found.add(ref)
                repo = re.sub(r"(:[^/@]+)?@.*$", "", ref)
                if ":" in ref.split("@")[0].split("/")[-1]:
                    self.assertIn(ref, by_index, p)
                else:
                    self.assertIn(repo, by_repo, p)
        # cert-manager's chart takes repository, tag and digest apart
        (cm,) = docs(m2()["out"]["bootstrap/k8s/21-cert-manager-values.yaml"])
        for img in [cm["image"]] + [cm[k]["image"] for k in ("webhook", "cainjector", "startupapicheck")]:
            ref = f"{img['repository']}:{img['tag']}@{img['digest']}"
            self.assertIn(ref, by_index)
            found.add(ref)
        # kube-vip, Cilium's three, the test backend, helm, cert-manager's four
        self.assertEqual(len(found), 10, sorted(found))
        have = {(c.name, c.version) for c in charts}
        for key in ("cilium", "cert_manager"):
            c = versions()["kubernetes"][key]["chart"]
            self.assertIn((c["name"], str(c["version"])), have)

    def test_control_plane_images(self):
        """kubeadm v1.35.8's images are seeded: the API server and its peers at the cluster's
        version, etcd, CoreDNS and pause at kubeadm's own versions for 1.35."""
        imgs = versions()["kubernetes"]["control_plane"]["images"]
        refs = {d["ref"] for d in imgs.values()}
        v = versions()["kubernetes"]["version"]
        for c in ("kube-apiserver", "kube-controller-manager", "kube-scheduler"):
            self.assertIn(f"registry.k8s.io/{c}:{v}", refs)
        self.assertIn("registry.k8s.io/pause:3.10.1", refs)
        self.assertIn("registry.k8s.io/etcd:3.6.6-0", refs)
        self.assertIn("registry.k8s.io/coredns/coredns:v1.13.1", refs)
        self.assertFalse([r for r in refs if "kube-proxy" in r], "no kube-proxy")

    def test_pins_are_complete(self):
        k = versions()["kubernetes"]
        for key in ("cilium", "cert_manager"):
            self.assertRegex(k[key]["chart"]["sha256"], r"^[0-9a-f]{64}$")
            for name, img in k[key]["images"].items():
                self.assertRegex(img["digest"], r"^sha256:[0-9a-f]{64}$", f"{key}.{name}")
        for key in ("kube_vip", "test_backend", "node_helm"):
            self.assertRegex(k[key]["image"]["digest"], r"^sha256:[0-9a-f]{64}$", key)
        self.assertRegex(k["node_helm"]["image"]["platform_digest"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(str(k["cilium"]["version"]), str(k["cilium"]["chart"]["version"]))
        self.assertEqual(str(k["cert_manager"]["version"]), str(k["cert_manager"]["chart"]["version"]))
        self.assertTrue(k["kube_vip"]["image"]["ref"].endswith(":" + k["kube_vip"]["version"]))
        self.assertTrue(k["node_helm"]["image"]["ref"].endswith(":" + k["node_helm"]["version"].lstrip("v")))


# --------------------------------------------------------------------------------------------
# cluster-bootstrap.sh, against stand-ins

FAKE_KUBEADM = r"""#!/usr/bin/env bash
# kubeadm stand-in: writes what the real one would leave behind, and logs its arguments.
set -euo pipefail
printf 'kubeadm %s\n' "$*" >> "$FAKE_LOG"
K=$SFAB_KUBE_DIR
leaf() {  # leaf <name> <sans>: a certificate signed by $K/pki/ca.crt
  local d; d=$(mktemp -d)
  openssl ecparam -name prime256v1 -genkey -noout -out "$K/pki/$1.key" 2>/dev/null
  openssl req -new -key "$K/pki/$1.key" -subj "/CN=kube-apiserver" -out "$d/csr" 2>/dev/null
  printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$2" > "$d/ext"
  openssl x509 -req -in "$d/csr" -CA "$K/pki/ca.crt" -CAkey "$K/pki/ca.key" -set_serial 7 -days 1 -extfile "$d/ext" -out "$K/pki/$1.crt" 2>/dev/null
  rm -rf "$d"
}
control_files() {
  mkdir -p "$K/manifests" "$K/pki/etcd"
  echo "apiVersion: v1" > "$K/manifests/kube-apiserver.yaml"
  printf 'apiVersion: v1\nkind: Config\nclusters:\n- name: sfab-m2\n' > "$K/admin.conf"
}
case "$1 ${2:-}" in
  "reset -f") rm -rf "$K/pki" "$K/manifests" "$K/admin.conf" "$K/super-admin.conf" "$K/kubelet.conf"; echo reset >> "$FAKE_EVENTS" ;;
  "token generate") echo "$FAKE_TOKEN" ;;
  "init phase") leaf apiserver "$FAKE_SANS"; echo certs >> "$FAKE_EVENTS" ;;
  "init --config")
    [ -z "${FAKE_INIT_FAIL:-}" ] || exit 1
    grep -q super-admin.conf "$K/manifests/kube-vip.yaml" && echo "kube-vip-at-init super-admin" >> "$FAKE_EVENTS"
    [ "$(grep -c 'BEGIN CERTIFICATE' "$K/pki/apiserver.crt")" = 2 ] && echo "chain-at-init" >> "$FAKE_EVENTS"
    control_files
    printf 'apiVersion: v1\nkind: Config\n' > "$K/super-admin.conf"
    for f in sa.key sa.pub front-proxy-ca.crt front-proxy-ca.key etcd/ca.crt etcd/ca.key; do echo "$f of the cluster" > "$K/pki/$f"; done
    echo init >> "$FAKE_EVENTS" ;;
  "token create") echo "token-create ${3:0:6} $*" | sed "s/${FAKE_TOKEN#*.}/SECRET/g" >> "$FAKE_EVENTS"; echo "$3" ;;
  "token delete") echo token-delete >> "$FAKE_EVENTS" ;;
  "config validate") cp "$4" "$FAKE_DIR/join-config.yaml"; { stat -c %a "$4" 2>/dev/null || stat -f %Lp "$4"; } > "$FAKE_DIR/join-config.mode" ;;
  "join --config")
    if ! grep -q '^controlPlane:' "$3"; then
      [ ! -e "$K/pki/ca.crt" ] || { echo "[preflight] /etc/kubernetes/pki/ca.crt already exists" >&2; exit 1; }
    else
      [ -s "$K/pki/sa.key" ] && [ -s "$K/pki/ca.key" ] || { echo "no shared keys" >&2; exit 1; }
      control_files
      leaf apiserver "$FAKE_SANS"
    fi
    echo "kubelet" > "$K/kubelet.conf"
    echo join >> "$FAKE_EVENTS" ;;
  *) ;;
esac
"""

FAKE_KUBECTL = r"""#!/usr/bin/env bash
set -euo pipefail
printf 'kubectl %s\n' "$*" >> "$FAKE_LOG"
kc=""
if [ "${1:-}" = --kubeconfig ]; then kc=$2; shift 2; fi
case "$*" in
  "config set-cluster "*) for a in "$@"; do case $a in --server=*) echo "    server: ${a#--server=}" >> "$kc" ;; esac; done ;;
  "get --raw /readyz") echo ok ;;
  *"get secret bootstrap-token-"*) [ -f "$FAKE_DIR/token-made" ] && printf '%s' "${FAKE_TOKEN#*.}" | base64; [ -f "$FAKE_DIR/token-made" ] ;;
  "apply "*) echo "apply $*" >> "$FAKE_EVENTS" ;;
  *"get pods"*) echo True ;;
  *) ;;
esac
"""

FAKE_HELM = r"""#!/usr/bin/env bash
set -euo pipefail
printf 'helm %s\n' "$*" >> "$FAKE_LOG"
case "${1:-}" in
  version) echo v3.22.0 ;;
  list) if [ -f "$FAKE_DIR/cilium-deployed" ]; then echo '[{"name":"cilium","chart":"cilium-1.19.7","status":"deployed"}]'; else echo '[]'; fi ;;
  upgrade) echo "helm $*" >> "$FAKE_EVENTS"; touch "$FAKE_DIR/cilium-deployed" ;;
esac
"""

FAKE_CTR = r"""#!/usr/bin/env bash
set -euo pipefail
printf 'ctr %s\n' "$*" >> "$FAKE_LOG"
args=("$@")
n=${#args[@]}
# containerd 2.2.1's `ctr images mount` fails on the guests, so the bootstrap copies helm out with
# `ctr run --rm --mount type=bind,src=DIR,dst=/out,... IMAGE NAME sh -c ...`: the stand-in does the copy.
case "$*" in
  *"images mount"*) echo "ctr images mount fails on containerd 2.2.1" >&2; exit 1 ;;
  *" run "*)
    src=""; img=""
    for ((i = 0; i < n; i++)); do
      case "${args[i]}" in
        --mount) src=$(printf '%s\n' "${args[i+1]}" | tr ',' '\n' | sed -n 's/^src=//p'); img="${args[i+2]}" ;;
      esac
    done
    [ -n "$src" ] && [ -d "$src" ] || exit 1
    cp "$FAKE_HELM_BIN" "$src/helm"; echo "copy $img" >> "$FAKE_EVENTS" ;;
esac
"""

FAKE_SIMPLE = """#!/usr/bin/env bash
printf '%s %s\\n' "$(basename "$0")" "$*" >> "$FAKE_LOG"
case "$(basename "$0")" in
  crictl) echo "pull $*" >> "$FAKE_EVENTS" ;;
  curl) echo ok ;;
esac
"""


def _ossl(*args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def make_ca(d: Path, without: tuple = ()) -> None:
    """A lab root and a name-constrained Kubernetes intermediate under d (root.crt, ca.crt, ca.key),
    with the spec's constraints, less the DNS names in without."""
    import dataclasses

    from sfab.render.ca import name_constraints

    inter = next(i for i in m2()["model"].ca.intermediates if i.name == "kubernetes")
    inter = dataclasses.replace(inter, dns=tuple(x for x in inter.dns if x not in without))

    d.mkdir(parents=True, exist_ok=True)
    (d / "root.cnf").write_text("[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nO=Tarnwick\nCN=Tarnwick Lab Root CA\n"
                                "[ext]\nbasicConstraints=critical,CA:TRUE,pathlen:1\nkeyUsage=critical,keyCertSign,cRLSign\n")
    _ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "root.key", cwd=d)
    _ossl("req", "-x509", "-new", "-key", "root.key", "-config", "root.cnf", "-extensions", "ext", "-days", "2", "-out", "root.crt", cwd=d)
    nc = name_constraints(inter)
    (d / "ca.cnf").write_text("[req]\nprompt=no\ndistinguished_name=dn\n[dn]\nO=Tarnwick\nCN=Tarnwick Kubernetes CA\n"
                              "[ext]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\n"
                              f"nameConstraints={nc}\n")
    _ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key", cwd=d)
    _ossl("req", "-new", "-key", "ca.key", "-config", "ca.cnf", "-out", "ca.csr", cwd=d)
    _ossl("x509", "-req", "-in", "ca.csr", "-CA", "root.crt", "-CAkey", "root.key", "-set_serial", "2", "-days", "2",
          "-extfile", "ca.cnf", "-extensions", "ext", "-out", "ca.crt", cwd=d)
    for f in ("root.key", "ca.csr", "root.cnf", "ca.cnf"):
        (d / f).unlink()
    os.chmod(d / "ca.key", 0o600)


def apiserver_sans(node: str, address: str) -> str:
    return ",".join([f"DNS:{n}" for n in ("kubernetes", "kubernetes.default", "kubernetes.default.svc",
                                          "kubernetes.default.svc.cluster.local", node, "k8s.ai.tarnwick.example")]
                    + [f"IP:{a}" for a in ("10.23.0.1", address, "10.20.1.10")])


@unittest.skipUnless(BASH and OPENSSL and HAVE_YAML, "bash 4 or later, openssl and PyYAML are needed")
class TestClusterBootstrap(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.fake = self.d / "fake"
        self.fake.mkdir()
        self.shared = self.d / "shared"
        bin_dir = standins.make_bin(self.d / "bin", {
            "kubeadm": FAKE_KUBEADM, "kubectl": FAKE_KUBECTL, "ctr": FAKE_CTR, "crictl": FAKE_SIMPLE, "curl": FAKE_SIMPLE,
        })
        (self.fake / "helm").write_text(FAKE_HELM)
        (self.fake / "helm").chmod(0o755)
        self.env = {
            "PATH": standins.path_with(bin_dir), "LC_ALL": "C", "HOME": str(self.d),
            "FAKE_LOG": str(self.fake / "log"), "FAKE_EVENTS": str(self.fake / "events"), "FAKE_DIR": str(self.fake),
            "FAKE_HELM_BIN": str(self.fake / "helm"), "FAKE_TOKEN": TOKEN,
            "SFAB_SHARED_CLUSTER": str(self.shared), "SFAB_STATE_DIR": str(self.d / "state"), "SFAB_RUN_DIR": str(self.d / "run"),
            "SFAB_BIN_DIR": str(self.d / "usrbin"), "SFAB_WAIT_S": "3", "SFAB_POLL_S": "1",
        }
        standins.check(self.env, bin_dir, standins.DEVICE_COMMANDS + ("kubeadm", "kubectl", "ctr", "crictl", "curl"))

    def tearDown(self):
        self.tmp.cleanup()

    def node(self, name: str) -> dict:
        """The node's rendered files in its own k8s directory, and its own /etc/kubernetes."""
        k = self.d / name / "k8s"
        k.mkdir(parents=True)
        for p, text in m2()["out"].items():
            if p.startswith(f"bootstrap/{name}/k8s/"):
                (k / p.rsplit("/", 1)[1]).write_text(text)
        kube = self.d / name / "kubernetes"
        kube.mkdir()
        addr = m2()["model"].nodes[name].primary
        return {"SFAB_K8S_DIR": str(k), "SFAB_KUBE_DIR": str(kube), "FAKE_SANS": apiserver_sans(name, addr)}

    def run_node(self, name: str, env: dict) -> subprocess.CompletedProcess:
        full = {**self.env, **env}
        r = subprocess.run([BASH, str(BOOTSTRAP)], env=full, capture_output=True, text=True, timeout=standins.SCRIPT_TIMEOUT_S)
        self.assertNotIn(TOKEN.split(".")[1], r.stdout + r.stderr, "the token's secret is never printed")
        return r

    def events(self) -> list:
        p = self.fake / "events"
        return p.read_text().splitlines() if p.exists() else []

    def lab_ca(self, without=()):
        make_ca(self.shared / "ca", without)

    def token_file(self):
        self.shared.mkdir(exist_ok=True)
        f = self.shared / "kubeadm.env"
        f.write_text(f"SFAB_KUBEADM_TOKEN={TOKEN}\n")
        f.chmod(0o600)

    def init(self) -> tuple:
        self.lab_ca()
        self.token_file()
        env = self.node("k8s-cp1")
        r = self.run_node("k8s-cp1", env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return env, r

    def test_init(self):
        env, r = self.init()
        ev = self.events()
        i = ev.index
        self.assertLess(i("reset"), i("certs"))
        self.assertLess(i("certs"), i("init"))
        self.assertIn("kube-vip-at-init super-admin", ev)
        self.assertIn("chain-at-init", ev)
        kube = Path(env["SFAB_KUBE_DIR"])
        # kube-vip moved to admin.conf after init
        self.assertEqual((kube / "manifests" / "kube-vip.yaml").read_text(), m2()["out"]["bootstrap/k8s-cp1/k8s/kube-vip.yaml"])
        self.assertEqual((kube / "pki" / "apiserver.crt").read_text().count("BEGIN CERTIFICATE"), 2)
        self.assertEqual((kube / "pki" / "ca.crt").read_bytes(), (self.shared / "ca" / "ca.crt").read_bytes())
        # the token, made with no expiry, never printed
        tok = [e for e in ev if e.startswith("token-create")]
        self.assertEqual(len(tok), 1)
        self.assertIn("--ttl 0", tok[0])
        # the shared keys, keys 0600
        for f, mode in (("sa.key", 0o600), ("sa.pub", 0o644), ("front-proxy-ca.key", 0o600), ("etcd-ca.crt", 0o644), ("etcd-ca.key", 0o600)):
            self.assertEqual((self.shared / "pki" / f).stat().st_mode & 0o777, mode, f)
        # the admin kubeconfig stays on the node: none is published, the chain is checked instead
        self.assertFalse((self.shared / "kubeconfig").exists(), "no kubeconfig leaves the init node")
        self.assertFalse((self.shared / "ready").exists())
        # Secrets at rest: the EncryptionConfiguration made once, 0600, a secretbox key of 32 bytes
        # and identity after it, shared as a .key file (the retract removes it); never printed
        enc = kube / "enc" / "config.yaml"
        self.assertEqual(enc.stat().st_mode & 0o777, 0o600)
        doc = yaml.safe_load(enc.read_text())
        self.assertEqual(doc["kind"], "EncryptionConfiguration")
        (res,) = doc["resources"]
        self.assertEqual(res["resources"], ["secrets"])
        self.assertEqual(list(res["providers"][0]), ["secretbox"])
        self.assertEqual(res["providers"][1], {"identity": {}})
        key = res["providers"][0]["secretbox"]["keys"][0]
        self.assertEqual((key["name"], len(base64.b64decode(key["secret"]))), ("key1", 32))
        self.assertNotIn(key["secret"], r.stdout + r.stderr)
        self.assertEqual((self.shared / "pki" / "encryption-config.key").read_bytes(), enc.read_bytes())
        self.assertEqual((self.shared / "pki" / "encryption-config.key").stat().st_mode & 0o777, 0o600)
        self.assertIn("verifies against the lab root alone", r.stdout)
        # the CRDs before Cilium, helm from its image, the chart from the registry
        crd = [n for n, e in enumerate(ev) if e.startswith("apply") and "10-gateway-api-crds.yaml" in e]
        helm = [n for n, e in enumerate(ev) if e.startswith("helm upgrade")]
        self.assertTrue(crd and helm and crd[0] < helm[0], ev)
        self.assertIn("--server-side", ev[crd[0]])
        h = ev[helm[0]]
        for part in ("--install cilium oci://192.0.2.6:5000/charts/cilium", "--version 1.19.7", "-n kube-system", "--ca-file /shared/ca/root.crt",
                     f"-f {env['SFAB_K8S_DIR']}/20-cilium-values.yaml"):
            self.assertIn(part, h)
        pulls = [e for e in ev if e.startswith("pull ")]
        self.assertEqual(len(pulls), 1)
        self.assertTrue(pulls[0].endswith("docker.io/alpine/helm@" + versions()["kubernetes"]["node_helm"]["image"]["platform_digest"]))
        self.assertTrue((self.d / "usrbin" / "helm").exists())
        # copied out by a container of the pinned image, never through `ctr images mount`
        self.assertEqual([e for e in ev if e.startswith("copy ")],
                         ["copy docker.io/alpine/helm@" + versions()["kubernetes"]["node_helm"]["image"]["platform_digest"]])
        self.assertNotIn("images mount", (self.fake / "log").read_text())
        self.assertFalse(list((self.d / "run").glob("helm-image.*")), "the copy directory is removed")
        self.assertTrue((self.d / "state" / "cilium.applied").exists())
        self.assertIn("k8s-cp1: done", r.stdout)

    def test_init_again_acts_on_nothing(self):
        env, _ = self.init()
        (self.fake / "token-made").touch()
        (self.fake / "events").unlink()
        r = self.run_node("k8s-cp1", env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        ev = self.events()
        for e in ("reset", "certs", "init"):
            self.assertNotIn(e, ev)
        self.assertFalse([e for e in ev if e.startswith(("token-create", "helm upgrade", "pull "))], ev)
        self.assertIn("the cluster exists", r.stdout)
        self.assertIn("is deployed with these values", r.stdout)

    def test_init_again_after_the_retract(self):
        # finish retracts the CA key (and the shared keys) once the control nodes joined; the init
        # node's next run takes only the certificates and publishes its shared keys again
        env, _ = self.init()
        (self.shared / "ca" / "ca.key").unlink()
        for f in (self.shared / "pki").glob("*.key"):
            f.unlink()
        (self.fake / "events").unlink()
        r = self.run_node("k8s-cp1", env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn("waiting for the lab's Kubernetes CA", r.stdout)
        self.assertEqual((Path(env["SFAB_KUBE_DIR"]) / "pki" / "ca.key").stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.shared / "pki" / "sa.key").exists())
        self.assertIn("k8s-cp1: done", r.stdout)

    def test_init_makes_a_token_when_none_was_written(self):
        self.lab_ca()
        env = self.node("k8s-cp1")
        r = self.run_node("k8s-cp1", env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        f = self.shared / "kubeadm.env"
        self.assertEqual(f.read_text(), f"SFAB_KUBEADM_TOKEN={TOKEN}\n")
        self.assertEqual(f.stat().st_mode & 0o777, 0o600)

    def test_init_refuses_a_certificate_the_constraints_refuse(self):
        """With a Kubernetes intermediate whose constraints leave out the control nodes' names, the
        API server's certificate names k8s-cp1 outside them: the run stops before kubeadm init."""
        self.lab_ca(without=("k8s-cp1", "k8s-cp2", "k8s-cp3"))
        self.token_file()
        env = self.node("k8s-cp1")
        r = self.run_node("k8s-cp1", env)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("does not verify against the lab root", r.stdout)
        self.assertIn("k8s-cp1", r.stdout)
        self.assertNotIn("init", self.events())

    def test_failed_init_is_reset(self):
        self.lab_ca()
        self.token_file()
        env = self.node("k8s-cp1")
        r = self.run_node("k8s-cp1", {**env, "FAKE_INIT_FAIL": "1"})
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.events()[-1], "reset")

    def test_join_control(self):
        self.init()
        (self.fake / "events").unlink()
        env = self.node("k8s-cp2")
        r = self.run_node("k8s-cp2", env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        kube = Path(env["SFAB_KUBE_DIR"])
        cfg = yaml.safe_load((self.fake / "join-config.yaml").read_text())
        pin = subprocess.run("openssl x509 -in ca.crt -noout -pubkey | openssl pkey -pubin -outform DER | openssl dgst -sha256 -r",
                             shell=True, cwd=self.shared / "ca", capture_output=True, text=True, check=True).stdout.split()[0]
        self.assertEqual(cfg["discovery"]["bootstrapToken"],
                         {"apiServerEndpoint": "k8s.ai.tarnwick.example:6443", "token": TOKEN, "caCertHashes": [f"sha256:{pin}"]})
        self.assertIn("controlPlane", cfg)
        self.assertEqual((self.fake / "join-config.mode").read_text().strip(), "600")
        self.assertFalse((self.d / "run" / "kubeadm-join.yaml").exists(), "the copy with the token is removed")
        self.assertEqual((kube / "pki" / "etcd" / "ca.key").read_text(), "etcd/ca.key of the cluster\n")
        self.assertEqual((kube / "pki" / "sa.key").stat().st_mode & 0o777, 0o600)
        # the init node's EncryptionConfiguration, the same bytes, 0600
        self.assertEqual((kube / "enc" / "config.yaml").read_bytes(), (self.shared / "pki" / "encryption-config.key").read_bytes())
        self.assertEqual((kube / "enc" / "config.yaml").stat().st_mode & 0o777, 0o600)
        self.assertEqual((kube / "manifests" / "kube-vip.yaml").read_text(), m2()["out"]["bootstrap/k8s-cp2/k8s/kube-vip.yaml"])
        self.assertEqual((kube / "pki" / "apiserver.crt").read_text().count("BEGIN CERTIFICATE"), 2)
        self.assertEqual(self.events()[-1], "join")

    def test_join_worker(self):
        self.init()
        (self.fake / "events").unlink()
        env = self.node("k8s-gpu1")
        r = self.run_node("k8s-gpu1", env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cfg = yaml.safe_load((self.fake / "join-config.yaml").read_text())
        self.assertNotIn("controlPlane", cfg)
        self.assertEqual(cfg["nodeRegistration"]["name"], "k8s-gpu1")
        kube = Path(env["SFAB_KUBE_DIR"])
        self.assertFalse((kube / "manifests" / "kube-vip.yaml").exists())
        # a second run finds the node joined and does nothing
        (self.fake / "events").unlink()
        r = self.run_node("k8s-gpu1", env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.events(), [])

    def test_join_waits_for_the_token(self):
        self.lab_ca()
        env = self.node("k8s-gpu2")
        r = self.run_node("k8s-gpu2", env)
        self.assertEqual(r.returncode, 1)
        self.assertIn("gave up after 3s waiting for", r.stdout)
        self.assertNotIn("join", self.events())


@unittest.skipUnless(HAVE_YAML, "PyYAML is needed to read the spec")
class TestConstraints(unittest.TestCase):
    def test_the_kubernetes_intermediate_permits_the_api_server(self):
        """Every name kubeadm puts in a control node's API server certificate (its node name
        included) sits inside the Kubernetes intermediate's name constraints, or every client of
        the API refuses it."""
        from sfab.render.ca import apiserver_sans, permits

        model = m2()["model"]
        inter = next(i for i in model.ca.intermediates if i.name == "kubernetes")
        for c in model.k8s.control:
            for s in apiserver_sans(model, c):
                self.assertTrue(permits(inter, s), f"{c}: {s}")


class TestUnit(unittest.TestCase):
    def test_unit(self):
        text = UNIT.read_text()
        for line in ("Type=oneshot", "Restart=on-failure", "ExecStart=/opt/sfab/bin/cluster-bootstrap.sh",
                     "Requires=sfab-netsetup.service containerd.service", "ConditionPathExists=/etc/sfab/k8s/cluster.env",
                     "StartLimitIntervalSec=0", "TimeoutStartSec=infinity", "WantedBy=multi-user.target"):
            self.assertIn(line + "\n", text)
        self.assertRegex(text, r"(?m)^After=sfab-netsetup\.service ")

    def test_script(self):
        text = BOOTSTRAP.read_text()
        self.assertTrue(text.startswith("#!/usr/bin/env bash\n"))
        self.assertIn("\nset -euo pipefail\n", text)
        self.assertTrue(os.access(BOOTSTRAP, os.X_OK), "executable")
        self.assertNotIn("unsafeSkipCAVerification", text)


if __name__ == "__main__":
    unittest.main()
