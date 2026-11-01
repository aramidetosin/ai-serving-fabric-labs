"""Kubernetes (FRAMEWORK.md sections 2.2, 3.4 and 5): the cluster's own files, fully rendered.

Two places, because two parties read them.

bootstrap/<node>/k8s/, for every Kubernetes node. The topology binds bootstrap/<node>/ into the
node's container, vm-init.sh seeds this directory into the guest at /etc/sfab/k8s, and
cluster-bootstrap.sh (images/vm-node/node-files, run by sfab-cluster.service) reads it:

  cluster.env              what cluster-bootstrap.sh needs beside the files: the node, its role and
                           address, the API endpoint, and on the init node the chart, helm and the
                           kubeconfig it publishes (KEY=value lines sorted by key, as node.env)
  kubeadm-user.yaml        the init node: the ClusterConfiguration alone, for kubeadm kubeconfig user,
                           which issues each operator's short-lived kubeconfig (finish, operators)
  kubeadm.yaml             init: InitConfiguration, ClusterConfiguration, KubeletConfiguration;
                           join: one JoinConfiguration, whose last lines are the bootstrap token
                           discovery mapping, so cluster-bootstrap.sh appends the token and the CA
                           pin, the only values not rendered, to a 0600 copy at run time
  kube-vip.yaml            control nodes: the static pod that holds the API VIP, on the node's
                           admin.conf (after init or join)
  kube-vip-init.yaml       the init node: the same pod on super-admin.conf, the only kubeconfig
                           that works while kubeadm init runs
  10-gateway-api-crds.yaml the init node: the Gateway API CRDs, applied before Cilium, whose
                           operator enables its Gateway controller only when they exist at start
  20-cilium-values.yaml    the init node: the Cilium release's values

bootstrap/k8s/, applied by the finish stage with the harness's kubectl, which runs on the init node
with the admin kubeconfig kubeadm wrote there (common/lib.sh K; the bastion holds none):

  05-namespaces.yaml       the Gateways', the test backend's and cert-manager's namespaces
  07-operators.yaml        the ClusterRoleBinding of the operators' group (k8s.operators) to their
                           ClusterRole: what an operator's short-lived kubeconfig on the bastion may do
  10-gateway-api-crds.yaml the same CRDs (re-applied server-side, so a heal restores them)
  20-cilium-values.yaml    the same values (the finish stage's device drift fix reuses the release's)
  21-cert-manager-values.yaml
  30-lb-pools.yaml         one CiliumLoadBalancerIPPool per Gateway, its VIP's range
  31-l2-announcement.yaml  the CiliumL2AnnouncementPolicy: the Gateway Services on the spec's
                           interfaces, from the control nodes
  40-pki.yaml              cert-manager's CA ClusterIssuer and the Gateways' listener certificate
  50-gateways.yaml         one Gateway per spec Gateway, its VIP as its address; with serving on,
                           each listener admits routes only from the namespaces labelled for it
                           (k8s.allowed_routes: route_namespaces(), allowed_routes())
  55-test-backend.yaml     the plain HTTP backend and one HTTPRoute per Gateway it sits behind
  12-multus-daemonset-thick.yaml  with serving on: Multus v4.3.0's thick plugin, the upstream
                           manifest with its image pinned and its memory raised (multus())
  serving.env              with serving on: the serving recipe's settings and placement table,
                           which finish hands to `make -C serving-layer serve` (serving_env())
  60-inference-base.yaml   with serving on and the spec's inference block: the API gateway's and
  61-inference-keys.yaml   the router's namespace and roles, the key Job, and the API gateway, the
  62-inference.yaml        router and the model routes (render/inference.py); finish applies them
                           after the serving recipe, outside apply.list
  apply.list               the manifests in apply order (finish sets aside a kind not served yet)
  charts.list              the releases finish installs: cert-manager, and the CSI releases of
                           render/storage.py (phase storage)
  ca-secrets.list          "<intermediate> <namespace>/<secret>": the CA key pairs sfab-ca k8s-secret
                           writes from the lab host for cert-manager's issuer

gen/k8s.json is the same cluster as names (releases, Services, leases, routes) for the audit and
the trace.

Every pin comes from spec/versions.yaml: images by digest, charts by version (the in-lab
registry serves them, render/storage.py's way), and the Gateway API CRDs from the upstream file
under common/sfab/render/upstream/, checked against its sha256. Nothing here is a secret: the
join token reaches the nodes through state/shared/cluster/kubeadm.env, and every key is made on the
lab host (sfab-ca, state/ca) or by kubeadm.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path

from ..model import Host, Model
from . import RenderError
from .host import env_file

SCHEMA = 1

# kubeadm and the kubelet
KUBEADM_API = "kubeadm.k8s.io/v1beta4"
KUBELET_API = "kubelet.config.k8s.io/v1beta1"
API_PORT = 6443
CRI_SOCKET = "unix:///run/containerd/containerd.sock"
IMAGE_REPOSITORY = "registry.k8s.io"
DNS_DOMAIN = "cluster.local"
# The VM guests are slow to start a control plane, so every kubeadm wait is doubled or more.
KUBEADM_TIMEOUTS = {"controlPlaneComponentHealthCheck": "10m0s", "kubeletHealthCheck": "10m0s",
                    "discovery": "10m0s", "tlsBootstrap": "10m0s"}
# Absolute eviction thresholds (FRAMEWORK 6.4). A threshold the kubelet is given replaces the
# whole default set, so all five are named. Absolute values mean the same on the 40 GiB control
# disks as on the 80 GiB GPU disks, and nothing is read as a share of a disk the host thin-provisions.
EVICTION_HARD = {"imagefs.available": "4Gi", "imagefs.inodesFree": "5%", "memory.available": "256Mi",
                 "nodefs.available": "4Gi", "nodefs.inodesFree": "5%"}
# netsetup.sh writes the lab's resolvers as the node's here; kubeadm would otherwise point the
# kubelet at systemd-resolved's file, which knows no lab resolver, and CoreDNS would forward nowhere.
RESOLV_CONF = "/etc/resolv.conf"

# Where things live in the guest (images/vm-node/node-files/cluster-bootstrap.sh).
GUEST_K8S_DIR = "/etc/sfab/k8s"
SHARED_CLUSTER = "/shared/cluster"
KUBE_DIR = "/etc/kubernetes"
# Secrets at rest (k8s.secrets_encryption): the API server's EncryptionConfiguration, which
# cluster-bootstrap.sh writes on the init node at its first init (a key of 32 random bytes) and
# places on every other control node from the shared keys before it joins. The directory is the
# API server's hostPath volume; kubeadm reset leaves it.
ENCRYPTION_DIR = "/etc/kubernetes/enc"
ENCRYPTION_FILE = "config.yaml"
ENCRYPTION_PROVIDERS = ("secretbox",)

# kube-vip: ARP on the data bond, leader election on a lease. The timings are those of the example ARP
# manifest in kube-vip's static Pod guide, shorter than the release's defaults of 15, 10 and 2 s.
KUBE_VIP_LEASE = "plndr-cp-lock"
KUBE_VIP_TIMING = {"vip_leaseduration": "5", "vip_renewdeadline": "3", "vip_retryperiod": "1"}

# Cilium
CILIUM_RELEASE = "cilium"
SYSTEM_NS = "kube-system"
CILIUM_TUNNEL = "geneve"
CILIUM_POD_MASK = 24
CILIUM_CLIENT_RATE = {"qps": 50, "burst": 100}

# cert-manager
CERT_MANAGER_RELEASE = "cert-manager"
CERT_MANAGER_NS = "cert-manager"
CERT_MANAGER_IMAGES = ("controller", "webhook", "cainjector", "startupapicheck", "acmesolver")
# The listener certificate's key (cert-manager makes it in the cluster).
CERT_KEY = {"algorithm": "ECDSA", "size": 256, "rotationPolicy": "Always"}

# The test backend's container, restricted-profile clean.
TEST_BACKEND_RESOURCES = {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}}
TEST_BACKEND_UID = 65534

# Output names.
FILES = {
    "namespaces": "05-namespaces.yaml",
    "operators": "07-operators.yaml",
    "crds": "10-gateway-api-crds.yaml",
    "cilium": "20-cilium-values.yaml",
    "cert_manager": "21-cert-manager-values.yaml",
    "pools": "30-lb-pools.yaml",
    "l2": "31-l2-announcement.yaml",
    "pki": "40-pki.yaml",
    "gateways": "50-gateways.yaml",
    "test_backend": "55-test-backend.yaml",
    "multus": "12-multus-daemonset-thick.yaml",
    "serving": "serving.env",
    "identity": "57-identity.yaml",
    "netpol": "58-network-policy.yaml",
}
APPLY_ORDER = ("namespaces", "operators", "crds", "multus", "pools", "l2", "pki", "gateways", "test_backend", "identity", "netpol")
NODE_FILES = {"env": "cluster.env", "kubeadm": "kubeadm.yaml", "kube_vip": "kube-vip.yaml",
              "kube_vip_init": "kube-vip-init.yaml", "kubeadm_user": "kubeadm-user.yaml"}
# Where the harness's kubectl finds the cluster's admin kubeconfig on the init node (kubeadm writes
# it there, and it never leaves the node), and the operators' defaults (k8s.operators).
ADMIN_KUBECONFIG = "/etc/kubernetes/admin.conf"
OPERATORS = {"users": [], "group": "operators", "cluster_role": "view", "validity_h": 8}
# The built-in view role reads namespaced objects only, so an operator could not list the nodes. Its
# companion role reads the cluster-scoped objects an operator inspects, and still no Secret.
OPERATOR_CLUSTER_READ = [
    ("", ["nodes", "namespaces", "persistentvolumes"]),
    ("storage.k8s.io", ["storageclasses", "csidrivers", "csinodes", "volumeattachments"]),
    ("networking.k8s.io", ["ingressclasses"]),
    ("gateway.networking.k8s.io", ["gatewayclasses"]),
    ("apiextensions.k8s.io", ["customresourcedefinitions"]),
    ("scheduling.k8s.io", ["priorityclasses"]),
    ("node.k8s.io", ["runtimeclasses"]),
]
# What a join configuration ends with: cluster-bootstrap.sh checks for this line before it appends.
JOIN_TAIL = "# cluster-bootstrap.sh appends token and caCertHashes here at run time"

# Registries the in-lab registry's seed copies one platform from (images/registry/seed.py): a node
# pulls their images by the platform manifest's digest, never by the index digest.
ONE_PLATFORM_HOSTS = ("docker.io",)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


# --------------------------------------------------------------------------------------------
# YAML: a small, deterministic writer for the subset Kubernetes objects use. Mappings keep the
# order given; lists sit at their key's indentation, as kubectl prints them; a string is written
# plain only when YAML cannot read it as anything else.

_PLAIN = re.compile(r"^[A-Za-z_/][A-Za-z0-9_./@=+-]*(?::[A-Za-z0-9_./@=+-]+)*$")
_WORDS = {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~", "="}


def scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        raise RenderError(f"no floats in the Kubernetes files: {v!r}")
    s = str(v)
    if _PLAIN.match(s) and s.lower() not in _WORDS:
        return s
    return json.dumps(s)


def _lines(obj, indent: int) -> list:
    pad = " " * indent
    out: list = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = scalar(k)
            if isinstance(v, dict) and v:
                out.append(f"{pad}{key}:")
                out.extend(_lines(v, indent + 2))
            elif isinstance(v, list) and v:
                out.append(f"{pad}{key}:")
                out.extend(_lines(v, indent))
            elif isinstance(v, (dict, list)):
                out.append(f"{pad}{key}: {'{}' if isinstance(v, dict) else '[]'}")
            elif isinstance(v, str) and "\n" in v.rstrip("\n"):
                out.extend(_block(f"{pad}{key}:", v, indent + 2))
            else:
                out.append(f"{pad}{key}: {scalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                sub = _lines(item, indent + 2)
                out.append(f"{pad}- {sub[0][indent + 2:]}")
                out.extend(sub[1:])
            elif isinstance(item, (dict, list)):
                out.append(f"{pad}- {'{}' if isinstance(item, dict) else '[]'}")
            elif isinstance(item, str) and "\n" in item.rstrip("\n"):
                out.extend(_block(f"{pad}-", item, indent + 2))
            else:
                out.append(f"{pad}- {scalar(item)}")
    else:
        out.append(pad + scalar(obj))
    return out


def _block(head: str, text: str, indent: int) -> list:
    """A string of several lines as a literal block scalar (a ConfigMap's file, as a reader would
    write it): '|' when it ends with one newline, '|-' with none."""
    if text.endswith("\n\n") or text.startswith((" ", "\n")) or "\t" in text or "\r" in text:
        raise RenderError(f"a block scalar must start with text and end with at most one newline: {text[:40]!r}")
    pad = " " * indent
    body = text[:-1] if text.endswith("\n") else text
    return [f"{head} |" if text.endswith("\n") else f"{head} |-"] + [(pad + line) if line else "" for line in body.split("\n")]


def dump(obj) -> str:
    return "\n".join(_lines(obj, 0)) + "\n"


def dump_all(docs: list) -> str:
    return "---\n".join(dump(d) for d in docs)


def yaml_file(head: list, docs: list) -> str:
    for line in head:
        if "\n" in line:
            raise RenderError(f"a header line may not hold a newline: {line!r}")
    return "".join(f"# {h}\n" if h else "#\n" for h in head) + dump_all(docs)


def header(model: Model, what: str, ctx) -> list:
    return [f"{model.lab} {what}: rendered from {ctx.profile_file(model)} by render/k8s.py; edit the spec and run make render"]


# --------------------------------------------------------------------------------------------
# the model, the spec and the pins


def enabled(model: Model) -> bool:
    return bool(model.features.get("k8s")) and model.k8s is not None


def _kspec(model: Model) -> dict:
    return dict((model.spec or {}).get("k8s") or {})


def _versions(model: Model) -> dict:
    return dict((model.meta.versions or {}).get("kubernetes") or {})


def _addon(model: Model, key: str) -> dict:
    v = _versions(model).get(key)
    if not isinstance(v, dict):
        raise RenderError(f"spec/versions.yaml kubernetes.{key} is not pinned")
    return v


def image_ref(pin: dict, where: str) -> str:
    """'<ref>@<digest>' for one image pin; the ref names its registry host and its tag."""
    ref, digest = (pin or {}).get("ref"), (pin or {}).get("digest")
    if not ref or not digest:
        raise RenderError(f"spec/versions.yaml {where} needs a ref and a digest")
    if not _DIGEST.match(str(digest)):
        raise RenderError(f"spec/versions.yaml {where}: digest {digest!r} is not sha256:<64 hex>")
    first, sep, rest = str(ref).partition("/")
    if not sep or not ("." in first or ":" in first) or ":" not in rest or "@" in str(ref):
        raise RenderError(f"spec/versions.yaml {where}: ref {ref!r} must be <registry host>/<repository>:<tag>")
    return f"{ref}@{digest}"


def image_parts(pin: dict, where: str) -> dict:
    """{repository, tag, digest} of one image pin, the way the cert-manager chart takes them."""
    full = image_ref(pin, where)
    ref, _, digest = full.partition("@")
    repo, _, tag = ref.rpartition(":")
    return {"repository": repo, "tag": tag, "digest": digest}


def chart_pin(model: Model, key: str) -> dict:
    c = (_addon(model, key).get("chart") or {})
    missing = [f for f in ("name", "repo", "version", "sha256") if not c.get(f)]
    if missing:
        raise RenderError(f"spec/versions.yaml kubernetes.{key}.chart is missing {', '.join(missing)}")
    if not _SHA.match(str(c["sha256"])):
        raise RenderError(f"spec/versions.yaml kubernetes.{key}.chart.sha256 is not 64 hex digits")
    return {k: str(c[k]) for k in ("name", "repo", "version", "sha256")}


def chart_oci(model: Model, name: str) -> str:
    r = model.k8s.registry or model.registry
    if r is None:
        raise RenderError("Kubernetes needs the in-lab registry (spec registry:) for its charts and images")
    path = ((model.spec or {}).get("registry") or {}).get("charts", "charts")
    return f"oci://{r.mirror}/{path}/{name}"


def registry_plain_http(model: Model) -> bool:
    return str(((model.spec or {}).get("registry") or {}).get("scheme", "http")) == "http"


# The lab root every guest finds in the shared directory it mounts (state/shared/ca, sfab-ca): helm
# and containerd verify the registry's certificate against it.
REGISTRY_CA = "/shared/ca/root.crt"


def crd_source(model: Model, ctx) -> tuple:
    """(upstream text, pin) of the Gateway API CRDs, checked against versions.yaml."""
    g = _addon(model, "gateway_api")
    m = g.get("manifest") or {}
    if not g.get("version") or not m.get("file") or not m.get("sha256"):
        raise RenderError("spec/versions.yaml kubernetes.gateway_api needs version and manifest.file and manifest.sha256")
    p = Path(ctx.root) / str(m["file"])
    try:
        data = p.read_bytes()
    except OSError as e:
        raise RenderError(f"the Gateway API CRDs {m['file']}: {e}") from None
    have = hashlib.sha256(data).hexdigest()
    if have != str(m["sha256"]):
        raise RenderError(f"{m['file']} has sha256 {have}, spec/versions.yaml pins {m['sha256']}")
    text = data.decode("utf-8")
    if f"bundle-version: {g['version']}" not in text:
        raise RenderError(f"{m['file']} is not the Gateway API {g['version']} bundle")
    return text, {"version": str(g["version"]), "channel": str(g.get("channel") or "standard"),
                  "url": m.get("url"), "sha256": have, "file": str(m["file"])}


def k8s_hosts(model: Model) -> list:
    """The Kubernetes nodes of this lab, in spec order."""
    return [h for h in model.hosts.values() if h.k8s and not h.pending]


def node_address(h: Host) -> str:
    if not h.primary:
        raise RenderError(f"{h.name}: a Kubernetes node needs a primary address")
    return h.primary


def bond_name(h: Host) -> str:
    if h.bond is None:
        raise RenderError(f"{h.name}: a control node needs its data bond for the API VIP")
    return h.bond.name


def node_labels(model: Model, h: Host) -> dict:
    """The labels a node registers with: the control label on control nodes, the GPU label on the
    GPU group (empty values, as node-role labels are)."""
    k = model.k8s
    out = {}
    if h.name in k.control and "control" in k.labels:
        out[k.labels["control"]] = ""
    if h.group == "gpu" and "gpu" in k.labels:
        out[k.labels["gpu"]] = ""
    if h.group == "ingress" and "ingress" in k.labels:
        out[k.labels["ingress"]] = ""
    return out


def node_taints(model: Model, h: Host) -> list:
    """The taints a node registers with (k8s.taints, by node group): the ingress nodes' NoSchedule
    keyed on their role label, so only what tolerates it runs there."""
    k = model.k8s
    out = []
    for role, t in (_kspec(model).get("taints") or {}).items():
        if h.group == role and role in k.labels:
            out.append({"key": k.labels[role], "effect": str((t or {}).get("effect", "NoSchedule"))})
    return out


def edge_placement(model: Model) -> dict:
    """{nodeSelector, tolerations} for what users reach (k8s.edge.nodes: the ingress nodes): the
    role's label and a toleration of its taint, or {} when the spec names no edge or the lab has no
    node of that group (its pods then go where the scheduler puts them)."""
    edge = (_kspec(model).get("edge") or {}).get("nodes")
    if not edge:
        return {}
    k = model.k8s
    if edge not in k.labels:
        raise RenderError(f"spec k8s.edge.nodes {edge!r} is not a label role ({sorted(k.labels)})")
    if not any(h.group == edge for h in k8s_hosts(model)):
        return {}
    out: dict = {"nodeSelector": {k.labels[edge]: ""}}
    t = (_kspec(model).get("taints") or {}).get(edge)
    if t is not None:
        out["tolerations"] = [{"key": k.labels[edge], "operator": "Exists", "effect": str((t or {}).get("effect", "NoSchedule"))}]
    return out


def label_arg(labels: dict) -> str:
    return ",".join(f"{k}={v}" for k, v in sorted(labels.items()))


def _decision(model: Model, d) -> dict:
    return {model.k8s.labels["decision"]: d} if d and "decision" in model.k8s.labels else {}


def _api_endpoint(model: Model) -> str:
    return f"{model.k8s.api_fqdn}:{API_PORT}"


def _fqdn(model: Model, name: str) -> str:
    """A spec name: 'wildcard' (the platform zone's wildcard name, a listener and certificate name
    only: the zone publishes no wildcard record), a bare label (under the zone) or an FQDN."""
    if name == "wildcard":
        return model.org.fqdn("*")
    return name if "." in name else model.org.fqdn(name)


# --------------------------------------------------------------------------------------------
# kubeadm


def kubelet_extra(model: Model, h: Host) -> list:
    args = [{"name": "node-ip", "value": node_address(h)}]
    labels = node_labels(model, h)
    if labels:
        args.append({"name": "node-labels", "value": label_arg(labels)})
    return args


def node_registration(model: Model, h: Host) -> dict:
    out = {"name": h.name, "criSocket": CRI_SOCKET, "kubeletExtraArgs": kubelet_extra(model, h)}
    taints = node_taints(model, h)
    if taints:
        out["taints"] = taints
    return out


def secrets_encryption(model: Model) -> dict | None:
    """{provider, resources, config} of k8s.secrets_encryption, or None when the spec has none."""
    e = _kspec(model).get("secrets_encryption")
    if not e:
        return None
    prov = str(e.get("provider") or "")
    if prov not in ENCRYPTION_PROVIDERS:
        raise RenderError(f"spec k8s.secrets_encryption.provider {prov!r} is not one of {list(ENCRYPTION_PROVIDERS)}")
    res = [str(r) for r in e.get("resources") or ["secrets"]]
    return {"provider": prov, "resources": res, "config": f"{ENCRYPTION_DIR}/{ENCRYPTION_FILE}", "dir": ENCRYPTION_DIR}


def cluster_configuration(model: Model) -> dict:
    k = model.k8s
    api: dict = {"certSANs": [k.api_fqdn, k.api_vip]}
    enc = secrets_encryption(model)
    if enc:
        # the API servers read the EncryptionConfiguration cluster-bootstrap.sh writes there
        api["extraArgs"] = [{"name": "encryption-provider-config", "value": enc["config"]}]
        api["extraVolumes"] = [{"name": "encryption", "hostPath": enc["dir"], "mountPath": enc["dir"], "readOnly": True,
                                "pathType": "DirectoryOrCreate"}]
    return {
        "apiVersion": KUBEADM_API, "kind": "ClusterConfiguration",
        "clusterName": model.lab,
        "kubernetesVersion": k.version,
        "imageRepository": IMAGE_REPOSITORY,
        "controlPlaneEndpoint": _api_endpoint(model),
        "networking": {"dnsDomain": DNS_DOMAIN, "podSubnet": k.pod_cidr, "serviceSubnet": k.service_cidr},
        "apiServer": api,
        # No kube-proxy: Cilium replaces it (kubeProxyReplacement), and an upgrade never adds it back.
        "proxy": {"disabled": True},
    }


def kubelet_configuration() -> dict:
    return {
        "apiVersion": KUBELET_API, "kind": "KubeletConfiguration",
        "cgroupDriver": "systemd",
        "resolvConf": RESOLV_CONF,
        "evictionHard": dict(sorted(EVICTION_HARD.items())),
    }


def kubeadm_init(model: Model, h: Host, ctx) -> str:
    init = {
        "apiVersion": KUBEADM_API, "kind": "InitConfiguration",
        "localAPIEndpoint": {"advertiseAddress": node_address(h), "bindPort": API_PORT},
        "nodeRegistration": node_registration(model, h),
        "timeouts": dict(KUBEADM_TIMEOUTS),
    }
    head = header(model, f"{h.name} kubeadm init", ctx) + [
        "kubeadm init --config, on the init node. No token or certificate key: cluster-bootstrap.sh",
        "creates the lab's join token after init, and the control nodes take the shared keys from",
        f"{SHARED_CLUSTER}/pki. The CA is the lab's Kubernetes intermediate ({SHARED_CLUSTER}/ca, from sfab-ca),",
        "placed before init; the API server's certificate is made first and the intermediate appended to it,",
        "so a client that trusts only the lab root can build the chain. The KubeletConfiguration is the",
        "cluster's: kubeadm uploads it and every joining node uses it.",
    ]
    return yaml_file(head, [init, cluster_configuration(model), kubelet_configuration()])


def kubeadm_user(model: Model, h: Host, ctx) -> str:
    """The init node's ClusterConfiguration alone: kubeadm kubeconfig user --config reads the
    cluster's name, its control-plane endpoint (the API's name through the VIP) and where its CA
    is, and signs an operator's client certificate with that CA."""
    head = header(model, f"{h.name} kubeadm kubeconfig user", ctx) + [
        "kubeadm kubeconfig user --config, on the init node: each operator's short-lived kubeconfig for the bastion",
        "(finish, operators). The client certificate is signed with the cluster CA kubeadm holds on this node.",
    ]
    return yaml_file(head, [cluster_configuration(model)])


def operators(model: Model) -> dict:
    """k8s.operators, with its defaults."""
    o = dict(OPERATORS)
    o.update(_kspec(model).get("operators") or {})
    o["users"] = [str(u) for u in o.get("users") or []]
    return o


def operators_manifest(model: Model, ctx) -> str:
    o = operators(model)
    head = header(model, "operators", ctx) + [
        f"The operators' group {o['group']} bound to the ClusterRole {o['cluster_role']}. Each operator's kubeconfig on the",
        f"bastion carries a client certificate in that group, issued on the init node for {o['validity_h']} hours by",
        "kubeadm kubeconfig user (finish, operators); no standing cluster-admin credential leaves the init node.",
        f"{o['cluster_role']} reads namespaced objects only, so the group is also bound to {o['group']}-cluster-view,",
        "which reads the cluster-scoped objects (nodes, namespaces, volumes, classes, CRDs) and no Secret.",
    ]
    subjects = [{"apiGroup": "rbac.authorization.k8s.io", "kind": "Group", "name": o["group"]}]
    doc = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
           "metadata": {"name": f"{o['group']}-{o['cluster_role']}"},
           "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": o["cluster_role"]},
           "subjects": subjects}
    read = f"{o['group']}-cluster-view"
    role = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": {"name": read},
            "rules": [{"apiGroups": [g], "resources": r, "verbs": ["get", "list", "watch"]}
                      for g, r in OPERATOR_CLUSTER_READ]}
    bind = {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding",
            "metadata": {"name": read},
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": read},
            "subjects": subjects}
    return yaml_file(head, [doc, role, bind])


def kubeadm_join(model: Model, h: Host, ctx) -> str:
    join: dict = {
        "apiVersion": KUBEADM_API, "kind": "JoinConfiguration",
        "nodeRegistration": node_registration(model, h),
        "timeouts": dict(KUBEADM_TIMEOUTS),
    }
    if h.k8s == "join-control":
        join["controlPlane"] = {"localAPIEndpoint": {"advertiseAddress": node_address(h), "bindPort": API_PORT}}
    # Last, so the two run-time values continue this mapping (cluster-bootstrap.sh appends them).
    join["discovery"] = {"bootstrapToken": {"apiServerEndpoint": _api_endpoint(model)}}
    head = header(model, f"{h.name} kubeadm join ({h.k8s})", ctx) + [
        "kubeadm join --config, from a 0600 copy that cluster-bootstrap.sh makes at run time by appending",
        f"the lab's join token ({SHARED_CLUSTER}/kubeadm.env) and the pin of the cluster CA's public key",
        f"({SHARED_CLUSTER}/ca/ca.crt) to the bootstrapToken mapping that ends this file. The CA is",
        "verified, never skipped.",
    ]
    if h.k8s == "join-control":
        head.append(f"A control node joins with the cluster's shared keys copied from {SHARED_CLUSTER}/pki first.")
    return yaml_file(head, [join]) + JOIN_TAIL + "\n"


# --------------------------------------------------------------------------------------------
# kube-vip


def kube_vip(model: Model, h: Host, ctx, during_init: bool) -> str:
    k = model.k8s
    pin = _addon(model, "kube_vip")
    image = image_ref(pin.get("image") or {}, "kubernetes.kube_vip.image")
    kubeconfig = f"{KUBE_DIR}/super-admin.conf" if during_init else f"{KUBE_DIR}/admin.conf"
    env = [
        {"name": "vip_arp", "value": "true"},
        {"name": "port", "value": str(API_PORT)},
        {"name": "vip_nodename", "valueFrom": {"fieldRef": {"fieldPath": "spec.nodeName"}}},
        {"name": "vip_interface", "value": bond_name(h)},
        {"name": "vip_subnet", "value": "32"},
        {"name": "address", "value": k.api_vip},
        {"name": "cp_enable", "value": "true"},
        {"name": "cp_namespace", "value": SYSTEM_NS},
        {"name": "svc_enable", "value": "false"},
        {"name": "vip_leaderelection", "value": "true"},
        {"name": "vip_leasename", "value": KUBE_VIP_LEASE},
    ] + [{"name": n, "value": v} for n, v in KUBE_VIP_TIMING.items()]
    pod = {
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": "kube-vip", "namespace": SYSTEM_NS, "labels": {"app.kubernetes.io/name": "kube-vip"}},
        "spec": {
            "hostNetwork": True,
            "priorityClassName": "system-node-critical",
            # kube-vip calls the API as kubernetes:6443, which this alias sends to this node's own
            # API server: its leader election never waits on the VIP it holds.
            "hostAliases": [{"ip": "127.0.0.1", "hostnames": ["kubernetes"]}],
            "containers": [{
                "name": "kube-vip",
                "image": image,
                "imagePullPolicy": "IfNotPresent",
                "args": ["manager"],
                "env": env,
                "securityContext": {"capabilities": {"drop": ["ALL"], "add": ["NET_ADMIN", "NET_RAW"]}},
                "resources": {"requests": {"cpu": "50m", "memory": "64Mi"}, "limits": {"memory": "256Mi"}},
                "volumeMounts": [{"name": "kubeconfig", "mountPath": f"{KUBE_DIR}/admin.conf", "readOnly": True}],
            }],
            "volumes": [{"name": "kubeconfig", "hostPath": {"path": kubeconfig, "type": "File"}}],
        },
    }
    what = "kube-vip during kubeadm init" if during_init else "kube-vip"
    head = header(model, f"{h.name} {what}", ctx) + [
        f"The static pod that holds the API VIP {k.api_vip} on {bond_name(h)} by ARP, the lease {SYSTEM_NS}/{KUBE_VIP_LEASE}",
        "deciding which control node answers. It calls the API on this node through the host alias below.",
    ]
    if during_init:
        head.append("During kubeadm init only super-admin.conf can write the lease; cluster-bootstrap.sh moves the pod")
        head.append("to admin.conf (kube-vip.yaml) as soon as init has bound admin.conf's group to cluster-admin.")
    return yaml_file(head, [pod])


# --------------------------------------------------------------------------------------------
# Cilium


def cilium_values_doc(model: Model, idle_s: int | None = None) -> dict:
    """The Cilium release's values. idle_s, when given, sets Envoy's stream idle timeout as the
    spec's k8s.envoy_stream_idle_s would (chapter 7's idle-timeout drill applies it, then puts the
    rendered values back)."""
    k = model.k8s
    ks = _kspec(model)
    pins = _addon(model, "cilium")
    imgs = pins.get("images") or {}
    devices = list(ks.get("cilium_devices") or [])
    if not devices:
        raise RenderError("spec k8s.cilium_devices names no device for Cilium's datapath")
    v: dict = {
        # The API through the VIP: there is no kube-proxy to reach the kubernetes Service with.
        "k8sServiceHost": k.api_vip,
        "k8sServicePort": API_PORT,
        "kubeProxyReplacement": True,
        "devices": devices,
        "routingMode": "tunnel",
        "tunnelProtocol": CILIUM_TUNNEL,
        "ipam": {"mode": "cluster-pool",
                 "operator": {"clusterPoolIPv4PodCIDRList": [k.pod_cidr], "clusterPoolIPv4MaskSize": CILIUM_POD_MASK}},
        "bpf": {"masquerade": False, "hostLegacyRouting": True},
        # Multus (the rail networks, from chapter 5) chains its own configurations beside Cilium's.
        "cni": {"exclusive": False},
        "l2announcements": dict({"enabled": True}, **lease_values(model)),
        # Lease renewals for every announced Service ride on the agents' API client.
        "k8sClientRateLimit": dict(CILIUM_CLIENT_RATE),
        # The class always: the CRDs are in before the chart, and a missing one should fail the install.
        "gatewayAPI": {"enabled": True, "gatewayClass": {"create": "true"}},
        "envoy": {"enabled": True, "image": {"override": image_ref(imgs.get("envoy"), "kubernetes.cilium.images.envoy")}},
        "operator": {"replicas": 2, "image": {"override": image_ref(imgs.get("operator"), "kubernetes.cilium.images.operator")}},
        "hubble": {"enabled": True, "relay": {"enabled": False}, "ui": {"enabled": False}},
        "image": {"override": image_ref(imgs.get("agent"), "kubernetes.cilium.images.agent")},
    }
    pe = ks.get("pod_encryption")
    if pe:
        if pe != "wireguard":
            raise RenderError(f"spec k8s.pod_encryption {pe!r}: only wireguard (Cilium's transparent encryption)")
        # Pod traffic between nodes through each node's WireGuard tunnel (build A revision 2); traffic
        # between two pods of one node stays on the node, unencrypted, and the rails are outside Cilium.
        v["encryption"] = {"enabled": True, "type": "wireguard"}
    vb = [int(x) for x in ks.get("cilium_vlan_bypass") or []]
    if vb:
        # Cilium drops VLAN-tagged frames on its devices unless the VLAN is listed (seen on 1.19.7)
        v["bpf"]["vlanBypass"] = vb
    idle = idle_s if idle_s is not None else ks.get("envoy_stream_idle_s")
    if idle:
        # Both keys (FRAMEWORK 6.4): Envoy's own (cilium-config http-stream-idle-timeout, which the
        # agents read) and the one the operator writes into each Gateway's listeners
        # (proxy-stream-idle-timeout-seconds); the first alone left the listeners at their default.
        v["envoy"]["streamIdleTimeoutDurationSeconds"] = int(idle)
        v["extraConfig"] = {"proxy-stream-idle-timeout-seconds": str(int(idle))}
    return v


def cilium_values(model: Model, ctx) -> str:
    v = cilium_values_doc(model)
    idle = _kspec(model).get("envoy_stream_idle_s")
    chart = chart_pin(model, "cilium")
    head = header(model, "Cilium values", ctx) + [
        f"helm upgrade --install {CILIUM_RELEASE} {chart_oci(model, chart['name'])} --version {chart['version']} -n {SYSTEM_NS},",
        "run by cluster-bootstrap.sh on the init node after the Gateway API CRDs. The finish stage compares",
        "devices with the running cilium-config and every agent's start time (the agents read it only at start).",
        "Every image is pinned by digest (spec/versions.yaml); the in-lab registry serves them.",
    ]
    if not idle:
        head.append("Envoy's stream idle timeout stays at the chart's default here (chapter 7 records it before raising it).")
    return yaml_file(head, [v])


# --------------------------------------------------------------------------------------------
# cert-manager, the issuer and the listener certificate


def cert_manager_values(model: Model, ctx) -> str:
    pins = _addon(model, "cert_manager")
    imgs = pins.get("images") or {}
    v: dict = {"crds": {"enabled": True, "keep": True}}
    v["image"] = image_parts(imgs.get("controller"), "kubernetes.cert_manager.images.controller")
    for key in CERT_MANAGER_IMAGES[1:]:
        v[key] = {"image": image_parts(imgs.get(key), f"kubernetes.cert_manager.images.{key}")}
    chart = chart_pin(model, "cert_manager")
    head = header(model, "cert-manager values", ctx) + [
        f"helm upgrade --install {CERT_MANAGER_RELEASE} {chart_oci(model, chart['name'])} --version {chart['version']}"
        f" -n {CERT_MANAGER_NS}, from the bastion (charts.list).",
        "Every image is pinned by digest; the ACME solver's is named for completeness and never pulled.",
    ]
    return yaml_file(head, [v])


def ca_settings(model: Model) -> dict:
    return dict((model.spec or {}).get("ca") or {})


def issuer(model: Model) -> dict:
    """{name, intermediate, secret, namespace} of cert-manager's CA ClusterIssuer."""
    i = ca_settings(model).get("issuer") or {}
    if not i.get("name") or not i.get("intermediate"):
        raise RenderError("spec ca.issuer needs a name and an intermediate")
    names = [x.name for x in (model.ca.intermediates if model.ca else ())]
    if i["intermediate"] not in names:
        raise RenderError(f"spec ca.issuer.intermediate {i['intermediate']!r} is not one of the intermediates {names}")
    return {"name": str(i["name"]), "intermediate": str(i["intermediate"]), "secret": str(i["name"]), "namespace": CERT_MANAGER_NS}


def certificates(model: Model) -> list:
    """The certificates cert-manager issues for the Gateways, in spec order, each with its
    namespace and FQDNs; every name must sit inside the issuer's constraints."""
    from .ca import permits, san  # noqa: PLC0415

    iss = issuer(model)
    inter = next(x for x in model.ca.intermediates if x.name == iss["intermediate"])
    out = []
    for c in ca_settings(model).get("certificates") or []:
        for f in ("id", "secret", "dns"):
            if not c.get(f):
                raise RenderError(f"spec ca.certificates entry {c!r} needs {f}")
        gw = c.get("gateway")
        if gw is not None and str(gw) not in model.gateways:
            # a Gateway this state does not hold (the internet Gateway before state many) gets none
            continue
        dns = [_fqdn(model, str(d)) for d in c["dns"]]
        for d in dns:
            if not permits(inter, san(d)):
                raise RenderError(f"certificate {c['id']}: {d} is outside the {inter.name} CA's name constraints")
        out.append({"id": str(c["id"]), "secret": str(c["secret"]), "namespace": gateway_namespace(model), "dns": dns,
                    "gateway": str(gw) if gw is not None else None,
                    "duration": f"{int(c.get('duration_h') or 2160)}h", "renew_before": f"{int(c.get('renew_before_h') or 360)}h"})
    secrets = [c["secret"] for c in out]
    if len(set(secrets)) != len(secrets):
        raise RenderError(f"spec ca.certificates: two certificates share a Secret ({secrets})")
    return out


def pki(model: Model, ctx) -> str:
    iss = issuer(model)
    docs: list = [{
        "apiVersion": "cert-manager.io/v1", "kind": "ClusterIssuer",
        "metadata": {"name": iss["name"]},
        "spec": {"ca": {"secretName": iss["secret"]}},
    }]
    for c in certificates(model):
        docs.append({
            "apiVersion": "cert-manager.io/v1", "kind": "Certificate",
            "metadata": {"name": c["id"], "namespace": c["namespace"]},
            "spec": {
                "secretName": c["secret"],
                "dnsNames": c["dns"],
                "duration": c["duration"],
                "renewBefore": c["renew_before"],
                "privateKey": dict(CERT_KEY),
                "usages": ["digital signature", "server auth"],
                "issuerRef": {"group": "cert-manager.io", "kind": "ClusterIssuer", "name": iss["name"]},
            },
        })
    head = header(model, "PKI", ctx) + [
        f"cert-manager's CA ClusterIssuer {iss['name']} signs with the lab's {iss['intermediate']} intermediate: its key pair is",
        f"the Secret {iss['namespace']}/{iss['secret']}, which the bastion writes with sfab-ca k8s-secret (ca-secrets.list),",
        "its tls.crt the chain to the lab root. The Gateways' listener certificates come from it, each with its own key.",
    ]
    return yaml_file(head, docs)


# --------------------------------------------------------------------------------------------
# Gateways, pools and the announcement policy


def gateway_namespace(model: Model) -> str:
    return str(_kspec(model).get("gateway_namespace") or "gateways")


def listener(model: Model, gw: str | None = None) -> dict:
    """The one HTTPS listener: its name, port and hostname, and with gw that Gateway's certificate
    Secret. k8s.listener.certificate is a ca.certificates id that every Gateway shares, or
    'gateway': each Gateway's own certificate, the entry whose gateway: names it."""
    ls = _kspec(model).get("listener") or {}
    port = int(ls.get("port") or 443)
    host = _fqdn(model, str(ls.get("hostname") or "wildcard"))
    out = {"name": "https", "port": port, "hostname": host}
    if gw is None:
        return out
    cert_id = str(ls.get("certificate") or "wildcard")
    certs = certificates(model)
    if cert_id == "gateway":
        c = next((x for x in certs if x.get("gateway") == gw), None)
        if c is None:
            raise RenderError(f"Gateway {gw}: no ca.certificates entry names it (gateway: {gw}), and k8s.listener.certificate is 'gateway'")
    else:
        c = next((x for x in certs if x["id"] == cert_id), None)
        if c is None:
            raise RenderError(f"spec k8s.listener.certificate {cert_id!r} is not one of ca.certificates {sorted(x['id'] for x in certs)}")
    if host not in c["dns"]:
        raise RenderError(f"the listener hostname {host} is not a name of certificate {c['id']} ({c['dns']})")
    return dict(out, secret=c["secret"], certificate=c["id"])


def per_gateway_certificates(model: Model) -> bool:
    return str((_kspec(model).get("listener") or {}).get("certificate") or "") == "gateway"


def gateway_service(g) -> str:
    """The LoadBalancer Service Cilium makes for a Gateway."""
    return f"cilium-gateway-{g.name}"


def l2_lease(model: Model, g) -> str:
    """The lease of a Service's L2 announcement: cilium-l2announce-<namespace>-<service>."""
    return f"cilium-l2announce-{gateway_namespace(model)}-{gateway_service(g)}"


def gateway_names(model: Model) -> dict:
    """{gateway: {vip, service, lease, cec}}: the Service Cilium makes for each Gateway, the lease of
    its L2 announcement, and the CiliumEnvoyConfig its operator writes for the Gateway's listener."""
    ns = gateway_namespace(model)
    return {g.name: {"vip": g.vip, "service": f"{ns}/{gateway_service(g)}", "lease": f"{SYSTEM_NS}/{l2_lease(model, g)}",
                     "cec": f"{ns}/{gateway_service(g)}"} for g in model.gateways.values()}


def _pool_labels(model: Model, g) -> dict:
    out = {model.k8s.labels["pool"]: g.name}
    if "audience" in model.k8s.labels and g.audience:
        out[model.k8s.labels["audience"]] = g.audience
    return out


def route_label_prefix(model: Model) -> str | None:
    p = (_kspec(model).get("allowed_routes") or {}).get("label_prefix")
    return str(p) if p else None


def routes_restricted(model: Model) -> bool:
    """Whether each Gateway admits routes only from the namespaces labelled for it: with serving on
    (the API gateway's namespace and the recipe's attach routes beside the test backend's) and the
    spec's k8s.allowed_routes. Without serving every Gateway admits All, as recorded before."""
    from . import inference  # noqa: PLC0415

    return bool(route_label_prefix(model)) and inference.enabled(model)


def route_label(model: Model, gw: str) -> str:
    """The namespace label key a Gateway's listener selects: <prefix>.<label domain>/<gateway>."""
    key = f"{route_label_prefix(model)}.{model.org.label_domain}/{gw}"
    head, _, name = key.partition("/")
    if len(name) > 63 or len(head) > 253:
        raise RenderError(f"the route label {key} is too long for a label key")
    return key


def route_namespaces(model: Model) -> dict:
    """{gateway: the namespaces whose routes the render attaches to it, sorted}: the test backend's
    for its Gateways, and with serving on the recipe's for its route's Gateway and the API
    gateway's for every Gateway with a model route."""
    out: dict = {g: set() for g in model.gateways}
    tb = test_backend_settings(model)
    if tb:
        for g in tb["gateways"]:
            out[g].add(str(tb["namespace"]))
    if serving_enabled(model):
        from . import inference  # noqa: PLC0415

        s = serving_settings(model)
        if s["route"]["gateway"] in out:
            out[s["route"]["gateway"]].add(str(s["namespace"]))
        if inference.enabled(model):
            inf = inference.settings(model)
            for rt in inf["routes"]:
                out[rt["gateway"]].add(inf["namespace"])
        from . import identity  # noqa: PLC0415

        if identity.enabled(model):
            idp = identity.settings(model)
            for g in idp["gateways"]:
                out[g].add(idp["namespace"])
    return {g: sorted(v) for g, v in out.items()}


def namespace_route_labels(model: Model, ns: str) -> dict:
    """The route labels namespace ns carries: one per Gateway it attaches routes to, when the
    Gateways admit labelled namespaces only; else none."""
    if not routes_restricted(model):
        return {}
    return {route_label(model, g): "true" for g, nss in sorted(route_namespaces(model).items()) if ns in nss}


def allowed_routes(model: Model, g) -> dict:
    if routes_restricted(model):
        return {"namespaces": {"from": "Selector", "selector": {"matchLabels": {route_label(model, g.name): "true"}}},
                "kinds": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute"}]}
    return {"namespaces": {"from": "All"}}


def gateways(model: Model, ctx) -> str:
    ls = listener(model)
    ns = gateway_namespace(model)
    docs = []
    for g in model.gateways.values():
        gls = listener(model, g.name)
        labels = {}
        if "audience" in model.k8s.labels and g.audience:
            labels[model.k8s.labels["audience"]] = g.audience
        labels.update(_decision(model, g.decision))
        docs.append({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "Gateway",
            "metadata": {"name": g.name, "namespace": ns, "labels": labels},
            "spec": {
                "gatewayClassName": model.k8s.gateway_class,
                "addresses": [{"type": "IPAddress", "value": g.vip}],
                # Cilium copies these onto the Gateway's Service: the pool and the announcement
                # policy select it by them.
                "infrastructure": {"labels": _pool_labels(model, g)},
                "listeners": [{
                    "name": ls["name"], "protocol": "HTTPS", "port": ls["port"], "hostname": ls["hostname"],
                    "tls": {"mode": "Terminate", "certificateRefs": [{"group": "", "kind": "Secret", "name": gls["secret"]}]},
                    "allowedRoutes": allowed_routes(model, g),
                }],
            },
        })
    secrets = ", ".join(f"{g} {listener(model, g)['secret']}" for g in model.gateways)
    head = header(model, "Gateways", ctx) + [
        f"One Gateway per spec Gateway, class {model.k8s.gateway_class}, its VIP as its address. The one HTTPS listener",
        f"answers {ls['hostname']} with the Gateway's certificate ({secrets}), so a hostname a Gateway has no route for",
        "reaches the Gateway and is answered 404 there, rather than refused in TLS.",
    ]
    if per_gateway_certificates(model):
        head.append("Each Gateway's certificate has a key of its own: the users' Gateway's proxy holds no key the internal Gateway uses.")
    if routes_restricted(model):
        rn = route_namespaces(model)
        head.append("Each listener admits HTTPRoutes only from the namespaces labelled for its Gateway: "
                    + "; ".join(f"{route_label(model, g)} on {', '.join(rn[g]) or 'none'}" for g in sorted(rn)) + ".")
    return yaml_file(head, docs)


def lb_pools(model: Model, ctx) -> str:
    docs = []
    for g in model.gateways.values():
        docs.append({
            "apiVersion": "cilium.io/v2", "kind": "CiliumLoadBalancerIPPool",
            "metadata": {"name": g.name, "labels": _decision(model, g.decision)},
            "spec": {
                "blocks": [{"start": g.pool_start, "stop": g.pool_end}],
                "serviceSelector": {"matchLabels": {model.k8s.labels["pool"]: g.name}},
            },
        })
    head = header(model, "load balancer pools", ctx) + [
        "One pool per Gateway, its VIP's range in the data VLAN, for the Service that carries the Gateway's pool label.",
    ]
    return yaml_file(head, docs)


def l2_nodes_selector(model: Model) -> dict:
    who = str(model.k8s.l2_announce.get("nodes") or "control")
    if who not in model.k8s.labels:
        raise RenderError(f"spec k8s.l2_announce.nodes {who!r} is not a label role ({sorted(model.k8s.labels)})")
    return {"matchExpressions": [{"key": model.k8s.labels[who], "operator": "Exists"}]}


# The one policy for every Gateway (chapters 1 to 7), and the name of each audience's policy when the
# spec's k8s.l2_announce.policies says per-audience (chapter 8 on).
L2_POLICY = "gateways"
L2_POLICY_MODES = ("single", "per-audience")
# Cilium's lease timers (the release's l2announcements values) as the spec's k8s.l2_announce.lease
# names them, and Cilium 1.19's defaults, which a lab without tuned timers keeps.
L2_LEASE_KEYS = {"duration": "leaseDuration", "renew_deadline": "leaseRenewDeadline", "retry_period": "leaseRetryPeriod"}
L2_LEASE_DEFAULTS = {"duration": "15s", "renew_deadline": "5s", "retry_period": "2s"}
_DURATION = re.compile(r"^([0-9]+)(ms|s)$")


def _duration_ms(v: str, where: str) -> int:
    m = _DURATION.match(str(v))
    if not m:
        raise RenderError(f"{where}: {v!r} is not a duration in ms or s (for example 3s, 200ms)")
    return int(m.group(1)) * (1 if m.group(2) == "ms" else 1000)


def lease_timers(model: Model) -> dict | None:
    """The tuned lease timers, {duration, renew_deadline, retry_period} as written, when the spec's
    k8s.l2_announce.lease says tuned: true; None keeps Cilium's defaults. The renew deadline must
    be shorter than the duration, and the retry period shorter than the renew deadline."""
    le = model.k8s.l2_announce.get("lease")
    if not le:
        return None
    if not isinstance(le, dict) or set(le) - {"tuned", *L2_LEASE_KEYS, "since"}:
        raise RenderError(f"spec k8s.l2_announce.lease: tuned and {', '.join(L2_LEASE_KEYS)} only")
    if not le.get("tuned"):
        return None
    out = {}
    for k in L2_LEASE_KEYS:
        if not le.get(k):
            raise RenderError(f"spec k8s.l2_announce.lease: tuned timers need {k}")
        out[k] = str(le[k])
    d, r, t = (_duration_ms(out[k], f"spec k8s.l2_announce.lease.{k}") for k in L2_LEASE_KEYS)
    if not (t < r < d):
        raise RenderError("spec k8s.l2_announce.lease: want retry_period < renew_deadline < duration")
    return out


def lease_values(model: Model) -> dict:
    """The tuned timers as the Cilium release's l2announcements values, or nothing."""
    le = lease_timers(model)
    return {L2_LEASE_KEYS[k]: v for k, v in le.items()} if le else {}


def lease_summary(model: Model) -> dict:
    """The timers the agents run with, the renew rate the Gateway Services ask of the agents' client
    (Cilium's sizing: QPS = Services x 1 / renew deadline) and the failover window Cilium's page
    gives (duration - renew deadline to duration + renew deadline), for the audit and the chapter."""
    le = lease_timers(model)
    t = dict(le) if le else dict(L2_LEASE_DEFAULTS)
    d, r = _duration_ms(t["duration"], "lease"), _duration_ms(t["renew_deadline"], "lease")
    n = len(model.gateways)
    return {"tuned": bool(le), **t, "services": n, "renew_qps": round(n * 1000 / r, 3),
            "client_qps": CILIUM_CLIENT_RATE["qps"], "failover_ms": [d - r, d + r]}


def l2_policy_mode(model: Model) -> str:
    po = model.k8s.l2_announce.get("policies")
    if not po:
        return "single"
    mode = str(po.get("mode") if isinstance(po, dict) else po)
    if mode not in L2_POLICY_MODES:
        raise RenderError(f"spec k8s.l2_announce.policies.mode {mode!r} is not one of {', '.join(L2_POLICY_MODES)}")
    return mode


def l2_policies(model: Model) -> dict:
    """{gateway: the name of the CiliumL2AnnouncementPolicy that announces its VIP}: gateways for
    every one, or gateways-<audience> per audience."""
    if l2_policy_mode(model) == "single":
        return {g.name: L2_POLICY for g in model.gateways.values()}
    out = {}
    for g in model.gateways.values():
        if not g.audience:
            raise RenderError(f"gateway {g.name}: a policy per audience needs the Gateway's audience")
        out[g.name] = f"{L2_POLICY}-{g.audience}"
    if len(set(out.values())) != len(out):
        raise RenderError("spec k8s.l2_announce.policies per-audience: two Gateways share an audience")
    return out


def l2_policy_doc(model: Model, name: str, selector: dict, interfaces: list | None = None) -> dict:
    ifaces = list(interfaces if interfaces is not None else model.k8s.l2_announce.get("interfaces") or [])
    return {
        "apiVersion": "cilium.io/v2alpha1", "kind": "CiliumL2AnnouncementPolicy",
        "metadata": {"name": name},
        "spec": {
            "serviceSelector": selector,
            "nodeSelector": l2_nodes_selector(model),
            "interfaces": ifaces,
            "loadBalancerIPs": True,
            "externalIPs": False,
        },
    }


def l2_policy_docs(model: Model) -> list:
    """The policies in Gateway order: one selecting every Gateway's Service by its pool label, or
    one per audience selecting its own Gateway's Service by the audience label (Cilium copies each
    Gateway's infrastructure labels onto the Service it makes, as it does the pool label)."""
    if l2_policy_mode(model) == "single":
        names = [g.name for g in model.gateways.values()]
        return [l2_policy_doc(model, L2_POLICY, {"matchExpressions": [{"key": model.k8s.labels["pool"], "operator": "In", "values": names}]})]
    if "audience" not in model.k8s.labels:
        raise RenderError("spec k8s.labels needs audience for a policy per audience")
    pol = l2_policies(model)
    return [l2_policy_doc(model, pol[g.name], {"matchLabels": {model.k8s.labels["audience"]: g.audience}})
            for g in model.gateways.values()]


def l2_policy(model: Model, ctx) -> str:
    ifaces = list(model.k8s.l2_announce.get("interfaces") or [])
    if not ifaces:
        raise RenderError("spec k8s.l2_announce.interfaces is empty")
    docs = l2_policy_docs(model)
    who = model.k8s.labels[str(model.k8s.l2_announce.get('nodes') or 'control')]
    if l2_policy_mode(model) == "single":
        head = header(model, "L2 announcement policy", ctx) + [
            f"The Gateway Services' VIPs answered by ARP on {', '.join(ifaces)}, from the nodes labelled",
            f"{who}; one lease per Service decides which node answers.",
        ]
    else:
        pol = l2_policies(model)
        head = header(model, "L2 announcement policies", ctx) + [
            f"One policy per audience ({', '.join(f'{pol[g.name]} for {g.name}' for g in model.gateways.values())}), each",
            f"selecting its own Gateway's Service by the label {model.k8s.labels['audience']}: the VIP answered by ARP on",
            f"{', '.join(ifaces)}, from the nodes labelled {who}; one lease per Service decides which node answers.",
        ]
    le = lease_timers(model)
    if le:
        head.append(f"The leases run on tuned timers (cilium-config, 20-cilium-values.yaml): duration {le['duration']}, renew "
                    f"deadline {le['renew_deadline']}, retry period {le['retry_period']}.")
    return yaml_file(head, docs)


# --------------------------------------------------------------------------------------------
# the test backend


def test_backend_settings(model: Model) -> dict | None:
    tb = (model.spec or {}).get("test_backend")
    if not tb:
        return None
    tb = dict(tb)
    for f in ("name", "namespace", "image", "port", "path", "gateways"):
        if not tb.get(f):
            raise RenderError(f"spec test_backend needs {f}")
    gws = [g for g in tb["gateways"] if g in model.gateways]
    tb["gateways"] = gws
    return tb


def test_backend_image(model: Model, key: str) -> str:
    k = _versions(model).get(key)
    if isinstance(k, dict) and isinstance(k.get("image"), dict):
        return image_ref(k["image"], f"kubernetes.{key}.image")
    top = ((model.meta.versions or {}).get("images") or {}).get(key)
    if isinstance(top, dict):
        return image_ref(top, f"images.{key}")
    raise RenderError(f"spec/versions.yaml pins no image {key} for the test backend (kubernetes.{key}.image)")


def route_name(tb: dict, gw: str) -> str:
    return f"{tb['name']}-{gw}"


def test_backend(model: Model, ctx) -> str:
    tb = test_backend_settings(model)
    docs = test_backend_docs(model)
    args = [str(a) for a in tb.get("args") or []]
    head = header(model, "test backend", ctx) + [
        f"A plain HTTP server behind the Gateways, before any model is served: agnhost {' '.join(args)},",
        f"whose {tb['path']}?msg=<text> answers <text>. One HTTPRoute per Gateway lists that Gateway's own hostnames,",
        "so a name sent to a Gateway that does not carry it matches no route and gets the Gateway's 404.",
    ]
    return yaml_file(head, docs)


def test_backend_docs(model: Model) -> list:
    """The test backend's Deployment, Service and one HTTPRoute per Gateway it sits behind."""
    tb = test_backend_settings(model)
    name, ns, port = str(tb["name"]), str(tb["namespace"]), int(tb["port"])
    sel = {"app.kubernetes.io/name": name}
    container = {
        "name": name,
        "image": test_backend_image(model, str(tb["image"])),
        "args": [str(a) for a in tb.get("args") or []],
        "ports": [{"name": "http", "containerPort": port}],
        "readinessProbe": {"tcpSocket": {"port": "http"}, "periodSeconds": 5},
        "resources": TEST_BACKEND_RESOURCES,
        "securityContext": {"allowPrivilegeEscalation": False, "runAsNonRoot": True, "runAsUser": TEST_BACKEND_UID,
                            "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}},
    }
    docs: list = [
        {
            "apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": ns, "labels": dict(sel)},
            "spec": {
                "replicas": int(tb.get("replicas") or 1),
                "selector": {"matchLabels": dict(sel)},
                "template": {
                    "metadata": {"labels": dict(sel)},
                    "spec": {
                        "containers": [container],
                        "topologySpreadConstraints": [{"maxSkew": 1, "topologyKey": "kubernetes.io/hostname",
                                                       "whenUnsatisfiable": "ScheduleAnyway",
                                                       "labelSelector": {"matchLabels": dict(sel)}}],
                    },
                },
            },
        },
        {
            "apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": ns, "labels": dict(sel)},
            "spec": {"selector": dict(sel), "ports": [{"name": "http", "port": port, "targetPort": "http", "protocol": "TCP"}]},
        },
    ]
    for gname in tb["gateways"]:
        g = model.gateways[gname]
        labels = {}
        if "audience" in model.k8s.labels and g.audience:
            labels[model.k8s.labels["audience"]] = g.audience
        labels.update(_decision(model, g.decision))
        docs.append({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": route_name(tb, gname), "namespace": ns, "labels": labels},
            "spec": {
                "parentRefs": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": gname,
                                "namespace": gateway_namespace(model), "sectionName": listener(model)["name"]}],
                "hostnames": list(g.hostnames),
                "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": str(tb["path"])}}],
                           "backendRefs": [{"name": name, "port": port}]}],
            },
        })
    return docs


# --------------------------------------------------------------------------------------------
# Multus and the serving recipe's settings (labs whose features turn serving on)


def serving_enabled(model: Model) -> bool:
    return enabled(model) and bool(model.features.get("serving")) and bool((model.spec or {}).get("serving"))


def pod_image(pin: dict, where: str) -> str:
    """What a pod names for an upstream image pin: <ref>@<digest>, or <repository>@<platform_digest>
    for an image the seed copies one platform of (the mirror does not hold the index the pin names;
    helm_image() names the node's helm the same way)."""
    full = image_ref(pin, where)
    plat = (pin or {}).get("platform_digest")
    ref = full.partition("@")[0]
    one = (pin or {}).get("platforms") == "one" or ref.split("/", 1)[0] in ONE_PLATFORM_HOSTS
    if one and (pin or {}).get("platforms") != "all":
        if not plat or not _DIGEST.match(str(plat)):
            raise RenderError(f"spec/versions.yaml {where}: the seed copies one platform of it; pin its linux/amd64 "
                              "manifest as platform_digest")
        return f"{ref.rpartition(':')[0]}@{plat}"
    return full


# The quickstart manifest's daemon resources (multus-daemonset-thick.yml), and what the render puts
# in their place: the daemon serves every pod's CNI calls on its node, and the quickstart's own
# note says it leaves deployment sizing to the platform. The memory request and limit are raised and
# the CPU limit dropped, so a node starting a placement's pods at once is not held to 100m.
MULTUS_DS = "kube-multus-ds"
MULTUS_UPSTREAM_IMAGE = "ghcr.io/k8snetworkplumbingwg/multus-cni:snapshot-thick"
MULTUS_RESOURCES_UPSTREAM = (
    '          resources:\n'
    '            requests:\n'
    '              cpu: "100m"\n'
    '              memory: "50Mi"\n'
    '            limits:\n'
    '              cpu: "100m"\n'
    '              memory: "50Mi"\n')
MULTUS_RESOURCES = (
    '          resources:\n'
    '            requests:\n'
    '              cpu: "100m"\n'
    '              memory: "100Mi"\n'
    '            limits:\n'
    '              memory: "512Mi"\n')


def multus_source(model: Model, ctx) -> tuple:
    """(upstream text, pin) of the Multus thick manifest, checked against versions.yaml."""
    m = _addon(model, "multus")
    man = m.get("manifest") or {}
    if not m.get("version") or not man.get("file") or not man.get("sha256"):
        raise RenderError("spec/versions.yaml kubernetes.multus needs version and manifest.file and manifest.sha256")
    p = Path(ctx.root) / str(man["file"])
    try:
        data = p.read_bytes()
    except OSError as e:
        raise RenderError(f"the Multus manifest {man['file']}: {e}") from None
    have = hashlib.sha256(data).hexdigest()
    if have != str(man["sha256"]):
        raise RenderError(f"{man['file']} has sha256 {have}, spec/versions.yaml pins {man['sha256']}")
    return data.decode("utf-8"), {"version": str(m["version"]), "url": man.get("url"), "sha256": have,
                                  "file": str(man["file"]), "image": pod_image(m.get("image") or {}, "kubernetes.multus.image")}


def multus(model: Model, ctx) -> str:
    text, pin = multus_source(model, ctx)
    n = text.count(f"image: {MULTUS_UPSTREAM_IMAGE}\n")
    if n != 2:
        raise RenderError(f"{pin['file']}: expected the image {MULTUS_UPSTREAM_IMAGE} twice (daemon and installer), found {n}")
    if text.count(MULTUS_RESOURCES_UPSTREAM) != 1:
        raise RenderError(f"{pin['file']}: the daemon's resources are not the quickstart's; check the render's MULTUS_RESOURCES")
    text = text.replace(f"image: {MULTUS_UPSTREAM_IMAGE}\n", f"image: {pin['image']}\n").replace(MULTUS_RESOURCES_UPSTREAM, MULTUS_RESOURCES)
    head = header(model, f"Multus {pin['version']} (thick plugin)", ctx) + [
        f"The upstream deployments/multus-daemonset-thick.yml of {pin['version']}, kept as {pin['file']}",
        f"(sha256 {pin['sha256']}, spec/versions.yaml kubernetes.multus),",
        "with three changes and nothing else: both containers run the pinned image by",
        "digest instead of the quickstart's snapshot tag, the daemon's memory request is 100Mi instead of 50Mi,",
        "and its memory limit is 512Mi with no CPU limit instead of 50Mi and 100m. Multus takes Cilium's",
        "configuration as the cluster network (Cilium runs with",
        "cni.exclusive false) and adds the rail attachments a pod's networks annotation names.",
    ]
    return "".join(f"# {h}\n" for h in head) + text


def keys_image_key(spec_value) -> str:
    """The images.<key> of the key tool this state runs: serving.keys_image is that key, or a list
    of {id: <key>, when: ...} of which exactly one holds in the state (sfab/keys:3 through chapter 7,
    sfab/keys:4 from chapter 8, whose mint refuses a model outside the caller's audience)."""
    v = spec_value
    if isinstance(v, list):
        ids = [str(x.get("id") or "") for x in v if isinstance(x, dict)]
        if len(ids) != 1 or not ids[0]:
            raise RenderError(f"spec serving.keys_image: exactly one entry must hold in this state (have {ids})")
        return ids[0]
    return str(v or "")


def serving_settings(model: Model) -> dict:
    s = dict((model.spec or {}).get("serving") or {})
    for f in ("namespace", "image", "keys_image", "key", "ports", "server_args", "worker_args", "readiness", "route", "load"):
        if s.get(f) in (None, "", {}, []):
            raise RenderError(f"spec serving needs {f}")
    s["keys_image"] = keys_image_key(s["keys_image"])
    for f in ("secret", "field", "prefix"):
        if not (s["key"] or {}).get(f):
            raise RenderError(f"spec serving.key needs {f}")
    for f in ("http", "rpc", "rail_probe"):
        if not isinstance((s["ports"] or {}).get(f), int):
            raise RenderError(f"spec serving.ports.{f} must be a port number")
    for f in ("period_s", "failure_threshold", "timeout_s"):
        if not isinstance((s["readiness"] or {}).get(f), int) or s["readiness"][f] < 1:
            raise RenderError(f"spec serving.readiness.{f} must be a positive whole number")
    r = s["route"] or {}
    for f in ("gateway", "hostname", "request_s", "backend_request_s"):
        if not r.get(f):
            raise RenderError(f"spec serving.route needs {f}")
    if int(r["backend_request_s"]) > int(r["request_s"]):
        raise RenderError("spec serving.route: backend_request_s must not exceed request_s (the Gateway API requires it)")
    w = s.get("weights") or {}
    for f in ("dir", "tag", "guest"):
        if not w.get(f):
            raise RenderError(f"spec serving.weights needs {f}")
    if not re.match(r"^(/[a-z0-9]+)+$", str(w["guest"])):
        raise RenderError(f"spec serving.weights.guest {w['guest']!r} must be an absolute path of lower-case words")
    if not re.match(r"^[a-z][a-z0-9]{0,30}$", str(w["tag"])):
        raise RenderError(f"spec serving.weights.tag {w['tag']!r} must be a short lower-case word")
    return s


def weights_pin(model: Model, key: str) -> dict:
    """The pin of one model's weights (spec/versions.yaml serving.models.<key>)."""
    pin = ((((model.meta.versions or {}).get("serving") or {}).get("models") or {}).get(key)) or {}
    if not pin.get("file") or not pin.get("sha256") or not isinstance(pin.get("size"), int):
        raise RenderError(f"spec/versions.yaml serving.models.{key} needs file, sha256 and size")
    return pin


def weights_nodes(model: Model) -> list:
    """The GPU nodes of this lab that run a model server, so hold the models share (sorted)."""
    if not serving_enabled(model):
        return []
    return sorted({r.node for r in model.placement if r.role == "server" and r.node in model.nodes})


def local_image(model: Model, key: str) -> str:
    """<mirror>/<repository>:<tag> of an image this repository builds (images.<key>, mirror: local)."""
    pin = ((model.meta.versions or {}).get("images") or {}).get(key)
    if not isinstance(pin, dict) or pin.get("mirror") != "local" or not pin.get("ref"):
        raise RenderError(f"spec/versions.yaml images.{key} is not an image built here (mirror: local)")
    r = model.k8s.registry or model.registry
    if r is None:
        raise RenderError("the images built here are served by the in-lab registry, which this lab does not hold")
    return f"{r.mirror}/{pin['ref']}"


def _container(model: Model, node: str) -> str:
    return f"{model.lab}-{node}"


# The harness's kubectl wrapper, relative to the repository root.
SFAB_KUBECTL = "common/bin/sfab-kubectl"


def _render_dir(model: Model, ctx) -> str:
    """The lab's render directory (the lab, or its variant's directory) relative to the repo root."""
    import os  # noqa: PLC0415

    base = Path(ctx.labdir)
    if model.variant:
        base = base / "variants" / model.variant
    return Path(os.path.relpath(base.resolve(), Path(ctx.root).resolve())).as_posix()


# A pod's rail MAC: the guests' prefix, POD_MAC_TAG, the rail, 00 and the last octet of the pod's
# rail address. No guest's management octet is 254, so no node NIC or relay macvlan holds one; the
# CNI macvlan plugin sets it from the networks annotation (the attachment's mac capability).
POD_MAC_TAG = 0xFE


def pod_mac(model: Model, rail: int, address: str) -> str:
    prefix = str(((model.common or {}).get("guest") or {}).get("mac_prefix") or "02:5a")
    last = int(str(ipaddress.ip_interface(address).ip).split(".")[-1])
    if not 0 < rail < 256:
        raise RenderError(f"rail {rail}: a pod MAC needs a rail number below 256")
    return f"{prefix}:{POD_MAC_TAG:02x}:{rail:02x}:00:{last:02x}"


def placement(model: Model) -> list:
    """Every placement row with its rail attachment, fixed rail address and rail MAC, in spec order:
    each rail's pods take the rail's pod range from its first address, in placement order."""
    nads = {n.rail: n for n in model.k8s.nads}
    taken: dict = {}
    out = []
    for row in model.placement:
        nad = nads.get(row.rail)
        if nad is None:
            raise RenderError(f"pod {row.pod}: rail {row.rail} has no attachment")
        i = taken.get(row.rail, 0)
        taken[row.rail] = i + 1
        start, end = ipaddress.ip_address(nad.range_start), ipaddress.ip_address(nad.range_end)
        a = start + i
        if a > end:
            raise RenderError(f"rail {row.rail}: more pods than its pod range {nad.range_start}-{nad.range_end} holds")
        plen = ipaddress.ip_network(nad.prefix).prefixlen
        out.append({"pod": row.pod, "model": row.model, "copy": row.copy, "role": row.role, "index": row.index,
                    "node": row.node, "rail": row.rail, "nad": nad.name, "address": f"{a}/{plen}", "decision": row.decision or "-",
                    "mac": pod_mac(model, row.rail, f"{a}/{plen}"), "controller": row.controller or row.pod})
    return out


def _rails_used(model: Model) -> list:
    used = sorted({r["rail"] for r in placement(model)})
    return [n for n in model.k8s.nads if n.rail in used]


def serving_summary(model: Model) -> dict:
    s = serving_settings(model)
    rows = placement(model)
    gw = s["route"]["gateway"]
    if gw not in model.gateways:
        raise RenderError(f"spec serving.route.gateway {gw!r} is not a Gateway of this lab ({sorted(model.gateways)})")
    fqdn = _fqdn(model, str(s["route"]["hostname"]))
    ls = listener(model)
    if not _covered(fqdn, [d for c in certificates(model) for d in c["dns"]]):
        raise RenderError(f"the recipe's hostname {fqdn} is not a name of any listener certificate")
    pins = {}
    for mod in model.models.values():
        if not mod.weights:
            raise RenderError(f"model {mod.name}: no weights (a key of serving.models in spec/versions.yaml)")
        pins[mod.name] = weights_pin(model, str(mod.weights))
    w = s["weights"]
    client = str(s["load"]["client"])
    if client not in model.nodes:
        raise RenderError(f"spec serving.load.client {client!r} is not a node of this lab")
    pop = next((p for p in model.populations.values() if client in p.clients), None)
    if pop is None or not pop.answer_address:
        raise RenderError(f"spec serving.load.client {client}: no population of this lab answers its names")
    if not model.k8s.init:
        raise RenderError("the serving recipe runs the harness's kubectl on the init node, which this lab does not hold")
    first = next(iter(model.models))
    return {
        "namespace": str(s["namespace"]),
        "image": local_image(model, str(s["image"])),
        "keys_image": local_image(model, str(s["keys_image"])),
        "key": {"secret": str(s["key"]["secret"]), "field": str(s["key"]["field"]),
                "prefix": f"sk-{model.org.short}-{s['key']['prefix']}"},
        "ports": dict(s["ports"]),
        "server_args": [str(a) for a in s["server_args"]],
        "worker_args": [str(a) for a in s["worker_args"]],
        "readiness": dict(s["readiness"]),
        "labels": {"prefix": model.org.label_domain, "decision": model.k8s.labels.get("decision")},
        "nads": [{"name": n.name, "master": n.master, "prefix": n.prefix, "mtu": _rail_mtu(model)} for n in _rails_used(model)],
        "models": [{"name": m.name, "alias": m.name, "route_id": m.route_id, "copies": [c.name for c in m.copies],
                    "file": str(pins[m.name]["file"]), "bytes": int(pins[m.name]["size"]),
                    "spans": [c.name for c in m.copies if c.spans]}
                   for m in model.models.values()],
        # the models directory: in the checkout (dir), bound into each GPU node that runs a server,
        # exported to its guest under tag and mounted at guest, then a PersistentVolume per node
        "weights": {"dir": str(w["dir"]), "tag": str(w["tag"]), "guest": str(w["guest"]), "nodes": weights_nodes(model)},
        "placement": rows,
        "route": {"name": "serving", "gateway": gw, "namespace": gateway_namespace(model), "section": ls["name"],
                  "hostname": fqdn, "request": f"{int(s['route']['request_s'])}s",
                  "backend_request": f"{int(s['route']['backend_request_s'])}s"},
        # the harness's kubectl on the init node (common/bin/sfab-kubectl, the lab's render directory
        # relative to the repository root); serving.py resolves a relative path against that root
        "kubectl": SFAB_KUBECTL,
        "wait_daemonsets": [f"{SYSTEM_NS}/{MULTUS_DS}"],
        # the client's name is pinned to its population's answer unless the population's own
        # resolver is in the lab and the view that answers the client holds the name: build A's
        # operator resolves through ops-dns where it is in the lab (chapter 7), but the public view
        # publishes no platform name in state one, so its requests name the internal Gateway's VIP
        "load": {"client": client, "exec": f"docker exec -i {_container(model, client)}",
                 "url": f"https://{fqdn}/{first}/v1",
                 "resolve": "" if pop.resolver and pop.resolver in model.nodes and _view_answers(model, client, fqdn)
                 else f"{fqdn}:{ls['port']}:{pop.answer_address}",
                 "population": pop.name},
    }


def _view_answers(model: Model, client: str, fqdn: str) -> bool:
    """Whether the DNS view that answers the client's lookups (render/dns.py client_view) holds fqdn."""
    from .dns import client_view  # noqa: PLC0415

    n = model.nodes.get(client)
    if model.dns is None or n is None or not getattr(n, "resolver", None):
        return False
    _res, v = client_view(model, n)
    return v is not None and fqdn in model.dns.names_of(v)


def _covered(fqdn: str, names: list) -> bool:
    """Whether a certificate with these DNS names serves fqdn: the name itself, or a wildcard one
    label above it."""
    for d in names:
        if fqdn == d:
            return True
        if d.startswith("*.") and fqdn.endswith(d[1:]) and "." not in fqdn[: len(fqdn) - len(d) + 1]:
            return True
    return False


def _rail_mtu(model: Model) -> int:
    rl = (model.spec or {}).get("relay") or {}
    return int(rl.get("mtu") or ((model.spec or {}).get("guest") or {}).get("data_mtu") or 9000)


def serving_env(model: Model, ctx) -> str:
    """bootstrap/k8s/serving.env: everything serving-layer/ needs, as KEY=value lines. A table is
    numbered rows (SERVING_POD_01, ...), its row count in SERVING_PODS and its columns named in
    SERVING_POD_COLUMNS; serving-layer/serving.py reads it."""
    s = serving_summary(model)
    env: dict = {
        "SERVING_LAB": model.lab,
        "SERVING_NAMESPACE": s["namespace"],
        "SERVING_NAMESPACE_LABELS": " ".join(f"{k}={v}" for k, v in sorted(namespace_route_labels(model, s["namespace"]).items())),
        "SERVING_KUBECTL": f"{s['kubectl']} {_render_dir(model, ctx)}",
        "SERVING_WAIT_DAEMONSETS": " ".join(s["wait_daemonsets"]),
        "SERVING_IMAGE": s["image"],
        "SERVING_KEYS_IMAGE": s["keys_image"],
        "SERVING_KEY_SECRET": s["key"]["secret"],
        "SERVING_KEY_FIELD": s["key"]["field"],
        "SERVING_KEY_PREFIX": s["key"]["prefix"],
        "SERVING_LABEL_PREFIX": s["labels"]["prefix"],
        "SERVING_DECISION_LABEL": s["labels"]["decision"] or "",
        "SERVING_HTTP_PORT": s["ports"]["http"],
        "SERVING_RPC_PORT": s["ports"]["rpc"],
        "SERVING_RAIL_PROBE_PORT": s["ports"]["rail_probe"],
        "SERVING_SERVER_ARGS": " ".join(s["server_args"]),
        "SERVING_WORKER_ARGS": " ".join(s["worker_args"]),
        "SERVING_READINESS_PERIOD_S": s["readiness"]["period_s"],
        "SERVING_READINESS_FAILURES": s["readiness"]["failure_threshold"],
        "SERVING_READINESS_TIMEOUT_S": s["readiness"]["timeout_s"],
        "SERVING_NAD_COLUMNS": "name master prefix mtu",
        "SERVING_NADS": len(s["nads"]),
        "SERVING_MODELS_PATH": s["weights"]["guest"],
        "SERVING_MODEL_COLUMNS": "name alias route_id file bytes",
        "SERVING_MODELS": len(s["models"]),
        "SERVING_POD_COLUMNS": "pod model copy role index node rail nad address decision mac",
        "SERVING_PODS": len(s["placement"]),
        "SERVING_ROUTE_NAME": s["route"]["name"],
        "SERVING_ROUTE_GATEWAY": s["route"]["gateway"],
        "SERVING_ROUTE_GATEWAY_NAMESPACE": s["route"]["namespace"],
        "SERVING_ROUTE_SECTION": s["route"]["section"],
        "SERVING_ROUTE_HOSTNAME": s["route"]["hostname"],
        "SERVING_ROUTE_REQUEST_TIMEOUT": s["route"]["request"],
        "SERVING_ROUTE_BACKEND_TIMEOUT": s["route"]["backend_request"],
        "SERVING_LOAD_EXEC": s["load"]["exec"],
        "SERVING_LOAD_URL": s["load"]["url"],
        "SERVING_LOAD_RESOLVE": s["load"]["resolve"],
    }
    from . import decisions  # noqa: PLC0415

    if decisions.on(model):
        # a decisions lab (chapter 2 on): each rail attachment's annotation and the recipe's route label
        env["SERVING_NAD_DECISIONS"] = " ".join(f"{k}={v}" for k, v in decisions.nad_decisions(model).items())
        g = model.gateways[s["route"]["gateway"]]
        env["SERVING_ROUTE_DECISION"] = decisions.label_of(model, "routeset", s["route"]["name"], g.decision) or ""
    for i, n in enumerate(s["nads"], 1):
        env[f"SERVING_NAD_{i:02d}"] = f"{n['name']} {n['master']} {n['prefix']} {n['mtu']}"
    for i, m in enumerate(s["models"], 1):
        env[f"SERVING_MODEL_{i:02d}"] = f"{m['name']} {m['alias']} {m['route_id']} {m['file']} {m['bytes']}"
    for i, r in enumerate(s["placement"], 1):
        env[f"SERVING_POD_{i:02d}"] = " ".join(str(r[c]) for c in ("pod", "model", "copy", "role", "index", "node", "rail", "nad", "address",
                                                                   "decision", "mac"))
    hd = (f"# {model.lab} serving: rendered from {ctx.profile_file(model)} by render/k8s.py; edit the spec and run make render")
    return env_file(hd, env)


# --------------------------------------------------------------------------------------------
# namespaces, the CRDs and the lists


def namespaces(model: Model, ctx) -> str:
    names = [(gateway_namespace(model), {}), (CERT_MANAGER_NS, {})]
    tb = test_backend_settings(model)
    if tb:
        names.append((str(tb["namespace"]), dict({"pod-security.kubernetes.io/enforce": "restricted"},
                                                 **namespace_route_labels(model, str(tb["namespace"])))))
    seen, docs = set(), []
    for n, labels in names:
        if n in seen:
            continue
        seen.add(n)
        md: dict = {"name": n}
        if labels:
            md["labels"] = labels
        docs.append({"apiVersion": "v1", "kind": "Namespace", "metadata": md})
    head = header(model, "namespaces", ctx) + [
        f"Made first, so the lab host can write {CERT_MANAGER_NS}'s CA Secret before the chart and the certificate land.",
    ]
    return yaml_file(head, docs)


def crds(model: Model, ctx) -> str:
    text, pin = crd_source(model, ctx)
    head = header(model, f"Gateway API {pin['version']} CRDs ({pin['channel']} channel)", ctx) + [
        f"The upstream {pin['channel']}-install.yaml unchanged below this header: {pin['file']}, sha256 {pin['sha256']}",
        f"(spec/versions.yaml kubernetes.gateway_api). Applied server-side: the CRDs are too large for a client-side apply.",
    ]
    return "".join(f"# {h}\n" for h in head) + text


def charts(model: Model) -> list:
    """Every release finish installs, in order: (release, namespace, chart, version, values, phase)."""
    from .storage import csi_releases  # noqa: PLC0415

    cm = chart_pin(model, "cert_manager")
    rows = [(CERT_MANAGER_RELEASE, CERT_MANAGER_NS, cm["name"], cm["version"], FILES["cert_manager"], "k8s")]
    for r in csi_releases(model):
        rows.append((r["release"], r["namespace"], r["chart"], r["version"], r["values"], "storage"))
    return rows


def charts_list(model: Model, ctx) -> str:
    head = header(model, "charts", ctx) + [
        "<release> <namespace> <chart> <version> <values file under bootstrap/k8s/> <phase>: finish installs each from",
        "the in-lab registry's OCI charts. Cilium is not here: the init node installs it (cluster-bootstrap.sh).",
    ]
    return "".join(f"# {h}\n" for h in head) + "".join(" ".join(r) + "\n" for r in charts(model))


def apply_list(model: Model, ctx) -> str:
    head = header(model, "manifests", ctx) + [
        "Applied in this order with the harness's kubectl (kubectl apply --server-side on the init node); a file whose kinds a chart",
        "brings (cert-manager's) waits until the charts are in.",
    ]
    return "".join(f"# {h}\n" for h in head) + "".join(FILES[k] + "\n" for k in APPLY_ORDER if _wanted(model, k))


def ca_secrets_list(model: Model, ctx) -> str:
    iss = issuer(model)
    head = header(model, "CA secrets", ctx) + [
        "<intermediate> <namespace>/<secret>: sfab-ca k8s-secret <intermediate> <namespace>/<secret> on the lab host",
        f"after the namespaces exist; cert-manager's ClusterIssuer {iss['name']} reads the key pair from it.",
    ]
    return "".join(f"# {h}\n" for h in head) + f"{iss['intermediate']} {iss['namespace']}/{iss['secret']}\n"


def _wanted(model: Model, key: str) -> bool:
    if key in ("multus", "serving"):
        return serving_enabled(model)
    if key == "identity":
        from . import identity  # noqa: PLC0415

        return identity.enabled(model)
    if key == "netpol":
        from . import netpol  # noqa: PLC0415

        return netpol.enabled(model) and bool(netpol.base_docs(model))
    if key == "test_backend":
        tb = test_backend_settings(model)
        return bool(tb and tb["gateways"])
    if key in ("gateways", "pools", "l2"):
        return bool(model.gateways)
    return True


# --------------------------------------------------------------------------------------------
# cluster.env, per node


def helm_image(model: Model) -> dict:
    """{ref, name, version}: what the init node pulls and what containerd then calls it. An image
    the seed copies for one platform only (Docker Hub's) is pulled by that platform's manifest
    digest (platform_digest), since the mirror does not hold the index the pin names."""
    pin = _addon(model, "node_helm")
    img = pin.get("image") or {}
    full = image_ref(img, "kubernetes.node_helm.image")
    ref, _, digest = full.partition("@")
    repo = ref.rpartition(":")[0]
    if not pin.get("version"):
        raise RenderError("spec/versions.yaml kubernetes.node_helm needs the helm version the image carries")
    plat = img.get("platform_digest")
    if plat is not None and not _DIGEST.match(str(plat)):
        raise RenderError(f"spec/versions.yaml kubernetes.node_helm.image.platform_digest {plat!r} is not sha256:<64 hex>")
    if ONE_PLATFORM_HOSTS and repo.split("/", 1)[0] in ONE_PLATFORM_HOSTS and not plat:
        raise RenderError("spec/versions.yaml kubernetes.node_helm.image comes from a registry the seed copies one "
                          "platform from: pin its linux/amd64 manifest as platform_digest")
    if plat:
        return {"ref": f"{repo}@{plat}", "name": f"{repo}@{plat}", "version": str(pin["version"])}
    # containerd keeps an image pulled by tag and digest under its digest name.
    return {"ref": full, "name": f"{repo}@{digest}", "version": str(pin["version"])}


def cluster_env(model: Model, h: Host, ctx) -> str:
    k = model.k8s
    env = {
        "CLUSTER_NAME": model.lab,
        "CLUSTER_NODE": h.name,
        "CLUSTER_ROLE": h.k8s,
        "CLUSTER_ADDRESS": node_address(h),
        "CLUSTER_API_ENDPOINT": _api_endpoint(model),
        "CLUSTER_API_VIP": k.api_vip,
        "CLUSTER_API_PORT": API_PORT,
        "CLUSTER_INIT_NODE": k.init,
        "CLUSTER_CRI": CRI_SOCKET,
        "CLUSTER_SHARED": SHARED_CLUSTER,
        "CLUSTER_KUBEADM": NODE_FILES["kubeadm"],
        "CLUSTER_JOIN_TAIL": JOIN_TAIL if h.k8s != "init" else None,
    }
    if h.name in k.control:
        env["CLUSTER_KUBE_VIP"] = NODE_FILES["kube_vip"]
        enc = secrets_encryption(model)
        if enc:
            env["CLUSTER_ENCRYPTION_PROVIDER"] = enc["provider"]
            env["CLUSTER_ENCRYPTION_CONFIG"] = enc["config"]
            env["CLUSTER_ENCRYPTION_RESOURCES"] = ",".join(enc["resources"])
    if h.k8s == "init":
        chart = chart_pin(model, "cilium")
        helm = helm_image(model)
        _, gw = crd_source(model, ctx)
        env.update({
            "CLUSTER_KUBE_VIP_INIT": NODE_FILES["kube_vip_init"],
            "CLUSTER_CRDS": FILES["crds"],
            "CLUSTER_GATEWAY_API_VERSION": gw["version"],
            "CLUSTER_CILIUM_VALUES": FILES["cilium"],
            "CLUSTER_CILIUM_RELEASE": CILIUM_RELEASE,
            "CLUSTER_CILIUM_NAMESPACE": SYSTEM_NS,
            "CLUSTER_CILIUM_CHART": chart_oci(model, chart["name"]),
            "CLUSTER_CILIUM_VERSION": chart["version"],
            "CLUSTER_HELM_PLAIN_HTTP": "1" if registry_plain_http(model) else "0",
            "CLUSTER_HELM_CA_FILE": None if registry_plain_http(model) else REGISTRY_CA,
            "CLUSTER_HELM_IMAGE": helm["ref"],
            "CLUSTER_HELM_IMAGE_NAME": helm["name"],
            "CLUSTER_HELM_VERSION": helm["version"],
            # The API through the VIP, checked against the lab root alone (no kubeconfig leaves the node).
            "CLUSTER_CHAIN_SERVER": f"https://{k.api_vip}:{API_PORT}",
        })
    hd = (f"# {model.lab} {h.name}: rendered from {ctx.profile_file(model)} by render/k8s.py; "
          f"edit the spec and run make render")
    return env_file(hd, env)


# --------------------------------------------------------------------------------------------
# gen/k8s.json


def summary(model: Model, ctx) -> dict:
    """The cluster as names, for the audit, the trace and the inventory."""
    k = model.k8s
    ns = gateway_namespace(model)
    tb = test_backend_settings(model)
    out: dict = {
        "schema": SCHEMA,
        "lab": model.lab,
        "version": k.version,
        "admin": {"node": k.init, "kubeconfig": ADMIN_KUBECONFIG, "user_config": f"{GUEST_K8S_DIR}/{NODE_FILES['kubeadm_user']}"},
        "operators": operators(model),
        "api": {"vip": k.api_vip, "endpoint": _api_endpoint(model), "port": API_PORT,
                "kube_vip_lease": f"{SYSTEM_NS}/{KUBE_VIP_LEASE}", "init": k.init, "control": list(k.control)},
        "nodes": {h.name: {"role": h.k8s, "address": node_address(h), "labels": node_labels(model, h)} for h in k8s_hosts(model)},
        "cilium": dict({"release": CILIUM_RELEASE, "namespace": SYSTEM_NS, "version": chart_pin(model, "cilium")["version"],
                        "chart": chart_oci(model, chart_pin(model, "cilium")["name"]),
                        "devices": list(_kspec(model).get("cilium_devices") or [])},
                       **({"stream_idle_s": int(_kspec(model)["envoy_stream_idle_s"])} if _kspec(model).get("envoy_stream_idle_s") else {})),
        "gateway_api": crd_source(model, ctx)[1]["version"],
        "gateway_namespace": ns,
        "gateways": {g.name: {"vip": g.vip, "service": gateway_service(g), "pool": g.name,
                              "pool_range": [g.pool_start, g.pool_end], "l2_lease": f"{SYSTEM_NS}/{l2_lease(model, g)}",
                              "hostnames": list(g.hostnames), "audience": g.audience,
                              "listener": listener(model, g.name)} for g in model.gateways.values()},
        "l2_policy": L2_POLICY if model.gateways and l2_policy_mode(model) == "single" else None,
        "issuer": dict(issuer(model), kind="ClusterIssuer"),
        "certificates": certificates(model),
        "charts": [dict(zip(("release", "namespace", "chart", "version", "values", "phase"), r)) for r in charts(model)],
        "apply": [FILES[x] for x in APPLY_ORDER if _wanted(model, x)],
    }
    if model.gateways and l2_policy_mode(model) != "single":
        # chapter 8: a policy per audience, and the lease timers the agents run with
        pol = l2_policies(model)
        out["l2_policies"] = {"mode": l2_policy_mode(model), "by_gateway": pol}
        for g in model.gateways.values():
            out["gateways"][g.name]["l2_policy"] = pol[g.name]
    if lease_timers(model):
        out["l2_lease"] = lease_summary(model)
    enc = secrets_encryption(model)
    if enc:
        out["secrets_encryption"] = enc
    if _kspec(model).get("pod_encryption"):
        out["pod_encryption"] = str(_kspec(model)["pod_encryption"])
    edge = edge_placement(model)
    if edge:
        out["edge"] = {"nodes": [h.name for h in k8s_hosts(model) if h.group == (_kspec(model).get("edge") or {}).get("nodes")],
                       "selector": edge["nodeSelector"]}
    from . import netpol  # noqa: PLC0415

    np_ = netpol.summary(model)
    if np_:
        out["network_policy"] = np_
    if routes_restricted(model):
        # chapter 7: which namespaces each Gateway admits routes from, and the CiliumEnvoyConfig
        # Cilium's operator writes for its listener (the stream idle timeout is read there)
        rn = route_namespaces(model)
        for g in model.gateways.values():
            out["gateways"][g.name].update({"cec": f"{ns}/{gateway_service(g)}",
                                            "allowed_routes": {"from": "Selector", "label": route_label(model, g.name),
                                                               "namespaces": rn[g.name]}})
    if tb:
        out["test_backend"] = {"namespace": str(tb["namespace"]), "deployment": str(tb["name"]), "service": str(tb["name"]),
                               "port": int(tb["port"]), "path": str(tb["path"]), "replicas": int(tb.get("replicas") or 1),
                               "routes": {g: route_name(tb, g) for g in tb["gateways"]}}
    if serving_enabled(model):
        mp = multus_source(model, ctx)[1]
        out["multus"] = {"version": mp["version"], "image": mp["image"], "daemonset": f"{SYSTEM_NS}/{MULTUS_DS}",
                         "file": FILES["multus"]}
        sv = serving_summary(model)
        out["serving"] = {k: sv[k] for k in ("namespace", "image", "keys_image", "key", "ports", "readiness", "nads", "models", "weights",
                                             "placement", "route", "load")}
        out["serving"]["env"] = FILES["serving"]
        from . import inference  # noqa: PLC0415

        inf = inference.summary(model)
        if inf is not None:
            out["inference"] = inf
        from . import identity  # noqa: PLC0415

        idp = identity.summary(model)
        if idp is not None:
            out["identity"] = idp
    return out


# --------------------------------------------------------------------------------------------


def _check(model: Model) -> None:
    k = model.k8s
    if not k.init or k.init not in model.nodes:
        raise RenderError("Kubernetes needs its init node in the lab")
    hosts = {h.name: h for h in k8s_hosts(model)}
    for c in k.control:
        if c not in hosts:
            raise RenderError(f"control node {c} is not a Kubernetes node of this lab")
    for h in hosts.values():
        if h.kind != "vm-node":
            raise RenderError(f"{h.name}: only VM guests run Kubernetes")
    svc = ipaddress.ip_network(k.service_cidr)
    pods = ipaddress.ip_network(k.pod_cidr)
    if svc.overlaps(pods):
        raise RenderError(f"the pod network {pods} overlaps the service network {svc}")
    for g in model.gateways.values():
        a = ipaddress.ip_address(g.vip)
        if not (ipaddress.ip_address(g.pool_start) <= a <= ipaddress.ip_address(g.pool_end)):
            raise RenderError(f"Gateway {g.name}: its VIP {g.vip} is outside its pool {g.pool_start}-{g.pool_end}")


def render(model: Model, ctx) -> dict:
    if not enabled(model):
        return {}
    _check(model)
    k = model.k8s
    out: dict = {}
    base = "bootstrap/k8s"
    crd_text = crds(model, ctx)
    values = cilium_values(model, ctx)
    out[f"{base}/{FILES['namespaces']}"] = namespaces(model, ctx)
    out[f"{base}/{FILES['operators']}"] = operators_manifest(model, ctx)
    out[f"{base}/{FILES['crds']}"] = crd_text
    out[f"{base}/{FILES['cilium']}"] = values
    out[f"{base}/{FILES['cert_manager']}"] = cert_manager_values(model, ctx)
    out[f"{base}/{FILES['pki']}"] = pki(model, ctx)
    if model.gateways:
        out[f"{base}/{FILES['pools']}"] = lb_pools(model, ctx)
        out[f"{base}/{FILES['l2']}"] = l2_policy(model, ctx)
        out[f"{base}/{FILES['gateways']}"] = gateways(model, ctx)
    if _wanted(model, "test_backend"):
        out[f"{base}/{FILES['test_backend']}"] = test_backend(model, ctx)
    if serving_enabled(model):
        from . import identity, inference  # noqa: PLC0415

        out[f"{base}/{FILES['multus']}"] = multus(model, ctx)
        out[f"{base}/{FILES['serving']}"] = serving_env(model, ctx)
        out.update(inference.render(model, ctx))
        out.update(identity.render(model, ctx))
    from . import netpol  # noqa: PLC0415

    out.update(netpol.render(model, ctx))
    out[f"{base}/apply.list"] = apply_list(model, ctx)
    out[f"{base}/charts.list"] = charts_list(model, ctx)
    out[f"{base}/ca-secrets.list"] = ca_secrets_list(model, ctx)
    for h in k8s_hosts(model):
        nb = f"bootstrap/{h.name}/k8s"
        out[f"{nb}/{NODE_FILES['env']}"] = cluster_env(model, h, ctx)
        out[f"{nb}/{NODE_FILES['kubeadm']}"] = kubeadm_init(model, h, ctx) if h.k8s == "init" else kubeadm_join(model, h, ctx)
        if h.name in k.control:
            out[f"{nb}/{NODE_FILES['kube_vip']}"] = kube_vip(model, h, ctx, during_init=False)
        if h.k8s == "init":
            out[f"{nb}/{NODE_FILES['kube_vip_init']}"] = kube_vip(model, h, ctx, during_init=True)
            out[f"{nb}/{NODE_FILES['kubeadm_user']}"] = kubeadm_user(model, h, ctx)
            out[f"{nb}/{FILES['crds']}"] = crd_text
            out[f"{nb}/{FILES['cilium']}"] = values
    out["gen/k8s.json"] = json.dumps(summary(model, ctx), indent=2, sort_keys=True) + "\n"
    return out


__all__ = ["render", "summary", "dump", "dump_all", "scalar"]
