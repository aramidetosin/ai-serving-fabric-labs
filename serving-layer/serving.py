#!/usr/bin/env python3
"""serving.py: the model-serving recipe (serving-layer/README.md), from one serving.env.

    serving.py render --env FILE --out DIR   the manifests and the placement table, as files
    serving.py serve  --env FILE [--replace POD ...]   deploy them; a second run acts only on what changed
    serving.py move   --env FILE --pod POD --rail N --address A --master NIC [--mac M]
                                             one pod made again on another rail than its row's: the
                                             break exercise a lab's breaks/ uses (serve puts it back)
    serving.py reroute --env FILE --pod POD --nad NAME --dst CIDR --via ADDR
                                             one pod made again at its row's address and MAC, but on
                                             a copy of its rail attachment (NAME) whose static IPAM
                                             adds a route to CIDR via ADDR (serve puts it back and
                                             removes the copy)
    serving.py status --env FILE             each pod's node, rail address and readiness, each Service's endpoints
    serving.py load   --env FILE [...]       hand the key to the load client, run load.py there
    serving.py client --env FILE [...]       one chat completion from the same client with client.py,
                                             an OpenAI-compatible client given only the base URL and key
    serving.py delete --env FILE             remove the recipe's namespace

serving.env holds KEY=value lines (shell quoting), written by the labs' generator
(render/k8s.py) or by hand on another cluster (serving.env.example). A table is numbered rows,
SERVING_POD_01 and on, with its row count in SERVING_PODS and its columns in SERVING_POD_COLUMNS.

What `serve` deploys, in order, each step waiting for the last:
  1. the DaemonSets SERVING_WAIT_DAEMONSETS names rolled out (Multus, which attaches the rails);
  2. the namespace (with the labels SERVING_NAMESPACE_LABELS names: a Gateway whose listener admits
     routes only from labelled namespaces needs its label on the namespace of the recipe's route),
     one macvlan NetworkAttachmentDefinition per rail the placement uses (the rail NIC as master,
     the static IPAM plugin, no routes), the key tool's account and role, and for every node that
     runs a server a local PersistentVolume of SERVING_MODELS_PATH on that node with its claim
     (read-only: the weights are never in the image);
  3. the key: when the Secret is missing, a Job of the key tool generates it inside the cluster
     and prints only its fingerprint; the Job is then removed. An existing key is never replaced;
  4. the workers (ggml-rpc-server, bound to the pod's rail address), then the servers
     (llama-server, bound to the pod's own cluster address, --rpc to its workers' rail addresses,
     the weights read from the models PersistentVolume of its node), one StatefulSet of one pod
     per placement row (the row's pod is <controller>-0), each pinned to its node with its rail
     address and MAC fixed in its networks annotation, so a pod made again comes back with both.
     The StatefulSets update on delete: a pod whose rendered spec changed (the stamp annotation),
     or whose sandbox was made again without its rail (its network-status names another address
     than its own, as after a boot on a kept disk), is deleted once its StatefulSet holds the
     rendered template, and its controller makes it again; a StatefulSet or pod no row names is
     removed;
  5. one Service per model (both copies' servers) and one per copy, and the HTTPRoute on the one
     Gateway serving.env names, with its request timeouts;
  6. a rail attachment the table no longer uses is removed (after the pods that used it);
  7. the read-back: every Pod Running and Ready on its node with its rail address in its
     network-status annotation, and every Service's endpoints its servers' pod addresses.

--replace removes the named pods first, so serve makes them again (a server whose RPC session to a
worker that was re-created cannot come back, as after a lab's break-6a).

kubectl is SERVING_KUBECTL, split like a shell command (in the labs, common/bin/sfab-kubectl with the
lab's directory: kubectl with the cluster's admin kubeconfig on the init node, over SSH): every
manifest goes to it on stdin, and no key is ever on a command line. A relative program path that
does not exist from the current directory is taken from the repository root (serving-layer's
parent), so a lab's serving.env works whichever directory make runs in.
Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOAD_PY = HERE / "load.py"
CLIENT_PY = HERE / "client.py"

KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
# A label key (an optional DNS-subdomain prefix, a slash, a name of 63 characters at most) and value.
LABEL_KEY_RE = re.compile(r"^([a-z0-9]([-a-z0-9.]*[a-z0-9])?/)?[A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?$")
LABEL_VALUE_RE = re.compile(r"^([A-Za-z0-9]([-A-Za-z0-9_.]{0,61}[A-Za-z0-9])?)?$")
APP = "serving"
NETWORKS = "k8s.v1.cni.cncf.io/networks"
NETWORK_STATUS = "k8s.v1.cni.cncf.io/network-status"
MODELS_MOUNT = "/models"
KEY_DIR = "/secret"
UID = 65532
# Resource requests and memory limits. A server maps its model file and sends every layer to its
# workers (-ngl 99), keeping only the token embeddings: 0.3 GB resident for chat and 0.9 GB for
# staff on the lab host (2026-10-28, with --cache-ram 0 and --ctx-checkpoints 0), plus the file's
# pages it read while loading, which the kernel reclaims under the limit. A worker holds its share
# of the weights: the file's size over its copy's workers, plus WORKER_HEADROOM_MIB for the KV cache
# and the compute buffers (the workers read 4 to 196 MiB above their share on 8 slots); its limit
# leaves WORKER_LIMIT_MIB more. The requests place the pods; the limits keep one from the node.
SERVER_RESOURCES = {"requests": {"cpu": "500m", "memory": "512Mi"}, "limits": {"memory": "4Gi"}}
WORKER_CPU = "1"
WORKER_HEADROOM_MIB = 384
WORKER_LIMIT_MIB = 1536
KEYS_RESOURCES = {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "128Mi"}}
# Waits (seconds), and how often a wait reads the pods.
WAIT = {"daemonset": 600, "job": 300, "workers": 900, "servers": 1200, "delete": 120}
WAIT_POLL_S = 3.0
FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
LOAD_KEY = "/tmp/sfab-load.key"
LOAD_RECORDS = "/tmp/sfab-load-records.jsonl"
CLIENT_KEY = "/tmp/sfab-client.key"


class ServingError(Exception):
    pass


# ------------------------------------------------------------------------------------------
# serving.env


def read_env(path: Path) -> dict:
    out = {}
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ServingError(f"{path}: {e}") from None
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        k, sep, v = s.partition("=")
        if not sep or not KEY_RE.match(k):
            raise ServingError(f"{path}:{n}: expected KEY=value")
        try:
            words = shlex.split(v)
        except ValueError as e:
            raise ServingError(f"{path}:{n}: {e}") from None
        if len(words) > 1:
            raise ServingError(f"{path}:{n}: {k}'s value is more than one word; quote it")
        out[k] = words[0] if words else ""
    return out


def _need(env: dict, key: str) -> str:
    v = env.get(key, "")
    if v == "":
        raise ServingError(f"serving.env has no {key}")
    return v


def _int(env: dict, key: str) -> int:
    v = _need(env, key)
    if not v.isdigit():
        raise ServingError(f"serving.env {key}={v!r} is not a whole number")
    return int(v)


def table(env: dict, name: str) -> list:
    """The rows of SERVING_<name>_NN as dicts keyed by SERVING_<name>_COLUMNS."""
    cols = _need(env, f"SERVING_{name}_COLUMNS").split()
    n = _int(env, f"SERVING_{name}S")
    rows = []
    for i in range(1, n + 1):
        raw = env.get(f"SERVING_{name}_{i:02d}", env.get(f"SERVING_{name}_{i}", ""))
        words = raw.split()
        if len(words) != len(cols):
            raise ServingError(f"serving.env SERVING_{name}_{i:02d} has {len(words)} fields, not {len(cols)} ({' '.join(cols)})")
        rows.append(dict(zip(cols, words)))
    extra = sorted(k for k in env if re.match(rf"^SERVING_{name}_[0-9]+$", k) and int(k.rsplit("_", 1)[1]) > n)
    if extra:
        raise ServingError(f"serving.env holds {', '.join(extra)} beyond SERVING_{name}S={n}")
    return rows


@dataclass
class Settings:
    lab: str
    namespace: str
    kubectl: list
    wait_daemonsets: list
    image: str
    keys_image: str
    key_secret: str
    key_field: str
    key_prefix: str
    label_prefix: str
    decision_label: str
    http_port: int
    rpc_port: int
    rail_probe_port: int
    models_path: str
    server_args: list
    worker_args: list
    period: int
    failures: int
    timeout: int
    nads: list
    models: list
    pods: list
    route: dict
    load: dict
    copies: dict = field(default_factory=dict)   # (model, copy) -> {"server": row, "workers": [rows]}
    namespace_labels: dict = field(default_factory=dict)
    nad_decisions: dict = field(default_factory=dict)   # attachment -> the decision ids its annotation carries
    route_decision: str = ""                            # the decision id the recipe's HTTPRoute is labelled with

    def label(self, name: str) -> str:
        return f"{self.label_prefix}/{name}"


def _kubectl_argv(text: str) -> list:
    """SERVING_KUBECTL split like a shell command, a relative program path taken from the repository
    root when it is not there from the current directory."""
    argv = shlex.split(text)
    if argv and "/" in argv[0] and not os.path.isabs(argv[0]) and not os.path.exists(argv[0]):
        cand = HERE.parent / argv[0]
        if cand.exists():
            argv[0] = str(cand)
    return argv


def settings(env: dict) -> Settings:
    s = Settings(
        lab=env.get("SERVING_LAB", ""),
        namespace=_need(env, "SERVING_NAMESPACE"),
        kubectl=_kubectl_argv(_need(env, "SERVING_KUBECTL")),
        wait_daemonsets=env.get("SERVING_WAIT_DAEMONSETS", "").split(),
        image=_need(env, "SERVING_IMAGE"),
        keys_image=_need(env, "SERVING_KEYS_IMAGE"),
        key_secret=_need(env, "SERVING_KEY_SECRET"),
        key_field=_need(env, "SERVING_KEY_FIELD"),
        key_prefix=_need(env, "SERVING_KEY_PREFIX"),
        label_prefix=_need(env, "SERVING_LABEL_PREFIX"),
        decision_label=env.get("SERVING_DECISION_LABEL", ""),
        http_port=_int(env, "SERVING_HTTP_PORT"),
        rpc_port=_int(env, "SERVING_RPC_PORT"),
        rail_probe_port=_int(env, "SERVING_RAIL_PROBE_PORT"),
        models_path=_need(env, "SERVING_MODELS_PATH"),
        server_args=shlex.split(env.get("SERVING_SERVER_ARGS", "")),
        worker_args=shlex.split(env.get("SERVING_WORKER_ARGS", "")),
        period=_int(env, "SERVING_READINESS_PERIOD_S"),
        failures=_int(env, "SERVING_READINESS_FAILURES"),
        timeout=_int(env, "SERVING_READINESS_TIMEOUT_S"),
        nads=table(env, "NAD"),
        models=table(env, "MODEL"),
        pods=table(env, "POD"),
        route={"name": _need(env, "SERVING_ROUTE_NAME"), "gateway": _need(env, "SERVING_ROUTE_GATEWAY"),
               "namespace": _need(env, "SERVING_ROUTE_GATEWAY_NAMESPACE"), "section": env.get("SERVING_ROUTE_SECTION", ""),
               "hostname": _need(env, "SERVING_ROUTE_HOSTNAME"), "request": _need(env, "SERVING_ROUTE_REQUEST_TIMEOUT"),
               "backend": _need(env, "SERVING_ROUTE_BACKEND_TIMEOUT")},
        load={"exec": shlex.split(env.get("SERVING_LOAD_EXEC", "")), "url": env.get("SERVING_LOAD_URL", ""),
              "resolve": env.get("SERVING_LOAD_RESOLVE", "")},
        namespace_labels=namespace_labels(env.get("SERVING_NAMESPACE_LABELS", "")),
        nad_decisions=nad_decisions(env.get("SERVING_NAD_DECISIONS", "")),
        route_decision=env.get("SERVING_ROUTE_DECISION", ""),
    )
    check(s)
    return s


def nad_decisions(text: str) -> dict:
    """SERVING_NAD_DECISIONS (chapter 2 on): space-separated <attachment>=<id>[,<id>...] pairs, the
    decision ids each rail attachment's annotation carries."""
    out = {}
    for item in text.split():
        k, sep, v = item.partition("=")
        if not sep or not k or not all(LABEL_VALUE_RE.match(x) for x in v.split(",")):
            raise ServingError(f"SERVING_NAD_DECISIONS: {item!r} is not <attachment>=<decision id>[,<id>]")
        out[k] = v
    return out


def namespace_labels(text: str) -> dict:
    """SERVING_NAMESPACE_LABELS: space-separated key=value pairs the namespace carries."""
    out = {}
    for item in text.split():
        k, sep, v = item.partition("=")
        if not sep or not LABEL_KEY_RE.match(k) or not LABEL_VALUE_RE.match(v):
            raise ServingError(f"SERVING_NAMESPACE_LABELS: {item!r} is not a label key=value")
        out[k] = v
    return out


def _duration_s(v: str) -> int:
    m = re.match(r"^([0-9]+)(s|m|h)$", v)
    if not m:
        raise ServingError(f"timeout {v!r} is not a whole number of s, m or h")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]


def check(s: Settings) -> None:
    """Refuse a serving.env the manifests could not express or the placement rules forbid."""
    for name in [s.namespace, s.key_secret, s.route["name"], s.route["gateway"], s.route["namespace"]]:
        if not NAME_RE.match(name) or len(name) > 63:
            raise ServingError(f"{name!r} is not a Kubernetes name")
    if not s.kubectl:
        raise ServingError("SERVING_KUBECTL is empty")
    if _duration_s(s.route["backend"]) > _duration_s(s.route["request"]):
        raise ServingError("SERVING_ROUTE_BACKEND_TIMEOUT exceeds SERVING_ROUTE_REQUEST_TIMEOUT (the Gateway API requires backendRequest within request)")
    nads = {}
    for n in s.nads:
        net = ipaddress.ip_network(n["prefix"], strict=True)
        if not NAME_RE.match(n["name"]) or not n["mtu"].isdigit():
            raise ServingError(f"attachment {n}: a name and a numeric MTU are needed")
        nads[n["name"]] = (n, net)
    if not re.match(r"^(/[A-Za-z0-9._-]+)+$", s.models_path):
        raise ServingError(f"SERVING_MODELS_PATH {s.models_path!r} is not an absolute path")
    models = {m["name"]: m for m in s.models}
    for m in s.models:
        if not FILE_RE.match(m.get("file", "")) or not m.get("bytes", "").isdigit() or int(m["bytes"]) <= 0:
            raise ServingError(f"model {m['name']}: a file name (no directory) and its size in bytes are needed")
    seen_pods, seen_addr, seen_mac = set(), set(), set()
    for p in s.pods:
        for f in ("pod", "model", "copy"):
            if not NAME_RE.match(p[f]):
                raise ServingError(f"pod row {p['pod']}: {f} {p[f]!r} is not a Kubernetes name")
        if not p["pod"].endswith("-0") or not NAME_RE.match(controller(p)) or len(controller(p)) > 52:
            raise ServingError(f"pod row {p['pod']}: a row's pod is its StatefulSet's pod 0, <controller>-0")
        if p["pod"] in seen_pods:
            raise ServingError(f"pod {p['pod']} is placed twice")
        seen_pods.add(p["pod"])
        if p["model"] not in models:
            raise ServingError(f"pod {p['pod']}: model {p['model']} is not in the model table")
        if p["role"] not in ("server", "worker"):
            raise ServingError(f"pod {p['pod']}: role {p['role']} is neither server nor worker")
        if p["nad"] not in nads:
            raise ServingError(f"pod {p['pod']}: attachment {p['nad']} is not in the attachment table")
        iface = ipaddress.ip_interface(p["address"])
        if iface.network != nads[p["nad"]][1]:
            raise ServingError(f"pod {p['pod']}: {p['address']} is not on {p['nad']}'s {nads[p['nad']][1]}")
        if str(iface.ip) in seen_addr:
            raise ServingError(f"pod {p['pod']}: {iface.ip} is given twice")
        seen_addr.add(str(iface.ip))
        mac = p.get("mac")
        if mac not in (None, "", "-"):
            if not MAC_RE.match(mac) or int(mac[:2], 16) & 1:
                raise ServingError(f"pod {p['pod']}: {mac!r} is not a unicast MAC (aa:bb:cc:dd:ee:ff)")
            if mac in seen_mac:
                raise ServingError(f"pod {p['pod']}: MAC {mac} is given twice")
            seen_mac.add(mac)
        c = s.copies.setdefault((p["model"], p["copy"]), {"server": None, "workers": []})
        if p["role"] == "server":
            if c["server"] is not None:
                raise ServingError(f"copy {p['model']}-{p['copy']} has two servers")
            c["server"] = p
        else:
            c["workers"].append(p)
    for (m, cp), c in s.copies.items():
        if c["server"] is None or not c["workers"]:
            raise ServingError(f"copy {m}-{cp} needs one server and at least one worker")
        rails = {x["nad"] for x in [c["server"]] + c["workers"]}
        if len(rails) != 1:
            raise ServingError(f"copy {m}-{cp} spans the attachments {sorted(rails)}: every pod of a copy sits on one rail")
    for m in models:
        if not any(k[0] == m for k in s.copies):
            raise ServingError(f"model {m} has no copy placed")


# ------------------------------------------------------------------------------------------
# YAML: a small, deterministic writer for the subset these manifests use


_PLAIN = re.compile(r"^[A-Za-z_/][A-Za-z0-9_./@=+-]*(?::[A-Za-z0-9_./@=+-]+)*$")
_WORDS = {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~", "="}


def scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v)
    if _PLAIN.match(s) and s.lower() not in _WORDS:
        return s
    return json.dumps(s)


def _lines(obj, indent: int) -> list:
    pad = " " * indent
    out: list = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict) and v:
                out.append(f"{pad}{scalar(k)}:")
                out.extend(_lines(v, indent + 2))
            elif isinstance(v, list) and v:
                out.append(f"{pad}{scalar(k)}:")
                out.extend(_lines(v, indent))
            elif isinstance(v, (dict, list)):
                out.append(f"{pad}{scalar(k)}: {'{}' if isinstance(v, dict) else '[]'}")
            else:
                out.append(f"{pad}{scalar(k)}: {scalar(v)}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)) and item:
                sub = _lines(item, indent + 2)
                out.append(f"{pad}- {sub[0][indent + 2:]}")
                out.extend(sub[1:])
            elif isinstance(item, (dict, list)):
                out.append(f"{pad}- {'{}' if isinstance(item, dict) else '[]'}")
            else:
                out.append(f"{pad}- {scalar(item)}")
    return out


def dump_all(docs: list) -> str:
    return "---\n".join("\n".join(_lines(d, 0)) + "\n" for d in docs)


# ------------------------------------------------------------------------------------------
# The manifests


def _restricted() -> dict:
    return {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}


def _pod_security() -> dict:
    return {"runAsNonRoot": True, "runAsUser": UID, "runAsGroup": UID, "fsGroup": UID,
            "seccompProfile": {"type": "RuntimeDefault"}}


def pod_labels(s: Settings, p: dict) -> dict:
    out = {"app.kubernetes.io/name": APP, "app.kubernetes.io/component": p["role"],
           s.label("model"): p["model"], s.label("copy"): p["copy"], s.label("role"): p["role"],
           s.label("pod"): p["pod"], s.label("rail"): str(p["nad"])}
    if s.decision_label and p.get("decision", "-") != "-":
        out[s.decision_label] = p["decision"]
    return out


def rail_ip(p: dict) -> str:
    return str(ipaddress.ip_interface(p["address"]).ip)


def networks(s: Settings, p: dict) -> str:
    """The pod's networks annotation: its rail attachment, named for the rail, at its fixed address,
    and at its fixed MAC when the table gives one (the mac column)."""
    net = {"name": p["nad"], "namespace": s.namespace, "interface": p["nad"], "ips": [p["address"]]}
    if p.get("mac") not in (None, "", "-"):
        net["mac"] = p["mac"]
    return json.dumps([net], separators=(",", ":"))


def _probe(s: Settings, command: list) -> dict:
    return {"exec": {"command": command}, "periodSeconds": s.period, "failureThreshold": s.failures,
            "timeoutSeconds": s.timeout}


def controller(p: dict) -> str:
    """The row's StatefulSet: its pod's name without the ordinal (every row's pod is pod 0)."""
    return p["pod"][:-2] if p["pod"].endswith("-0") else p["pod"]


def model_of(s: Settings, name: str) -> dict:
    return next(m for m in s.models if m["name"] == name)


def worker_resources(s: Settings, p: dict) -> dict:
    """A worker's share of its copy's weights, the file's size over the copy's workers, plus the
    headroom for the KV cache and compute buffers; its limit WORKER_LIMIT_MIB above that."""
    n = max(1, len(s.copies[(p["model"], p["copy"])]["workers"]))
    mib = -(-int(model_of(s, p["model"])["bytes"]) // (n * (1 << 20))) + WORKER_HEADROOM_MIB
    return {"requests": {"cpu": WORKER_CPU, "memory": f"{mib}Mi"}, "limits": {"memory": f"{mib + WORKER_LIMIT_MIB}Mi"}}


def server_nodes(s: Settings) -> list:
    """The nodes that run a server, each of which holds the models PersistentVolume (sorted)."""
    return sorted({c["server"]["node"] for c in s.copies.values()})


def pv_name(s: Settings, node: str) -> str:
    return f"{s.namespace}-models-{node}"


def pvc_name(node: str) -> str:
    return f"models-{node}"


def worker_pod(s: Settings, p: dict) -> dict:
    ip = rail_ip(p)
    c = {
        "name": "worker",
        "image": s.image,
        "imagePullPolicy": "IfNotPresent",
        "command": ["ggml-rpc-server", "-H", ip, "-p", str(s.rpc_port)] + list(s.worker_args),
        "ports": [{"name": "rpc", "containerPort": s.rpc_port, "protocol": "TCP"}],
        "readinessProbe": _probe(s, ["sfab-ready", "worker", "--rpc-port", str(s.rpc_port), ip]),
        "resources": worker_resources(s, p),
        "securityContext": _restricted(),
    }
    return _sts(s, p, [c], [])


def server_pod(s: Settings, p: dict, workers: list) -> dict:
    ips = [rail_ip(w) for w in workers]
    m = model_of(s, p["model"])
    split = ["--tensor-split", ",".join("1" for _ in ips)] if len(ips) > 1 else []
    c = {
        "name": "server",
        "image": s.image,
        "imagePullPolicy": "IfNotPresent",
        # llama-server listens on the pod's own cluster address only (the downward API's POD_IP):
        # the Gateway's Envoy and the router reach it there, and nothing listens on the rail
        "env": [{"name": "POD_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}},
                {"name": "SFAB_READY_HOST", "value": "$(POD_IP)"}],
        "command": ["llama-server", "-m", f"{MODELS_MOUNT}/{m['file']}", "--alias", m["alias"], "--host", "$(POD_IP)",
                    "--port", str(s.http_port), "--rpc", ",".join(f"{ip}:{s.rpc_port}" for ip in ips)] + split
                   + list(s.server_args) + ["--no-ui", "--api-key-file", f"{KEY_DIR}/{s.key_field}"],
        "ports": [{"name": "http", "containerPort": s.http_port, "protocol": "TCP"}],
        # Ready only while llama-server answers its health check and every worker answers over the
        # rail: an established RPC session that is not retransmitting, and the worker's kernel
        # refusing a connection to a closed port (no RPC session is opened to check it). A filter
        # on the rail must REJECT that port with a reset, never DROP it, or every copy goes unready.
        "readinessProbe": _probe(s, ["sfab-ready", "server", "--port", str(s.http_port), "--rpc-port", str(s.rpc_port),
                                     "--probe-port", str(s.rail_probe_port)] + ips),
        "resources": SERVER_RESOURCES,
        "securityContext": _restricted(),
        "volumeMounts": [{"name": "key", "mountPath": KEY_DIR, "readOnly": True},
                         {"name": "models", "mountPath": MODELS_MOUNT, "readOnly": True}],
    }
    vols = [{"name": "key", "secret": {"secretName": s.key_secret, "defaultMode": 0o440,
                                        "items": [{"key": s.key_field, "path": s.key_field}]}},
            {"name": "models", "persistentVolumeClaim": {"claimName": pvc_name(p["node"]), "readOnly": True}}]
    return _sts(s, p, [c], vols)


def _sts(s: Settings, p: dict, containers: list, volumes: list) -> dict:
    """One placement row as a StatefulSet of one pod: its template pinned to the row's node, with
    the row's rail attachment, address and MAC in its networks annotation and the stamp of the
    template as rendered; updates on delete, so serve decides when a pod is made again."""
    spec = {
        "nodeSelector": {"kubernetes.io/hostname": p["node"]},
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 2,
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "securityContext": _pod_security(),
        "containers": containers,
    }
    if volumes:
        spec["volumes"] = volumes
    labels = pod_labels(s, p)
    tmpl = {"metadata": {"labels": labels, "annotations": {NETWORKS: networks(s, p)}}, "spec": spec}
    tmpl["metadata"]["annotations"][s.label("spec")] = stamp(tmpl)
    name = controller(p)
    return {"apiVersion": "apps/v1", "kind": "StatefulSet",
            "metadata": {"name": name, "namespace": s.namespace, "labels": dict(labels)},
            "spec": {"replicas": 1, "serviceName": name, "podManagementPolicy": "Parallel",
                     "updateStrategy": {"type": "OnDelete"},
                     "selector": {"matchLabels": {"app.kubernetes.io/name": APP, s.label("pod"): p["pod"]}},
                     "template": tmpl}}


def template_stamp(s: Settings, doc: dict) -> str:
    """The stamp of a rendered StatefulSet's pod template."""
    return doc["spec"]["template"]["metadata"]["annotations"][s.label("spec")]


def stamp(doc: dict) -> str:
    """The first 16 hex digits of the sha256 of a pod template as rendered (before the stamp is
    added): a running pod whose stamp differs is made again, since most of a pod's spec cannot
    change."""
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def models_docs(s: Settings) -> list:
    """For each node that runs a server: a local PersistentVolume of the models path on that node,
    read-only, claimed ahead by its PersistentVolumeClaim in the namespace."""
    size = f"{-(-sum(int(m['bytes']) for m in s.models) // (1 << 30))}Gi"
    labels = {"app.kubernetes.io/name": APP, s.label("namespace"): s.namespace}
    out = []
    for node in server_nodes(s):
        out.append({"apiVersion": "v1", "kind": "PersistentVolume",
                    "metadata": {"name": pv_name(s, node), "labels": dict(labels, **{s.label("node"): node})},
                    "spec": {"capacity": {"storage": size}, "accessModes": ["ReadOnlyMany"],
                             "persistentVolumeReclaimPolicy": "Retain", "storageClassName": f"{APP}-models",
                             "volumeMode": "Filesystem", "local": {"path": s.models_path},
                             "claimRef": {"namespace": s.namespace, "name": pvc_name(node)},
                             "nodeAffinity": {"required": {"nodeSelectorTerms": [{"matchExpressions": [
                                 {"key": "kubernetes.io/hostname", "operator": "In", "values": [node]}]}]}}}})
        out.append({"apiVersion": "v1", "kind": "PersistentVolumeClaim",
                    "metadata": {"name": pvc_name(node), "namespace": s.namespace, "labels": dict(labels, **{s.label("node"): node})},
                    "spec": {"accessModes": ["ReadOnlyMany"], "storageClassName": f"{APP}-models", "volumeName": pv_name(s, node),
                             "resources": {"requests": {"storage": size}}}})
    return out


def services(s: Settings) -> list:
    out = []
    for m in s.models:
        sel = {s.label("model"): m["name"], s.label("role"): "server"}
        out.append(_service(s, m["name"], sel, {s.label("model"): m["name"]}))
    for (model, cp) in s.copies:
        sel = {s.label("model"): model, s.label("copy"): cp, s.label("role"): "server"}
        out.append(_service(s, f"{model}-{cp}", sel, {s.label("model"): model, s.label("copy"): cp}))
    return out


def _service(s: Settings, name: str, selector: dict, labels: dict) -> dict:
    return {"apiVersion": "v1", "kind": "Service",
            "metadata": {"name": name, "namespace": s.namespace, "labels": dict({"app.kubernetes.io/name": APP}, **labels)},
            "spec": {"selector": selector,
                     "ports": [{"name": "http", "port": s.http_port, "targetPort": "http", "protocol": "TCP"}]}}


def route(s: Settings) -> dict:
    r = s.route
    parent = {"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": r["gateway"], "namespace": r["namespace"]}
    if r["section"]:
        parent["sectionName"] = r["section"]
    rules = []
    for name in [m["name"] for m in s.models] + [f"{m}-{c}" for (m, c) in s.copies]:
        rules.append({
            "matches": [{"path": {"type": "PathPrefix", "value": f"/{name}"}}],
            "filters": [{"type": "URLRewrite", "urlRewrite": {"path": {"type": "ReplacePrefixMatch", "replacePrefixMatch": "/"}}}],
            "backendRefs": [{"name": name, "port": s.http_port}],
            "timeouts": {"request": r["request"], "backendRequest": r["backend"]},
        })
    return {"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": r["name"], "namespace": s.namespace, "labels": route_labels(s)},
            "spec": {"parentRefs": [parent], "hostnames": [r["hostname"]], "rules": rules}}


def route_labels(s: Settings) -> dict:
    out = {"app.kubernetes.io/name": APP}
    if s.decision_label and s.route_decision:
        out[s.decision_label] = s.route_decision
    return out


def nad_doc(s: Settings, n: dict) -> dict:
    """One rail attachment: macvlan on the rail NIC, bridge mode, the rail MTU, the static IPAM plugin
    (the address comes from the pod's networks annotation) and no routes."""
    conf = {"cniVersion": "1.0.0", "name": n["name"], "type": "macvlan", "master": n["master"], "mode": "bridge",
            "mtu": int(n["mtu"]), "capabilities": {"ips": True, "mac": True}, "ipam": {"type": "static"}}
    meta = {"name": n["name"], "namespace": s.namespace, "labels": {"app.kubernetes.io/name": APP}}
    if s.decision_label and s.nad_decisions.get(n["name"]):
        meta["annotations"] = {s.decision_label: s.nad_decisions[n["name"]]}
    return {"apiVersion": "k8s.cni.cncf.io/v1", "kind": "NetworkAttachmentDefinition", "metadata": meta,
            "spec": {"config": json.dumps(conf, separators=(",", ":"))}}


def base_docs(s: Settings) -> list:
    labels = dict({"app.kubernetes.io/name": APP, "pod-security.kubernetes.io/enforce": "restricted"}, **s.namespace_labels)
    docs = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": s.namespace, "labels": labels}}]
    for n in s.nads:
        docs.append(nad_doc(s, n))
    sa = f"{APP}-keys"
    docs += [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": sa, "namespace": s.namespace}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": sa, "namespace": s.namespace},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [s.key_secret], "verbs": ["get"]},
                   {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": sa, "namespace": s.namespace},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": sa},
         "subjects": [{"kind": "ServiceAccount", "name": sa, "namespace": s.namespace}]},
    ]
    return docs + models_docs(s)


def key_job(s: Settings) -> dict:
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": s.key_secret, "namespace": s.namespace, "labels": {"app.kubernetes.io/name": APP,
                                                                                    "app.kubernetes.io/component": "key"}},
            "spec": {"backoffLimit": 2, "template": {
                "metadata": {"labels": {"app.kubernetes.io/name": APP, "app.kubernetes.io/component": "key"}},
                "spec": {"serviceAccountName": f"{APP}-keys", "restartPolicy": "Never", "enableServiceLinks": False,
                         "securityContext": _pod_security(),
                         "containers": [{"name": "keys", "image": s.keys_image, "imagePullPolicy": "IfNotPresent",
                                         "command": ["sfab-keys", "ensure", "--namespace", s.namespace, "--secret", s.key_secret,
                                                     "--field", s.key_field, "--prefix", s.key_prefix],
                                         "resources": KEYS_RESOURCES, "securityContext": _restricted()}]}}}}


def manifests(s: Settings) -> dict:
    """file name -> YAML, in apply order."""
    workers = [worker_pod(s, p) for p in s.pods if p["role"] == "worker"]
    servers = [server_pod(s, c["server"], c["workers"]) for c in s.copies.values()]
    return {
        "00-base.yaml": dump_all(base_docs(s)),
        "10-key-job.yaml": dump_all([key_job(s)]),
        "20-workers.yaml": dump_all(workers),
        "30-servers.yaml": dump_all(servers),
        "40-services.yaml": dump_all(services(s)),
        "50-route.yaml": dump_all([route(s)]),
    }


def placement_table(s: Settings) -> str:
    cols = ("pod", "model", "copy", "role", "node", "rail", "nad", "address") + (("mac",) if any(p.get("mac") for p in s.pods) else ())
    rows = [cols] + [tuple(str(p[c]) for c in cols) for p in s.pods]
    w = [max(len(r[i]) for r in rows) for i in range(len(cols))]
    return "".join("  ".join(r[i].ljust(w[i]) for i in range(len(cols))).rstrip() + "\n" for r in rows)


def render(s: Settings, out: Path) -> list:
    out.mkdir(parents=True, exist_ok=True)
    head = f"# serving-layer manifests for {s.lab or 'this cluster'}: rendered by serving.py from serving.env\n"
    files = manifests(s)
    for name, text in files.items():
        (out / name).write_text(head + text, encoding="utf-8")
    (out / "placement.txt").write_text(placement_table(s), encoding="utf-8")
    return list(files) + ["placement.txt"]


# ------------------------------------------------------------------------------------------
# kubectl


class Kube:
    """SERVING_KUBECTL, run with argv (never a shell), a manifest or nothing on stdin."""

    def __init__(self, argv: list, run=None):
        self.argv = list(argv)
        self._run = run or (lambda argv, stdin: subprocess.run(argv, input=stdin, capture_output=True))

    def __call__(self, *args, stdin: bytes | None = None, check: bool = True) -> subprocess.CompletedProcess:
        r = self._run(self.argv + list(args), stdin)
        if check and r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
            raise ServingError(f"kubectl {' '.join(args[:4])}: {err[-1] if err else 'exit ' + str(r.returncode)}")
        return r

    def out(self, *args) -> str:
        return (self(*args).stdout or b"").decode("utf-8", "replace")

    def apply(self, text: str) -> None:
        self("apply", "-f", "-", stdin=text.encode())

    def exists(self, *args) -> bool:
        return self("get", *args, "-o", "name", check=False).returncode == 0

    def json(self, *args) -> dict:
        return json.loads(self.out("get", *args, "-o", "json") or "{}")


class Report:
    """The repository's vocabulary: PASS, FAIL and the RESULT line."""

    def __init__(self, out=None):
        self.out = out or sys.stdout
        self.passed = self.failed = 0

    def sec(self, name: str) -> None:
        print(f"== {name}", file=self.out, flush=True)

    def ok(self, label: str) -> None:
        self.passed += 1
        print(f"  PASS  {label}", file=self.out, flush=True)

    def bad(self, label: str, detail: str) -> None:
        self.failed += 1
        print(f"  FAIL  {label} -> {detail}", file=self.out, flush=True)

    def summary(self) -> int:
        print(f"== RESULT: {self.passed} passed, {self.failed} failed, 0 known platform limitation(s), 0 skipped", file=self.out, flush=True)
        return 1 if self.failed else 0


# ------------------------------------------------------------------------------------------
# serve


def _detached(pod: dict) -> bool:
    """A pod whose sandbox was made again without Multus: it has an address, and the network-status
    annotation is missing or gives its default network another one. A node that boots on a kept disk
    runs its pods' sandboxes again, and one made before Multus's daemon has written its CNI
    configuration gets Cilium alone, so the pod keeps its old annotation and has no rail."""
    ip = (pod.get("status") or {}).get("podIP")
    if not ip:
        return False
    raw = ((pod.get("metadata") or {}).get("annotations") or {}).get(NETWORK_STATUS)
    try:
        nets = json.loads(raw) if raw else []
    except ValueError:
        return True
    default = [n for n in nets if n.get("default")] or nets[:1]
    return not default or ip not in (default[0].get("ips") or [])


def _running_stamps(kube: Kube, s: Settings) -> dict:
    """Each server and worker pod's stamp, or None for one that is detached from its rail."""
    items = kube.json("pods", "-n", s.namespace, "-l", f"app.kubernetes.io/name={APP}").get("items") or []
    return {i["metadata"]["name"]: None if _detached(i) else (i["metadata"].get("annotations") or {}).get(s.label("spec"))
            for i in items if (i["metadata"].get("labels") or {}).get("app.kubernetes.io/component") in ("server", "worker")}


def wait_pods(kube: Kube, s: Settings, want: dict, timeout: int, clock=time.monotonic, sleep=time.sleep) -> list:
    """Wait until every pod named in want ({pod: stamp}) exists with that stamp, is not being
    deleted and is Ready; return the ones that are not, each with what it lacks ([] when all are)."""
    end = clock() + timeout
    while True:
        items = {i["metadata"]["name"]: i for i in kube.json("pods", "-n", s.namespace, "-l", f"app.kubernetes.io/name={APP}").get("items") or []}
        missing = []
        for name, st in want.items():
            got = items.get(name)
            if got is None:
                missing.append(f"{name} (not made yet)")
            elif (got["metadata"].get("annotations") or {}).get(s.label("spec")) != st or got["metadata"].get("deletionTimestamp"):
                missing.append(f"{name} (the old one still there)")
            elif not _ready(got):
                missing.append(f"{name} (not Ready)")
        if not missing or clock() >= end:
            return missing
        sleep(WAIT_POLL_S)


def _apply_role(kube: Kube, s: Settings, rep: Report, files: dict, role: str, stale: list) -> bool:
    """Apply one role's StatefulSets, delete its stale pods so their controllers make them again
    from the rendered template, and wait for every pod of the role Ready."""
    fname = "20-workers.yaml" if role == "worker" else "30-servers.yaml"
    kube.apply(files[fname])
    rows = [p for p in s.pods if p["role"] == role]
    gone = [p["pod"] for p in rows if p["pod"] in stale]
    if gone:
        kube("delete", "pod", "-n", s.namespace, "--wait=true", f"--timeout={WAIT['delete']}s", "--ignore-not-found", *gone)
    want = {d["metadata"]["name"] + "-0": template_stamp(s, d) for d in _docs_of(s, fname)}
    wait = WAIT["workers" if role == "worker" else "servers"]
    missing = wait_pods(kube, s, want, wait)
    if missing:
        rep.bad(f"{len(rows)} {role} pod(s) Ready", f"not within {wait}s: {', '.join(missing)}")
        return False
    rep.ok(f"{len(rows)} {role} pod(s) Ready")
    return True


def serve(kube: Kube, s: Settings, rep: Report, replace: list | None = None) -> int:
    files = manifests(s)
    rep.sec(f"serving: {len(s.pods)} pods of {len(s.copies)} copies of {len(s.models)} models, namespace {s.namespace}")
    replace = list(replace or [])
    unknown = [x for x in replace if x not in {p["pod"] for p in s.pods}]
    if unknown:
        rep.bad("the pods to replace are rows of the table", ", ".join(unknown))
        return rep.summary()
    for ds in s.wait_daemonsets:
        ns, _, name = ds.partition("/")
        kube("-n", ns, "rollout", "status", f"daemonset/{name}", f"--timeout={WAIT['daemonset']}s")
        rep.ok(f"daemonset {ds} rolled out")
    # a models volume released by an earlier namespace's claim cannot bind again: it is only a
    # pointer to the node's path, so it is made again
    for pv in kube.json("pv", "-l", f"app.kubernetes.io/name={APP},{s.label('namespace')}={s.namespace}").get("items") or []:
        if ((pv.get("status") or {}).get("phase")) in ("Released", "Failed"):
            kube("delete", "pv", pv["metadata"]["name"], "--wait=true", f"--timeout={WAIT['delete']}s")
            rep.ok(f"models volume {pv['metadata']['name']} released by an earlier claim: made again")
    kube.apply(files["00-base.yaml"])
    rep.ok(f"namespace {s.namespace}, {len(s.nads)} rail attachment(s), the key tool's role and the models volume of "
           f"{len(server_nodes(s))} node(s) applied")

    if kube.exists("secret", s.key_secret, "-n", s.namespace):
        rep.ok(f"key Secret {s.namespace}/{s.key_secret} present (kept as it is)")
    else:
        kube("delete", "job", s.key_secret, "-n", s.namespace, "--ignore-not-found", "--wait=true")
        kube.apply(files["10-key-job.yaml"])
        r = kube("-n", s.namespace, "wait", "--for=condition=complete", f"job/{s.key_secret}", f"--timeout={WAIT['job']}s", check=False)
        logs = kube("-n", s.namespace, "logs", f"job/{s.key_secret}", check=False)
        for line in (logs.stdout or b"").decode("utf-8", "replace").splitlines():
            print(f"  key tool: {line}", flush=True)
        kube("delete", "job", s.key_secret, "-n", s.namespace, "--ignore-not-found", "--wait=true")
        if r.returncode != 0 or not kube.exists("secret", s.key_secret, "-n", s.namespace):
            rep.bad(f"key Secret {s.namespace}/{s.key_secret} generated in the cluster", "the key tool's Job did not complete")
            return rep.summary()
        rep.ok(f"key Secret {s.namespace}/{s.key_secret} generated in the cluster by the key tool (its value never printed)")

    want = {p["pod"] for p in s.pods}
    rendered = {d["metadata"]["name"] + "-0": template_stamp(s, d) for f in ("20-workers.yaml", "30-servers.yaml") for d in _docs_of(s, f)}
    running = _running_stamps(kube, s)
    stale = sorted(n for n, st in running.items() if n not in want or st != rendered.get(n) or n in replace)
    # the StatefulSets no row names go first, with their pods; a pod no row names (a bare pod of an
    # earlier recipe) is deleted
    sts = [i["metadata"]["name"] for i in kube.json("statefulsets", "-n", s.namespace, "-l", f"app.kubernetes.io/name={APP}").get("items") or []]
    extra = sorted(set(sts) - {controller(p) for p in s.pods})
    if extra:
        kube("delete", "statefulset", "-n", s.namespace, "--wait=true", f"--timeout={WAIT['delete']}s", *extra)
    orphans = [n for n in stale if n not in want]
    if orphans:
        kube("delete", "pod", "-n", s.namespace, "--wait=true", f"--timeout={WAIT['delete']}s", "--ignore-not-found", *orphans)
    rep.ok(f"{len(stale)} pod(s) replaced or removed, {len(running) - len(stale)} kept as rendered"
           + (f"; StatefulSet(s) no row names removed: {', '.join(extra)}" if extra else ""))

    for role in ("worker", "server"):
        if not _apply_role(kube, s, rep, files, role, stale):
            return rep.summary()
    kube.apply(files["40-services.yaml"])
    kube.apply(files["50-route.yaml"])
    rep.ok(f"{len(s.models) + len(s.copies)} Services and HTTPRoute {s.namespace}/{s.route['name']} on "
           f"{s.route['namespace']}/{s.route['gateway']} applied")
    have = [i["metadata"]["name"] for i in kube.json("network-attachment-definitions", "-n", s.namespace, "-l",
                                                      f"app.kubernetes.io/name={APP}").get("items") or []]
    extra = sorted(set(have) - {n["name"] for n in s.nads})
    if extra:
        kube("delete", "network-attachment-definitions", "-n", s.namespace, *extra)
        rep.ok(f"rail attachment(s) the table does not use removed: {', '.join(extra)}")
    verify(kube, s, rep)
    return rep.summary()


def moved_pod(s: Settings, p: dict, nad: str, address: str, mac: str | None = None) -> dict:
    """The row's StatefulSet as the recipe renders it, but its pod attached to another rail at
    another address (and MAC): its labels still name the table's rail, its networks annotation, its
    bind address and its probe the new one. Its stamp differs from the rendered one, so serve makes
    the pod again from the rendered template."""
    moved = dict(p, nad=nad, address=address, mac=mac or "-")
    if p["role"] == "worker":
        doc = worker_pod(s, moved)
    else:
        workers = s.copies[(p["model"], p["copy"])]["workers"]
        doc = server_pod(s, moved, workers)
    tmpl = doc["spec"]["template"]
    tmpl["metadata"]["labels"] = pod_labels(s, p)
    tmpl["metadata"]["annotations"].pop(s.label("spec"), None)
    tmpl["metadata"]["annotations"][s.label("spec")] = stamp(tmpl)
    doc["metadata"]["labels"] = dict(pod_labels(s, p))
    return doc


def _remake(kube: Kube, s: Settings, docs: list, pod: str, wait: int) -> list:
    """Apply docs (a StatefulSet last), delete its pod so the controller makes it from the new
    template, and wait for it; the pod's missing conditions, [] when it is Ready."""
    kube.apply(dump_all(docs))
    kube("delete", "pod", "-n", s.namespace, "--wait=true", f"--timeout={WAIT['delete']}s", "--ignore-not-found", pod)
    return wait_pods(kube, s, {pod: template_stamp(s, docs[-1])}, wait)


def move(kube: Kube, s: Settings, rep: Report, pod: str, rail: str, address: str, master: str, mac: str | None = None) -> int:
    p = next((x for x in s.pods if x["pod"] == pod), None)
    if p is None:
        rep.bad(f"{pod} is a row of the table", "no such row")
        return rep.summary()
    nad = f"rail{rail}"
    iface = ipaddress.ip_interface(address)
    rep.sec(f"{pod}: made again on {nad} at {iface}, against its row ({p['nad']} {p['address']})")
    docs = []
    if nad not in {n["name"] for n in s.nads}:
        mtu = s.nads[0]["mtu"] if s.nads else "9000"
        docs.append(nad_doc(s, {"name": nad, "master": master, "prefix": str(iface.network), "mtu": mtu}))
    doc = moved_pod(s, p, nad, address, mac)
    missing = _remake(kube, s, docs + [doc], pod, WAIT["workers"])
    rep.ok(f"{pod} made again by StatefulSet {controller(p)} on {nad} at {iface}"
           + (f", with a {nad} attachment the table does not use" if docs else ""))
    if not missing:
        rep.ok(f"{pod} Running and Ready on {nad}")
    else:
        rep.bad(f"{pod} Running and Ready on {nad}", f"not within {WAIT['workers']}s: {', '.join(missing)}")
    return rep.summary()


def routed_pod(s: Settings, p: dict, nad: str) -> dict:
    """The row's StatefulSet as the recipe renders it, its pod at its own address and MAC, but
    attached through the copy nad of its rail attachment: the networks annotation names the copy and
    keeps the row's interface name. Its stamp differs from the rendered one, so serve makes the pod
    again from the rendered template."""
    doc = moved_pod(s, p, nad, p["address"], p.get("mac"))
    tmpl = doc["spec"]["template"]
    nets = json.loads(tmpl["metadata"]["annotations"][NETWORKS])
    nets[0]["interface"] = p["nad"]
    tmpl["metadata"]["annotations"][NETWORKS] = json.dumps(nets, separators=(",", ":"))
    tmpl["metadata"]["annotations"].pop(s.label("spec"), None)
    tmpl["metadata"]["annotations"][s.label("spec")] = stamp(tmpl)
    return doc


def routed_nad(s: Settings, p: dict, nad: str, dst: str, via: str) -> dict:
    """A copy of the row's rail attachment under the name nad, whose static IPAM adds one route
    (cni.dev static IPAM: routes, each a dst and an optional gw)."""
    n = next(x for x in s.nads if x["name"] == p["nad"])
    doc = nad_doc(s, dict(n, name=nad))
    conf = json.loads(doc["spec"]["config"])
    conf["ipam"]["routes"] = [{"dst": dst, "gw": via}]
    doc["spec"]["config"] = json.dumps(conf, separators=(",", ":"))
    doc["metadata"].pop("annotations", None)
    return doc


def reroute(kube: Kube, s: Settings, rep: Report, pod: str, nad: str, dst: str, via: str) -> int:
    p = next((x for x in s.pods if x["pod"] == pod), None)
    if p is None:
        rep.bad(f"{pod} is a row of the table", "no such row")
        return rep.summary()
    if nad in {n["name"] for n in s.nads}:
        rep.bad(f"{nad} is a new attachment", "the table uses that name")
        return rep.summary()
    rep.sec(f"{pod}: made again at {p['address']} through {nad}, a copy of {p['nad']} with a route to {dst} via {via}")
    missing = _remake(kube, s, [routed_nad(s, p, nad, dst, via), routed_pod(s, p, nad)], pod, WAIT["servers"])
    rep.ok(f"{pod} made again by StatefulSet {controller(p)} through {nad} (route {dst} via {via}) at {p['address']}")
    # whether it turns Ready is what the break records, so either way is reported, never failed
    rep.ok(f"{pod} Ready through {nad}" if not missing else f"{pod} not Ready within {WAIT['servers']}s (recorded)")
    return rep.summary()


def _docs_of(s: Settings, name: str) -> list:
    if name == "20-workers.yaml":
        return [worker_pod(s, p) for p in s.pods if p["role"] == "worker"]
    return [server_pod(s, c["server"], c["workers"]) for c in s.copies.values()]


def rail_status(pod: dict, nad: str, namespace: str) -> str | None:
    """The address the network-status annotation gives the pod on that attachment."""
    raw = ((pod.get("metadata") or {}).get("annotations") or {}).get(NETWORK_STATUS)
    try:
        nets = json.loads(raw) if raw else []
    except ValueError:
        return None
    for n in nets:
        if n.get("name") in (nad, f"{namespace}/{nad}") and n.get("ips"):
            return n["ips"][0]
    return None


def _ready(pod: dict) -> bool:
    return any(c.get("type") == "Ready" and c.get("status") == "True" for c in (pod.get("status") or {}).get("conditions") or [])


def verify(kube: Kube, s: Settings, rep: Report) -> None:
    """Every pod where its row puts it, every Service on the servers it names."""
    rep.sec("placement read back")
    pods = {i["metadata"]["name"]: i for i in kube.json("pods", "-n", s.namespace).get("items") or []}
    for p in s.pods:
        got = pods.get(p["pod"])
        if got is None:
            rep.bad(f"{p['pod']} on {p['node']}, rail {p['rail']} {rail_ip(p)}", "no such pod")
            continue
        node = (got.get("spec") or {}).get("nodeName")
        ip = rail_status(got, p["nad"], s.namespace)
        owners = [o.get("name") for o in (got["metadata"].get("ownerReferences") or []) if o.get("kind") == "StatefulSet"]
        detail = []
        if owners != [controller(p)]:
            detail.append(f"owned by {', '.join(owners) or 'no StatefulSet'}")
        if node != p["node"]:
            detail.append(f"on {node}")
        if ip != rail_ip(p):
            detail.append(f"rail address {ip}")
        if not _ready(got):
            detail.append("not Ready")
        label = f"{p['pod']} of StatefulSet {controller(p)} on {p['node']}, {p['nad']} {rail_ip(p)}, Ready"
        if detail:
            rep.bad(label, ", ".join(detail))
        else:
            rep.ok(label)
    rep.sec("Services")
    for svc in services(s):
        name = svc["metadata"]["name"]
        sel = svc["spec"]["selector"]
        want = sorted((pods[n].get("status") or {}).get("podIP") or "" for n in pods
                      if all((pods[n]["metadata"].get("labels") or {}).get(k) == v for k, v in sel.items()))
        slices = kube.json("endpointslices", "-n", s.namespace, "-l", f"kubernetes.io/service-name={name}").get("items") or []
        have = sorted(a for sl in slices for e in sl.get("endpoints") or [] if (e.get("conditions") or {}).get("ready")
                      for a in e.get("addresses") or [])
        if have and have == want:
            rep.ok(f"Service {name}: {len(have)} ready endpoint(s), its servers ({' '.join(have)})")
        else:
            rep.bad(f"Service {name}: its servers ready", f"endpoints {' '.join(have) or 'none'}, servers {' '.join(want) or 'none'}")


def status(kube: Kube, s: Settings) -> int:
    pods = {i["metadata"]["name"]: i for i in kube.json("pods", "-n", s.namespace).get("items") or []}
    print(f"{'pod':<20} {'node':<9} {'rail address':<16} ready")
    for p in s.pods:
        got = pods.get(p["pod"]) or {}
        print(f"{p['pod']:<20} {(got.get('spec') or {}).get('nodeName') or '-':<9} "
              f"{rail_status(got, p['nad'], s.namespace) or '-':<16} {'yes' if got and _ready(got) else 'no'}")
    for svc in services(s):
        name = svc["metadata"]["name"]
        slices = kube.json("endpointslices", "-n", s.namespace, "-l", f"kubernetes.io/service-name={name}").get("items") or []
        ready = [a for sl in slices for e in sl.get("endpoints") or [] if (e.get("conditions") or {}).get("ready")
                 for a in e.get("addresses") or []]
        print(f"Service {name}: {' '.join(sorted(ready)) or 'no ready endpoint'}")
    return 0


# ------------------------------------------------------------------------------------------
# load


def read_key(kube: Kube, s: Settings) -> bytes:
    """The key's value, from the Secret, for the load client only: never printed or logged."""
    r = kube("get", "secret", s.key_secret, "-n", s.namespace, "-o", f"jsonpath={{.data.{s.key_field}}}")
    try:
        key = base64.b64decode(r.stdout.strip(), validate=True)
    except ValueError:
        raise ServingError(f"Secret {s.namespace}/{s.key_secret} holds no base64 {s.key_field}") from None
    if not key:
        raise ServingError(f"Secret {s.namespace}/{s.key_secret} has an empty {s.key_field}")
    return key


def load_args(a, s: Settings, key_file: str, records: str | None) -> list:
    url = a.url or s.load["url"]
    if not url:
        raise ServingError("no URL: give --url, or SERVING_LOAD_URL in serving.env")
    out = ["--url", url, "--users", str(a.users), "--seconds", str(a.seconds), "--key-file", key_file,
           "--max-tokens", str(a.max_tokens)]
    resolve = s.load["resolve"] if a.resolve is None else a.resolve
    if resolve:
        out += ["--resolve", resolve]
    if a.model:
        out += ["--model", a.model]
    if records:
        out += ["--records", records]
    if a.cut_ok:
        out.append("--cut-ok")
    return out


def load(kube: Kube, s: Settings, a, run=None) -> int:
    run = run or (lambda argv, stdin=None, capture=False: subprocess.run(argv, input=stdin, capture_output=capture))
    key = read_key(kube, s)
    ex = list(s.load["exec"]) if a.local is False else []
    if ex:
        r = run(ex + ["sh", "-c", f"umask 077; cat > {LOAD_KEY}"], key)
        if r.returncode != 0:
            raise ServingError("could not hand the key to the load client")
        try:
            argv = ex + ["python3", "-", *load_args(a, s, LOAD_KEY, LOAD_RECORDS if a.records else None)]
            rc = run(argv, LOAD_PY.read_bytes()).returncode
            if a.records:
                got = run(ex + ["cat", LOAD_RECORDS], None, True)
                Path(a.records).write_bytes(got.stdout or b"")
        finally:
            run(ex + ["rm", "-f", LOAD_KEY, LOAD_RECORDS])
        return rc
    with tempfile.TemporaryDirectory(prefix="sfab-load-") as d:
        kf = Path(d) / "key"
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return run([sys.executable, str(LOAD_PY), *load_args(a, s, str(kf), a.records)]).returncode


def client_args(a, s: Settings, key_file: str) -> list:
    url = a.url or s.load["url"]
    if not url:
        raise ServingError("no URL: give --url, or SERVING_LOAD_URL in serving.env")
    out = ["--base-url", url, "--key-file", key_file, "--max-tokens", str(a.max_tokens)]
    resolve = s.load["resolve"] if a.resolve is None else a.resolve
    if resolve:
        out += ["--resolve", resolve]
    if a.model:
        out += ["--model", a.model]
    return out


def client(kube: Kube, s: Settings, a, run=None) -> int:
    """One chat completion with client.py where make load runs (SERVING_LOAD_EXEC), the key handed
    to it on a pipe into a 0600 file and removed after; with --local, here."""
    run = run or (lambda argv, stdin=None, capture=False: subprocess.run(argv, input=stdin, capture_output=capture))
    key = read_key(kube, s)
    ex = list(s.load["exec"]) if a.local is False else []
    if ex:
        r = run(ex + ["sh", "-c", f"umask 077; cat > {CLIENT_KEY}"], key)
        if r.returncode != 0:
            raise ServingError("could not hand the key to the client")
        try:
            return run(ex + ["python3", "-", *client_args(a, s, CLIENT_KEY)], CLIENT_PY.read_bytes()).returncode
        finally:
            run(ex + ["rm", "-f", CLIENT_KEY])
    with tempfile.TemporaryDirectory(prefix="sfab-client-") as d:
        kf = Path(d) / "key"
        fd = os.open(kf, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        return run([sys.executable, str(CLIENT_PY), *client_args(a, s, str(kf))]).returncode


# ------------------------------------------------------------------------------------------


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(prog="serving.py", description=__doc__.strip().splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("render", "serve", "status", "load", "client", "delete", "move", "reroute"):
        p = sub.add_parser(name)
        p.add_argument("--env", required=True, help="serving.env")
        if name == "render":
            p.add_argument("--out", required=True)
        if name == "serve":
            p.add_argument("--replace", action="append", default=[], help="a pod to remove first, so serve makes it again")
        if name == "move":
            p.add_argument("--pod", required=True)
            p.add_argument("--rail", required=True)
            p.add_argument("--address", required=True, help="the address on that rail, with its prefix length")
            p.add_argument("--master", required=True, help="the node NIC of that rail")
            p.add_argument("--mac", default=None, help="the pod's MAC on that rail")
        if name == "reroute":
            p.add_argument("--pod", required=True)
            p.add_argument("--nad", required=True, help="the copy's name (a new attachment)")
            p.add_argument("--dst", required=True, help="the route's destination prefix")
            p.add_argument("--via", required=True, help="the route's gateway, an address on the pod's rail")
        if name == "load":
            p.add_argument("--users", type=int, default=10)
            p.add_argument("--seconds", type=int, default=60)
            p.add_argument("--max-tokens", type=int, default=64)
            p.add_argument("--url", default="")
            p.add_argument("--model", default="")
            p.add_argument("--resolve", default=None, help="host:port:address, or '' for none")
            p.add_argument("--records", default="", help="write one JSON line per request here (on this host)")
            p.add_argument("--cut-ok", action="store_true", help="report streams cut mid-answer without failing on them")
            p.add_argument("--local", action="store_true", help="run load.py here, not through SERVING_LOAD_EXEC")
        if name == "client":
            p.add_argument("--max-tokens", type=int, default=64)
            p.add_argument("--url", default="", help="the base URL (SERVING_LOAD_URL by default)")
            p.add_argument("--model", default="")
            p.add_argument("--resolve", default=None, help="host:port:address, or '' for none")
            p.add_argument("--local", action="store_true", help="run client.py here, not through SERVING_LOAD_EXEC")
    a = ap.parse_args(argv)
    try:
        s = settings(read_env(Path(a.env)))
        if a.cmd == "render":
            for f in render(s, Path(a.out)):
                print(f"{Path(a.out) / f}")
            return 0
        kube = Kube(s.kubectl)
        if a.cmd == "serve":
            return serve(kube, s, Report(), a.replace)
        if a.cmd == "move":
            if not a.rail.isdigit():
                raise ServingError(f"--rail {a.rail!r} is not a rail number")
            try:
                ipaddress.ip_interface(a.address)
            except ValueError:
                raise ServingError(f"--address {a.address!r} is not an address with its prefix length") from None
            if not NAME_RE.match(a.master):
                raise ServingError(f"--master {a.master!r} is not an interface name")
            if a.mac is not None and not MAC_RE.match(a.mac):
                raise ServingError(f"--mac {a.mac!r} is not a MAC")
            return move(kube, s, Report(), a.pod, a.rail, a.address, a.master, a.mac)
        if a.cmd == "reroute":
            if not NAME_RE.match(a.nad):
                raise ServingError(f"--nad {a.nad!r} is not a name")
            try:
                ipaddress.ip_network(a.dst)
                ipaddress.ip_address(a.via)
            except ValueError:
                raise ServingError(f"--dst {a.dst!r} or --via {a.via!r} is not a prefix and an address") from None
            return reroute(kube, s, Report(), a.pod, a.nad, a.dst, a.via)
        if a.cmd == "status":
            return status(kube, s)
        if a.cmd == "load":
            return load(kube, s, a)
        if a.cmd == "client":
            return client(kube, s, a)
        kube("delete", "namespace", s.namespace, "--ignore-not-found", "--wait=true")
        kube("delete", "pv", "-l", f"app.kubernetes.io/name={APP},{s.label('namespace')}={s.namespace}", "--ignore-not-found", "--wait=true")
        print(f"namespace {s.namespace} and its models volumes removed")
        return 0
    except ServingError as e:
        print(f"serving.py: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
