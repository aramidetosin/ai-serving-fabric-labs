"""The identity provider (chapter 7), in a lab whose features turn serving on.

Dex stands in for the enterprise's own identity provider. render/k8s.py calls render(), which
writes bootstrap/k8s/57-identity.yaml (in apply.list, after the Gateways): the namespace (Pod
Security restricted, labelled for the Gateways it is published on), Dex's configuration as a
ConfigMap, its Deployment on the ingress nodes (k8s.edge), its Service, and one HTTPRoute per
Gateway for <hostname>.<org zone>. The configuration names no secret: each client's secret and
each person's password hash are environment variables (Dex's secretEnv and hashFromEnv) from the
Secret <name>-credentials, which finish writes from the lab host (common/bin/idp-secret.py, through
a pipe) after the namespace exists. The values are made on the lab host by common/bin/secrets.py
(SFAB_IDP_*, gen/k8s.json identity.secrets names them), so the redaction pass knows them.

A person signs in through one of the clients with the resource owner password grant (Dex's local
password database, oauth2.passwordConnector local; production uses the authorization code flow
with PKCE in the person's browser) and asks for the scope audience:server:client_id:<audience>.
Dex writes the API gateway's client id into the token's aud only because that client trusts the
person's client (trustedPeers); the API gateway (render/inference.py, the oidc-consumer plugin)
refuses a token without it. The API gateway reads Dex's signing keys from the Service inside the
cluster, so its check needs no route through a Gateway.
"""

from __future__ import annotations

import json
import re
import uuid

from ..model import Model
from . import RenderError

FILE = "57-identity.yaml"
CONFIG_DIR = "/etc/dex"
UID = 1001
RESOURCES = {"requests": {"cpu": "20m", "memory": "48Mi"}, "limits": {"memory": "192Mi"}}
SCOPES = "openid email profile"
# A person's userID: a fixed UUID from the person's id, so the token's sub never changes between runs.
_NS = uuid.UUID("6f1d2a8e-3b9c-5e47-9a0d-1c2b3a4d5e6f")


def enabled(model: Model) -> bool:
    from .k8s import serving_enabled  # noqa: PLC0415

    return serving_enabled(model) and bool((model.spec or {}).get("identity"))


def _env(prefix: str, ident: str) -> str:
    return prefix + re.sub(r"[^A-Z0-9]", "_", ident.upper())


def _name(v, where: str) -> str:
    s = str(v or "")
    if not re.match(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", s) or len(s) > 63:
        raise RenderError(f"spec identity.{where} {s!r} is not a Kubernetes name")
    return s


def settings(model: Model) -> dict:
    from .k8s import _addon, _fqdn, edge_placement, pod_image  # noqa: PLC0415

    raw = dict((model.spec or {}).get("identity") or {})
    if raw.get("provider") != "dex":
        raise RenderError("spec identity.provider: only dex")
    for f in ("namespace", "name", "image", "port", "hostname", "audience", "clients", "people"):
        if raw.get(f) in (None, "", [], {}):
            raise RenderError(f"spec identity needs {f}")
    ns, name = _name(raw["namespace"], "namespace"), _name(raw["name"], "name")
    host = _fqdn(model, str(raw["hostname"]))
    if model.dns is not None and host not in model.dns.identity:
        raise RenderError(f"spec identity.hostname {raw['hostname']!r} is not one of dns.identity: no view answers {host}")
    gws = [str(g) for g in raw.get("gateways") or list(model.gateways) if str(g) in model.gateways]
    if not gws:
        raise RenderError("spec identity: no Gateway of this lab publishes the identity provider")
    clients = []
    for c in raw["clients"]:
        cid = _name(c.get("id"), "clients.id")
        clients.append({"id": cid, "name": str(c.get("name") or cid), "secret_env": _env("SFAB_IDP_CLIENT_", cid)})
    aud = _name(raw["audience"], "audience")
    if aud in {c["id"] for c in clients}:
        raise RenderError("spec identity.audience must not be one of the clients people sign in with")
    people = []
    for p in raw["people"]:
        pid = _name(p.get("id"), "people.id")
        email = str(p.get("email") or "")
        if not re.match(r"^[a-z0-9._-]+@[a-z0-9.-]+\.example$", email):
            raise RenderError(f"spec identity.people {pid}: email {email!r} must be an address under .example")
        node = str(p.get("node") or "")
        if node and node not in model.nodes:
            node = ""  # the person's client is not in this lab's slice
        people.append({"id": pid, "email": email, "name": str(p.get("name") or pid), "node": node or None,
                       "user_id": str(uuid.uuid5(_NS, f"{model.org.domain}/{pid}")),
                       "password_env": _env("SFAB_IDP_PASSWORD_", pid), "hash_env": _env("SFAB_IDP_HASH_", pid)})
    port = int(raw["port"])
    return {
        "provider": "dex", "namespace": ns, "name": name, "port": port, "hostname": host, "issuer": f"https://{host}",
        "jwks_uri": f"http://{name}.{ns}.svc.cluster.local:{port}/keys",
        "service": f"{name}.{ns}.svc.cluster.local", "audience": aud, "clients": clients, "people": people,
        "gateways": gws, "replicas": int(raw.get("replicas") or 1), "token_ttl_m": int(raw.get("token_ttl_m") or 60),
        "keys_h": int(raw.get("keys_h") or 6), "scope": f"{SCOPES} audience:server:client_id:{aud}",
        "token_path": "/token", "secret": f"{name}-credentials", "configmap": f"{name}-config",
        "image": pod_image(_addon(model, str(raw["image"])).get("image") or {}, f"kubernetes.{raw['image']}.image"),
        "placement": edge_placement(model), "file": FILE,
        "secrets": [c["secret_env"] for c in clients] + [p["password_env"] for p in people],
        "hashes": {p["hash_env"]: p["password_env"] for p in people},
        "since": raw.get("since"),
    }


def dex_config(s: dict) -> str:
    from .k8s import dump  # noqa: PLC0415

    doc = {
        "issuer": s["issuer"],
        "storage": {"type": "memory"},
        "web": {"http": f"0.0.0.0:{s['port']}"},
        "logger": {"level": "info", "format": "json"},
        "oauth2": {"passwordConnector": "local", "skipApprovalScreen": True, "responseTypes": ["code"]},
        "enablePasswordDB": True,
        "expiry": {"idTokens": f"{s['token_ttl_m']}m", "signingKeys": f"{s['keys_h']}h"},
        "staticClients": [{"id": s["audience"], "name": "The API gateway", "public": True,
                           "trustedPeers": [c["id"] for c in s["clients"]]}]
                         + [{"id": c["id"], "name": c["name"], "secretEnv": c["secret_env"]} for c in s["clients"]],
        "staticPasswords": [{"email": p["email"], "hashFromEnv": p["hash_env"], "username": p["id"], "userID": p["user_id"]}
                            for p in s["people"]],
    }
    return dump(doc)


def docs(model: Model, s: dict) -> list:
    from .k8s import _decision, gateway_namespace, listener, namespace_route_labels  # noqa: PLC0415

    ns, name = s["namespace"], s["name"]
    sel = {"app.kubernetes.io/name": name}
    cfg = dex_config(s)
    import hashlib  # noqa: PLC0415

    stamp = hashlib.sha256(cfg.encode()).hexdigest()[:16]
    pod_spec: dict = {
        "automountServiceAccountToken": False, "enableServiceLinks": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": UID, "runAsGroup": UID, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "dex", "image": s["image"], "imagePullPolicy": "IfNotPresent",
            "command": ["dex", "serve", f"{CONFIG_DIR}/config.yaml"],
            "envFrom": [{"secretRef": {"name": s["secret"]}}],
            "ports": [{"name": "http", "containerPort": s["port"], "protocol": "TCP"}],
            "readinessProbe": {"httpGet": {"path": "/healthz", "port": "http"}, "periodSeconds": 5, "failureThreshold": 3},
            "resources": RESOURCES,
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
            "volumeMounts": [{"name": "config", "mountPath": CONFIG_DIR, "readOnly": True}],
        }],
        "volumes": [{"name": "config", "configMap": {"name": s["configmap"]}}],
    }
    pod_spec.update(s["placement"])
    nsl = dict({"pod-security.kubernetes.io/enforce": "restricted"}, **namespace_route_labels(model, ns))
    out = [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": nsl}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": s["configmap"], "namespace": ns, "labels": dict(sel)},
         "data": {"config.yaml": cfg}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": ns, "labels": dict(sel)},
         "spec": {"replicas": s["replicas"], "selector": {"matchLabels": dict(sel)},
                  "template": {"metadata": {"labels": dict(sel), "annotations": {f"{model.org.label_domain}/config": stamp}},
                               "spec": pod_spec}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": ns, "labels": dict(sel)},
         "spec": {"selector": dict(sel), "ports": [{"name": "http", "port": s["port"], "targetPort": "http", "protocol": "TCP"}]}},
    ]
    for g in s["gateways"]:
        gate = model.gateways[g]
        labels = {}
        if "audience" in model.k8s.labels and gate.audience:
            labels[model.k8s.labels["audience"]] = gate.audience
        labels.update(_decision(model, gate.decision))
        out.append({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": f"{name}-{g}", "namespace": ns, "labels": labels},
            "spec": {"parentRefs": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": g,
                                     "namespace": gateway_namespace(model), "sectionName": listener(model)["name"]}],
                     "hostnames": [s["hostname"]],
                     "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": "/"}}], "backendRefs": [{"name": name, "port": s["port"]}]}]},
        })
    return out


def summary(model: Model) -> dict | None:
    if not enabled(model):
        return None
    s = settings(model)
    out = {k: v for k, v in s.items() if k not in ("placement",)}
    out["routes"] = {g: f"{s['name']}-{g}" for g in s["gateways"]}
    return json.loads(json.dumps(out))


def render(model: Model, ctx) -> dict:
    if not enabled(model):
        return {}
    from .k8s import header, yaml_file  # noqa: PLC0415

    s = settings(model)
    head = header(model, "identity provider", ctx) + [
        f"Dex stands in for the enterprise's identity provider, published on {', '.join(s['gateways'])} as {s['hostname']}.",
        f"Its configuration names no secret: the clients' secrets and the people's password hashes come from the Secret {s['secret']},",
        "which finish writes from the lab host (common/bin/idp-secret.py). A token is for the API gateway only when its",
        f"aud names {s['audience']}, which Dex writes for a client that client trusts (trustedPeers).",
    ]
    return {f"bootstrap/k8s/{FILE}": yaml_file(head, docs(model, s))}


__all__ = ["render", "settings", "summary", "enabled", "FILE"]
