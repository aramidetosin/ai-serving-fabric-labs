"""The API gateway and the model router (chapters 6 and 7), in a lab whose features turn serving on.

render/k8s.py calls render() and writes three files under bootstrap/k8s/, which the finish stage
applies from the bastion after the serving recipe (common/stages/finish.sh, step inference),
because the router needs the recipe's key:

  60-inference-base.yaml   the namespace (Pod Security restricted, and the route labels of the
                           Gateways its model routes attach to), the key Job's account and its
                           two roles: in this namespace get and patch on the three Secrets it keeps
                           and create; in the recipe's namespace get on the recipe's key Secret;
                           and the per-pod key probe's account (chapter 7), which may get and list
                           the namespace's pods
  61-inference-keys.yaml   the key Job (sfab/keys): the router's master key (ensure), one key per
                           model (mint --if-none), and the recipe's key copied as the router's
                           backend key (copy). It prints fingerprints only; finish removes it after
  62-inference.yaml        the API gateway (APISIX in standalone mode: its config.yaml and its base
                           apisix.yaml as ConfigMaps, the per-model consumers composed from the
                           mounted key Secret by sfab-keys compose, an init container and a
                           sidecar), the router (LiteLLM: its config.yaml as a ConfigMap), their
                           Services, and one HTTPRoute of model routes per Gateway

A request through a Gateway: the Gateway's model route (the users' Gateway one rule per model its
audience may call, <path>/<route id>; the internal Gateway the bare <path>) to the API gateway's
Service; the API gateway's route for that model: key authentication on the Authorization header,
consumer restriction to the model's consumer group (another model's key is answered 401, not the
default 403), and a rewrite to the router's per-model path, /engines/<model>/chat/completions, so
the model is the route's whatever the body names, with the router's master key set in place of the
caller's key; the router's deployment for that model, on the model's Service (both copies'
servers, whose readiness keeps a dead copy out of it), with the backend key; a server and its
workers over their rail.

Nothing here is a secret: every key is made or copied by the Job inside the cluster, and the
manifests name only the Secrets. The timeouts nest, each inside the next: the router's attempts
(attempt_timeout_s times retries plus one) inside the API gateway's upstream read, inside the
HTTPRoute's backendRequest, inside its request.
"""

from __future__ import annotations

import hashlib
import json

from ..model import Model
from . import RenderError

FILES = {"base": "60-inference-base.yaml", "keys": "61-inference-keys.yaml", "layer": "62-inference.yaml"}
KEYS_JOB = "inference-keys"
KEYS_SA = "inference-keys"
# The consumer restriction's answer to a credential of a caller the model's route does not admit:
# 401 with the authentication's own message for an unknown credential, so a caller cannot tell a
# key that works elsewhere from none. With the identity provider on, authentication is multi-auth
# (key-auth, then oidc-consumer), whose one refusal is "Authorization Failed"; with keys alone it
# is key-auth's own.
REJECTED_CODE = 401
REJECTED_MSG = "Invalid API key in request"
REJECTED_MSG_MULTI = "Authorization Failed"
# Every 401 says how to authenticate (RFC 9110 section 11.6.1): a Bearer credential.
WWW_AUTHENTICATE = 'Bearer realm="{realm}"'
# The plugins the API gateway loads: exactly the ones its routes use (config.yaml plugins:), the
# lab's own oidc-consumer among them (render/apisix/oidc-consumer.lua, mounted from a ConfigMap
# into the image's plugin directory).
PLUGINS = ("multi-auth", "key-auth", "oidc-consumer", "consumer-restriction", "proxy-rewrite", "limit-count",
           "response-rewrite", "file-logger")
OIDC_PLUGIN = "oidc-consumer"
OIDC_SOURCE = "apisix/oidc-consumer.lua"
# One access line per request, as JSON on stdout (file-logger): the consumer and its group name
# the caller; no header is logged, so no credential is.
ACCESS_LOG = {"time": "$time_iso8601", "client": "$remote_addr", "host": "$host", "route": "$route_id",
              "request": "$request_method $uri", "status": "$status", "consumer": "$consumer_name",
              "caller": "$consumer_group_id", "upstream_status": "$upstream_status", "request_time": "$request_time"}
CALLER_KINDS = ("application", "people")
# Where the API gateway's files live in its container (the apache/apisix image's prefix).
APISIX_PREFIX = "/usr/local/apisix"
APISIX_START = (f"/usr/bin/apisix init && exec /usr/local/openresty/bin/openresty -p {APISIX_PREFIX} -g 'daemon off;'")
STANDALONE = "/standalone"
MASTER_ENV = "ROUTER_MASTER_KEY"
BACKEND_ENV = "SERVING_KEY"
ROUTER_CONFIG = "/etc/router"
# The API gateway reads the key Secret as files <model>.<id>; compose writes the consumers' keys as
# the whole Authorization header value they must match.
KEY_FORMAT = "Bearer {key}"
UID_KEYS = 65532
UID_ROUTER = 65532
GATEWAY_RESOURCES = {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}}
SIDECAR_RESOURCES = {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "128Mi"}}
ROUTER_RESOURCES = {"requests": {"cpu": "200m", "memory": "512Mi"}, "limits": {"memory": "2Gi"}}
JOB_RESOURCES = {"requests": {"cpu": "10m", "memory": "32Mi"}, "limits": {"memory": "128Mi"}}
# The API gateway and the router name their upstreams by their full cluster names
# (router.inference.svc.cluster.local, <model>.serving.svc.cluster.local). Under the cluster's
# default ndots:5 a name of four dots is tried with each search domain first, and the last search
# domain is the node's, the lab's own domain, whose internal view answers every name under it with
# the internal Gateway's address: the name came back as that VIP (ch06/README.md, platform notes).
# With ndots:1 a name holding a dot is asked for as it is first.
POD_DNS = {"options": [{"name": "ndots", "value": "1"}]}


def enabled(model: Model) -> bool:
    from .k8s import serving_enabled  # noqa: PLC0415

    return serving_enabled(model) and bool((model.spec or {}).get("inference"))


def _int(d: dict, key: str, where: str, low: int = 1) -> int:
    v = d.get(key)
    if isinstance(v, bool) or not isinstance(v, int) or v < low:
        raise RenderError(f"spec inference.{where}.{key} must be a whole number of at least {low}")
    return v


def _name(v, where: str) -> str:
    import re  # noqa: PLC0415

    s = str(v or "")
    if not re.match(r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", s) or len(s) > 63:
        raise RenderError(f"spec inference.{where} {s!r} is not a Kubernetes name")
    return s


def settings(model: Model) -> dict:
    """The block as the manifests, finish, the audit and the trace use it (gen/k8s.json inference)."""
    from . import decisions  # noqa: PLC0415
    from .k8s import _addon, edge_placement, gateway_namespace, listener, local_image, pod_image, serving_summary  # noqa: PLC0415

    raw = dict((model.spec or {}).get("inference") or {})
    for f in ("namespace", "path", "gateway", "router", "keys", "route"):
        if raw.get(f) in (None, "", {}):
            raise RenderError(f"spec inference needs {f}")
    pr = dict(raw.get("probe") or {})
    probe_name = _name(pr.get("name") or "key-probe", "probe.name")
    ns = _name(raw["namespace"], "namespace")
    sv = serving_summary(model)
    if ns == sv["namespace"]:
        raise RenderError("spec inference.namespace must not be the serving recipe's namespace (the recipe's delete removes it)")
    path = str(raw["path"])
    if not path.startswith("/") or path.endswith("/") or " " in path:
        raise RenderError(f"spec inference.path {path!r} must start with / and not end with one")
    g, r, k, rt = dict(raw["gateway"]), dict(raw["router"]), dict(raw["keys"]), dict(raw["route"])
    gw = {"name": _name(g.get("name"), "gateway.name"), "replicas": _int(g, "replicas", "gateway"), "port": _int(g, "port", "gateway"),
          "uid": _int(g, "uid", "gateway"), "upstream_timeout_s": _int(g, "upstream_timeout_s", "gateway"),
          "image": pod_image(_addon(model, str(g.get("image") or "")).get("image") or {}, f"kubernetes.{g.get('image')}.image")}
    ro = {"name": _name(r.get("name"), "router.name"), "replicas": _int(r, "replicas", "router"), "port": _int(r, "port", "router"),
          "attempt_timeout_s": _int(r, "attempt_timeout_s", "router"), "retries": _int(r, "retries", "router", 0),
          # a streamed attempt's bound is the longest silence (the router's client times each read),
          # never more than a whole attempt's
          "stream_timeout_s": _int(r, "stream_timeout_s", "router") if r.get("stream_timeout_s") is not None else _int(r, "attempt_timeout_s", "router"),
          "image": pod_image(_addon(model, str(r.get("image") or "")).get("image") or {}, f"kubernetes.{r.get('image')}.image")}
    ro["host"] = f"{ro['name']}.{ns}.svc.cluster.local"
    if gw["name"] == ro["name"]:
        raise RenderError("spec inference: the API gateway and the router need two names")
    if ro["stream_timeout_s"] > ro["attempt_timeout_s"]:
        raise RenderError("spec inference.router: stream_timeout_s must not exceed attempt_timeout_s")
    tries = ro["retries"] + 1
    request_s, backend_s = _int(rt, "request_s", "route"), _int(rt, "backend_request_s", "route")
    if not tries * ro["attempt_timeout_s"] < gw["upstream_timeout_s"] < backend_s <= request_s:
        raise RenderError(
            f"spec inference: the timeouts must nest: the router's {tries} attempts of {ro['attempt_timeout_s']} s "
            f"< the API gateway's read {gw['upstream_timeout_s']} s < backendRequest {backend_s} s <= request {request_s} s")
    short = model.org.short
    km, kmaster, kb = dict(k.get("models") or {}), dict(k.get("master") or {}), dict(k.get("backend") or {})
    keys = {
        "models": {"secret": _name(km.get("secret"), "keys.models.secret"), "prefix": f"sk-{short}"},
        "master": {"secret": _name(kmaster.get("secret"), "keys.master.secret"), "field": str(kmaster.get("field") or "key"),
                   "prefix": f"sk-{short}-{_name(kmaster.get('prefix'), 'keys.master.prefix')}"},
        "backend": {"secret": _name(kb.get("secret"), "keys.backend.secret"), "field": sv["key"]["field"],
                    "from": {"namespace": sv["namespace"], "secret": sv["key"]["secret"]}},
    }
    if len({keys["models"]["secret"], keys["master"]["secret"], keys["backend"]["secret"]}) != 3:
        raise RenderError("spec inference.keys: the model keys, the master key and the backend key need three Secrets")
    http = int(sv["ports"]["http"])
    models = []
    for m in model.models.values():
        if len(m.name) > 16 or not m.name.isalnum() or m.name.lower() != m.name:
            raise RenderError(f"model {m.name}: a model name is at most 16 lower case letters and digits (it names a key's consumer group)")
        models.append({"name": m.name, "route_id": m.route_id, "path": f"{path}/{m.route_id}",
                       "service": f"{m.name}.{sv['namespace']}.svc.cluster.local", "api_base": f"http://{m.name}.{sv['namespace']}.svc.cluster.local:{http}/v1",
                       "audiences": list(m.audiences), "copies": [c.name for c in m.copies]})
        if decisions.on(model):
            # a decisions lab (chapter 2 on) labels each model's consumer group with the key row's id
            models[-1]["decision"] = decisions.label_of(model, "key", m.name)
    callers = _callers(model, raw, models)
    refuse = audience_refusal(raw)
    if refuse:
        # chapter 8 on: every caller names its audience, its models lie inside it, and the key tool
        # refuses a key for a model outside it (sfab/keys:4)
        auds = {a.get("id"): a for a in (model.spec or {}).get("audiences") or []}
        names = [m["name"] for m in models]
        for c in callers:
            spec_c = next((x for x in raw.get("callers") or [] if str(x.get("id")) == c["id"]), {})
            a = auds.get(spec_c.get("audience"))
            if a is None:
                raise RenderError(f"spec inference.callers {c['id']}: the audience refusal needs every caller's audience")
            am = list(names) if a.get("models") == "all" else [str(x) for x in a.get("models") or [] if str(x) in names]
            out = [x for x in c["models"] if x not in am]
            if out:
                raise RenderError(f"spec inference.callers {c['id']}: {', '.join(out)} lies outside audience {a['id']} ({', '.join(am)})")
            c["audience"] = str(a["id"])
            c["audience_models"] = am
    for m in models:
        m["callers"] = [c["id"] for c in callers if m["name"] in c["models"]]
        if not m["callers"]:
            raise RenderError(f"spec inference.callers: no caller may call model {m['name']}")
    from . import identity  # noqa: PLC0415

    idp = identity.settings(model) if identity.enabled(model) else None
    if any(c["kind"] == "people" for c in callers) and idp is None:
        raise RenderError("spec inference.callers: a people caller needs the identity provider (spec identity, serving on)")
    oidc = None
    if idp is not None:
        people = {p["id"]: p for p in idp["people"]}
        for c in callers:
            for pid in c.get("people") or []:
                if pid not in people:
                    raise RenderError(f"spec inference.callers {c['id']}: {pid} is not one of identity.people")
            c["consumers"] = [{"username": f"{c['id']}_{pid.replace('-', '_')}", "person": pid, "subject": people[pid]["email"]}
                              for pid in c.get("people") or []]
        oidc = {"issuer": idp["issuer"], "jwks_uri": idp["jwks_uri"], "audience": idp["audience"], "claim": "email"}
    users = list(model.dns.users) if model.dns is not None else []
    ls = listener(model)
    routes = []
    for gname, gate in model.gateways.items():
        aud = next((a for a in ((model.spec or {}).get("audiences") or []) if a.get("id") == gate.audience), None)
        if aud is None:
            continue
        hosts = [h for h in gate.hostnames if h in users] or list(gate.hostnames[:1])
        if aud.get("models") == "all":
            rules = [{"path": path, "model": None}]
        else:
            rules = [{"path": x["path"], "model": x["name"]} for x in models if gate.audience in x["audiences"]]
        if not rules:
            continue
        routes.append({"name": f"models-{gname}", "gateway": gname, "namespace": gateway_namespace(model), "section": ls["name"],
                       "hostnames": hosts, "rules": rules, "audience": gate.audience, "decision": gate.decision})
    if not routes:
        raise RenderError("spec inference: no Gateway's audience may call a model")
    if decisions.on(model):
        # a decisions lab (chapter 2 on) labels each caller's consumer group with the key row's id
        for c in callers:
            c["decision"] = decisions.label_of(model, "key", c["id"])
    rejected_msg = REJECTED_MSG_MULTI if oidc else REJECTED_MSG
    realm = users[0] if users else model.org.names
    return {
        "callers": callers, "callers_on": bool(raw.get("callers")), "oidc": oidc, "www_authenticate": WWW_AUTHENTICATE.format(realm=realm),
        "placement": edge_placement(model),
        "namespace": ns, "path": path, "gateway": gw, "router": ro, "keys": keys, "keys_image": sv["keys_image"],
        "serving_namespace": sv["namespace"], "models": models, "routes": routes, "key_format": KEY_FORMAT,
        "timeouts": {"router_attempt_s": ro["attempt_timeout_s"], "router_stream_s": ro["stream_timeout_s"], "router_retries": ro["retries"],
                     "gateway_read_s": gw["upstream_timeout_s"], "backend_request_s": backend_s, "request_s": request_s},
        "files": dict(FILES), "job": KEYS_JOB, "key_sa": KEYS_SA, "deployments": [gw["name"], ro["name"]],
        "labels": {"prefix": model.org.label_domain}, "hostname": users[0] if users else None,
        "probe": {"name": probe_name, "sa": probe_name, "selector": f"app.kubernetes.io/name={gw['name']}", "port": gw["port"]},
        "rejected": {"code": REJECTED_CODE, "message": rejected_msg},
        "configmaps": {"routes": f"{gw['name']}-routes", "config": f"{gw['name']}-config", "router": f"{ro['name']}-config",
                       "plugins": f"{gw['name']}-plugins"},
    }


def audience_refusal(raw: dict) -> bool:
    """The spec's inference.keys.audience: refuse: true turns on the key tool's audience refusal."""
    a = (raw.get("keys") or {}).get("audience")
    if not a:
        return False
    if not isinstance(a, dict) or set(a) - {"refuse", "since"}:
        raise RenderError("spec inference.keys.audience: refuse only")
    return bool(a.get("refuse"))


def mint_audience_args(c: dict, for_models: list | None = None) -> list:
    """The key tool's audience arguments for a key of caller c (sfab/keys:4), or none."""
    if not c.get("audience"):
        return []
    return ["--for", ",".join(for_models if for_models is not None else c["models"]), "--audience", c["audience"],
            "--audience-models", ",".join(c["audience_models"])]


def _callers(model: Model, raw: dict, models: list) -> list:
    """inference.callers as the render uses them: id, kind, models (the names), owner and expiry
    (applications), people (people callers) and the group's request limit. With no callers in the
    spec, one application caller per model, named for the model (the keys of a lab before callers)."""
    import datetime  # noqa: PLC0415

    names = [m["name"] for m in models]
    auds = {a.get("id"): a for a in (model.spec or {}).get("audiences") or []}
    out = []
    spec = raw.get("callers")
    if not spec:
        return [{"id": m, "kind": "application", "models": [m], "owner": None, "expires": None, "people": [], "limit": None}
                for m in names]
    for c in spec:
        cid = str(c.get("id") or "")
        where = f"spec inference.callers {cid or c!r}"
        if len(cid) > 16 or not cid.isalnum() or cid.lower() != cid:
            raise RenderError(f"{where}: a caller's id is at most 16 lower case letters and digits (it names a consumer group and its keys)")
        kind = str(c.get("kind") or "")
        if kind not in CALLER_KINDS:
            raise RenderError(f"{where}: kind {kind!r} is not one of {list(CALLER_KINDS)}")
        if c.get("models") is not None:
            ms = [str(x) for x in c["models"]]
        elif c.get("audience") is not None:
            a = auds.get(c["audience"])
            if a is None:
                raise RenderError(f"{where}: audience {c['audience']!r} is not an audience of the spec")
            ms = list(names) if a.get("models") == "all" else [str(x) for x in a.get("models") or []]
        else:
            raise RenderError(f"{where}: needs models or an audience")
        ms = [x for x in ms if x in names]
        if not ms:
            raise RenderError(f"{where}: may call no model this lab serves")
        lim = c.get("limit")
        if lim is not None:
            if not isinstance(lim, dict) or int(lim.get("count") or 0) < 1 or int(lim.get("window_s") or 0) < 1:
                raise RenderError(f"{where}: limit needs a count and a window_s of at least 1")
            lim = {"count": int(lim["count"]), "window_s": int(lim["window_s"])}
        entry = {"id": cid, "kind": kind, "models": ms, "owner": None, "expires": None, "people": [], "limit": lim}
        if kind == "application":
            if not c.get("owner") or not c.get("expires"):
                raise RenderError(f"{where}: an application caller needs an owner and an expiry date (expires: YYYY-MM-DD)")
            try:
                exp = c["expires"] if isinstance(c["expires"], datetime.date) else datetime.date.fromisoformat(str(c["expires"]))
            except ValueError as e:
                raise RenderError(f"{where}: expires {c['expires']!r} is not a date") from e
            entry.update(owner=str(c["owner"]), expires=exp.isoformat())
        else:
            entry["people"] = [str(x) for x in c.get("people") or []]
            if not entry["people"]:
                raise RenderError(f"{where}: a people caller names its people (identity.people ids)")
        if any(x["id"] == cid for x in out):
            raise RenderError(f"{where}: two callers share the id")
        out.append(entry)
    return out


# --------------------------------------------------------------------------------------------
# the manifests


def _restricted() -> dict:
    return {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}}


def _pod_security(uid: int) -> dict:
    return {"runAsNonRoot": True, "runAsUser": uid, "runAsGroup": uid, "fsGroup": uid, "seccompProfile": {"type": "RuntimeDefault"}}


def _labels(name: str, component: str) -> dict:
    return {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": "inference", "app.kubernetes.io/component": component}


def _stamp(*texts: str) -> str:
    return hashlib.sha256("\n".join(texts).encode()).hexdigest()[:16]


def base_docs(model: Model, s: dict) -> list:
    from .k8s import namespace_route_labels  # noqa: PLC0415

    ns, k = s["namespace"], s["keys"]
    keep = [k["master"]["secret"], k["models"]["secret"], k["backend"]["secret"]]
    src = k["backend"]["from"]
    pr = s["probe"]
    nsl = dict({"app.kubernetes.io/part-of": "inference", "pod-security.kubernetes.io/enforce": "restricted"},
               **namespace_route_labels(model, ns))
    return [
        {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns, "labels": nsl}},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": KEYS_SA, "namespace": ns}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": KEYS_SA, "namespace": ns},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": keep, "verbs": ["get", "patch"]},
                   {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": KEYS_SA, "namespace": ns},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": KEYS_SA},
         "subjects": [{"kind": "ServiceAccount", "name": KEYS_SA, "namespace": ns}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": f"{ns}-backend-key", "namespace": src["namespace"]},
         "rules": [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [src["secret"]], "verbs": ["get"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": f"{ns}-backend-key", "namespace": src["namespace"]},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": f"{ns}-backend-key"},
         "subjects": [{"kind": "ServiceAccount", "name": KEYS_SA, "namespace": ns}]},
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": pr["sa"], "namespace": ns}},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": pr["sa"], "namespace": ns},
         "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]},
        {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": pr["sa"], "namespace": ns},
         "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": pr["sa"]},
         "subjects": [{"kind": "ServiceAccount", "name": pr["sa"], "namespace": ns}]},
    ]


def keys_command(s: dict) -> str:
    ns, k = s["namespace"], s["keys"]
    src = k["backend"]["from"]
    lines = [f"sfab-keys ensure --namespace {ns} --secret {k['master']['secret']} --field {k['master']['field']} --prefix {k['master']['prefix']}"]
    for c in s["callers"]:
        if c["kind"] == "application":
            aud = " ".join(mint_audience_args(c))
            lines.append(f"sfab-keys mint --namespace {ns} --secret {k['models']['secret']} --prefix {k['models']['prefix']} --model {c['id']} --if-none"
                         + (f" {aud}" if aud else ""))
    lines.append(f"sfab-keys copy --from-namespace {src['namespace']} --from-secret {src['secret']} --field {k['backend']['field']} "
                 f"--namespace {ns} --secret {k['backend']['secret']}")
    return "set -e\n" + "\n".join(lines) + "\n"


def keys_job(s: dict) -> dict:
    lab = {"app.kubernetes.io/part-of": "inference", "app.kubernetes.io/component": "keys"}
    return {"apiVersion": "batch/v1", "kind": "Job", "metadata": {"name": KEYS_JOB, "namespace": s["namespace"], "labels": lab},
            "spec": {"backoffLimit": 2, "template": {"metadata": {"labels": lab}, "spec": {
                "serviceAccountName": KEYS_SA, "restartPolicy": "Never", "enableServiceLinks": False,
                "securityContext": _pod_security(UID_KEYS),
                "containers": [{"name": "keys", "image": s["keys_image"], "imagePullPolicy": "IfNotPresent",
                                "command": ["sh", "-c", keys_command(s)], "resources": JOB_RESOURCES,
                                "securityContext": _restricted()}]}}}}


def apisix_config(s: dict) -> str:
    """The API gateway's config.yaml: standalone (a data plane reading apisix.yaml), no Admin API."""
    from .k8s import dump  # noqa: PLC0415

    doc = {
        "deployment": {"role": "data_plane", "role_data_plane": {"config_provider": "yaml"}},
        "apisix": {"node_listen": s["gateway"]["port"], "enable_admin": False, "enable_control": False,
                   "enable_server_tokens": False, "enable_ipv6": False},
        "nginx_config": {"error_log": "/dev/stderr", "error_log_level": "warn", "worker_processes": 2,
                         "envs": [MASTER_ENV], "http": {"access_log": "/dev/stdout"}},
    }
    if s.get("callers_on"):
        # exactly the plugins the routes use (the default list would load every plugin of the image)
        doc["plugins"] = [p for p in PLUGINS if p != OIDC_PLUGIN or s.get("oidc")]
    return dump(doc)


def apisix_routes(s: dict, default_code: str | None = None) -> str:
    """The API gateway's base apisix.yaml: one route per model and its consumer group; the keys'
    consumers are added in each pod by sfab-keys compose. With default_code, that model's consumer
    restriction carries no rejected_code and no rejected_msg, so the plugin's own default answers
    (chapter 7's rejected-code drill applies it, and puts the rendered file back)."""
    from .k8s import dump  # noqa: PLC0415

    up = "router"
    routes, groups = [], []
    keyauth = {"header": "Authorization", "hide_credentials": True}
    oidc = s.get("oidc")
    for m in s["models"]:
        p = m["path"]
        cr = {"type": "consumer_group_id", "whitelist": list(m["callers"]), "rejected_code": s["rejected"]["code"],
              "rejected_msg": s["rejected"]["message"]}
        if default_code == m["name"]:
            cr = {"type": "consumer_group_id", "whitelist": list(m["callers"])}
        plugins: dict = {}
        if oidc:
            # a key first, then a token: the first that finds a consumer authenticates the request
            plugins["multi-auth"] = {"auth_plugins": [{"key-auth": dict(keyauth)}, {OIDC_PLUGIN: dict(oidc)}]}
        else:
            plugins["key-auth"] = dict(keyauth)
        plugins["consumer-restriction"] = cr
        plugins["proxy-rewrite"] = {"regex_uri": [f"^{p}/v1/(chat/completions|completions)$", f"/engines/{m['name']}/$1"],
                                    "headers": {"set": {"Authorization": "Bearer ${{" + MASTER_ENV + "}}"}}}
        if s.get("callers_on"):
            plugins["response-rewrite"] = {"headers": {"set": {"WWW-Authenticate": s["www_authenticate"]}}, "vars": [["status", "==", 401]]}
            plugins["file-logger"] = {"path": "/dev/stdout", "log_format": dict(ACCESS_LOG)}
        routes.append({
            "id": m["name"], "name": m["name"], "uris": [f"{p}/v1/chat/completions", f"{p}/v1/completions"], "methods": ["POST"],
            "upstream_id": up, "plugins": plugins,
        })
        if not s.get("callers_on"):
            desc = f"the keys for model {m['name']}"
            groups.append({"id": m["name"], "desc": f"{m['decision']}: {desc}" if m.get("decision") else desc, "plugins": {}})
    consumers = []
    if s.get("callers_on"):
        for c in s["callers"]:
            what = (f"application {c['id']} (owner {c['owner']}, keys expire {c['expires']})" if c["kind"] == "application"
                    else f"people: {', '.join(c['people'])}")
            desc = f"{what}; may call {', '.join(c['models'])}"
            gp: dict = {}
            if c.get("limit"):
                # one count for the whole group, kept in each API gateway pod (policy local)
                gp["limit-count"] = {"count": c["limit"]["count"], "time_window": c["limit"]["window_s"], "key_type": "var",
                                     "key": "consumer_group_id", "rejected_code": 429, "policy": "local"}
            groups.append({"id": c["id"], "desc": f"{c['decision']}: {desc}" if c.get("decision") else desc, "plugins": gp})
            for x in c.get("consumers") or []:
                consumers.append({"username": x["username"], "group_id": c["id"], "plugins": {OIDC_PLUGIN: {"subject": x["subject"]}}})
    t = s["timeouts"]
    doc = {"routes": routes,
           "upstreams": [{"id": up, "type": "roundrobin", "scheme": "http", "pass_host": "pass",
                          "nodes": [{"host": s["router"]["host"], "port": s["router"]["port"], "weight": 1}],
                          "timeout": {"connect": 5, "send": t["gateway_read_s"], "read": t["gateway_read_s"]}}],
           "consumer_groups": groups}
    if consumers:
        doc["consumers"] = consumers
    return dump(doc) + "#END\n"


def router_config(s: dict) -> str:
    """The router's config.yaml: one deployment per model, on the model's Service."""
    from .k8s import dump  # noqa: PLC0415

    t = s["timeouts"]
    ml = [{"model_name": m["name"], "litellm_params": {"model": f"openai/{m['name']}", "api_base": m["api_base"],
                                                      "api_key": f"os.environ/{BACKEND_ENV}", "timeout": t["router_attempt_s"],
                                                      "stream_timeout": t["router_stream_s"], "max_retries": 0}}
          for m in s["models"]]
    return dump({
        "model_list": ml,
        "router_settings": {"routing_strategy": "simple-shuffle", "num_retries": t["router_retries"], "timeout": t["router_attempt_s"],
                            "retry_after": 0},
        "litellm_settings": {"num_retries": t["router_retries"], "request_timeout": t["router_attempt_s"], "drop_params": True,
                             "telemetry": False},
        "general_settings": {"master_key": f"os.environ/{MASTER_ENV}"},
    })


def _secret_env(name: str, secret: str, key: str) -> dict:
    return {"name": name, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}}


def _spread(labels: dict) -> list:
    return [{"maxSkew": 1, "topologyKey": "kubernetes.io/hostname", "whenUnsatisfiable": "ScheduleAnyway",
             "labelSelector": {"matchLabels": dict(labels)}}]


def gateway_docs(s: dict) -> list:
    g, ns, k = s["gateway"], s["namespace"], s["keys"]
    sel = {"app.kubernetes.io/name": g["name"]}
    cfg, base = apisix_config(s), apisix_routes(s)
    compose = ["sfab-keys", "compose", "--base", "/base/apisix.yaml", "--keys", "/keys", "--out", f"{STANDALONE}/apisix.yaml",
               "--format", KEY_FORMAT]
    mounts = [{"name": "base", "mountPath": "/base", "readOnly": True}, {"name": "keys", "mountPath": "/keys", "readOnly": True},
              {"name": "standalone", "mountPath": STANDALONE}]
    gw_mounts = [{"name": "config", "mountPath": f"{APISIX_PREFIX}/conf/config.yaml", "subPath": "config.yaml", "readOnly": True},
                 {"name": "standalone", "mountPath": f"{APISIX_PREFIX}/conf/apisix.yaml", "subPath": "apisix.yaml"}]
    volumes = [{"name": "config", "configMap": {"name": f"{g['name']}-config"}},
               {"name": "base", "configMap": {"name": f"{g['name']}-routes"}},
               {"name": "keys", "secret": {"secretName": k["models"]["secret"], "defaultMode": 0o440}},
               {"name": "standalone", "emptyDir": {}}]
    plugin_src = plugin_source() if s.get("oidc") else None
    if plugin_src is not None:
        gw_mounts.append({"name": "plugins", "mountPath": f"{APISIX_PREFIX}/apisix/plugins/{OIDC_PLUGIN}.lua",
                          "subPath": f"{OIDC_PLUGIN}.lua", "readOnly": True})
        volumes.append({"name": "plugins", "configMap": {"name": s["configmaps"]["plugins"]}})
    pod = {
        "metadata": {"labels": dict(_labels(g["name"], "api-gateway"), **sel),
                     "annotations": {f"{s['labels']['prefix']}/config": _stamp(cfg, base, plugin_src or "")}},
        "spec": {
            "automountServiceAccountToken": False, "enableServiceLinks": False, "terminationGracePeriodSeconds": 10,
            "securityContext": _pod_security(g["uid"]), "topologySpreadConstraints": _spread(sel), "dnsConfig": POD_DNS,
            "initContainers": [{"name": "compose", "image": s["keys_image"], "imagePullPolicy": "IfNotPresent",
                                "command": compose + ["--once"], "resources": SIDECAR_RESOURCES, "securityContext": _restricted(),
                                "volumeMounts": mounts}],
            "containers": [
                {"name": "apisix", "image": g["image"], "imagePullPolicy": "IfNotPresent", "command": ["/bin/sh", "-c", APISIX_START],
                 "env": [_secret_env(MASTER_ENV, k["master"]["secret"], k["master"]["field"])],
                 "ports": [{"name": "http", "containerPort": g["port"], "protocol": "TCP"}],
                 "readinessProbe": {"tcpSocket": {"port": "http"}, "periodSeconds": 5, "failureThreshold": 3},
                 "resources": GATEWAY_RESOURCES, "securityContext": _restricted(),
                 "volumeMounts": gw_mounts},
                {"name": "keys", "image": s["keys_image"], "imagePullPolicy": "IfNotPresent",
                 "command": compose + ["--hold", f"{STANDALONE}/hold"], "resources": SIDECAR_RESOURCES, "securityContext": _restricted(),
                 "volumeMounts": mounts},
            ],
            "volumes": volumes,
        },
    }
    pod["spec"].update(s.get("placement") or {})
    plugin_cm = []
    if plugin_src is not None:
        plugin_cm = [{"apiVersion": "v1", "kind": "ConfigMap",
                      "metadata": {"name": s["configmaps"]["plugins"], "namespace": ns, "labels": _labels(g["name"], "api-gateway")},
                      "data": {f"{OIDC_PLUGIN}.lua": plugin_src}}]
    return plugin_cm + [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{g['name']}-config", "namespace": ns, "labels": _labels(g["name"], "api-gateway")},
         "data": {"config.yaml": cfg}},
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{g['name']}-routes", "namespace": ns, "labels": _labels(g["name"], "api-gateway")},
         "data": {"apisix.yaml": base}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": g["name"], "namespace": ns, "labels": _labels(g["name"], "api-gateway")},
         "spec": {"replicas": g["replicas"], "selector": {"matchLabels": sel}, "template": pod}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": g["name"], "namespace": ns, "labels": _labels(g["name"], "api-gateway")},
         "spec": {"selector": sel, "ports": [{"name": "http", "port": g["port"], "targetPort": "http", "protocol": "TCP"}]}},
    ]


def plugin_source() -> str:
    """The lab's oidc-consumer plugin for APISIX, as the ConfigMap carries it."""
    from pathlib import Path  # noqa: PLC0415

    return (Path(__file__).resolve().parent / OIDC_SOURCE).read_text(encoding="utf-8")


def router_docs(s: dict) -> list:
    r, ns, k = s["router"], s["namespace"], s["keys"]
    sel = {"app.kubernetes.io/name": r["name"]}
    cfg = router_config(s)
    env = [_secret_env(MASTER_ENV, k["master"]["secret"], k["master"]["field"]),
           _secret_env(BACKEND_ENV, k["backend"]["secret"], k["backend"]["field"]),
           {"name": "HOME", "value": "/tmp"}, {"name": "LITELLM_LOCAL_MODEL_COST_MAP", "value": "True"},
           {"name": "DISABLE_ADMIN_UI", "value": "True"}]
    pod = {
        "metadata": {"labels": dict(_labels(r["name"], "router"), **sel), "annotations": {f"{s['labels']['prefix']}/config": _stamp(cfg)}},
        "spec": {
            "automountServiceAccountToken": False, "enableServiceLinks": False, "terminationGracePeriodSeconds": 10,
            "securityContext": _pod_security(UID_ROUTER), "topologySpreadConstraints": _spread(sel), "dnsConfig": POD_DNS,
            "containers": [{"name": "router", "image": r["image"], "imagePullPolicy": "IfNotPresent",
                            "args": ["--config", f"{ROUTER_CONFIG}/config.yaml", "--port", str(r["port"])], "env": env,
                            "ports": [{"name": "http", "containerPort": r["port"], "protocol": "TCP"}],
                            "readinessProbe": {"httpGet": {"path": "/health/readiness", "port": "http"}, "periodSeconds": 5,
                                               "timeoutSeconds": 3, "failureThreshold": 3},
                            "resources": ROUTER_RESOURCES, "securityContext": _restricted(),
                            "volumeMounts": [{"name": "config", "mountPath": ROUTER_CONFIG, "readOnly": True},
                                             {"name": "tmp", "mountPath": "/tmp"}]}],
            "volumes": [{"name": "config", "configMap": {"name": f"{r['name']}-config"}}, {"name": "tmp", "emptyDir": {}}],
        },
    }
    pod["spec"].update(s.get("placement") or {})
    return [
        {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {"name": f"{r['name']}-config", "namespace": ns, "labels": _labels(r["name"], "router")},
         "data": {"config.yaml": cfg}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": r["name"], "namespace": ns, "labels": _labels(r["name"], "router")},
         "spec": {"replicas": r["replicas"], "selector": {"matchLabels": sel}, "template": pod}},
        {"apiVersion": "v1", "kind": "Service", "metadata": {"name": r["name"], "namespace": ns, "labels": _labels(r["name"], "router")},
         "spec": {"selector": sel, "ports": [{"name": "http", "port": r["port"], "targetPort": "http", "protocol": "TCP"}]}},
    ]


def route_docs(model: Model, s: dict) -> list:
    from .k8s import _decision  # noqa: PLC0415

    out = []
    t = s["timeouts"]
    for rt in s["routes"]:
        labels = {}
        if "audience" in model.k8s.labels and rt["audience"]:
            labels[model.k8s.labels["audience"]] = rt["audience"]
        labels.update(_decision(model, rt["decision"]))
        out.append({
            "apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
            "metadata": {"name": rt["name"], "namespace": s["namespace"], "labels": labels},
            "spec": {
                "parentRefs": [{"group": "gateway.networking.k8s.io", "kind": "Gateway", "name": rt["gateway"],
                                "namespace": rt["namespace"], "sectionName": rt["section"]}],
                "hostnames": list(rt["hostnames"]),
                "rules": [{"matches": [{"path": {"type": "PathPrefix", "value": x["path"]}}],
                           "backendRefs": [{"name": s["gateway"]["name"], "port": s["gateway"]["port"]}],
                           "timeouts": {"request": f"{t['request_s']}s", "backendRequest": f"{t['backend_request_s']}s"}}
                          for x in rt["rules"]],
            },
        })
    return out


def render(model: Model, ctx) -> dict:
    """bootstrap/k8s/60-, 61- and 62-*.yaml, or nothing when the lab serves no model."""
    if not enabled(model):
        return {}
    from .k8s import header, yaml_file  # noqa: PLC0415

    s = settings(model)
    base = "bootstrap/k8s"
    t = s["timeouts"]
    return {
        f"{base}/{FILES['base']}": yaml_file(header(model, "inference: namespace and the key Job's roles", ctx) + [
            f"The API gateway's and the router's namespace, and the account of the key Job (61): get and patch on the three",
            f"Secrets it keeps and create here, and get on the serving recipe's key Secret in {s['serving_namespace']}, which it copies.",
            f"The per-pod key probe's account, {s['probe']['sa']}, may get and list this namespace's pods.",
        ], base_docs(model, s)),
        f"{base}/{FILES['keys']}": yaml_file(header(model, "inference: the key Job", ctx) + [
            "Run once by finish after the serving recipe and removed after: the router's master key, one key per model (the",
            "first only: --if-none) and the recipe's key copied for the router. Every key is made or copied here and never",
            "printed; the Job's log names each by its fingerprint.",
        ], [keys_job(s)]),
        f"{base}/{FILES['layer']}": yaml_file(header(model, "inference: the API gateway, the router and the model routes", ctx) + [
            f"Router attempts of {t['router_attempt_s']} s, {t['router_stream_s']} s of silence in a stream ({t['router_retries']} "
            f"retr{'y' if t['router_retries'] == 1 else 'ies'}) inside the API gateway's read of "
            f"{t['gateway_read_s']} s, inside backendRequest {t['backend_request_s']} s, inside request {t['request_s']} s.",
            ("Each caller is a consumer group: an application's keys are consumers composed into each API gateway pod from the"
             " mounted Secret, a person a consumer matched on the verified email of an OIDC token; each model's route admits"
             " the groups that may call it." if s.get("callers_on") else
             "Each model's key is a consumer of the model's group, composed into each API gateway pod from the mounted Secret."),
        ], gateway_docs(s) + router_docs(s) + route_docs(model, s)),
    }


def summary(model: Model) -> dict | None:
    if not enabled(model):
        return None
    s = settings(model)
    return json.loads(json.dumps(s))


__all__ = ["render", "settings", "summary", "enabled", "FILES"]
