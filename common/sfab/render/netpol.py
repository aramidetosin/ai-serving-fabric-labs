"""Network policy in the cluster (build A revision 2; FRAMEWORK.md 2.2), with k8s.network_policy.

Every namespace the render puts workloads in gets one CiliumNetworkPolicy that selects every pod of
the namespace and denies all ingress and egress (a rule {} selects no peer: Cilium's default deny),
then one allow per path a request needs, each naming its peers by label and its ports:

  echo (the test backend)    in: the Gateways' Envoy (Cilium's reserved ingress identity) on its port
  identity (the IdP)         in: the Gateways' Envoy and the API gateway on the IdP's port
  inference                  the API gateway: in from the Gateways' Envoy and from the key probe on
                             its port; out to the router, to the IdP's keys, and DNS. The router: in
                             from the API gateway; out to the model servers, and DNS. The key Jobs
                             and the key probe: out to the API server; the key probe also to the
                             API gateway
  serving                    the model servers: in from the router and from the Gateways' Envoy (the
                             recipe's own route) on the HTTP port. The recipe's key Job: out to the
                             API server. The workers take nothing over the cluster network: their
                             RPC runs on the rails, macvlan attachments Cilium's policy does not see

The policies are written in two files: 58-network-policy.yaml (apply.list: the namespaces that exist
when finish applies, the test backend's and the IdP's) and, with serving on, 63-inference-policy.yaml,
which finish applies after the serving recipe and the API gateway (the serving namespace is the
recipe's own: its delete removes it).
"""

from __future__ import annotations

from ..model import Model
from . import RenderError

FILES = {"base": "58-network-policy.yaml", "inference": "63-inference-policy.yaml"}
API = "cilium.io/v2"
NS_KEY = "k8s:io.kubernetes.pod.namespace"
DNS_PEER = {"matchLabels": {NS_KEY: "kube-system", "k8s:k8s-app": "kube-dns"}}
DNS_PORTS = [{"ports": [{"port": "53", "protocol": "UDP"}, {"port": "53", "protocol": "TCP"}]}]
API_PORTS = [{"ports": [{"port": "6443", "protocol": "TCP"}]}]


def enabled(model: Model) -> bool:
    np = ((model.spec or {}).get("k8s") or {}).get("network_policy") or {}
    if not np:
        return False
    if np.get("default") != "deny":
        raise RenderError("spec k8s.network_policy.default must be deny (the allows are rendered per path)")
    return True


def _ports(port: int) -> list:
    return [{"ports": [{"port": str(int(port)), "protocol": "TCP"}]}]


def _sel(labels: dict, ns: str | None = None) -> dict:
    m = {f"k8s:{k}": v for k, v in labels.items()}
    if ns:
        m[NS_KEY] = ns
    return {"matchLabels": m}


def _cnp(name: str, ns: str, desc: str, selector: dict, ingress: list | None = None, egress: list | None = None) -> dict:
    spec: dict = {"description": desc, "endpointSelector": selector}
    if ingress is not None:
        spec["ingress"] = ingress
    if egress is not None:
        spec["egress"] = egress
    return {"apiVersion": API, "kind": "CiliumNetworkPolicy", "metadata": {"name": name, "namespace": ns}, "spec": spec}


def default_deny(ns: str) -> dict:
    return _cnp("default-deny", ns, f"every pod in {ns}: no ingress and no egress but what an allow names",
                {}, ingress=[{}], egress=[{}])


def _identity(model: Model) -> dict | None:
    from . import identity  # noqa: PLC0415

    return identity.settings(model) if identity.enabled(model) else None


def base_docs(model: Model) -> list:
    from .k8s import test_backend_settings  # noqa: PLC0415

    docs: list = []
    tb = test_backend_settings(model)
    if tb and tb["gateways"]:
        ns, sel = str(tb["namespace"]), {"app.kubernetes.io/name": str(tb["name"])}
        docs += [default_deny(ns),
                 _cnp("allow-gateways-to-backend", ns, "the Gateways' Envoy to the test backend", _sel(sel),
                      ingress=[{"fromEntities": ["ingress"], "toPorts": _ports(int(tb["port"]))}])]
    idp = _identity(model)
    if idp:
        ns, sel = idp["namespace"], {"app.kubernetes.io/name": idp["name"]}
        ing = [{"fromEntities": ["ingress"], "toPorts": _ports(idp["port"])}]
        from . import inference  # noqa: PLC0415

        if inference.enabled(model):
            inf = inference.settings(model)
            ing.append({"fromEndpoints": [_sel({"app.kubernetes.io/name": inf["gateway"]["name"]}, inf["namespace"])],
                        "toPorts": _ports(idp["port"])})
        docs += [default_deny(ns),
                 _cnp("allow-to-idp", ns, "the Gateways' Envoy (people signing in) and the API gateway (the signing keys) to the IdP",
                      _sel(sel), ingress=ing)]
    return docs


def inference_docs(model: Model) -> list:
    from . import inference  # noqa: PLC0415
    from .k8s import serving_summary  # noqa: PLC0415

    if not inference.enabled(model):
        return []
    inf = inference.settings(model)
    sv = serving_summary(model)
    ns, sns = inf["namespace"], sv["namespace"]
    gw, ro = inf["gateway"], inf["router"]
    gsel, rsel = {"app.kubernetes.io/name": gw["name"]}, {"app.kubernetes.io/name": ro["name"]}
    probe = {"app.kubernetes.io/component": "key-probe", "app.kubernetes.io/part-of": "inference"}
    keys = {"app.kubernetes.io/component": "keys", "app.kubernetes.io/part-of": "inference"}
    http = int(sv["ports"]["http"])
    server = {"app.kubernetes.io/name": "serving", "app.kubernetes.io/component": "server"}
    gw_egress = [{"toEndpoints": [_sel(rsel, ns)], "toPorts": _ports(ro["port"])}, {"toEndpoints": [DNS_PEER], "toPorts": DNS_PORTS}]
    idp = _identity(model)
    if idp:
        gw_egress.insert(1, {"toEndpoints": [_sel({"app.kubernetes.io/name": idp["name"]}, idp["namespace"])], "toPorts": _ports(idp["port"])})
    docs = [
        default_deny(ns),
        _cnp("allow-api-gateway", ns, "the API gateway: in from the Gateways' Envoy and the key probe; out to the router, the IdP's keys and DNS",
             _sel(gsel),
             ingress=[{"fromEntities": ["ingress"], "toPorts": _ports(gw["port"])},
                      {"fromEndpoints": [_sel(probe, ns)], "toPorts": _ports(gw["port"])}],
             egress=gw_egress),
        _cnp("allow-router", ns, "the router: in from the API gateway; out to the model servers and DNS", _sel(rsel),
             ingress=[{"fromEndpoints": [_sel(gsel, ns)], "toPorts": _ports(ro["port"])}],
             egress=[{"toEndpoints": [_sel(server, sns)], "toPorts": _ports(http)}, {"toEndpoints": [DNS_PEER], "toPorts": DNS_PORTS}]),
        _cnp("allow-key-jobs", ns, "the key Jobs: out to the API server", _sel(keys),
             egress=[{"toEntities": ["kube-apiserver"], "toPorts": API_PORTS}]),
        _cnp("allow-key-probe", ns, "the key probe: out to the API server (it lists the API gateway's pods) and to each API gateway pod",
             _sel(probe),
             egress=[{"toEntities": ["kube-apiserver"], "toPorts": API_PORTS}, {"toEndpoints": [_sel(gsel, ns)], "toPorts": _ports(gw["port"])}]),
        default_deny(sns),
        _cnp("allow-to-servers", sns, "the model servers: in from the router and from the Gateways' Envoy (the recipe's own route)",
             _sel(server),
             ingress=[{"fromEndpoints": [_sel(rsel, ns)], "toPorts": _ports(http)}, {"fromEntities": ["ingress"], "toPorts": _ports(http)}]),
        _cnp("allow-key-job", sns, "the recipe's key Job: out to the API server",
             _sel({"app.kubernetes.io/name": "serving", "app.kubernetes.io/component": "key"}),
             egress=[{"toEntities": ["kube-apiserver"], "toPorts": API_PORTS}]),
    ]
    return docs


def summary(model: Model) -> dict | None:
    if not enabled(model):
        return None
    out = {"files": dict(FILES), "base": [], "inference": []}
    for key, docs in (("base", base_docs(model)), ("inference", inference_docs(model))):
        out[key] = [{"namespace": d["metadata"]["namespace"], "name": d["metadata"]["name"]} for d in docs]
    return out


def render(model: Model, ctx) -> dict:
    if not enabled(model):
        return {}
    from .k8s import header, yaml_file  # noqa: PLC0415

    out = {}
    base = base_docs(model)
    if base:
        out[f"bootstrap/k8s/{FILES['base']}"] = yaml_file(header(model, "network policy: the test backend and the IdP", ctx) + [
            "Each namespace: one CiliumNetworkPolicy that denies every pod all ingress and egress, then the allows its",
            "paths need. Cilium's ingress identity is the Gateways' Envoy.",
        ], base)
    inf = inference_docs(model)
    if inf:
        out[f"bootstrap/k8s/{FILES['inference']}"] = yaml_file(header(model, "network policy: the API gateway, the router and the models", ctx) + [
            "Applied by finish after the serving recipe and the API gateway. Default deny in both namespaces, then the",
            "request path: the Gateways' Envoy to the API gateway, the API gateway to the router (and the IdP's keys),",
            "the router to the model servers. The rails are macvlan attachments, outside Cilium's policy.",
        ], inf)
    return out


__all__ = ["render", "summary", "enabled", "FILES"]
