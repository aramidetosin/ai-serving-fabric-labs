"""The inventory blocks the M2 harness reads (finish, the audit's collection plans and judges,
dev/m2/trace.sh) beside the ones render/inventory.py writes today: gateways, populations, dns,
k8s, registry, ca and ntp, and the CSI settings of each storage node.

This is the reference for render/inventory.py, which emits exactly these keys (services() and
storage_csi() there); test_m2.SelectionTest holds the two equal, and augment() adds nothing to a
current render. Every value comes from the model (sfab.model) or, where the model has no field for
it yet, from model.spec, the merged profile tree, as the comments say. Standard library and sfab only.

    from services_block import augment, services
    inv = json.load(open("gen/inventory.json"))
    augment(inv, model)            # adds whatever keys the inventory lacks
"""

from __future__ import annotations

from typing import Any


def _ip(cidr):
    return None if cidr is None else str(cidr).split("/")[0]


def services(m) -> dict:
    """The blocks, from a selected sfab.model.Model."""
    spec = m.spec or {}
    out: dict[str, Any] = {}
    out["gateways"] = {
        g.name: {"vip": g.vip, "pool": [g.pool_start, g.pool_end], "pool_cidrs": list(g.pool_cidrs),
                 "audience": g.audience, "hostnames": list(g.hostnames), "segment": g.segment, "decision": g.decision}
        for g in m.gateways.values()
    }
    aud_gw = {a.name: a.gateway for a in m.audiences.values()}
    out["populations"] = {
        p.name: {"segments": list(p.segments), "prefixes": list(p.prefixes), "zones": list(p.zones),
                 "audience": p.audience, "gateway": aud_gw.get(p.audience), "clients": list(p.clients),
                 "resolver": p.resolver, "resolver_address": p.resolver_address, "resolvers": list(p.resolvers), "answer": p.answer,
                 "answer_address": p.answer_address, "translated": p.translated}
        for p in m.populations.values()
    }
    if m.dns is None:
        out["dns"] = None
    else:
        views = [v for v in m.dns.views]
        out["dns"] = {
            "zone": m.dns.zone, "users": list(m.dns.users), "admin": list(m.dns.admin), "internal": list(m.dns.internal),
            "identity": list(m.dns.identity), "wildcard": m.dns.wildcard,
            "records": {r.name: r.address for r in m.dns.records},
            "views": {v.name: {"server": v.server, "servers": [x for x in v.servers if x in m.nodes], "kind": v.kind,
                               "match_cidrs": list(v.match_cidrs), "answer_address": v.answer_address, "recursion": v.recursion,
                               "infra": v.infra, "names": list(m.dns.names_of(v))}
                      for v in views},
            "resolvers": {r.name: {"servers": [x for x in r.servers if x in m.nodes], "kind": r.kind, "clients": list(r.client_cidrs),
                                   "to": [x for x in r.to if x in m.nodes], "local": list(r.local)}
                          for r in m.dns.resolvers},
            # one TSIG key per view a secondary transfers: <view>-xfr
            "tsig": [f"{v.name}-xfr" for v in views if len([x for x in v.servers if x in m.nodes]) > 1],
        }
    k = m.k8s
    if k is None:
        out["k8s"] = None
    else:
        ks = spec.get("k8s") or {}
        tb = dict(spec.get("test_backend") or {})
        if tb.get("gateways"):
            # the Gateways of this state only (gw-inet joins the list from chapter 8)
            tb["gateways"] = [g for g in tb["gateways"] if g in m.gateways]
        out["k8s"] = {
            "version": k.version, "api_vip": k.api_vip, "api_fqdn": k.api_fqdn, "pod_cidr": k.pod_cidr,
            "service_cidr": k.service_cidr, "init": k.init, "control": list(k.control), "workers": list(k.workers),
            "gateway_class": k.gateway_class, "labels": dict(k.labels), "l2_announce": dict(k.l2_announce),
            # not in the model yet: spec k8s.cilium_devices, gateway_namespace, listener; test_backend
            "cilium_devices": list(ks.get("cilium_devices") or []),
            "gateway_namespace": ks.get("gateway_namespace"),
            # the harness's kubectl runs on the init node with kubeadm's admin kubeconfig
            "admin_node": k.init, "admin_kubeconfig": "/etc/kubernetes/admin.conf",
            "test_backend": {key: tb.get(key) for key in ("name", "namespace", "port", "path", "replicas", "gateways")} if tb else None,
        }
    r = m.registry
    if r is None:
        out["registry"] = None
    else:
        rs = spec.get("registry") or {}
        out["registry"] = {"node": r.node, "address": r.address, "port": r.port, "mirror": r.mirror, "fqdn": r.fqdn,
                           # not in the model yet: spec registry.scheme, upstreams, charts
                           "scheme": rs.get("scheme", "http"), "upstreams": list(rs.get("upstreams") or []),
                           "charts": rs.get("charts", "charts")}
    c = m.ca
    cs = spec.get("ca") or {}
    leaf_nodes = [lf for lf in cs.get("leaves") or [] if lf.get("node") in m.nodes]
    # the lab runs its CA when Kubernetes is on or a leaf's node is in the lab
    if c is None or not cs or not ((m.features or {}).get("k8s") or leaf_nodes):
        out["ca"] = None
    else:
        def node_ref(x):
            x = str(x)
            return _ip(m.nodes[x[5:]].address) if x.startswith("node:") and x[5:] in m.nodes else x
        leaves = {lf["id"]: {"ca": lf["ca"], "node": lf["node"], "dns": list(lf.get("dns") or []),
                             "ip": [node_ref(x) for x in lf.get("ip") or []], "dir": f"state/tls/{lf['node']}"}
                  for lf in leaf_nodes}
        out["ca"] = {"root_cn": c.root_cn,
                     "intermediates": {i.name: {"cn": i.cn, "key": i.key, "dns": list(i.dns), "ip": list(i.ip)} for i in c.intermediates},
                     "proof_inside": list(c.proof_inside), "proof_outside": list(c.proof_outside),
                     # not in the model yet: spec ca.issuer and ca.certificates
                     "issuer": cs.get("issuer"),
                     "certificates": [x for x in cs.get("certificates") or [] if x.get("gateway") is None or x.get("gateway") in m.gateways],
                     # kept on the lab host by common/ca/sfab-ca
                     "conf": "bootstrap/ca", "state": "state/ca", "root": "state/shared/ca/root.crt", "leaves": leaves}
    nt = spec.get("ntp") or {}
    names = [x for x in nt.get("servers") or [] if x in m.nodes]
    up = nt.get("upstream")
    out["ntp"] = None if not nt else {
        "servers": {x: _ip(m.nodes[x].address) for x in names},
        "upstream": {"node": up, "address": _ip(m.nodes[up].address)} if up in m.nodes else None,
        "nts": bool(nt.get("nts")) and up in m.nodes, "allow": list(nt.get("allow") or []),
        "local_stratum": nt.get("local_stratum"), "reference_stratum": nt.get("reference_stratum")}
    return out


def storage_csi(m) -> dict:
    """Per storage node: its CSI settings (spec storage.csi), for nodes.<name>.csi."""
    out = {}
    for s in m.storage.values():
        csi = (s.settings or {}).get("csi")
        if csi:
            out[s.name] = {"user": csi.get("user"), "api": csi.get("api"), "classes": list(csi.get("classes") or []),
                           "default_class": csi.get("default_class")}
    return out


def augment(inv: dict, m) -> dict:
    """Add every block the inventory lacks (a key render/inventory.py already writes is kept)."""
    for k, v in services(m).items():
        inv.setdefault(k, v)
    for name, csi in storage_csi(m).items():
        if name in (inv.get("nodes") or {}):
            inv["nodes"][name].setdefault("csi", csi)
    return inv
