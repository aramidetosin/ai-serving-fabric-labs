"""The lab CA (FRAMEWORK.md sections 0, 2.2, 3.2 and 5; chapter 7).

The CA lives on the lab host, outside every node: sfab-ca (common/ca/sfab-ca) makes and keeps its
keys under the lab's state/ca (mode 0700, every key 0600), which no topology binds into any node.
This module renders what sfab-ca needs, under the lab's own bootstrap/ca/:

- root.cnf: the root's subject and extensions (CA, path length 1). sfab-ca makes the root key and
  self-signs the root from it once, on the first `sfab-ca init` (make ca, and the up stage before
  every deploy); the root key is used only to sign the intermediates.
- <intermediate>.cnf, one per spec intermediate: its subject, key type, and critical name
  constraints, which are the spec's names and address ranges (RFC 5280 section 4.2.1.10), with
  path length 0. sfab-ca signs it with the root, and signs it again only when the certificate
  is missing, does not match its key, does not chain to the root, expires within RENEW_DAYS, or
  was signed from different constraints.
- leaf-<leaf>.cnf, one per spec leaf whose node is in the lab: a server certificate sfab-ca signs on
  the lab host with the leaf's intermediate (the registry's, the time reference's), its key, its
  certificate and its chain (the leaf, then the intermediate) written to state/tls/<node>/, which
  the topology binds read-only into that node only.
- proof.json: the leaves sfab-ca signs with each intermediate and verifies against the root.
  Inside leaves must verify: each intermediate's proof names (its own, else the spec's
  ca.proof.inside), what the lab really issues (each certificate cert-manager issues from the
  issuer's intermediate, ca.certificates; kubeadm's API server certificate on each control node from
  the Kubernetes CA; each node leaf). Outside leaves must fail with a name-constraint error: each
  intermediate's outside names and the firewall's public address.

The [sfab] section of each .cnf carries what OpenSSL itself does not read: the key type, the
validity in days, the renewal window, and the role (kubeadm: the intermediate the init node's
kubeadm signs the cluster with, published to state/shared/cluster/ca; gateways: the one
cert-manager's issuer signs with, ca.issuer.intermediate, written as a Secret in the cluster from the
lab host; upstream: an intermediate that signs node leaves only, its key never leaving state/ca).
Nothing rendered here is a secret.

Rendered when the spec has a CA and the lab needs it: Kubernetes on, or a leaf's node in the lab.
"""

from __future__ import annotations

import ipaddress
import json
import re

from ..model import Ca, CaIntermediate, CaLeaf, Model

# What each spec key type means to OpenSSL.
KEY_TYPES = {"ec-p256", "ec-p384", "rsa-2048", "rsa-3072", "rsa-4096"}
# The root's key type when the spec does not name one (ca.root.key).
ROOT_KEY = "ec-p256"
ROOT_DAYS = 3650
INTERMEDIATE_DAYS = 1826
RENEW_DAYS = 90
# A node leaf: a server certificate's lifetime and renewal window, and its key type.
LEAF_DAYS = 397
LEAF_RENEW_DAYS = 30
LEAF_KEY = "ec-p256"
# Where the lab's own render puts the CA's files (under the lab directory, not under a node).
CA_DIR = "bootstrap/ca"
# Where sfab-ca writes a node leaf on the lab host, and where the topology binds it in the node.
TLS_STATE = "state/tls"
TLS_BOUND = "/sfab/tls"

# The intermediate kubeadm signs the cluster with, and the one cert-manager's issuer signs with
# when the spec names no ca.issuer.
KUBEADM_CA = "kubernetes"
ISSUER_CA = "platform"
# kubeadm's default cluster DNS domain; its API server certificate names
# kubernetes.default.svc.<domain>.
KUBEADM_DNS_DOMAIN = "cluster.local"

_DNS = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
_SUBJ_BAD = re.compile(r"[$/\\\n=#]")


class CaRenderError(ValueError):
    """The spec's CA cannot be rendered."""


# --------------------------------------------------------------------------------------------
# helpers


def bastion_of(model: Model):
    for n in model.hosts.values():
        if n.kind == "bastion" and not n.pending:
            return n
    return None


def lab_leaves(model: Model) -> list:
    """The spec's leaves whose node is in this lab."""
    if model.ca is None:
        return []
    return [lf for lf in model.ca.leaves if lf.node in model.nodes and not model.nodes[lf.node].pending]


def ca_on(model: Model) -> bool:
    """The lab renders and runs its CA: the spec has one, and Kubernetes is on or a leaf's node is in
    the lab."""
    return model.ca is not None and (bool(model.features.get("k8s")) or bool(lab_leaves(model)))


def leaf_of(model: Model, node: str) -> CaLeaf | None:
    for lf in lab_leaves(model):
        if lf.node == node:
            return lf
    return None


def header(model: Model, what: str, ctx) -> str:
    return f"# {model.lab} lab CA, {what}: rendered from {ctx.profile_file(model)} by render/ca.py; edit the spec and run make render"


def _spec_ca(model: Model) -> dict:
    """The spec's ca block as written (model.spec, the merged profile tree). The model carries the
    root, the intermediates and the proof names; the root's key type, the issuer and the issued
    certificates are read here until the model carries them."""
    t = (model.spec or {}).get("ca")
    return t if isinstance(t, dict) else {}


def _subject_value(v: str, what: str) -> str:
    if not v or _SUBJ_BAD.search(v):
        raise CaRenderError(f"{what} {v!r}: a subject value may not be empty or hold $ / \\ = # or a newline")
    return v


def _key(k: str, what: str) -> str:
    if k not in KEY_TYPES:
        raise CaRenderError(f"{what}: key type {k!r} is not one of {', '.join(sorted(KEY_TYPES))}")
    return k


def san(name: str) -> str:
    """'DNS:<name>' or 'IP:<address>'."""
    try:
        return f"IP:{ipaddress.ip_address(name)}"
    except ValueError:
        pass
    n = name.lower()
    if not _DNS.match(n.removeprefix("*.")):
        raise CaRenderError(f"{name!r} is neither an address nor a DNS name")
    return f"DNS:{n}"


def name_constraints(i: CaIntermediate) -> str:
    """The OpenSSL nameConstraints value: critical, one permitted subtree per spec name and range."""
    parts = []
    for d in i.dns:
        dn = str(d).lower()
        if dn.startswith("*") or not _DNS.match(dn):
            raise CaRenderError(f"intermediate {i.name}: {d!r} is not a DNS name constraint")
        parts.append(f"permitted;DNS:{dn}")
    for p in i.ip:
        try:
            net = ipaddress.ip_network(str(p), strict=True)
        except ValueError as e:
            raise CaRenderError(f"intermediate {i.name}: {p!r} is not a prefix ({e})") from None
        parts.append(f"permitted;IP:{net.network_address}/{net.netmask}")
    if not parts:
        raise CaRenderError(f"intermediate {i.name}: no name constraints; every intermediate is constrained")
    return "critical," + ",".join(parts)


def permits(i: CaIntermediate, s: str) -> bool:
    """Whether the intermediate's constraints permit one SAN (RFC 5280 section 4.2.1.10): a DNS
    name equal to a constraint or below it, an address inside a range. A type the intermediate
    does not constrain is permitted."""
    kind, _, value = s.partition(":")
    if kind == "DNS":
        if not i.dns:
            return True
        v = value.lower()
        return any(v == c.lower() or v.endswith("." + c.lower()) for c in i.dns)
    if kind == "IP":
        if not i.ip:
            return True
        a = ipaddress.ip_address(value)
        return any(a in ipaddress.ip_network(str(p)) for p in i.ip)
    raise CaRenderError(f"unknown SAN {s!r}")


def issuer_ca(model: Model) -> str:
    """The intermediate cert-manager's issuer signs with (ca.issuer.intermediate)."""
    iss = _spec_ca(model).get("issuer")
    if isinstance(iss, dict) and iss.get("intermediate"):
        return str(iss["intermediate"])
    return ISSUER_CA


def roles(model: Model) -> dict:
    """{intermediate: role}: kubeadm, gateways, upstream (signs the node leaves only), or other."""
    out = {}
    issuer = issuer_ca(model)
    leaf_cas = {lf.ca for lf in model.ca.leaves}
    for i in model.ca.intermediates:
        if i.name == KUBEADM_CA:
            out[i.name] = "kubeadm"
        elif i.name == issuer:
            out[i.name] = "gateways"
        elif i.name in leaf_cas:
            out[i.name] = "upstream"
        else:
            out[i.name] = "other"
    return out


def _cert_name(model: Model, n: str) -> str:
    """A name in ca.certificates: 'wildcard' is the platform zone's wildcard name (a certificate
    name only: the zone publishes no wildcard record), a bare label is under the zone, anything
    else is as written."""
    if n == "wildcard":
        return model.org.fqdn("*")
    if "." not in n:
        return model.org.fqdn(n)
    return n


def issued_certificates(model: Model) -> list:
    """What cert-manager issues from the issuer's intermediate: [{id, secret, sans}], from
    ca.certificates."""
    out = []
    for c in _spec_ca(model).get("certificates") or []:
        if not isinstance(c, dict) or not c.get("id"):
            raise CaRenderError(f"ca.certificates: every entry needs an id, got {c!r}")
        if c.get("gateway") is not None and str(c["gateway"]) not in model.gateways:
            continue  # a Gateway's own certificate, for a Gateway this state does not hold
        names = [_cert_name(model, str(n)) for n in c.get("dns") or []]
        names += [str(a) for a in c.get("ip") or []]
        if not names:
            raise CaRenderError(f"ca.certificates {c['id']}: no names")
        out.append({"id": str(c["id"]), "secret": c.get("secret"), "sans": [san(n) for n in names]})
    return out


# --------------------------------------------------------------------------------------------
# the configuration files


def root_cnf(model: Model, ca: Ca, ctx) -> str:
    key = _key(str((_spec_ca(model).get("root") or {}).get("key", ROOT_KEY)), "the root")
    lines = [
        header(model, "the root", ctx),
        "# sfab-ca makes the root key and self-signs the root from this file once, on the first",
        "# `sfab-ca init` on the lab host. The key never leaves the lab's state/ca, which no node binds,",
        "# and signs only the intermediates; make wipe starts a new CA.",
        "[sfab]",
        f"key = {key}",
        f"days = {ROOT_DAYS}",
        "role = root",
        "",
        "[req]",
        "prompt = no",
        "distinguished_name = dn",
        "",
        "[dn]",
        f"O = {_subject_value(model.org.name, 'organization')}",
        f"CN = {_subject_value(ca.root_cn, 'the root CN')}",
        "",
        "[ext]",
        "basicConstraints = critical,CA:TRUE,pathlen:1",
        "keyUsage = critical,keyCertSign,cRLSign",
        "subjectKeyIdentifier = hash",
    ]
    return "\n".join(lines) + "\n"


def intermediate_cnf(model: Model, i: CaIntermediate, role: str, ctx) -> str:
    what = {"kubeadm": "the init node's kubeadm signs the cluster's certificates with it",
            "gateways": "cert-manager's CA issuer signs the Gateway certificates with it",
            "upstream": "sfab-ca signs the upstream stand-ins' leaves with it on the lab host"}.get(role, "")
    lines = [
        header(model, f"the {i.name} intermediate", ctx),
        "# sfab-ca signs it with the root. Its name constraints are the only names and",
        "# addresses any certificate under it can verify for.",
    ]
    if what:
        lines.append(f"# Role {role}: {what}.")
    lines += [
        "[sfab]",
        f"key = {_key(i.key, f'intermediate {i.name}')}",
        f"days = {INTERMEDIATE_DAYS}",
        f"renew_days = {RENEW_DAYS}",
        f"role = {role}",
        "",
        "[req]",
        "prompt = no",
        "distinguished_name = dn",
        "",
        "[dn]",
        f"O = {_subject_value(model.org.name, 'organization')}",
        f"CN = {_subject_value(i.cn, f'intermediate {i.name} CN')}",
        "",
        "[ext]",
        "basicConstraints = critical,CA:TRUE,pathlen:0",
        "keyUsage = critical,keyCertSign,cRLSign,digitalSignature",
        "subjectKeyIdentifier = hash",
        "authorityKeyIdentifier = keyid:always",
        f"nameConstraints = {name_constraints(i)}",
    ]
    return "\n".join(lines) + "\n"


def leaf_cnf(model: Model, lf: CaLeaf, ctx) -> str:
    """A node's server certificate: its names, signed on the lab host by its intermediate."""
    sans = [san(n) for n in lf.dns] + [san(a) for a in lf.ip]
    if not sans:
        raise CaRenderError(f"leaf {lf.name}: no names")
    cn = lf.dns[0] if lf.dns else lf.ip[0]
    lines = [
        header(model, f"the {lf.name} leaf", ctx),
        f"# sfab-ca signs it on the lab host with the {lf.ca} intermediate and writes the key, the",
        f"# certificate and the chain (the leaf, then the intermediate) to {TLS_STATE}/{lf.node}/, which the",
        f"# topology binds read-only at {TLS_BOUND} in {lf.node} only.",
        "[sfab]",
        f"key = {LEAF_KEY}",
        f"days = {LEAF_DAYS}",
        f"renew_days = {LEAF_RENEW_DAYS}",
        f"ca = {lf.ca}",
        f"node = {lf.node}",
        "",
        "[req]",
        "prompt = no",
        "distinguished_name = dn",
        "",
        "[dn]",
        f"CN = {_subject_value(cn, f'leaf {lf.name} CN')}",
        "",
        "[ext]",
        "basicConstraints = critical,CA:FALSE",
        "keyUsage = critical,digitalSignature",
        "extendedKeyUsage = serverAuth",
        "subjectKeyIdentifier = hash",
        "authorityKeyIdentifier = keyid:always",
        f"subjectAltName = {','.join(sans)}",
    ]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------------------------
# the proof


def apiserver_sans(model: Model, node: str) -> list:
    """What kubeadm puts in the API server certificate on one control node: the kubernetes
    service names, the node's own name and address, the first service address, and the
    control-plane endpoint (the API name), plus the API VIP."""
    k = model.k8s
    svc = ipaddress.ip_network(k.service_cidr)
    names = ["kubernetes", "kubernetes.default", "kubernetes.default.svc",
             f"kubernetes.default.svc.{KUBEADM_DNS_DOMAIN}", node, k.api_fqdn]
    out = [f"DNS:{n}" for n in names]
    h = model.nodes[node]
    out += [f"IP:{svc.network_address + 1}"]
    if getattr(h, "primary", None):
        out.append(f"IP:{h.primary}")
    out.append(f"IP:{k.api_vip}")
    return out


def gateway_sans(model: Model) -> list:
    """Every Gateway listener hostname and the zone's wildcard: the leaf the proof signs for the
    Gateways when the spec lists no issued certificate."""
    names: list = []
    if model.dns is not None and model.dns.wildcard:
        names.append(model.dns.wildcard)
    for g in model.gateways.values():
        for h in g.hostnames:
            if h not in names:
                names.append(h)
    return [san(n) for n in names]


def proof_leaves(model: Model) -> list:
    """Every proof leaf, in order: per intermediate, the inside leaves then the outside ones."""
    ca = model.ca
    role_of = roles(model)
    public = model.firewall.public if model.firewall is not None else None
    leaves = []
    for i in ca.intermediates:
        role = role_of[i.name]

        def leaf(kind, n, sans, source):
            leaves.append({"id": f"{i.name}-{kind}-{n}", "ca": i.name, "san": sans,
                           "expect": "verify" if kind == "inside" else "reject", "source": source})

        inside = i.proof_inside or ca.proof_inside
        outside = i.proof_outside or ca.proof_outside
        src = f"ca.intermediates.{i.name}.proof" if i.proof_inside or i.proof_outside else "ca.proof"
        for n, x in enumerate(inside, 1):
            leaf("inside", n, [san(x)], f"the spec's {src}.inside")
        if role == "gateways":
            certs = issued_certificates(model)
            for c in certs:
                where = f" (secret {c['secret']})" if c.get("secret") else ""
                leaf("inside", f"cert-{c['id']}", c["sans"], f"the {c['id']} certificate cert-manager issues{where}")
            if not certs:
                leaf("inside", "gateway", gateway_sans(model), "the Gateway listener names: the wildcard and every Gateway hostname")
        if role == "kubeadm" and model.k8s is not None:
            for c in model.k8s.control:
                leaf("inside", f"apiserver-{c}", apiserver_sans(model, c), f"kubeadm's API server certificate on {c}")
        for lf in lab_leaves(model):
            if lf.ca == i.name:
                leaf("inside", f"leaf-{lf.name}", [san(n) for n in lf.dns] + [san(a) for a in lf.ip],
                     f"the {lf.name} leaf {lf.node} serves")
        for n, x in enumerate(outside, 1):
            leaf("outside", n, [san(x)], f"the spec's {src}.outside")
        if public:
            leaf("outside", "public", [f"IP:{public}"], "the firewall's public address, which no lab certificate may name")
    return leaves


def check_leaves(model: Model, leaves: list) -> list:
    """Problems sfab-ca's proof will report: an inside SAN the constraints refuse, or an outside
    leaf they wholly permit."""
    by = {i.name: i for i in model.ca.intermediates}
    role_of = roles(model)
    out = []
    for lf in leaves:
        i = by[lf["ca"]]
        refused = [s for s in lf["san"] if not permits(i, s)]
        if lf["expect"] == "verify" and refused:
            msg = f"ca: proof leaf {lf['id']} ({lf['source']}) names {', '.join(refused)}, outside the {i.name} CA's constraints"
            if role_of.get(i.name) == "kubeadm":
                msg += ("; kubeadm always puts the node name in the API server certificate, so add the control "
                        "nodes' names to ca.intermediates." + i.name + ".dns in the spec, or the cluster's own "
                        "clients refuse the API server")
            out.append(msg)
        if lf["expect"] == "reject" and not refused:
            out.append(f"ca: proof leaf {lf['id']} ({lf['source']}) is inside the {i.name} CA's constraints, so it cannot be refused")
    return out


def proof(model: Model, ctx) -> dict:
    leaves = proof_leaves(model)
    for p in check_leaves(model, leaves):
        ctx.warn(p)
    return {
        "schema": 2,
        "lab": model.lab,
        "root": "root",
        "intermediates": [i.name for i in model.ca.intermediates],
        "roles": roles(model),
        "constraints": {i.name: {"dns": list(i.dns), "ip": list(i.ip)} for i in model.ca.intermediates},
        "kubeadm": bool(model.features.get("k8s")) and model.k8s is not None,
        "node_leaves": [{"id": lf.name, "ca": lf.ca, "node": lf.node, "dir": f"{TLS_STATE}/{lf.node}"} for lf in lab_leaves(model)],
        "leaves": leaves,
    }


# --------------------------------------------------------------------------------------------


def render(model: Model, ctx) -> dict:
    if not ca_on(model):
        return {}
    names = [i.name for i in model.ca.intermediates]
    if len(set(names)) != len(names) or "root" in names:
        raise CaRenderError(f"intermediate names must be unique and not 'root': {names}")
    if not all(re.fullmatch(r"[a-z][a-z0-9-]{0,30}", n) for n in names):
        raise CaRenderError(f"intermediate names must be short lower-case words (they name files): {names}")
    issuer = issuer_ca(model)
    if issuer not in names:
        raise CaRenderError(f"ca.issuer.intermediate {issuer!r} is not one of the intermediates {names}")
    leaf_ids = [lf.name for lf in model.ca.leaves]
    if len(set(leaf_ids)) != len(leaf_ids) or not all(re.fullmatch(r"[a-z][a-z0-9-]{0,30}", n) for n in leaf_ids):
        raise CaRenderError(f"leaf ids must be unique short lower-case words (they name files): {leaf_ids}")
    role_of = roles(model)
    out = {f"{CA_DIR}/root.cnf": root_cnf(model, model.ca, ctx)}
    for i in model.ca.intermediates:
        out[f"{CA_DIR}/{i.name}.cnf"] = intermediate_cnf(model, i, role_of[i.name], ctx)
    for lf in lab_leaves(model):
        out[f"{CA_DIR}/leaf-{lf.name}.cnf"] = leaf_cnf(model, lf, ctx)
    out[f"{CA_DIR}/proof.json"] = json.dumps(proof(model, ctx), indent=2, sort_keys=True) + "\n"
    return out
