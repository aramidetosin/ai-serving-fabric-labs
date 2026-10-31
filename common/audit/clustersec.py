#!/usr/bin/env python3
"""The cluster-security and identity groups of judge.py (build A revision 2: the cluster's protections and sign-in), and
the plans their collection in lib-audit.sh reads.

    clustersec.py targets K8S_JSON            the policed Services the probe pod connects to:
                                              "<tag>\\t<namespace>\\t<service>\\t<port>\\t<expect>"
    clustersec.py probe-pod NAME IMAGE        the probe pod's manifest (JSON), in namespace default
    clustersec.py reply-plan INV K8S_JSON     "<vip> <lease> <client>": a Gateway a population's
                                              client reaches, and the lease that names its holder
    clustersec.py people K8S_JSON INV         each person who signs in from a client of the lab:
                                              "<person>\\t<client>\\t<gateway>\\t<idp host>\\t<pin or ->"

cluster-security (cluster-security/, a full audit):

  Secrets at rest   every control node's API server runs with the encryption provider config, the
                    config is 0600 root and names the spec's provider; etcd stores the issuer's CA
                    Secret behind the provider's prefix (k8s:enc:<provider>:v1:), and the API
                    still reads it back
  WireGuard         cilium-config enables it, and every agent reports WireGuard encryption with a
                    peer for every other node
  certificates      each Gateway's certificate is issued by the platform intermediate for the
                    zone's wildcard name, and no two Gateways share a public key
  network policy    the policies the render names exist; a pod in a namespace no policy selects is
                    refused by every policed Service (its connect times out: Cilium drops it), and
                    reaches the cluster's DNS, which no policy selects
  edge placement    the API gateway's, the router's and the identity provider's pods run on the
                    ingress nodes only
  policy routing    each ingress node sends what its ingress unit's prefix sources by table 110,
                    through the firewall's ingress interface; and the Gateway's SYN-ACK to a
                    population's client leaves the lease holder tagged in VLAN 110

identity (identity/, a full audit, with the identity provider):

  discovery         the IdP's discovery document through the person's Gateway names its issuer
  sign-in           the person's token from the IdP: issuer, audience holding the API gateway's
                    client id, the person's client as azp, a verified email
  callers           the token answers 200 on every model the person's caller may call, and a token
                    without the API gateway's audience, and an altered one, 401 with a Bearer
                    challenge
  logs              the API gateway's access log names the person's consumer and caller
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def _json(p: Path):
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def _text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# --------------------------------------------------------------------------------------------
# the plans


def targets(k8s_json: str) -> int:
    k = json.load(open(k8s_json, encoding="utf-8"))
    rows = []
    tb = k.get("test_backend") or {}
    if tb:
        rows.append(("echo", tb["namespace"], tb["service"], tb["port"], "refused"))
    inf = k.get("inference") or {}
    if inf:
        rows.append(("api-gateway", inf["namespace"], inf["gateway"]["name"], inf["gateway"]["port"], "refused"))
        rows.append(("router", inf["namespace"], inf["router"]["name"], inf["router"]["port"], "refused"))
        sv = k.get("serving") or {}
        for m in inf.get("models") or []:
            rows.append((f"model-{m['name']}", sv.get("namespace"), m["name"], (sv.get("ports") or {}).get("http"), "refused"))
    idp = k.get("identity") or {}
    if idp:
        rows.append(("idp", idp["namespace"], idp["name"], idp["port"], "refused"))
    rows.append(("cluster-dns", "kube-system", "kube-dns", 53, "connected"))
    sys.stdout.write("".join("\t".join(str(x) for x in r) + "\n" for r in rows))
    return 0


def probe_pod(name: str, image: str) -> int:
    doc = {"apiVersion": "v1", "kind": "Pod",
           "metadata": {"name": name, "namespace": "default", "labels": {"app.kubernetes.io/name": name}},
           "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False, "enableServiceLinks": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "probe", "image": image, "args": ["pause"],
                                    "securityContext": {"allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]}},
                                    "resources": {"requests": {"cpu": "10m", "memory": "16Mi"}, "limits": {"memory": "64Mi"}}}]}}
    print(json.dumps(doc, sort_keys=True))
    return 0


def reply_plan(inv_json: str, k8s_json: str) -> int:
    inv, k = json.load(open(inv_json)), json.load(open(k8s_json))
    nodes = inv.get("nodes") or {}
    for p in (inv.get("populations") or {}).values():
        g = p.get("gateway")
        c = next((x for x in p.get("clients") or [] if (nodes.get(x) or {}).get("kind") == "client"), None)
        lease = ((k.get("gateways") or {}).get(g) or {}).get("l2_lease")
        if g and c and lease and (inv.get("gateways") or {}).get(g):
            print(str(inv["gateways"][g]["vip"]).split("/")[0], lease, c)
            return 0
    return 1


def people(k8s_json: str, inv_json: str) -> int:
    k, inv = json.load(open(k8s_json)), json.load(open(inv_json))
    idp, nodes = k.get("identity") or {}, inv.get("nodes") or {}
    pops = inv.get("populations") or {}
    for p in idp.get("people") or []:
        c = p.get("node")
        if not c or c not in nodes:
            continue
        pop = next((x for x in pops.values() if c in (x.get("clients") or [])), None)
        if not pop or not pop.get("gateway"):
            continue
        res = (nodes.get(c) or {}).get("resolver")
        pin = "-" if res and res in nodes else f"{idp['hostname']}:443:{pop.get('answer_address')}"
        print("\t".join((p["id"], c, pop["gateway"], idp["hostname"], pin)))
    return 0


# --------------------------------------------------------------------------------------------
# the judge groups


def _k8s(self) -> dict:
    return _json(Path(self.render) / "gen" / "k8s.json") or {}


def _pods_by(pods: dict, ns: str, name: str) -> list:
    return [i for i in (pods or {}).get("items") or [] if i["metadata"]["namespace"] == ns
            and ((i["metadata"].get("labels") or {}).get("app.kubernetes.io/name") == name)]


def g_cluster_security(self, names):
    d = Path(self.rs.path) / "cluster-security"
    v = self.v
    k = _k8s(self)
    v.sec("cluster security: Secrets at rest, WireGuard, the Gateways' keys, network policy, the edge (build A revision 2)")
    if not d.is_dir():
        v.skip("the cluster's protections", "no cluster-security reads in this set (a quick audit)")
        return
    enc = k.get("secrets_encryption")
    if enc:
        for n in (k.get("api") or {}).get("control") or []:
            lines = _text(d / f"encryption-{n}.txt").split()
            ok = len(lines) >= 4 and lines[0] == "1" and lines[1] == "600" and lines[2] == "root" and lines[3] == "1"
            v.check(f"{n}: the API server runs with --encryption-provider-config={enc['config']}, the file 0600 root, naming {enc['provider']}",
                    ok, " ".join(lines) or "not read")
        lines = _text(d / "etcd-prefix.txt").strip().splitlines()
        pre = next((x for x in lines if x.startswith("k8s:")), lines[-1] if lines else "")
        want = f"k8s:enc:{enc['provider']}:v1:"
        sec = _text(d / "etcd-secret.txt").strip()
        v.check(f"etcd stores the Secret {sec} encrypted: its value starts {want}", pre.startswith(want), repr(pre[:26]) or "not read")
        typ = _text(d / "api-secret-type.txt").strip()
        v.check(f"the API server still reads {sec} back (type {typ or 'none'})", typ == "kubernetes.io/tls", typ or "not read")
    if k.get("pod_encryption") == "wireguard":
        cfg = ((_json(d / "cilium-config.json") or {}).get("data") or {})
        v.check("cilium-config: enable-wireguard true", cfg.get("enable-wireguard") == "true", repr(cfg.get("enable-wireguard")))
        nodes = list((k.get("nodes") or {}).keys())
        blocks = [b for b in _text(d / "wireguard.txt").split("== ") if b.strip()]
        v.check(f"a Cilium agent read on each of the {len(nodes)} nodes", len(blocks) == len(nodes), f"{len(blocks)} read")
        for b in blocks:
            head = b.splitlines()[0].split()
            pod, node = (head + ["?", "?"])[:2]
            peers = re.search(r"(?:Number of peers|Peers):\s*(\d+)", b)
            wg = re.search(r"Encryption:\s*Wireguard", b, re.I)
            v.check(f"{node}: the agent reports WireGuard encryption with {len(nodes) - 1} peers ({peers.group(1) if peers else 'none'} read)",
                    bool(wg) and bool(peers) and int(peers.group(1)) == len(nodes) - 1,
                    (b.strip().splitlines()[1:3] or ["no status"])[0] if not wg else f"peers {peers.group(1) if peers else 'none'}")
    certs = k.get("certificates") or []
    if len(certs) > 1:
        text = _text(d / "gateway-certs.txt")
        spki = {}
        for b in [x for x in text.split("== ") if x.strip()]:
            name = b.splitlines()[0].strip()
            m = re.search(r"spki sha256 ([0-9a-f]{64})", b)
            spki[name] = m.group(1) if m else None
            c = next((x for x in certs if x["secret"] == name), None)
            inter = (k.get("issuer") or {}).get("intermediate")
            pcn = (((self.inv.get("ca") or {}).get("intermediates") or {}).get(inter) or {}).get("cn")
            iss = re.search(r"^issuer=(.*)$", b, re.M)
            wild = next((x for x in (c or {}).get("dns") or [] if x.startswith("*.")), None)
            v.check(f"{name} ({(c or {}).get('gateway') or '?'}): issued by {pcn} for {wild}",
                    bool(c) and bool(iss) and bool(pcn) and f"CN={pcn}" in iss.group(1) and bool(wild) and f"DNS:{wild}" in b,
                    iss.group(1) if iss else "no issuer")
        keys = [x for x in spki.values() if x]
        v.check(f"the {len(certs)} Gateways' certificates hold {len(certs)} different keys (no Gateway holds another's)",
                len(keys) == len(certs) and len(set(keys)) == len(keys), f"{len(set(keys))} distinct of {len(keys)} read")
    np_ = k.get("network_policy")
    if np_:
        live = {(i["metadata"]["namespace"], i["metadata"]["name"]) for i in (_json(d / "cnp.json") or {}).get("items") or []}
        want = [(x["namespace"], x["name"]) for key in ("base", "inference") for x in np_.get(key) or []]
        miss = [f"{a}/{b}" for a, b in want if (a, b) not in live]
        v.check(f"the {len(want)} CiliumNetworkPolicies the render names are in the cluster", not miss, ", ".join(miss[:4]))
        plan = [l.split("\t") for l in _text(d / "targets.txt").splitlines() if l.strip()]
        blocks = {b.splitlines()[0].split()[0]: b for b in _text(d / "probe.txt").split("== ") if b.strip()}
        if not plan:
            v.bad("the network policy probe", "no target was planned")
        for row in plan:
            tag, ns, svc, port, expect = row[:5]
            b = blocks.get(tag, "")
            rc = re.search(r"rc=(\d+)", b)
            refused = bool(rc) and rc.group(1) != "0"
            out = " ".join(l for l in b.splitlines()[1:] if not l.startswith("rc=")).strip()
            if expect == "refused":
                v.check(f"a pod outside every policed namespace to {ns}/{svc}:{port}: refused ({out or 'no answer'})",
                        refused and "TIMEOUT" in b.upper(), f"rc {rc.group(1) if rc else 'none'} {out}")
            else:
                v.check(f"the same pod to {ns}/{svc}:{port}, which no policy selects: connected", bool(rc) and rc.group(1) == "0",
                        f"rc {rc.group(1) if rc else 'none'} {out}")
    edge = k.get("edge")
    if edge:
        pods = _json(d / "pods.json") or {}
        on = set(edge.get("nodes") or [])
        groups = []
        inf = k.get("inference") or {}
        if inf:
            groups += [(inf["namespace"], inf["gateway"]["name"], "the API gateway"), (inf["namespace"], inf["router"]["name"], "the router")]
        idp = k.get("identity") or {}
        if idp:
            groups.append((idp["namespace"], idp["name"], "the identity provider"))
        for ns, name, what in groups:
            ps = _pods_by(pods, ns, name)
            where = sorted({(p.get("spec") or {}).get("nodeName") for p in ps})
            v.check(f"{what}'s {len(ps)} pod(s) on the ingress nodes only ({', '.join(map(str, where)) or 'none'})",
                    bool(ps) and set(where) <= on, ", ".join(map(str, where)) or "no pod")
        for n in sorted(on):
            t = _text(d / f"policy-routing-{n}.txt")
            if not t:
                continue
            rule = re.search(r"from 10\.20\.11\.\d+(/\d+)? lookup 110", t) or re.search(r"from \S+ lookup 110", t)
            route = re.search(r"default via (\S+) dev bond0\.110", t)
            v.check(f"{n}: what the ingress unit's prefix sources leaves by table 110, default via {route.group(1) if route else '?'} on bond0.110",
                    bool(rule) and bool(route), "no rule" if not rule else "no default route in table 110")
        plan = _text(d / "reply-plan.txt").split()
        cap = _text(d / "reply-capture.txt")
        if len(plan) == 3 and plan[1] != "none":
            vip, holder, client = plan
            synack = [l for l in cap.splitlines() if "vlan 110" in l and f"{vip}.443 >" in l and "[S." in l]
            v.check(f"{holder}, the lease holder of {vip}: the Gateway's SYN-ACK to {client} leaves bond0 tagged vlan 110 ({len(synack)} seen)",
                    bool(synack), (cap.strip().splitlines() or ["nothing captured"])[0][:120])


def g_identity(self, names):
    d = Path(self.rs.path) / "identity"
    v = self.v
    k = _k8s(self)
    idp = k.get("identity") or {}
    inf = k.get("inference") or {}
    v.sec("identity: a person's OpenID Connect token at the API gateway (chapter 7)")
    if not idp or not d.is_dir():
        v.skip("the identity provider", "no identity provider in this lab, or a quick audit")
        return
    pods = [i for i in (_json(d / "idp-pods.json") or {}).get("items") or []]
    ready = [p for p in pods if any(c.get("type") == "Ready" and c.get("status") == "True" for c in (p.get("status") or {}).get("conditions") or [])]
    v.check(f"the identity provider {idp['namespace']}/{idp['name']}: {len(ready)} of {idp.get('replicas', 1)} pod(s) Ready",
            len(ready) == idp.get("replicas", 1), f"{len(pods)} pods")
    people = [json.loads(l) for l in _text(d / "people.jsonl").splitlines() if l.strip().startswith("{")]
    if not people:
        v.bad("a person's sign-in", "no person signs in from a client of this lab")
        return
    callers = inf.get("callers") or []
    log = _text(d / "api-gateway-log.txt")
    for p in people:
        pid, client, gw = p["person"], p["client"], p["gateway"]
        st = (_text(d / f"{pid}-discovery-status.txt").split() or ["0"])[-1]
        disc = _json(d / f"{pid}-discovery.json") or {}
        v.check(f"{client}: the IdP's discovery document through {gw}, issuer {disc.get('issuer')}", st == "200" and disc.get("issuer") == idp["issuer"],
                f"HTTP {st}")
        claims = _json(d / f"{pid}-claims.json") or {}
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        person = next((x for x in idp.get("people") or [] if x["id"] == pid), {})
        cid = (idp.get("clients") or [{}])[0].get("id")
        v.check(f"{pid} signs in from {client} (client {cid}): a token from {idp['issuer']} for {claims.get('email')}, verified, its audience "
                f"{auds}, valid {claims.get('lifetime_s')} s",
                claims.get("iss") == idp["issuer"] and idp["audience"] in auds and claims.get("azp") == cid
                and claims.get("email") == person.get("email") and claims.get("email_verified") is True,
                json.dumps(claims, sort_keys=True) if claims else (_text(d / f"{pid}-token-status.txt").strip() or "no token"))
        c2 = _json(d / f"{pid}-claims-noaud.json") or {}
        a2 = c2.get("aud") if isinstance(c2.get("aud"), list) else [c2.get("aud")]
        v.check(f"{pid}'s token asked without the API gateway's audience names only {a2}", bool(c2) and idp["audience"] not in a2, json.dumps(c2))
        caller = next((c for c in callers if c.get("kind") == "people" and pid in (c.get("people") or [])), None)
        allowed = set((caller or {}).get("models") or [])
        for m in inf.get("models") or []:
            mn = m["name"]
            r = d / f"{pid}-{mn}-aud-result.txt"
            if not r.exists():
                continue
            s1 = (_text(r).split() or ["0"])[0]
            if mn in allowed:
                v.check(f"{pid}'s token on {mn} through {gw}: HTTP 200 (caller {caller['id']} may call it)", s1 == "200",
                        f"HTTP {s1} {_text(d / f'{pid}-{mn}-aud-body.txt')[:80]}")
            else:
                v.check(f"{pid}'s token on {mn} through {gw}: HTTP {inf['rejected']['code']} (caller {(caller or {}).get('id')} may not)",
                        s1 == str(inf["rejected"]["code"]), f"HTTP {s1}")
            for kind, what in (("noaud", "without the API gateway's audience"), ("altered", "altered by one character")):
                s2 = (_text(d / f"{pid}-{mn}-{kind}-result.txt").split() or ["0"])[0]
                body = _text(d / f"{pid}-{mn}-{kind}-body.txt").strip()
                www = _text(d / f"{pid}-{mn}-{kind}-www.txt").strip()
                v.check(f"a token {what} on {mn}: HTTP 401 ({body[:60]}), challenged {www or 'with nothing'}",
                        s2 == "401" and inf["rejected"]["message"] in body and www.lower().startswith("www-authenticate: bearer"),
                        f"HTTP {s2}, {www or 'no WWW-Authenticate'}")
        cons = [x["username"] for x in (caller or {}).get("consumers") or [] if x.get("person") == pid]
        lines = [l for l in log.splitlines() if cons and f'"consumer":"{cons[0]}"' in l.replace(" ", "")]
        ok200 = [l for l in lines if '"status":"200"' in l.replace(" ", "") or '"status":200' in l.replace(" ", "")]
        v.check(f"the API gateway's access log names the person: consumer {cons[0] if cons else '?'} of caller {(caller or {}).get('id')}, "
                f"{len(ok200)} answered request(s)", bool(ok200), f"{len(lines)} line(s) name it")


def main(argv=None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if not a:
        print(__doc__)
        return 2
    cmd, rest = a[0], a[1:]
    if cmd == "targets" and len(rest) == 1:
        return targets(rest[0])
    if cmd == "probe-pod" and len(rest) == 2:
        return probe_pod(*rest)
    if cmd == "reply-plan" and len(rest) == 2:
        return reply_plan(*rest)
    if cmd == "people" and len(rest) == 2:
        return people(*rest)
    print(f"clustersec: unknown command {' '.join(a)}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
