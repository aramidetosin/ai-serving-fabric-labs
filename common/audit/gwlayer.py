"""The gateway-layer and keys groups of judge.py (chapter 7): the chain from the firewall to the model.

audit_gateway_layer in lib-audit.sh saves the reads, then `judge.py run ... keys` and (in a full
audit) `judge.py run ... gateway-layer` judge them, from the saved files only.

keys (keys/, a quick audit too), for each model route a client of the lab reaches. A model's key is
the first key of the first application caller (inference.callers) that may call the model
(common/trace/servekeys.py): in build A chat's is the batch caller's and staff's the helpdesk's.

  no key        a request with no Authorization header answered 401 by key authentication
  unknown key   a key no Secret holds, made in the client, answered 401
  cross key     each other model's key, a key of a caller the route does not admit, answered 401
                with the same body as the unknown key, so a caller cannot learn that a key works
                elsewhere (the consumer restriction's rejected code and message, set by the render)
  per pod       the per-pod key probe (a pod of the key tool in the cluster): every API gateway pod,
                by its own address, answers each model's key on the model's route with 200 and
                every other model's key there with 401, so no pod lags the key Secret

gateway-layer (gateway-layer/, a full audit only):

  GatewayClass  cilium Accepted
  allowedRoutes each Gateway's listener admits HTTPRoutes from the namespaces labelled for it
                (from: Selector), and exactly the namespaces the render attaches routes from carry
                the label; its attached routes are the render's
  hostnames     each Gateway's accepted routes carry the hostname and path pairs the render gives
                it (Table 7-1): the internal Gateway the bare model prefix and the admin hostnames,
                the users' Gateway one rule a model; no route on a Gateway without admin hostnames
                names one
  leases        each Gateway's VIP announced by a node the L2 announcement policy selects, its
                lease's holder (Table 7-3): an ingress node in build A revision 2
  the VIPs      from a GPU node, each VIP resolves by ARP and opens TCP 443, and answers no ICMP
                echo (every VIP check is a TCP connect)
  certificates  each VIP's chain, for the users' hostname, verifies against the lab root: the
                wildcard leaf from the platform intermediate, which the root signs
  the CA proof  sfab-ca proof on the lab host, where the CA lives: every inside leaf verifies, and every leaf the
                intermediates sign outside their name constraints is refused on a name constraint,
                the verification failure recorded with openssl's own error line
  timeouts      the chain as the cluster runs it (Table 7-2): the router's attempts inside the API
                gateway's upstream read, inside the model routes' backendRequest, inside their
                request; and the stream idle timeout Cilium's operator wrote into each Gateway's
                listener

Each check is a PASS or FAIL line.
"""

from __future__ import annotations

import json
import re
from pathlib import Path


def _json(p: Path):
    import evfile  # noqa: PLC0415

    try:
        return json.loads(evfile.read_text(p, "strict"))
    except (OSError, ValueError):
        return None


def _text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _cond(obj: dict, kind: str) -> bool:
    return any(c.get("type") == kind and c.get("status") == "True" for c in (obj or {}).get("conditions") or [])


def _k8s(self) -> dict:
    return _json(Path(self.render) / "gen" / "k8s.json") or {}


def _status(p: Path) -> int:
    first = (_text(p).split() or ["0"])[0]
    return int(first) if first.isdigit() else 0


def _message(p: Path) -> str:
    t = _text(p).strip()
    try:
        d = json.loads(t)
        if isinstance(d, dict) and d.get("message"):
            return str(d["message"])
    except ValueError:
        pass
    return (t.splitlines() or [""])[0][:100]


# --------------------------------------------------------------------------------------------
# keys


def probe_rows(path: Path) -> list:
    out = []
    for line in _text(path).splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if "pod" in r:
                out.append(r)
    return out


def g_keys(self, names):
    d = Path(self.rs.path) / "keys"
    v = self.v
    k8s = _k8s(self)
    inf = k8s.get("inference") or {}
    v.sec("keys: the callers' keys at the API gateway (chapter 7)")
    if not inf:
        v.skip("the callers' keys", "the lab serves no model through the API gateway")
        return
    rej = (inf.get("rejected") or {})
    targets = [json.loads(l) for l in _text(d / "targets.jsonl").splitlines() if l.strip().startswith("{")]
    if not targets:
        v.bad("the key checks through the Gateways", "no route a client of the lab reaches was read")
    for t in targets:
        tag = t["tag"]
        where = f"{t['model']} through {t['gateway']} from {t['client']}"
        st = _status(d / f"{tag}-nokey-result.txt")
        v.check(f"{where}, no key: HTTP 401 from key authentication ({_message(d / f'{tag}-nokey-body.txt')})", st == 401, f"HTTP {st or 'none'}")
        su = _status(d / f"{tag}-unknown-result.txt")
        mu = _message(d / f"{tag}-unknown-body.txt")
        v.check(f"{where}, a key no Secret holds: HTTP 401 ({mu})", su == 401, f"HTTP {su or 'none'}")
        for o in t.get("cross") or []:
            sc = _status(d / f"{tag}-cross-{o}-result.txt")
            mc = _message(d / f"{tag}-cross-{o}-body.txt")
            v.check(f"{where}, {o}'s key: HTTP {rej.get('code', 401)} with the unknown key's own message ({mc}), so a key that works "
                    f"elsewhere reads as none", sc == rej.get("code", 401) and mc == mu and (not rej.get("message") or mc == rej["message"]),
                    f"HTTP {sc or 'none'}, message {mc!r} against {mu!r}")
    phase = _text(d / "probe.phase").strip()
    rows = probe_rows(d / "probe.log")
    pods = sorted({r["pod"] for r in rows})
    v.check(f"the per-pod key probe ran in the cluster and ended ({phase or 'not read'}), reaching {len(pods)} API gateway pod(s) by their "
            f"addresses", phase == "Succeeded" and bool(pods), _text(d / "probe.log").strip().splitlines()[-1:] or "no probe log")
    checks = [json.loads(l) for l in _text(d / "checks.jsonl").splitlines() if l.strip().startswith("{")]
    for c in checks:
        got = {r["pod"]: r for r in rows if r.get("label") == c["label"]}
        bad = [f"{p} HTTP {got[p].get('status')}" for p in pods if p not in got or got[p].get("status") != c["expect"]]
        what = "its own first key" if c["kind"] == "own" else f"{c['key_model']}'s key"
        v.check(f"every API gateway pod ({', '.join(pods) or 'none'}) answers {what} on {c['route']}'s route with HTTP {c['expect']}",
                bool(pods) and not bad, "; ".join(bad[:4]) or "no answer")


# --------------------------------------------------------------------------------------------
# the gateway layer


def _routes_of(hr: dict, gw: str) -> list:
    out = []
    for r in (hr or {}).get("items") or []:
        sp, ss = r.get("spec") or {}, r.get("status") or {}
        if not any(p.get("name") == gw for p in sp.get("parentRefs") or []):
            continue
        parents = [p for p in ss.get("parents") or [] if (p.get("parentRef") or {}).get("name") == gw]
        out.append({"name": r["metadata"]["name"], "namespace": r["metadata"].get("namespace"), "spec": sp,
                    "accepted": any(_cond(p, "Accepted") for p in parents), "resolved": any(_cond(p, "ResolvedRefs") for p in parents)})
    return out


def _pairs(routes: list) -> set:
    out = set()
    for r in routes:
        if not r["accepted"]:
            continue
        for h in r["spec"].get("hostnames") or []:
            for rule in r["spec"].get("rules") or []:
                for m in rule.get("matches") or [{"path": {"value": "/"}}]:
                    out.add((h, ((m.get("path") or {}).get("value")) or "/"))
    return out


def expected_pairs(k8s: dict) -> dict:
    """{gateway: {(hostname, path)}} as the render attaches routes."""
    out: dict = {g: set() for g in (k8s.get("gateways") or {})}
    tb = k8s.get("test_backend") or {}
    for g in (tb.get("routes") or {}):
        for h in (k8s["gateways"].get(g) or {}).get("hostnames") or []:
            out.setdefault(g, set()).add((h, tb.get("path")))
    inf = k8s.get("inference") or {}
    for rt in inf.get("routes") or []:
        for h in rt.get("hostnames") or []:
            for rule in rt.get("rules") or []:
                out.setdefault(rt["gateway"], set()).add((h, rule["path"]))
    sv = k8s.get("serving") or {}
    r = sv.get("route") or {}
    if r.get("gateway"):
        for m in sv.get("models") or []:
            out.setdefault(r["gateway"], set()).add((r["hostname"], f"/{m['name']}"))
            for c in m.get("copies") or []:
                out[r["gateway"]].add((r["hostname"], f"/{m['name']}-{c}"))
    idp = k8s.get("identity") or {}
    for g in idp.get("gateways") or []:
        # the identity provider, published on its Gateways under its own name (render/identity.py)
        out.setdefault(g, set()).add((idp["hostname"], "/"))
    return out


def _idle(cec: dict) -> dict:
    """{name: the streamIdleTimeout of every HTTP connection manager in a CiliumEnvoyConfig, or 'unset'}."""
    out = {}
    for it in (cec or {}).get("items") or []:
        found = []

        def walk(x):
            if isinstance(x, dict):
                if "streamIdleTimeout" in x or "stream_idle_timeout" in x:
                    found.append(str(x.get("streamIdleTimeout") or x.get("stream_idle_timeout")))
                if str(x.get("@type", "")).endswith("HttpConnectionManager") and "streamIdleTimeout" not in x and "stream_idle_timeout" not in x:
                    found.append("unset")
                for y in x.values():
                    walk(y)
            elif isinstance(x, list):
                for y in x:
                    walk(y)

        walk(it.get("spec") or {})
        out[it["metadata"]["name"]] = sorted(set(found)) or ["none found"]
    return out


def _secs(v) -> float | None:
    m = re.match(r"^(\d+(?:\.\d+)?)s$", str(v or ""))
    return float(m.group(1)) if m else None


def g_gateway_layer(self, names):
    d = Path(self.rs.path) / "gateway-layer"
    v = self.v
    k8s = _k8s(self)
    gws = k8s.get("gateways") or {}
    inv_gws = self.inv.get("gateways") or {}
    ns_gw = k8s.get("gateway_namespace")
    v.sec("gateway layer: Gateways, hostnames and routes (chapter 7)")
    gc = _json(d / "gatewayclasses.json")
    cls = next((i for i in (gc or {}).get("items") or [] if i["metadata"]["name"] == "cilium"), None)
    v.check("GatewayClass cilium Accepted", bool(cls) and _cond((cls or {}).get("status") or {}, "Accepted"), "absent" if not cls else "not Accepted")
    gw = _json(d / "gateways.json")
    hr = _json(d / "httproutes.json")
    nss = _json(d / "namespaces.json")
    labels_of = {i["metadata"]["name"]: (i["metadata"].get("labels") or {}) for i in (nss or {}).get("items") or []}
    want_pairs = expected_pairs(k8s)
    for name, g in sorted(gws.items()):
        it = next((i for i in (gw or {}).get("items") or [] if i["metadata"]["name"] == name and i["metadata"].get("namespace") == ns_gw), None)
        ar = g.get("allowed_routes") or {}
        ls = next(iter(((it or {}).get("spec") or {}).get("listeners") or []), {})
        sel = (((ls.get("allowedRoutes") or {}).get("namespaces")) or {})
        ml = ((sel.get("selector") or {}).get("matchLabels")) or {}
        v.check(f"{name}: its listener {ls.get('name', '-')} admits HTTPRoutes from the namespaces labelled {ar.get('label')}=true only "
                f"(allowedRoutes from {sel.get('from', '-')})", bool(it) and sel.get("from") == "Selector" and ml == {ar.get("label"): "true"},
                f"from {sel.get('from')}, selector {ml}" if it else "absent")
        have = sorted(n for n, lb in labels_of.items() if lb.get(ar.get("label")) == "true")
        v.check(f"{name}: the namespaces carrying its label are the render's ({', '.join(ar.get('namespaces') or []) or 'none'})",
                have == sorted(ar.get("namespaces") or []), f"labelled: {', '.join(have) or 'none'}")
        routes = _routes_of(hr, name)
        st = ((it or {}).get("status") or {})
        attached = next((x.get("attachedRoutes") for x in st.get("listeners") or [] if x.get("name") == ls.get("name")), None)
        acc = [r for r in routes if r["accepted"] and r["resolved"]]
        v.check(f"{name}: {len(acc)} HTTPRoutes Accepted with their references resolved ({', '.join(sorted(r['namespace'] + '/' + r['name'] for r in acc))}), "
                f"the listener counting {attached} attached", bool(acc) and len(acc) == len(routes) and attached == len(acc),
                f"{len(routes)} routes name it, {len(acc)} accepted, attachedRoutes {attached}")
        got = _pairs(routes)
        want = want_pairs.get(name) or set()
        rows = "; ".join(f"{h} {', '.join(sorted(p for hh, p in want if hh == h))}" for h in sorted({h for h, _ in want}))
        v.check(f"{name} answers exactly the render's hostnames and paths: {rows}", got == want,
                "missing " + ", ".join(f"{h}{p}" for h, p in sorted(want - got)[:4]) + "; extra " + ", ".join(f"{h}{p}" for h, p in sorted(got - want)[:4]))
    dom = (self.inv.get("org") or {}).get("zone") or (self.inv.get("org") or {}).get("domain")
    admin_fq = {h if h.endswith("." + str(dom)) else f"{h}.{dom}" for h in ((self.inv.get("dns") or {}).get("admin") or [])}
    for name, g in sorted(gws.items()):
        if set(g.get("hostnames") or []) & admin_fq:
            v.check(f"{name}, the internal Gateway, carries the bare {(k8s.get('inference') or {}).get('path')} prefix and the admin hostnames "
                    f"({', '.join(sorted(admin_fq))})",
                    any(p == (k8s.get("inference") or {}).get("path") for _, p in _pairs(_routes_of(hr, name)))
                    and admin_fq <= {h for h, _ in _pairs(_routes_of(hr, name))}, "not both")
        else:
            leak = sorted({(r["namespace"] + "/" + r["name"]) for r in _routes_of(hr, name)
                           for h in r["spec"].get("hostnames") or [] if h in admin_fq})
            v.check(f"{name}: no HTTPRoute on it names an admin hostname", not leak, ", ".join(leak))

    v.sec("gateway layer: VIPs, leases and certificates (chapter 7)")
    leases = _json(d / "leases.json")
    # the nodes the L2 announcement policy selects: its role (inventory k8s.l2_announce.nodes), the
    # control nodes by default and the ingress nodes in revision 2
    role = str(((self.inv.get("k8s") or {}).get("l2_announce") or {}).get("nodes") or "control")
    if role == "control":
        announcers = (k8s.get("api") or {}).get("control") or []
    else:
        announcers = [n for n, x in (k8s.get("nodes") or {}).items() if f"node-role.tarnwick.example/{role}" in (x.get("labels") or {})]
    art = "an" if role[:1] in "aeiou" else "a"
    for name, g in sorted(gws.items()):
        ln = (g.get("l2_lease") or "").split("/", 1)[-1]
        it = next((i for i in (leases or {}).get("items") or [] if i["metadata"]["name"] == ln), None)
        holder = ((it or {}).get("spec") or {}).get("holderIdentity")
        v.check(f"{name}: {g['vip']} for {', '.join(g.get('hostnames') or [])}, announced by {holder} (its lease {ln}), {art} {role} node",
                holder in announcers, f"held by {holder}" if it else "no lease")
        t = _text(d / f"vip-{name}.txt")
        tx = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", t)
        sent, recv = (int(tx.group(1)), int(tx.group(2))) if tx else (0, -1)
        arp = re.search(r"lladdr ([0-9a-f:]{17})", t)
        frm = _text(d / f"vip-from-{name}.txt").strip() or _text(d / "vip-from.txt").strip() or "a GPU node"
        v.check(f"{name}: {g['vip']} from {frm} answers ARP ({arp.group(1) if arp else 'none'}) and "
                f"TCP 443, and no ICMP echo ({recv if recv >= 0 else '?'} of {sent} answered): every VIP check is a TCP connect",
                bool(arp) and "tcp-open" in t and recv == 0 and sent > 0, (t.strip().splitlines() or ["not read"])[-1][:120])
        c = _text(d / f"tls-{name}.txt")
        ok = "Verify return code: 0 (ok)" in c
        subj = [x.strip() or "the leaf (no subject, named by its SAN)" for x in re.findall(r"(?m)^\s*\d+ s:(.*)$", c)]
        iss = re.findall(r"(?m)^\s*i:(.*)$", c)
        v.check(f"{name}: the chain for {(k8s.get('inference') or {}).get('hostname') or 'the users hostname'} verifies against the lab root: "
                + " <- ".join(subj[:2]) + (f" <- {iss[-1].strip()}" if iss else ""), ok,
                (re.findall(r"(?m)^(?:verify error:.*|Verify return code:.*)$", c) or ["no verify line"])[-1])
    proof = _text(d / "ca-proof.txt")
    res = re.search(r"== RESULT: (\d+) passed, (\d+) failed", proof)
    v.check(f"the lab CA's proof on the lab host: {res.group(1) if res else '?'} leaves as expected, every inside leaf verifying and every "
            "outside one refused", bool(res) and res.group(2) == "0" and int(res.group(1)) > 0, (proof.strip().splitlines() or ["not read"])[-1])
    for line in proof.splitlines():
        m = re.match(r"^  PASS  (\S+): (\S+) refused \((.*)\)$", line)
        if m:
            v.check(f"the {m.group(1)} intermediate's leaf for {m.group(2)}, outside its name constraints, fails verification: {m.group(3)}",
                    "subtree" in m.group(3) or "name constraint" in m.group(3).lower(), m.group(3))

    v.sec("gateway layer: the timeout chain as the cluster runs it (chapter 7)")
    inf = k8s.get("inference") or {}
    tmo = inf.get("timeouts") or {}
    for rt in inf.get("routes") or []:
        r = next((x for x in (hr or {}).get("items") or [] if x["metadata"]["name"] == rt["name"] and x["metadata"].get("namespace") == inf.get("namespace")), None)
        tos = [rule.get("timeouts") or {} for rule in ((r or {}).get("spec") or {}).get("rules") or []]
        good = bool(tos) and all(_secs(x.get("request")) == tmo.get("request_s") and _secs(x.get("backendRequest")) == tmo.get("backend_request_s")
                                 for x in tos)
        v.check(f"{rt['name']} on {rt['gateway']}: every rule's timeouts request {tmo.get('request_s')}s, backendRequest {tmo.get('backend_request_s')}s",
                good, "; ".join(f"{x.get('request')}/{x.get('backendRequest')}" for x in tos[:3]) or "absent")
    cms = {i["metadata"]["name"]: i for i in (_json(d / "configmaps.json") or {}).get("items") or []}
    names_ = inf.get("configmaps") or {}
    ap = ((cms.get(names_.get("routes")) or {}).get("data") or {}).get("apisix.yaml", "")
    rd = re.search(r"(?ms)^upstreams:.*?^\s+read:\s*(\d+)", ap)
    rc = ((cms.get(names_.get("router")) or {}).get("data") or {}).get("config.yaml", "")
    at = re.search(r"(?m)^\s+timeout:\s*(\d+)", rc)
    nr = re.search(r"(?ms)^router_settings:.*?^\s+num_retries:\s*(\d+)", rc)
    read_s = int(rd.group(1)) if rd else None
    att = int(at.group(1)) if at else None
    tries = int(nr.group(1)) + 1 if nr else None
    chain = (att is not None and tries is not None and read_s is not None
             and tries * att < read_s < (tmo.get("backend_request_s") or 0) <= (tmo.get("request_s") or 0))
    v.check(f"the chain nests: the router's {tries} attempts of {att} s < the API gateway's upstream read {read_s} s < backendRequest "
            f"{tmo.get('backend_request_s')} s <= request {tmo.get('request_s')} s", chain and read_s == tmo.get("gateway_read_s")
            and att == tmo.get("router_attempt_s"), f"router {att} s x {tries}, read {read_s} s")
    cec = _idle(_json(d / "cec.json"))
    cm = ((_json(d / "cilium-config.json") or {}).get("data") or {})
    keys = {k: cm.get(k, "unset") for k in ("http-stream-idle-timeout", "proxy-stream-idle-timeout-seconds")}
    want = str((k8s.get("cilium") or {}).get("stream_idle_s") or "")
    for name, g in sorted(gws.items()):
        cname = (g.get("cec") or "").split("/", 1)[-1]
        vals = cec.get(cname) or ["no CiliumEnvoyConfig"]
        v.check(f"{name}: its listener's stream idle timeout as Cilium's operator wrote it: {', '.join(vals)} (cilium-config "
                + ", ".join(f"{k} {x}" for k, x in keys.items()) + ")",
                cname in cec and (not want or vals == [f"{want}s"]), ", ".join(vals))
