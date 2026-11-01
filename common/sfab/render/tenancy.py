"""gen/tenancy.json: what Part III's tools check and run in a lab of build A's state many from step 8
(chapters 8 to 11), resolved against the lab's model so the lab host needs no PyYAML and a changed
plan is drift to `sfab check`.

The audit groups (common/audit/lib-tenancy.sh, judged by common/audit/tenancy.py) and the held
connections (common/trace/hold_conns.py) read it. Each section is present from the step that adds
what it checks:

    audiences   step 8 on: a Gateway per audience. For each Gateway its audience, VIP, pool,
                announcement policy, lease, Service, certificate Secret and model route, the models
                that route carries, whether it carries the bare model prefix, the admin hostnames and
                the identity provider; the callers with their audiences and the models each audience
                may call; the ingress nodes that may hold a lease; the lease timers and the
                cilium-config keys Cilium's chart writes them to; and the refused mint the audit
                asks the key tool for (an application caller's key for a model outside its
                audience, which sfab/keys:4 refuses with exit 3 before it reads the Secret);
                the internet Gateway's column for every other population with a client in the
                lab (each one's connect to its VIP, with the outcome the firewall gives it,
                render/decisions.py's path); each population's connect to its own Gateway at
                its answer address at this step (reach), so chapter 7's key and placement
                checks ask only through a Gateway the population reaches; and the node each
                Gateway's certificate chain is read from (tls_from: a population's client that
                reaches it at its answer address, else the nodes' client, k8s-cp2, whose own
                datapath answers every VIP)
    dns         step 9 on (the internet side): the public server and the names it must answer and
                must not; the ISP's resolver, the clients it recurses for and a source outside them
                (the ISP router's own link address toward the firewall); every population's typed
                names on its own resolver for the AAAA check; the uplink side's public server, which
                publishes no platform name; the ISP router, which must hold no route into the
                inside prefixes; the Envoy certificate Secrets Cilium copies (recorded, not judged);
                and the internet client's connect to the published address, with the outcome the
                firewall gives it at this step (render/decisions.py's path); the nodes whose
                Envoy's loaded certificates the audit records (both ingress nodes and the first
                control node)
    firewall    step 10 on (the zone-keyed translation): the NAT and security rulebases in order, the
                published address with its interface, zone, NAT rule, translated address and
                security rule, the only rules that may name the isp zone, and each inside
                population's connect to the published address with the outcome the firewall gives it
                (the arrival zone keys the translation, so none of them is translated)
    hold        with chapter.yaml's tenancy.hold: the held-connection generator's plan, one row a
                population whose client is a container wired to the firewall (the staff, the
                operator, the internet users): its Gateway, the address and name it connects to, its
                arrival zone, the session filter that counts its connections on the firewall and the
                plan's bound on that count; the PAN-OS 12.1 session timeouts the measurement checks
    isolation   step 11 on: the negative checks of Chapter 11's audit (no route for another
                audience's model on a Gateway, no admin or identity hostname on the internet
                Gateway, no enterprise rule beyond the users' VIP, the isp zone translated to the
                internet Gateway alone, the ISP router with no inside route)

Standard library only; every name and address is the model's.
"""

from __future__ import annotations

import ipaddress
import json
import re

from . import RenderError

SCHEMA = 1
PATH = "gen/tenancy.json"
# Cilium's chart writes the l2announcements lease values into cilium-config under these keys (the
# agent's flags of the same names); the audit reads them back there
CILIUM_LEASE_KEYS = {"duration": "l2-announcements-lease-duration", "renew_deadline": "l2-announcements-renew-deadline",
                     "retry_period": "l2-announcements-retry-period"}
# the refused mint's key id: a fixed id the lab's own keys never take (they start at 0a1b2c3d)
REFUSED_ID = "fe000000"
# PAN-OS 12.1 help, "Session Timeouts" (seconds): what show session info must print on the pinned
# release before the chapter quotes it; discard is the time a denied TCP session holds its entry
SESSION_TIMEOUTS = {"tcp": 3600, "tcp_handshake": 10, "tcp_init": 5, "tcp_half_closed": 120, "tcp_time_wait": 15,
                    "discard_tcp": 90}
HOLD_KEYS = {"n", "hold_s", "every_s", "sport", "chat", "slack", "populations"}
INSIDE = ("10.0.0.0/8",)
# what the audit runs in each recorded node's Cilium agent pod to list the certificates its Envoy has
# loaded (Envoy's admin /certs: names, serials and expiry, never a key); the subcommand is the
# design's first choice and is confirmed on the pinned agent before the chapter quotes it
ENVOY_CERTS_CMD = ("cilium-dbg", "envoy", "admin", "certs")


def _err(where: str, msg: str):
    raise RenderError(f"{where}: {msg}")


def _bare(a) -> str | None:
    return str(a).split("/")[0] if a else None


def _num(v, where: str) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
        _err(where, "must be a positive number")
    return v


def on(model) -> bool:
    """A lab of state many from step 8 with the API gateway's callers: Part III."""
    from . import inference  # noqa: PLC0415

    return (getattr(model, "state", None) == "many" and (getattr(model, "step", None) or 0) >= 8 and model.k8s is not None
            and inference.enabled(model))


def _in(prefixes, a: str) -> bool:
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(p, strict=False) for p in prefixes)


# --------------------------------------------------------------------------------------------
# audiences


def audiences(model, inv: dict, k: dict) -> dict:
    inf = k["inference"]
    dns = inv.get("dns") or {}
    admin = set(dns.get("admin") or [])
    idp = k.get("identity") or {}
    routes = {r["gateway"]: r for r in inf["routes"]}
    gws = {}
    for name, g in sorted((k.get("gateways") or {}).items()):
        rt = routes.get(name)
        models = sorted({x["model"] for x in (rt or {}).get("rules") or [] if x.get("model")})
        bare = any(x.get("model") is None for x in (rt or {}).get("rules") or [])
        gws[name] = {
            "audience": g.get("audience"), "vip": g["vip"], "pool": list(g.get("pool_range") or []), "policy": g.get("l2_policy"),
            "lease": g.get("l2_lease"), "service": g.get("service"), "secret": (g.get("listener") or {}).get("secret"),
            "route": (rt or {}).get("name"), "models": [m["name"] for m in inf["models"]] if bare else models, "bare_prefix": bare,
            "admin": sorted(h for h in g.get("hostnames") or [] if h in admin),
            "idp": name in (idp.get("gateways") or []), "namespaces": list((g.get("allowed_routes") or {}).get("namespaces") or []),
            "label": (g.get("allowed_routes") or {}).get("label"),
        }
    callers = [{"id": c["id"], "kind": c["kind"], "audience": c.get("audience"), "models": list(c["models"]),
                "audience_models": list(c.get("audience_models") or [])} for c in inf.get("callers") or []]
    served = [m["name"] for m in inf["models"]]
    refused = None
    for c in callers:
        out = [m for m in served if m not in c["audience_models"]]
        if c["kind"] == "application" and c["audience"] and out:
            refused = {"caller": c["id"], "model": out[0], "id": REFUSED_ID, "audience": c["audience"],
                       "audience_models": c["audience_models"]}
            break
    lease = dict(k.get("l2_lease") or {})
    lease["config"] = {CILIUM_LEASE_KEYS[x]: lease[x] for x in CILIUM_LEASE_KEYS if lease.get("tuned") and lease.get(x)}
    ingress = [n for n in (inv.get("groups") or {}).get("ingress") or [] if n in inv["nodes"]]
    l2 = ((inv.get("k8s") or {}).get("l2_announce") or {})
    return {"gateways": gws, "callers": callers, "models": served, "refused_mint": refused, "lease": lease,
            "ingress_nodes": ingress, "holder_role": l2.get("nodes") or "control", "interfaces": list(l2.get("interfaces") or []),
            "policy_mode": (k.get("l2_policies") or {}).get("mode"), "keys": {"namespace": inf["namespace"],
                                                                                "secret": inf["keys"]["models"]["secret"]},
            "gateway_namespace": k.get("gateway_namespace"), "idp_hostname": idp.get("hostname")}


# --------------------------------------------------------------------------------------------
# split-horizon DNS


def _platform_names(inv: dict) -> list:
    dns = inv.get("dns") or {}
    names = []
    for key in ("users", "admin", "internal", "identity"):
        for n in dns.get(key) or []:
            if n not in names:
                names.append(n)
    return names + sorted(n for n in (dns.get("records") or {}) if n not in names)


def _pop_client(inv: dict, pop: dict, prefer: str | None = None) -> tuple:
    """(client, kind) a population's checks run from: the client the spec's matrix names for it when
    the lab holds it (k8s-cp2 for the nodes), else its first client container in the lab, else the
    first control node of its prefixes that asks its resolver."""
    nodes = inv["nodes"]
    if prefer and prefer in nodes:
        return prefer, nodes[prefer]["kind"]
    c = next((x for x in pop.get("clients") or [] if x in nodes), None)
    if c:
        return c, nodes[c]["kind"]
    for n in (inv.get("groups") or {}).get("ctrl") or []:
        x = nodes.get(n)
        if x and x.get("resolver") in (pop.get("resolvers") or []) and _in(pop.get("prefixes") or [], _bare(x.get("address")) or ""):
            return n, x["kind"]
    return None, None


def matrix_clients(model) -> dict:
    """{population: the client the spec's matrix tries it from}."""
    rows = ((getattr(model, "spec", None) or {}).get("matrix") or {}).get("rows") or []
    return {str(r.get("population")): str(r.get("client")) for r in rows if isinstance(r, dict) and r.get("client")}


def dns_plan(model, inv: dict, v) -> dict | None:
    pops = inv.get("populations") or {}
    prefer = matrix_clients(model)
    dns = inv.get("dns") or {}
    nodes = inv["nodes"]
    inet = next((p for p in pops.values() if p.get("translated") and p.get("resolver") in nodes), None)
    if inet is None:
        return None
    zone = dns.get("zone")
    pub = next((x for x in (dns.get("views") or {}).values() if any(_in(x.get("match_cidrs") or [], _bare(nodes[c]["address"]) or "")
                                                                      for c in inet["clients"] if c in nodes)
                and x.get("server") in nodes), None)
    if pub is None:
        _err("tenancy dns", "no public view answers the internet users")
    res_name = inet["resolver"]
    res = next((r for r in (dns.get("resolvers") or {}).values() if res_name in (r.get("servers") or [])), None)
    if res is None:
        _err("tenancy dns", f"{res_name} is no resolver of the spec's dns.resolvers")
    client = next(c for c in inet["clients"] if c in nodes)
    isp_rtr = nodes[client].get("gateway")
    rtr = next((n for n, x in nodes.items() if x.get("kind") == "frr" and any(_bare(i.get("address")) == isp_rtr
                                                                                for i in (x.get("ifaces") or {}).values())), None)
    if rtr is None:
        _err("tenancy dns", f"{client}'s gateway {isp_rtr} is no router of the lab")
    # the router's own address toward the firewall: a source outside the resolver's clients
    fwname = (inv.get("stages") or {}).get("fw")
    out_src = next((_bare(i["address"]) for i in (nodes[rtr].get("ifaces") or {}).values()
                    if (i.get("peer") or "").split(":")[0] == fwname and i.get("address")), None)
    if out_src is None or _in(res.get("clients") or [], out_src):
        _err("tenancy dns", f"{rtr} holds no address outside {res_name}'s clients to probe its refusal from")
    platform = _platform_names(inv)
    public = {n: pub["answer_address"] for n in pub.get("names") or []}
    absent = [n for n in platform if n not in public]
    rows = []
    for pid, p in sorted(pops.items()):
        c, kind = _pop_client(inv, p, prefer.get(pid))
        if c is None or not p.get("resolver") or p["resolver"] not in nodes:
            continue
        view = _answering_view(inv, p, c)
        names = list((view or {}).get("names") or [])
        rows.append({"population": pid, "client": c, "kind": kind, "resolver": p["resolver"], "server": p.get("resolver_address"),
                     "view": _view_id(inv, view), "names": names, "answer": (view or {}).get("answer_address")})
    # the uplink side's public server: a view of its own server that publishes no platform name
    ops = next((x for x in (dns.get("views") or {}).values() if x is not pub and x.get("server") in nodes
                and x.get("server") != pub.get("server") and not x.get("infra") and not (x.get("names") or [])), None)
    syn = _connect(model, v, client, inet["answer_address"], 443)
    return {
        "zone": zone,
        "public": {"server": pub["server"], "address": _bare(nodes[pub["server"]]["address"]), "view": _view_id(inv, pub), "names": public,
                   "absent": absent, "wildcard": f"sfab-nowhere.{zone}", "recursion_name": "registry.k8s.io", "from": client},
        "isp": {"server": res_name, "address": _bare(nodes[res_name]["address"]), "clients": list(res.get("clients") or []),
                "to": list(res.get("to") or []), "from": client, "name": next(iter(public), None),
                "answer": inet["answer_address"], "outside": {"node": rtr, "source": out_src}},
        "aaaa": rows,
        "ops": ({"server": ops["server"], "address": _bare(nodes[ops["server"]]["address"]), "view": _view_id(inv, ops),
                 "names": [n for key in ("users", "admin", "identity") for n in dns.get(key) or []]} if ops else None),
        "isp_router": {"node": rtr, "inside": list(INSIDE)},
        "internet_syn": dict(syn, client=client, address=inet["answer_address"], port=443, sport=42390),
    }


def reach_plan(model, inv: dict, k: dict, v) -> tuple:
    """(reach, tls_from): each population's connect to its own Gateway at its answer address, with
    the firewall's outcome at this step, from its first client in the lab; and per Gateway the node
    its certificate chain is read from: a client container of a population that reaches it, at
    that population's answer address, else the nodes' client (the spec's matrix names k8s-cp2) at
    the VIP, which the node's own datapath answers."""
    pops = inv.get("populations") or {}
    nodes = inv["nodes"]
    gws = k.get("gateways") or {}
    reach = []
    for pid, p in sorted(pops.items()):
        g = p.get("gateway")
        c = next((x for x in p.get("clients") or [] if x in nodes), None)
        if not g or g not in gws or c is None:
            continue
        addr = p.get("answer_address") or _bare(gws[g]["vip"])
        r = _connect(model, v, c, addr, 443)
        reach.append({"population": pid, "gateway": g, "client": c, "kind": nodes[c]["kind"], "address": addr, "outcome": r["outcome"],
                      "rule": r.get("rule"), "device": r.get("device")})
    prefer = matrix_clients(model)
    tls = {}
    for g in sorted(gws):
        row = next((r for r in reach if r["gateway"] == g and r["outcome"] == "reached" and r["kind"] == "client"), None)
        if row is not None:
            tls[g] = {"node": row["client"], "kind": "client", "address": row["address"], "population": row["population"]}
            continue
        node, kind = _pop_client(inv, pops.get("nodes") or {}, prefer.get("nodes"))
        vip = _bare(gws[g]["vip"])
        if node is None:
            _err("tenancy audiences", f"no client of the lab reaches {g}: no population's client, and no node of the cluster")
        r = _connect(model, v, node, vip, 443)
        if r["outcome"] != "reached":
            _err("tenancy audiences", f"{node} does not reach {g} at {vip}: {r['outcome']}")
        tls[g] = {"node": node, "kind": kind, "address": vip, "population": "nodes"}
    return reach, tls


def column_plan(model, inv: dict, k: dict, v, gateway: str) -> dict:
    """The internet Gateway's column: every population but the one whose Gateway it is, from its
    client in the lab, connecting to the Gateway's VIP, with the firewall's outcome (the staff, the
    operator and the internet host refused by deny-all-log, the nodes answered by their own
    datapath). A population with no client in the lab's slice is named, unchecked."""
    pops = inv.get("populations") or {}
    prefer = matrix_clients(model)
    vip = _bare(((k.get("gateways") or {}).get(gateway) or {}).get("vip"))
    rows, none = [], []
    for pid, p in sorted(pops.items()):
        if p.get("gateway") == gateway:
            continue
        c, kind = _pop_client(inv, p, prefer.get(pid))
        if c is None:
            none.append(pid)
            continue
        r = _connect(model, v, c, vip, 443)
        rows.append(dict(r, population=pid, client=c, kind=kind, address=vip, port=443))
    return {"gateway": gateway, "address": vip, "rows": rows, "no_client": none}


def _view_id(inv: dict, view) -> str | None:
    for vid, x in ((inv.get("dns") or {}).get("views") or {}).items():
        if x is view:
            return vid
    return None


def _answering_view(inv: dict, pop: dict, client: str):
    """The authoritative view that answers a population's client: the one matching its resolver's
    address (a recursive or forwarding resolver), else its own address (a public server asked
    directly)."""
    nodes = inv["nodes"]
    dns = inv.get("dns") or {}
    res = pop.get("resolver")
    raddr = _bare(nodes[res]["address"]) if res in nodes else None
    caddr = _bare(nodes[client]["address"])
    views = (dns.get("views") or {}).values()
    is_res = any(res in (r.get("servers") or []) for r in (dns.get("resolvers") or {}).values())
    for x in views:
        if is_res and raddr and _in(x.get("match_cidrs") or [], raddr):
            return x
    for x in views:
        if res in (x.get("servers") or [x.get("server")]) and _in(x.get("match_cidrs") or [], caddr):
            return x
    return None


def answers(inv: dict, client: str, host: str) -> bool:
    """Whether a client's own resolver answers a hostname: a resolver of the spec's dns.resolvers
    (it recurses or forwards to the platform's servers), or an authoritative server whose view for
    the client holds the name. A client whose resolver does not (the operator's: its public server
    publishes no platform name) names the address with curl --resolve, as chapter 7's tools do."""
    nodes = inv["nodes"]
    res = (nodes.get(client) or {}).get("resolver")
    if not res or res not in nodes:
        return False
    dns = inv.get("dns") or {}
    if any(res in (r.get("servers") or []) for r in (dns.get("resolvers") or {}).values()):
        return True
    caddr = _bare((nodes.get(client) or {}).get("address")) or ""
    return any(res in (x.get("servers") or [x.get("server")]) and _in(x.get("match_cidrs") or [], caddr) and host in (x.get("names") or [])
               for x in (dns.get("views") or {}).values())


def _connect(model, v, client: str, address: str, port: int) -> dict:
    """The firewall's outcome for one connect, as render/decisions.py's path computes it."""
    from .decisions import path  # noqa: PLC0415

    h = model.nodes[client]
    p = path(model, v, h, address, port, f"tenancy {client} to {address}:{port}")
    out = {"outcome": p["outcome"]}
    for key in ("rule", "action", "from_zone", "to_zone", "nat_rule", "at", "device", "layer", "drop", "counter"):
        if p.get(key) is not None:
            out[key] = p[key]
    out["hops"] = [x.get("what") for x in p["hops"]]
    return out


# --------------------------------------------------------------------------------------------
# the firewall: zone-keyed translation


def firewall_plan(model, inv: dict, v) -> dict | None:
    pops = inv.get("populations") or {}
    nodes = inv["nodes"]
    inet = next((p for p in pops.values() if p.get("translated") and any(c in nodes for c in p.get("clients") or [])), None)
    if inet is None or v is None:
        return None
    pub = inet["answer_address"]
    dn = [n for n in v.nat if n.dnat and _in(n.dst_cidrs, pub)]
    if not dn:
        return None
    n0 = dn[0]
    own = next((i for i in v.interfaces if i.address and _bare(i.address) == pub), None)
    if own is None:
        _err("tenancy firewall", f"the published address {pub} is no interface address of the firewall")
    sec = next((r for r in v.rules if set(r.from_zones) & set(n0.from_zones) and r.action == "allow" and _in(r.dst_cidrs, pub)), None)
    if sec is None:
        _err("tenancy firewall", f"no security rule admits the published address {pub}")
    isp_zones = set(n0.from_zones)
    gw = inet.get("gateway")
    prefer = matrix_clients(model)
    inside = []
    for pid, p in sorted(pops.items()):
        if p is inet:
            continue
        c, kind = _pop_client(inv, p, prefer.get(pid))
        if c is None:
            continue
        r = _connect(model, v, c, pub, 443)
        inside.append(dict(r, population=pid, client=c, kind=kind, address=pub, port=443))
    return {
        "nat_order": [n.name for n in v.nat], "security_order": [r.name for r in v.rules],
        "published": {"address": pub, "interface": own.name, "zone": own.zone, "nat_rule": n0.name, "translated": n0.dnat,
                      "gateway": gw, "security_rule": sec.name, "applications": list(sec.applications), "services": list(sec.services),
                      "from_zones": sorted(isp_zones)},
        "isp_nat": [n.name for n in v.nat if set(n.from_zones) & isp_zones],
        "isp_rules": [r.name for r in v.rules if set(r.from_zones) & isp_zones and r.action == "allow"],
        "enterprise": _enterprise(inv, v),
        "inside": inside,
    }


def _enterprise(inv: dict, v) -> dict | None:
    """The staff's allow rules toward the ingress zone: one, to the users' VIP /32 (Chapter 11's
    negative check)."""
    pops = inv.get("populations") or {}
    ent = pops.get("enterprise")
    if not ent:
        return None
    zones = set(ent.get("zones") or [])
    vip = ent.get("answer_address")
    ing = [r for r in v.rules if set(r.from_zones) & zones and r.action == "allow" and "ingress" in r.to_zones]
    return {"zones": sorted(zones), "vip": vip, "rules": [{"name": r.name, "dst": list(r.dst_cidrs)} for r in ing]}


# --------------------------------------------------------------------------------------------
# the held connections


def hold_plan(model, inv: dict, k: dict, raw: dict, fwp: dict | None) -> dict:
    where = "chapter.yaml tenancy.hold"
    if not isinstance(raw, dict) or set(raw) - HOLD_KEYS:
        _err(where, f"a mapping of {', '.join(sorted(HOLD_KEYS))}")
    n = int(_num(raw.get("n", 8), f"{where}.n"))
    hold_s = _num(raw.get("hold_s", 120), f"{where}.hold_s")
    every_s = _num(raw.get("every_s", 20), f"{where}.every_s")
    if every_s >= hold_s:
        _err(f"{where}.every_s", "shorter than hold_s: each connection is used again while it is held")
    sport = int(_num(raw.get("sport", 44000), f"{where}.sport"))
    slack = int(raw.get("slack", 2))
    pops = inv.get("populations") or {}
    nodes = inv["nodes"]
    want = raw.get("populations")
    rows = []
    tb = k.get("test_backend") or {}
    inf = k["inference"]
    from .decisions import own_caller  # noqa: PLC0415
    from .panos import view  # noqa: PLC0415

    v = view(model)
    for pid, p in sorted(pops.items()):
        if want is not None and pid not in want:
            continue
        g = p.get("gateway")
        c = next((x for x in p.get("clients") or [] if x in nodes and nodes[x]["kind"] == "client"), None)
        if not g or c is None or g not in (tb.get("routes") or {}):
            continue
        host = (k["gateways"][g].get("hostnames") or [None])[0]
        addr = p["answer_address"]
        r = _connect(model, v, c, addr, 443)
        if r["outcome"] != "reached":
            _err(where, f"{c} cannot reach {g} at {addr}: {r['outcome']}")
        zone = r["from_zone"]
        flt = f"from {zone} destination {addr} destination-port 443"
        resolver_in = answers(inv, c, host)
        caller = None
        rt = next((x for x in inf["routes"] if x["gateway"] == g), None)
        chat = None
        if raw.get("chat", True) and rt:
            mdl = next((m for m in inf["models"] if any(x["model"] in (None, m["name"]) for x in rt["rules"])), None)
            if mdl:
                caller, _default = own_caller(model, inf, model.populations[pid], mdl["name"])
                chat = {"model": mdl["name"], "url": f"https://{host}{mdl['path']}/v1/chat/completions", "caller": caller}
        rows.append({"population": pid, "client": c, "gateway": g, "address": addr, "hostname": host, "zone": zone,
                     "translated_to": r.get("at") if r.get("at") != addr else None, "rule": r.get("rule"), "nat_rule": r.get("nat_rule"),
                     "resolve": None if resolver_in else f"{host}:443:{addr}", "path": tb.get("path"),
                     "filter": flt, "sport": sport + 100 * len(rows), "chat": chat,
                     "bound": {"min": n, "max": n + (1 if chat else 0) + slack}})
    if not rows:
        _err(where, "no population with a client container reaches its own Gateway's test backend")
    return {"n": n, "hold_s": hold_s, "every_s": every_s, "slack": slack, "rows": rows, "timeouts": dict(SESSION_TIMEOUTS),
            "ca_root": "/shared/ca/root.crt", "dir": "/tmp/sfab-hold"}


# --------------------------------------------------------------------------------------------


def plan(model, ctx) -> dict:
    from . import k8s  # noqa: PLC0415
    from .inventory import inventory  # noqa: PLC0415
    from .panos import view  # noqa: PLC0415

    inv = inventory(model)
    k = k8s.summary(model, ctx)
    v = view(model) if model.firewall is not None else None
    step = model.step or 0
    out = {"schema": SCHEMA, "lab": model.lab, "step": step, "audiences": audiences(model, inv, k)}
    if v is not None:
        a = out["audiences"]
        a["reach"], a["tls_from"] = reach_plan(model, inv, k, v)
        inet = next((g for g, x in a["gateways"].items() if x["audience"] == "internet"), None)
        if inet is not None:
            a["column"] = column_plan(model, inv, k, v, inet)
    d = dns_plan(model, inv, v) if v is not None else None
    if d is not None:
        ctrl = [n for n in (inv.get("groups") or {}).get("ctrl") or [] if n in inv["nodes"]]
        ing = [n for n in (inv.get("groups") or {}).get("ingress") or [] if n in inv["nodes"]]
        d["envoy_certs"] = {"namespace": "cilium-secrets",
                            "secrets": sorted(f"{k['gateway_namespace']}-{g['listener']['secret']}" for g in k["gateways"].values()),
                            "nodes": ing + ctrl[:1], "command": list(ENVOY_CERTS_CMD)}
        out["dns"] = d
    fwp = firewall_plan(model, inv, v) if v is not None else None
    if fwp is not None:
        out["firewall"] = fwp
    raw = ((getattr(model.meta.chapter, "raw", None) or {}).get("tenancy") or {}) if model.meta.chapter is not None else {}
    if not isinstance(raw, dict) or set(raw) - {"hold", "isolation"}:
        _err("chapter.yaml tenancy", "a mapping of hold and isolation")
    if raw.get("hold") is not None:
        if fwp is None:
            _err("chapter.yaml tenancy.hold", "needs the zone-keyed translation (step 10 on): every population reaches its own Gateway")
        out["hold"] = hold_plan(model, inv, k, raw["hold"], fwp)
    if raw.get("isolation"):
        if fwp is None or d is None:
            _err("chapter.yaml tenancy.isolation", "needs the internet side and the zone-keyed translation (step 11)")
        a = out["audiences"]
        inet = next(g for g, x in a["gateways"].items() if x["audience"] == "internet")
        out["isolation"] = {
            "gateway": inet, "forbidden_models": [m for m in a["models"] if m not in a["gateways"][inet]["models"]],
            "forbidden_hostnames": sorted(set((inv.get("dns") or {}).get("admin") or []) | ({a["idp_hostname"]} if a["idp_hostname"] else set())),
            "enterprise": fwp["enterprise"], "isp_nat": fwp["isp_nat"], "translated": fwp["published"]["translated"],
            "isp_router": d["isp_router"],
        }
    return out


def render(model, ctx) -> dict:
    if not on(model):
        return {}
    return {PATH: json.dumps(plan(model, ctx), indent=2, sort_keys=True) + "\n"}


__all__ = ["render", "on", "plan", "SESSION_TIMEOUTS", "CILIUM_LEASE_KEYS"]


# --------------------------------------------------------------------------------------------
# Part III's drills (chapter.yaml drills.list, rendered into gen/drills.json by render/drills.py)

P3_DRILL_KEYS = ("lease_loss", "isolation", "leaked_key")
P3_TIMING_DEFAULTS = {
    "lead_s": 20,           # the probes running before the cut, or before the forbidden tries begin
    "hold_s": 30,           # a lease drill's ports stay shut this long
    "tail_s": 30,           # the probes keep running after the restore, or after the last try
    "settle_max_s": 300,    # the bonds back on both legs and every lease on an ingress node within this
    "whole_polls": 3,       # the lab must be whole before and after a drill: polls in a row, 5 s apart
}
LEASE_KEYS = {"echo", "connect", "model", "interval_s", "connect_interval_s"}
ISO_KEYS = {"rounds", "interval_s", "factors", "columns"}
LEAK_KEYS = {"from", "model", "caller", "id_base", "interval_s", "accept_max_s"}


def _bare_vip(inv: dict, g: str) -> str:
    return _bare((inv.get("gateways") or {}).get(g, {}).get("vip"))


def _client_target(inv: dict, k: dict, client: str, gateway: str, where: str) -> dict:
    nodes = inv["nodes"]
    c = nodes.get(client)
    if c is None or c.get("kind") != "client":
        _err(where, f"{client!r} must be a client container of the lab (the probe runs its python3)")
    pop = next((p for p in (inv.get("populations") or {}).values() if client in (p.get("clients") or [])), None)
    if pop is None or pop.get("gateway") != gateway:
        _err(where, f"{client}'s population is not {gateway}'s")
    host = (k["gateways"][gateway].get("hostnames") or [None])[0]
    addr = pop.get("answer_address")
    resolver_in = answers(inv, client, host)
    return {"client": client, "gateway": gateway, "address": addr, "vip": _bare_vip(inv, gateway), "hostname": host,
            "resolve": None if resolver_in else f"{host}:443:{addr}"}


def lease_drill(model, inv: dict, k: dict, d: dict, where: str) -> dict:
    from .drills import _shut_session  # noqa: PLC0415

    b = d.get("lease_loss") or {}
    if not isinstance(b, dict) or set(b) - LEASE_KEYS:
        _err(f"{where}.lease_loss", f"a mapping of {', '.join(sorted(LEASE_KEYS))}")
    a = audiences(model, inv, k)
    tb = k.get("test_backend") or {}
    echo = []
    for i, x in enumerate(b.get("echo") or []):
        t = _client_target(inv, k, str((x or {}).get("from") or ""), str((x or {}).get("gateway") or ""), f"{where}.lease_loss.echo[{i}]")
        t["url"] = f"https://{t['hostname']}{tb.get('path') or '/echo'}"
        echo.append(t)
    if not echo:
        _err(f"{where}.lease_loss.echo", "names no probe: the gap is measured on the test backend through each Gateway")
    connect = [{"client": t["client"], "gateway": t["gateway"], "address": t["address"], "port": 443} for t in echo]
    m = b.get("model")
    model_probe = None
    if m:
        t = _client_target(inv, k, str(m.get("from") or ""), str(m.get("gateway") or ""), f"{where}.lease_loss.model")
        inf = k["inference"]
        mi = next((x for x in inf["models"] if x["name"] == str(m.get("model") or "")), None)
        if mi is None:
            _err(f"{where}.lease_loss.model.model", "a model the lab serves")
        t.update(model=mi["name"], url=f"https://{t['hostname']}{mi['path']}/v1/chat/completions", every=int(m.get("every", 1)),
                 keys={"namespace": inf["namespace"], "secret": inf["keys"]["models"]["secret"]})
        model_probe = t
    nodes = inv["nodes"]
    cands = {}
    for n in a["ingress_nodes"]:
        sws = {}
        for eth, nic in sorted((nodes[n].get("nics") or {}).items()):
            if nic.get("role") != "bond-member" or not nic.get("peer"):
                continue
            sw, peth = nic["peer"].split(":")
            native = ((nodes.get(sw) or {}).get("nics") or {}).get(peth, {}).get("native")
            if not native:
                pcs = (nodes.get(sw) or {}).get("portchannels") or {}
                native = next((pc["members"][pc["member_eths"].index(peth)] for pc in pcs.values() if peth in (pc.get("member_eths") or [])), None)
            if not native:
                _err(where, f"{n}'s {eth} lands on {sw} {peth}, a port the render cannot name")
            sws.setdefault(sw, []).append(native)
        cands[n] = {"members": [{"switch": sw, "port": p} for sw, ps in sorted(sws.items()) for p in ps],
                    "shut": {sw: _shut_session(ps, "shutdown") for sw, ps in sorted(sws.items())},
                    "restore": {sw: _shut_session(ps, "no shutdown") for sw, ps in sorted(sws.items())},
                    "mac": (nodes[n].get("bond") or {}).get("mac")}
    if len(cands) < 2:
        _err(where, "the lease drill needs two ingress nodes: one to lose, one to take the leases")
    lease = a["lease"]
    lo, hi = (lease.get("failover_ms") or [None, None])[:2]
    return {"kind": "lease-loss", "echo": echo, "connect": connect, "model": model_probe,
            "interval_s": _num(b.get("interval_s", 2), f"{where}.lease_loss.interval_s"),
            "connect_interval_s": _num(b.get("connect_interval_s", 0.5), f"{where}.lease_loss.connect_interval_s"),
            "candidates": cands, "leases": {g: x["lease"] for g, x in a["gateways"].items()},
            "vips": {g: x["vip"] for g, x in a["gateways"].items()}, "ingress": a["ingress_nodes"],
            "prediction": {"min_ms": lo, "max_ms": hi, "tuned": bool(lease.get("tuned")), "duration": lease.get("duration"),
                           "renew_deadline": lease.get("renew_deadline"), "retry_period": lease.get("retry_period")},
            # where the pods the cut could take run, and the Services whose endpoints the drill reads
            "endpoints": sorted({tb.get("namespace") or "echo", k["inference"]["namespace"]})}


def isolation_drill(model, inv: dict, k: dict, d: dict, where: str) -> dict:
    """Chapter 11: every population's held connections, its own Gateway probed while it tries the
    matrix's other cells it must not reach (the other Gateways, staff's path on the internet Gateway,
    the admin hostnames), once at the plan's load and once at each further factor."""
    from . import decisions  # noqa: PLC0415
    from .panos import view  # noqa: PLC0415

    b = d.get("isolation") or {}
    if not isinstance(b, dict) or set(b) - ISO_KEYS:
        _err(f"{where}.isolation", f"a mapping of {', '.join(sorted(ISO_KEYS))}")
    raw = ((getattr(model.meta.chapter, "raw", None) or {}).get("tenancy") or {}).get("hold")
    if raw is None or not decisions.on(model):
        _err(f"{where}.isolation", "needs chapter.yaml tenancy.hold (the held connections) and decisions: true (the matrix's cells)")
    hp = hold_plan(model, inv, k, raw, firewall_plan(model, inv, view(model)))
    mx = decisions.matrix(model)
    cols = [str(x) for x in (b.get("columns") or ["gw-internal", "gw-users", "gw-inet", "staff", "admin"])]
    known = {c["id"] for c in mx["columns"]}
    for c in cols:
        if c not in known:
            _err(f"{where}.isolation.columns", f"{c!r} is not a column of the matrix")
    rows = []
    for hr in hp["rows"]:
        cells = [c for c in mx["cells"] if c["client"] == hr["client"] and c["column"] in cols]
        tries = []
        for c in cells:
            q = (c.get("requests") or [{}])[0]
            if c["kind"] == "model" and c["mode"] == "allowed":
                continue          # an allowed model cell needs a key: the own-Gateway probe stands for the allowed side
            t = {"cell": c["id"], "column": c["column"], "mode": c["mode"], "kind": "connect" if q.get("id") == "connect" else "http",
                 "address": c.get("address"), "port": int(c.get("port") or 443)}
            if t["kind"] == "http":
                t.update(url=q.get("url"), method="GET", hostname=c.get("hostname"),
                         resolve=f"{c['hostname']}:443:{c['address']}" if c.get("pin") else None)
            tries.append(t)
        rows.append({"population": hr["population"], "client": hr["client"], "gateway": hr["gateway"],
                     "own": {"url": f"https://{hr['hostname']}{hr['path']}", "resolve": hr["resolve"], "address": hr["address"]},
                     "tries": tries})
    factors = [int(x) for x in (b.get("factors") or [1, 2])]
    if factors[0] != 1 or any(x < 1 for x in factors):
        _err(f"{where}.isolation.factors", "starts at 1 (the plan's load), each a whole multiple of it")
    return {"kind": "isolation", "hold": hp, "rows": rows, "factors": factors,
            "rounds": int(_num(b.get("rounds", 10), f"{where}.isolation.rounds")),
            "interval_s": _num(b.get("interval_s", 3), f"{where}.isolation.interval_s"), "timeout_s": mx.get("timeout_s", 4)}


def leaked_key_drill(model, inv: dict, k: dict, d: dict, where: str) -> dict:
    """Chapter 11: the one cell no network layer holds. A key of another audience's application caller
    (batch's, the enterprise's) minted, sent from the internet client through its own Gateway to a
    model that Gateway carries, answered and logged under that caller; then revoked, and refused."""
    b = d.get("leaked_key") or {}
    if not isinstance(b, dict) or set(b) - LEAK_KEYS:
        _err(f"{where}.leaked_key", f"a mapping of {', '.join(sorted(LEAK_KEYS))}")
    inf = k["inference"]
    client = str(b.get("from") or "")
    pop = next((p for p in (inv.get("populations") or {}).values() if client in (p.get("clients") or [])), None)
    if pop is None or not pop.get("gateway"):
        _err(f"{where}.leaked_key.from", f"{client!r} is no client of a population with a Gateway")
    t = _client_target(inv, k, client, pop["gateway"], f"{where}.leaked_key.from")
    mi = next((m for m in inf["models"] if m["name"] == str(b.get("model") or "")), None)
    rt = next((r for r in inf["routes"] if r["gateway"] == pop["gateway"]), None)
    if mi is None or rt is None or not any(x["model"] in (None, mi["name"]) for x in rt["rules"]):
        _err(f"{where}.leaked_key.model", f"a model {pop['gateway']}'s route carries")
    caller = next((c for c in inf.get("callers") or [] if c["id"] == str(b.get("caller") or "")), None)
    if caller is None or caller["kind"] != "application" or mi["name"] not in caller["models"]:
        _err(f"{where}.leaked_key.caller", f"an application caller that may call {mi['name']}")
    if caller.get("audience") == pop.get("audience"):
        _err(f"{where}.leaked_key.caller", f"{caller['id']} is in {client}'s own audience: its key is no leak")
    base = str(b.get("id_base") or "fb000000")
    if not re.match(r"^[0-9a-f]{8}$", base):
        _err(f"{where}.leaked_key.id_base", "eight hex digits; each pass's key id adds the pass to it")
    return {"kind": "leaked-key", "client": client, "gateway": pop["gateway"], "address": t["address"], "hostname": t["hostname"],
            "resolve": t["resolve"], "url": f"https://{t['hostname']}{mi['path']}/v1/chat/completions", "model": mi["name"],
            "caller": caller["id"], "caller_audience": caller.get("audience"), "client_audience": pop.get("audience"), "id_base": base,
            "interval_s": _num(b.get("interval_s", 2), f"{where}.leaked_key.interval_s"),
            "accept_max_s": _num(b.get("accept_max_s", 300), f"{where}.leaked_key.accept_max_s"),
            "keys": {"namespace": inf["namespace"], "secret": inf["keys"]["models"]["secret"]}, "rejected": dict(inf["rejected"]),
            "api_gateway": {"namespace": inf["namespace"], "selector": f"app.kubernetes.io/name={inf['gateway']['name']}"},
            "probe": inf["probe"]["name"], "ca_root": "/shared/ca/root.crt"}


def p3_drill(model, inv: dict, d: dict, seen: set, ctx) -> dict:
    """One of Part III's drills, from render/drills.py: the lease-holder loss (chapter 8) or the
    isolation drill under load (chapter 11)."""
    from . import k8s  # noqa: PLC0415

    did = str(d.get("id") or "")
    where = f"chapter.yaml drills.list[{did or '?'}]"
    if not re.match(r"^[a-z][a-z0-9-]*$", did) or did in seen:
        _err(where, "id must be a new name of lower case letters, digits and hyphens")
    seen.add(did)
    extra = set(d) - {"id", "title", "max_passes"} - set(P3_DRILL_KEYS)
    if extra:
        _err(where, f"unknown keys {sorted(extra)}")
    k = k8s.summary(model, ctx)
    if "lease_loss" in d:
        body = lease_drill(model, inv, k, d, where)
    elif "leaked_key" in d:
        body = leaked_key_drill(model, inv, k, d, where)
    else:
        body = isolation_drill(model, inv, k, d, where)
    out = {"id": did, "title": str(d.get("title") or did)}
    if d.get("max_passes") is not None:
        out["max_passes"] = int(_num(d["max_passes"], f"{where}.max_passes"))
    out.update(body)
    return out
