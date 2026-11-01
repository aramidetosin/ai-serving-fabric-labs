#!/usr/bin/env python3
"""Part III's audit groups of judge.py (chapters 8 to 11), judged from the files
common/audit/lib-tenancy.sh saves, against gen/tenancy.json (sfab.render.tenancy).

audiences (audiences/, chapter 8): a Gateway per audience

  route sets    each Gateway's accepted HTTPRoutes carry exactly its audience's row of hostnames and
                paths (the render's, render/inference.py and render/k8s.py): the internet Gateway
                chat's path and the test backend's /echo, nothing for staff
  hostnames     the admin hostnames only on the Gateway the render gives them (the internal one),
                the identity provider's only on the Gateways it is published on
  namespaces    the namespaces labelled for each Gateway are the render's (for the internet
                Gateway, echo and inference alone)
  callers       every caller the API gateway's routes admit for a model may call that model in its
                audience (the routes ConfigMap's consumer-restriction whitelists against the callers'
                audiences)
  keys          each Gateway's certificate has its own key: no two public key fingerprints equal
  leases        each Gateway's lease held by an ingress node, at the tuned duration
  timers        cilium-config holds the tuned lease timers under Cilium's keys
  policies      one announcement policy per audience, each selecting its own audience's Services
                on the rendered interfaces
  refused mint  the key Job for a model outside its caller's audience failed with the key tool's
                refusal, and the key Secret holds the same fields and fingerprints after it

split-horizon (split-horizon/, chapter 9): one hostname, an answer per population

  the public    the public server answers exactly the spec's public names with the published
  server        address, authoritatively; no admin, internal, identity or infrastructure name; no
                wildcard; recursion refused
  the ISP's     the ISP's resolver answers its customer with the published address, recursing, and
  resolver      refuses a source outside its clients (the ISP router's link address)
  AAAA          every population's typed name answered NOERROR with no AAAA record through its own
                resolver, beside its A answer (a resolver that answered A and failed AAAA would break
                a stub that asks both: Chapter 9's break)
  the uplink    the uplink side's public server holds no platform name
  the ISP       the ISP router holds no route into the inside prefixes
  router
  the SYN       the internet client's connect to the published address meets the firewall as the
                render says at this step (deny-all-log from isp to isp before the translation is
                configured, the translation and isp-to-internet-gateway after)
  Envoy's       Cilium's copies of the Gateway certificates recorded (a KNOWN-free record: every
  copies        node's Envoy holds every Gateway's key, Chapter 8; the audit does not fail on it)

zone-nat (zone-nat/, chapter 10): translation keyed on the arrival zone

  order         the NAT and security rulebases in the rendered order
  translation   the isp zone's one NAT rule, from isp to isp, on the published address and tcp/443,
                translating to the internet Gateway's VIP; the isp zone's one allow rule, to the
                published address, ssl only
  from inside   each inside population's connect to the published address untranslated and refused
                where the render says (deny-all-log from its own zone to isp, or silence at the
                router in front of the firewall, whose table holds no route to it)
  sessions      with the held connections: every connection held with every reply 200, and each
                zone's session count on the firewall within the plan's bound

isolation (chapter 11): the negative checks, from the three groups' files

  no HTTPRoute for a model outside the internet audience on the internet Gateway; no admin or
  identity hostname on it; no enterprise allow rule toward the ingress zone that reaches another
  Gateway's pool; the isp zone translated to the internet Gateway alone; the ISP router with no route
  into the inside prefixes.

As a command:  tenancy.py tlog-missing --plan gen/tenancy.json --dir D   (zone-nat's inside connects
the traffic log in D does not hold yet: 0 when every refused one is there). Standard library only.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

STATUS = re.compile(r";; ->>HEADER<<- opcode: \w+, status: (\w+), id: \d+")
FLAGS = re.compile(r";; flags: ([a-z ]*);")
ANS = re.compile(r"^(\S+)\s+(\d+)\s+IN\s+(A|AAAA|CNAME)\s+(\S+)\s*$")
FRR_ROUTE = re.compile(r"^([A-Z])[>*]*\s*\*?\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+")


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


def slug(s: str) -> str:
    return re.sub(r"^-|-$", "", re.sub(r"[^a-z0-9]+", "-", str(s).lower()))


def plan_of(render) -> dict:
    return _json(Path(render) / "gen" / "tenancy.json") or {}


def dig_result(text: str) -> dict:
    """dig's (or dnsq.py's) answer: {status, flags, answers [(name, type, value)], line}; status
    'timeout' when no server answered, 'none' when nothing was read."""
    out = {"status": "none", "flags": [], "answers": [], "line": None}
    for i, line in enumerate((text or "").splitlines(), 1):
        s = line.strip()
        if "connection timed out" in s or "no servers could be reached" in s:
            out["status"] = "timeout"
            out["line"] = i
        m = STATUS.search(s)
        if m:
            out["status"], out["line"] = m.group(1), i
        m = FLAGS.search(s)
        if m:
            out["flags"] = m.group(1).split()
        m = ANS.match(s)
        if m and not s.startswith(";"):
            out["answers"].append((m.group(1).rstrip("."), m.group(3), m.group(4)))
    return out


def dig_text(r: dict) -> str:
    vals = ", ".join(f"{t} {v}" for _n, t, v in r["answers"])
    return f"{r['status']}" + (f", {vals}" if vals else ", no answer") + (f" (flags {' '.join(r['flags'])})" if r["flags"] else "")


def router_routes(text: str) -> list:
    out = []
    for i, line in enumerate((text or "").splitlines(), 1):
        m = FRR_ROUTE.match(line.strip())
        if m:
            out.append({"type": m.group(1), "dest": m.group(2), "line": i})
    return out


def overlaps(a: str, b: str) -> bool:
    try:
        return ipaddress.ip_network(a, strict=False).overlaps(ipaddress.ip_network(b, strict=False))
    except ValueError:
        return False


def covers(prefix: str, address: str) -> bool:
    try:
        return ipaddress.ip_address(address) in ipaddress.ip_network(prefix, strict=False)
    except ValueError:
        return False


def connect_line(text: str) -> dict:
    """syn_connect.py's line: {outcome (CONNECTED, TIMEOUT, REFUSED, ERROR:...), line}."""
    for i, line in enumerate((text or "").splitlines(), 1):
        x = line.split()
        if len(x) >= 6 and x[2] in ("0", "1"):
            return {"outcome": x[4], "line": i}
    return {"outcome": "none", "line": None}


def hold_events(text: str) -> list:
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def hold_summary(events: list) -> dict:
    opened = {e["conn"] for e in events if e.get("event") == "open"}
    replies = [e for e in events if e.get("event") == "reply"]
    errors = [e for e in events if e.get("event") == "error"]
    held = next((e for e in events if e.get("event") == "held"), None)
    done = next((e for e in events if e.get("event") == "done"), None)
    by_conn: dict = {}
    for e in replies:
        by_conn.setdefault(e["conn"], []).append(e)
    first = min((e["t"] for e in events if e.get("event") == "open"), default=None)
    last = max((e["t"] for e in events if e.get("event") == "closed"), default=None)
    return {"opened": len(opened), "replies": len(replies), "non200": sum(1 for e in replies if e.get("status") != 200),
            "errors": len(errors), "held": (held or {}).get("open"), "alive": (done or {}).get("open"),
            "rounds": max((len(x) for x in by_conn.values()), default=0), "span_s": (last - first) if first and last else None,
            "first_error": (errors[0].get("error") if errors else None)}


COUNT = re.compile(r"(?i)number of sessions that match filter\s*:?\s*(\d+)")
TIMEOUTS = {
    "tcp": re.compile(r"(?i)^\s*TCP default timeout:\s*(\d+)\s*secs"),
    "tcp_init": re.compile(r"(?i)^\s*TCP session timeout before SYN-ACK received:\s*(\d+)\s*secs"),
    "tcp_handshake": re.compile(r"(?i)^\s*TCP session timeout before 3-way handshaking:\s*(\d+)\s*secs"),
    "tcp_half_closed": re.compile(r"(?i)^\s*TCP half-closed session timeout:\s*(\d+)\s*secs"),
    "tcp_time_wait": re.compile(r"(?i)^\s*TCP session timeout in TIME_WAIT:\s*(\d+)\s*secs"),
    "discard_tcp": re.compile(r"(?i)^\s*TCP discard timeout:\s*(\d+)\s*secs"),
}


def session_count(text: str) -> int | None:
    m = COUNT.search(text or "")
    return int(m.group(1)) if m else None


def session_timeouts(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        for k, rx in TIMEOUTS.items():
            m = rx.match(line)
            if m and k not in out:
                out[k] = int(m.group(1))
    return out


def judge_hold(v, d: Path, hp: dict, tag: str, factor: int = 1, label: str = "") -> dict:
    """The held connections of every hold row in d: each connection held with every reply 200, and
    the row's session count within its bound (times factor, the isolation drill's doubled load)."""
    out = {}
    for r in hp["rows"]:
        pop = r["population"]
        s = hold_summary(hold_events(_text(d / f"hold-{pop}.jsonl")))
        n = hp["n"] * factor
        v.check(f"{label}{pop}: {n} connection(s) from {r['client']} held to {r['gateway']} at {r['address']}:443 ({r['hostname']}), "
                f"{s['replies']} replies, every one 200", s["opened"] == n and s["held"] == n and s["non200"] == 0 and s["errors"] == 0,
                f"opened {s['opened']}, held {s['held']}, non-200 {s['non200']}, errors {s['errors']}"
                + (f" ({s['first_error']})" if s["first_error"] else ""))
        c = session_count(_text(d / f"counts-{tag}-{pop}.txt"))
        lo, hi = n, n + (r["bound"]["max"] - r["bound"]["min"])
        v.check(f"{label}{pop}: the firewall counts {c if c is not None else '?'} session(s) {r['filter']} while they are held, "
                f"within the plan's bound {lo} to {hi}", c is not None and lo <= c <= hi,
                "no count read" if c is None else f"{c} outside {lo} to {hi}")
        out[pop] = {"held": s, "count": c, "bound": [lo, hi]}
    return out


# --------------------------------------------------------------------------------------------
# audiences


def _apisix_whitelists(yaml_text: str) -> dict:
    """{route id: [callers]} from the API gateway's apisix.yaml (render/inference.py's shape)."""
    out, cur, inwl, section = {}, None, False, None
    for line in (yaml_text or "").splitlines():
        m = re.match(r"^([a-z_]+):\s*$", line)
        if m:
            section, cur, inwl = m.group(1), None, False
            continue
        if section != "routes":
            continue
        m = re.match(r"^- id: (\S+)\s*$", line)
        if m:
            cur, inwl = m.group(1), False
            out[cur] = []
            continue
        if cur is None:
            continue
        if re.match(r"^\s+whitelist:\s*$", line):
            inwl = True
            continue
        m = re.match(r"^\s+- (\S+)\s*$", line)
        if inwl and m:
            out[cur].append(m.group(1))
            continue
        if inwl and not re.match(r"^\s+- ", line):
            inwl = False
    return out


def _certs(text: str) -> dict:
    out, cur = {}, None
    for line in (text or "").splitlines():
        m = re.match(r"^== (\S+) (\S+)", line)
        if m:
            cur = m.group(1)
            out[cur] = None
            continue
        m = re.match(r"^spki sha256 ([0-9a-f]{64})", line.strip())
        if m and cur:
            out[cur] = m.group(1)
    return out


def _fields(text: str) -> dict:
    out = {}
    for line in (text or "").splitlines():
        x = line.split()
        if len(x) == 2 and "." in x[0]:
            out[x[0]] = x[1]
    return out


def g_audiences(self, names):
    import gwlayer as GL  # noqa: PLC0415

    d = Path(self.rs.path) / "audiences"
    v = self.v
    p = plan_of(self.render).get("audiences")
    v.sec("audiences: a Gateway per audience (chapter 8)")
    if not p:
        v.skip("the audiences", "the lab has no Gateway per audience")
        return
    k8s = GL._k8s(self)
    hr = _json(d / "httproutes.json")
    nss = _json(d / "namespaces.json")
    want_pairs = GL.expected_pairs(k8s)
    admin_all = sorted({h for g in p["gateways"].values() for h in g["admin"]} | set(((self.inv.get("dns") or {}).get("admin") or [])))
    labels_of = {i["metadata"]["name"]: (i["metadata"].get("labels") or {}) for i in (nss or {}).get("items") or []}
    for name, g in sorted(p["gateways"].items()):
        routes = GL._routes_of(hr, name)
        got = GL._pairs(routes)
        want = want_pairs.get(name) or set()
        rows = "; ".join(f"{h} {', '.join(sorted(x for hh, x in want if hh == h))}" for h in sorted({h for h, _ in want}))
        v.check(f"{name} ({g['audience']}): its routes are its audience's row, {rows}", bool(routes) and got == want,
                "missing " + ", ".join(f"{h}{x}" for h, x in sorted(want - got)[:4]) + "; extra " + ", ".join(f"{h}{x}" for h, x in sorted(got - want)[:4]))
        hosts = {h for h, _ in got}
        have_admin = sorted(h for h in hosts if h in admin_all)
        v.check(f"{name}: admin hostnames {', '.join(g['admin']) or 'none'}, as the render puts them", have_admin == g["admin"],
                f"carries {', '.join(have_admin) or 'none'}")
        idp = p.get("idp_hostname")
        if idp:
            v.check(f"{name}: the identity provider's hostname {idp} {'published' if g['idp'] else 'absent'}, as the render puts it",
                    (idp in hosts) == g["idp"], f"{'present' if idp in hosts else 'absent'}")
        have = sorted(n for n, lb in labels_of.items() if lb.get(g["label"]) == "true")
        v.check(f"{name}: the namespaces labelled {g['label']}=true are {', '.join(g['namespaces'])} alone", have == sorted(g["namespaces"]),
                f"labelled: {', '.join(have) or 'none'}")
    # the callers each model route admits, against their audiences
    cm = _json(d / "routes-cm.json") or {}
    wl = _apisix_whitelists(((cm.get("data") or {}).get("apisix.yaml")) or "")
    cal = {c["id"]: c for c in p["callers"]}
    for model in p["models"]:
        ids = wl.get(model)
        bad = [c for c in ids or [] if c in cal and model not in cal[c]["audience_models"]]
        unknown = [c for c in ids or [] if c not in cal]
        v.check(f"{model}'s route admits {', '.join(ids or []) or 'nobody'}, each a caller whose audience may call {model}",
                ids is not None and not bad and not unknown, "no route read" if ids is None else f"outside the audience: {', '.join(bad + unknown)}")
    for c in p["callers"]:
        v.check(f"caller {c['id']} ({c['kind']}, audience {c['audience']}) may call {', '.join(c['models'])}, within its audience's "
                f"{', '.join(c['audience_models'])}", set(c["models"]) <= set(c["audience_models"]), "outside its audience")
    certs = _certs(_text(d / "certs.txt"))
    fps = [certs.get(g) for g in sorted(p["gateways"])]
    each = ", ".join(f"{g} {(certs.get(g) or 'none')[:12]}" for g in sorted(p["gateways"]))
    v.check(f"each Gateway's certificate has its own key: {len(set(f for f in fps if f))} distinct public key fingerprints for "
            f"{len(fps)} Gateways ({each})",
            all(fps) and len(set(fps)) == len(fps), "a key shared or unread")
    leases = _json(d / "leases.json")
    lease = p["lease"]
    for name, g in sorted(p["gateways"].items()):
        ln = (g["lease"] or "").split("/", 1)[-1]
        it = next((i for i in (leases or {}).get("items") or [] if i["metadata"]["name"] == ln), None)
        sp = (it or {}).get("spec") or {}
        holder, dur = sp.get("holderIdentity"), sp.get("leaseDurationSeconds")
        want_dur = int(str(lease.get("duration", "15s")).rstrip("s")) if lease.get("tuned") else None
        v.check(f"{name}: its lease {ln} held by {holder}, an {p['holder_role']} node" + (f", duration {dur} s" if dur is not None else ""),
                holder in p["ingress_nodes"] and (want_dur is None or dur == want_dur),
                f"held by {holder}, duration {dur}" if it else "no lease")
    cfg = ((_json(d / "cilium-config.json") or {}).get("data") or {})
    for key, val in sorted((lease.get("config") or {}).items()):
        v.check(f"cilium-config {key}: {cfg.get(key, 'unset')} (the tuned {val})", cfg.get(key) == val, f"{cfg.get(key, 'unset')}")
    pols = {i["metadata"]["name"]: i for i in (_json(d / "l2-policies.json") or {}).get("items") or []}
    alabel = ((self.inv.get("k8s") or {}).get("labels") or {}).get("audience")
    for name, g in sorted(p["gateways"].items()):
        it = pols.get(g["policy"])
        sp = (it or {}).get("spec") or {}
        sel = ((sp.get("serviceSelector") or {}).get("matchLabels")) or {}
        v.check(f"{name}: the announcement policy {g['policy']} selects the {g['audience']} audience's Services ({alabel}={g['audience']}) "
                f"on {', '.join(p['interfaces'])}", bool(it) and sel.get(alabel) == g["audience"] and list(sp.get("interfaces") or []) == p["interfaces"],
                f"selector {sel}, interfaces {sp.get('interfaces')}" if it else "no such policy")
    extra = sorted(set(pols) - {g["policy"] for g in p["gateways"].values()})
    v.check(f"one announcement policy per audience, no other ({len(pols)} read)", not extra, f"also {', '.join(extra)}")
    rm = p.get("refused_mint")
    if rm:
        log = _text(d / "refused-mint.log")
        phase = _text(d / "refused-mint.phase").strip()
        want = f"caller {rm['caller']} is in audience {rm['audience']}"
        v.check(f"the key Job asked for {rm['caller']}'s key for {rm['model']}, outside the {rm['audience']} audience, failed ({phase or 'not run'}) "
                f"with the key tool's refusal", phase == "Failed" and "refused" in log and want in log,
                (log.strip().splitlines() or ["no log"])[-1][:160])
        b, a = _fields(_text(d / "keys-before.txt")), _fields(_text(d / "keys-after.txt"))
        v.check(f"the key Secret holds the same {len(b)} fields and fingerprints after the refused mint, and no {rm['caller']}.{rm['id']}",
                bool(b) and a == b and f"{rm['caller']}.{rm['id']}" not in a, f"before {len(b)}, after {len(a)}")


# --------------------------------------------------------------------------------------------
# split-horizon


def g_split_horizon(self, names):
    import panos_parse as PP  # noqa: PLC0415

    d = Path(self.rs.path) / "split-horizon"
    v = self.v
    p = plan_of(self.render).get("dns")
    v.sec("split-horizon DNS: the public side (chapter 9)")
    if not p:
        v.skip("split-horizon DNS", "the lab has no internet side")
        return
    pub = p["public"]
    for n, want in sorted(pub["names"].items()):
        r = dig_result(_text(d / f"public-{slug(n)}.txt"))
        got = [x[2] for x in r["answers"] if x[1] == "A" and x[0] == n]
        v.check(f"{pub['server']} ({pub['address']}): {n} A {want}, authoritative: {dig_text(r)}",
                r["status"] == "NOERROR" and got == [want] and "aa" in r["flags"], dig_text(r))
    leaked = []
    for n in pub["absent"]:
        r = dig_result(_text(d / f"absent-{slug(n)}.txt"))
        if r["status"] != "NXDOMAIN" or r["answers"]:
            leaked.append(f"{n} {dig_text(r)}")
    v.check(f"{pub['server']} holds none of the {len(pub['absent'])} admin, internal, identity and infrastructure names (each NXDOMAIN)",
            not leaked, "; ".join(leaked[:4]))
    r = dig_result(_text(d / "wildcard.txt"))
    v.check(f"{pub['server']}: {pub['wildcard']}, under no record, NXDOMAIN (no wildcard): {dig_text(r)}",
            r["status"] == "NXDOMAIN" and not r["answers"], dig_text(r))
    r = dig_result(_text(d / "recursion.txt"))
    v.check(f"{pub['server']}: {pub['recursion_name']} asked with recursion desired, outside its zone: REFUSED, no recursion "
            f"available ({dig_text(r)})", r["status"] == "REFUSED" and not r["answers"] and "ra" not in r["flags"], dig_text(r))
    isp = p["isp"]
    r = dig_result(_text(d / "isp-answer.txt"))
    got = [x[2] for x in r["answers"] if x[1] == "A"]
    v.check(f"{isp['server']} ({isp['address']}) answers its customer {isp['from']}: {isp['name']} A {isp['answer']}, recursing "
            f"({dig_text(r)})", r["status"] == "NOERROR" and got == [isp["answer"]] and "ra" in r["flags"], dig_text(r))
    t = _text(d / "isp-outside.txt")
    r = dig_result(t)
    o = isp["outside"]
    if "no python3" in t:
        v.skip(f"{isp['server']} refuses {o['node']}'s {o['source']}, outside its clients", f"{o['node']} has no python3 for dnsq.py")
    else:
        v.check(f"{isp['server']} refuses a source outside its clients ({', '.join(isp['clients'])}): {o['node']} from {o['source']}, "
                f"{dig_text(r)}", r["status"] == "REFUSED" and not r["answers"], dig_text(r))
    v.sec("split-horizon DNS: every population's answers, A and AAAA (chapter 9)")
    for row in p["aaaa"]:
        if not row["names"]:
            continue
        for n in row["names"]:
            ra = dig_result(_text(d / f"a-{row['population']}-{slug(n)}.txt"))
            r6 = dig_result(_text(d / f"aaaa-{row['population']}-{slug(n)}.txt"))
            a = [x[2] for x in ra["answers"] if x[1] == "A"]
            six = [x for x in r6["answers"] if x[1] == "AAAA"]
            v.check(f"{row['population']} ({row['client']} through {row['resolver']}, view {row['view']}): {n} A {row['answer']}, and AAAA "
                    f"NOERROR with no record ({dig_text(r6)})", ra["status"] == "NOERROR" and a == [row["answer"]] and r6["status"] == "NOERROR"
                    and not six, f"A {dig_text(ra)}; AAAA {dig_text(r6)}")
    ops = p.get("ops")
    if ops:
        held = []
        for n in ops["names"]:
            r = dig_result(_text(d / f"ops-{slug(n)}.txt"))
            if r["answers"] or r["status"] not in ("NXDOMAIN", "REFUSED"):
                held.append(f"{n} {dig_text(r)}")
        v.check(f"{ops['server']} ({ops['address']}), the uplink side's public server, holds no platform name ({', '.join(ops['names'])})",
                not held, "; ".join(held[:3]))
    rt = p["isp_router"]
    routes = router_routes(_text(d / f"{rt['node']}-ip-route.txt"))
    inside = [x for x in routes if any(overlaps(x["dest"], i) for i in rt["inside"])]
    v.check(f"{rt['node']} holds no route into {', '.join(rt['inside'])} ({len(routes)} routes read)", bool(routes) and not inside,
            "no table read" if not routes else ", ".join(f"{x['dest']} line {x['line']}" for x in inside[:3]))
    s = p["internet_syn"]
    c = connect_line(_text(d / "syn.txt"))
    caddr = ((self.inv.get("nodes") or {}).get(s["client"]) or {}).get("address", "").split("/")[0]
    hits = PP.tlog_find(_text(d / "traffic-log.txt"), src=caddr, sport=s["sport"])
    e = hits[0] if hits else {}
    if s["outcome"] == "log-line":
        v.check(f"{s['client']}'s connect to {s['address']}:443 from port {s['sport']} refused ({c['outcome']}), logged by {s['rule']} from "
                f"{s['from_zone']} to {s['to_zone']}", c["outcome"] != "CONNECTED" and e.get("rule") == s["rule"][:19]
                and e.get("from") == s["from_zone"] and e.get("to") == s["to_zone"],
                f"client {c['outcome']}, log {e.get('rule')} {e.get('from')} to {e.get('to')}" if e else f"client {c['outcome']}, no log line")
    else:
        v.check(f"{s['client']}'s connect to {s['address']}:443 from port {s['sport']} connected ({c['outcome']}), logged by {s.get('rule')} "
                f"from {s.get('from_zone')} to {s.get('to_zone')}", c["outcome"] == "CONNECTED" and e.get("rule") == str(s.get("rule"))[:19],
                f"client {c['outcome']}, log {e.get('rule') or 'none'}")
    ec = p["envoy_certs"]
    t = _text(d / "cilium-secrets.txt")
    have = [x for x in ec["secrets"] if re.search(rf"(?m)^{re.escape(x)}\s", t)]
    v.ok(f"Cilium's copies of the Gateway certificates in {ec['namespace']} recorded ({len(have)} of {len(ec['secrets'])}: "
         f"{', '.join(have) or 'none'}); every node's Envoy loads them, which the audit records and does not judge")


# --------------------------------------------------------------------------------------------
# zone-nat


def _blocks(text: str) -> dict:
    """show running security-policy or nat-policy: name -> {index, line, fields {key: (value, line)}}
    (walktrace.py's reading, kept here so the judge needs no trace module)."""
    import panos_parse as PP  # noqa: PLC0415

    out, cur = {}, None
    for i, line in enumerate((text or "").splitlines(), 1):
        m = PP.POLICY_HEAD.match(line.strip())
        if m:
            cur = {"index": int(m.group(2)), "line": i, "fields": {}}
            out[m.group(1)] = cur
            continue
        if line.strip() == "}":
            cur = None
            continue
        if cur is not None:
            k = re.match(r"^\s*([A-Za-z][A-Za-z0-9 /_-]*?)\s+(.*?);?\s*$", line)
            if k and k.group(1) not in cur["fields"]:
                cur["fields"][k.group(1)] = (k.group(2).rstrip(";").strip(), i)
    return out


def _members(v: str) -> list:
    v = (v or "").strip()
    if v.startswith("["):
        return v.strip("[]").split()
    return [v] if v else []


def inside_wanted(plan: dict, d: Path) -> list:
    """(population, src, sport) of every inside connect the firewall refuses with a log line."""
    rows = {r["population"]: r for r in (plan.get("firewall") or {}).get("inside") or []}
    out = []
    for line in _text(d / "inside.tsv").splitlines():
        x = line.split("\t")
        if len(x) >= 4 and (rows.get(x[0]) or {}).get("outcome") == "log-line":
            out.append((x[0], x[2], int(x[3])))
    return out


def g_zone_nat(self, names):
    import panos_parse as PP  # noqa: PLC0415

    d = Path(self.rs.path) / "zone-nat"
    v = self.v
    tp = plan_of(self.render)
    p = tp.get("firewall")
    v.sec("zone-keyed translation: the rulebases (chapter 10)")
    if not p:
        v.skip("the zone-keyed translation", "the lab publishes no address to the internet users")
        return
    nat_t, sec_t = _text(d / "running-nat.txt"), _text(d / "running-security.txt")
    got_nat, got_sec = PP.policy(nat_t), PP.policy(sec_t)
    v.check(f"the NAT rulebase in the rendered order: {', '.join(p['nat_order'])}", got_nat == p["nat_order"], f"running {', '.join(got_nat) or 'none'}")
    v.check(f"the security rulebase in the rendered order ({len(p['security_order'])} rules, {p['security_order'][-1]} last)",
            got_sec == p["security_order"], f"running {len(got_sec)}: " + ", ".join(x for x in got_sec if x not in p["security_order"])[:120])
    pub = p["published"]
    nb, sb = _blocks(nat_t), _blocks(sec_t)
    isp = set(pub["from_zones"])
    nat_isp = [n for n, b in nb.items() if set(_members(b["fields"].get("from", ("", 0))[0])) & isp]
    rule = nb.get(pub["nat_rule"]) or {"fields": {}}
    f = {k: x[0] for k, x in rule["fields"].items()}
    tt = f.get("translate-to", "").strip('"')
    v.check(f"the isp zone's NAT rules are {pub['nat_rule']} alone: from {', '.join(sorted(isp))} to {f.get('to') or '?'}, destination "
            f"{f.get('destination') or '?'}, {f.get('service') or '?'}, translated {tt or 'nowhere'}",
            nat_isp == [pub["nat_rule"]] and set(_members(f.get("to", ""))) == isp and f.get("destination") == pub["address"]
            and "tcp/" in f.get("service", "") and "/443" in f.get("service", "") and f"dst: {pub['translated']}" in tt,
            f"isp NAT rules {', '.join(nat_isp) or 'none'}")
    sec_isp = [n for n, b in sb.items() if set(_members(b["fields"].get("from", ("", 0))[0])) & isp
               and (b["fields"].get("action", ("", 0))[0] == "allow")]
    s = {k: x[0] for k, x in (sb.get(pub["security_rule"]) or {"fields": {}})["fields"].items()}
    v.check(f"the isp zone's allow rules are {pub['security_rule']} alone: destination {s.get('destination') or '?'} (the published "
            f"address, before translation), to {s.get('to') or '?'}, {s.get('application/service') or '?'}",
            sec_isp == [pub["security_rule"]] and s.get("destination") == pub["address"] and "ssl" in s.get("application/service", "")
            and all(a.split("/")[0].split(":")[-1] == "ssl" for a in _members(s.get("application/service", ""))),
            f"isp allow rules {', '.join(sec_isp) or 'none'}")
    v.sec("zone-keyed translation: the published address from inside (chapter 10)")
    tl = _text(d / "traffic-log-443.txt")
    want = {x[0]: x for x in inside_wanted(tp, d)}
    for r in p["inside"]:
        c = connect_line(_text(d / f"inside-{r['population']}.txt"))
        if r["outcome"] == "log-line":
            x = want.get(r["population"])
            hits = PP.tlog_find(tl, src=x[1], sport=x[2]) if x else []
            e = hits[0] if hits else {}
            v.check(f"{r['population']} ({r['client']}) to {r['address']}:443: untranslated, refused by {r['rule']} from {r['from_zone']} to "
                    f"{r['to_zone']} (the client: {c['outcome']})", c["outcome"] != "CONNECTED" and e.get("rule") == r["rule"][:19]
                    and e.get("from") == r["from_zone"] and e.get("to") == r["to_zone"] and e.get("dst") == r["address"],
                    f"client {c['outcome']}, log {e.get('rule')} {e.get('from')} to {e.get('to')} dst {e.get('dst')}" if e else
                    f"client {c['outcome']}, no log line")
        elif r["outcome"] == "silence":
            routes = router_routes(_text(d / "routers" / f"{r['device']}-ip-route.txt"))
            hit = [x for x in routes if covers(x["dest"], r["address"])]
            v.check(f"{r['population']} ({r['client']}) to {r['address']}:443: silence at {r['device']}, which holds no route to it "
                    f"({len(routes)} routes read; the client: {c['outcome']})", c["outcome"] != "CONNECTED" and bool(routes) and not hit,
                    "no table read" if not routes else f"{hit[0]['dest'] if hit else ''} client {c['outcome']}")
        else:
            v.bad(f"{r['population']} ({r['client']}) to {r['address']}:443", f"the render reaches it ({r['outcome']}): the arrival zone must refuse it")
    hp = tp.get("hold")
    if hp:
        v.sec("zone-keyed translation: sessions per zone under the held connections (chapter 10)")
        judge_hold(v, d, hp, "held")


# --------------------------------------------------------------------------------------------
# isolation


def g_isolation(self, names):
    import gwlayer as GL  # noqa: PLC0415

    rs = Path(self.rs.path)
    v = self.v
    tp = plan_of(self.render)
    p = tp.get("isolation")
    v.sec("isolation: the negative checks (chapter 11)")
    if not p:
        v.skip("the negative checks", "chapter.yaml asks for none")
        return
    hr = _json(rs / "audiences" / "httproutes.json")
    k8s = GL._k8s(self)
    paths = {m["name"]: m["path"] for m in (k8s.get("inference") or {}).get("models") or []}
    got = GL._pairs(GL._routes_of(hr, p["gateway"])) if hr else set()
    for m in p["forbidden_models"]:
        hit = sorted(f"{h}{x}" for h, x in got if x.startswith(paths.get(m, "\0")))
        v.check(f"no HTTPRoute for {m}'s path on {p['gateway']} ({len(got)} hostname and path pairs read)", bool(hr) and not hit, ", ".join(hit))
    hit = sorted({h for h, _ in got if h in p["forbidden_hostnames"]})
    v.check(f"no admin or identity hostname on {p['gateway']} ({', '.join(p['forbidden_hostnames'])})", bool(hr) and not hit, ", ".join(hit))
    sb = _blocks(_text(rs / "zone-nat" / "running-security.txt"))
    ent = p.get("enterprise") or {}
    pools = [g for g, x in tp["audiences"]["gateways"].items() if x["vip"] != ent.get("vip")]
    reach = []
    for n, b in sb.items():
        f = {k: x[0] for k, x in b["fields"].items()}
        if not set(_members(f.get("from", ""))) & set(ent.get("zones") or []) or f.get("action") != "allow":
            continue
        for dst in _members(f.get("destination", "")):
            for g in pools:
                a, z = (ipaddress.ip_address(x) for x in tp["audiences"]["gateways"][g]["pool"])
                pool = list(ipaddress.summarize_address_range(a, z))
                if dst == "any" or any(overlaps(dst, str(x)) for x in pool):
                    reach.append(f"{n} to {dst} ({g}'s pool)")
    v.check(f"no enterprise allow rule beyond {ent.get('vip')}/32 reaches another Gateway's pool ({', '.join(pools)})", bool(sb) and not reach,
            "; ".join(reach[:3]) or "no security rulebase read")
    nb = _blocks(_text(rs / "zone-nat" / "running-nat.txt"))
    tos = []
    for n in p["isp_nat"]:
        tt = (nb.get(n) or {"fields": {}})["fields"].get("translate-to", ("", 0))[0]
        tos += re.findall(r"dst: (\d+\.\d+\.\d+\.\d+)", tt)
    v.check(f"the isp zone translates to {p['translated']} alone, the internet Gateway's VIP", bool(nb) and tos == [p["translated"]],
            f"translated to {', '.join(tos) or 'nothing'}")
    rt = p["isp_router"]
    routes = router_routes(_text(rs / "split-horizon" / f"{rt['node']}-ip-route.txt"))
    inside = [x for x in routes if any(overlaps(x["dest"], i) for i in rt["inside"])]
    v.check(f"{rt['node']} holds no route into {', '.join(rt['inside'])}", bool(routes) and not inside,
            "no table read" if not routes else ", ".join(x["dest"] for x in inside[:3]))


# --------------------------------------------------------------------------------------------


def cmd_tlog_missing(a) -> int:
    import panos_parse as PP  # noqa: PLC0415

    d = Path(a.dir)
    plan = json.loads(Path(a.plan).read_text())
    tl = _text(d / "traffic-log-443.txt")
    print(sum(1 for _p, src, sp in inside_wanted(plan, d) if not PP.tlog_find(tl, src=src, sport=sp)))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="tenancy")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("tlog-missing")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    a = ap.parse_args(argv)
    return {"tlog-missing": cmd_tlog_missing}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
