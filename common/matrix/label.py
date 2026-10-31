#!/usr/bin/env python3
"""label.py: chapter 2's label.sh judge. It reads gen/decisions.json (the decision table, Table 2-1,
with label.sh's plan of reads) and what label.sh saved from the running build, and names the live
object behind every row of the table with the decision label it carries.

    label.py get --plan P PATH              one value of the plan (gen/decisions.json), by dotted path
    label.py judge --plan P --dir D [--stamp S]
                                            verdict lines (PASS/FAIL) and D/LABELS.md

What label.sh saves under D (the result set), one directory a row:

    view/<population>-lookup.txt    the population's client looking up the users' hostname through its
                                    own resolver (dig in a container, getent ahostsv4 in a VM guest)
    view/<server>-<zone file>.txt   the zone file each BIND server serves, as installed in it
    fw/tables-session.txt           show routing route, show running nat-policy and show running
                                    security-policy in one CLI session, and each body beside it as
                                    fw/routing-route.txt, fw/running-nat-policy.txt and
                                    fw/running-security-policy.txt
    fw/rulebase.xml                 the running rulebase through the XML API (each rule's description)
    routing/<router>-ip-route.txt   each router's routing table, and <router>-frr.conf its rendered
                                    configuration as bound into it (each static route's comment line)
    routeset/httproutes.txt         every HTTPRoute with its audience and decision labels as columns, and
                                    httproutes.json
    key/api-gateway-routes.yaml     the API gateway's routes and consumer groups (each group's desc), and
                                    key/<pod>-keys.txt one pod's compose and key sidecar logs (by fingerprint)
    placement/serving.env           the placement table the recipe deployed (a copy of the render),
                                    placement/pods.txt and pods.json the serving pods with their decision
                                    label, placement/nads.json the rail attachments with their annotation
    forwarding/<switch>-startup.txt the first lines of the KLISH startup file delivered to the switch,
                                    and <switch>-ip-route.txt its show ip route

Standard library only, plus the harness's evfile and vocab.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import evfile  # noqa: E402
import vocab  # noqa: E402

DIG_A = re.compile(r"^(\S+)\s+(\d+)\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)\s*$")
GETENT = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(STREAM|DGRAM|RAW)?")
RULE_HEAD = re.compile(r'^"([^;"]+); index: (\d+)"')
FRR_ROUTE = re.compile(r"^([A-Z])[>*]*\s*\*?\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+\[\d+/\d+\]\s+via\s+(\d+\.\d+\.\d+\.\d+)")
GROUP_ID = re.compile(r"^-\s+id:\s*(\S+)\s*$")
GROUP_DESC = re.compile(r'^desc:\s*"?(dec-[a-z0-9-]+):')
CONSUMER = re.compile(r"^-\s+username:\s*(\S+)\s*$")
CONSUMER_GROUP = re.compile(r"^group_id:\s*(\S+)\s*$")
NXDOMAIN = re.compile(r"status: NXDOMAIN")


def load(p):
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def cite(path: str, line=None) -> str:
    return f"`{path}:{line}`" if line else f"`{path}`"


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")


def line_of(text: str, rx) -> int | None:
    r = re.compile(rx) if isinstance(rx, str) else rx
    for i, line in enumerate((text or "").splitlines(), 1):
        if r.search(line):
            return i
    return None


def cmd_get(a) -> int:
    cur = load(a.plan)
    for part in a.path.split("."):
        if isinstance(cur, list) and part.isdigit():
            cur = cur[int(part)]
        else:
            cur = cur.get(part) if isinstance(cur, dict) else None
    if isinstance(cur, list):
        print("\n".join(json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else str(x) for x in cur))
    elif isinstance(cur, dict):
        print(json.dumps(cur, sort_keys=True))
    elif cur is not None:
        print(cur)
    return 0


def consumer_groups(y: str) -> tuple:
    """({group: (its desc's decision, line)}, {group: [(consumer, line)]}) from the API gateway's
    standalone routes: each consumer group's id and desc, and each consumer the file names directly
    (the people, matched by their identity token, beside the applications' keys composed at start)."""
    groups, consumers = {}, {}
    sec = gid = cons = None
    for i, raw in enumerate((y or "").splitlines(), 1):
        if raw and not raw[0].isspace() and not raw.startswith("-"):
            sec, gid, cons = raw.rstrip(":").strip(), None, None
            continue
        l = raw.strip()
        if sec == "consumer_groups":
            m = GROUP_ID.match(l)
            if m:
                gid = m.group(1)
                groups.setdefault(gid, (None, i))
                continue
            m = GROUP_DESC.match(l)
            if m and gid and raw.startswith("  ") and not raw.startswith("   "):
                groups[gid] = (m.group(1), i)
        elif sec == "consumers":
            m = CONSUMER.match(l)
            if m:
                cons = (m.group(1), i)
                continue
            m = CONSUMER_GROUP.match(l)
            if m and cons:
                consumers.setdefault(m.group(1), []).append(cons)
    return groups, consumers


def answer_of(text: str, name: str) -> tuple:
    for i, l in enumerate((text or "").splitlines(), 1):
        m = DIG_A.match(l.strip())
        if m and m.group(1).rstrip(".") == name:
            return m.group(3), i
    for i, l in enumerate((text or "").splitlines(), 1):
        m = GETENT.match(l.strip())
        if m:
            return m.group(1), i
    return None, None


PREDEFINED = ("intrazone-default", "interzone-default")


def rule_order(text: str) -> list:
    return [(m.group(1), i) for i, l in enumerate((text or "").splitlines(), 1) for m in [RULE_HEAD.match(l.strip())] if m]


def rulebase(text: str) -> dict:
    """{'security': {name: description}, 'nat': {...}} from the XML API's answer."""
    out = {"security": {}, "nat": {}}
    i = text.find("<")
    if i < 0:
        return out
    try:
        root = ET.fromstring(text[i:].strip())
    except ET.ParseError:
        return out
    for kind in ("security", "nat"):
        for e in root.iter(kind):
            for r in e.iter("entry"):
                if r.get("name"):
                    out[kind][r.get("name")] = (r.findtext("description") or "").strip()
    return out


def fw_route_rows(text: str) -> list:
    out = []
    for i, l in enumerate((text or "").splitlines(), 1):
        x = l.split()
        if len(x) >= 4 and "/" in x[0] and re.match(r"^\d+\.\d+\.\d+\.\d+/\d+$", x[0]):
            out.append({"dest": x[0], "nexthop": x[1], "flags": " ".join(t for t in x[3:] if re.match(r"^[A-Z?~]+$", t)),
                        "iface": next((t for t in reversed(x) if re.match(r"^(ae\d+(\.\d+)?|ethernet\d+/\d+)$", t)), None), "line": i})
    return out


def judge(a) -> int:
    d = Path(a.dir)
    t = load(a.plan)
    plan = t["plan"]
    v = vocab.Vocab()
    rows = {r["id"]: r for r in t["rows"]}
    out = []

    def tag(rid):
        return f"[{rid}]"

    # view
    r = rows["view"]
    v.sec(f"{r['layer']} ({r['owner']}): {r['decision'].lower()}")
    for lk in plan["view"]["lookups"]:
        p = f"view/{slug(lk['population'])}-lookup.txt"
        text = read(d / p)
        got, ln = answer_of(text, lk["name"])
        if lk["answer"] is None:
            # the view publishes no record for the name: the server answers NXDOMAIN
            nx = line_of(text, NXDOMAIN.pattern)
            v.check(f"{tag('view')} {lk['population']} ({lk['client']}): {lk['name']} answers NXDOMAIN through {lk['server']}, view {lk['view']}",
                    got is None and nx is not None, f"got {got or 'no answer, and no NXDOMAIN status'}")
            out.append(("view", f"{lk['client']}'s lookup: view {lk['view']} answers {lk['name']} NXDOMAIN", lk["decision"], cite(p, nx)))
            continue
        v.check(f"{tag('view')} {lk['population']} ({lk['client']}): {lk['name']} answers {got} through {lk['server']}, view {lk['view']}",
                got == lk["answer"], f"want {lk['answer']}, got {got or 'no answer'}")
        out.append(("view", f"{lk['client']}'s lookup: view {lk['view']} answers {lk['name']} {got}", lk["decision"], cite(p, ln)))
    for z in plan["view"]["zones"]:
        p = f"view/{z['server']}-{z['file']}.txt"
        text = read(d / p)
        if not z.get("holds", True):
            # no entry for the name: the zone file's header names the view's decision
            ln = line_of(text, rf"^;\s*decision {re.escape(z['decision'])}\s*$")
            entry = line_of(text, rf"^{re.escape(z['name'].split('.')[0])}\s+IN\s+")
            v.check(f"{tag('view')} {z['server']}, view {z['view']}: the zone file is labelled {z['decision']} and holds no entry for {z['name']}",
                    ln is not None and entry is None,
                    f"{'no header label' if ln is None else 'an entry for the name at line ' + str(entry)} in {p}")
            out.append(("view", f"{z['server']}'s zone file {z['file']}, no entry for {z['name']}", z["decision"], cite(p, ln)))
            continue
        ln = line_of(text, rf"^{re.escape(z['name'].split('.')[0])}\s+IN\s+A\s+\S+\s*;\s*decision {re.escape(z['decision'])}:")
        v.check(f"{tag('view')} {z['server']}, view {z['view']}: the zone file's entry for {z['name']} carries decision {z['decision']}",
                ln is not None, f"no entry labelled {z['decision']} in {p}")
        out.append(("view", f"{z['server']}'s zone file {z['file']}, the entry for {z['name']}", z["decision"], cite(p, ln)))
    # routing
    r = rows["routing"]
    v.sec(f"{r['layer']} ({r['owner']}): {r['decision'].lower()}")
    rt = fw_route_rows(read(d / "fw" / "routing-route.txt"))
    for o in r["objects"]:
        if o["device"] != plan["routing"]["firewall"]:
            continue
        hit = next((x for x in rt if x["dest"] == o["dest"]), None)
        what = f"connected on {o['name']}" if o["kind"] == "connected subnet" else f"via {o.get('nexthop')} on {o.get('interface')}"
        v.check(f"{tag('routing')} {o['device']}: {o['dest']} {what} ({o['decision']}, in the decision table only)", hit is not None,
                f"not in {plan['routing']['firewall']}'s routing table")
        out.append(("routing", f"{o['device']}'s route {o['dest']} {what}", o["decision"], cite("fw/routing-route.txt", hit["line"] if hit else None)))
    for rr in plan["routing"]["routers"]:
        conf = read(d / "routing" / f"{rr['node']}-frr.conf")
        live = {}
        for l in read(d / "routing" / f"{rr['node']}-ip-route.txt").splitlines():
            m = FRR_ROUTE.match(l.strip())
            if m:
                live[m.group(2)] = {"dest": m.group(2), "via": m.group(3)}
        for o in [o for o in r["objects"] if o["device"] == rr["node"]]:
            cl = line_of(conf, rf"^!\s*{re.escape(o['name'])}: {re.escape(o['decision'])}\s*$")
            ok = cl is not None and o["dest"] in live and live[o["dest"]]["via"] == o.get("nexthop")
            v.check(f"{tag('routing')} {rr['node']}: {o['dest']} via {o.get('nexthop')} ({o['name']}), labelled {o['decision']}", ok,
                    f"label line {'found' if cl else 'missing'}, route {'live' if o['dest'] in live else 'not in show ip route'}")
            out.append(("routing", f"{rr['node']}'s static route {o['dest']} via {o.get('nexthop')}", o["decision"],
                        cite(f"routing/{rr['node']}-frr.conf", cl)))
    # nat and policy: the order of the running rulebase, and each rule's description
    rb = rulebase(read(d / "fw" / "rulebase.xml"))
    for rid, f, kind in (("nat", "running-nat-policy.txt", "nat"), ("policy", "running-security-policy.txt", "security")):
        r = rows[rid]
        v.sec(f"{r['layer']} ({r['owner']}): {r['decision'].lower()}")
        # PAN-OS prints its two predefined rules after the rulebase; deny-all-log above them takes
        # every session first, so they are set aside as the audit's judge sets them aside
        # (listed by name, or as <vsys>+<name> once overridden, as build A revision 2 does to log them)
        order = [(n, i) for n, i in rule_order(read(d / "fw" / f)) if n.split("+", 1)[-1] not in PREDEFINED]
        names = [n for n, _ in order]
        v.chk(f"{tag(rid)} the running {kind} rulebase in the rendered order ({len(plan[rid]['rules'])} rules)", " ".join(plan[rid]["rules"]),
              " ".join(names) or "none")
        for name in plan[rid]["rules"]:
            want = plan[rid]["decisions"][name]
            got = rb[kind].get(name)
            v.check(f"{tag(rid)} {name}: description {want}", bool(got) and got.split(":")[0] == want, f"got {got!r}")
            ln = next((i for n, i in order if n == name), None)
            out.append((rid, f"{kind} rule {name}", want, cite(f"fw/{f}", ln)))
        if rid == "policy" and names:
            v.chk(f"{tag(rid)} the rulebase closes with deny-all-log", "deny-all-log", names[-1])
    # route set
    r = rows["routeset"]
    v.sec(f"{r['layer']} ({r['owner']}): {r['decision'].lower()}")
    try:
        items = (load(d / "routeset" / "httproutes.json") or {}).get("items") or []
    except (OSError, ValueError):
        items = []
    txt = read(d / "routeset" / "httproutes.txt")
    lk = plan["routeset"]["label"]
    for o in plan["routeset"]["routes"]:
        it = next((i for i in items if (i.get("metadata") or {}).get("name") == o["name"] and i["metadata"].get("namespace") == o["namespace"]), None)
        got = ((it or {}).get("metadata") or {}).get("labels", {}).get(lk) if it else None
        v.check(f"{tag('routeset')} HTTPRoute {o['namespace']}/{o['name']} on {o['gateway']}: label {lk}={o['decision']}", got == o["decision"],
                f"got {got or ('no route' if it is None else 'no label')}")
        out.append(("routeset", f"HTTPRoute {o['namespace']}/{o['name']} on {o['gateway']}", o["decision"],
                    cite("routeset/httproutes.txt", line_of(txt, rf"^{re.escape(o['namespace'])}\s+{re.escape(o['name'])}\s"))))
    # key
    if "key" in plan:
        r = rows["key"]
        v.sec(f"{r['layer']} ({r['owner']}): {r['decision'].lower()}")
        y = read(d / "key" / "api-gateway-routes.yaml")
        groups, named = consumer_groups(y)
        side = sorted(d.glob("key/*-keys.txt"))
        stext = read(side[0]) if side else ""
        for g, want in sorted(plan["key"]["groups"].items()):
            got, ln = groups.get(g, (None, None))
            v.check(f"{tag('key')} consumer group {g}: desc labelled {want}", got == want, f"got {got or 'no group'}")
            cons = re.findall(rf"\b{re.escape(g)}\.[0-9a-f]{{8}} sha256:[0-9a-f]{{12}}", stext)
            if not cons and named.get(g):
                # people: a consumer the routes name directly, matched by its identity token, no key
                who, cl = named[g][0]
                v.check(f"{tag('key')} consumer group {g}: its consumer {who} in the routes (key/api-gateway-routes.yaml:{cl})", True, "")
                out.append(("key", f"consumer group {g} in {plan['key']['configmap']}", want, cite("key/api-gateway-routes.yaml", ln)))
                continue
            v.check(f"{tag('key')} consumer group {g}: its consumer composed in {side[0].name.rsplit('-keys', 1)[0] if side else 'no pod'}"
                    + (f" ({cons[-1]})" if cons else ""), bool(cons), "no consumer of the group in the pod's key logs")
            out.append(("key", f"consumer group {g} in {plan['key']['configmap']}", want, cite("key/api-gateway-routes.yaml", ln)))
    # placement
    if "placement" in plan:
        r = rows["placement"]
        v.sec(f"{r['layer']} ({r['owner']}): {r['decision'].lower()}")
        try:
            pods = (load(d / "placement" / "pods.json") or {}).get("items") or []
        except (OSError, ValueError):
            pods = []
        try:
            nads = (load(d / "placement" / "nads.json") or {}).get("items") or []
        except (OSError, ValueError):
            nads = []
        env = read(d / "placement" / "serving.env")
        lab = plan["placement"]["label"]
        for cp, want in sorted(plan["placement"]["copies"].items()):
            model, copy = cp.rsplit("-", 1)
            mine = [p for p in pods if (p.get("metadata") or {}).get("name", "").startswith(f"{cp}-")]
            bad = [p["metadata"]["name"] for p in mine if (p["metadata"].get("labels") or {}).get(lab) != want]
            v.check(f"{tag('placement')} copy {cp}: {len(mine)} pods labelled {want}", mine and not bad, f"unlabelled: {', '.join(bad) or 'no pod'}")
            out.append(("placement", f"copy {cp}'s row of the placement table", want,
                        cite("placement/serving.env", line_of(env, rf"^SERVING_POD_\d+='?{re.escape(cp)}-server(-\d+)? "))))
        for nad, want in sorted(plan["placement"]["nads"].items()):
            it = next((n for n in nads if (n.get("metadata") or {}).get("name") == nad), None)
            got = (((it or {}).get("metadata") or {}).get("annotations") or {}).get(lab)
            v.check(f"{tag('placement')} rail attachment {nad}: annotation {lab}={want}", got == want, f"got {got or 'none'}")
            out.append(("placement", f"rail attachment {nad}", want, "`placement/nads.json`"))
    # forwarding only
    v.sec("the switches: forwarding only, no row")
    fw_ = plan["forwarding"]
    for sw in fw_["switches"]:
        p = f"forwarding/{sw}-startup.txt"
        ln = line_of(read(d / p), rf"^! decision {re.escape(fw_['decision'])}:")
        rtx = read(d / "forwarding" / f"{sw}-ip-route.txt")
        v.check(f"[forwarding] {sw}: its startup file labelled {fw_['decision']}", ln is not None, f"no label line in {p}")
        v.check(f"[forwarding] {sw}: show ip route prints nothing", not rtx.strip(), f"{len(rtx.strip().splitlines())} lines")
        out.append(("forwarding", f"{sw}'s startup file", fw_["decision"], cite(p, ln)))
    write_md(d, t, out, a.stamp)
    return 1 if v.counts()["fail"] else 0


def write_md(d: Path, t: dict, out: list, stamp=None):
    try:
        run = load(d / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    unc = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    layers = {r["id"]: r["layer"] for r in t["rows"]}
    layers["forwarding"] = "forwarding only"
    L = ["# Decision labels", "",
         f"- Lab: `{t.get('lab')}`; labs repo commit `{repo.get('commit') or 'none'}`{unc}; UTC {run.get('utc_start') or 'unknown'}",
         f"- The live object behind each of the decision table's {len(t['rows'])} rows, and the switches, which implement none, each with "
         "the decision id it carries"]
    if stamp:
        L.append(f"- {stamp}")
    L += ["", "| Row | Live object | Decision | Evidence |", "|---|---|---|---|"]
    for rid, what, dec, ev in out:
        L.append(f"| {layers.get(rid, rid)} | {what} | `{dec}` | {ev} |")
    verdict = read(d / "verdict.txt")
    L += ["", "## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", ""]
    (d / "LABELS.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="label")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    s = sub.add_parser("judge")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--stamp")
    a = p.parse_args(argv)
    return {"get": cmd_get, "judge": judge}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
