#!/usr/bin/env python3
"""matrix.py: chapter 2's population and endpoint matrix (gen/matrix.json), for matrix.sh and for
break-2a's cell_mode check.

    matrix.py get --plan P PATH                  one value of the plan, by dotted path (a list prints
                                                 one item a line, a mapping as JSON)
    matrix.py requests --plan P [--only CELL...] the requests matrix.sh makes, one a line, tab-separated:
                                                 cell, request, kind (connect | http), client, client kind,
                                                 client address, address, port, source port, method,
                                                 URL, key model (- for none), marker (-), whether an
                                                 answer is expected (1) or a refusal (0), the model
                                                 the request's body names (-), the pin (-) and the
                                                 caller whose key it carries when the cell names one
                                                 (Part III: the population's own, key_caller; - for
                                                 the model's first key)
    matrix.py lookups --plan P [--only CELL...]  the names each client looks up first: row, client,
                                                 client kind, hostname
    matrix.py strict-ip --plan P [--only CELL...]
                                                 the cells zone protection's strict IP check drops, one a
                                                 line (the run then reads the firewall's drop counters)
    matrix.py tlog-ports --plan P --dir D [--only CELL...]
                                                 the destination ports whose traffic log the run reads
    matrix.py tlog-missing --plan P --dir D [--only CELL...]
                                                 how many unanswered attempts that crossed the firewall
                                                 the saved logs do not hold yet (0 when every one is there)
    matrix.py observe --plan P --dir D [--only CELL...]
                                                 each cell's mode as the evidence shows it, as JSON lines
    matrix.py judge --plan P --dir D [--stamp S] [--only CELL...]
                                                 verdict lines (PASS/FAIL) and D/MATRIX.md

The evidence matrix.sh saves under D (the result set, or a break's record/matrix-<mode>/):

    lookups/<row>-<name>.txt    the client's lookup of the name through its own resolver (dig in a
                                container, getent ahostsv4 in a VM guest)
    requests.tsv                one line an attempt: tag, cell, request, attempt, source port, kind
    requests/<tag>.txt          a connect: syn_connect.py's line; a request: "exit <curl status>" then
                                curl's "<status> <remote address>" line and its error
    requests/<tag>-headers.txt  a request's response headers, and -body.txt its body (no request
                                header is ever saved, so no key is)
    fw/traffic-log-<port>.txt   the firewall's traffic log for that destination port, read after the cells
    fw/routing-route.txt        the firewall's routing table (show routing route)
    fw/counters-before.txt      every counter's value before the requests and after them (show counter
    fw/counters-after.txt       global filter value all), when a cell of the plan is dropped by zone
                                protection's strict IP check: the judge reads the drop from their difference
    fw/drops.txt                the drop counters' delta view over the run (show counter global filter delta
                                yes severity drop, read before the requests and after them, between the two
                                value reads), recorded beside them: the firewall can start a new sampling
                                between its two reads, so the view is not what the judge decides by
    routers/<node>-ip-route.txt each router's routing table (show ip route)
    api-gateway/access.txt      the API gateway pods' access log over the run

A mode is observed from that evidence alone: a connect that opened or an HTTP status is an answer
(allowed, or 200, 401 and 404 by the status); an attempt that got none is a log line when the
traffic log holds a deny for its source port, unanswered when the log holds it allowed, and silence
when no log line names it. The judge then asserts each cell's mode with its evidence, never only its
outcome: a log line names the rule and the zones, and the client's view (a timeout or an error such
as an ICMP unreachable) is recorded; a 404 comes with no line for the request's marker in the API
gateway's log, which must itself hold the run's model requests; a 401 carries the API gateway's own
message; an operator cell refused at the firewall needs the router's static route for the
destination via the public address; a silent cell names the device that dropped it with that
device's evidence (a router's table without the route, the firewall's discard route, or for zone
protection's strict IP check the firewall's route back to the source out another interface and the
drop counter that counted it). Standard library only, plus the harness's panos_parse and vocab.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "audit"))
import evfile  # noqa: E402
import panos_parse as PP  # noqa: E402
import vocab  # noqa: E402

DIG_A = re.compile(r"^(\S+)\s+(\d+)\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)\s*$")
GETENT = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(STREAM|DGRAM|RAW)?")
# a route of FRR's show ip route: a route via a next hop, or a connected or local one (via None), so a
# router whose table holds only its connected links (the ISP router) is still read as a table
FRR_ROUTE = re.compile(r"^([A-Z])[>*]*\s*\*?\s*(\d+\.\d+\.\d+\.\d+/\d+)\s+(?:\[\d+/\d+\]\s+via\s+(\d+\.\d+\.\d+\.\d+)|is directly connected)")
MODE_TEXT = {"allowed": "allowed", "log-line": "log line", "404": "404", "401": "401", "silence": "silence"}


def load(p):
    return json.loads(evfile.read_text(p, "strict"))


def read(p) -> str:
    try:
        return evfile.read_text(p)
    except (OSError, ValueError):
        return ""


def line_of(text: str, rx) -> int | None:
    r = re.compile(rx) if isinstance(rx, str) else rx
    for i, line in enumerate((text or "").splitlines(), 1):
        if r.search(line):
            return i
    return None


def cite(path: str, line=None) -> str:
    return f"`{path}:{line}`" if line else f"`{path}`"


def slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")


def tag(cell: str, req: str, attempt: int) -> str:
    return f"{slug(cell)}-{req}-a{attempt}"


def cells_of(plan: dict, only) -> list:
    cs = plan["cells"]
    if only:
        want = set(only)
        bad = want - {c["id"] for c in cs}
        if bad:
            raise SystemExit(f"matrix: no cell {', '.join(sorted(bad))} in the plan")
        cs = [c for c in cs if c["id"] in want]
    return cs


def rows_of(plan: dict) -> dict:
    return {r["id"]: r for r in plan["rows"]}


def cols_of(plan: dict) -> dict:
    return {c["id"]: c for c in plan["columns"]}


# --------------------------------------------------------------------------------------------
# the plan, as matrix.sh reads it


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


def strict_ip(plan: dict, only=None) -> list:
    """The cells zone protection's strict IP check drops at the firewall, whose drop counters the run
    reads around its requests."""
    return [c["id"] for c in cells_of(plan, only) if c.get("mode") == "silence" and (c.get("expect") or {}).get("drop") == "strict-ip"]


def cmd_strict_ip(a) -> int:
    for x in strict_ip(load(a.plan), a.only):
        print(x)
    return 0


def requests(plan: dict, only=None) -> list:
    out = []
    for c in cells_of(plan, only):
        for q in c.get("requests") or []:
            kind = "connect" if q["id"] == "connect" else "http"
            answer = "1" if (kind == "connect" and c["mode"] == "allowed") or (kind == "http" and q.get("expect")) else "0"
            # a cell whose view holds no record for its name (pin) is asked at its address with
            # curl --resolve: the lookup is judged on its own (NXDOMAIN), the request by the layers behind
            pin = f"{c['hostname']}:{c['port']}:{c['address']}" if c.get("pin") and c.get("hostname") and c.get("address") else "-"
            out.append((c["id"], q["id"], kind, c["client"], c["client_kind"], c["client_addr"], c.get("address") or "-", str(c["port"]),
                        str(q["sport"]), q.get("method") or "-", q.get("url") or "-", q.get("key") or "-", q.get("marker") or "-", answer,
                        (q.get("body") or {}).get("model") or "-", pin, q.get("key_caller") or "-"))
    return out


def cmd_requests(a) -> int:
    for r in requests(load(a.plan), a.only):
        print("\t".join(r))
    return 0


def lookups(plan: dict, only=None) -> list:
    rows = rows_of(plan)
    seen, out = set(), []
    for c in cells_of(plan, only):
        h = c.get("hostname")
        if not h or (c["row"], h) in seen:
            continue
        seen.add((c["row"], h))
        r = rows[c["row"]]
        out.append((r["id"], r["client"], r["kind"], h))
    return out


def cmd_lookups(a) -> int:
    for r in lookups(load(a.plan), a.only):
        print("\t".join(r))
    return 0


# --------------------------------------------------------------------------------------------
# the evidence


def attempts(d: Path) -> dict:
    """{(cell, request): [ {tag, attempt, sport, kind}, ... ]} from requests.tsv, in order."""
    out: dict = {}
    for line in read(d / "requests.tsv").splitlines():
        x = line.split("\t")
        if len(x) < 6:
            continue
        out.setdefault((x[1], x[2]), []).append({"tag": x[0], "attempt": int(x[3]), "sport": int(x[4]), "kind": x[5]})
    return out


def parse_connect(text: str) -> dict:
    for i, line in enumerate((text or "").splitlines(), 1):
        x = line.split()
        if len(x) >= 6 and x[2] in ("0", "1"):
            return {"answered": x[4] == "CONNECTED", "outcome": x[4], "took": x[5], "line": i, "status": None}
    return {"answered": False, "outcome": "none", "took": None, "line": None, "status": None}


def parse_http(text: str) -> dict:
    ex, status, remote, took, line, err = None, None, None, None, None, ""
    for i, l in enumerate((text or "").splitlines(), 1):
        m = re.match(r"^exit (\d+)$", l.strip())
        if m:
            ex = int(m.group(1))
            continue
        m = re.match(r"^(\d{3}) (\S*) ?(\S*)$", l.strip())
        if m and status is None:
            status, remote, took, line = int(m.group(1)), m.group(2) or None, m.group(3) or None, i
            continue
        if l.strip() and not err:
            err = l.strip()
    answered = status is not None and status > 0
    outcome = f"HTTP {status}" if answered else (f"curl exit {ex}" + (f": {err}" if err else ""))
    return {"answered": answered, "outcome": outcome, "status": status if answered else None, "remote": remote, "took": took,
            "line": line, "exit": ex, "error": err}


def lookup_answer(d: Path, row: str, name: str) -> dict:
    p = f"lookups/{slug(row)}-{slug(name)}.txt"
    text = read(d / p)
    for i, l in enumerate(text.splitlines(), 1):
        m = DIG_A.match(l.strip())
        if m and m.group(1).rstrip(".") == name:
            return {"answer": m.group(3), "line": i, "file": p}
    for i, l in enumerate(text.splitlines(), 1):
        m = GETENT.match(l.strip())
        if m:
            return {"answer": m.group(1), "line": i, "file": p}
    return {"answer": None, "line": None, "file": p}


def tlog_entry(d: Path, src: str, sport: int, dst: str, dport: int):
    p = f"fw/traffic-log-{dport}.txt"
    hits = PP.tlog_find(read(d / p), src=src, sport=sport, dst=dst, dport=dport)
    return (hits[0], p) if hits else (None, p)


def in_node(cell: dict) -> bool:
    """A cell the client's own node answers (a cluster node asking its own Gateway's VIP)."""
    return any(h.get("row") is None and h.get("device") == cell.get("client") for h in cell.get("hops") or [])


def crosses_fw(cell: dict) -> bool:
    return any(h.get("row") in ("policy", "nat") for h in cell.get("hops") or [])


def observe_request(d: Path, plan: dict, cell: dict, q: dict, att: list) -> dict:
    """The last attempt of one request, classified."""
    if not att:
        return {"mode": "not run", "attempts": 0}
    last = att[-1]
    p = f"requests/{last['tag']}.txt"
    text = read(d / p)
    o = parse_connect(text) if last["kind"] == "connect" else parse_http(text)
    o.update(file=p, attempts=len(att), sport=last["sport"], tag=last["tag"])
    if o["answered"]:
        if last["kind"] == "connect":
            o["mode"] = "allowed"
        else:
            o["mode"] = {200: "allowed", 401: "401", 404: "404"}.get(o["status"], f"http-{o['status']}")
        return o
    # where the request went: the name's answer through the population's resolver, else (no
    # answer, a pinned cell) the cell's address, where matrix.sh pins it
    dst = cell.get("address")
    if cell.get("hostname"):
        la = lookup_answer(d, cell["row"], cell["hostname"])
        dst = la["answer"] or dst
    o["dst"] = dst
    e, tp = tlog_entry(d, cell["client_addr"], last["sport"], dst, int(cell["port"]))
    o["tlog_file"] = tp
    if e is not None:
        o["tlog"] = e
        o["mode"] = "log-line" if e["action"] in ("deny", "drop", "reset-both", "reset-client", "reset-server") else "unanswered"
    else:
        # no log line names it: silence where the request crossed the firewall or the plan names a
        # device that drops it without a word (a router with no route, a discard route)
        o["mode"] = "silence" if crosses_fw(cell) or dst != cell.get("address") or cell.get("mode") == "silence" else "unanswered"
    return o


def observe(d: Path, plan: dict, only=None) -> list:
    att = attempts(d)
    out = []
    for c in cells_of(plan, only):
        reqs = {}
        for q in c.get("requests") or []:
            reqs[q["id"]] = observe_request(d, plan, c, q, att.get((c["id"], q["id"]), []))
        first = (c.get("requests") or [{}])[0].get("id")
        out.append({"cell": c["id"], "mode": (reqs.get(first) or {}).get("mode"), "requests": reqs})
    return out


def cmd_observe(a) -> int:
    for o in observe(Path(a.dir), load(a.plan), a.only):
        print(json.dumps(o, sort_keys=True))
    return 0


def silent_at_fw(plan: dict, cell: dict) -> bool:
    """A silence cell whose silent device is the firewall (a discard route): its traffic log is read
    for the absence of a line, never waited on."""
    return cell.get("mode") == "silence" and (cell.get("expect") or {}).get("device") == plan.get("firewall")


def tlog_wanted(d: Path, plan: dict, only=None, waiting: bool = False) -> list:
    """(dport, src, sport, dst) of every unanswered attempt that may have crossed the firewall, and
    of every one the firewall discarded (read to show no line names it); waiting=True leaves those
    out, since no read will ever hold them."""
    att = attempts(d)
    out = []
    for c in cells_of(plan, only):
        for q in c.get("requests") or []:
            a_ = att.get((c["id"], q["id"]), [])
            if not a_:
                continue
            last = a_[-1]
            text = read(d / f"requests/{last['tag']}.txt")
            o = parse_connect(text) if last["kind"] == "connect" else parse_http(text)
            if o["answered"]:
                continue
            dst = c.get("address")
            if c.get("hostname"):
                dst = lookup_answer(d, c["row"], c["hostname"])["answer"] or dst
            if silent_at_fw(plan, c):
                if not waiting:
                    out.append((int(c["port"]), c["client_addr"], last["sport"], dst))
                continue
            if not crosses_fw(c) and dst == c.get("address"):
                continue
            out.append((int(c["port"]), c["client_addr"], last["sport"], dst))
    return out


def cmd_tlog_ports(a) -> int:
    for p in sorted({x[0] for x in tlog_wanted(Path(a.dir), load(a.plan), a.only)}):
        print(p)
    return 0


def cmd_tlog_missing(a) -> int:
    d = Path(a.dir)
    miss = [x for x in tlog_wanted(d, load(a.plan), a.only, waiting=True) if tlog_entry(d, x[1], x[2], x[3], x[0])[0] is None]
    print(len(miss))
    return 0


# --------------------------------------------------------------------------------------------
# the judge


def _covers(prefix: str, address) -> bool:
    try:
        return ipaddress.ip_address(str(address)) in ipaddress.ip_network(str(prefix), strict=False)
    except ValueError:
        return False


# PAN-OS show routing route: "destination  nexthop  metric flags  age  interface  next-AS"; a
# discard route's nexthop reads "discard"
PANOS_DISCARD = re.compile(r"^(\d+\.\d+\.\d+\.\d+/\d+)\s+discard\b")


def fw_discards(text: str) -> list:
    out = []
    for i, l in enumerate((text or "").splitlines(), 1):
        m = PANOS_DISCARD.match(l.strip())
        if m:
            out.append({"dest": m.group(1), "line": i})
    return out


def fw_route_line(text: str, dest: str, iface: str) -> int | None:
    """The line of show routing route that routes dest out iface, or None."""
    for i, l in enumerate((text or "").splitlines(), 1):
        x = l.split()
        if x and x[0] == dest and iface in x[1:]:
            return i
    return None


def drop_count(text: str, name: str) -> int | None:
    """A counter's value in a saved show counter global read (its delta view), or None when the read
    does not list it (a counter that did not move is not listed in the delta view)."""
    m = re.search(rf"^\s*{re.escape(name)}\s+(\d+)", text or "", re.M) if name else None
    return int(m.group(1)) if m else None


def sampling(text: str) -> str:
    """The delta view's own account of its window ("sampled over the last N s"), or that it was not read."""
    m = re.search(r"Elapsed time since last sampling:\s*([\d.]+)\s*seconds", text or "")
    return f"its sampling began {m.group(1)} s before it was read" if m else "not read"


def router_routes(text: str) -> list:
    out = []
    for i, l in enumerate((text or "").splitlines(), 1):
        m = FRR_ROUTE.match(l.strip())
        if m:
            out.append({"type": m.group(1), "dest": m.group(2), "via": m.group(3), "line": i})
    return out


def view_text(o: dict) -> str:
    """The client's view of an attempt, without a measured duration (a guest's clock is its own; the
    timeout named is the plan's, not a measurement)."""
    if o.get("outcome") == "TIMEOUT" or o.get("exit") == 28:
        return "timed out, at its connect timeout"
    if str(o.get("outcome", "")).startswith("ERROR:"):
        return f"an error, {o['outcome'][6:].replace('_', ' ')}"
    if o.get("outcome") == "REFUSED":
        return "a reset"
    if o.get("exit") is not None and o.get("error"):
        return f"curl exit {o['exit']}, {o['error']}"
    return str(o.get("outcome") or "none")


def judge_cell(v, d: Path, plan: dict, c: dict, ob: dict, rows: dict, cols: dict, gwlog: str) -> dict:
    r, col = rows[c["row"]], cols[c["column"]]
    name = f"{r['label']} / {col['label']}"
    res = {"cell": c["id"], "ok": True, "text": "", "cites": []}
    first = c["requests"][0]["id"]
    o = ob["requests"].get(first) or {}
    want = c["mode"]
    got = o.get("mode")
    tagx = f"[{c['layer'] or 'allowed'}]"

    def fail(label, detail):
        res["ok"] = False
        v.bad(f"{tagx} {name}: {label}", detail)

    # the view the population's resolver answers with, for a name cell
    if c.get("hostname"):
        la = lookup_answer(d, c["row"], c["hostname"])
        if (c.get("lookup") or {}).get("expect") == "nxdomain":
            # the view holds no record for the name: no answer, and the request was pinned
            if la["answer"] is None:
                v.ok(f"[view] {name}: {c['hostname']} has no answer through {r['resolver']} (view {r['view']} holds no record for it); "
                     f"the request pinned to {c['address']}")
            else:
                fail(f"{c['hostname']} through {r['resolver']}", f"want no answer (view {r['view']} holds no record), got {la['answer']}")
        elif la["answer"] == c["address"]:
            v.ok(f"[view] {name}: {c['hostname']} answers {la['answer']} through {r['resolver']} (view {r['view']})")
        else:
            fail(f"{c['hostname']} through {r['resolver']}", f"want {c['address']} (view {r['view']}), got {la['answer'] or 'no answer'}")
        res["cites"].append(cite(la["file"], la["line"]))
    if o.get("file"):
        res["cites"].append(cite(o["file"], o.get("line")))
    if got != want:
        fail(f"mode {MODE_TEXT.get(want, want)}", f"got {got or 'none'} ({view_text(o)})")
        res["text"] = f"FAIL: want {MODE_TEXT.get(want, want)}, got {got or 'none'}"
        return res
    if want == "allowed" and c["kind"] == "connect":
        v.ok(f"{tagx} {name}: connected to {c['address']}:{c['port']}" + (f" ({c['note']})" if c.get("note") else "")
             + f", attempt {o.get('attempts')} from port {o.get('sport')}")
        res["text"] = "allowed" + (", at the public address" if c.get("note") else "")
        if in_node(c):
            # answered on the client node (Cilium's service translation): the firewall logged nothing for it
            e, p = tlog_entry(d, c["client_addr"], int(o.get("sport") or c["sport"]), c["address"], int(c["port"]))
            v.check(f"{tagx} {name}: answered on {c['client']} itself, no line in the firewall's traffic log for port {o.get('sport')}",
                    e is None, f"{p}:{(e or {}).get('line')} names it")
            res["text"] = "allowed, on the node"
            res["cites"].append(cite(p))
    elif want == "allowed":
        v.ok(f"{tagx} {name}: HTTP 200 from {c.get('gateway')} ({c.get('route')}), from port {o.get('sport')}")
        res["text"] = "200" if c["kind"] == "model" else "allowed"
        kc = c["requests"][0].get("key_caller")
        if c["kind"] == "model" and kc:
            # Part III: the cell's own key is its population's caller's (inetapp for the internet
            # users), and the API gateway's access log names that caller's consumer group
            hit = [i for i, l in enumerate(gwlog.splitlines(), 1) if f'"caller":"{kc}"' in l.replace(" ", "")
                   and ('"status":"200"' in l.replace(" ", "") or '"status":200' in l.replace(" ", ""))]
            v.check(f"[key] {name}: with {kc}'s key, the population's own caller: the API gateway's access log names caller {kc} "
                    f"({len(hit)} answered line(s))", bool(hit), f"no 200 line names caller {kc} in api-gateway/access.txt")
            if hit:
                res["cites"].append(cite("api-gateway/access.txt", hit[0]))
            res["text"] = f"200 with {kc}'s key"
        hd = read(d / f"requests/{o['tag']}-headers.txt")
        if hd:
            res["cites"].append(cite(f"requests/{o['tag']}-headers.txt", 1))
        if in_node(c):
            e, p = tlog_entry(d, c["client_addr"], int(o.get("sport") or c["sport"]), c["address"], int(c["port"]))
            v.check(f"{tagx} {name}: answered on {c['client']} itself, no line in the firewall's traffic log for port {o.get('sport')}",
                    e is None, f"{p}:{(e or {}).get('line')} names it")
            res["cites"].append(cite(p))
    elif want == "log-line":
        e, ex = o.get("tlog") or {}, c["expect"]
        good = e.get("rule") == str(ex["rule"])[:19] and e.get("from") == ex["from_zone"] and e.get("to") == ex["to_zone"]
        lab = (f"{tagx} {name}: log line, {ex['rule']} ({e.get('action')}), zone {ex['from_zone']} to {ex['to_zone']}, "
               f"for port {o.get('sport')}; the client: {view_text(o)}")
        if good:
            v.ok(lab)
        else:
            fail("log line", f"want {ex['rule']} {ex['from_zone']} to {ex['to_zone']}, got {e.get('rule')} {e.get('from')} to {e.get('to')}")
        res["cites"].append(cite(o.get("tlog_file"), e.get("line")))
        res["text"] = f"log line, {ex['rule']} (policy); {view_text(o)}"
        # an operator cell: the router in front of the firewall routes the destination to it
        for h in c.get("hops") or []:
            if h.get("row") == "routing" and h.get("via") and h["device"] in plan.get("routers", []):
                p = f"routers/{h['device']}-ip-route.txt"
                rt = next((x for x in router_routes(read(d / p)) if x["dest"] == h["dest"] and x["via"] == h["via"]), None)
                if rt:
                    v.ok(f"[routing] {name}: {h['device']} routes {h['dest']} via {h['via']}, so the request meets the firewall")
                else:
                    fail(f"{h['device']}'s route to {h['dest']}", f"no route via {h['via']} in {p}")
                res["cites"].append(cite(p, rt["line"] if rt else None))
    elif want == "404":
        hd = read(d / f"requests/{o['tag']}-headers.txt")
        srv = next((l.split(":", 1)[1].strip() for l in hd.splitlines() if l.lower().startswith("server:")), None)
        marker = c["requests"][0].get("marker")
        seen = [i for i, l in enumerate(gwlog.splitlines(), 1) if marker and marker in l]
        lab = f"{tagx} {name}: 404 from {c.get('gateway')}" + (f", server {srv}" if srv else "") + f", from port {o.get('sport')}"
        v.ok(lab)
        if not gw_log_read(gwlog):
            fail("the API gateway's log", "no model request of the run in api-gateway/access.txt: its absence proves nothing")
        elif seen:
            fail(f"no API gateway line for {marker}", f"{len(seen)} line(s), the first at api-gateway/access.txt:{seen[0]}")
        else:
            v.ok(f"[routeset] {name}: no line for {marker} in the API gateway's log, which holds the run's model requests")
        res["cites"].append(cite(f"requests/{o['tag']}-headers.txt", 1))
        res["text"] = f"404, {c.get('gateway')} (route set)"
    elif want == "silence":
        dev = c["expect"].get("device")
        dst = o.get("dst") or c.get("address")
        if dev in plan.get("routers", []):
            p = f"routers/{dev}-ip-route.txt"
            rr = router_routes(read(d / p))
            hit = next((x for x in rr if _covers(x["dest"], dst)), None)
            if not rr:
                fail(f"{dev} holds no route to {dst}", f"no routing table read in {p}")
            elif hit is not None:
                fail(f"{dev} holds no route to {dst}", f"{p}:{hit['line']} routes {hit['dest']}")
            else:
                v.ok(f"[routing] {name}: {dev} holds no route to {dst} ({len(rr)} routes read)")
                res["cites"].append(cite(p, 1))
        elif dev == plan.get("firewall") and c["expect"].get("drop") == "strict-ip":
            # zone protection's strict IP check: the source arrived on an interface the firewall does
            # not route it over (its route back, in the routing table), and only a drop counter says so
            p = "fw/routing-route.txt"
            m = re.match(r"^by (\S+/\d+) out (\S+)", str(c["expect"].get("source_route") or ""))
            ln = fw_route_line(read(d / p), m.group(1), m.group(2)) if m else None
            if ln is None:
                fail(f"{dev} routes the source {c['client_addr']} {c['expect'].get('source_route')}",
                     f"no such route in {p}")
            else:
                v.ok(f"[routing] {name}: {dev} routes the source {c['client_addr']} {c['expect']['source_route']}, not over the "
                     "interface the request arrived on")
                res["cites"].append(cite(p, ln))
            cname = str(c["expect"].get("counter") or "")
            pb, pa, dp = "fw/counters-before.txt", "fw/counters-after.txt", "fw/drops.txt"
            cb, ca = PP.counters_cli(read(d / pb)), PP.counters_cli(read(d / pa))
            vb, va = (cb.get(cname) or {}).get("value"), (ca.get(cname) or {}).get("value")
            dv = drop_count(read(d / dp), cname)
            dtext = (f"the delta view lists it +{dv}" if dv else
                     f"the delta view does not list it ({sampling(read(d / dp))})")
            if not cb or not ca:
                fail(f"zone protection's strict IP check dropped it ({cname} counted)",
                     f"no counter values read in {pb if not cb else pa}, the counters read around the run")
            elif va is None:
                fail(f"zone protection's strict IP check dropped it ({cname} counted)",
                     f"{cname} not among the {len(ca)} counters in {pa}")
            elif va - (vb or 0) <= 0:
                fail(f"zone protection's strict IP check dropped it ({cname} counted)",
                     f"{cname} {vb or 0} in {pb} and {va} in {pa}: it did not rise over the run")
            else:
                v.ok(f"[routing] {name}: zone protection's strict IP check dropped it before any rule ({cname} rose by "
                     f"{va - (vb or 0)} over the run, {vb or 0} to {va}, {pb}, {pa}; {dtext}, {dp})")
                res["cites"].append(cite(pa, line_of(read(d / pa), rf"^\s*{re.escape(cname)}\s")))
        elif dev == plan.get("firewall"):
            p = "fw/routing-route.txt"
            dr = fw_discards(read(d / p))
            hit = next((x for x in dr if _covers(x["dest"], dst)), None)
            if hit is None:
                fail(f"{dev} discards {dst}", f"no discard route covering it in {p}")
            else:
                v.ok(f"[routing] {name}: {dev} discards {dst} by its route {hit['dest']}, before any rule")
                res["cites"].append(cite(p, hit["line"]))
        v.ok(f"{tagx} {name}: silence at {dev}; no traffic log line names it; the client: {view_text(o)}")
        res["text"] = f"silence, {dev} (routing)"
    # a model cell's second request: another model's key on this route
    if c["kind"] == "model" and len(c["requests"]) > 1:
        q = c["requests"][1]
        o2 = ob["requests"].get(q["id"]) or {}
        ex = q["expect"]
        body = read(d / f"requests/{o2.get('tag')}-body.txt") if o2.get("tag") else ""
        if o2.get("status") == ex["status"] and ex["message"] in body:
            v.ok(f"[key] {name}: {ex['status']} with {q['key']}'s key, `{ex['message']}`, from port {o2.get('sport')}")
        else:
            fail(f"{ex['status']} with {q['key']}'s key", f"got {o2.get('status') or view_text(o2)}, message {'found' if ex['message'] in body else 'absent'}")
        if o2.get("tag"):
            res["cites"].append(cite(f"requests/{o2['tag']}-body.txt", 1))
        res["text"] += f"; {ex['status']} with the other model's key (key)"
    return res


def gw_log_read(gwlog: str) -> bool:
    return any("/models/" in l for l in gwlog.splitlines())


def cmd_judge(a) -> int:
    d = Path(a.dir)
    plan = load(a.plan)
    v = vocab.Vocab()
    rows, cols = rows_of(plan), cols_of(plan)
    obs = {o["cell"]: o for o in observe(d, plan, a.only)}
    gwlog = read(d / "api-gateway" / "access.txt")
    out = {}
    cells = cells_of(plan, a.only)
    for r in plan["rows"]:
        mine = [c for c in cells if c["row"] == r["id"]]
        if not mine:
            continue
        v.sec(f"{r['label']}: {r['client']} ({r['address']}), resolver {r['resolver']}, view {r['view']}")
        for c in mine:
            out[c["id"]] = judge_cell(v, d, plan, c, obs[c["id"]], rows, cols, gwlog)
    if not a.only:
        v.sec("the matrix")
        cnt = {m: sum(1 for c in cells if c["mode"] == m) for m in ("allowed", "log-line", "404", "silence")}
        good = sum(1 for x in out.values() if x["ok"])
        v.check(f"{good} of {len(cells)} cells in their mode ({cnt['allowed']} allowed, {cnt['log-line']} log lines, "
                f"{cnt['404']} 404, {cnt['silence']} silent)", good == len(cells), f"{len(cells) - good} cell(s) not in their mode")
        dc = (plan.get("counts") or {}).get("depth")
        if dc:
            got_d = {}
            for c in cells:
                got_d[str(c.get("depth"))] = got_d.get(str(c.get("depth")), 0) + 1
            tail = f" (and {cnt['allowed']} allowed at depth 0)" if "0" not in dc else ""
            v.check("the cells' isolation depth as the render computes it: " + ", ".join(f"depth {k} {n}" for k, n in sorted(dc.items())) + tail,
                    all(got_d.get(k) == n for k, n in dc.items()), f"the plan's cells count {got_d}")
        write_md(d, plan, out, a.stamp)
    return 1 if v.counts()["fail"] else 0


def write_md(d: Path, plan: dict, out: dict, stamp=None):
    try:
        run = load(d / "RUN.json")
    except (OSError, ValueError):
        run = {}
    repo = run.get("labs_repo") or {}
    commit = repo.get("commit") or "none"
    unc = " (with uncommitted changes)" if repo.get("dirty") is True else ""
    rows = plan["rows"]
    cn = plan["counts"]
    L = ["# Population and endpoint matrix", "",
         f"- Lab: `{plan.get('lab')}`; labs repo commit `{commit}`{unc}; UTC {run.get('utc_start') or 'unknown'}",
         f"- {len(rows)} populations by {len(plan['columns'])} endpoints: {cn['cells']} cells, {cn['allowed']} allowed and {cn['forbidden']} "
         f"forbidden ({cn['log-line']} log lines, {cn['404']} 404, {cn['silence']} silent), and {cn['401']} requests with another model's key",
         "- Every cell is tried by TCP connect or HTTP request from the population's own client, never by ping, its mode asserted with "
         "its evidence"]
    if stamp:
        L.append(f"- {stamp}")
    L += ["", "| Endpoint | Address and port | " + " | ".join(r["label"] for r in rows) + " |", "|---|---|" + "---|" * len(rows)]
    by = {c["id"]: c for c in plan["cells"]}
    for col in plan["columns"]:
        if col["kind"] == "connect":
            ap = f"{col['address']}, tcp/{col['port']}"
        elif col["kind"] == "model":
            ap = f"the resolver's answer, tcp/443, {col['path']}"
        else:
            ap = f"the resolver's answer, tcp/443, {col['path']}"
        cells = []
        for r in rows:
            cid = f"{r['id']}/{col['id']}"
            x = out.get(cid)
            cells.append(("PASS " if x and x["ok"] else "FAIL ") + (x["text"] if x else by[cid]["mode"]) if x else "-")
        L.append(f"| {col['label']} | {ap} | " + " | ".join(cells) + " |")
    deep = any("depth" in c for c in plan["cells"])
    if deep:
        # Part III (chapter 11): each cell's isolation depth, the layers that would refuse it if every
        # earlier layer let it through (render/decisions.py), beside its evidence
        L += ["", "## Evidence by cell", "", "| Cell | Mode | Depth | The layers that would refuse it | Evidence |", "|---|---|---|---|---|"]
    else:
        L += ["", "## Evidence by cell", "", "| Cell | Mode | Evidence |", "|---|---|---|"]
    for c in plan["cells"]:
        x = out.get(c["id"])
        if x and deep:
            layers = "; ".join(f"{y['device']} ({y['row']}): {y['why']}" for y in c.get("depth_layers") or []) or "none: allowed"
            L.append(f"| `{c['id']}` | {MODE_TEXT.get(c['mode'], c['mode'])} | {c.get('depth')} | {layers} | {', '.join(x['cites']) or '-'} |")
        elif x:
            L.append(f"| `{c['id']}` | {MODE_TEXT.get(c['mode'], c['mode'])} | {', '.join(x['cites']) or '-'} |")
    L += ["", f"Silence: {', '.join(plan['silence']['cells']) or 'no cell'}; its evidence is {plan['silence']['evidence']}.", ""]
    if deep and (plan.get("counts") or {}).get("depth"):
        L += ["Cells by depth: " + ", ".join(f"depth {k} {n}" for k, n in sorted(plan["counts"]["depth"].items())) + ".", ""]
    verdict = read(d / "verdict.txt")
    L += ["## Verdict", "", "```"] + [l for l in verdict.splitlines() if l.strip()] + ["```", ""]
    L += ["## Files", "",
          "- `verdict.txt`, `commands.txt`, `matrix.json` (the plan), `requests.tsv` (one line an attempt)",
          "- `lookups/`: each client's lookup of the names it asks for, through its own resolver",
          "- `requests/`: each attempt as the client saw it, and each answer's headers and body; no request header is saved",
          "- `fw/`: the traffic log read for the refused cells; `routers/`: the routing table of each router in front of the firewall",
          "- `api-gateway/access.txt`: the API gateway pods' access log over the run", ""]
    (d / "MATRIX.md").write_text("\n".join(L), encoding="utf-8")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="matrix")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("get")
    s.add_argument("--plan", required=True)
    s.add_argument("path")
    for name in ("requests", "lookups", "strict-ip"):
        s = sub.add_parser(name)
        s.add_argument("--plan", required=True)
        s.add_argument("--only", nargs="*")
    for name in ("tlog-ports", "tlog-missing", "observe"):
        s = sub.add_parser(name)
        s.add_argument("--plan", required=True)
        s.add_argument("--dir", required=True)
        s.add_argument("--only", nargs="*")
    s = sub.add_parser("judge")
    s.add_argument("--plan", required=True)
    s.add_argument("--dir", required=True)
    s.add_argument("--stamp")
    s.add_argument("--only", nargs="*")
    a = p.parse_args(argv)
    return {"get": cmd_get, "requests": cmd_requests, "lookups": cmd_lookups, "tlog-ports": cmd_tlog_ports,
            "tlog-missing": cmd_tlog_missing, "observe": cmd_observe, "judge": cmd_judge, "strict-ip": cmd_strict_ip}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
