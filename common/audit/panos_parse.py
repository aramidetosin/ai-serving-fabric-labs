#!/usr/bin/env python3
"""panos_parse: what the PA-VM prints, read into data (chapter 4's audit, trace, drills and break).

    panos_parse.py counters  --cli FILE [--xml FILE]           JSON {name: {value, severity, ...}}
    panos_parse.py delta     --before CLI [--before-xml XML] --after CLI [--after-xml XML] [--name N]
    panos_parse.py ping      FILE                               JSON {sent, received}
    panos_parse.py tlog      FILE [--src A] [--sport N] [--dst A] [--dport N] [--rule R]
    panos_parse.py sessions  FILE                               JSON list of show session all rows
    panos_parse.py session   FILE                               JSON of show session id
    panos_parse.py policy    FILE                               the rule names of show running *-policy, in order
    panos_parse.py ntp       FILE                               JSON {servers, synched}

Every reader is tolerant of what it does not know: it returns what it found, and the caller judges
what is missing. The formats are the ones the PA-VM 12.1.2 printed in chapter 3's result sets
where those exist (the traffic log and the running policies, common/tests/recorded/ch03-rev1/); the others are the
CLI's documented shapes and are marked unproven in ch04/README.md until a deploy records them:
show counter global, show session all, show session id and show ntp. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evfile  # noqa: E402

IP = r"\d{1,3}(?:\.\d{1,3}){3}"


def read(p) -> str:
    """The text of a recorded file, stored plain or compressed (evfile.py); "" when it is not there."""
    try:
        return evfile.read_text(p)
    except (OSError, TypeError, ValueError):
        return ""


# --------------------------------------------------------------------------------------------
# show counter global


COUNTER_ROW = re.compile(r"^([a-z][a-z0-9_]*)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*)$")


def counters_cli(text: str) -> dict:
    """show counter global [filter ...]: {name: {value, rate, severity, category, aspect, desc}}.
    A row reads: name value rate severity category aspect description."""
    out = {}
    for line in (text or "").splitlines():
        m = COUNTER_ROW.match(line.strip())
        if m and m.group(1) not in ("name",):
            out[m.group(1)] = {"value": int(m.group(2)), "rate": int(m.group(3)), "severity": m.group(4),
                               "category": m.group(5), "aspect": m.group(6), "desc": m.group(7).strip()}
    return out


def counters_xml(text: str) -> dict:
    """The XML API's answer to <show><counter><global>...: every entry with a name and a value."""
    out = {}
    try:
        root = ET.fromstring((text or "").strip() or "<x/>")
    except ET.ParseError:
        return out
    for e in root.iter("entry"):
        name, value = e.findtext("name"), e.findtext("value")
        if name and value is not None and re.match(r"^\d+$", value.strip()):
            out[name.strip()] = {"value": int(value.strip()), "rate": int((e.findtext("rate") or "0").strip() or 0)
                                 if (e.findtext("rate") or "0").strip().isdigit() else 0,
                                 "severity": (e.findtext("severity") or "").strip(), "category": (e.findtext("category") or "").strip(),
                                 "aspect": (e.findtext("aspect") or "").strip(), "desc": (e.findtext("desc") or "").strip()}
    return out


def counters(cli: str = "", xml: str = "") -> dict:
    """The XML form where it parsed, the CLI form beside it for any name only it holds."""
    out = counters_cli(cli)
    out.update(counters_xml(xml))
    return out


def delta(before: dict, after: dict, name: str | None = None) -> dict:
    """{name: after - before} for every counter that moved (or the one named, moved or not; a name
    in neither table is absent from the answer)."""
    if name is not None:
        if name not in before and name not in after:
            return {}
        return {name: (after.get(name) or {}).get("value", 0) - (before.get(name) or {}).get("value", 0)}
    out = {}
    for k in sorted(set(before) | set(after)):
        d = (after.get(k) or {}).get("value", 0) - (before.get(k) or {}).get("value", 0)
        if d:
            out[k] = d
    return out


# --------------------------------------------------------------------------------------------
# ping (Linux iputils and busybox, as the guests and containers print it)


def ping(text: str) -> dict:
    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", text or "")
    if not m:
        return {"sent": None, "received": None}
    return {"sent": int(m.group(1)), "received": int(m.group(2))}


# --------------------------------------------------------------------------------------------
# show log traffic (the CLI's table: two lines of fields per entry, then the users and end reason,
# then the rule's uuid; common/tests/recorded/ch03-rev1/fw-traffic-log.txt)

TLOG_DATE = re.compile(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\b")


def _columns(header: str) -> list:
    """[(name, start)] from a header line, each column name where its word starts."""
    cols = []
    for m in re.finditer(r"\S+(?: \S+)?", header):
        cols.append((m.group(0).strip(), m.start()))
    return cols


def _slice(line: str, cols: list) -> dict:
    out = {}
    for i, (name, start) in enumerate(cols):
        end = cols[i + 1][1] if i + 1 < len(cols) else len(line)
        out[name] = line[start:end].strip() if start < len(line) else ""
    return out


def tlog(text: str) -> list:
    """Every entry: {time, app, from, sport, src, rule, action, to, dport, dst, end_reason, line}.
    Read by the header's columns when the header is there, else by tokens."""
    lines = (text or "").splitlines()
    h1 = next((l for l in lines if l.startswith("Time ") and "Source" in l), None)
    h2 = next((l for l in lines if l.startswith("Rule ") and "Destination" in l), None)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not TLOG_DATE.match(line):
            i += 1
            continue
        nxt = lines[i + 1] if i + 1 < len(lines) else ""
        third = lines[i + 2] if i + 2 < len(lines) and not TLOG_DATE.match(lines[i + 2]) else ""
        if h1 and h2:
            a = _slice(line, [("Time", 0)] + [c for c in _columns(h1) if c[0] != "Time"])
            b = _slice(nxt, _columns(h2))
            e = {"time": a.get("Time", ""), "app": a.get("App", ""), "from": a.get("From", ""), "sport": a.get("Src Port", ""),
                 "src": a.get("Source", ""), "rule": b.get("Rule", ""), "action": b.get("Action", ""), "to": b.get("To", ""),
                 "dport": b.get("Dst Port", ""), "dst": b.get("Destination", "")}
        else:
            t, u = line.split(), nxt.split()
            e = {"time": " ".join(t[:2]), "app": t[2] if len(t) > 2 else "", "from": t[3] if len(t) > 3 else "",
                 "sport": t[4] if len(t) > 4 else "", "src": t[5] if len(t) > 5 else "", "rule": u[0] if u else "",
                 "action": u[1] if len(u) > 1 else "", "to": u[2] if len(u) > 2 else "", "dport": u[3] if len(u) > 3 else "",
                 "dst": u[4] if len(u) > 4 else ""}
        e["end_reason"] = third.strip().split()[-1] if third.strip() else ""
        e["line"] = i + 1
        out.append(e)
        i += 2
    return out


def tlog_find(text: str, src=None, sport=None, dst=None, dport=None, rule=None) -> list:
    """The entries matching every filter given (a rule name is compared on its first 19
    characters, as the CLI cuts it)."""
    out = []
    for e in tlog(text):
        if src is not None and e["src"] != str(src):
            continue
        if sport is not None and e["sport"] != str(sport):
            continue
        if dst is not None and e["dst"] != str(dst):
            continue
        if dport is not None and e["dport"] != str(dport):
            continue
        if rule is not None and e["rule"] != str(rule)[:19]:
            continue
        out.append(e)
    return out


def tlog_key(e: dict) -> tuple:
    return (e.get("time"), e.get("src"), e.get("sport"), e.get("dst"), e.get("dport"), e.get("rule"), e.get("action"))


# --------------------------------------------------------------------------------------------
# show session all / show session id

SESS_SRC = re.compile(rf"({IP})\[(\d+)\]/([^/\s]+)/(\d+)\s+\(({IP})\[(\d+)\]\)")
SESS_DST = re.compile(rf"({IP})\[(\d+)\]/([^/\s(]+)\s+\(({IP})\[(\d+)\]\)")


def sessions(text: str) -> list:
    """show session all [filter ...]: [{id, app, state, flag, src, sport, from, proto, xsrc, xsport,
    dst, dport, to, xdst, xdport}]. A row is two lines: the id, application, state, type, flag and
    the source side; then the vsys and the destination side, each with its translated address."""
    out = []
    lines = (text or "").splitlines()
    for i, line in enumerate(lines):
        m = re.match(r"^(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(.*)$", line.strip())
        if not m:
            continue
        s = SESS_SRC.search(line)
        if not s:
            continue
        d = SESS_DST.search(lines[i + 1]) if i + 1 < len(lines) else None
        pre = line[:s.start()].split()
        flag = pre[4] if len(pre) > 4 else ""
        row = {"id": m.group(1), "app": m.group(2), "state": m.group(3), "type": m.group(4), "flag": flag,
               "src": s.group(1), "sport": int(s.group(2)), "from": s.group(3), "proto": int(s.group(4)),
               "xsrc": s.group(5), "xsport": int(s.group(6)), "line": i + 1}
        if d:
            row.update({"dst": d.group(1), "dport": int(d.group(2)), "to": d.group(3), "xdst": d.group(4), "xdport": int(d.group(5))})
        out.append(row)
    return out


def sessions_xml(text: str) -> list:
    """The XML API's show session all: one dict per entry, child tag to text."""
    try:
        root = ET.fromstring((text or "").strip() or "<x/>")
    except ET.ParseError:
        return []
    out = []
    for e in root.iter("entry"):
        d = {c.tag: (c.text or "").strip() for c in e if len(c) == 0}
        if d:
            out.append(d)
    return out


def session(text: str) -> dict:
    """show session id N: the c2s and s2c flows ({source, zone, dst, sport, dport, proto}) and the
    `key : value` lines (rule, nat-rule, ingress interface, egress interface and the rest)."""
    out = {"c2s": {}, "s2c": {}, "kv": {}}
    cur = None
    for raw in (text or "").splitlines():
        line = raw.strip()
        if re.match(r"^c2s flow:?$", line):
            cur = "c2s"
            continue
        if re.match(r"^s2c flow:?$", line):
            cur = "s2c"
            continue
        m = re.match(rf"^source:\s+({IP})\s*(?:\[([^\]]*)\])?", line)
        if m and cur:
            out[cur]["source"], out[cur]["zone"] = m.group(1), (m.group(2) or "").strip()
            continue
        m = re.match(rf"^dst:\s+({IP})", line)
        if m and cur:
            out[cur]["dst"] = m.group(1)
            continue
        m = re.match(r"^proto:\s+(\d+)", line)
        if m and cur:
            out[cur]["proto"] = int(m.group(1))
            continue
        m = re.match(r"^sport:\s+(\d+)\s+dport:\s+(\d+)", line)
        if m and cur:
            out[cur]["sport"], out[cur]["dport"] = int(m.group(1)), int(m.group(2))
            continue
        m = re.match(r"^([A-Za-z][A-Za-z0-9 /()_.-]*?)\s+:\s+(.*)$", line)
        if m:
            cur = None  # the "key : value" lines follow the two flows
            out["kv"][m.group(1).strip()] = m.group(2).strip()
    kv = out["kv"]
    out["rule"] = kv.get("rule")
    nr = kv.get("nat-rule")
    out["nat_rule"] = re.sub(r"\(.*\)$", "", nr).strip() if nr else None
    out["ingress"] = kv.get("ingress interface")
    out["egress"] = kv.get("egress interface")
    out["translation"] = kv.get("address/port translation")
    return out


# --------------------------------------------------------------------------------------------
# show running security-policy / nat-policy (common/tests/recorded/ch03-rev1/12_running_nat.txt)

POLICY_HEAD = re.compile(r'^"([^";]+); index: (\d+)" \{')


def policy(text: str) -> list:
    """The rule names in index order, with their index."""
    rows = []
    for line in (text or "").splitlines():
        m = POLICY_HEAD.match(line.strip())
        if m:
            rows.append((m.group(1), int(m.group(2))))
    return [n for n, _ in sorted(rows, key=lambda r: r[1])]


# --------------------------------------------------------------------------------------------
# show ntp


def ntp(text: str) -> dict:
    t = text or ""
    servers = sorted(set(re.findall(rf"\b({IP})\b", t)))
    synched = bool(re.search(r"synched to\s+\S+|status:\s*synched", t, re.I))
    m = re.search(rf"synched to\s+({IP})\b", t, re.I)
    return {"servers": servers, "synched": synched, "synched_to": m.group(1) if m else None}


# --------------------------------------------------------------------------------------------


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="panos_parse")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("counters")
    s.add_argument("--cli")
    s.add_argument("--xml")
    s = sub.add_parser("delta")
    s.add_argument("--before", required=True)
    s.add_argument("--before-xml")
    s.add_argument("--after", required=True)
    s.add_argument("--after-xml")
    s.add_argument("--name")
    for name in ("ping", "sessions", "session", "policy", "ntp"):
        s = sub.add_parser(name)
        s.add_argument("file")
    s = sub.add_parser("tlog")
    s.add_argument("file")
    s.add_argument("--src")
    s.add_argument("--sport")
    s.add_argument("--dst")
    s.add_argument("--dport")
    s.add_argument("--rule")
    a = p.parse_args(argv)
    if a.cmd == "counters":
        print(json.dumps(counters(read(a.cli), read(a.xml)), sort_keys=True))
    elif a.cmd == "delta":
        b = counters(read(a.before), read(a.before_xml))
        c = counters(read(a.after), read(a.after_xml))
        print(json.dumps(delta(b, c, a.name), sort_keys=True))
    elif a.cmd == "ping":
        print(json.dumps(ping(read(a.file))))
    elif a.cmd == "tlog":
        print(json.dumps(tlog_find(read(a.file), a.src, a.sport, a.dst, a.dport, a.rule), sort_keys=True))
    elif a.cmd == "sessions":
        print(json.dumps(sessions(read(a.file)), sort_keys=True))
    elif a.cmd == "session":
        print(json.dumps(session(read(a.file)), sort_keys=True))
    elif a.cmd == "policy":
        print("\n".join(policy(read(a.file))))
    elif a.cmd == "ntp":
        print(json.dumps(ntp(read(a.file)), sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
