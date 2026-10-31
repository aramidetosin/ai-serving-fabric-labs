#!/usr/bin/env python3
"""parity.py: does a switch's running configuration hold every line of its rendered startup file?

    parity.py RENDERED RUNNING [--switch NAME] [--normalize FILE] [--json FILE] [--replay FILE]
                               [--reverse] [--quiet]

RENDERED is bootstrap/<sw>/startup-config.cfg. RUNNING is a saved `show running-configuration`
session (prompt lines, carriage returns and terminal escapes are dropped), or - for stdin.

Each rendered configuration line is looked up within its context: a line typed under
`interface PortChannel 10` must appear in the running configuration's `interface PortChannel10`
block, and the block headers themselves must appear. Both sides are compared in one spelling
(sfab.klish_lint.canonical: interface type and number joined), and the switch prints some blocks
in two parts (`mclag domain 1`), so blocks with the same header are merged.

Where the switch writes a line differently from how it was typed, a row of the normalization
table says how to compare them (spec/klish-normalize.yaml; the generator renders it to
gen/klish-normalize.json so this script needs no PyYAML). Row actions:
  rewrite  compare the rendered line as the row's running pattern (\\1 ... refer to rendered groups)
  absent   the switch accepts the line and never prints it
  default  the switch prints the line only when it differs from a default; missing is fine

--replay FILE writes the missing lines as KLISH blocks, in rendered order, one block per
top-level context, blocks separated by a blank line, each ready to be typed between
configure terminal and end (common/klish/replay.sh does that). --json FILE writes the result.
--reverse also lists running lines that no rendered line accounts for, in the blocks the render
touches (information only).

The launcher does not stop on "% Error", so parity is the only proof the file took.
Exit status: 0 nothing missing, 1 lines missing, 2 usage or input error. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sfab.klish_lint import PROMPT_RE, Item, Running, canonical, clean_capture_line, parse_rendered, parse_running  # noqa: E402

ACTIONS = ("rewrite", "absent", "default")


class TableError(ValueError):
    """The normalization table is malformed."""


class Row:
    def __init__(self, d: dict):
        if not isinstance(d, dict):
            raise TableError(f"normalization row {d!r} is not a mapping")
        self.id = str(d.get("id") or "")
        if not re.match(r"^n[0-9]+$", self.id):
            raise TableError(f"normalization row {d!r}: id must be n followed by a number")
        self.action = d.get("action")
        if self.action not in ACTIONS:
            raise TableError(f"{self.id}: action must be one of {', '.join(ACTIONS)}")
        try:
            self.context = re.compile(d["context"]) if d.get("context") else None
            self.rendered = re.compile(d["rendered"])
        except (KeyError, re.error) as e:
            raise TableError(f"{self.id}: bad context or rendered pattern: {e}") from None
        self.running = d.get("running")
        if self.action == "rewrite" and not self.running:
            raise TableError(f"{self.id}: a rewrite row needs a running pattern")

    def applies(self, item: Item):
        hdr = item.context[-1] if item.context else ""
        if self.context is not None and not self.context.search(hdr):
            return None
        return self.rendered.search(item.text)

    def running_re(self, m: re.Match) -> re.Pattern:
        def sub(g: re.Match) -> str:
            return re.escape(m.group(int(g.group(1))) or "")
        return re.compile(re.sub(r"\\([0-9])", sub, self.running))


def load_table(path: str | None) -> list:
    if not path:
        return []
    p = Path(path)
    if not p.is_file():
        raise TableError(f"{path}: no such normalization table")
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # noqa: PLC0415
        except ImportError:
            raise TableError(f"{path}: PyYAML is not installed; pass gen/klish-normalize.json") from None
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    else:
        data = json.loads(p.read_text(encoding="utf-8"))
    rows = data.get("normalize") if isinstance(data, dict) else data
    return [Row(r) for r in (rows or [])]


class RawRunning:
    """The running lines by context with their printed spelling, for rewrite rows."""

    def __init__(self, text: str):
        self.raw: dict = {}
        stack: list = []
        for line0 in text.splitlines():
            line = clean_capture_line(line0)
            s = line.strip()
            if not s or s.startswith("!") or PROMPT_RE.match(line):
                continue
            indent = len(line) - len(line.lstrip(" "))
            while stack and stack[-1][0] >= indent:
                stack.pop()
            ctx = tuple(h for _, h in stack)
            self.raw.setdefault(ctx, []).append((" ".join(s.split()), canonical(s)))
            stack.append((indent, canonical(s)))

    def find(self, context: tuple, rx: re.Pattern):
        for raw, can in self.raw.get(tuple(context), []):
            if rx.search(raw) or rx.search(can):
                return can
        return None


def compare(rendered_lines, running_text: str, rows: list) -> dict:
    items, problems = parse_rendered(rendered_lines)
    run = parse_running(running_text)
    raw = RawRunning(running_text)
    present, missing, absent, default = [], [], [], []
    used: set = set()
    for it in items:
        row, m = None, None
        for r in rows:
            m = r.applies(it)
            if m is not None:
                row = r
                break
        rec = {"lineno": it.lineno, "line": it.text, "context": list(it.context)}
        if row is not None and row.action == "absent":
            absent.append(dict(rec, row=row.id))
            continue
        if row is not None and row.action == "rewrite":
            hit = raw.find(it.context, row.running_re(m))
            if hit is not None:
                used.add((it.context, hit))
                present.append(dict(rec, row=row.id))
            else:
                missing.append(dict(rec, row=row.id))
            continue
        key = it.key
        if run.has(it.context, key):
            used.add((it.context, key))
            present.append(rec)
        elif row is not None and row.action == "default":
            default.append(dict(rec, row=row.id))
        else:
            missing.append(rec)
    return {"items": items, "present": present, "missing": missing, "absent": absent, "default": default,
            "problems": problems, "running": run, "used": used}


def extras(items, run: Running, used: set) -> list:
    """Running lines in the rendered blocks that no rendered line accounts for."""
    out = []
    ctxs = []
    for it in items:
        if it.header:
            c = tuple(it.context) + (it.key,)
            if c not in ctxs:
                ctxs.append(c)
    for c in ctxs:
        for line in run.lines(c):
            if (c, line) not in used:
                out.append({"context": list(c), "line": line})
    return out


def replay_blocks(items, missing: list) -> list:
    """The missing lines as KLISH blocks (lists of lines), one per top-level context, in file order."""
    want = {r["lineno"] for r in missing}
    typed: dict = {}
    for it in items:
        if it.header:
            typed[tuple(it.context) + (it.key,)] = it.text
    blocks: list = []
    order: dict = {}
    for it in items:
        if it.lineno not in want:
            continue
        path = tuple(it.context) + ((it.key,) if it.header else ())
        top = path[0] if path else ("", it.lineno)
        if top not in order:
            order[top] = len(blocks)
            blocks.append([])
        blocks[order[top]].append((path, it))
    out = []
    for entries in blocks:
        lines: list = []
        open_path: tuple = ()
        for path, it in entries:
            common = 0
            while common < min(len(open_path), len(path)) and open_path[common] == path[common]:
                common += 1
            for _ in range(len(open_path) - common):
                lines.append("exit")
            open_path = open_path[:common]
            for k in range(common, len(path)):
                hdr = typed.get(path[: k + 1])
                if hdr is None:
                    raise ValueError(f"no rendered header for {' / '.join(path[: k + 1])}")
                lines.append(hdr)
                open_path = path[: k + 1]
            if not it.header:
                lines.append(it.text)
        lines += ["exit"] * len(open_path)
        out.append(lines)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="parity.py", description="rendered KLISH lines against show running-configuration")
    ap.add_argument("rendered")
    ap.add_argument("running")
    ap.add_argument("--switch", default=None)
    ap.add_argument("--normalize", default=None, help="gen/klish-normalize.json (or the .yaml with PyYAML)")
    ap.add_argument("--json", dest="json_out", default=None)
    ap.add_argument("--replay", default=None)
    ap.add_argument("--reverse", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    sw = a.switch or Path(a.rendered).parent.name or "switch"
    try:
        rendered = Path(a.rendered).read_text(encoding="utf-8").splitlines()
        running = sys.stdin.read() if a.running == "-" else Path(a.running).read_text(encoding="utf-8", errors="replace")
        norm = a.normalize
        if norm is None and os.path.isfile(os.path.join("gen", "klish-normalize.json")):
            norm = os.path.join("gen", "klish-normalize.json")
        rows = load_table(norm)
    except (OSError, TableError, ValueError) as e:
        print(f"parity.py: {e}", file=sys.stderr)
        return 2
    if not running.strip():
        print(f"parity.py: {a.running}: the running configuration capture is empty", file=sys.stderr)
        return 2
    res = compare(rendered, running, rows)
    total = len(res["items"])
    miss = res["missing"]
    if not a.quiet:
        print(f"== parity {sw}")
        for p in res["problems"]:
            print(f"  note: {p}")
        if miss:
            print(f"  FAIL  parity {sw} -> {len(miss)} of {total} rendered lines missing")
            for r in miss:
                where = " / ".join(r["context"]) or "top level"
                print(f"      missing (line {r['lineno']}, {where}): {r['line']}")
        else:
            print(f"  PASS  parity {sw}: {total - len(res['absent']) - len(res['default'])} of {total} rendered lines present"
                  + (f", {len(res['absent'])} absent by row" if res["absent"] else "")
                  + (f", {len(res['default'])} at their default by row" if res["default"] else ""))
    extra = extras(res["items"], res["running"], res["used"]) if a.reverse else []
    if a.reverse and not a.quiet:
        for e in extra:
            print(f"      extra ({' / '.join(e['context'])}): {e['line']}")
    if a.replay:
        blocks = replay_blocks(res["items"], miss)
        text = "\n\n".join("\n".join(b) for b in blocks)
        Path(a.replay).write_text(text + ("\n" if text else ""), encoding="utf-8")
    if a.json_out:
        data = {"switch": sw, "rendered": total, "present": len(res["present"]), "missing": miss,
                "absent": res["absent"], "default": res["default"], "problems": res["problems"]}
        if a.reverse:
            data["extra"] = extra
        Path(a.json_out).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 1 if miss else 0


if __name__ == "__main__":
    sys.exit(main())
