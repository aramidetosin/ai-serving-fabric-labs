#!/usr/bin/env python3
"""vocab: the result vocabulary every check prints (FRAMEWORK.md section 4.2).

    == section name
      PASS  [U][X] label
      FAIL  [U][X] label -> detail
      SKIP  [U] label (reason)
      KNOWN [R] label: L9
    == RESULT: 41 passed, 0 failed, 1 known platform limitation(s), 0 skipped

The shell helpers in common/lib.sh (sec, ok, bad, skip, known, chk, ge, summary) print the same
lines byte for byte; common/tests/test_harness.py holds them to it. Every line goes to stdout and,
when a verdict file is set (the constructor's verdict argument, else $SFAB_VERDICT), is appended
to it as well, so a Python judge and a shell check running in the same result set share one
count. KNOWN names an id from spec/known.yaml; an id outside the registry prints a FAIL instead.
KNOWN is never counted as a pass.

As a command, for scripts that are neither shell nor Python:

    vocab.py sec NAME | ok LABEL | bad LABEL [DETAIL] | skip LABEL [REASON] | known ID LABEL
    vocab.py chk LABEL WANT GOT | ge LABEL MIN GOT | count [FILE] | summary [FILE]

count prints the four totals as JSON; summary prints the RESULT line and exits 1 on any FAIL.
"""

from __future__ import annotations

import json
import os
import re
import sys

LINE_RE = re.compile(r"^  (PASS|FAIL|SKIP|KNOWN) ")
RESULT_RE = re.compile(
    r"^== RESULT: (\d+) passed, (\d+) failed, (\d+) known platform limitation\(s\), (\d+) skipped$")


def result_line(c: dict) -> str:
    return (f"== RESULT: {c['pass']} passed, {c['fail']} failed, "
            f"{c['known']} known platform limitation(s), {c['skip']} skipped")


def count_lines(lines) -> dict:
    c = {"pass": 0, "fail": 0, "known": 0, "skip": 0}
    for line in lines:
        m = LINE_RE.match(line)
        if m:
            c[m.group(1).lower()] += 1
    return c


def counts_of(path: str) -> dict:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return count_lines(f)
    except OSError:
        return count_lines([])


def parse_result(text: str):
    """The last RESULT line in text as a dict, or None."""
    found = None
    for line in text.splitlines():
        m = RESULT_RE.match(line.strip())
        if m:
            found = dict(zip(("pass", "fail", "known", "skip"), map(int, m.groups())))
    return found


def known_ids_default() -> set:
    env = os.environ.get("SFAB_KNOWN_IDS")
    if env:
        return set(env.split())
    inv = os.environ.get("SFAB_INV")
    if inv and os.path.isfile(inv):
        try:
            with open(inv, encoding="utf-8") as f:
                return set(json.load(f).get("known") or [])
        except (OSError, ValueError):
            pass
    return {f"L{i}" for i in range(1, 12)}


def _one(s) -> str:
    """Labels and details are one line each."""
    return " ".join(str(s).split())


class Vocab:
    def __init__(self, verdict: str | None = None, known: set | None = None, out=None):
        self.verdict = verdict if verdict is not None else (os.environ.get("SFAB_VERDICT") or None)
        self.known_ids = set(known) if known is not None else known_ids_default()
        self.out = out or sys.stdout
        self.mem = {"pass": 0, "fail": 0, "known": 0, "skip": 0}

    def emit(self, line: str) -> None:
        print(line, file=self.out, flush=True)
        m = LINE_RE.match(line)
        if m:
            self.mem[m.group(1).lower()] += 1
        if self.verdict:
            with open(self.verdict, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def sec(self, name) -> None:
        self.emit(f"== {_one(name)}")

    def ok(self, label) -> bool:
        self.emit(f"  PASS  {_one(label)}")
        return True

    def bad(self, label, detail="") -> bool:
        d = _one(detail)
        self.emit(f"  FAIL  {_one(label)}" + (f" -> {d}" if d else ""))
        return False

    def skip(self, label, reason="") -> None:
        r = _one(reason)
        self.emit(f"  SKIP  {_one(label)}" + (f" ({r})" if r else ""))

    def known(self, kid, label) -> bool:
        if kid not in self.known_ids:
            return self.bad(label, f"KNOWN id {kid} is not in spec/known.yaml")
        self.emit(f"  KNOWN {_one(label)}: {kid}")
        return True

    def check(self, label, cond: bool, detail="") -> bool:
        return self.ok(label) if cond else self.bad(label, detail)

    def chk(self, label, want, got) -> bool:
        if str(want) == str(got):
            return self.ok(label)
        return self.bad(label, f"want {want}, got {got}")

    def ge(self, label, minimum, got) -> bool:
        try:
            good = float(got) >= float(minimum)
        except (TypeError, ValueError):
            good = False
        if good:
            return self.ok(label)
        return self.bad(label, f"want >= {minimum}, got {got}")

    def counts(self) -> dict:
        return counts_of(self.verdict) if self.verdict else dict(self.mem)

    def summary(self) -> int:
        c = self.counts()
        self.emit(result_line(c))
        return 1 if c["fail"] else 0


def main(argv=None) -> int:
    a = list(sys.argv[1:] if argv is None else argv)
    if not a:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    cmd, args = a[0], a[1:]
    v = Vocab()
    if cmd == "sec" and args:
        v.sec(" ".join(args))
    elif cmd == "ok" and args:
        v.ok(" ".join(args))
    elif cmd == "bad" and args:
        v.bad(args[0], " ".join(args[1:]))
        return 1
    elif cmd == "skip" and args:
        v.skip(args[0], " ".join(args[1:]))
    elif cmd == "known" and len(args) >= 2:
        return 0 if v.known(args[0], " ".join(args[1:])) else 1
    elif cmd == "chk" and len(args) == 3:
        return 0 if v.chk(*args) else 1
    elif cmd == "ge" and len(args) == 3:
        return 0 if v.ge(*args) else 1
    elif cmd == "count":
        path = args[0] if args else v.verdict
        print(json.dumps(counts_of(path) if path else v.mem, sort_keys=True))
    elif cmd == "summary":
        if args:
            v.verdict = args[0]
        return v.summary()
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
