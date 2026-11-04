#!/usr/bin/env python3
"""vocab: the result vocabulary every check prints.

    == section name
      PASS  [U][X] label
      FAIL  [U][X] label -> detail
      SKIP  [U] label (reason)
      LIMITATION  label
    == RESULT: 41 passed, 0 failed, 1 known platform limitation(s), 0 skipped

The shell helpers in common/lib.sh (sec, ok, bad, skip, limitation, chk, ge, summary) print the same
lines byte for byte. Every line goes to stdout and,
when a results file is set (the constructor's results argument, else $SFAB_RESULTS), is appended
to it as well, so a Python checker and a shell check running in the same run directory share one
count. spec/limitations.yaml lists the limitations. A LIMITATION line is never counted as a pass.

As a command, for scripts that are neither shell nor Python:

    vocab.py sec NAME | ok LABEL | bad LABEL [DETAIL] | skip LABEL [REASON] | limitation LABEL
    vocab.py chk LABEL WANT GOT | ge LABEL MIN GOT | count [FILE] | summary [FILE]

count prints the four totals as JSON; summary prints the RESULT line and exits 1 on any FAIL.
"""

from __future__ import annotations

import json
import os
import re
import sys

LINE_RE = re.compile(r"^  (PASS|FAIL|SKIP|LIMITATION) ")
RESULT_RE = re.compile(
    r"^== RESULT: (\d+) passed, (\d+) failed, (\d+) known platform limitation\(s\), (\d+) skipped$")


def result_line(c: dict) -> str:
    return (f"== RESULT: {c['pass']} passed, {c['fail']} failed, "
            f"{c['limitation']} known platform limitation(s), {c['skip']} skipped")


def count_lines(lines) -> dict:
    c = {"pass": 0, "fail": 0, "limitation": 0, "skip": 0}
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
            found = dict(zip(("pass", "fail", "limitation", "skip"), map(int, m.groups())))
    return found


def _one(s) -> str:
    """Labels and details are one line each."""
    return " ".join(str(s).split())


class Vocab:
    def __init__(self, results: str | None = None, out=None):
        self.results = results if results is not None else (os.environ.get("SFAB_RESULTS") or None)
        self.out = out or sys.stdout
        self.mem = {"pass": 0, "fail": 0, "limitation": 0, "skip": 0}

    def emit(self, line: str) -> None:
        print(line, file=self.out, flush=True)
        m = LINE_RE.match(line)
        if m:
            self.mem[m.group(1).lower()] += 1
        if self.results:
            with open(self.results, "a", encoding="utf-8") as f:
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

    def limitation(self, label) -> bool:
        self.emit(f"  LIMITATION  {_one(label)}")
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
        return counts_of(self.results) if self.results else dict(self.mem)

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
    elif cmd == "limitation" and args:
        return 0 if v.limitation(" ".join(args)) else 1
    elif cmd == "chk" and len(args) == 3:
        return 0 if v.chk(*args) else 1
    elif cmd == "ge" and len(args) == 3:
        return 0 if v.ge(*args) else 1
    elif cmd == "count":
        path = args[0] if args else v.results
        print(json.dumps(counts_of(path) if path else v.mem, sort_keys=True))
    elif cmd == "summary":
        if args:
            v.results = args[0]
        return v.summary()
    else:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
