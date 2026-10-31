#!/usr/bin/env python3
"""setsize: the recording size policy for result sets (FRAMEWORK.md 4.4, "Recording size").

    setsize.py pack SET...           compress what the policy stores compressed (rs_close runs it,
                                     after redact)
    setsize.py check SET...          the gate's caps: one line per finding, exit 1 on any
    setsize.py report [--sets] PATH...   sizes per lab and per file class, checkout and gzip

The policy:

- Each output is committed once. The transcript (commands.txt) is the one record of every command
  as it was sent, so it is kept; the per-node 00_ALL_OUTPUT.txt and the set's
  ALL_DEVICES_OUTPUT.txt, which only joined the per-command files, are no longer written, and the
  drills' placement windows (captures/place/, partial decodes of the captures beside them, read
  while the drill runs) are not committed (.gitignore).
- Raw machine-readable evidence, a .xml or .json file of GZIP_MIN (256 KiB) or more, is stored
  compressed as NAME.gz (evfile.py); the judge reads it before the set closes, and every reader
  accepts either form afterwards.
- No plain text file over TEXT_CAP (10 MiB) is committed. A transcript over it is stored as
  commands.txt.gz; any other text over it fails the gate, because a capture's decode is committed
  whole and as plain text (the book quotes decodes by line), so the drill or trace captures less.
- A set commits at most SET_CAP (64 MiB): every file but the ones git ignores (captures/place/
  and the pcaps the gate set aside), counted as stored.
- A pcap over 5 MiB is set aside by the gate (gate.sh, harness.pcap_max_mib), as before.

$SFAB_TEXT_MAX_MIB and $SFAB_SET_MAX_MIB override the two caps for one run.

A file the book quotes by line stays plain text: lines are counted in the decompressed text, so a
citation of NAME.gz still holds, but a file the book comes to quote is committed decompressed.

check prints, for the gate:

    SIZE <bytes> <files> <cap>     the set as it would be committed
    OVER <bytes> <path>            a plain file over the text cap
    PLAIN <bytes> <path>           a .xml or .json file at or over GZIP_MIN stored plain

Exit status: 0 clean, 1 a finding, 2 a usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evfile  # noqa: E402
import redact_tree  # noqa: E402

MIB = 1048576
GZIP_MIN = 256 * 1024
TEXT_CAP_MIB = 10
SET_CAP_MIB = 64
TRANSCRIPT = "commands.txt"
CONCATENATIONS = ("00_ALL_OUTPUT.txt", "ALL_DEVICES_OUTPUT.txt")
MACHINE = (".xml", ".json")


def text_cap() -> int:
    return int(float(os.environ.get("SFAB_TEXT_MAX_MIB") or TEXT_CAP_MIB) * MIB)


def set_cap() -> int:
    return int(float(os.environ.get("SFAB_SET_MAX_MIB") or SET_CAP_MIB) * MIB)


def is_place(rel: str) -> bool:
    """A drill's placement window: anything under a captures/place/ directory."""
    parts = rel.split("/")
    return any(parts[i] == "captures" and parts[i + 1] == "place" for i in range(len(parts) - 2))


def set_ignored(root: str) -> set:
    """The paths the gate set aside in the set's own .gitignore ("/<path>" lines)."""
    out = set()
    try:
        with open(os.path.join(root, ".gitignore"), encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("/"):
                    out.add(line[1:])
    except OSError:
        pass
    return out


def committed(root: str) -> list:
    """(path relative to the set, bytes) of every file a commit of the set carries."""
    ign = set_ignored(root)
    out = []
    for d, ds, fs in os.walk(root):
        ds[:] = sorted(x for x in ds if x != ".git")
        for f in sorted(fs):
            p = os.path.join(d, f)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            if is_place(rel) or rel in ign:
                continue
            out.append((rel, os.path.getsize(p)))
    return out


def is_plain(rel: str) -> bool:
    return not rel.endswith(evfile.GZ) and not rel.endswith(".pcap")


def to_compress(root: str) -> list:
    """The files pack would compress: machine-readable evidence of GZIP_MIN or more, and a
    transcript over the text cap."""
    cap = text_cap()
    out = []
    for rel, n in committed(root):
        if rel.endswith(MACHINE) and n >= GZIP_MIN:
            out.append(rel)
        elif rel == TRANSCRIPT and n > cap:
            out.append(rel)
    return out


def cmd_pack(sets: list) -> int:
    """Compress what the policy stores compressed. A set whose REDACTIONS.md names a file that is
    now compressed gets its ledger rebuilt from its markers, so it names NAME.gz."""
    rc = 0
    for s in sets:
        if not os.path.isdir(s):
            print(f"setsize: no directory {s}", file=sys.stderr)
            rc = 2
            continue
        done = 0
        for rel in to_compress(s):
            p = os.path.join(s, rel)
            before = os.path.getsize(p)
            try:
                after = os.path.getsize(evfile.compress_file(p))
            except (OSError, ValueError) as e:
                print(f"setsize: {rel}: not compressed: {e}", file=sys.stderr)
                rc = max(rc, 1)
                continue
            done += 1
            print(f"setsize: {rel} stored compressed, {before} bytes as {after}")
        if done and os.path.isfile(os.path.join(s, redact_tree.LEDGER)):
            redact_tree.write_ledger(s, redact_tree.set_marks(s), False, when=None)
    return rc


def findings(root: str) -> tuple:
    """(committed bytes, files, [finding lines]) for one set."""
    files = committed(root)
    total = sum(n for _, n in files)
    cap = text_cap()
    out = []
    for rel, n in files:
        if rel.endswith(MACHINE) and n >= GZIP_MIN:
            out.append(f"PLAIN {n} {rel}")
        elif is_plain(rel) and n > cap:
            out.append(f"OVER {n} {rel}")
    return total, len(files), out


def cmd_check(sets: list) -> int:
    rc = 0
    for s in sets:
        if not os.path.isdir(s):
            print(f"setsize: no directory {s}", file=sys.stderr)
            rc = 2
            continue
        total, n, out = findings(s)
        print(f"SIZE {total} {n} {set_cap()}")
        for line in out:
            print(line)
        if out or total > set_cap():
            rc = max(rc, 1)
    return rc


# --------------------------------------------------------------------------------------------
# report


def klass(rel: str) -> str:
    parts = rel.split("/")
    base = evfile.plain_name(parts[-1])
    if len(parts) == 1 and base == TRANSCRIPT:
        return "transcript (commands.txt)"
    if base in CONCATENATIONS:
        return "concatenations (00_ALL_OUTPUT, ALL_DEVICES_OUTPUT)"
    if "raw" in parts[:-1]:
        return "raw sessions (raw/)"
    if base.endswith(".pcap"):
        return "pcaps"
    if is_place(rel):
        return "placement windows (captures/place/)"
    low = base.lower()
    if "counter" in low and low.endswith(".xml"):
        return "counter tables, XML"
    if "counter" in low:
        return "counter tables, text"
    if any(p.startswith("captures") for p in parts[:-1]) and low.endswith(".txt"):
        return "capture decodes"
    if low.endswith(".xml"):
        return "other XML"
    if low.endswith(".json"):
        return "JSON"
    if len(parts) == 2 and re.match(r"^\d\d_", base):
        return "per-command files"
    return "other"


def lab_of(path: str):
    """(lab directory, set name) for a file under <lab>/audits/<set>/."""
    parts = os.path.abspath(path).split(os.sep)
    for i in range(len(parts) - 2, 0, -1):
        if parts[i] == "audits" and i + 2 < len(parts):
            return os.sep.join(parts[:i]), parts[i + 1]
    return None, None


def cmd_report(paths: list, sets: bool) -> int:
    labs = {}
    for p in paths:
        for d, ds, fs in os.walk(p):
            ds[:] = sorted(x for x in ds if x != ".git")
            for f in fs:
                full = os.path.join(d, f)
                lab, s = lab_of(full)
                if lab is None:
                    continue
                with open(full, "rb") as fh:
                    data = fh.read()
                n, g = len(data), len(zlib.compress(data, 6))
                rel = os.path.relpath(full, os.path.join(lab, "audits", s)).replace(os.sep, "/")
                L = labs.setdefault(lab, {"n": 0, "b": 0, "g": 0, "c": {}, "s": {}})
                for t in (L, L["s"].setdefault(s, {"n": 0, "b": 0, "g": 0, "c": {}})):
                    t["n"] += 1
                    t["b"] += n
                    t["g"] += g
                    c = t["c"].setdefault(klass(rel), [0, 0, 0])
                    c[0] += 1
                    c[1] += n
                    c[2] += g
    for lab in sorted(labs):
        L = labs[lab]
        print(f"{os.path.relpath(lab)}: {L['n']} files, {L['b'] / MIB:.2f} MiB checkout, {L['g'] / MIB:.2f} MiB gzip")
        for c, (n, b, g) in sorted(L["c"].items(), key=lambda x: -x[1][1]):
            print(f"  {c:52s} {n:6d} files {b / MIB:9.2f} MiB {100 * b / max(L['b'], 1):5.1f}%  gzip {g / MIB:7.2f} MiB")
        if sets:
            for s, S in sorted(L["s"].items(), key=lambda x: -x[1]["b"]):
                kind = re.sub(r"^[^_]+_", "", s)
                print(f"  set {kind:34s} {S['n']:6d} files {S['b'] / MIB:9.2f} MiB  gzip {S['g'] / MIB:7.2f} MiB")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="setsize", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for c in ("pack", "check"):
        sp = sub.add_parser(c)
        sp.add_argument("sets", nargs="+", metavar="SET")
    sp = sub.add_parser("report")
    sp.add_argument("--sets", action="store_true", help="also one line per result set")
    sp.add_argument("paths", nargs="+", metavar="PATH")
    a = ap.parse_args(argv)
    if a.cmd == "pack":
        return cmd_pack(a.sets)
    if a.cmd == "check":
        return cmd_check(a.sets)
    return cmd_report(a.paths, a.sets)


if __name__ == "__main__":
    sys.exit(main())
