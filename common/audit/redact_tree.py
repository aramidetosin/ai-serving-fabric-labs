#!/usr/bin/env python3
r"""redact_tree: replace text in recorded result sets with a class marker, in place, after recording.

It also cuts a set's saved namecheck output to the lines the audit saves today (namecheck-summary).

    redact_tree.py --class CLASS SOURCE... [--where RX] [--token] [--check] PATH...
    redact_tree.py --class namecheck-summary [--check] PATH...

redact.py scrubs a set while it is recorded, and replaces the lab host's kernel release there with
the host-kernel marker below, the PA-VM's CPU signature with the host-cpuid marker and a measured
throughput figure with the throughput marker. This tool is for text found in a set after it was recorded and
committed that the repository must not carry, for example the lab host's own DNS search domain in
a capture made before a fix reached the lab (FRAMEWORK.md section 4.3).

PATH is a file or a directory: a result set, an audits/ directory or a whole lab. Every text file
under it is read; a file holding a NUL byte is binary and left alone, but is still searched for
every literal (below). A file stored compressed (NAME.gz, evfile.py) is read decompressed and, when
it changes, written back compressed; its line numbers are those of the decompressed text.

SOURCE says what to replace; give one or more:

  --literals FILE     strings, one per line (blank lines and lines starting with # skipped),
                      matched without regard to case and never printed;
                      ~/.config/sfab/scrub-secrets.txt is such a file. In a binary file (a
                      capture) a literal also counts as left when it appears in DNS wire form:
                      a dotted literal's labels, each after its length byte; or a leading run of
                      them followed by a compression pointer, as a name compressed against an
                      earlier one spells it (a run of 2 or more characters), so every DNS message
                      that names the literal holds one of the two; or its first label alone after
                      its length byte, which also finds a name a capture's snap length cut short
                      (only when that label has 4 or more characters: a shorter one would match
                      unrelated bytes). wire_forms below has the rules
  --regex RX          a Python regular expression; when it has a group, only group 1 is replaced
  --regex-file FILE   one such expression per line (blank and # lines skipped), never printed

--where RX replaces only on lines that RX finds a match in. --token widens each match to the whole
name around it, the run of letters, digits, dots, hyphens and underscores, so a literal that is
part of a domain takes the whole domain with it.

Each match becomes [redacted: CLASS] on the line that held it. No line is added or removed, so
every line keeps its number and file:line citations still hold. A match that overlaps a marker
already in the line is skipped, so a second run changes nothing. The classes (CLASSES below):

  host-search-domain   the lab host's own DNS search domain, which Docker copies from the lab
                       host's resolv.conf into each container's
  host-kernel          the lab host's kernel release, which a container prints as its own
                       (redact.py replaces it while a set is recorded)
  host-cpuid           the CPU signature a PA-VM passes through from the lab host's processor,
                       its vm-cpuid (redact.py replaces it while a set is recorded; HOST_CPUID
                       below)
  throughput           a measured throughput figure, which the repository does not publish
                       (redact.py replaces it while a set is recorded; THROUGHPUT and TIMINGS below)
  private-path         a path into the author's own private files, which a reader cannot open
                       (no recording writes one; a check written by hand into a set did)
  host-note            a line written by hand into a set's host readings about the lab host
                       outside the lab, which the repository does not describe (no recording
                       writes one)
  work-note            words written by hand into a set about a step of the author's own
                       workflow, which the repository does not describe (no recording writes
                       them)
  upgrade-notice       containerlab's notice of a release newer than the pin, which its own
                       version check prints in a deploy's output; the repository names only the
                       release it pins (spec/versions.yaml)

One class works on whole files and takes no SOURCE:

  namecheck-summary    a set's saved namecheck output, repo/namecheck.txt, cut to the lines the
                       audit saves today (common/lib.sh audit_clean): every warn line is dropped,
                       because each quoted the text it matched, a fail line keeps its path, line,
                       severity and kind but not its text (namecheck --mask), and the summary line
                       stays as recorded. A line's severity is the one right after its first
                       path:line prefix, so a fail line that quotes a saved warn line stays a fail
                       line. A file that keeps no summary line, a line of another form, or fail
                       lines that the summary's fail count does not match, is left alone and makes
                       the exit status 1. The file's lines are renumbered, so its ledger row gives
                       its length as recorded and the recorded numbers of the lines it kept.

The ledger. A result set is the directory just under an audits/ directory. Each set that holds a
marker or a cut file gets REDACTIONS.md, rebuilt from the markers in the set's files: file
(relative to the set), line and class, and what each class replaced; then, in a last table, each
file a whole-file class cut. A rebuild keeps the rows of that last table from the ledger already
there, for every file that still exists, so a later marker run does not lose them. redact.py
writes the same ledger when it leaves a marker while a set is recorded; the ledger's first
paragraph says whether its markers were written then, after (by this tool), or both, and a rebuild
keeps what it said and adds "after" only when this run changed the set. The ledger names no
replaced text. A changed file outside any result set has no ledger and is only listed in
the output. Say in the set's entry in the lab's audits/INDEX.md (or in the lab's README where it
has no index) that the set has one.

Output: one line per changed line, path:line: CLASS, or per cut file, path: CLASS: cut from N
lines to M, never the text; then a summary. A literal left after the run, on a line --where skips
or in a binary file, is listed as path:line (or path) and makes the exit status 1, and so does a
file namecheck-summary leaves alone. --check changes nothing and lists what a run would change.

Exit status: 0 done or nothing to do; 1 a literal is left, a file was left alone, or --check found
something to change; 2 a usage error, an unreadable source or a missing PATH.

common/audit/gate.sh looks for the literals of the author's literals file in every file of each
set it gates, in the same forms (literal_hits below), and lists each hit as path:line, or path for
a binary file, without the literal.

The runs below are the ones that wrote the markers the committed sets carry today, each on the
audits tree that holds them.

The lab host's search domain in M2's sets (the literals file holds the domain):

    common/audit/redact_tree.py --class host-search-domain \
        --literals ~/.config/sfab/scrub-secrets.txt --where '^\s*(search|domain)\s' --token \
        dev/m2/audits

The lab host's kernel release in M2's sets (the literals file holds the release; a VM's own
kernel is a different release and is kept):

    uname -r >"$release_file"    # on the lab host the sets were recorded on
    common/audit/redact_tree.py --class host-kernel --literals "$release_file" dev/m2/audits

The PA-VM's vm-cpuid in M1's and M2's sets (the expression is HOST_CPUID below, the one redact.py
applies while a set is recorded):

    common/audit/redact_tree.py --class host-cpuid \
        --regex 'vm-cpuid"?[ \t]*(?::[ \t]*"?|>)(?!\[redacted)([^\s<"]+)' \
        dev/m1/audits dev/m2/audits

M1's ten saved namecheck outputs:

    common/audit/redact_tree.py --class namecheck-summary dev/m1/audits

M1's iperf3 figures in its two settle sets (the expression is THROUGHPUT below, the one redact.py
applies while a set is recorded; it was later widened to the byte-rate and lowercase forms, which
match nothing in the recorded sets):

    common/audit/redact_tree.py --class throughput \
        --regex '(?:\d+(?:\.\d+)? [KMGT]?Bytes[ \t]+)?\d+(?:\.\d+)? ?(?:[kKMGT]?bits?|[kKMGT]?i?[Bb]ytes|[kKMGT]?i?B)/s(?:ec)?\b' \
        dev/m1/audits

llama-server's timings in the answers a serving trace saves (`request/request-body.json` and
`warmup-body.json`), for a set recorded before redact.py knew that form (the expression is TIMINGS
below, the one redact.py applies while a set is recorded; the committed traces were recorded with
it, so they need no run):

    common/audit/redact_tree.py --class throughput \
        --regex '"(?:prompt|predicted)_(?:ms|per_token_ms|per_second)"[ \t]*:[ \t]*(-?\d[\d.eE+-]*)' \
        chNN/audits

The request count chapter 7's make load printed over its fixed 60 s, which with the duration reads
as a request rate, in the record-run set's journal and its typescript (the expression takes the
requests and answered counts and each PASS line's total, on the load report's lines alone; the
failed and cut counts are kept):

    common/audit/redact_tree.py --class throughput \
        --regex '(?:^\s*requests |, answered |\(\d+ of )(\d+)' \
        --where '^\s*(?:requests \d+, answered \d+, failed \d+, cut mid-answer \d+|PASS  no (?:failed request|stream cut mid-answer) \(\d+ of \d+\))\s*$' \
        ch07/audits/sfab-ch07_record-run_20261030T120209Z

The path to the author's scrub list in M2's record-refused set (the file that held it, a check
written into the set by hand, was removed from the set the same day):

    common/audit/redact_tree.py --class private-path --regex 'SFAB_SCRUB_LIST=(<[^>]*>/\S+)' \
        dev/m2/audits

M2's hand-written reading of the lab host's checkout size in its record-refused set (the
expression file, kept outside the repository, matches the whole line):

    common/audit/redact_tree.py --class host-note --regex-file "$host_note_rx" dev/m2/audits

The hand-written workflow words in the header comment of M2's record run disk reading (set G of
dev/m2/RESULTS.md; the expression file, kept outside the repository, matches only those words, so
the rest of the header reads as written):

    common/audit/redact_tree.py --class work-note --regex-file "$work_note_rx" dev/m2/audits
"""

from __future__ import annotations

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import evfile  # noqa: E402

CLASSES = {
    "host-search-domain": "the lab host's own DNS search domain, which Docker copies from the lab host's "
                          "resolv.conf into each container's",
    "host-kernel": "the lab host's kernel release, which a container prints as its own",
    "host-cpuid": "the CPU signature the PA-VM passes through from the lab host's processor (its vm-cpuid)",
    "throughput": "a measured throughput figure, which the repository does not publish",
    "private-path": "a path into the author's own private files, which a reader cannot open",
    "host-note": "a line written by hand into the set's host readings about the lab host outside the lab, "
                 "which the repository does not describe",
    "work-note": "words written by hand into the set about a step of the author's own workflow, which the "
                 "repository does not describe",
    "upgrade-notice": "containerlab's notice of a release newer than the pin, printed by its own version "
                      "check in a deploy's output; the repository names only the release it pins",
    "namecheck-summary": "the set's saved namecheck output, cut to the lines the audit saves today "
                         "(common/lib.sh audit_clean): its warn lines, each of which quoted the text it matched, "
                         "are dropped, a fail line keeps its path, line, severity and kind but not its text, and "
                         "the summary line is kept as recorded",
}

# whole-file classes: the class, and the path inside a result set of the files it cuts
FILE_CLASSES = {
    "namecheck-summary": "repo/namecheck.txt",
}

MARK = "[redacted: {}]"
# a measured throughput figure: iperf3's transfer and bitrate columns, as one span, and any other
# rate in bits or bytes per second, in the forms tools print it: bits/sec, bit/s, kbit/s, Gbits/s,
# Bytes/sec, bytes/sec, B/s, kB/s, MB/s, MiB/s and the like. Retransmits, the congestion window, a
# packet rate and a link's configured speed (Mbps, Mb/s, ethtool's 10000Mb/s, whose lowercase b
# the expression leaves alone) are not throughput figures and are kept.
THROUGHPUT = r"(?:\d+(?:\.\d+)? [KMGT]?Bytes[ \t]+)?\d+(?:\.\d+)? ?(?:[kKMGT]?bits?|[kKMGT]?i?[Bb]ytes|[kKMGT]?i?B)/s(?:ec)?\b"
# the firewall's own measured throughput (group 2), as PAN-OS show session info prints it
# ("Throughput:                                      5 kbps"): the dataplane's rate at the read, in
# bits per second written as bps, kbps, Mbps or Gbps. Only that labelled line: a configured rate
# (storm control's "Rate (kbps)", a link's Mbps) is kept.
FW_THROUGHPUT = r"(?m)^([ \t]*Throughput:[ \t]+)(\d+(?:\.\d+)?[ \t]*[kKMGT]?bps)\b"
# the timings llama-server adds to an answer's JSON (each value, group 1): the prompt's and the
# prediction's milliseconds, milliseconds per token and tokens per second, from which a token rate
# reads directly (chapter 7's keyed captures and the answers a trace or a drill saves). The token
# counts beside them (cache_n, prompt_n, predicted_n) are not rates and are kept.
TIMINGS = r'"(?:prompt|predicted)_(?:ms|per_token_ms|per_second)"[ \t]*:[ \t]*(-?\d[\d.eE+-]*)'
# the PA-VM's vm-cpuid value (group 1), as show system info prints it ("vm-cpuid: <value>") and as
# the XML API or a JSON rendering carries it; a value already replaced is not matched again
HOST_CPUID = r'vm-cpuid"?[ \t]*(?::[ \t]*"?|>)(?!\[redacted)([^\s<"]+)'
MARK_RX = re.compile(r"\[redacted: ([a-z][a-z0-9-]*)\]")
CLASS_RX = re.compile(r"^[a-z][a-z0-9-]*$")
TOKEN_CH = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
LEDGER = "REDACTIONS.md"
SKIP_DIRS = {".git"}
FILE_ROW_RX = re.compile(r"^\| (?P<file>[^|]+?) \| (?P<lines>\d+) \| (?P<kept>[^|]+?) \| (?P<cls>[a-z][a-z0-9-]*) \|$")

# a line of namecheck's output: path:line: severity kind[: text]. The severity is the one right
# after the first path:line prefix, so a fail line whose text quotes an earlier saved warn line
# (": warn " inside its text) is still a fail line. (audit_clean saves its output with
# grep -v ': warn ', which is safe there because it runs namecheck --mask: its lines carry no text.)
NC_LINE_RX = re.compile(r"^(?P<hit>.+?:\d+: (?P<sev>fail|warn) [^:]+?)(?:: .*)?$")
NC_SUMMARY = "namecheck: "
NC_FAILS_RX = re.compile(r"\b(\d+) fail\b")


class Usage(Exception):
    pass


# --------------------------------------------------------------------------------------------
# sources


def _lines_of(path: str) -> list:
    try:
        with open(os.path.expanduser(path), encoding="utf-8") as f:
            raw = f.read().splitlines()
    except OSError as e:
        raise Usage(f"cannot read {path}: {e.strerror}") from None
    return [l for l in raw if l.strip() and not l.startswith("#")]


def read_literals(path: str) -> list:
    return sorted({l.rstrip("\r") for l in _lines_of(path)}, key=len, reverse=True)


def compile_rx(text: str, origin: str) -> re.Pattern:
    try:
        return re.compile(text)
    except re.error as e:
        raise Usage(f"a regular expression from {origin} does not compile: {e.msg}") from None


# --------------------------------------------------------------------------------------------
# one line


class Rules:
    def __init__(self, cls: str, literals=(), regexes=(), where=None, token=False):
        self.cls, self.mark = cls, MARK.format(cls)
        self.literals = [l for l in literals if l]
        # a literal matches without regard to case: a name a device printed in capitals is the same name
        self.lit_rx = [re.compile(re.escape(l), re.IGNORECASE) for l in self.literals]
        self.wire = list({rx.pattern: rx for l in self.literals for rx in wire_forms(l)}.values())
        self.regexes = list(regexes)
        self.where, self.token = where, token

    def spans(self, line: str) -> list:
        """The spans to replace in one line, widened, merged, and clear of existing markers."""
        if self.where is not None and not self.where.search(line):
            return []
        found = []
        for rx in self.lit_rx:
            found += [m.span() for m in rx.finditer(line)]
        for rx in self.regexes:
            for m in rx.finditer(line):
                s, e = m.span(1) if rx.groups else m.span()
                if s >= 0 and e > s:
                    found.append((s, e))
        if not found:
            return []
        marks = [m.span() for m in MARK_RX.finditer(line)]
        out = []
        for s, e in found:
            if self.token:
                while s > 0 and line[s - 1] in TOKEN_CH:
                    s -= 1
                while e < len(line) and line[e] in TOKEN_CH:
                    e += 1
            if any(s < me and ms < e for ms, me in marks):
                continue
            out.append((s, e))
        out.sort()
        merged = []
        for s, e in out:
            if merged and s <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((s, e))
        return merged

    def apply(self, line: str) -> str:
        sp = self.spans(line)
        for s, e in reversed(sp):
            line = line[:s] + self.mark + line[e:]
        return line

    def left(self, line: str) -> bool:
        return any(rx.search(line) for rx in self.lit_rx)

    def may_match(self, text: str) -> bool:
        return bool(self.regexes) or any(rx.search(text) for rx in self.lit_rx)

    def in_binary(self, data: bytes) -> bool:
        """Whether a binary file holds a literal, as text or in DNS wire form, in any case."""
        low = data.lower()
        return any(l.lower().encode("utf-8", "surrogateescape") in low for l in self.literals) or \
            any(rx.search(low) for rx in self.wire)


# the shortest first label searched for on its own in a binary file: a shorter one, after its
# length byte, is a few bytes that unrelated data holds by chance
WIRE_LABEL_MIN = 4
# the first byte of a DNS compression pointer: its top two bits set (RFC 1035, section 4.1.4)
POINTER = rb"[\xc0-\xff]"
# the shortest leading run of labels searched for before a pointer, in characters: a run of one
# character is three bytes with its length byte and the pointer, which DNS traffic spells for
# unrelated one-letter names
WIRE_RUN_MIN = 2


def _spell(labels: list) -> bytes:
    return b"".join(bytes([len(x)]) + x for x in labels)


def wire_forms(literal: str) -> list:
    """A dotted literal as a DNS message carries it, as compiled byte patterns over the lower-cased
    data:

    - its labels, each after its length byte: the whole name, with no terminating zero, so a longer
      name ending in it still matches;
    - each leading run of those labels, each after its length byte, followed by a compression
      pointer's first byte (0xC0 to 0xFF), when the run has WIRE_RUN_MIN or more characters. A name
      compressed against an earlier one spells its first labels and points at the rest, and a
      pointer only points back, so the first time a message spells the literal it writes either
      the whole name or one of these runs: every message that names the literal holds one of these
      forms, however short the literal's first label;
    - its first label alone after its length byte, when that label has WIRE_LABEL_MIN or more
      characters, which also finds a name a capture's snap length cut short.

    [] for a literal that is not a dotted name."""
    labels = literal.strip(".").lower().split(".")
    if len(labels) < 2 or not all(0 < len(x) < 64 for x in labels):
        return []
    try:
        enc = [x.encode("ascii") for x in labels]
    except UnicodeEncodeError:
        return []
    out = [re.escape(_spell(enc))]
    for k in range(1, len(enc)):
        if sum(len(x) for x in enc[:k]) >= WIRE_RUN_MIN:
            out.append(re.escape(_spell(enc[:k])) + POINTER)
    if len(enc[0]) >= WIRE_LABEL_MIN:
        out.append(re.escape(_spell(enc[:1])))
    return [re.compile(p) for p in out]


# --------------------------------------------------------------------------------------------
# files and sets


def walk(paths: list) -> list:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for d, ds, fs in os.walk(p):
                ds[:] = sorted(x for x in ds if x not in SKIP_DIRS)
                out.extend(os.path.join(d, f) for f in sorted(fs))
        elif os.path.isfile(p):
            out.append(p)
        else:
            raise Usage(f"no file or directory {p}")
    seen, uniq = set(), []
    for f in out:
        k = os.path.realpath(f)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq


def set_root(path: str):
    """The result set a file belongs to: the directory just under its nearest audits/ ancestor."""
    d = os.path.dirname(os.path.abspath(path))
    while True:
        parent = os.path.dirname(d)
        if parent == d:
            return None
        if os.path.basename(parent) == "audits":
            return d
        d = parent


def read_text(path: str):
    """(text, None) for a text file, decoded so that writing it back restores every byte, or
    (None, data) for a binary one. A compressed file is read decompressed; one that does not
    decompress counts as binary."""
    with open(path, "rb") as f:
        data = f.read()
    if evfile.is_gz(path):
        try:
            data = evfile.gunzip_bytes(data)
        except ValueError:
            return None, data
    if b"\0" in data:
        return None, data
    return data.decode("utf-8", "surrogateescape"), None


def write_text(path: str, text: str) -> None:
    """Write text back as read_text read it: compressed again when the file is stored compressed."""
    evfile.write_bytes(path, text.encode("utf-8", "surrogateescape"))


def marks_in(lines) -> list:
    return [(no, m.group(1)) for no, line in enumerate(lines, 1) if "[redacted: " in line
            for m in MARK_RX.finditer(line)]


class FileResult:
    __slots__ = ("changed", "left", "binary_hit", "marks")

    def __init__(self, changed=(), left=(), binary_hit=False, marks=()):
        self.changed, self.left, self.binary_hit, self.marks = list(changed), list(left), binary_hit, list(marks)


def redact_file(path: str, rules: Rules, check: bool) -> FileResult:
    """Redact one file in place (unless check); report its changed lines, the lines where a
    literal is left, whether it is a binary file holding a literal, and its markers afterwards."""
    if os.path.basename(path) == LEDGER:
        return FileResult()
    text, data = read_text(path)
    if text is None:
        return FileResult(binary_hit=bool(rules.literals) and rules.in_binary(data))
    lines = text.split("\n")
    if not rules.may_match(text):
        return FileResult(marks=marks_in(lines) if "[redacted: " in text else ())
    changed, left = [], []
    for i, line in enumerate(lines):
        new = rules.apply(line)
        if new != line:
            lines[i] = new
            changed.append(i + 1)
        if rules.literals and rules.left(new):
            left.append(i + 1)
    if changed and not check:
        write_text(path, "\n".join(lines))
    return FileResult(changed, left, False, marks_in(lines))


def literal_hits(root: str, literals) -> list:
    """Every place under root (a result set) that holds a literal, in the forms --check counts one
    left, as lines that never name the literal: path:line for a text file (a compressed file read
    decompressed, its lines counted in the decompressed text), and path for a binary file (a
    capture) that holds one as text or in DNS wire form, in any case. A path is relative to root;
    a path that itself holds a literal is listed once as such, and printed with each literal in it
    replaced by a marker. common/audit/gate.sh runs it over each set with the author's literals."""
    rules = Rules("literal", sorted({l for l in literals if l}, key=len, reverse=True))
    out = []
    if not rules.literals:
        return out
    for f in walk([root]):
        rel = os.path.relpath(f, root).replace(os.sep, "/")
        shown = rel
        if rules.left(rel):
            shown = rules.apply(rel)
            out.append(f"{shown}: a literal in the path")
        try:
            text, data = read_text(f)
        except OSError:
            out.append(f"{shown}: unreadable")
            continue
        if text is None:
            if rules.in_binary(data):
                out.append(f"{shown}: a literal (binary, as text or in DNS wire form)")
            continue
        if rules.may_match(text):
            out += [f"{shown}:{no}: a literal" for no, line in enumerate(text.split("\n"), 1) if rules.left(line)]
    return out


def set_marks(root: str) -> list:
    """Every marker in a set's files: (file relative to the set, line, class)."""
    rows = []
    for f in walk([root]):
        if os.path.basename(f) == LEDGER:
            continue
        text, _ = read_text(f)
        if text is not None and "[redacted: " in text:
            rel = os.path.relpath(f, root).replace(os.sep, "/")
            rows += [(rel, no, c) for no, c in marks_in(text.split("\n"))]
    return rows


# the ledger's first sentence, by when its markers were written: "after" by this tool, "recorded"
# by redact.py while the set was recorded, or both
INTRO = {
    "after": ("Some recorded text in this result set was replaced after the set was recorded, with "
              "`common/audit/redact_tree.py`."),
    "recorded": ("Some recorded text in this result set was replaced while the set was recorded, by "
                 "`common/audit/redact.py`."),
    "both": ("Some recorded text in this result set was replaced while the set was recorded, by "
             "`common/audit/redact.py`, and after it was recorded, with `common/audit/redact_tree.py`."),
}


def ledger_text(rows: list, files=(), when: str = "after") -> str:
    """The ledger: rows are markers (file, line, class); files are whole-file cuts (file, lines as
    recorded, recorded numbers of the lines kept, class); when is a key of INTRO."""
    rows, files = sorted(set(rows)), sorted(set(files))
    intro = INTRO[when]
    if rows:
        intro += (" Each replacement is the marker `[redacted: <class>]` on the line that held the text, so every "
                  "line keeps its number and the rest of the line reads as recorded.")
    if files:
        intro += (" Each file in the last table was cut to fewer lines, so its lines were renumbered: the table "
                  "gives its length as recorded and the recorded numbers of the lines it kept, in order, the first "
                  "of which is now line 1.")
    out = [
        "# Redactions",
        "",
        intro + " This file names no replaced text.",
        "",
        "| Class | What it replaced |",
        "|---|---|",
    ]
    for c in sorted({r[-1] for r in rows} | {r[-1] for r in files}):
        out.append(f"| {c} | {CLASSES.get(c, 'a class this version of redact_tree.py does not describe')} |")
    if rows:
        out += ["", "| File | Line | Class |", "|---|---|---|"]
        out += [f"| {f} | {n} | {c} |" for f, n, c in rows]
    if files:
        out += ["", "| File | Lines as recorded | Lines kept, by recorded number | Class |", "|---|---|---|---|"]
        out += [f"| {f} | {n} | {k} | {c} |" for f, n, k, c in files]
    return "\n".join(out) + "\n"


def ledger_files(root: str) -> list:
    """The whole-file rows of the set's ledger, for every file that still exists."""
    try:
        with open(os.path.join(root, LEDGER), encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return []
    out = []
    for line in text.splitlines():
        m = FILE_ROW_RX.match(line)
        if m and m["cls"] in FILE_CLASSES and os.path.isfile(os.path.join(root, m["file"])):
            out.append((m["file"], int(m["lines"]), m["kept"], m["cls"]))
    return out


def ledger_when(root: str):
    """What the set's ledger says about when its markers were written (a key of INTRO), or None
    when it has no ledger."""
    try:
        with open(os.path.join(root, LEDGER), encoding="utf-8") as f:
            text = f.read()
    except OSError:
        return None
    for k in ("both", "recorded", "after"):
        if INTRO[k] in text:
            return k
    return "after"


def merge_when(old, new):
    if old is None or old == new:
        return new
    if new is None:
        return old
    return "both"


def write_ledger(root: str, rows: list, check: bool, files=None, when="after"):
    """'wrote', 'would write', 'same', or None when the set holds no marker and no cut file.
    files defaults to the whole-file rows of the ledger already there. when is what this run did
    to the set: "after" (this tool changed it), "recorded" (redact.py, while it was recorded), or
    None (nothing); the ledger keeps what it said before and adds this."""
    if files is None:
        files = ledger_files(root)
    if not rows and not files:
        return None
    p = os.path.join(root, LEDGER)
    new = ledger_text(rows, files, merge_when(ledger_when(root), when) or "after")
    try:
        with open(p, encoding="utf-8") as f:
            if f.read() == new:
                return "same"
    except OSError:
        pass
    if check:
        return "would write"
    with open(p, "w", encoding="utf-8") as f:
        f.write(new)
    return "wrote"


# --------------------------------------------------------------------------------------------
# whole files: namecheck-summary


def spans_text(numbers: list) -> str:
    """1-based line numbers as runs: '4, 7 to 9'."""
    out, i = [], 0
    while i < len(numbers):
        j = i
        while j + 1 < len(numbers) and numbers[j + 1] == numbers[j] + 1:
            j += 1
        out.append(str(numbers[i]) if i == j else f"{numbers[i]} to {numbers[j]}")
        i = j + 1
    return ", ".join(out)


def namecheck_summary(text: str):
    """(lines as recorded, kept lines, recorded numbers of the kept lines, the first line of another
    form or None) for one saved namecheck output."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    kept, numbers, odd, fails = [], [], None, 0
    for no, line in enumerate(lines, 1):
        m = None if line.startswith(NC_SUMMARY) else NC_LINE_RX.match(line)
        if m and m["sev"] == "warn":
            continue
        if m:
            line = m["hit"]
            fails += 1
        elif not line.startswith(NC_SUMMARY):
            odd = odd or no
        kept.append(line)
        numbers.append(no)
    summaries = [l for l in kept if l.startswith(NC_SUMMARY)]
    if odd is None and not summaries:
        odd = len(lines) or 1
    elif odd is None:
        # the fail lines kept must be the ones the summary counts: a file that disagrees is left alone
        m = NC_FAILS_RX.search(summaries[-1])
        if m and int(m.group(1)) != fails:
            odd = numbers[kept.index(summaries[-1])]
    return len(lines), kept, numbers, odd


def is_cut_target(path: str, cls: str) -> bool:
    rel = FILE_CLASSES[cls].split("/")
    return os.path.normpath(os.path.abspath(path)).split(os.sep)[-len(rel):] == rel


def run_files(a) -> int:
    if a.literals or a.regex or a.regex_file or a.where or a.token:
        raise Usage(f"{a.cls} works on whole files and takes no --literals, --regex, --regex-file, --where or --token")
    files = [f for f in walk(a.paths) if is_cut_target(f, a.cls)]
    verb = "would cut" if a.check else "cut"
    ncut, refused, outside = 0, [], []
    sets = {}
    for f in files:
        text, _ = read_text(f)
        if text is None:
            refused.append(f"{f}: a binary file, left alone")
            continue
        n, kept, numbers, odd = namecheck_summary(text)
        if odd is not None:
            refused.append(f"{f}:{odd}: a line the audit would not save in this form; the file is left alone")
            continue
        new = "\n".join(kept) + "\n"
        root = set_root(f)
        changed = new != text
        if changed:
            ncut += 1
            print(f"{f}: {a.cls}: {verb} from {n} line{'s' * (n != 1)} to {len(kept)}")
            if not a.check:
                write_text(f, new)
            if root is None:
                outside.append(f)
        if root is not None and changed:
            rel = os.path.relpath(os.path.abspath(f), root).replace(os.sep, "/")
            sets.setdefault(root, {})[rel] = (rel, n, spans_text(numbers), a.cls)

    ledgers = {"wrote": 0, "would write": 0, "same": 0}
    for root in sorted(sets):
        rows = ledger_files(root)
        new_rows = sets[root]
        rows = [r for r in rows if r[0] not in new_rows] + list(new_rows.values())
        st = write_ledger(root, set_marks(root), a.check, rows)
        if st:
            ledgers[st] += 1
            if st != "same":
                print(f"{os.path.join(root, LEDGER)}: ledger {'would be written' if a.check else 'written'}")
    for f in outside:
        print(f"{f}: outside any result set, so no ledger")
    for x in refused:
        print(x)
    print(f"redact_tree: {a.cls}: {verb} {ncut} file{'s' * (ncut != 1)} of {len(files)}; "
          f"ledgers {'to write' if a.check else 'written'} {ledgers['would write'] if a.check else ledgers['wrote']}, "
          f"unchanged {ledgers['same']}; left alone {len(refused)}")
    if refused:
        return 1
    if a.check and (ncut or ledgers["would write"]):
        return 1
    return 0


# --------------------------------------------------------------------------------------------


def run(a) -> int:
    if not CLASS_RX.match(a.cls) or a.cls not in CLASSES:
        raise Usage(f"unknown class {a.cls!r}; the classes are {', '.join(sorted(CLASSES))}")
    if a.cls in FILE_CLASSES:
        return run_files(a)
    literals = []
    for p in a.literals:
        literals += read_literals(p)
    regexes = [compile_rx(r, "--regex") for r in a.regex]
    for p in a.regex_file:
        regexes += [compile_rx(r, p) for r in _lines_of(p)]
    if not literals and not regexes:
        raise Usage("no pattern: give --literals, --regex or --regex-file, with at least one entry")
    where = compile_rx(a.where, "--where") if a.where else None
    rules = Rules(a.cls, sorted(set(literals), key=len, reverse=True), regexes, where, a.token)

    files = walk(a.paths)
    dirs = [os.path.abspath(p) for p in a.paths if os.path.isdir(p)]
    nlines = nfiles = 0
    sets, outside, left, touched = {}, [], [], set()
    for f in files:
        r = redact_file(f, rules, a.check)
        root = set_root(f)
        if root is not None:
            rel = os.path.relpath(os.path.abspath(f), root).replace(os.sep, "/")
            seen, rows = sets.setdefault(root, (set(), []))
            seen.add(rel)
            rows.extend((rel, no, c) for no, c in r.marks)
            if r.changed:
                touched.add(root)
        if r.changed:
            nfiles += 1
            nlines += len(r.changed)
            if root is None:
                outside.append(f)
            for n in r.changed:
                print(f"{f}:{n}: {a.cls}" + (" (would change)" if a.check else ""))
        left += [f"{f}:{n}" for n in r.left]
        if r.binary_hit:
            left.append(f"{f} (binary, left alone)")

    ledgers = {"wrote": 0, "would write": 0, "same": 0}
    for root in sorted(sets):
        seen, rows = sets[root]
        if not any(os.path.commonpath([d, root]) == d for d in dirs):
            # only some of the set's files were named: the markers in its other files count too
            rows = rows + [x for x in set_marks(root) if x[0] not in seen]
        st = write_ledger(root, rows, a.check, when="after" if root in touched else None)
        if st:
            ledgers[st] += 1
            if st != "same":
                print(f"{os.path.join(root, LEDGER)}: ledger {'would be written' if a.check else 'written'}")
    for f in outside:
        print(f"{f}: outside any result set, so no ledger")
    for x in left:
        print(f"{x}: a literal is left")

    verb = "would change" if a.check else "changed"
    print(f"redact_tree: {a.cls}: {verb} {nlines} line{'s' * (nlines != 1)} in {nfiles} file{'s' * (nfiles != 1)} "
          f"of {len(files)}; ledgers {'to write' if a.check else 'written'} "
          f"{ledgers['would write'] if a.check else ledgers['wrote']}, unchanged {ledgers['same']}; "
          f"literals left {len(left)}")
    if left:
        return 1
    if a.check and (nlines or ledgers["would write"]):
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="redact_tree", description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--class", dest="cls", required=True, help="the marker's class: " + ", ".join(sorted(CLASSES)))
    ap.add_argument("--literals", action="append", default=[], metavar="FILE")
    ap.add_argument("--regex", action="append", default=[], metavar="RX")
    ap.add_argument("--regex-file", action="append", default=[], metavar="FILE")
    ap.add_argument("--where", metavar="RX")
    ap.add_argument("--token", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("paths", nargs="+", metavar="PATH")
    a = ap.parse_args(argv)
    try:
        return run(a)
    except Usage as e:
        print(f"redact_tree: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
