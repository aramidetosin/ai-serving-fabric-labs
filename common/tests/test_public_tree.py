"""The public tree points at nothing a reader cannot open. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p test_public_tree.py

The repository is public; the files the author keeps beside it are not. No file a reader meets
outside the recorded evidence may send them there. Three general patterns hold for any repository
and live here: a ../ path whose first name after the climb is no file or directory of this
repository (a lab directory still to come, chNN, counts as one of its own), a path into a notes/
directory, and a decision cited by its number, whatever joins the word and the number (a space,
an underscore, a hyphen or nothing). A fact such a file held is stated where it is used, or the
book's chapter or appendix is cited by title.

A recording keeps the names it was recorded under as well as its text, so one form of a numbered
decision is let through, and only in the files that must write it (CITES_RECORDED: chapter 4's
audits/INDEX.md, which cites the recorded files, the judge, which reads them, and the judge's
test): the head of a file name a recorded set in this tree carries (the match and the character
after it begin such a name, and the match starts a name of its own). Anywhere else the name is
caught, and only the recorded sets keep it: once the last set carrying it goes, every line that
still names it is caught in those files too.

The other patterns are the author's own: names and wording from private files and working notes,
which this repository does not spell out. They are read from the pattern list that
$SFAB_PUBLIC_TREE_PATTERNS names, kept outside the repository like namecheck's lists. Without the
variable only the general patterns run and the list's own checks are skipped, as namecheck skips
names without a scrub list; a list the variable names that is not there is an error, so a mistyped
path cannot turn the checks off. With $SFAB_REQUIRE_NAMECHECK set (not empty and not 0), as the
gate reads it, a missing variable is an error too, so a run that must have the author's lists
cannot skip them.

The list's format: one item per line, blank lines and lines that start with # skipped.

    label TEXT   starts a group; a hit is reported as TEXT
    re REGEX     one pattern of the group (Python re; a leading (?i) folds case)
    hit TEXT     a made-up line the group must catch; each pattern of the group must catch one
    pass TEXT    a made-up line no pattern, general or the list's, may catch

In hit and pass lines a backslash followed by n is a line break.

Each line of a file is also read joined with the next, so a phrase split across a line break is
caught. A hit is reported by path, line and label, never by its text.

Recorded evidence is every file under an audits/ directory except the lab's own audits/INDEX.md,
which is prose. A recording keeps its text as recorded (FRAMEWORK.md section 4.3), so the sets
are not read. This file is read like any other, so its made-up lines are assembled from pieces.
"""

from __future__ import annotations

import functools
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "common" / "tools"))

import namecheck  # noqa: E402

PATTERNS_VAR = "SFAB_PUBLIC_TREE_PATTERNS"
# set, a run must have the author's lists (common/audit/gate.sh reads the same variable)
REQUIRE_VAR = "SFAB_REQUIRE_NAMECHECK"

# a lab directory the repository gains with a later chapter, which a page may name already
LAB_DIR = re.compile(r"ch\d{2}")


@functools.lru_cache(maxsize=None)
def own_names() -> frozenset:
    """Every file and directory name in this repository's tree."""
    return frozenset(part for rel in namecheck.repo_files() for part in Path(rel).parts)


class OutsidePath:
    """A ../ path whose first name after the climb is no name this repository has: a path into
    another repository beside it. It matches as a compiled pattern does (search, finditer)."""

    rx = re.compile(r"(?<![\w.])(?:\.\./)+(?P<name>[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?)")

    def finditer(self, text: str):
        return (m for m in self.rx.finditer(text)
                if m["name"] not in own_names() and not LAB_DIR.fullmatch(m["name"]))

    def search(self, text: str):
        return next(self.finditer(text), None)


# the characters of a file name, where a recorded name is looked for
NAME_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")


@functools.lru_cache(maxsize=None)
def recorded_names() -> frozenset:
    """The file names of the recorded sets in this repository's tree."""
    return frozenset(Path(rel).name for rel in namecheck.repo_files() if is_evidence(rel))


class NumberedDecision:
    """A decision cited by its number, with a space, an underscore, a hyphen or nothing between the
    word and the number. Given names (a function giving the recorded sets' file names), it lets
    through the head of a file name a recorded set carries; without, it lets nothing through. It
    matches as a compiled pattern does (search, finditer)."""

    rx = re.compile(r"\b[Dd]ecisions?[ _-]?\d+\b")

    def __init__(self, names=None):
        self.names = names

    def _recorded(self, text: str, m) -> bool:
        if self.names is None:
            return False
        if m.start() > 0 and text[m.start() - 1] in NAME_CHARS:
            return False
        head = text[m.start():m.end() + 1]
        return (len(head) > len(m[0]) and head[-1] in NAME_CHARS
                and any(n.startswith(head) for n in self.names()))

    def finditer(self, text: str):
        return (m for m in self.rx.finditer(text) if not self._recorded(text, m))

    def search(self, text: str):
        return next(self.finditer(text), None)


# a numbered decision anywhere, with no recorded name let through
DECISION = NumberedDecision()

# (what the line points at, the pattern); a hit is reported by path, line and label, never by text
GENERAL = [
    ("a ../ path into another repository", OutsidePath()),
    ("a path into a notes/ directory", re.compile(r"(?<![A-Za-z0-9_.-])notes/[A-Za-z0-9_.-]")),
    ("a numbered decision", DECISION),
]

# the files that must write a recorded set's file name whose head is a numbered decision: the lab
# index citing the recorded files, the judge reading them, and the judge's test
CITES_RECORDED = frozenset({"ch04/audits/INDEX.md", "common/audit/judge.py", "common/tests/test_ch04.py"})


def patterns_for(rel: str, patterns: list, names=recorded_names) -> list:
    """The patterns a file is read with: in a file of CITES_RECORDED, the numbered decision lets
    the recorded names through (names() gives them); in every other file, nothing."""
    if rel not in CITES_RECORDED:
        return patterns
    return [(label, NumberedDecision(names) if rx is DECISION else rx) for label, rx in patterns]

# what a line continued from the one above may start with before its text: a comment marker
CONTINUATION = re.compile(r"^\s*(?:#+|//+|\*+|;+|!+|>+)?\s*")


class PatternList:
    """A pattern list: labels in order, patterns [(label, compiled)], hits [(label, text)] and
    passes [text]. A line it cannot read is a ValueError naming the line's number."""

    def __init__(self, text: str):
        self.labels, self.patterns, self.hits, self.passes = [], [], [], []
        for no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, _, rest = line.partition(" ")
            if not rest or key not in ("label", "re", "hit", "pass"):
                raise ValueError(f"pattern list line {no}: expected label, re, hit or pass and its text")
            if key == "label":
                self.labels.append(rest)
            elif key == "pass":
                self.passes.append(rest.replace("\\n", "\n"))
            elif not self.labels:
                raise ValueError(f"pattern list line {no}: {key} before any label")
            elif key == "hit":
                self.hits.append((self.labels[-1], rest.replace("\\n", "\n")))
            else:
                try:
                    self.patterns.append((self.labels[-1], re.compile(rest)))
                except re.error as e:
                    raise ValueError(f"pattern list line {no}: not a pattern ({e})") from None


@functools.lru_cache(maxsize=None)
def _read_list(path: str) -> PatternList:
    return PatternList(Path(path).read_text(encoding="utf-8"))


def private_list():
    """The list $SFAB_PUBLIC_TREE_PATTERNS names, or None when the variable is unset or empty. A
    named list that is not there is an error, and so is no list while $SFAB_REQUIRE_NAMECHECK is
    set; the message does not print the path."""
    path = os.environ.get(PATTERNS_VAR) or None
    if path is None:
        if os.environ.get(REQUIRE_VAR, "") not in ("", "0"):
            raise LookupError(f"no pattern list, and ${REQUIRE_VAR} is set: set ${PATTERNS_VAR}")
        return None
    if not os.path.isfile(path):
        raise FileNotFoundError(f"the pattern list that ${PATTERNS_VAR} names does not exist")
    return _read_list(os.path.abspath(path))


def all_patterns() -> list:
    lst = private_list()
    return GENERAL + (lst.patterns if lst else [])


def _label(line: str, patterns: list):
    for label, rx in patterns:
        if rx.search(line):
            return label
    return None


def line_hits(text: str, patterns: list | None = None) -> list:
    """[(line number, label)] for every line of text that points at a private file. A phrase split
    across a line break counts too: each line is joined with the next (that line's comment marker
    and the whitespace between taken out), and a match that spans the join is the first line's."""
    patterns = all_patterns() if patterns is None else patterns
    out = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        label = _label(line, patterns)
        if label is None and i + 1 < len(lines):
            a = line.rstrip()
            joined = a + " " + CONTINUATION.sub("", lines[i + 1], count=1)
            for lab, rx in patterns:
                if any(m.start() < len(a) < m.end() - 1 for m in rx.finditer(joined)):
                    label = lab
                    break
        if label is not None:
            out.append((i + 1, label))
    return out


def is_evidence(rel: str) -> bool:
    """A recorded file: under an audits/ directory, other than that directory's INDEX.md."""
    parts = rel.split("/")
    if "audits" not in parts[:-1]:
        return False
    return not (parts[-1] == "INDEX.md" and parts[-2] == "audits")


def _listed_rel(root: Path):
    """The pattern list's path inside root, should the variable name a file there, else None."""
    path = os.environ.get(PATTERNS_VAR) or None
    if path is None:
        return None
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def scan(root: Path, files, patterns: list | None = None, names=recorded_names) -> list:
    """['path:line: label'] over the non-evidence files, their paths included, each file read with
    patterns_for() its path (names() gives the recorded names). The pattern list itself is never
    read as a file of the tree."""
    base = all_patterns() if patterns is None else patterns
    listed = _listed_rel(root)
    out = []
    # the renders hold the same upstream manifests many times over: a file of the same bytes as one
    # already read with the same patterns has the same line hits, so each such text is read once
    seen: dict = {}
    for rel in files:
        rel = rel.replace(os.sep, "/")
        if rel == listed or is_evidence(rel):
            continue
        patterns = patterns_for(rel, base, names)
        label = _label(rel, patterns)
        if label is not None:
            out.append(f"{rel}: the path itself is {label}")
        try:
            data = (root / rel).read_bytes()
        except OSError:
            continue
        if b"\0" in data:
            continue
        hits = seen.get(data) if patterns is base else None
        if hits is None:
            hits = line_hits(data.decode("utf-8", "replace"), patterns)
            if patterns is base:
                seen[data] = hits
        out.extend(f"{rel}:{n}: {label}" for n, label in hits)
    return out


def _no_list():
    return f"no pattern list of the author's (set {PATTERNS_VAR} to run it)"


class PublicTreeTest(unittest.TestCase):
    def test_the_tree_points_at_no_private_file(self):
        hits = scan(ROOT, namecheck.repo_files())
        self.assertEqual(hits, [], f"{len(hits)} line(s) point at files a reader cannot open; state the fact "
                         "in place or cite the book's chapter or appendix:\n" + "\n".join(hits[:50]))

    def test_each_general_pattern_catches_its_form(self):
        # made-up lines, assembled here so that no line of this file reads as one
        forms = {
            "a ../ path into another repository": ["see ../" + "other-repo/README.md",
                                                   "the plan in ../../" + "elsewhere/plan.md",
                                                   "(`../" + "sibling-repo/`)"],
            "a path into a notes/ directory": ["evidence in " + "notes/" + "x/",
                                               "see " + "notes/" + "a.md, line 4"],
            "a numbered decision": ["closes " + "decision " + "3",
                                    "as " + "Decisions " + "4 and 5 say",
                                    "the route of " + "decision" + "10",
                                    "per " + "decision_" + "10, the route",
                                    "see " + "Decision-" + "7 (routing)",
                                    "saved as fw-edge/" + "decision" + "99-users-vip.txt"],
        }
        self.assertEqual(set(forms), {lab for lab, _ in GENERAL}, "every general label is exercised")
        for label, lines in forms.items():
            for line in lines:
                self.assertEqual(line_hits(line, GENERAL), [(1, label)], line)
                self.assertEqual(len(line_hits(line)), 1, line)
        # a phrase split across a line break, as a comment or a docstring continues it
        text = "# the route follows " + "decision\n  # " + "4, so"
        self.assertEqual(line_hits(text, GENERAL), [(1, "a numbered decision")], text)

    def test_ordinary_lines_pass(self):
        for line in ("the decision dec-route-inside-via-fw", "a decision_id of the route",
                     "the decisions this design settles", "footnotes/a.md and release-notes/b.md",
                     "include ../common/mk/chapter.mk", '. "$(dirname "$0")/../../common/lib.sh"',
                     "${here}/../bin/inv.py", "the clone line is the repository README's (`../README.md`).",
                     "symlink_to('../ch09/README.md')", "SFAB_ROOT := $(abspath $(dir $(SFAB_MK))/../..)",
                     "must not contain '/../' when type one of", "make -C ../serving-layer serve"):
            self.assertEqual(line_hits(line), [], line)

    def test_a_recorded_name_passes_only_while_a_set_carries_it(self):
        # made-up names, assembled here so that no line of this file reads as one
        label, name = "a numbered decision", "decision" + "7-users-vip.txt"
        carried = [(label, NumberedDecision(lambda: frozenset({name, "verdict.txt"})))]
        gone = [(label, NumberedDecision(lambda: frozenset({"verdict.txt"})))]
        # a recorded file cited, a name built from the cell, a name pattern on a page, a shell write
        for line in ("A/fw-edge/" + name + ":1 (`failed`)", 'rd(f"' + "decision" + '7-{c[\'id\']}.txt")',
                     "`fw-edge/" + "decision" + "7-<cell>.txt`", '>"$d/' + "decision" + '7-$i.txt"'):
            self.assertEqual(line_hits(line, carried), [], line)
            self.assertEqual(line_hits(line, gone), [(1, label)], line)
        # what no recorded name begins with, a match inside a longer name, or a citation beside one
        for line in ("per " + "decision" + "7", "per " + "decision " + "7", "the " + "decision_" + "7-users-vip.txt",
                     "Decision" + "7-users-vip.txt", "decision" + "7.txt", "decision" + "8-users-vip.txt",
                     "x-" + name, "fw-edge/" + name + ", as " + "decision " + "7 says"):
            self.assertEqual(line_hits(line, carried), [(1, label)], line)

    def test_a_recorded_name_passes_only_in_the_files_that_cite_it(self):
        # made-up names, assembled here so that no line of this file reads as one
        label, name = "a numbered decision", "decision" + "7-users-vip.txt"
        line = "the client's view: A/fw-edge/" + name + ":1\n"
        self.assertEqual(line_hits(line, GENERAL), [(1, label)], "the general pattern lets no name through")
        citing = sorted(CITES_RECORDED)
        others = ["ch04/README.md", "ch05/audits/INDEX.md", "common/audit/lib-audit.sh", "FRAMEWORK.md"]
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for rel in citing + others:
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(line)
            hits = scan(root, citing + others, GENERAL, names=lambda: frozenset({name}))
            gone = scan(root, citing, GENERAL, names=lambda: frozenset())
        self.assertEqual(hits, [f"{rel}:1: {label}" for rel in others])
        self.assertEqual(gone, [f"{rel}:1: {label}" for rel in citing], "once no set carries the name")

    def test_each_listed_pattern_catches_its_form(self):
        lst = private_list()
        if lst is None:
            self.skipTest(_no_list())
        self.assertTrue(lst.patterns, "the list holds at least one pattern")
        for label in lst.labels:
            group = [(lab, rx) for lab, rx in lst.patterns if lab == label]
            hits = [text for lab, text in lst.hits if lab == label]
            self.assertTrue(group, f"label {label!r} has no pattern")
            self.assertTrue(hits, f"label {label!r} has no hit line")
            for text in hits:
                # the group catches it on its first line, and the whole guard reports it once
                self.assertEqual(line_hits(text, group), [(1, label)], f"{label!r}: a hit line passes")
                self.assertEqual([n for n, _ in line_hits(text)], [1], f"{label!r}: a hit line")
            for n, (lab, rx) in enumerate(group, 1):
                self.assertTrue(any(line_hits(text, [(lab, rx)]) for text in hits),
                                f"{label!r}: pattern {n} of the group catches none of its hit lines")
        for text in lst.passes:
            self.assertEqual(line_hits(text), [], "a pass line is caught")

    def test_scan_reads_the_listed_patterns(self):
        lst = private_list()
        if lst is None:
            self.skipTest(_no_list())
        with tempfile.TemporaryDirectory() as d:
            root, body, want = Path(d), [], []
            for _, text in lst.hits:
                want.append(f"ch09/README.md:{len(body) + 1}")
                body.extend(text.split("\n") + [""])
            (root / "ch09").mkdir()
            (root / "ch09" / "README.md").write_text("\n".join(body) + "\n")
            hits = scan(root, ["ch09/README.md"])
        self.assertEqual([h.split(": ", 1)[0] for h in hits], want)
        self.assertFalse(any(text in h for _, text in lst.hits for h in hits), "a hit quotes its text")

    def test_the_list_must_be_there_when_named(self):
        with tempfile.TemporaryDirectory() as d:
            missing = str(Path(d) / "absent.txt")
            with mock.patch.dict(os.environ, {PATTERNS_VAR: missing}):
                with self.assertRaises(FileNotFoundError) as cm:
                    private_list()
            self.assertNotIn(d, str(cm.exception), "the error does not print the path")
        with mock.patch.dict(os.environ, {PATTERNS_VAR: "", REQUIRE_VAR: ""}):
            self.assertIsNone(private_list())

    def test_the_list_must_be_named_when_required(self):
        # the gate's author flag: a run that must have the author's lists errors without this one
        for flag in ("1", "yes"):
            with mock.patch.dict(os.environ, {PATTERNS_VAR: "", REQUIRE_VAR: flag}):
                with self.assertRaises(LookupError):
                    private_list()
        for flag in ("", "0"):
            with mock.patch.dict(os.environ, {PATTERNS_VAR: "", REQUIRE_VAR: flag}):
                self.assertIsNone(private_list())
        with tempfile.TemporaryDirectory() as d:
            own = Path(d) / "list.txt"
            own.write_text("label a widget name\nre \\bGizmo\\b\nhit a Gizmo\n")
            with mock.patch.dict(os.environ, {PATTERNS_VAR: str(own), REQUIRE_VAR: "1"}):
                self.assertEqual(private_list().labels, ["a widget name"])

    def test_the_list_format(self):
        # a made-up list on made-up words: what the parser reads, and the guard applying it
        text = ("# a comment\n\nlabel a widget name\nre (?i)\\bwidget-[0-9]+\\b\nre \\bGizmo\\b\n"
                "hit the Widget-7 board\nhit a Gizmo\\nline\npass a gizmo\n")
        lst = PatternList(text)
        self.assertEqual(lst.labels, ["a widget name"])
        self.assertEqual(len(lst.patterns), 2)
        self.assertEqual(lst.hits, [("a widget name", "the Widget-7 board"), ("a widget name", "a Gizmo\nline")])
        self.assertEqual(lst.passes, ["a gizmo"])
        self.assertEqual(line_hits("the WIDGET-12 rack", GENERAL + lst.patterns), [(1, "a widget name")])
        self.assertEqual(line_hits("a gizmo", GENERAL + lst.patterns), [])
        for bad in ("re \\bx\\b\n", "label x\nre (unclosed\n", "label x\nfoo bar\n", "label x\nhit\n"):
            with self.assertRaises(ValueError, msg=bad):
                PatternList(bad)

    def test_a_listed_file_inside_the_tree_is_not_read(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "own-list.txt").write_text("label a widget name\nre \\bGizmo\\b\nhit a Gizmo\n")
            (root / "README.md").write_text("a Gizmo\n")
            with mock.patch.dict(os.environ, {PATTERNS_VAR: str(root / "own-list.txt")}):
                hits = scan(root, ["own-list.txt", "README.md"])
        self.assertEqual(hits, ["README.md:1: a widget name"])

    def test_evidence_is_the_recorded_sets(self):
        self.assertTrue(is_evidence("ch04/audits/x_audit_20261021T020607Z/verdict.txt"))
        self.assertTrue(is_evidence("dev/m2/audits/x_audit_20261020T044237Z/commands.txt"))
        self.assertTrue(is_evidence("ch03/audits/x_drills_20261020T124635Z/DRILLS.md"))
        self.assertFalse(is_evidence("ch03/audits/INDEX.md"), "a lab's index is prose")
        self.assertFalse(is_evidence("ch03/README.md"))
        self.assertFalse(is_evidence("common/audit/judge.py"))

    def test_scan_reports_where_never_what(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "ch09" / "audits" / "x_audit_1").mkdir(parents=True)
            secret = "see " + "notes/" + "plan.md, " + "decision " + "3"
            (root / "ch09" / "README.md").write_text(f"ok\nthe route ({secret})\n")
            (root / "ch09" / "audits" / "INDEX.md").write_text(f"({secret})\n")
            (root / "ch09" / "audits" / "x_audit_1" / "verdict.txt").write_text(f"== routes ({secret})\n")
            files = ["ch09/README.md", "ch09/audits/INDEX.md", "ch09/audits/x_audit_1/verdict.txt"]
            hits = scan(root, files, GENERAL)
            note = "notes/" + "x.md"
            (root / "ch09" / "notes").mkdir()
            (root / "ch09" / note).write_text("ok\n")
            path_hits = scan(root, [f"ch09/{note}"], GENERAL)
        label = "a path into a notes/ directory"
        self.assertEqual(hits, [f"ch09/README.md:2: {label}", f"ch09/audits/INDEX.md:1: {label}"])
        self.assertFalse(any(secret in h for h in hits))
        self.assertEqual(path_hits, [f"ch09/{note}: the path itself is {label}"])


if __name__ == "__main__":
    unittest.main()
