#!/usr/bin/env python3
"""namecheck: no private name, host, domain, path, address prefix or credential in the labs repo
(FRAMEWORK.md section 0, names and addresses, and section 4.4).

    namecheck.py [PATH ...]                    scan PATHs (files or directories), or the repo's files
    namecheck.py --mask [PATH ...]             the same, printing each hit without its text
    namecheck.py --allow-add CHUNK --why TEXT  add one chunk to the allow list

What it reads. Each is optional and none is in the repository, but a list that is named, by its
option or its variable, and is not there is an error (exit 2): only the default literals file,
~/.config/sfab/scrub-secrets.txt, may be missing.

- the scrub list, from $SFAB_SCRUB_LIST (or --list): the names, hosts, domains, paths, address
  prefixes and identifier prefixes that must not appear;
- the allow list, from $SFAB_NAMECHECK_ALLOW (or --allow): a salted sha256 of each exact chunk
  that a list entry catches by accident in what a device prints, never the plaintext, each with a
  comment naming where the device prints it; a chunk whose digest is there is not checked;
- credential literals, one per line, from $SFAB_SCRUB_SECRETS (or --secrets), by default
  ~/.config/sfab/scrub-secrets.txt: matched as exact strings and never printed.

Without a scrub list there is nothing to check names with. namecheck then prints "namecheck:
skipped, no scrub list" and exits 3, and the audit and the gate record the check as skipped, not
failed, so an audit run without the list still passes. When the literals file is there it is still
checked, and a literal found is a fail.

The list's format. Entries sit under section headers. Under "# fail: ..." a hit fails, under
"# warn: ..." it prints and does not fail, and a "# rule: ..." section holds no entries. A header
that says "token start" holds identifier prefixes, one that says "address" holds IPv4 prefixes
("A to B" is every prefix of one length from A to B), and one that says "credential" holds none
(those are the literals). Entries are separated by spaces, one with a space in it is quoted, and
text in parentheses is a comment.

How an entry matches. Text is cut into chunks of letters, digits and the separators - . _ / @ ~ :
and a name entry matches a piece of a chunk that starts and ends at a separator or at the
chunk's edge, case folded. For an entry "old-lab", the chunks clab-old-lab-x and OLD-LAB match;
for "corp.test", the domain www.corp.test matches; for "/srv/old", the path /srv/old/x matches;
an entry "ab" never matches inside the word "about". An entry with a space matches two
neighboring chunks. A prefix entry ("ol-") matches only at a token start. An address entry
fails any IPv4 address or prefix inside it. A line that holds terminal escape codes is checked a
second time with the codes taken out. A decision or finding number (D or F and two digits)
prints a warning.

Variants. A fail name entry of 6 or more letters and digits, not counting its hyphens,
underscores, spaces and dots, also fails when its letters and digits are written with any
hyphens, underscores, spaces or tabs between them, or none: "old-lab" as old_lab, old lab or
oldlab, and a domain or host "corp.test" as corp-test, corp_test or corptest (the form Kubernetes
object names and file names give a dotted name). Digits may follow it (oldlab2, old_lab_01),
unless the entry itself ends in a digit. The variant has to start and end on whole words of
letters and digits, so "goldlab" and "oldlabs" do not match. An entry that holds / ~ : or @ (a
path, a MAC prefix, a user at a host) has no variant: its parts are directory names, hex pairs or
a user name, which other text runs together by chance (capture timestamps, version strings).

What it does not match. An address entry is checked only against an address written as four
dotted decimal octets, with or without a prefix length: not one followed by a dot and a number,
as tcpdump prints an address and its port, one with zero-padded octets, one written with hyphens
(as in a host name), one reversed under in-addr.arpa, or one whose last octet is a letter. A name
entry of fewer than 6 letters and digits has no variant, so a short hyphenated entry written with
an underscore, a space or nothing does not match. A path entry matches only with its leading / or
~/, and a MAC prefix only as the list writes it, not with hyphens, in dotted groups of four or
inside an EUI-64 interface identifier. A prefix entry matches only with its own separator after
the stem, not with another separator or a digit in its place. A file that holds a NUL byte is
never read, so no capture is: redact_tree.py --check searches captures for the literals.

--mask prints each hit as path, line, severity and kind, without the text it matched or the entry,
so a saved output never quotes what it found; the audit and the gate save their namecheck output
so, and a saved quote would fail every later audit on the set that saved it.

How it stays fast. A file is read once as bytes. A hit's line holds the entry itself (and first
its longest word as a whole word, which one set lookup over the file's words finds), an address
entry's fixed octets, a literal, or a variant's letters and digits with only hyphens, underscores,
spaces or tabs between them. A file, and then a line, that holds none of these is passed over;
every other line, and every line with an escape code, goes through the full match above, so the
result is the same as matching every line. --jobs scans files in parallel processes and prints in
file order.

Without PATHs it scans every file git tracks or would track (untracked files not ignored),
skipping binary files and files over 20 MiB. A file stored compressed (NAME.gz: a result set keeps
its large evidence so, FRAMEWORK.md 4.4) is scanned decompressed, whatever its size, and its line
numbers are those of the decompressed text; one that does not decompress is reported as a fail.
Exit status: 0 clean (warnings allowed), 1 a hit, 2 a usage error, 3 skipped (no scrub list).
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import shlex
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SECRETS = os.path.join(os.path.expanduser("~"), ".config", "sfab", "scrub-secrets.txt")
SKIPPED = 3

CHUNK = re.compile(r"[A-Za-z0-9_@~./:-]+")
SEP = set("-._/@~:")
ADDR = re.compile(r"(?<![0-9.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?!\.?\d)")
DECISION = re.compile(r"(?<![A-Za-z0-9_-])[DF][0-9]{2}(?![A-Za-z0-9_])")
# terminal escape codes: CSI sequences, OSC strings of printable ASCII, charset and two-byte codes
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][ -~]*?(?:\x07|\x1b\\)|[()][0-9A-Za-z]|[@-Z\\^_])")
WORD = re.compile(r"[A-Za-z0-9]+")
JOIN = re.compile(r"[-_ \t]+")
JOINERS = b"-_ \t"
DIGITS = "0123456789"
VARIANT_MIN = 6
MAX_PARTS = 8
MAX_FILE = 20 * 1024 * 1024
# a compressed file is scanned decompressed, up to this many bytes
MAX_INFLATE = 1 << 30

# bytes.translate table: letters and digits kept (lowercased), every other byte a space
_WORDS = bytes(c + 32 if 65 <= c <= 90 else c if (48 <= c <= 57 or 97 <= c <= 122) else 32 for c in range(256))
_DECISION_WORDS = {f"{p}{n:02d}".encode() for p in "df" for n in range(100)}


# --------------------------------------------------------------------------------------------
# the list


class Entry:
    __slots__ = ("cls", "sev", "value", "shown")

    def __init__(self, cls, sev, value, shown=None):
        self.cls, self.sev, self.value, self.shown = cls, sev, value, shown or value

    def __reduce__(self):
        return Entry, (self.cls, self.sev, self.value, self.shown)


def _class_of(header: str) -> str:
    h = header.lower()
    if "token start" in h:
        return "pre"
    if "address" in h:
        return "net"
    if "credential" in h:
        return "none"
    return "tok"


def parse_list(text: str) -> list:
    out, sev, cls = [], None, None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = re.match(r"^#\s*(fail|warn|rule)\s*:\s*(.*)$", line)
        if m:
            sev = m.group(1)
            cls = "rule" if sev == "rule" else _class_of(m.group(2))
            continue
        if line.startswith("#") or sev in (None, "rule") or cls in ("none", "rule"):
            continue
        line = re.sub(r"\([^)]*\)", " ", line)
        try:
            toks = shlex.split(line)
        except ValueError:
            toks = line.split()
        i = 0
        while i < len(toks):
            t = toks[i]
            if cls == "net":
                if i + 2 < len(toks) and toks[i + 1] == "to":
                    for n in _net_range(t, toks[i + 2]):
                        out.append(Entry("net", sev, n))
                    i += 3
                    continue
                try:
                    out.append(Entry("net", sev, str(ipaddress.ip_network(t, strict=False))))
                except ValueError:
                    pass
            elif cls == "pre":
                out.append(Entry("pre", sev, t.lower()))
            else:
                out.append(Entry("phr" if " " in t else "tok", sev, t.lower()))
            i += 1
    return out


def _net_range(a: str, b: str) -> list:
    na, nb = ipaddress.ip_network(a, strict=False), ipaddress.ip_network(b, strict=False)
    if na.prefixlen != nb.prefixlen:
        return [str(na), str(nb)]
    step = na.num_addresses
    out, cur = [], int(na.network_address)
    while cur <= int(nb.network_address):
        out.append(str(ipaddress.ip_network((cur, na.prefixlen))))
        cur += step
    return out


def read_lines(path: str) -> list:
    """The literals file: one value per line, blank lines and # comments skipped."""
    with open(path, encoding="utf-8") as f:
        return [l.rstrip("\r\n") for l in f if l.strip() and not l.startswith("#")]


# --------------------------------------------------------------------------------------------
# the allow list


def h(salt: str, cls: str, value: str) -> str:
    return hashlib.sha256(f"{salt}\0{cls}\0{value}".encode()).hexdigest()


def read_allow(path):
    """The allow list: {"salt": hex, "set": {digest}}, or None."""
    if not path:
        return None
    salt, have = None, set()
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                p = line.split()
                if not p or p[0].startswith("#"):
                    continue
                if p[0] == "salt" and len(p) > 1:
                    salt = p[1]
                elif p[0] == "allow" and len(p) > 1:
                    have.add(p[1])
    except OSError:
        return None
    return {"salt": salt, "set": have} if salt else None


def add_allow(path: str, chunk: str, why: str) -> str:
    old = read_allow(path)
    new = old is None
    salt = old["salt"] if old else os.urandom(16).hex()
    d = h(salt, "allow", chunk.lower())
    if old and d in old["set"]:
        return d
    with open(path, "a", encoding="utf-8") as f:
        if new:
            f.write("# namecheck allow list: a salted sha256 of each exact chunk that a scrub entry catches by\n")
            f.write("# accident, never the plaintext. Add with: namecheck.py --allow-add CHUNK --why ...\n")
            f.write(f"salt {salt}\n")
        f.write(f"# {why}\n")
        f.write(f"allow {d}\n")
    return d


# --------------------------------------------------------------------------------------------
# candidates


def _bounds(chunk: str):
    starts, ends = {0}, {len(chunk)}
    for i, c in enumerate(chunk):
        if c in SEP:
            starts.update((i, i + 1))
            ends.update((i, i + 1))
    return sorted(s for s in starts if s < len(chunk)), sorted(e for e in ends if e > 0)


def _parts(s: str) -> int:
    return len([p for p in re.split(r"[-._/@~:]+", s) if p])


def pieces(chunk: str):
    """Every piece of a chunk that starts and ends at a boundary, lowercased."""
    c = chunk.lower()
    starts, ends = _bounds(c)
    for s in starts:
        for e in ends:
            if e <= s:
                continue
            piece = c[s:e]
            if _parts(piece) > MAX_PARTS:
                break
            yield piece


def prefixes(chunk: str):
    """Pieces that begin at a token start and end just after a separator (prefix entries)."""
    c = chunk.lower()
    for s in range(len(c)):
        if not (s == 0 or c[s - 1] in SEP) or c[s] in SEP:
            continue
        seen = 0
        for e in range(s + 1, len(c)):
            if c[e] in SEP and c[e - 1] not in SEP:
                seen += 1
                yield c[s:e + 1]
                if seen >= 3:
                    break


def ends_of(chunk: str, n=3):
    c = chunk.lower()
    starts, _ = _bounds(c)
    return [c[s:] for s in starts if _parts(c[s:]) <= n]


def heads_of(chunk: str, n=3):
    c = chunk.lower()
    _, ends = _bounds(c)
    return [c[:e] for e in ends if _parts(c[:e]) <= n]


def _finds(hay: bytes, needle: bytes, step: int = 1):
    i = hay.find(needle)
    while i >= 0:
        yield i
        i = hay.find(needle, i + step)


def _line_indexes(hay: bytes, offsets: list) -> set:
    """The 0-based line of each offset into hay, whose lines end in b"\\n"."""
    out, line, at = set(), 0, 0
    for o in sorted(offsets):
        line += hay.count(b"\n", at, o)
        at = o
        out.add(line)
    return out


# --------------------------------------------------------------------------------------------
# the scanner


# an entry holding one of these has no variant: a path, a MAC prefix or a user at a host
NO_VARIANT = set("/~:@")
VARIANT_DROP = re.compile(r"[-_. \t]+")


def variant_key(value: str):
    """A fail name entry's letters and digits, the key its variants match, or None: the entry is a
    path, a MAC prefix or a user at a host, or has fewer than VARIANT_MIN letters and digits."""
    if NO_VARIANT & set(value):
        return None
    key = VARIANT_DROP.sub("", value)
    return key if len(key) >= VARIANT_MIN and key.isascii() and key.isalnum() else None


class Checker:
    def __init__(self, entries: list, literals: list, allow=None):
        self.allow = allow
        self._allowed_cache = {}
        self.tok = {e.value: e for e in entries if e.cls == "tok"}
        self.phr = {e.value: e for e in entries if e.cls == "phr"}
        self.pre = {e.value: e for e in entries if e.cls == "pre"}
        self.nets = [(ipaddress.ip_network(e.value), e) for e in entries if e.cls == "net"]
        self.literals = [l for l in literals if l]
        # variants: a fail name entry's letters and digits, when there are 6 or more of them
        self.variants = {}
        for e in entries:
            if e.sev == "fail" and e.cls in ("tok", "phr"):
                key = variant_key(e.value)
                if key:
                    self.variants.setdefault(key, e)
        self.vmax = max(map(len, self.variants), default=0)
        # What a line needs to hold before line_hits can find anything in it (the module docstring).
        # A name, prefix or phrase entry is filed under its longest word, which a hit's line holds as
        # a whole word, with the text that line holds verbatim: the entry, or each part of a phrase.
        self.by_word, self.always = {}, []
        self.namewords, self.phrwords = set(), set()
        for e in entries:
            if e.cls in ("tok", "phr", "pre"):
                if not e.value.isascii():
                    continue  # chunks are ASCII, so such an entry never matches
                group = tuple(p.encode() for p in e.value.split(" ") if p) if e.cls == "phr" else (e.value.encode(),)
                ws = WORD.findall(e.value)
                words = self.phrwords if e.cls == "phr" else self.namewords
                if ws and words is not None:
                    key = max(ws, key=len)
                    self.by_word.setdefault(key.encode(), set()).add(group)
                    words.add(key)
                else:
                    # an entry with no letter or digit: every chunk has to be looked at
                    self.always.append(group)
                    if e.cls == "phr":
                        self.phrwords = None
                    else:
                        self.namewords = None
            elif e.cls == "net":
                net = ipaddress.ip_network(e.value)
                if net.version == 4:
                    # an address inside it starts with the prefix's fixed octets, and its second and
                    # third octets sit between dots, so they are whole words
                    k = net.prefixlen // 8
                    octets = str(net.network_address).split(".")[:k]
                    group = ((".".join(octets) + ("." if k < 4 else "")).encode(),)
                    if k >= 2:
                        self.by_word.setdefault(max(octets[1:3], key=len).encode(), set()).add(group)
                    else:
                        self.always.append(group)
        self.always = sorted(set(self.always))
        # the decision-number warning is the list's rule, so it runs only with a list
        self.decisions = bool(entries)
        self.dwords = set(_DECISION_WORDS) if self.decisions else set()
        self.words = set(self.by_word) | self.dwords
        self.literals_b = [l.encode("utf-8") for l in self.literals]
        self.vkeys = [k.encode() for k in self.variants]

    def _allowed(self, chunk: str) -> bool:
        if not self.allow:
            return False
        c = chunk.lower()
        hit = self._allowed_cache.get(c)
        if hit is None:
            hit = self._allowed_cache[c] = h(self.allow["salt"], "allow", c) in self.allow["set"]
        return hit

    def _exact(self, text: str, hits: list) -> list:
        chunks = [(m.group(0), m.start(), m.end()) for m in CHUNK.finditer(text)]
        if self.tok or self.pre or self.phr:
            # a hit's entry has its longest word as a whole word of the chunk: skip the rest
            line_words = {w.lower() for w in WORD.findall(text)}
            if (self.namewords is None or not self.namewords.isdisjoint(line_words)
                    or self.phrwords is None or not self.phrwords.isdisjoint(line_words)):
                self._names(text, chunks, hits)
        if self.nets:
            for m in ADDR.finditer(text):
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    continue
                plen = int(m.group(2)) if m.group(2) else 32
                if plen > 32:
                    continue
                for net, e in self.nets:
                    if ip in net and plen >= net.prefixlen:
                        hits.append((e.sev, "address", f"{m.group(0)} in {e.value}"))
        return chunks

    def _names(self, text: str, chunks: list, hits: list) -> None:
        cw = [{w.lower() for w in WORD.findall(ch)} for ch, _, _ in chunks]
        for (ch, _, _), words in zip(chunks, cw):
            if self.namewords is not None and self.namewords.isdisjoint(words):
                continue
            found = []
            for p in pieces(ch):
                e = self.tok.get(p)
                if e:
                    found.append((e.sev, "name", e.shown))
            if self.pre:
                for p in prefixes(ch):
                    e = self.pre.get(p)
                    if e:
                        found.append((e.sev, "prefix", e.shown))
            if found and not self._allowed(ch):
                hits.extend(found)
        if self.phr:
            for k, ((a, _, ae), (b, bs, _)) in enumerate(zip(chunks, chunks[1:])):
                if not text[ae:bs].isspace():
                    continue
                if self.phrwords is not None and self.phrwords.isdisjoint(cw[k]) and self.phrwords.isdisjoint(cw[k + 1]):
                    continue
                for x in ends_of(a):
                    for y in heads_of(b):
                        e = self.phr.get(f"{x} {y}")
                        if e:
                            hits.append((e.sev, "name", e.shown))

    def _variants(self, text: str, hits: list, chunks: list) -> None:
        ws = [(m.start(), m.end(), m.group(0).lower()) for m in WORD.finditer(text)]
        for i in range(len(ws)):
            acc = ""
            for j in range(i, len(ws)):
                if j > i and not JOIN.fullmatch(text, ws[j - 1][1], ws[j][0]):
                    break
                acc += ws[j][2]
                base = acc.rstrip(DIGITS)
                if len(base) > self.vmax:
                    break
                e = self.variants.get(acc) or (self.variants.get(base) if base != acc else None)
                if not e or ("fail", "name", e.shown) in hits:
                    continue
                s, t = ws[i][0], ws[j][1]
                if any(cs <= s and t <= ce and self._allowed(ch) for ch, cs, ce in chunks):
                    continue
                hits.append(("fail", "name (variant)", e.shown))

    def line_hits(self, line: str) -> list:
        hits = []
        chunks = self._exact(line, hits)
        clean = line
        if "\x1b" in line:
            clean = ANSI.sub("", line)
            if clean != line:
                chunks = self._exact(clean, hits)
        if self.variants:
            self._variants(clean, hits, chunks)
        for lit in self.literals:
            if lit in line or lit in clean:
                hits.append(("fail", "credential literal", "a value from scrub-secrets.txt"))
        m = DECISION.search(line) if self.decisions else None
        if m:
            hits.append(("warn", "a decision or finding number (D or F and two digits)", m.group(0)))
        # one line per distinct hit
        seen, out = set(), []
        for x in hits:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    def scan_data(self, data: bytes) -> list:
        """[(line number, hits)] for the lines of one file's bytes that hold a hit: the same lines,
        hits and order as line_hits over every line of data.decode("utf-8", "replace").splitlines()."""
        low = data.lower()
        found = self.words.intersection(low.translate(_WORDS).split()) if self.words else set()
        groups = {g for w in found for g in self.by_word.get(w, ())}
        groups = [g for g in sorted(groups.union(self.always)) if all(n in low for n in g)]
        dwords = found & self.dwords
        lits = [n for n in self.literals_b if n in data]
        keys = []
        if self.vkeys:
            nv = low.translate(None, JOINERS)
            keys = [k for k in self.vkeys if k in nv]
        esc = b"\x1b" in data
        if not (groups or dwords or lits or keys or esc):
            return []
        lines = data.decode("utf-8", "replace").splitlines()
        joined = "\n".join(lines).encode("utf-8")
        jlow = joined.lower()
        idx = set()
        for g in groups:
            idx |= set.intersection(*(_line_indexes(jlow, list(_finds(jlow, n))) for n in g))
        offs = []
        if dwords:
            padded = b" " + joined.translate(_WORDS) + b" "
            for w in dwords:
                offs.extend(_finds(padded, b" " + w + b" ", len(w) + 1))
        for n in lits:
            offs.extend(_finds(joined, n))
        if esc:
            offs.extend(_finds(joined, b"\x1b"))
        idx |= _line_indexes(jlow, offs)
        if keys:
            nv = jlow.translate(None, JOINERS)
            idx |= _line_indexes(nv, [o for k in keys for o in _finds(nv, k)])
        out = []
        for i in sorted(idx):
            hits = self.line_hits(lines[i])
            if hits:
                out.append((i + 1, hits))
        return out


def repo_files() -> list:
    try:
        p = subprocess.run(["git", "-C", ROOT, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                           capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        out = []
        for d, ds, fs in os.walk(ROOT):
            ds[:] = [x for x in ds if x not in (".git", "state") and not x.startswith("clab-")]
            out.extend(os.path.relpath(os.path.join(d, f), ROOT) for f in fs)
        return sorted(out)
    return sorted({f for f in p.stdout.decode("utf-8", "replace").split("\0") if f and os.path.isfile(os.path.join(ROOT, f))})


def walk(paths: list) -> list:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for d, ds, fs in os.walk(p):
                ds[:] = [x for x in ds if x != ".git"]
                out.extend(os.path.join(d, f) for f in fs)
        elif os.path.isfile(p):
            out.append(p)
    return sorted(out)


_CHECKER = None


def _init_worker(checker: Checker) -> None:
    global _CHECKER
    _CHECKER = checker


def _gunzip(data: bytes):
    """The bytes a gzip file holds, or None when it does not decompress within MAX_INFLATE."""
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data, MAX_INFLATE + 1)
    except zlib.error:
        return None
    return None if len(out) > MAX_INFLATE or d.unconsumed_tail or not d.eof else out


def _scan_file(full: str):
    """(read as text, [(line number, hits)]) for one file; a .gz file is read decompressed."""
    try:
        if full.endswith(".gz"):
            with open(full, "rb") as f:
                data = _gunzip(f.read())
            if data is None:
                return True, [(1, [("fail", "compressed file that does not decompress", "")])]
        else:
            if os.path.getsize(full) > MAX_FILE:
                return False, []
            with open(full, "rb") as f:
                data = f.read()
    except OSError:
        return False, []
    if b"\0" in data:
        return False, []
    return True, _CHECKER.scan_data(data)


def scan(checker: Checker, files: list, base: str, mask: bool = False, jobs: int = 1, skip=()) -> tuple:
    skip = {os.path.abspath(p) for p in skip if p}
    fulls = [f if os.path.isabs(f) else os.path.join(base, f) for f in files]
    fulls = [f for f in fulls if os.path.abspath(f) not in skip]
    _init_worker(checker)
    if jobs > 1 and len(fulls) > 64:
        import multiprocessing
        pool = multiprocessing.Pool(jobs, initializer=_init_worker, initargs=(checker,))
        results = pool.imap(_scan_file, fulls, chunksize=16)
    else:
        pool, results = None, map(_scan_file, fulls)
    fails = warns = nfiles = 0
    try:
        for full, (text, found) in zip(fulls, results):
            nfiles += text
            rel = os.path.relpath(full, ROOT) if full.startswith(ROOT + os.sep) else full
            for no, hits in found:
                for sev, what, shown in hits:
                    print(f"{rel}:{no}: {sev} {what}" + ("" if mask else f": {shown}"))
                    if sev == "fail":
                        fails += 1
                    else:
                        warns += 1
    finally:
        if pool:
            pool.close()
            pool.join()
    return nfiles, fails, warns


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="namecheck", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--list", default=os.environ.get("SFAB_SCRUB_LIST") or None,
                    help="the scrub list (default $SFAB_SCRUB_LIST; none: names are not checked)")
    ap.add_argument("--allow", default=os.environ.get("SFAB_NAMECHECK_ALLOW") or None,
                    help="the allow list (default $SFAB_NAMECHECK_ALLOW); named and missing is an error")
    ap.add_argument("--secrets", default=os.environ.get("SFAB_SCRUB_SECRETS") or None,
                    help="credential literals (default $SFAB_SCRUB_SECRETS, else ~/.config/sfab/scrub-secrets.txt, "
                         "which alone may be missing)")
    ap.add_argument("--allow-add", metavar="CHUNK")
    ap.add_argument("--why")
    ap.add_argument("--mask", action="store_true", help="print each hit without the text it matched")
    ap.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1),
                    help="parallel processes (default: the CPUs, at most 8)")
    a = ap.parse_args(argv)

    if a.allow_add:
        if not a.allow:
            print("namecheck: --allow-add needs an allow list: set SFAB_NAMECHECK_ALLOW or pass --allow", file=sys.stderr)
            return 2
        if not a.why:
            print("namecheck: --allow-add needs --why, naming where the device prints it", file=sys.stderr)
            return 2
        d = add_allow(a.allow, a.allow_add, a.why)
        print(f"namecheck: allowed one chunk (digest {d[:12]})")
        return 0

    entries = []
    if a.list:
        try:
            with open(a.list, encoding="utf-8") as f:
                entries = parse_list(f.read())
        except OSError as e:
            print(f"namecheck: cannot read the scrub list: {e.strerror}", file=sys.stderr)
            return 2
    # a list named by its option or variable must be there: a mistyped path must not turn a check
    # off. The path is not printed: an audit saves this output, and the path is the author's own.
    for what, src, path in (("allow list", "--allow or $SFAB_NAMECHECK_ALLOW", a.allow),
                            ("credential literals file", "--secrets or $SFAB_SCRUB_SECRETS", a.secrets)):
        if path and not os.path.isfile(path):
            print(f"namecheck: the {what} that {src} names does not exist", file=sys.stderr)
            return 2
    if a.secrets is None:
        a.secrets = SECRETS
    try:
        literals = read_lines(a.secrets) if os.path.isfile(a.secrets) else []
    except OSError as e:
        print(f"namecheck: cannot read the credential literals file: {e.strerror}", file=sys.stderr)
        return 2
    allow = read_allow(a.allow)

    if not entries and not literals:
        print("namecheck: skipped, no scrub list (set SFAB_SCRUB_LIST to check names)")
        return SKIPPED
    checker = Checker(entries, literals, allow)
    if a.paths:
        files, base = walk(a.paths), os.getcwd()
    else:
        files, base = repo_files(), ROOT
    n, fails, warns = scan(checker, files, base, a.mask, max(1, a.jobs), skip=(a.list, a.allow, a.secrets))
    if not entries:
        if fails:
            print(f"namecheck: {n} files, {fails} fail (local secrets only; no scrub list)")
            return 1
        print(f"namecheck: skipped, no scrub list ({n} files checked for local secrets only, 0 fail)")
        return SKIPPED
    src = ", ".join(x for x in ("scrub list", "allow list" if allow else "", "local secrets" if literals else "") if x)
    print(f"namecheck: {n} files, {fails} fail, {warns} warn ({src})")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
