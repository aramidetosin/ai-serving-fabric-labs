"""The recording size policy: evfile.py's compressed form, setsize.py's pack and check, the readers
that accept a compressed file, and the committed sets against the policy (FRAMEWORK.md 4.4).

    python3 -m unittest discover -s common/tests -t common/tests
"""

from __future__ import annotations

import contextlib
import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
sys.path.insert(0, str(COMMON / "audit"))
sys.path.insert(0, str(COMMON / "drill"))

import compare_passes  # noqa: E402
import evfile  # noqa: E402
import judge  # noqa: E402
import panos_parse as PP  # noqa: E402
import redact_tree  # noqa: E402
import setsize  # noqa: E402

KIB, MIB = 1024, 1048576


def counter_xml(rows: int, bump: int = -1) -> bytes:
    """A made-up counter table in the XML API's shape; row bump reads one higher."""
    out = ["<response status=\"success\"><result><global><counters>"]
    for i in range(rows):
        out.append(f"<entry><name>made_up_counter_{i}</name><value>{i + (i == bump)}</value>"
                   f"<rate>0</rate><severity>info</severity></entry>")
    out.append("</counters></global></result></response>")
    return ("\n".join(out) + "\n").encode()


class EvfileTest(unittest.TestCase):
    def test_round_trip_and_same_bytes_every_time(self):
        for data in (b"", b"one line\n", counter_xml(3000), bytes(range(256)) * 50):
            z = evfile.gzip_bytes(data)
            self.assertEqual(gzip.decompress(z), data, "a standard gzip member")
            self.assertEqual(evfile.gunzip_bytes(z), data)
            self.assertEqual(evfile.gzip_bytes(data), z, "no time stamp or name in the header")

    def test_a_small_change_changes_a_few_blocks(self):
        a, b = counter_xml(20000), counter_xml(20000, bump=10000)
        # the last 8 bytes are the CRC and length, which differ; compare the deflate streams
        za, zb = evfile.gzip_bytes(a)[:-8], evfile.gzip_bytes(b)[:-8]
        head = next(i for i, (x, y) in enumerate(zip(za, zb)) if x != y)
        tail = next(i for i, (x, y) in enumerate(zip(reversed(za), reversed(zb))) if x != y)
        self.assertGreater(head + tail, 0.9 * len(za), "the streams resynchronize after the changed line")
        self.assertLess(len(zb), len(b) / 5)

    def test_reads_plain_or_compressed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "counters-before.xml"
            p.write_bytes(b"<plain/>\n")
            self.assertEqual(evfile.read_text(p), "<plain/>\n")
            evfile.compress_file(p)
            self.assertFalse(p.exists())
            self.assertEqual(evfile.resolve(p), str(p) + ".gz")
            self.assertEqual(evfile.read_text(p), "<plain/>\n", "asked for NAME, NAME.gz is read")
            self.assertEqual(evfile.read_text(str(p) + ".gz"), "<plain/>\n")
            with self.assertRaises(FileNotFoundError):
                evfile.read_bytes(Path(d) / "missing.xml")
            (Path(d) / "bad.xml.gz").write_bytes(b"\x1f\x8b\x08\x00 not deflate")
            with self.assertRaises(ValueError):
                evfile.read_bytes(Path(d) / "bad.xml.gz")
            with self.assertRaises(ValueError):
                evfile.gunzip_bytes(gzip.compress(b"x" * 5000), limit=4999)


class ReadersTest(unittest.TestCase):
    """Every reader of a recorded XML or JSON file accepts it stored compressed."""

    def test_panos_parse_read(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "counters-after.xml"
            p.with_name(p.name + ".gz").write_bytes(evfile.gzip_bytes(b"<x>1</x>\n"))
            self.assertEqual(PP.read(p), "<x>1</x>\n")
            self.assertEqual(PP.read(Path(d) / "nothing.xml"), "")

    def test_judge_result_set(self):
        with tempfile.TemporaryDirectory() as d:
            node = Path(d) / "bastion"
            node.mkdir()
            (node / "18_pods.json.gz").write_bytes(evfile.gzip_bytes(b'{"items": [1, 2]}\n'))
            (node / "02_bonding.txt").write_text("Bonding Mode: IEEE 802.3ad\n")
            rs = judge.ResultSet(d)
            self.assertEqual(rs.file("bastion", "pods").name, "18_pods.json.gz")
            self.assertEqual(rs.json("bastion", "pods"), {"items": [1, 2]})
            self.assertEqual(rs.raw("bastion", "pods"), b'{"items": [1, 2]}\n')
            self.assertEqual(rs.body("bastion", "bonding"), "Bonding Mode: IEEE 802.3ad")

    def test_compare_passes_finds_compressed_analyses(self):
        with tempfile.TemporaryDirectory() as d:
            rs = Path(d)
            for n, form in ((1, "plain"), (2, "gz")):
                p = rs / f"pass{n}" / "fw-leg" / "analysis.json"
                p.parent.mkdir(parents=True)
                data = json.dumps({"drill": "fw-leg", "pass": n}).encode()
                if form == "gz":
                    p.with_name("analysis.json.gz").write_bytes(evfile.gzip_bytes(data))
                else:
                    p.write_bytes(data)
            self.assertEqual(sorted(compare_passes.load_set(rs)["fw-leg"]), [1, 2])


class SetsizeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.set = Path(self.tmp.name) / "lab" / "audits" / "x_drills_20261021T000000Z"
        (self.set / "pass1" / "land").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def run_tool(self, *args, env=None):
        out = io.StringIO()
        with unittest.mock.patch.dict(os.environ, env or {}), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            rc = setsize.main(list(args))
        return rc, out.getvalue()

    def test_pack_compresses_by_the_policy(self):
        land = self.set / "pass1" / "land"
        xml = counter_xml(9000)
        self.assertGreater(len(xml), setsize.GZIP_MIN)
        (land / "counters-before.xml").write_bytes(xml)
        (land / "route-before.xml").write_bytes(b"<small/>\n")
        (land / "counters-before.txt").write_bytes(b"flow_x 1 0 drop\n" * 30000)
        (self.set / "commands.txt").write_bytes(b"### t fw panos-cli\n" + b"line [redacted: host-kernel]\n" + b"x\n" * 40000)
        (self.set / "REDACTIONS.md").write_text(redact_tree.ledger_text([("commands.txt", 2, "host-kernel")], when="recorded"))
        (self.set / "captures").mkdir()
        (self.set / "captures" / "eth1.txt").write_bytes(b"12:00 IP a > b\n" * 20000)
        rc, out = self.run_tool("pack", str(self.set), env={"SFAB_TEXT_MAX_MIB": "0.05"})
        self.assertEqual(rc, 0, out)
        self.assertIn("setsize: pass1/land/counters-before.xml stored compressed", out)
        self.assertIn("setsize: commands.txt stored compressed", out)
        self.assertEqual(evfile.read_bytes(land / "counters-before.xml.gz"), xml)
        for kept in ("pass1/land/route-before.xml", "pass1/land/counters-before.txt", "captures/eth1.txt"):
            self.assertTrue((self.set / kept).is_file(), f"{kept}: text and small XML stay plain")
        led = (self.set / "REDACTIONS.md").read_text()
        self.assertIn("| commands.txt.gz | 2 | host-kernel |", led)
        self.assertIn(redact_tree.INTRO["recorded"], led, "the ledger keeps what it said about when")
        rc, out = self.run_tool("pack", str(self.set), env={"SFAB_TEXT_MAX_MIB": "0.05"})
        self.assertEqual((rc, out), (0, ""), "a second pack changes nothing")

    def test_check_reports_each_finding(self):
        (self.set / "pass1" / "land" / "counters-after.xml").write_bytes(counter_xml(9000))
        (self.set / "captures").mkdir()
        (self.set / "captures" / "eth1.txt").write_bytes(b"12:00 IP a > b\n" * 5000)
        place = self.set / "captures" / "place"
        place.mkdir()
        (place / "eth1.txt").write_bytes(b"y" * 300 * KIB)
        (self.set / "captures" / "eth9.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\0" * 300 * KIB)
        (self.set / ".gitignore").write_text("/captures/eth9.pcap\n")
        rc, out = self.run_tool("check", str(self.set), env={"SFAB_TEXT_MAX_MIB": "0.05", "SFAB_SET_MAX_MIB": "1"})
        self.assertEqual(rc, 1, out)
        lines = out.splitlines()
        size = [l for l in lines if l.startswith("SIZE ")][0].split()
        files = setsize.committed(str(self.set))
        self.assertEqual([r for r, _ in files], [".gitignore", "captures/eth1.txt", "pass1/land/counters-after.xml"],
                         "the placement windows and the pcap the gate set aside are not committed")
        self.assertEqual(int(size[1]), sum(n for _, n in files))
        self.assertEqual(int(size[3]), MIB)
        self.assertIn(f"OVER {5000 * 15} captures/eth1.txt", lines)
        self.assertIn(f"PLAIN {len(counter_xml(9000))} pass1/land/counters-after.xml", lines)
        rc, out = self.run_tool("pack", str(self.set))
        rc, out = self.run_tool("check", str(self.set))
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(out.splitlines()), 1, out)

    def test_set_over_the_cap(self):
        (self.set / "a.txt").write_bytes(b"z\n" * 600 * KIB)
        rc, out = self.run_tool("check", str(self.set), env={"SFAB_SET_MAX_MIB": "1"})
        self.assertEqual(rc, 1, out)
        self.assertEqual(out.split()[:2], ["SIZE", str(1200 * KIB)])

    def test_report(self):
        (self.set / "commands.txt").write_bytes(b"### t\n")
        (self.set / "pass1" / "land" / "counters-before.xml.gz").write_bytes(evfile.gzip_bytes(b"<x/>\n"))
        rc, out = self.run_tool("report", "--sets", str(self.set.parent.parent))
        self.assertEqual(rc, 0, out)
        self.assertIn("transcript (commands.txt)", out)
        self.assertIn("counter tables, XML", out)
        self.assertIn("set drills_20261021T000000Z", out)


class CommittedSetsTest(unittest.TestCase):
    """Every committed set meets the policy, except what was recorded before it (named below)."""

    # none: chapter 3's revision 1 drills set (126.7 MiB, recorded before the set cap) left the
    # repository with the revision 2 recording, whose three drill sets each fit the cap
    OVER_SET_CAP: set[str] = set()

    @classmethod
    def setUpClass(cls):
        try:
            p = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True)
        except (OSError, subprocess.CalledProcessError):
            raise unittest.SkipTest("not a git checkout")
        cls.files = [f for f in p.stdout.decode("utf-8", "replace").split("\0") if f and "/audits/" in f]
        cls.sets = {}
        for f in cls.files:
            parts = f.split("/")
            i = parts.index("audits")
            if i + 2 < len(parts):
                cls.sets.setdefault("/".join(parts[:i + 2]), []).append(f)

    def test_no_concatenation_or_placement_window(self):
        bad = [f for f in self.files if f.rsplit("/", 1)[-1] in setsize.CONCATENATIONS or setsize.is_place(f)]
        self.assertEqual(bad, [])

    def test_no_large_plain_file(self):
        cap = setsize.TEXT_CAP_MIB * MIB
        bad = []
        for f in self.files:
            n = os.path.getsize(ROOT / f) if (ROOT / f).is_file() else 0
            if f.endswith(setsize.MACHINE) and n >= setsize.GZIP_MIN:
                bad.append(f"{f}: {n} bytes stored plain")
            elif setsize.is_plain(f) and n > cap:
                bad.append(f"{f}: {n} bytes over the text cap")
        self.assertEqual(bad, [])

    def test_sets_within_the_cap(self):
        cap = setsize.SET_CAP_MIB * MIB
        over = sorted(s for s, fs in self.sets.items()
                      if sum(os.path.getsize(ROOT / f) for f in fs if (ROOT / f).is_file()) > cap)
        self.assertEqual(over, sorted(self.OVER_SET_CAP & set(self.sets)))

    def test_compressed_files_decompress(self):
        for f in self.files:
            if f.endswith(evfile.GZ):
                with self.subTest(f=f):
                    evfile.read_bytes(ROOT / f)


if __name__ == "__main__":
    unittest.main()
