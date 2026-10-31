"""Chapter 3's database reads (ch03/dbs.sh, common/sonic/dbs.sh): the stage is wired in, and the
field reader parses SONiC 4.6.0's hgetall output, alternating field and value lines with an
ASIC_DB key line first. The fixtures are made up in the recorded shape. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_dbs.py'
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DBS = ROOT / "common" / "sonic" / "dbs.sh"

READ = """admin@fe-sw1:~$ for k in ...; done
ASIC_STATE:SAI_OBJECT_TYPE_LAG_MEMBER:oid:0x1b0000000000aa
SAI_LAG_MEMBER_ATTR_LAG_ID
oid:0x20000000000bb
SAI_LAG_MEMBER_ATTR_PORT_ID
oid:0x10000000000cc
"""


def field(rs: Path, name: str, f: str) -> str:
    script = f'set -euo pipefail; RS={rs}; . {DBS}; dbs_field {name} {f}'
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout.strip()


class Dbs(unittest.TestCase):
    def test_stage_is_wired(self):
        self.assertTrue((ROOT / "ch03" / "dbs.sh").stat().st_mode & 0o111)
        run = (ROOT / "common" / "stages" / "run.sh").read_text()
        self.assertRegex(run, r"\n    audit\|trace\|label\|matrix\|(?:\w+\|)*dbs[|)]")
        self.assertRegex((ROOT / "common" / "mk" / "chapter.mk").read_text(), r"\nlabel matrix dbs[ :]")

    def test_field_reader_skips_the_key_line(self):
        with tempfile.TemporaryDirectory() as d:
            rs = Path(d)
            (rs / "asic").mkdir()
            (rs / "asic" / "2-lag-member.txt").write_text(READ)
            self.assertEqual(field(rs, "asic/2-lag-member", "SAI_LAG_MEMBER_ATTR_LAG_ID"), "oid:0x20000000000bb")
            self.assertEqual(field(rs, "asic/2-lag-member", "SAI_LAG_MEMBER_ATTR_PORT_ID"), "oid:0x10000000000cc")
            self.assertEqual(field(rs, "asic/2-lag-member", "NO_SUCH_FIELD"), "")

    def test_vlan_member_found_by_bridge_port_and_vlan(self):
        # a bridge port in two VLANs (access 100, tagged 120) has two VLAN members; the one the
        # chain follows is the one in the access VLAN, whichever the keys list first
        db = {"oid:0x27000000000001": {"SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID": "oid:0x3a000000000001",
                                       "SAI_VLAN_MEMBER_ATTR_VLAN_ID": "oid:0x26000000000120",
                                       "SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE": "SAI_VLAN_TAGGING_MODE_TAGGED"},
              "oid:0x27000000000002": {"SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID": "oid:0x3a000000000001",
                                       "SAI_VLAN_MEMBER_ATTR_VLAN_ID": "oid:0x26000000000100",
                                       "SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE": "SAI_VLAN_TAGGING_MODE_UNTAGGED"}}
        with tempfile.TemporaryDirectory() as d:
            rs, bin_ = Path(d) / "rs", Path(d) / "bin"
            rs.mkdir(); bin_.mkdir()
            lines = ["#!/usr/bin/env python3", "import sys", f"db = {db!r}",
                     "a = sys.argv[2:]",
                     "if a[0] == 'keys': print('\\n'.join('ASIC_STATE:SAI_OBJECT_TYPE_VLAN_MEMBER:' + k for k in db))",
                     "else:",
                     "    o = db[a[1].split(':', 2)[2]]",
                     "    print(o[a[2]] if a[0] == 'hget' else '\\n'.join(x for kv in o.items() for x in kv))"]
            cli = bin_ / "sonic-db-cli"
            cli.write_text("\n".join(lines) + "\n")
            cli.chmod(0o755)
            script = (f'set -euo pipefail; export PATH={bin_}:$PATH; RS={rs}; CRED_USER=admin; DBS_SWITCH=fe-sw1; '
                      f'. {DBS}; SH() {{ bash -c "$2"; }}; '
                      'dbs_find asic 7-vlan-member SAI_OBJECT_TYPE_VLAN_MEMBER SAI_VLAN_MEMBER_ATTR_BRIDGE_PORT_ID '
                      'oid:0x3a000000000001 SAI_VLAN_MEMBER_ATTR_VLAN_ID oid:0x26000000000100')
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "oid:0x27000000000002")
            self.assertEqual(field(rs, "asic/7-vlan-member", "SAI_VLAN_MEMBER_ATTR_VLAN_TAGGING_MODE"),
                             "SAI_VLAN_TAGGING_MODE_UNTAGGED")


if __name__ == "__main__":
    unittest.main()
