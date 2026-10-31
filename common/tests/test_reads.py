"""The read stages of chapters 5 and 6 (ch05/rpf.sh with common/reads/rpf.sh, ch06/attach.sh with
common/reads/attach.sh): the stages are wired in, each picks its flow or pod from the committed
render, and the readers parse what the guest and kubectl print. The fixtures are made up in the
shape the tools print. Run from the repo root:

    python3 -m unittest discover -s common/tests -t common/tests -p 'test_reads.py'
"""

from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
READS = ROOT / "common" / "reads"

SYSCTL = """admin@k8s-gpu2:~$ sudo ip netns exec gpu2 sysctl net.ipv4.conf.all.rp_filter
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.rail2.rp_filter = 0
net.ipv4.conf.relay.rp_filter = 2
"""


def bash(script: str) -> str:
    pre = "set -euo pipefail; py() { PYTHONDONTWRITEBYTECODE=1 python3 \"$@\"; }; "
    return subprocess.run(["bash", "-c", pre + script], capture_output=True, text=True, check=True).stdout


class Wiring(unittest.TestCase):
    def test_stages_are_wired(self):
        run = (ROOT / "common" / "stages" / "run.sh").read_text()
        mk = (ROOT / "common" / "mk" / "chapter.mk").read_text()
        lib = (ROOT / "common" / "lib.sh").read_text()
        disp = re.search(r"\n    (audit\|trace\|[\w|]+)\)\n", run).group(1).split("|")
        target = re.search(r"\nlabel matrix ([\w ]+):\n", mk).group(1).split()
        rec = re.search(r"\n    (audit\|trace\|[\w|*-]+)\) \[ -n \"\$record\" \]", lib).group(1).split("|")
        scratch = re.search(r"\n      (audit\|collect\|[\w|]+)\) rs_open", lib).group(1).split("|")
        for st, lab in (("rpf", "ch05"), ("attach", "ch06")):
            with self.subTest(stage=st):
                self.assertTrue((ROOT / lab / f"{st}.sh").stat().st_mode & 0o111)
                for where in (disp, target, rec, scratch):
                    self.assertIn(st, where)


class Rpf(unittest.TestCase):
    def test_pick_reads_the_cross_rail_flow(self):
        out = bash(f"RENDERDIR={ROOT / 'ch05'}; . {READS / 'rpf.sh'}; rpf_pick; "
                   'echo "$RPF_SRC $RPF_SRC_NS $RPF_SRC_ADDR $RPF_DST $RPF_DST_ADDR $RPF_NS $RPF_RAIL_IF $RPF_RELAY_IF $RPF_FROM_RAIL $RPF_TO_RAIL"')
        self.assertEqual(out.split(), ["k8s-gpu1", "gpu1", "10.21.1.11", "k8s-gpu2", "10.21.2.12", "gpu2", "rail2", "relay", "1", "2"])

    def test_value_reader(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "case-b").mkdir()
            (Path(d) / "case-b" / "2-values.txt").write_text(SYSCTL)
            got = bash(f"RS={d}; . {READS / 'rpf.sh'}; for k in all default rail2 relay nope; do "
                       'echo "$k=$(rpf_value case-b/2-values net.ipv4.conf.$k.rp_filter)"; done')
        self.assertEqual(got.split(), ["all=1", "default=2", "rail2=0", "relay=2", "nope="])


class Attach(unittest.TestCase):
    def test_pick_reads_the_table_and_the_switch(self):
        out = bash(f"RENDERDIR={ROOT / 'ch06'}; INV={ROOT / 'ch06' / 'gen' / 'inventory.json'}; . {READS / 'attach.sh'}; attach_pick; "
                   'echo "$ATT_NS $ATT_NODE $ATT_RAIL $ATT_NAD $ATT_ADDR $ATT_MAC $ATT_SW $ATT_VLAN"; echo "$ATT_RAIL_PODS"')
        lines = out.splitlines()
        self.assertEqual(lines[0].split(), ["serving", "k8s-gpu1", "7", "rail7", "10.21.7.100", "02:5a:fe:07:00:64", "rail-sw1", "107"])
        # the spanning copy c: its server and its worker on the other node cross rail-sw1, the worker
        # beside the server talks to it inside k8s-gpu1
        self.assertEqual([x.split() for x in lines[1:]],
                         [["chat-c-server-0", "k8s-gpu1", "02:5a:fe:07:00:64", "Ethernet3", "1"],
                          ["chat-c-worker0-0", "k8s-gpu2", "02:5a:fe:07:00:65", "Ethernet7", "1"],
                          ["chat-c-worker1-0", "k8s-gpu1", "02:5a:fe:07:00:66", "Ethernet3", "0"]])

    def test_prompt_quotes_what_the_shell_needs(self):
        out = bash(f". {READS / 'attach.sh'}; attach_words -n serving get pod x -o 'jsonpath={{.status.podIP}}' getent hosts a.b")
        self.assertEqual(out, "-n serving get pod x -o 'jsonpath={.status.podIP}' getent hosts a.b")


if __name__ == "__main__":
    unittest.main()
