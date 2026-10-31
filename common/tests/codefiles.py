"""The files of the work tree outside the recorded sets, for the tests that read every file of the
code (test_platform.py's product name, test_harness.py's kernel log).

A walk of the whole tree with Path.rglob("*") reads every file name of every recorded set (most
of the tree's 20,000 files) only to set them aside. These tests skip every path with a part of a
given name (audits, .git, __pycache__), so the walk does not go into such a directory and leaves
out such a file (a worktree's .git is a file): the files it gives are the same, and the sets are
never listed. As rglob does, it does not follow a link to a directory, and a link to a file is
given like a file.
"""

from __future__ import annotations

import os
from pathlib import Path


def files(root: Path, skip=(".git", "audits", "__pycache__")) -> list:
    """Every file under root (Paths, sorted) whose path below root has no part named in skip."""
    skip = frozenset(skip)
    out = []
    for d, ds, fs in os.walk(root):
        ds[:] = [x for x in ds if x not in skip]
        out.extend(Path(d) / f for f in fs if f not in skip)
    return sorted(p for p in out if p.is_file())
