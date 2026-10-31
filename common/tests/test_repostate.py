"""Tests for common/bin/repostate.py and the labs commit lib.sh writes into RUN.json (FRAMEWORK.md
4.4): from git, from the environment, from the stamp a copy without .git carries, or not known.

    python3 -m unittest discover -s common/tests -t common/tests -p test_repostate.py
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "common"
sys.path.insert(0, str(COMMON / "bin"))

import repostate  # noqa: E402

NO_REPO_ENV = {k: v for k, v in os.environ.items() if k not in ("SFAB_REPO_COMMIT", "SFAB_REPO_DIRTY")}


def git(root: Path, *args: str) -> str:
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True, env=env).stdout


def copy_without_git(src: Path, dst: Path) -> None:
    """A copy of the checkout as a sync that leaves .git out makes it."""
    shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(".git"))


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class RepoStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name).resolve()
        self.repo = self.t / "labs"
        (self.repo / "common").mkdir(parents=True)
        (self.repo / "ch09" / "audits" / "sfab-ch09_audit_1").mkdir(parents=True)
        (self.repo / "common" / "lib.sh").write_text("echo lib\n")
        (self.repo / "ch09" / "README.md").write_text("ch09\n")
        (self.repo / "ch09" / "audits" / "INDEX.md").write_text("index\n")
        (self.repo / "ch09" / "audits" / "sfab-ch09_audit_1" / "RESULT.txt").write_text("== RESULT: 1 passed\n")
        (self.repo / ".gitignore").write_text("**/state/\n/.repo-stamp.json\n/.repo-stamp.json.tmp\n")
        git(self.repo, "init", "-q")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "first")
        self.head = git(self.repo, "rev-parse", "HEAD").strip()

    def tearDown(self):
        self.tmp.cleanup()

    def show(self, root: Path, **env) -> dict:
        return repostate.state(root, {**NO_REPO_ENV, **env})

    # -- git -------------------------------------------------------------------------------

    def test_git_clean(self):
        self.assertEqual(self.show(self.repo), {"commit": self.head, "dirty": False, "source": "git"})

    def test_git_ignores_the_recorded_sets_and_ignored_files(self):
        (self.repo / "ch09" / "audits" / "sfab-ch09_audit_2").mkdir()
        (self.repo / "ch09" / "audits" / "sfab-ch09_audit_2" / "RUN.json").write_text("{}\n")
        (self.repo / "ch09" / "audits" / "INDEX.md").write_text("index, edited\n")
        (self.repo / "ch09" / "audits" / "sfab-ch09_audit_1" / "RESULT.txt").write_text("redacted\n")
        (self.repo / "ch10" / "audits" / "sfab-ch10_audit_1").mkdir(parents=True)
        (self.repo / "ch10" / "audits" / "sfab-ch10_audit_1" / "RUN.json").write_text("{}\n")
        (self.repo / "ch09" / "state").mkdir()
        (self.repo / "ch09" / "state" / "secrets.env").write_text("X=1\n")
        self.assertFalse(self.show(self.repo)["dirty"])

    def test_git_dirty_on_a_change_outside_the_sets(self):
        (self.repo / "common" / "lib.sh").write_text("echo changed\n")
        self.assertTrue(self.show(self.repo)["dirty"])
        git(self.repo, "checkout", "--", "common/lib.sh")
        (self.repo / "ch10").mkdir()
        (self.repo / "ch10" / "run.sh").write_text("new\n")
        self.assertTrue(self.show(self.repo)["dirty"], "an untracked file outside the sets is a change")
        (self.repo / "ch10" / "run.sh").unlink()
        (self.repo / "ch09" / "README.md").unlink()
        self.assertTrue(self.show(self.repo)["dirty"], "a deleted file is a change")

    def test_git_wins_over_the_environment_and_a_stamp(self):
        (self.repo / ".repo-stamp.json").write_text(json.dumps({"commit": "0" * 40, "dirty": True, "files": {}}))
        self.assertEqual(self.show(self.repo, SFAB_REPO_COMMIT="1" * 40, SFAB_REPO_DIRTY="1"),
                         {"commit": self.head, "dirty": False, "source": "git"})

    def test_a_directory_inside_another_repository_has_no_git_state(self):
        inner = self.repo / "ch09"
        self.assertIsNone(repostate.git_state(inner))
        self.assertEqual(self.show(inner), {"commit": "none", "dirty": None, "source": None})

    # -- the environment ---------------------------------------------------------------------

    def test_environment(self):
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        self.assertEqual(self.show(copy, SFAB_REPO_COMMIT=self.head, SFAB_REPO_DIRTY="0"),
                         {"commit": self.head, "dirty": False, "source": "environment"})
        self.assertTrue(self.show(copy, SFAB_REPO_COMMIT=self.head, SFAB_REPO_DIRTY="true")["dirty"])
        self.assertIsNone(self.show(copy, SFAB_REPO_COMMIT=self.head)["dirty"], "no flag exported: not known")
        self.assertIsNone(self.show(copy, SFAB_REPO_COMMIT=self.head, SFAB_REPO_DIRTY="maybe")["dirty"])

    # -- the stamp ---------------------------------------------------------------------------

    def stamp(self) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(COMMON / "bin" / "repostate.py"), "stamp", str(self.repo)],
                              capture_output=True, text=True, timeout=120)

    def test_stamp_and_copy(self):
        r = self.stamp()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"stamped {self.head} (dirty: false), 3 files", r.stdout)
        data = json.loads((self.repo / ".repo-stamp.json").read_text())
        self.assertEqual(sorted(data["files"]), [".gitignore", "ch09/README.md", "common/lib.sh"],
                         "the recorded sets and the stamp itself are not listed")
        self.assertFalse(self.show(self.repo)["dirty"], "git ignores the stamp")
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        self.assertEqual(self.show(copy), {"commit": self.head, "dirty": False, "source": "stamp"})
        (copy / "ch09" / "audits" / "sfab-ch09_audit_2").mkdir()
        (copy / "ch09" / "audits" / "sfab-ch09_audit_2" / "RUN.json").write_text("{}\n")
        self.assertFalse(self.show(copy)["dirty"], "a new set in the copy changes nothing")
        self.assertEqual(self.show(copy, SFAB_REPO_COMMIT="1" * 40)["source"], "environment",
                         "an exported commit wins over the stamp")

    def test_stamp_sees_a_changed_or_missing_file(self):
        self.assertEqual(self.stamp().returncode, 0)
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        (copy / "common" / "lib.sh").write_text("echo edited after the copy\n")
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.show(copy), {"commit": self.head, "dirty": True, "source": "stamp"})
        self.assertIn("1 of 3 files differ from the stamp", err.getvalue())
        shutil.rmtree(copy)
        copy_without_git(self.repo, copy)
        (copy / "ch09" / "README.md").unlink()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(self.show(copy)["dirty"])

    def test_stamp_sees_a_file_added_after_it(self):
        # a stale stamp: a later commit only adds a file, and the copy is made without stamping again
        self.assertEqual(self.stamp().returncode, 0)
        (self.repo / "ch10").mkdir()
        (self.repo / "ch10" / "new.sh").write_text("new\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "add")
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(self.show(copy), {"commit": self.head, "dirty": True, "source": "stamp"})
        self.assertIn("1 files outside the recorded sets are not in the stamp", err.getvalue())
        # files the repository ignores and a new recorded set are no additions
        self.assertEqual(self.stamp().returncode, 0)
        shutil.rmtree(copy)
        copy_without_git(self.repo, copy)
        (copy / "ch10" / "state").mkdir()
        (copy / "ch10" / "state" / "disk.img").write_text("x\n")
        (copy / "ch09" / "audits" / "sfab-ch09_audit_2").mkdir()
        (copy / "ch09" / "audits" / "sfab-ch09_audit_2" / "RUN.json").write_text("{}\n")
        self.assertEqual(self.show(copy)["dirty"], False)

    def test_stamp_without_git_cannot_say_clean(self):
        self.assertEqual(self.stamp().returncode, 0)
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        err = io.StringIO()
        with unittest.mock.patch.object(repostate, "unlisted_files", return_value=None), contextlib.redirect_stderr(err):
            self.assertEqual(self.show(copy), {"commit": self.head, "dirty": None, "source": "stamp"})
            (copy / "common" / "lib.sh").write_text("edited\n")
            self.assertTrue(self.show(copy)["dirty"], "a listed file that differs still says dirty")
        self.assertIn("cannot be looked for", err.getvalue())

    def test_stamp_hashes_a_link_as_a_link(self):
        (self.repo / "common" / "lib-link.sh").symlink_to("lib.sh")
        git(self.repo, "add", "common/lib-link.sh")
        git(self.repo, "commit", "-qm", "link")
        head = git(self.repo, "rev-parse", "HEAD").strip()
        self.assertEqual(self.stamp().returncode, 0)
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        self.assertEqual(self.show(copy), {"commit": head, "dirty": False, "source": "stamp"})
        (copy / "common" / "lib-link.sh").unlink()
        (copy / "common" / "lib-link.sh").symlink_to("../ch09/README.md")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(self.show(copy)["dirty"])

    def test_stamp_of_a_dirty_tree_says_dirty(self):
        (self.repo / "common" / "new.sh").write_text("new\n")
        self.assertEqual(self.stamp().returncode, 0)
        data = json.loads((self.repo / ".repo-stamp.json").read_text())
        self.assertTrue(data["dirty"])
        self.assertIn("common/new.sh", data["files"], "an untracked file is copied too, so it is stamped")
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        self.assertEqual(self.show(copy), {"commit": self.head, "dirty": True, "source": "stamp"})

    def test_a_broken_stamp_is_no_stamp(self):
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        for text in ("{", "[]", json.dumps({"dirty": False, "files": {}}), json.dumps({"commit": "x", "files": []})):
            (copy / ".repo-stamp.json").write_text(text)
            self.assertEqual(self.show(copy), {"commit": "none", "dirty": None, "source": None}, text)

    def test_stamp_refuses_outside_git(self):
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        r = subprocess.run([sys.executable, str(COMMON / "bin" / "repostate.py"), "stamp", str(copy)],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not the top of a git checkout", r.stderr)
        self.assertFalse((copy / ".repo-stamp.json").exists())

    def test_nothing_known(self):
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        self.assertEqual(self.show(copy), {"commit": "none", "dirty": None, "source": None})


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class RunJsonTest(unittest.TestCase):
    """lib.sh's _run_json in a small copy of the repository: lib.sh and the tools it calls."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.t = Path(self.tmp.name).resolve()
        self.repo = self.t / "labs"
        (self.repo / "common" / "bin").mkdir(parents=True)
        shutil.copy(COMMON / "lib.sh", self.repo / "common" / "lib.sh")
        for f in ("repostate.py", "tick.py"):
            shutil.copy(COMMON / "bin" / f, self.repo / "common" / "bin" / f)
        (self.repo / ".gitignore").write_text("**/state/\n__pycache__/\n/.repo-stamp.json\n/.repo-stamp.json.tmp\n")
        self.lab = self.repo / "ch09"
        (self.lab / "audits").mkdir(parents=True)
        (self.lab / "README.md").write_text("ch09\n")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self) -> str:
        git(self.repo, "init", "-q")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-qm", "first")
        return git(self.repo, "rev-parse", "HEAD").strip()

    def run_json(self, root: Path, between: str = "", **env) -> dict:
        """Open a set under ch09/audits the way rs_open does, write RUN.json, then write it again
        after the shell command BETWEEN, as rs_close does; return the second."""
        rs = root / "ch09" / "audits" / "sfab-ch09_audit_20261021T000000Z"
        script = ('. "$1/common/lib.sh"; RS="$2"; mkdir -p "$RS"; RENDERDIR="$3"; STATEDIR="$3/state"; '
                  'LAB=sfab-ch09; SFAB_CATEGORY=audit; RS_START=2026-10-21T00:00:00Z; RS_REPO=""; _run_json; '
                  f'{between or ":"}; RS_END=2026-10-21T00:00:09Z; _run_json')
        r = subprocess.run(["bash", "-c", script, "test", str(root), str(rs), str(root / "ch09")],
                           env={**NO_REPO_ENV, "PYTHONDONTWRITEBYTECODE": "1", **env},
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return json.loads((rs / "RUN.json").read_text())

    def test_a_git_clone_records_its_commit_and_its_own_set_is_no_change(self):
        head = self.commit()
        run = self.run_json(self.repo)
        self.assertEqual(run["labs_repo"], {"commit": head, "dirty": False, "source": "git"})
        self.assertEqual(run["utc_end"], "2026-10-21T00:00:09Z")

    def test_the_commit_is_read_when_the_set_opens(self):
        head = self.commit()
        run = self.run_json(self.repo, between='echo changed >"$1/ch09/README.md"')
        self.assertEqual(run["labs_repo"], {"commit": head, "dirty": False, "source": "git"})
        self.assertTrue(self.run_json(self.repo)["labs_repo"]["dirty"], "the next set reads it again")

    def test_a_copy_without_git(self):
        head = self.commit()
        copy = self.t / "copy"
        copy_without_git(self.repo, copy)
        self.assertEqual(self.run_json(copy)["labs_repo"], {"commit": "none", "dirty": None, "source": None})
        self.assertEqual(self.run_json(copy, SFAB_REPO_COMMIT=head, SFAB_REPO_DIRTY="0")["labs_repo"],
                         {"commit": head, "dirty": False, "source": "environment"})
        r = subprocess.run([sys.executable, str(self.repo / "common" / "bin" / "repostate.py"), "stamp"],
                           capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stderr)
        shutil.rmtree(copy)
        copy_without_git(self.repo, copy)
        self.assertEqual(self.run_json(copy)["labs_repo"], {"commit": head, "dirty": False, "source": "stamp"})


class HeaderTest(unittest.TestCase):
    """The drill pages common/ writes print the labs commit, and say when the tree had uncommitted
    changes (dirty true); false and null print nothing more."""

    def setUp(self):
        self.rs = Path(tempfile.mkdtemp(prefix="sfab-test-header-"))
        self.addCleanup(shutil.rmtree, self.rs, True)

    def page(self, argv, dirty) -> str:
        commit = "a" * 40
        (self.rs / "RUN.json").write_text(json.dumps({"lab": "sfab-ch09", "labs_repo": {"commit": commit, "dirty": dirty, "source": "git"},
                                                      "utc_start": "2026-10-21T00:00:00Z", "host_tick": 10000}))
        r = subprocess.run([sys.executable, *argv, "--set", str(self.rs)], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return (self.rs / "DRILLS.md").read_text()

    def test_drill_pages(self):
        for argv in ([str(COMMON / "drill" / "summarize.py")], [str(COMMON / "drill" / "fwdrill.py"), "summarize"],
                     [str(COMMON / "drill" / "raildrill.py"), "summarize"]):
            for dirty, note in ((True, " (with uncommitted changes)"), (False, ""), (None, "")):
                with self.subTest(tool=Path(argv[0]).name, dirty=dirty):
                    self.assertIn(f"; labs repo commit `{'a' * 40}`{note}; UTC 2026-10-21T00:00:00Z;", self.page(argv, dirty))


class MakeWiringTest(unittest.TestCase):
    """common/mk/chapter.mk passes an exported commit to the transient unit of make up BG=1."""

    def make_up(self, **env) -> str:
        # the commit comes in exported, as FRAMEWORK.md 4.4 has it, never as a make argument
        mk = shutil.which("make")
        if not mk:
            self.skipTest("make is not installed")
        r = subprocess.run([mk, "-s", "-n", "-C", str(ROOT / "dev" / "m1"), "up", "BG=1"],
                           capture_output=True, text=True, timeout=120, env={**NO_REPO_ENV, **env})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout

    def test_bg_passes_the_exported_commit(self):
        out = self.make_up(SFAB_REPO_COMMIT="a" * 40, SFAB_REPO_DIRTY="0")
        self.assertIn(f"--setenv=SFAB_REPO_COMMIT={'a' * 40} --setenv=SFAB_REPO_DIRTY=0", out)
        self.assertNotIn("SFAB_REPO_", self.make_up())


if __name__ == "__main__":
    unittest.main()
