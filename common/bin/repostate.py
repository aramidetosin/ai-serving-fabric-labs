#!/usr/bin/env python3
"""repostate: which commit of this repository a run used, for RUN.json (FRAMEWORK.md 4.4).

    repostate.py show  [ROOT]   print the commit, the dirty flag and their source as one JSON line
    repostate.py stamp [ROOT]   in a git checkout, write ROOT/.repo-stamp.json for a copy without .git

ROOT is the repository's top directory; it defaults to the one this file is in.

`show` takes the first source that applies:

    git          ROOT is the top of a git work tree of its own. commit is HEAD; dirty is true when a
                 file outside the recorded sets (every audits/ directory) differs from HEAD, or is
                 untracked and not ignored.
    environment  SFAB_REPO_COMMIT is set. commit is its value; dirty is SFAB_REPO_DIRTY (1 or true,
                 0 or false; anything else, or unset, is null).
    stamp        ROOT/.repo-stamp.json, which `stamp` wrote in the git checkout the copy was made
                 from. commit and dirty are the stamp's, and dirty is also true when a file the stamp
                 lists is missing or no longer has the sha256 it recorded, or when a file outside the
                 recorded sets that the repository's .gitignore does not ignore is not in the stamp
                 (added after it). Looking for added files needs git, run on an empty repository of
                 its own; without git, dirty is null unless a listed file already differs.

With none of them, commit is "none" and dirty is null: not known.

A copy of the checkout made without .git (rsync with --exclude .git/, say) has no commit of its
own, so run `stamp` in the git checkout before every copy and copy the stamp with the tree. The
stamp holds the commit, the dirty flag by the rule above and the sha256 of every file that rule
covers (tracked and untracked, those the repository's .gitignore ignores left out). Git ignores
the stamp. A git checkout never reads it, so a stamp left behind there does no harm.

Exit status: 0; 2 on a usage error, or when `stamp` runs outside a git checkout or cannot write the
stamp.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

STAMP = ".repo-stamp.json"
RECORDED = ":(exclude,glob)**/audits/**"  # the recorded sets: no input to a run, so never dirty
# the repository's own ignore rules only, so a stamp made on one host and checked on another agree
OWN_IGNORES = ("-c", "core.excludesFile=" + os.devnull)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    # safe.directory: a lab runs as root, so a checkout another user owns (cloned by that user, then
    # run with sudo or as a systemd unit) is refused by git as of dubious ownership. Root runs this
    # checkout's own scripts anyway, so its .git is trusted no less. No optional locks: a status
    # read never takes the index lock from a git command running beside it.
    try:
        return subprocess.run(["git", "-c", f"safe.directory={os.path.realpath(root)}", "-C", str(root), *args],
                              capture_output=True, timeout=120, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.SubprocessError):
        return None


def git_state(root: Path) -> dict | None:
    """The commit and dirty flag from git, or None when ROOT is not the top of a git work tree."""
    top = _git(root, "rev-parse", "--show-toplevel")
    if top is None or top.returncode != 0:
        return None
    if os.path.realpath(top.stdout.decode().strip()) != os.path.realpath(root):
        return None  # ROOT sits inside another repository, which says nothing about this one
    head = _git(root, "rev-parse", "--verify", "HEAD")
    if head is None or head.returncode != 0:
        return None
    st = _git(root, "status", "--porcelain", "-z", "--untracked-files=all", "--", ".", RECORDED)
    dirty = None if st is None or st.returncode != 0 else bool(st.stdout)
    return {"commit": head.stdout.decode().strip(), "dirty": dirty, "source": "git"}


def _flag(v: str | None) -> bool | None:
    v = (v or "").strip().lower()
    if v in ("1", "true", "yes"):
        return True
    if v in ("0", "false", "no"):
        return False
    return None


def env_state(env) -> dict | None:
    commit = (env.get("SFAB_REPO_COMMIT") or "").strip()
    if not commit:
        return None
    return {"commit": commit, "dirty": _flag(env.get("SFAB_REPO_DIRTY")), "source": "environment"}


def file_sha256(p: Path) -> str:
    h = hashlib.sha256()
    if p.is_symlink():
        h.update(b"symlink\0" + os.fsencode(os.readlink(p)))
    else:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    return h.hexdigest()


def stamp_state(root: Path) -> dict | None:
    """The stamp's commit and dirty flag, checked against the files it lists; None without one."""
    try:
        data = json.loads((root / STAMP).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    commit, files = data.get("commit"), data.get("files")
    if not isinstance(commit, str) or not commit.strip() or not isinstance(files, dict):
        return None
    differ = 0
    for rel, digest in files.items():
        p = root / rel
        try:
            if not (p.is_symlink() or p.is_file()) or file_sha256(p) != digest:
                differ += 1
        except OSError:
            differ += 1
    dirty = data.get("dirty") if isinstance(data.get("dirty"), bool) else None
    added = unlisted_files(root, files)
    if differ:
        print(f"repostate: {differ} of {len(files)} files differ from the stamp; the tree is not the stamped one",
              file=sys.stderr)
        dirty = True
    if added:
        print(f"repostate: {len(added)} files outside the recorded sets are not in the stamp; the tree is not the "
              "stamped one", file=sys.stderr)
        dirty = True
    elif added is None and not differ:
        print("repostate: without git, files added since the stamp cannot be looked for; dirty is not known",
              file=sys.stderr)
        dirty = None
    return {"commit": commit.strip(), "dirty": dirty, "source": "stamp"}


def unlisted_files(root: Path, listed) -> list[str] | None:
    """Files outside the recorded sets that the repository's .gitignore does not ignore and the stamp
    does not list, read with git on an empty repository of its own over ROOT; None without git."""
    try:
        with tempfile.TemporaryDirectory(prefix="repostate-") as d:
            init = subprocess.run(["git", "init", "-q", d], capture_output=True, timeout=60)
            if init.returncode != 0:
                return None
            r = subprocess.run(["git", *OWN_IGNORES, "--git-dir", os.path.join(d, ".git"), "--work-tree", str(root),
                                "ls-files", "-z", "--others", "--exclude-standard", "--", ".", RECORDED],
                               cwd=root, capture_output=True, timeout=120, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    names = {n for n in r.stdout.decode("utf-8", "surrogateescape").split("\0") if n}
    return sorted(n for n in names - set(listed) - {STAMP, STAMP + ".tmp"}
                  if (root / n).is_symlink() or (root / n).is_file())


def state(root: Path, env=None) -> dict:
    env = os.environ if env is None else env
    return (git_state(root) or env_state(env) or stamp_state(root)
            or {"commit": "none", "dirty": None, "source": None})


def stamped_files(root: Path) -> list[str]:
    """Every file outside the recorded sets that git tracks or would add, present in the tree."""
    r = _git(root, *OWN_IGNORES, "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ".", RECORDED)
    if r is None or r.returncode != 0:
        raise OSError("git ls-files failed")
    names = sorted({n for n in r.stdout.decode("utf-8", "surrogateescape").split("\0") if n})
    return [n for n in names if (root / n).is_symlink() or (root / n).is_file()]


def write_stamp(root: Path) -> dict:
    g = git_state(root)
    if g is None:
        raise SystemExit(f"repostate: {root} is not the top of a git checkout; nothing to stamp")
    files = {rel: file_sha256(root / rel) for rel in stamped_files(root)}
    data = {"commit": g["commit"], "dirty": g["dirty"], "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": files}
    tmp = root / (STAMP + ".tmp")
    try:
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(tmp, root / STAMP)
    except OSError as exc:
        raise SystemExit(f"repostate: cannot write {root / STAMP}: {exc}") from exc
    return data


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in ("show", "stamp") or len(argv) > 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    root = Path(argv[1] if len(argv) > 1 else Path(__file__).resolve().parents[2]).resolve()
    if argv[0] == "show":
        print(json.dumps(state(root), sort_keys=True))
        return 0
    try:
        data = write_stamp(root)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"repostate: cannot stamp {root}: {exc}", file=sys.stderr)
        return 2
    print(f"repostate: stamped {data['commit']} (dirty: {json.dumps(data['dirty'])}), "
          f"{len(data['files'])} files, in {STAMP}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
