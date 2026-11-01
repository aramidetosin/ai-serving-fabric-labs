#!/usr/bin/env python3
"""testrun: the labs repo's tests, in parallel processes (FRAMEWORK.md section 2.6).

    testrun.py                       make test: every test but the tree tier
    testrun.py --full                make test-full: every test, the tree tier too
    testrun.py --quick [PATH ...]    make test-quick: the tests for the areas PATHs touch
    testrun.py --since REF --quick   ... the paths changed since REF (git diff REF...HEAD and the tree)
    testrun.py --list [--full]       the tests a run would run, one id per line, and the counts

Options: --jobs N (default: the CPU count), --durations N (also print the N slowest tests and
units), -v (print every unit as it ends, and its output when it failed or with -vv).

The suites are the four that the Makefile used to run one after the other with
`python3 -m unittest discover`:

    generator   common/sfab/tests     top common, with PYTHONPATH=common
    serving     serving-layer/tests   top serving-layer
    keys        images/keys/tests     top images/keys
    harness     common/tests          top common/tests

How a run goes. One process per suite lists its tests with unittest's own discovery, so a run
holds exactly the tests `discover` finds, in its order. The tests are cut into units: each class
whole, or, when its tests take long (and its class fixture, if it has one, was timed short), a
few of its tests at a time, and short classes of one module run together. A unit is one process,
a fresh interpreter started at the repository's top with the environment the Makefile gave its
suite, so no test shares memory with another unit's. Up to --jobs units run at once, the longest
first. A run lasts as long as its longest unit, so every unit estimated at less than half the
longest runs at a lower priority (nice 10) and leaves the CPU to the long ones when they need
it. Each process runs its tests with unittest's runner and writes back every test's outcome and
time; the run fails when a test fails or errors, or when a listed test was neither run nor
skipped by a class or module fixture. The counts printed are unittest's: tests run, and of them
failures, errors and skips. What a unit's tests leave running in its process group is stopped
when the unit ends.

The time each test and each class fixture took is kept for the next run's estimates in the git
directory the checkout's worktrees share (sfab-test-durations.json under `git rev-parse
--git-common-dir`), never in the tree; outside git the estimates are the defaults below.

The tree tier (TREE below) is the tests that read every recorded set rather than the code: they
run in make test-full, once per stage, and not in make test. Every other test runs in make test.

make test-quick maps each changed path to the tests that cover it (QUICK below, first match
wins), then runs the public-tree guard and namecheck on the changed files. A path no rule names
runs the whole of make test, so an unmapped change is never untested. With no PATH and no
--since, the paths are the work tree's changes against HEAD, untracked files included.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
THIS = Path(__file__).resolve()

# name: (start directory, top-level directory, environment the Makefile set)
SUITES = {
    "generator": ("common/sfab/tests", "common", {"PYTHONPATH": "common"}),
    "serving": ("serving-layer/tests", "serving-layer", {}),
    "keys": ("images/keys/tests", "images/keys", {}),
    "harness": ("common/tests", "common/tests", {}),
}
BASE_ENV = {"PYTHONDONTWRITEBYTECODE": "1"}

# The tree tier: suite:test id -> what it reads. make test-full runs these, make test does not.
TREE = {
    "harness:test_harness.NamecheckTest.test_repo_is_clean":
        "namecheck over every file of the tree, the recorded sets' too",
    "harness:test_setsize.CommittedSetsTest.test_compressed_files_decompress":
        "decompresses every compressed file of every recorded set",
    "harness:test_setsize.CommittedSetsTest.test_no_concatenation_or_placement_window":
        "the name of every file of every recorded set",
    "harness:test_setsize.CommittedSetsTest.test_no_large_plain_file":
        "the size of every file of every recorded set",
    "harness:test_setsize.CommittedSetsTest.test_sets_within_the_cap":
        "the size of every recorded set",
}

# make test-quick: (path pattern, selectors), the first rule whose pattern matches a changed path
# (from its start) giving that path's tests. A selector is a suite, suite:module or
# suite:module.Class; "tree" lets the tree tier's tests among them run too, and "make test" means
# the whole of make test. A path no rule matches is "make test", so a change the table does not
# know is never left untested. Every path outside the recorded sets also gets ALWAYS, two cheap
# checks that read every file of the code; the public-tree guard and namecheck then read the
# changed files themselves (their whole-tree tests run when their own rules name them).
LABS = ("harness:test_ch01 harness:test_ch02 harness:test_ch03 harness:test_ch04 harness:test_ch05 harness:test_ch06 harness:test_ch07 harness:test_m2 "
        "harness:test_part3_labs harness:test_part3_judges")
STAGES = "harness:test_stages harness:test_m2 harness:test_ch06"
# common/audit/: every audit, trace and drill runs redact.py (common/lib.sh), which imports
# redact_tree.py and evfile.py, and every audit runs the judge, which imports panos_parse.py;
# test_setsize imports those four, the drill summaries test_repostate runs import the judge, and
# chapter 7's render tests import redact.py and the trace tools that import it and evfile.py
AUDIT = ("harness:test_harness " + LABS + " harness:test_stages harness:test_redact_tree harness:test_setsize "
         "harness:test_repostate generator:sfab.tests.test_ch07_render")
ALWAYS = "harness:test_platform.ProductNameTest harness:test_harness.RedactHostKernelTest.test_no_audit_records_a_kernel_log"
QUICK = [
    # the recorded sets: their size policy and namecheck, which the tree tier holds, and the tests
    # that read a recorded file
    (r"ch03/audits/[^/]+/", "tree harness:test_setsize harness:test_harness.NamecheckTest harness:test_ch04"),
    (r"dev/m2/audits/[^/]+/", "tree harness:test_setsize harness:test_harness.NamecheckTest harness:test_stages"),
    (r"(?:[^/]+/)+audits/[^/]+/", "tree harness:test_setsize harness:test_harness.NamecheckTest"),
    (r"(?:[^/]+/)+audits/INDEX\.md$", ""),
    # the tests themselves: the module that changed, or the modules that use a shared piece
    (r"common/sfab/tests/(test_\w+)\.py$", "generator:sfab.tests.{0}"),
    (r"common/sfab/tests/golden/m1-panos/", "generator:sfab.tests.test_firewall"),
    (r"common/sfab/tests/golden/m1-hosts/", "generator:sfab.tests.test_hosts"),
    (r"common/sfab/tests/golden/m1/", "generator:sfab.tests.test_switches"),
    (r"common/sfab/tests/", "generator"),
    (r"serving-layer/tests/(test_\w+)\.py$", "serving:tests.{0}"),
    (r"images/keys/tests/(test_\w+)\.py$", "keys:tests.{0}"),
    (r"common/tests/(test_\w+)\.py$", "harness:{0}"),
    (r"common/tests/ch04_world\.py$", "harness:test_ch04"),
    (r"common/tests/recorded/", "harness:test_ch04"),
    (r"common/tests/m2_world\.py$", "harness:test_m2 harness:test_ch03 harness:test_ch04"),
    (r"common/tests/services_block\.py$", "harness:test_m2"),
    (r"common/tests/codefiles\.py$", "harness:test_platform.ProductNameTest harness:test_harness.RedactHostKernelTest"),
    (r"common/tests/runscope\.py$", "harness:test_ch03 harness:test_ch04 harness:test_ch05 harness:test_ch06 harness:test_m2"),
    (r"common/tests/shims-ch0[34]/", "harness:test_ch03 harness:test_ch04"),
    (r"common/tests/shims-ch05/", "harness:test_ch05"),
    (r"common/tests/shims-ch0[67]/", "harness:test_ch06 harness:test_ch07 harness:test_part3_labs"),
    (r"common/tests/shims-part3/|common/tests/p3_world\.py$", "harness:test_part3_labs"),
    (r"common/tests/shims-m2/", "harness:test_m2 harness:test_ch03 harness:test_ch04"),
    (r"common/tests/shims/", LABS + " harness:test_stages"),
    # the serving recipe and the key tool, and the labs that run them
    (r"serving-layer/", "serving generator:sfab.tests.test_serving_render generator:sfab.tests.test_ch02_render harness:test_ch06 harness:test_ch07"),
    (r"images/keys/", "keys generator:sfab.tests.test_serving_render generator:sfab.tests.test_ch06_render "
                      "generator:sfab.tests.test_ch07_render generator:sfab.tests.test_part3_render harness:test_ch07"),
    # the generator and the spec it reads: every render, and the labs' harness tests render too
    (r"common/sfab/|common/bin/sfab$|spec/", "make test"),
    # the harness's tools
    (r"common/tools/namecheck\.py$", "tree harness:test_harness.NamecheckTest harness:test_public_tree "
                                      "generator:sfab.tests.test_frr_registry harness:test_stages " + LABS),
    (r"common/tools/typescript\.py$", "harness:test_harness.TypescriptTest"),
    (r"common/tools/testrun\.py$", "make test"),
    (r"common/audit/evfile\.py$", "tree " + AUDIT),
    (r"common/audit/setsize\.py$", "tree harness:test_setsize " + LABS + " harness:test_stages"),
    (r"common/audit/", AUDIT),
    # chapter 2's matrix and label runs, which break-2a's driver sources too
    (r"common/matrix/", LABS + " generator:sfab.tests.test_ch02_render"),
    # chapter 5's rp_filter stage and chapter 6's attachment reads
    (r"common/reads/", "harness:test_reads harness:test_ch05 harness:test_ch06"),
    (r"common/(?:trace|drill|break)/|common/breakheal\.py$", LABS + " generator:sfab.tests.test_drills_render "
     "generator:sfab.tests.test_ch07_render generator:sfab.tests.test_part3_render generator:sfab.tests.test_part3_tools_render "
     "harness:test_repostate harness:test_setsize"),
    (r"common/stages/", STAGES + " harness:test_platform generator:sfab.tests.test_ch04_render"),
    (r"common/(?:fw|klish|host|storage)/", "generator " + LABS + " harness:test_stages"),
    (r"common/(?:mk/|lib\.sh$)", "harness:test_repostate harness:test_harness " + LABS + " harness:test_stages"),
    (r"common/bin/(?:repostate|tick)\.py$", "harness:test_repostate harness:test_harness harness:test_stages " + LABS),
    (r"common/bin/secrets\.py$", "harness:test_harness harness:test_stages generator:sfab.tests.test_switches " + LABS),
    (r"common/bin/", "generator " + LABS + " harness:test_stages harness:test_harness"),
    # a lab: its harness tests, its render tests, and the pages that name it
    (r"ch01/", "harness:test_ch01 harness:test_platform generator:sfab.tests.test_ch01_render"),
    (r"ch02/", "harness:test_ch02 harness:test_platform generator:sfab.tests.test_ch02_render"),
    (r"ch03/", "harness:test_ch03 harness:test_platform"),
    (r"ch0([4-7])/", "harness:test_ch0{0} harness:test_platform generator:sfab.tests.test_ch0{0}_render"),
    # Part III's labs (chapters 8 to 11): their render tests, and the pages that name them
    (r"ch(?:0[89]|1[01])/", "harness:test_platform harness:test_part3_labs generator:sfab.tests.test_part3_render "
                            "generator:sfab.tests.test_part3_tools_render"),
    (r"dev/m2/", "harness:test_m2 harness:test_platform generator:sfab.tests.test_k8s generator:sfab.tests.test_storage"),
    (r"dev/m1/", "harness:test_stages harness:test_platform generator:sfab.tests.test_integration "
                 "generator:sfab.tests.test_switches generator:sfab.tests.test_firewall generator:sfab.tests.test_hosts"),
    (r"images/", "generator harness:test_platform harness:test_stages"),
    (r"platform/", "harness:test_platform"),
    # the pages at the top, and the files git reads
    (r"README\.md$", "harness:test_platform harness:test_repostate generator:sfab.tests.test_k8s"),
    (r"FRAMEWORK\.md$|LICENSE", "harness:test_platform generator:sfab.tests.test_k8s"),
    (r"Makefile$|\.git(?:ignore|attributes)$|\.shellcheckrc$", "harness:test_repostate harness:test_setsize"),
]

# the estimate for a test with no recorded time, by suite (seconds), and for a test of a class that
# runs a lab's scripts against the stand-ins (it has run_cmd: the harness's lab tests)
DEFAULT_TEST_S = {"generator": 0.3, "serving": 0.2, "keys": 0.2, "harness": 1.0}
DEFAULT_LAB_TEST_S = 30.0
# a unit is cut to about this long, and never split below MIN_UNIT_S of estimated time
MIN_UNIT_S = 3.0
DURATIONS_FILE = "sfab-test-durations.json"
# a unit estimated at less than this share of the longest runs at this niceness
LONG_SHARE, NICE = 0.5, 10


# ----------------------------------------------------------------------------------------------
# the worker side: list a suite's tests, or run some of them


def _suite_path(suite: str) -> None:
    start, top, _env = SUITES[suite]
    # as python -m unittest puts the working directory first, and discover the top directory
    sys.path[0] = os.getcwd()
    top = str(ROOT / top)
    if top not in sys.path:
        sys.path.insert(0, top)


def _flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from _flatten(t)
        else:
            yield t


def _overridden(cls, name: str) -> bool:
    mine = getattr(cls, name, None)
    base = getattr(unittest.TestCase, name)
    return getattr(mine, "__func__", mine) is not getattr(base, "__func__", base)


class Recorder(unittest.TextTestResult):
    """unittest's text result, which also keeps each test's outcome and time, and the time
    before each test that its class and module fixtures took."""

    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.out: dict = {}
        self.holders: list = []
        self._last = time.monotonic()
        self._t0 = self._last

    def _rec(self, test, status, detail=None):
        tid = test.id()
        if isinstance(test, unittest.TestCase):
            r = self.out.setdefault(tid, {"status": "ok", "details": []})
            order = ["ok", "skip", "xfail", "xpass", "fail", "error"]
            if order.index(status) > order.index(r["status"]):
                r["status"] = status
            if detail:
                r["details"].append(detail)
        else:
            # a class or module fixture's outcome (setUpClass (mod.Cls), and the like)
            self.holders.append({"id": tid, "status": status, "detail": detail})

    def startTest(self, test):
        now = time.monotonic()
        self.out.setdefault(test.id(), {"status": "ok", "details": []})["before_s"] = now - self._last
        self._t0 = now
        super().startTest(test)

    def stopTest(self, test):
        super().stopTest(test)
        now = time.monotonic()
        self.out.setdefault(test.id(), {"status": "ok", "details": []})["time_s"] = now - self._t0
        self._last = now

    def addError(self, test, err):
        super().addError(test, err)
        self._rec(test, "error", self._exc_info_to_string(err, test))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._rec(test, "fail", self._exc_info_to_string(err, test))

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._rec(test, "skip", reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self._rec(test, "xfail")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._rec(test, "xpass", "unexpected success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            failed = issubclass(err[0], test.failureException)
            self._rec(test, "fail" if failed else "error", f"{subtest}\n{self._exc_info_to_string(err, test)}")


def worker_list(suite: str) -> int:
    _suite_path(suite)
    start, top, _env = SUITES[suite]
    found = unittest.defaultTestLoader.discover(str(ROOT / start), top_level_dir=str(ROOT / top))
    tests, pre = [], []
    for t in _flatten(found):
        cls = type(t)
        if cls.__module__.startswith("unittest."):
            # an import that failed or a module that skipped itself: run it here, as discover would
            with open(os.devnull, "w") as null:
                r = Recorder(unittest.runner._WritelnDecorator(null), False, 0)
                t.run(r)
            pre.append({"id": t.id(), "ran": True, **r.out.get(t.id(), {"status": "error", "details": ["no outcome"]})})
            continue
        mod = sys.modules.get(cls.__module__)
        tests.append({"id": t.id(), "module": cls.__module__, "class": f"{cls.__module__}.{cls.__qualname__}",
                      "lab": hasattr(cls, "run_cmd"),
                      "class_fixture": _overridden(cls, "setUpClass") or _overridden(cls, "tearDownClass"),
                      "module_fixture": bool(mod and (hasattr(mod, "setUpModule") or hasattr(mod, "tearDownModule")))})
    json.dump({"tests": tests, "pre": pre}, sys.stdout)
    return 0


def worker_run(suite: str, ids: list, out: str, nice: int = 0) -> int:
    if nice:
        os.nice(nice)
    _suite_path(suite)
    loader = unittest.TestLoader()
    tests = unittest.TestSuite()
    load_errors = []
    for tid in ids:
        try:
            tests.addTest(loader.loadTestsFromName(tid))
        except Exception:  # noqa: BLE001 - reported as the test's error
            load_errors.append({"id": tid, "status": "error", "details": [traceback.format_exc()]})
    runner = unittest.TextTestRunner(stream=sys.stderr, resultclass=Recorder, verbosity=1,
                                     warnings=None if sys.warnoptions else "default")
    t0 = time.monotonic()
    res = runner.run(tests)
    res_out = dict(res.out)
    for e in load_errors:
        res_out[e["id"]] = {"status": "error", "details": e["details"]}
    Path(out).write_text(json.dumps({"tests": res_out, "holders": res.holders, "ran": res.testsRun,
                                     "wall_s": time.monotonic() - t0}))
    sys.stdout.flush()
    sys.stderr.flush()
    # what the tests left running in this unit's process group (a stand-in capture never stopped)
    # is asked to stop now, while this process still leads the group; only a worker the runner
    # started in a session of its own leads one
    if os.getpgrp() == os.getpid():
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            os.killpg(os.getpid(), signal.SIGTERM)
        except OSError:
            pass
    return 0


# ----------------------------------------------------------------------------------------------
# the runner side


def git(*args: str) -> str | None:
    try:
        p = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True)
    except OSError:
        return None
    return p.stdout if p.returncode == 0 else None


def durations_path() -> Path | None:
    d = git("rev-parse", "--path-format=absolute", "--git-common-dir")
    return Path(d.strip()) / DURATIONS_FILE if d and d.strip() else None


def load_durations() -> dict:
    p = durations_path()
    try:
        d = json.loads(p.read_text()) if p else {}
    except (OSError, ValueError):
        d = {}
    return {"tests": d.get("tests", {}), "fixtures": d.get("fixtures", {})}


def save_durations(new: dict) -> None:
    p = durations_path()
    if not p:
        return
    old = load_durations()
    for k in ("tests", "fixtures"):
        old[k].update(new[k])
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(old, sort_keys=True))
        os.replace(tmp, p)
    except OSError:
        pass


def suite_env(suite: str) -> dict:
    env = dict(os.environ)
    env.update(BASE_ENV)
    env.update(SUITES[suite][2])
    return env


def list_tests(suites: list) -> dict:
    """suite -> {"tests": [...], "pre": [...]} from each suite's own discovery, in parallel."""
    procs = {s: subprocess.Popen([sys.executable, str(THIS), "--worker-list", s], cwd=ROOT, env=suite_env(s),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
             for s in suites}
    out = {}
    for s, p in procs.items():
        so, se = p.communicate()
        if p.returncode != 0:
            raise SystemExit(f"testrun: listing the {s} suite failed:\n{se[-4000:]}")
        out[s] = json.loads(so)
    return out


class Unit:
    def __init__(self, suite: str, ids: list, est: float, name: str):
        self.suite, self.ids, self.est, self.name = suite, ids, est, name
        self.nice = 0
        self.result: dict | None = None
        self.log = ""
        self.rc = None
        self.wall = 0.0


def estimate(suite: str, t: dict, hist: dict) -> float:
    """A test's time at its last run, else the default for its kind."""
    return hist["tests"].get(f"{suite}:{t['id']}", DEFAULT_LAB_TEST_S if t.get("lab") else DEFAULT_TEST_S[suite])


def make_units(suite: str, tests: list, hist: dict, target: float) -> list:
    """Cut a suite's tests into units of about target seconds: a class whole, a class longer than
    target in runs of its tests, and the short classes of one module together. A class with a
    class fixture is cut only once a run has timed its fixture and found it short (each run
    repeats it), so its tests run as they would one at a time under unittest."""

    def est(t):
        return estimate(suite, t, hist)

    def fixture(cls):
        return hist["fixtures"].get(f"{suite}:{cls}", 0.0)

    units, cur, cur_est, cur_mod = [], [], 0.0, None

    def flush():
        nonlocal cur, cur_est
        if cur:
            units.append(Unit(suite, [t["id"] for t in cur], cur_est, _unit_name(cur)))
        cur, cur_est = [], 0.0

    classes: list = []
    for t in tests:
        if classes and classes[-1][0] == t["class"]:
            classes[-1][1].append(t)
        else:
            classes.append((t["class"], [t]))
    for cls, ts in classes:
        mod = ts[0]["module"]
        total = fixture(cls) + sum(est(t) for t in ts)
        if mod != cur_mod:
            flush()
            cur_mod = mod
        timed = f"{suite}:{cls}" in hist["fixtures"]
        cuttable = not ts[0]["class_fixture"] or (timed and fixture(cls) < target / 4)
        if total > target and len(ts) > 1 and cuttable:
            flush()
            run, run_est = [], fixture(cls)
            for t in ts:
                if run and run_est + est(t) > target:
                    units.append(Unit(suite, [x["id"] for x in run], run_est, _unit_name(run)))
                    run, run_est = [], fixture(cls)
                run.append(t)
                run_est += est(t)
            units.append(Unit(suite, [x["id"] for x in run], run_est, _unit_name(run)))
            continue
        if cur and cur_est + total > target:
            flush()
        cur.extend(ts)
        cur_est += total
    flush()
    return units


def _unit_name(ts: list) -> str:
    classes = sorted({t["class"] for t in ts})
    if len(ts) == 1:
        return ts[0]["id"]
    if len(classes) == 1:
        return f"{classes[0]} ({len(ts)} tests)"
    return f"{ts[0]['module']} ({len(classes)} classes, {len(ts)} tests)"


LIVE: dict = {}
LIVE_LOCK = threading.Lock()


def run_unit(u: Unit) -> Unit:
    with tempfile.TemporaryDirectory(prefix="sfab-testrun-") as d:
        out, log = Path(d) / "result.json", Path(d) / "log.txt"
        t0 = time.monotonic()
        with open(log, "wb") as lf:
            argv = [sys.executable, str(THIS), "--worker-run", u.suite, "--out", str(out), "--nice", str(u.nice)]
            p = subprocess.Popen(argv, cwd=ROOT, env=suite_env(u.suite), stdin=subprocess.PIPE, stdout=lf,
                                 stderr=subprocess.STDOUT, start_new_session=True)
            with LIVE_LOCK:
                LIVE[p.pid] = p
            try:
                p.communicate(json.dumps(u.ids).encode())
            finally:
                with LIVE_LOCK:
                    LIVE.pop(p.pid, None)
        u.wall, u.rc = time.monotonic() - t0, p.returncode
        u.log = log.read_text(errors="replace")
        try:
            u.result = json.loads(out.read_text())
        except (OSError, ValueError):
            u.result = None
    return u


def outcome(units: list, pre: dict) -> tuple:
    """(per test {suite:id: record}, problems [(name, text)])."""
    tests, problems = {}, []
    for suite, recs in pre.items():
        for r in recs:
            tests[f"{suite}:{r['id']}"] = r
    for u in units:
        res = u.result
        if res is None:
            problems.append((u.name, f"the unit's process ended ({u.rc}) without a result:\n{u.log[-6000:]}"))
            for tid in u.ids:
                tests[f"{u.suite}:{tid}"] = {"status": "error", "details": ["its unit ended without a result"], "ran": False}
            continue
        skipped_by = {}
        for h in res["holders"]:
            if h["status"] == "skip":
                # a class or module fixture skipped its tests, as unittest does: not run, not counted
                m = re.search(r"\(([\w.]+)\)", h["id"])
                if m:
                    skipped_by[m.group(1)] = h
                tests[f"{u.suite}:{h['id']}"] = {"status": "skip", "details": [h["detail"]], "ran": True, "holder": True}
            else:
                tests[f"{u.suite}:{h['id']}"] = {"status": h["status"], "details": [h["detail"]], "ran": True, "holder": True}
        for tid in u.ids:
            r = res["tests"].get(tid)
            if r is None:
                owner = next((k for k in skipped_by if tid == k or tid.startswith(k + ".")), None)
                if owner is None:
                    tests[f"{u.suite}:{tid}"] = {"status": "error", "details": ["listed, but neither run nor skipped"], "ran": False}
                continue
            r = dict(r)
            r["ran"] = "time_s" in r
            tests[f"{u.suite}:{tid}"] = r
    return tests, problems


def fmt_s(s: float) -> str:
    return f"{s:.1f} s" if s < 120 else f"{int(s // 60)} min {s % 60:.0f} s"


def changed_paths(since: str | None) -> list | None:
    out = set()
    if since:
        d = git("diff", "--name-only", f"{since}...HEAD")
        if d is None:
            return None
        out.update(d.split())
    d = git("diff", "--name-only", "HEAD")
    u = git("ls-files", "--others", "--exclude-standard")
    if d is None or u is None:
        return None
    out.update(d.split())
    out.update(u.split())
    return sorted(out)


def is_evidence(path: str) -> bool:
    """A recorded file: under an audits/ directory, other than that directory's INDEX.md."""
    parts = path.split("/")
    return "audits" in parts[:-1] and not (parts[-1] == "INDEX.md" and parts[-2] == "audits")


def quick_selectors(paths: list) -> tuple:
    """(selectors, tree, [(path, what)]): the tests for the changed paths, whether the tree tier's
    among them run too, and why; selectors is None when a path needs the whole of make test."""
    sel, tree, why = set(), False, []
    for path in paths:
        for rx, what in QUICK:
            m = re.match(rx, path)
            if m:
                what = what.format(*m.groups())
                break
        else:
            what = "make test"
        why.append((path, what))
        if what == "make test":
            return None, False, why
        words = what.split()
        tree = tree or "tree" in words
        sel.update(w for w in words if w != "tree")
        if not is_evidence(path):
            sel.update(ALWAYS.split())
    return sel, tree, why


def static_selectors() -> set:
    """Every selector the table writes out in full (not built from a path), which must name a test."""
    out = set(ALWAYS.split())
    for _rx, what in QUICK:
        out.update(w for w in what.split() if "{" not in w and w != "tree" and what != "make test")
    return out


# the public-tree guard's scan (common/tests/test_public_tree.py) over the files named: the lines
# its whole-tree test would report for them, by path, line and label
GUARD = """
import sys
sys.path.insert(0, "common/tests")
import test_public_tree as T
hits = T.scan(T.ROOT, sys.argv[1:])
print("\\n".join(hits + [f"public-tree guard: {len(sys.argv) - 1} files, {len(hits)} hit(s)"]))
sys.exit(1 if hits else 0)
"""


def quick_guards(paths: list) -> int:
    """The public-tree guard and namecheck --mask on the changed files that are there. namecheck is
    skipped (exit 3) without a scrub list, as make namecheck is, unless SFAB_REQUIRE_NAMECHECK is
    set; the guard reads the author's pattern list when $SFAB_PUBLIC_TREE_PATTERNS names one."""
    files = [p for p in paths if (ROOT / p).is_file()]
    code = [p for p in files if not is_evidence(p)]
    rc = 0
    for argv, these, skip_ok in (([sys.executable, "-c", GUARD], code, False),
                                 ([sys.executable, str(ROOT / "common" / "tools" / "namecheck.py"), "--mask"], files, True)):
        if not these:
            continue
        r = subprocess.run(argv + these, cwd=ROOT, env=suite_env("harness"), capture_output=True, text=True)
        print("\n".join((r.stdout + r.stderr).rstrip().splitlines()[-40:]))
        skipped = skip_ok and r.returncode == 3 and os.environ.get("SFAB_REQUIRE_NAMECHECK", "") in ("", "0")
        if r.returncode != 0 and not skipped:
            rc = 1
    return rc


def selected(suite: str, t: dict, sel: set | None) -> bool:
    if sel is None:
        return True
    if suite in sel:
        return True
    for s in sel:
        su, _, name = s.partition(":")
        if su == suite and name and (t["id"] == name or t["id"].startswith(name + ".")):
            return True
    return False


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Run the labs repo's tests in parallel processes.")
    ap.add_argument("--full", action="store_true", help="the tree tier too (make test-full)")
    ap.add_argument("--quick", action="store_true", help="only the tests for the changed paths (make test-quick)")
    ap.add_argument("--since", help="with --quick, the paths changed since this commit too")
    ap.add_argument("--list", action="store_true", help="print the tests a run would run, and the counts")
    ap.add_argument("--jobs", type=int, default=0, help="units at once (default: the CPU count)")
    ap.add_argument("--durations", type=int, default=0, metavar="N", help="print the N slowest tests and units")
    ap.add_argument("-v", "--verbose", action="count", default=0)
    ap.add_argument("paths", nargs="*", help="with --quick, the changed paths")
    ap.add_argument("--worker-list", metavar="SUITE", help=argparse.SUPPRESS)
    ap.add_argument("--worker-run", metavar="SUITE", help=argparse.SUPPRESS)
    ap.add_argument("--out", help=argparse.SUPPRESS)
    ap.add_argument("--nice", type=int, default=0, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.worker_list:
        return worker_list(a.worker_list)
    if a.worker_run:
        return worker_run(a.worker_run, json.loads(sys.stdin.read()), a.out, a.nice)
    if a.paths and not a.quick:
        ap.error("paths are for --quick")

    jobs = a.jobs or os.cpu_count() or 1
    sel, tree, paths = None, a.full, []
    if a.quick:
        paths = set(a.paths)
        if a.since or not a.paths:
            found = changed_paths(a.since)
            if found is None:
                print("testrun: git cannot list the changed paths here; name them (make test-quick CHANGED='...')",
                      file=sys.stderr)
                return 2
            paths |= set(found)
        paths = sorted(p.rstrip("/") for p in paths)
        if not paths:
            print("testrun: no path changed against HEAD; name the paths (CHANGED='...') or a commit (SINCE=...)")
            return 0
        sel, tree_too, why = quick_selectors(paths)
        tree = tree or tree_too
        for path, what in why:
            print(f"testrun: {path} -> {what or 'the checks every change to the code gets'}")
        if sel is None:
            print("testrun: so the whole of make test runs")
    suites = list(SUITES) if sel is None else [s for s in SUITES if any(x.partition(":")[0] == s for x in sel)]

    t0 = time.monotonic()
    listed = list_tests(suites)

    def names(x: str) -> bool:
        su, _, _ = x.partition(":")
        return su in listed and any(selected(su, t, {x}) for t in listed[su]["tests"])

    # the table's own check, on every whole run: each tree-tier test and each selector written out
    # in full names a test, so a renamed test cannot drop out of a tier or a rule unseen
    if sel is None:
        known = {f"{su}:{t['id']}" for su in listed for t in listed[su]["tests"]}
        bad = sorted(k for k in TREE if k not in known) + sorted(x for x in static_selectors() if not names(x))
        if bad:
            print("testrun: TREE or QUICK names what no test is:\n  " + "\n  ".join(bad), file=sys.stderr)
            return 2
    else:
        # a selector built from a path (a lab with no render tests, say) may name nothing
        sel = {x for x in sel if names(x) or x in SUITES}
    picked = {su: [t for t in listed[su]["tests"] if selected(su, t, sel) and (tree or f"{su}:{t['id']}" not in TREE)]
              for su in suites}
    pre = {su: listed[su]["pre"] for su in suites}
    if a.list:
        for su in suites:
            for t in picked[su]:
                print(f"{su}:{t['id']}")
        n = sum(len(v) for v in picked.values())
        held = sum(1 for su in suites for t in listed[su]["tests"] if f"{su}:{t['id']}" in TREE and selected(su, t, sel))
        print(f"# {n} tests" + ("" if tree else f"; the tree tier holds {held} more"), file=sys.stderr)
        return 0

    hist = load_durations()
    total_est = sum(estimate(s, t, hist) for s in suites for t in picked[s])
    target = max(MIN_UNIT_S, total_est / (jobs * 3))
    units = [u for s in suites for u in make_units(s, picked[s], hist, target)]
    units.sort(key=lambda u: -u.est)
    # the run lasts as long as its longest units: every other unit yields the CPU to them
    for u in units:
        if units and u.est < LONG_SHARE * units[0].est:
            u.nice = NICE
    tier = "make test-full" if a.full else "make test-quick" if sel is not None else "make test"
    print(f"testrun: {tier}: {sum(len(u.ids) for u in units)} tests in {len(units)} units, {min(jobs, len(units) or 1)} at once")
    sys.stdout.flush()

    done = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=jobs)
    try:
        futs = [pool.submit(run_unit, u) for u in units]
        for f in concurrent.futures.as_completed(futs):
            u = f.result()
            done.append(u)
            bad = u.result is None or any(r["status"] in ("fail", "error", "xpass") for r in u.result["tests"].values()) \
                or any(h["status"] in ("fail", "error") for h in u.result["holders"])
            if a.verbose or bad:
                print(f"  {'FAIL' if bad else 'ok  '}  {u.suite}: {u.name}  {fmt_s(u.wall)}  [{len(done)}/{len(units)}]")
                if bad or a.verbose > 1:
                    print("\n".join("      " + ln for ln in u.log.rstrip().splitlines()[-200:]))
                sys.stdout.flush()
    except KeyboardInterrupt:
        with LIVE_LOCK:
            for p in LIVE.values():
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
        pool.shutdown(wait=False, cancel_futures=True)
        print("testrun: interrupted", file=sys.stderr)
        return 130
    pool.shutdown()
    wall = time.monotonic() - t0

    tests, problems = outcome(done, pre)
    new = {"tests": {}, "fixtures": {}}
    for u in done:
        if not u.result:
            continue
        seen = set()
        for tid in u.ids:
            r = u.result["tests"].get(tid)
            if not r or "time_s" not in r:
                continue
            new["tests"][f"{u.suite}:{tid}"] = round(r["time_s"], 3)
            cls = tid.rsplit(".", 1)[0]
            if cls not in seen:
                seen.add(cls)
                new["fixtures"][f"{u.suite}:{cls}"] = round(r.get("before_s", 0.0), 3)
    save_durations(new)

    rc = 0
    for s in suites:
        recs = {k: v for k, v in tests.items() if k.partition(":")[0] == s}
        # as unittest counts: every test started; a fixture's skip or error is counted, not run
        ran = sum(1 for v in recs.values() if v.get("ran") and not v.get("holder"))
        counts = {st: sum(1 for v in recs.values() if v["status"] == st) for st in ("fail", "error", "skip", "xfail", "xpass")}
        bad = counts["fail"] + counts["error"] + counts["xpass"]
        extra = ", ".join(f"{n}={counts[k]}" for k, n in (("fail", "failures"), ("error", "errors"), ("skip", "skipped"),
                                                          ("xfail", "expected failures"), ("xpass", "unexpected successes"))
                          if counts[k])
        print(f"{s}: ran {ran} tests: {'FAILED' if bad else 'OK'}{f' ({extra})' if extra else ''}")
        if bad:
            rc = 1
    for k, v in sorted(tests.items()):
        if v["status"] in ("fail", "error", "xpass"):
            print(f"\n{'=' * 70}\n{v['status'].upper()}: {k}\n{'-' * 70}")
            print("\n".join(v.get("details") or []))
    for name, text in problems:
        rc = 1
        print(f"\n{'=' * 70}\nUNIT: {name}\n{'-' * 70}\n{text}")
    if a.durations:
        rows = sorted(((v.get("time_s", 0.0), k) for k, v in tests.items() if "time_s" in v), reverse=True)[:a.durations]
        print(f"\nthe {len(rows)} slowest tests:")
        for t, k in rows:
            print(f"  {t:8.2f} s  {k}")
        print(f"\nthe {min(a.durations, len(done))} slowest units:")
        for u in sorted(done, key=lambda u: -u.wall)[:a.durations]:
            print(f"  {u.wall:8.2f} s  {u.suite}: {u.name}")
    if a.quick:
        rc = max(rc, quick_guards(paths))
    total = sum(1 for v in tests.values() if v.get("ran") and not v.get("holder"))
    cpu = sum(u.wall for u in done)
    print(f"\ntestrun: {tier}: ran {total} tests in {fmt_s(wall)} ({fmt_s(cpu)} of units, {len(done)} units): "
          f"{'OK' if rc == 0 else 'FAILED'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
