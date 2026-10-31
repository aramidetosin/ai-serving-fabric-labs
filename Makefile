# The labs repo's own checks (FRAMEWORK.md 2.5 and 2.6). Each lab has its own Makefile for running it.
#
#   make check       sfab check on every lab, then every test, then namecheck
#   make test        the generator's unit tests, the serving recipe's and the key tool's, and the harness
#                    tests, in parallel processes (common/tools/testrun.py): every test but the tree tier
#   make test-full   every test, the tree tier too (the tests that read every recorded set): once per stage
#   make test-quick  the tests for the areas a change touches, then the public-tree guard and namecheck on
#                    the changed files: CHANGED='path ...', SINCE=<commit>, else the work tree's changes
#   make test-serial every test, one suite after another in one process each, as unittest discover runs them
#   make namecheck   no private name, host, domain, path, prefix or credential in the repo; it
#                    needs a scrub list in $SFAB_SCRUB_LIST and is skipped without one, which
#                    fails instead when SFAB_REQUIRE_NAMECHECK is set (FRAMEWORK.md 4.4)
#
# JOBS=N runs N test processes at once (default: the CPU count); DURATIONS=N prints the N slowest.

PY := PYTHONDONTWRITEBYTECODE=1 python3
LABS := $(sort $(patsubst %/chapter.yaml,%,$(wildcard ch[0-9][0-9]/chapter.yaml dev/*/chapter.yaml)))
TESTRUN := $(PY) common/tools/testrun.py $(if $(JOBS),--jobs $(JOBS)) $(if $(DURATIONS),--durations $(DURATIONS))

.PHONY: check test test-full test-quick test-serial namecheck labs

check: labs test-full namecheck

labs:
	@rc=0; for lab in $(LABS); do common/bin/sfab check $$lab || rc=1; done; exit $$rc

test:
	$(TESTRUN)

test-full:
	$(TESTRUN) --full

test-quick:
	$(TESTRUN) --quick $(if $(SINCE),--since $(SINCE)) $(CHANGED)

test-serial:
	PYTHONPATH=common $(PY) -m unittest discover -s common/sfab/tests -t common
	$(PY) -m unittest discover -s serving-layer/tests -t serving-layer
	$(PY) -m unittest discover -s images/keys/tests -t images/keys
	$(PY) -m unittest discover -s common/tests -t common/tests

# namecheck exits 3 when it is skipped (no scrub list): not run, so not a failure, unless
# SFAB_REQUIRE_NAMECHECK is set (not empty and not 0, as common/audit/gate.sh reads it)
namecheck:
	@rc=0; $(PY) common/tools/namecheck.py || rc=$$?; [ $$rc -eq 0 ] || { [ $$rc -eq 3 ] && \
	  case "$${SFAB_REQUIRE_NAMECHECK:-}" in '' | 0) ;; \
	    *) echo "namecheck: skipped, and SFAB_REQUIRE_NAMECHECK is set" >&2; exit 1 ;; esac; }
