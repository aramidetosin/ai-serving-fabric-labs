# Milestone M2, lab sfab-m2 (FRAMEWORK.md 6.3, first row). The targets are common/mk/chapter.mk's;
# see README.md and RESULTS.md.
include ../../common/mk/chapter.mk

.PHONY: teardown-check exit-criteria node-sync memwatch-check

# Exit criterion 15: after make down, no sfab-m2-* container and no clab-sfab-m2/ remain, and the
# state/ disks are kept. Runs down (again, harmlessly) and records the checks as a result set.
teardown-check:
	$(COMMON)/stages/down.sh fast --verify

# The guests' boot-time files against the current render: CHECK=1 only compares, otherwise the
# files that differ are installed and applied live (boot runs the same step after the guests answer).
# Exit 3 (files installed, a cluster file among them) is a success here; boot restarts the init
# node's sfab-cluster.service on it, this target only says so.
node-sync:
	@rc=0; $(COMMON)/host/node-sync.sh $(if $(filter 1,$(CHECK)),--check,) || rc=$$?; \
	if [ $$rc -eq 3 ]; then echo "node-sync: a cluster file changed; each guest's sfab-cluster.service runs the new one at its next start"; rc=0; fi; \
	exit $$rc

# One poll of the memory watchdog, as a dry run: its floor, its victim order and what it would stop.
memwatch-check:
	$(COMMON)/host/mem-watchdog.sh $(LAB) --once --dry-run

# The M2 sequence end to end (RESULTS.md, How to reproduce). Each line stops the sequence on failure.
exit-criteria:
	$(MAKE) render
	$(MAKE) up
	$(MAKE) trace
	$(MAKE) up
	$(COMMON)/stages/run.sh status
	docker rm -f sfab-m2-k8s-gpu1
	$(MAKE) recover
	$(MAKE) audit
	$(MAKE) down
	$(MAKE) teardown-check
	$(MAKE) up
	$(MAKE) down
	$(MAKE) teardown-check
