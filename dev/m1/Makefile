# Milestone M1, lab sfab-m1 (FRAMEWORK.md 6.2). The targets are common/mk/chapter.mk's; see README.md.
include ../../common/mk/chapter.mk

.PHONY: teardown-check exit-criteria settle

# Exit criterion 8: after make down, no sfab-m1-* container and no clab-sfab-m1/ remain, and the
# state/ disks are kept. Runs down (again, harmlessly) and records the checks as a result set.
teardown-check:
	$(COMMON)/stages/down.sh fast --verify

# The questions the first deploy settles (RESULTS.md, the settle answers), recorded as the result
# set audits/sfab-m1_settle_<UTC>/. It turns the guests' TX offload on and back off, and reboots k8s-gpu2;
# SETTLE_ARGS=--skip-reboot leaves k8s-gpu2 alone.
settle:
	$(LABDIR)/settle.sh $(SETTLE_ARGS)

# The M1 sequence end to end (FRAMEWORK.md 6.2). Each line stops the sequence on failure.
exit-criteria:
	$(MAKE) render
	$(MAKE) up
	$(MAKE) up
	$(COMMON)/stages/run.sh status
	docker rm -f sfab-m1-k8s-gpu1
	$(MAKE) recover
	$(MAKE) audit
	$(MAKE) down
	$(MAKE) teardown-check
	$(MAKE) up
	$(MAKE) down
	$(MAKE) teardown-check
