# common/mk/chapter.mk: the make targets every lab shares (FRAMEWORK.md 3.6).
#
# A lab's Makefile is one line, `include ../common/mk/chapter.mk` (`../../common/mk/chapter.mk`
# under dev/). VARIANT=<key> selects the variant lab sfab-chNN<key>, rendered under
# variants/<key>/. BG=1 runs `make up` as the transient unit <lab>-up; follow it with
# `journalctl -fu <lab>-up`.
#
#   render check lint show       the generator (render writes, check diffs, lint checks)
#   ca ca-status                 the lab CA on the lab host (common/ca/sfab-ca): make or check it, sign
#                                and publish the node leaves, prove it; its subjects, expiries and
#                                constraints (no key). The up stage runs sfab-ca init before every deploy
#   up                           preflight up boot finish audit
#   deploy boot finish recover   one stage each; recover is boot then finish
#   audit trace drills accept    the lab's own scripts; accept is audit, trace, then drills
#   label matrix dbs             the lab's label.sh, matrix.sh and dbs.sh: the decision table's
#                                live objects, every cell of the matrix, a member through SONiC's DBs
#   rpf attach                   the lab's rpf.sh and attach.sh: rp_filter's all and per-interface
#                                values (chapter 5), a server pod's two networks (chapter 6)
#   record                       audit, trace, label and matrix (each the lab has), then
#                                common/audit/gate.sh on the new sets
#   break-<id> heal-<id> heal-all  common/breakheal.py
#   load serve client            serving-layer, with this lab's bootstrap/k8s/serving.env
#   status stop down wipe        down keeps state/ disks; wipe removes them
#   namecheck                    common/tools/namecheck.py over the repo (skipped without a scrub list)

SFAB_MK   := $(abspath $(lastword $(MAKEFILE_LIST)))
SFAB_ROOT := $(abspath $(dir $(SFAB_MK))/../..)
LABDIR    := $(abspath $(CURDIR))
COMMON    := $(SFAB_ROOT)/common
SFAB      := $(COMMON)/bin/sfab
RUN       := $(COMMON)/stages/run.sh
PY        := PYTHONDONTWRITEBYTECODE=1 python3

VARIANT ?=
RENDERDIR := $(if $(VARIANT),$(LABDIR)/variants/$(VARIANT),$(LABDIR))
LAB       := $(or $(shell $(PY) $(COMMON)/bin/inv.py --inv $(RENDERDIR)/gen/inventory.json get lab 2>/dev/null),sfab-$(notdir $(LABDIR))$(VARIANT))
VARG      := $(if $(VARIANT),--variant $(VARIANT),)

export SFAB_LABDIR := $(LABDIR)
export VARIANT

DRILLS ?=
PASSES ?= 3
BG     ?= 0

# the unit does not inherit the caller's environment: pass on the labs commit when it is exported
# (common/bin/repostate.py)
REPOENV = $(if $(SFAB_REPO_COMMIT),--setenv=SFAB_REPO_COMMIT=$(SFAB_REPO_COMMIT)) \
          $(if $(SFAB_REPO_DIRTY),--setenv=SFAB_REPO_DIRTY=$(SFAB_REPO_DIRTY))

ifeq ($(BG),1)
RUNUP = systemd-run --unit=$(LAB)-up --collect --working-directory=$(LABDIR) --setenv=SFAB_LABDIR=$(LABDIR) --setenv=VARIANT=$(VARIANT) $(REPOENV) $(RUN)
else
RUNUP = $(RUN)
endif

.PHONY: render check lint show ca ca-status up deploy boot finish recover audit trace label matrix dbs rpf attach drills accept record \
        heal-all load serve client status stop down wipe namecheck help

help:
	@sed -n 's/^#   //p' $(SFAB_MK)

render:
	$(SFAB) render $(LABDIR) $(VARG)

check:
	$(SFAB) check $(LABDIR) $(VARG)

lint:
	$(SFAB) lint $(LABDIR) $(VARG)

ca:
	$(COMMON)/ca/sfab-ca -C $(RENDERDIR) init

ca-status:
	$(COMMON)/ca/sfab-ca -C $(RENDERDIR) status

show:
	$(SFAB) show $(LABDIR) $(VARG) $(WHAT)

up:
	$(RUNUP) preflight up boot finish audit
ifeq ($(BG),1)
	@echo "follow it with: journalctl -fu $(LAB)-up"
endif

deploy:
	$(RUN) preflight up

boot:
	$(RUN) boot

finish:
	$(RUN) finish

recover:
	$(RUN) recover

audit:
	$(RUN) audit

trace:
	$(RUN) trace

label matrix dbs rpf attach:
	@test -x $(LABDIR)/$@.sh || { echo "$(LAB) has no $@.sh"; exit 1; }
	$(RUN) $@

drills:
	@test -x $(LABDIR)/drills.sh || { echo "$(LAB) has no drills.sh"; exit 1; }
	$(LABDIR)/drills.sh $(if $(DRILLS),--drills "$(DRILLS)",) --passes $(PASSES)

accept: audit trace
	@if [ -x $(LABDIR)/drills.sh ]; then $(MAKE) --no-print-directory drills; else echo "$(LAB) has no drills.sh"; fi

# record: audit, then trace, label and matrix (each when the lab has one), then the gate on the result
# sets this target made.
record:
	@mark=$$(mktemp); trap 'rm -f $$mark' EXIT; \
	$(RUN) audit && { [ ! -x $(LABDIR)/trace.sh ] || $(RUN) trace; } && { [ ! -x $(LABDIR)/label.sh ] || $(RUN) label; } && \
	  { [ ! -x $(LABDIR)/matrix.sh ] || $(RUN) matrix; }; rc=$$?; \
	sets=$$(find $(RENDERDIR)/audits -mindepth 1 -maxdepth 1 -type d -newer $$mark -name '$(LAB)_*' 2>/dev/null | sort); \
	[ -n "$$sets" ] || { echo "record: no new result set"; exit 1; }; \
	$(COMMON)/audit/gate.sh $$sets && exit $$rc

break-%:
	$(PY) $(COMMON)/breakheal.py break $*

heal-%:
	$(PY) $(COMMON)/breakheal.py heal $*

heal-all:
	$(PY) $(COMMON)/breakheal.py heal all

serve load client:
	@test -f $(RENDERDIR)/bootstrap/k8s/serving.env || { echo "$(LAB) renders no bootstrap/k8s/serving.env"; exit 1; }
	$(MAKE) -C $(SFAB_ROOT)/serving-layer $@ SERVING_ENV=$(RENDERDIR)/bootstrap/k8s/serving.env

status:
	@$(RUN) status

stop:
	$(RUN) stop

down:
	$(RUN) down

wipe:
	$(RUN) wipe

namecheck:
	@rc=0; $(PY) $(COMMON)/tools/namecheck.py || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
