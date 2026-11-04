# Render checks across every lab. Each lab has its own Makefile for running it.
#
#   make check   sfab check on every lab: a fresh render matches the committed files

LABS := $(sort $(patsubst %/chapter.yaml,%,$(wildcard ch[0-9][0-9]/chapter.yaml)))

.PHONY: check labs

check: labs

labs:
	@rc=0; for lab in $(LABS); do common/bin/sfab check $$lab || rc=1; done; exit $$rc
