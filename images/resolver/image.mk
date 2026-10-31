# images/resolver/image.mk: sfab/resolver, included by images/Makefile (FRAMEWORK.md section 5).
#
#   make -C images resolver   sfab/resolver:3 from alpine:3.20 (pinned by digest), with BIND, dnsmasq
#                             and chrony at their pinned package versions
#
# Every pin comes from spec/versions.yaml: images.resolver (its packages.bind, packages.dnsmasq and
# packages.chrony) and images.alpine_base. The build takes images/client/init.sh (the network step)
# as a named context, so the client and the resolver run one copy of it. The image rebuilds when
# any of those files is newer than it.

RESOLVER         := $(call IMAGE,resolver)
RESOLVER_DIR     := $(IMG)/resolver
RESOLVER_BIND    := $(call PIN,images.resolver.packages.bind)
RESOLVER_DNSMASQ := $(call PIN,images.resolver.packages.dnsmasq)
RESOLVER_CHRONY  := $(call PIN,images.resolver.packages.chrony)

.PHONY: resolver check-resolver

all: resolver

resolver:
	$(BUILD) $(RESOLVER) $(RESOLVER_DIR) \
	  --watch $(RESOLVER_DIR) --watch $(IMG)/client/init.sh \
	  -- --network $(BUILD_NETWORK) --build-context client=$(IMG)/client \
	  --build-arg ALPINE_BASE=$(ALPINE_BASE) --build-arg BIND_VERSION=$(RESOLVER_BIND) \
	  --build-arg DNSMASQ_VERSION=$(RESOLVER_DNSMASQ) --build-arg CHRONY_VERSION=$(RESOLVER_CHRONY) \
	  --build-arg IMAGE_VERSION=$(call TAG,$(RESOLVER))

check: check-resolver

check-resolver:
	@rc=0; python3 $(ROOT)/common/tools/namecheck.py $(RESOLVER_DIR) || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -s bash $(RESOLVER_DIR)/resolver-init.sh $(RESOLVER_DIR)/resolver-run.sh $(RESOLVER_DIR)/sfab-dns $(RESOLVER_DIR)/sfab-ntp && \
	  echo "shellcheck resolver: clean"; \
	else echo "shellcheck: not installed; skipped"; fi
