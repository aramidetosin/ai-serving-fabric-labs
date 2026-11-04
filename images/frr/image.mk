# images/frr/image.mk: sfab/frr, included by images/Makefile.
#
#   make -C images frr        sfab/frr:10.5.4-3 from quay.io/frrouting/frr:10.5.4, pinned by digest
#
# Both pins come from spec/versions.yaml (images.frr and images.frr_upstream). The image rebuilds
# when a file that goes into it (Dockerfile, frr-init.sh, frr-restore.sh) is newer than it.

FRR          := $(call IMAGE,frr)
FRR_UPSTREAM := $(call IMAGE,frr_upstream)
FRR_DIR      := $(IMG)/frr

.PHONY: frr check-frr

all: frr

frr:
	$(BUILD) $(FRR) $(FRR_DIR) \
	  --watch $(FRR_DIR)/Dockerfile --watch $(FRR_DIR)/frr-init.sh --watch $(FRR_DIR)/frr-restore.sh \
	  -- --network $(BUILD_NETWORK) \
	  --build-arg FRR_BASE=$(FRR_UPSTREAM) --build-arg IMAGE_VERSION=$(call TAG,$(FRR))

check: check-frr

check-frr:
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -s bash $(FRR_DIR)/frr-init.sh $(FRR_DIR)/frr-restore.sh && echo "shellcheck frr: clean"; \
	else echo "shellcheck: not installed; skipped"; fi
