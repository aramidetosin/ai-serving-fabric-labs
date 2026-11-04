# images/vpngw/image.mk: sfab/vpngw, included by images/Makefile.
#
#   make -C images vpngw   sfab/vpngw:3 on sfab/client, with strongSwan, GMP, openssh-server (and
#                          its common files) and sudo at their pinned versions and sha256 sums
#
# Every pin comes from spec/versions.yaml: images.vpngw (its packages and sha256) and images.client,
# which it is built on (make -C images client first). The image rebuilds when any file here is newer.

VPNGW        := $(call IMAGE,vpngw)
VPNGW_DIR    := $(IMG)/vpngw

.PHONY: vpngw check-vpngw

all: vpngw

vpngw: client
	$(BUILD) $(VPNGW) $(VPNGW_DIR) --watch $(VPNGW_DIR) \
	  -- --network $(BUILD_NETWORK) --build-arg CLIENT_BASE=$(CLIENT) \
	  --build-arg STRONGSWAN_VERSION=$(call PIN,images.vpngw.packages.strongswan) \
	  --build-arg STRONGSWAN_SHA256=$(call PIN,images.vpngw.sha256.strongswan) \
	  --build-arg GMP_VERSION=$(call PIN,images.vpngw.packages.gmp) \
	  --build-arg GMP_SHA256=$(call PIN,images.vpngw.sha256.gmp) \
	  --build-arg OPENSSH_VERSION=$(call PIN,images.vpngw.packages.openssh_server) \
	  --build-arg OPENSSH_SHA256=$(call PIN,images.vpngw.sha256.openssh_server) \
	  --build-arg OPENSSH_COMMON_SHA256=$(call PIN,images.vpngw.sha256.openssh_server_common) \
	  --build-arg SUDO_VERSION=$(call PIN,images.vpngw.packages.sudo) \
	  --build-arg SUDO_SHA256=$(call PIN,images.vpngw.sha256.sudo) \
	  --build-arg IMAGE_VERSION=$(call TAG,$(VPNGW))

check: check-vpngw

check-vpngw:
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -s bash $(VPNGW_DIR)/vpngw-init.sh $(VPNGW_DIR)/vpngw-run.sh && echo "shellcheck vpngw: clean"; \
	else echo "shellcheck: not installed; skipped"; fi
