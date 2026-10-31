# images/bastion/image.mk: sfab/bastion, included by images/Makefile (FRAMEWORK.md section 5).
#
#   make -C images bastion    sfab/bastion:4 from ubuntu:24.04 (pinned by digest), the pinned
#                             archive snapshot, and kubectl, helm and cilium-cli at their pins
#
# Every pin comes from spec/versions.yaml: images.bastion and images.ubuntu_base,
# ubuntu_archive.snapshot, and kubernetes.kubectl, kubernetes.helm and kubernetes.cilium_cli
# (version and sha256 each). The image rebuilds when a file in images/bastion/ is newer than it.

BASTION          := $(call IMAGE,bastion)
BASTION_DIR      := $(IMG)/bastion
KUBECTL_VERSION  := $(call PIN,kubernetes.kubectl.version)
KUBECTL_SHA256   := $(call PIN,kubernetes.kubectl.sha256)
HELM_VERSION     := $(call PIN,kubernetes.helm.version)
HELM_SHA256      := $(call PIN,kubernetes.helm.sha256)
CILIUM_CLI_VERSION := $(call PIN,kubernetes.cilium_cli.version)
CILIUM_CLI_SHA256  := $(call PIN,kubernetes.cilium_cli.sha256)

.PHONY: bastion check-bastion

all: bastion

bastion:
	$(BUILD) $(BASTION) $(BASTION_DIR) -- --network $(BUILD_NETWORK) \
	  --build-arg UBUNTU_BASE=$(UBUNTU_BASE) --build-arg UBUNTU_SNAPSHOT=$(UBUNTU_SNAPSHOT) \
	  --build-arg KUBECTL_VERSION=$(KUBECTL_VERSION) --build-arg KUBECTL_SHA256=$(KUBECTL_SHA256) \
	  --build-arg HELM_VERSION=$(HELM_VERSION) --build-arg HELM_SHA256=$(HELM_SHA256) \
	  --build-arg CILIUM_CLI_VERSION=$(CILIUM_CLI_VERSION) --build-arg CILIUM_CLI_SHA256=$(CILIUM_CLI_SHA256) \
	  --build-arg IMAGE_VERSION=$(call TAG,$(BASTION))

check: check-bastion

check-bastion:
	@rc=0; python3 $(ROOT)/common/tools/namecheck.py $(BASTION_DIR) || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -s bash $(BASTION_DIR)/bastion-init.sh $(ROOT)/common/ca/sfab-ca && \
	  shellcheck -s sh $(BASTION_DIR)/operator-shell.sh && echo "shellcheck bastion: clean"; \
	else echo "shellcheck: not installed; skipped"; fi
