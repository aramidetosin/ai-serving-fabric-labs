# images/Makefile: the sfab images every lab runs (FRAMEWORK.md section 5).
#
#   make -C images all            every image below and the registry seed; the one step that needs the internet
#   make -C images client         sfab/client (pinned Alpine plus the test tools)
#   make -C images vm-node-fetch  the pinned Ubuntu 24.04 cloud image, checked against its sha256
#   make -C images vm-node-base   bake node.qcow2 from it (containerd, kubeadm, storage clients)
#   make -C images vm-node        sfab/vm-node with the baked disk inside it
#   make -C images bastion        sfab/bastion (bastion/image.mk)
#   make -C images resolver       sfab/resolver (resolver/image.mk)
#   make -C images frr            sfab/frr (frr/image.mk)
#   make -C images registry       sfab/registry; registry-seed, registry-check, registry-link (registry/image.mk)
#   make -C images serving        sfab/serving, the model server; serving-fetch (serving-layer/image/image.mk)
#   make -C images keys           sfab/keys:4, the API key tool; keys-fetch (keys/image.mk)
#   make -C images check          namecheck and shellcheck over the build contexts
#   make -C images pins           print the pins this Makefile reads
#
# Every pin comes from spec/versions.yaml through versions.py. An image is rebuilt only when it is
# missing or a file it is built from is newer than it (FORCE=1 rebuilds anyway). The cloud image
# and the baked disk live under vm-node/base/, which git ignores, unless SFAB_IMAGE_STORE names a
# directory outside the checkout (see below). The serving image's and the key tool's pinned inputs
# sit in VENDOR_DIR (vendor/ in the checkout, which git ignores), with the charts the registry seed
# caches. Builds need BuildKit (docker 23 or later).

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

IMG  := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
ROOT := $(patsubst %/,%,$(dir $(IMG)))
PIN   = $(shell python3 $(IMG)/versions.py get $(1))
IMAGE = $(shell python3 $(IMG)/versions.py image $(1))
TAG   = $(lastword $(subst :, ,$(1)))

UBUNTU_BASE    := $(call IMAGE,ubuntu_base)
ALPINE_BASE    := $(call IMAGE,alpine_base)
VM_NODE        := $(call IMAGE,vm_node)
VM_RUNTIME     := $(VM_NODE)-runtime
CLIENT         := $(call IMAGE,client)
K8S_VERSION    := $(call PIN,kubernetes.version)
UBUNTU_RELEASE := $(call PIN,guest.ubuntu_cloud_image.release)
# The cloud image pin, from versions.yaml; UBUNTU_SERIAL and UBUNTU_SHA256 on the command line override it.
UBUNTU_SERIAL  ?= $(call PIN,guest.ubuntu_cloud_image.serial)
UBUNTU_SHA256  ?= $(call PIN,guest.ubuntu_cloud_image.sha256)
UBUNTU_IMAGE   := ubuntu-$(UBUNTU_RELEASE)-server-cloudimg-amd64.img
UBUNTU_URL     := https://cloud-images.ubuntu.com/releases/$(UBUNTU_RELEASE)/release-$(UBUNTU_SERIAL)/$(UBUNTU_IMAGE)
# The archive snapshot every Ubuntu package comes from, and the Kubernetes package versions.
UBUNTU_SNAPSHOT := $(call PIN,ubuntu_archive.snapshot)
K8S_PKG_VERSION := $(call PIN,kubernetes.packages.kubeadm)
K8S_CNI_VERSION := $(call PIN,kubernetes.packages.kubernetes_cni)
CRI_TOOLS_VERSION := $(call PIN,kubernetes.packages.cri_tools)

# Build and bake networking. host, the default, runs the build steps and the bake in the host's
# own network namespace, on its routes and resolver, rather than behind a Docker bridge.
BUILD_NETWORK ?= host
BUILD := $(IMG)/build-if-stale.sh

VMN  := $(IMG)/vm-node
# Where the large files live. By default the cloud image sits in vm-node/base/cache/ and the bake
# writes vm-node/base/, both ignored by git. A host that syncs the checkout with rsync --delete
# keeps them outside it: SFAB_IMAGE_STORE=<dir> finds (or fetches) the cloud image at
# <dir>/<its official name> and bakes into <dir>/vm-node-base/. CLOUD_IMAGE_DIR and VM_NODE_BASE
# set the two places one by one.
SFAB_IMAGE_STORE ?=
CLOUD_IMAGE_DIR ?= $(if $(SFAB_IMAGE_STORE),$(SFAB_IMAGE_STORE),$(VMN)/base/cache)
VM_NODE_BASE ?= $(if $(SFAB_IMAGE_STORE),$(SFAB_IMAGE_STORE)/vm-node-base,$(VMN)/base)
BASE := $(patsubst %/,%,$(VM_NODE_BASE))
CLOUD_IMAGE := $(patsubst %/,%,$(CLOUD_IMAGE_DIR))/$(UBUNTU_IMAGE)
BAKE_FILES := $(VMN)/bake/bake.sh $(VMN)/bake/provision.sh $(VMN)/bake/user-data-bake.tmpl
CONTEXTS := $(IMG)/client $(IMG)/vm-node
# The pinned files the builds and the registry seed read (images/fetch.py puts them there).
VENDOR_DIR ?= $(ROOT)/vendor

# Each other image brings its own targets, adding itself to all and check: <image>/image.mk, and
# the serving image's in serving-layer/image/.
include $(sort $(wildcard $(IMG)/*/image.mk))
include $(ROOT)/serving-layer/image/image.mk

.PHONY: help all client vm-node-runtime vm-node-fetch vm-node-base vm-node check pins clean FORCE

help:
	@sed -n '3,15p' $(IMG)/Makefile | sed 's/^# //'

all: client vm-node

pins:
	@printf '%-16s %s\n' ubuntu_base "$(UBUNTU_BASE)" alpine_base "$(ALPINE_BASE)" \
	  vm_node "$(VM_NODE)" client "$(CLIENT)" kubernetes "$(K8S_VERSION)" \
	  k8s_packages "kubeadm $(K8S_PKG_VERSION), kubernetes-cni $(K8S_CNI_VERSION), cri-tools $(CRI_TOOLS_VERSION)" \
	  cloud_image "$(UBUNTU_IMAGE) release-$(or $(UBUNTU_SERIAL),<unpinned>)" \
	  cloud_sha256 "$(or $(UBUNTU_SHA256),<unpinned>)" \
	  archive "$(or $(UBUNTU_SNAPSHOT),<live archive>)" \
	  cloud_file "$(CLOUD_IMAGE)" bake_dir "$(BASE)"

# ------------------------------------------------------------------------------------------
client:
	$(BUILD) $(CLIENT) $(IMG)/client -- --network $(BUILD_NETWORK) \
	  --build-arg ALPINE_BASE=$(ALPINE_BASE) --build-arg IMAGE_VERSION=$(call TAG,$(CLIENT))

# ------------------------------------------------------------------------------------------
# The runtime: QEMU and the tools, from the pinned archive snapshot. It rebuilds when the
# Dockerfile or a pin changes.
vm-node-runtime: $(BASE)/.pins
	$(BUILD) $(VM_RUNTIME) $(VMN) --watch $(VMN)/Dockerfile --watch $(BASE)/.pins -- --network $(BUILD_NETWORK) \
	  --target runtime --build-arg UBUNTU_BASE=$(UBUNTU_BASE) --build-arg UBUNTU_SNAPSHOT=$(UBUNTU_SNAPSHOT)

vm-node-fetch: $(BASE)/cloud-image.ok

# The pinned cloud image: used where it already is when its sha256 matches, fetched once otherwise.
$(BASE)/cloud-image.ok: $(BASE)/.pins
	@if [ -z "$(UBUNTU_SERIAL)" ] || [ -z "$(UBUNTU_SHA256)" ]; then \
	  echo "guest.ubuntu_cloud_image in spec/versions.yaml has no serial or sha256 yet;"; \
	  echo "pin them there, or give UBUNTU_SERIAL=... UBUNTU_SHA256=... on the command line"; exit 1; fi
	mkdir -p "$(dir $(CLOUD_IMAGE))"
	if [ -f "$(CLOUD_IMAGE)" ] && [ "$$(sha256sum < "$(CLOUD_IMAGE)" | cut -c1-64)" = "$(UBUNTU_SHA256)" ]; then \
	  echo "[fetch] $(CLOUD_IMAGE) is the pinned image; nothing to download"; \
	else \
	  echo "[fetch] downloading $(UBUNTU_URL)"; \
	  curl -fL --retry 5 --retry-delay 10 -o "$(CLOUD_IMAGE).part" "$(UBUNTU_URL)"; \
	  have=$$(sha256sum < "$(CLOUD_IMAGE).part" | cut -c1-64); \
	  if [ "$$have" != "$(UBUNTU_SHA256)" ]; then \
	    echo "the download has sha256 $$have, the pin says $(UBUNTU_SHA256)"; rm -f "$(CLOUD_IMAGE).part"; exit 1; fi; \
	  mv -f "$(CLOUD_IMAGE).part" "$(CLOUD_IMAGE)"; fi
	printf '%s %s\n' "$(UBUNTU_SHA256)" "$(CLOUD_IMAGE)" > $@

# The pins the bake depends on, rewritten only when they change, so a new pin re-bakes.
$(BASE)/.pins: FORCE
	@mkdir -p $(BASE)
	@want="$(UBUNTU_BASE) $(UBUNTU_IMAGE) $(UBUNTU_SERIAL) $(UBUNTU_SHA256) $(UBUNTU_SNAPSHOT) $(K8S_VERSION) $(K8S_PKG_VERSION) $(K8S_CNI_VERSION) $(CRI_TOOLS_VERSION)"; \
	if [ "$$(cat $@ 2>/dev/null || true)" != "$$want" ]; then printf '%s\n' "$$want" > $@; fi

vm-node-base: $(BASE)/node.id

$(BASE)/node.id: $(BAKE_FILES) $(BASE)/.pins | vm-node-runtime vm-node-fetch
	docker run --rm --network $(BUILD_NETWORK) --device /dev/kvm \
	  -v $(BASE):/out -v $(VMN)/bake:/bake:ro -v "$(CLOUD_IMAGE)":/in/$(UBUNTU_IMAGE):ro \
	  -e UBUNTU_IMAGE=$(UBUNTU_IMAGE) -e UBUNTU_IMAGE_PATH=/in/$(UBUNTU_IMAGE) -e UBUNTU_SHA256=$(UBUNTU_SHA256) \
	  -e UBUNTU_SNAPSHOT=$(UBUNTU_SNAPSHOT) -e K8S_VERSION=$(K8S_VERSION) -e K8S_PKG_VERSION=$(K8S_PKG_VERSION) \
	  -e K8S_CNI_VERSION=$(K8S_CNI_VERSION) -e CRI_TOOLS_VERSION=$(CRI_TOOLS_VERSION) \
	  $(VM_RUNTIME) bash /bake/bake.sh

# The node: the runtime plus the baked disk, which comes in as the named build context "base", so
# the disk can sit outside the checkout.
vm-node: $(BASE)/node.id
	$(BUILD) $(VM_NODE) $(VMN) \
	  --watch $(VMN)/Dockerfile --watch $(VMN)/vm-init.sh --watch $(VMN)/node-files \
	  --watch $(BASE)/node.qcow2 --watch $(BASE)/node.id --watch $(BASE)/.pins \
	  -- --network $(BUILD_NETWORK) --target node --build-context base=$(BASE) \
	  --build-arg UBUNTU_BASE=$(UBUNTU_BASE) --build-arg UBUNTU_SNAPSHOT=$(UBUNTU_SNAPSHOT) \
	  --build-arg IMAGE_VERSION=$(call TAG,$(VM_NODE))

# ------------------------------------------------------------------------------------------
check:
	@rc=0; python3 $(ROOT)/common/tools/namecheck.py $(CONTEXTS) $(IMG)/Makefile $(IMG)/README.md $(IMG)/versions.py $(IMG)/fetch.py || rc=$$?; \
	  [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -s bash $(IMG)/build-if-stale.sh $(VMN)/vm-init.sh $(VMN)/node-files/*.sh \
	    $(VMN)/bake/*.sh $(IMG)/client/*.sh && echo "shellcheck: clean"; \
	else echo "shellcheck: not installed; skipped"; fi

clean:
	rm -rf $(BASE)/work "$(CLOUD_IMAGE).part"
