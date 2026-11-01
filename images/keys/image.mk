# images/keys/image.mk: sfab/keys, included by images/Makefile (FRAMEWORK.md section 5).
#
#   make -C images keys-fetch   the pinned PyYAML wheel into VENDOR_DIR/keys/, checked against its sha256
#   make -C images keys         sfab/keys:4 on sfab/client, with sfab-keys and PyYAML
#
# The pins come from spec/versions.yaml (images.keys_audience, images.client, keys.pyyaml). This
# source builds sfab/keys:4, the tool of chapter 8 on, whose mint adds the audience refusal; every
# call that names no audience runs as on sfab/keys:3 (images.keys), the tool chapters 1 to 7 were
# recorded with, which the lab host keeps from its own build. The image rebuilds when its
# Dockerfile, sfab-keys, the client's build files or the wheel are newer than it. A host that has no
# sfab/keys:3 (a fresh clone) gets the sfab/keys:4 build tagged sfab/keys:3 as well, so chapters 1
# to 7 run on it; a host that has one keeps it untouched. make -C images registry-seed pushes both
# into the in-lab registry (each has mirror: local).

KEYS        := $(call IMAGE,keys_audience)
KEYS_PRIOR  := $(call IMAGE,keys)
KEYS_DIR    := $(IMG)/keys
KEYS_VENDOR := $(VENDOR_DIR)/keys
PYYAML_WHEEL   := $(call PIN,keys.pyyaml.file)
PYYAML_SHA256  := $(call PIN,keys.pyyaml.sha256)
PYYAML_VERSION := $(call PIN,keys.pyyaml.version)

.PHONY: keys keys-fetch check-keys

all: keys

keys-fetch:
	python3 $(IMG)/fetch.py keys.pyyaml $(KEYS_VENDOR)

keys: client keys-fetch
	$(BUILD) $(KEYS) $(KEYS_DIR) \
	  --watch $(KEYS_DIR)/Dockerfile --watch $(KEYS_DIR)/sfab-keys --watch $(IMG)/client \
	  --watch $(KEYS_VENDOR)/$(PYYAML_WHEEL) \
	  -- --network $(BUILD_NETWORK) --build-context vendor=$(KEYS_VENDOR) \
	  --build-arg CLIENT_IMAGE=$(CLIENT) --build-arg PYYAML_WHEEL=$(PYYAML_WHEEL) \
	  --build-arg PYYAML_SHA256=$(PYYAML_SHA256) --build-arg PYYAML_VERSION=$(PYYAML_VERSION) \
	  --build-arg IMAGE_VERSION=$(call TAG,$(KEYS))
	@if docker image inspect $(KEYS_PRIOR) >/dev/null 2>&1; then echo "[build] $(KEYS_PRIOR): present, kept"; \
	  else docker tag $(KEYS) $(KEYS_PRIOR) && echo "[build] $(KEYS_PRIOR): none on this host, tagged from $(KEYS)"; fi

check: check-keys

check-keys:
	@rc=0; python3 $(ROOT)/common/tools/namecheck.py $(KEYS_DIR) || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
	@python3 -m py_compile $(KEYS_DIR)/sfab-keys && echo "sfab-keys: compiles"
