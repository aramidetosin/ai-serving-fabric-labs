# images/keys/image.mk: sfab/keys, included by images/Makefile (FRAMEWORK.md section 5).
#
#   make -C images keys-fetch   the pinned PyYAML wheel into VENDOR_DIR/keys/, checked against its sha256
#   make -C images keys         sfab/keys:3 on sfab/client, with sfab-keys and PyYAML
#
# The pins come from spec/versions.yaml (images.keys, images.client, keys.pyyaml). The image
# rebuilds when its Dockerfile, sfab-keys, the client's build files or the wheel are newer than it.
# make -C images registry-seed pushes it into the in-lab registry (images.keys has mirror: local).

KEYS        := $(call IMAGE,keys)
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

check: check-keys

check-keys:
	@rc=0; python3 $(ROOT)/common/tools/namecheck.py $(KEYS_DIR) || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
	@python3 -m py_compile $(KEYS_DIR)/sfab-keys && echo "sfab-keys: compiles"
