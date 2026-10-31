# images/registry/image.mk: sfab/registry and its seed, included by images/Makefile
# (FRAMEWORK.md section 5).
#
#   make -C images registry        sfab/registry:3 from registry:2 (distribution 2.8.3), pinned by digest
#   make -C images registry-plan   every image and chart the seed copies, from spec/versions.yaml
#   make -C images registry-seed   copy them into the registry's data, and push the images built
#                                  here (serving, keys) from this host's Docker; needs the internet, once
#   make -C images registry-check  verify the data holds every pin, offline
#   make -C images registry-link   point images/registry/data at the data again (after a sync)
#
# The data lives in images/registry/data (git ignores it), which the topology binds read-only
# into the lab's registry. With SFAB_IMAGE_STORE=<dir> it lives in <dir>/registry-data instead,
# and images/registry/data becomes a link to it. A checkout synced with rsync --delete must
# exclude images/registry/data, or the sync removes the link (registry-link puts it back).
# REGISTRY_DATA names another place.
# The seed runs a seeding registry on the host's loopback, port SEED_PORT (5099), in a container
# named SEED_NAME (sfab-registry-seed), and each skopeo copy in SEED_NAME-copy; it removes both
# when done. Charts are cached in VENDOR_DIR/charts (vendor/, ignored by git).

REG_IMAGE    := $(call IMAGE,registry)
REG_UPSTREAM := $(call IMAGE,registry_upstream)
REG_SKOPEO   := $(call IMAGE,skopeo)
REG_DIR      := $(IMG)/registry
REGISTRY_DATA ?= $(if $(SFAB_IMAGE_STORE),$(SFAB_IMAGE_STORE)/registry-data,$(REG_DIR)/data)
SEED_NAME    ?= sfab-registry-seed
SEED_PORT    ?= 5099
VENDOR_DIR   ?= $(ROOT)/vendor
SEED_WORK    ?= $(VENDOR_DIR)/tmp
REG_LINK     := $(if $(filter $(abspath $(REGISTRY_DATA)),$(abspath $(REG_DIR)/data)),,--link $(REG_DIR)/data)

.PHONY: registry registry-plan registry-seed registry-check registry-link check-registry

all: registry-seed

registry:
	$(BUILD) $(REG_IMAGE) $(REG_DIR) \
	  --watch $(REG_DIR)/Dockerfile --watch $(REG_DIR)/config.yml --watch $(REG_DIR)/seed.yml --watch $(IMG)/client/init.sh \
	  -- --network $(BUILD_NETWORK) --build-context client=$(IMG)/client \
	  --build-arg REGISTRY_BASE=$(REG_UPSTREAM) --build-arg IMAGE_VERSION=$(call TAG,$(REG_IMAGE))

registry-plan:
	@python3 $(REG_DIR)/seed.py plan

registry-seed: registry serving keys
	python3 $(REG_DIR)/seed.py run --data $(REGISTRY_DATA) --image $(REG_IMAGE) --skopeo $(REG_SKOPEO) \
	  --name $(SEED_NAME) --port $(SEED_PORT) --vendor $(VENDOR_DIR) --work $(SEED_WORK) $(REG_LINK)

registry-check:
	python3 $(REG_DIR)/seed.py check --data $(REGISTRY_DATA)
	@if [ -n "$(REG_LINK)" ] && [ "$$(readlink -f $(REG_DIR)/data)" != "$$(readlink -f $(REGISTRY_DATA))" ]; then \
	  echo "$(REG_DIR)/data does not lead to $(REGISTRY_DATA): run make -C images registry-link"; exit 1; fi

registry-link:
	@if [ -z "$(REG_LINK)" ]; then echo "the data lives in $(REG_DIR)/data itself; nothing to link"; \
	elif [ "$$(readlink -f $(REG_DIR)/data)" = "$$(readlink -f $(REGISTRY_DATA))" ]; then echo "$(REG_DIR)/data -> $(REGISTRY_DATA)"; \
	elif [ -e $(REG_DIR)/data ] && [ ! -L $(REG_DIR)/data ]; then echo "$(REG_DIR)/data is a directory; move it to $(REGISTRY_DATA) first"; exit 1; \
	else ln -sfn $(REGISTRY_DATA) $(REG_DIR)/data && echo "$(REG_DIR)/data -> $(REGISTRY_DATA)"; fi

check: check-registry

check-registry:
	@rc=0; python3 $(ROOT)/common/tools/namecheck.py $(REG_DIR)/Dockerfile $(REG_DIR)/config.yml $(REG_DIR)/seed.yml \
	    $(REG_DIR)/seed.py $(REG_DIR)/image.mk $(REG_DIR)/README.md || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
