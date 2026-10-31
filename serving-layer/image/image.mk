# serving-layer/image/image.mk: sfab/serving, included by images/Makefile (FRAMEWORK.md section 5).
#
#   make -C images serving-fetch   the image's inputs into VENDOR_DIR/serving/, each checked against its sha256
#   make -C images serving         sfab/serving:b11382-2 from debian:12-slim (pinned by digest)
#   make -C images models-fetch    the models into images/models (SFAB_MODELS_STORE=<dir>: into <dir>,
#                                  with images/models a link to it), each checked against its sha256;
#                                  the image holds no model
#   make -C images models-link     point images/models at SFAB_MODELS_STORE again (after a sync)
#
# The pins come from spec/versions.yaml: images.serving and images.debian_base, and under
# serving: the llama.cpp release asset and the two Debian packages; the models under serving.models. Each input is
# used where it already is when its sha256 matches and is downloaded once otherwise
# (images/fetch.py); the build reads them from the vendor directory as the named context "vendor"
# and checks each sha256 again. The image rebuilds when its Dockerfile, sfab-ready or an input is
# newer than it. make -C images registry-seed pushes it into the in-lab registry (mirror: local).

SERVING          := $(call IMAGE,serving)
SERVING_DIR      := $(ROOT)/serving-layer/image
SERVING_VENDOR   := $(VENDOR_DIR)/serving
DEBIAN_BASE      := $(call IMAGE,debian_base)
LLAMA_ASSET      := $(call PIN,serving.llama_cpp.asset)
LLAMA_SHA256     := $(call PIN,serving.llama_cpp.sha256)
MODELS_LINK      := $(IMG)/models
MODELS_DIR       ?= $(if $(SFAB_MODELS_STORE),$(SFAB_MODELS_STORE),$(MODELS_LINK))
LIBGOMP1_DEB     := $(call PIN,serving.debs.libgomp1.file)
LIBGOMP1_SHA256  := $(call PIN,serving.debs.libgomp1.sha256)
LIBSSL3_DEB      := $(call PIN,serving.debs.libssl3.file)
LIBSSL3_SHA256   := $(call PIN,serving.debs.libssl3.sha256)

.PHONY: serving serving-fetch models-fetch models-link check-serving

all: serving

serving-fetch:
	python3 $(IMG)/fetch.py serving.llama_cpp $(SERVING_VENDOR)
	python3 $(IMG)/fetch.py serving.debs.libgomp1 $(SERVING_VENDOR)/debs
	python3 $(IMG)/fetch.py serving.debs.libssl3 $(SERVING_VENDOR)/debs

# The models are large (14.5 GB and 16.5 GB): fetched once into MODELS_DIR, never into an image.
# A lab binds images/models read-only into its GPU nodes (render/clab.py), so the link must exist.
models-fetch: $(if $(SFAB_MODELS_STORE),models-link)
	python3 $(IMG)/fetch.py serving.models.chat $(MODELS_DIR)
	python3 $(IMG)/fetch.py serving.models.staff $(MODELS_DIR)

models-link:
	@[ -n "$(SFAB_MODELS_STORE)" ] || { echo "models-link: set SFAB_MODELS_STORE=<the directory that holds the models>" >&2; exit 2; }
	@mkdir -p "$(SFAB_MODELS_STORE)"
	@if [ -L "$(MODELS_LINK)" ] || [ ! -e "$(MODELS_LINK)" ]; then ln -sfn "$(SFAB_MODELS_STORE)" "$(MODELS_LINK)"; \
	  echo "images/models -> $(SFAB_MODELS_STORE)"; \
	else echo "models-link: images/models exists and is not a link; move its files to $(SFAB_MODELS_STORE) first" >&2; exit 1; fi

serving: serving-fetch
	$(BUILD) $(SERVING) $(SERVING_DIR) \
	  --watch $(SERVING_DIR)/Dockerfile --watch $(SERVING_DIR)/sfab-ready \
	  --watch $(SERVING_VENDOR)/$(LLAMA_ASSET) \
	  --watch $(SERVING_VENDOR)/debs/$(LIBGOMP1_DEB) --watch $(SERVING_VENDOR)/debs/$(LIBSSL3_DEB) \
	  -- --network $(BUILD_NETWORK) --build-context vendor=$(SERVING_VENDOR) \
	  --build-arg DEBIAN_BASE=$(DEBIAN_BASE) --build-arg IMAGE_VERSION=$(call TAG,$(SERVING)) \
	  --build-arg LLAMA_ASSET=$(LLAMA_ASSET) --build-arg LLAMA_SHA256=$(LLAMA_SHA256) \
	  --build-arg LIBGOMP1_DEB=$(LIBGOMP1_DEB) --build-arg LIBGOMP1_SHA256=$(LIBGOMP1_SHA256) \
	  --build-arg LIBSSL3_DEB=$(LIBSSL3_DEB) --build-arg LIBSSL3_SHA256=$(LIBSSL3_SHA256)

check: check-serving

check-serving:
	@rc=0; python3 $(ROOT)/common/tools/namecheck.py $(SERVING_DIR) || rc=$$?; [ $$rc -eq 0 ] || [ $$rc -eq 3 ]
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck -s bash $(SERVING_DIR)/sfab-ready && echo "shellcheck serving: clean"; \
	else echo "shellcheck: not installed; skipped"; fi
