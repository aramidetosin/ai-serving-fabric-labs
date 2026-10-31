# serving-layer/Makefile: the model-serving recipe (README.md). Every target reads one serving.env:
# a lab's bootstrap/k8s/serving.env (a chapter lab's `make serve` and `make load` pass it), or
# your own, written from serving.env.example.
#
#   make serve  SERVING_ENV=<file>                    deploy the recipe; a second run acts only on what changed
#   make load   SERVING_ENV=<file> USERS=10 SECONDS=60 concurrent streaming clients; failed and cut requests counted
#   make client SERVING_ENV=<file>                    one chat completion as an OpenAI-compatible client sends it (base URL and key only)
#   make status SERVING_ENV=<file>                    each pod's node, rail address and readiness; each Service's endpoints
#   make render SERVING_ENV=<file> [OUT=<dir>]        the manifests and the placement table, as files
#   make delete SERVING_ENV=<file>                    remove the recipe's namespace
#   make image                                        sfab/serving and sfab/keys (make -C ../images serving keys)
#   make test                                         the recipe's unit tests (no cluster needed)
#
# make load also takes RECORDS=<file> (one JSON line per request, written on this host),
# MAX_TOKENS=<n> (64), CUT_OK=1 (report streams cut mid-answer without failing on them) and
# URL=<base URL> (instead of SERVING_LOAD_URL); make client takes MAX_TOKENS and URL too.

PY          := PYTHONDONTWRITEBYTECODE=1 python3
HERE        := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
SERVING_ENV ?= $(HERE)/serving.env
OUT         ?= $(HERE)/rendered
USERS       ?= 10
SECONDS     ?= 60
MAX_TOKENS  ?= 64
RECORDS     ?=
CUT_OK      ?= 0
URL         ?=

.PHONY: help serve load client status render delete image test

help:
	@sed -n 's/^#   //p' $(HERE)/Makefile

serve:
	$(PY) $(HERE)/serving.py serve --env $(SERVING_ENV)

load:
	$(PY) $(HERE)/serving.py load --env $(SERVING_ENV) --users $(USERS) --seconds $(SECONDS) --max-tokens $(MAX_TOKENS) \
	  $(if $(RECORDS),--records $(RECORDS)) $(if $(filter 1,$(CUT_OK)),--cut-ok) $(if $(URL),--url $(URL))

client:
	$(PY) $(HERE)/serving.py client --env $(SERVING_ENV) --max-tokens $(MAX_TOKENS) $(if $(URL),--url $(URL))

status:
	$(PY) $(HERE)/serving.py status --env $(SERVING_ENV)

render:
	$(PY) $(HERE)/serving.py render --env $(SERVING_ENV) --out $(OUT)

delete:
	$(PY) $(HERE)/serving.py delete --env $(SERVING_ENV)

image:
	$(MAKE) -C $(HERE)/../images serving keys

test:
	$(PY) -m unittest discover -s $(HERE)/tests -t $(HERE)
