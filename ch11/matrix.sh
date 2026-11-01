#!/usr/bin/env bash
# ch11/matrix.sh: every cell of the population and endpoint matrix, its mode asserted (FRAMEWORK.md
# 4.8), recorded as audits/sfab-ch11_matrix_<UTC>/ with MATRIX.md, verdict.txt, requests.tsv,
# lookups/, requests/, keys/, fw/, routers/ and api-gateway/.
#
# gen/matrix.json is the matrix as render/decisions.py computes it from the spec: chapter 2's four
# populations and the internet users from inet-client, against chapter 2's eleven endpoints and the
# internet Gateway, 60 cells, each with its mode, the layer that decides it and its isolation depth
# (the layers that would refuse it if every earlier layer let it through). Chapter 2's runner
# (common/matrix/matrix.sh and matrix.py) tries each cell from the population's own client and asserts
# its mode with its evidence. The internet users' chat cell names its own caller (key_caller inetapp
# in gen/matrix.json); the runner's use of it, and the depth's evidence, land with the record stage.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init matrix "$@"
# shellcheck source=common/matrix/matrix.sh
. "$SFAB_COMMON/matrix/matrix.sh"
matrix_run
