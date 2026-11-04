#!/usr/bin/env bash
# ch11/matrix.sh: every cell of the population and endpoint matrix, its mode asserted, saved as runs/sfab-ch11_matrix_<UTC>/ with matrix.md, results.txt, requests.tsv,
# lookups/, requests/, keys/, fw/, routers/ and api-gateway/.
#
# gen/matrix.json is the matrix as render/decisions.py computes it from the spec: chapter 2's four
# populations and the internet users from inet-client, against chapter 2's eleven endpoints and the
# internet Gateway, 60 cells, each with its mode, the layer that decides it and its isolation depth
# (the layers that would refuse it if every earlier layer let it through). Chapter 2's runner
# (common/matrix/matrix.sh and matrix.py) tries each cell from the population's own client and asserts
# its mode with its evidence. The internet users' chat cell names its own caller (key_caller inetapp
# in gen/matrix.json): its own request carries inetapp's key, and the checker wants the API gateway's
# access log to name that caller. matrix.md prints each cell's depth and its layers beside its
# evidence, and the checker checks the cells' depth counts against the plan's.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init matrix "$@"
# shellcheck source=common/matrix/matrix.sh
. "$SFAB_COMMON/matrix/matrix.sh"
matrix_run
