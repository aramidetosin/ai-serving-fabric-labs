#!/usr/bin/env bash
# ch05/rpf.sh: how Linux combines the all and per-interface rp_filter values, on the relay's
# cross-rail flow (book Chapter 5, "Cross-Rail Relay with PXN and IP Routes"), recorded as
# audits/sfab-ch05_rpf_<UTC>/ with FOLLOWED.txt, verdict.txt and one directory a step: built/,
# case-a/, case-b/, case-c/ and restored/. common/reads/rpf.sh does the work; it changes rp_filter
# in k8s-gpu2's namespace gpu2 for the three cases and puts back the values it read, on any exit.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init rpf "$@"
# shellcheck source=common/reads/rpf.sh
. "$SFAB_COMMON/reads/rpf.sh"
rpf_run
