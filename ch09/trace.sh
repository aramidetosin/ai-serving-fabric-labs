#!/usr/bin/env bash
# ch09/trace.sh: Part III's trace, saved as runs/sfab-ch09_trace_<UTC>/ with
# trace.md, results.txt and captures/ (common/trace/lib-tenanttrace.sh, checked by common/trace/tenanttrace.py).
#
# The split-horizon trace (chapter.yaml trace.dns): each population's lookup of the users' hostname
# captured at its own resolver, the resolver's query to its authority (or its cached answer), then the
# population's connect toward the answer, at the rungs the firewall's render says it reaches: the
# staff's through the firewall's enterprise port and one leg (allowed), the nodes' answered on
# k8s-cp2 itself, the internet users' on the ISP router's link and logged by deny-all-log from isp to
# isp, with nothing on the bundle.
# Changes nothing on any device; every process it starts it stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-tenanttrace.sh
. "$SFAB_COMMON/trace/lib-tenanttrace.sh"
tenanttrace_run
