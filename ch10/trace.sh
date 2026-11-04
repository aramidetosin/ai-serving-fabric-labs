#!/usr/bin/env bash
# ch10/trace.sh: Part III's trace, saved as runs/sfab-ch10_trace_<UTC>/ with
# trace.md, results.txt and captures/ (common/trace/lib-tenanttrace.sh, checked by common/trace/tenanttrace.py).
#
# The zone-keyed NAT trace (chapter.yaml trace.nat): one held HTTPS request per population to its
# own Gateway (chapter 4's held session: the firewall's session table read while it is held, the
# traffic log after it closes), each SYN followed by its sequence number from the point outside the
# firewall to the one leg of the bundle that carried it: the internet users' destination rewritten
# from the published address to the internet Gateway's VIP, the staff's and the operator's as sent.
# Changes nothing on any device; every process it starts it stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-tenanttrace.sh
. "$SFAB_COMMON/trace/lib-tenanttrace.sh"
tenanttrace_run
