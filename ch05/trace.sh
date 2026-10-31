#!/usr/bin/env bash
# ch05/trace.sh: the rail trace (book Examples 5-5 to 5-7 and 5-10; FRAMEWORK.md 4.5), recorded as
# audits/sfab-ch05_trace_<UTC>/ with TRACE.md, verdict.txt, health/, flows/, df/, captures/ and
# captures-df/.
#
# First the same rail on every rail: one ping from each of k8s-gpu1's GPU namespaces to k8s-gpu2's address
# on that rail. Then the two flows of chapter.yaml's trace block, from k8s-gpu1's namespace gpu1, each a
# ping under its own ICMP id, captured on both nodes' relay bridges and on the rail switches' ports
# facing each node on rails 1 and 2: same-rail (to k8s-gpu2's rail 1 address: request and reply on
# rail-sw1, TTL 64) and cross-rail (to k8s-gpu2's rail 2 address: the request through k8s-gpu1's relay onto
# rail 2 and rail-sw2, the reply through k8s-gpu2's relay onto rail 1 and rail-sw1, TTL 63). Then
# traceroute for each flow, and the DF probe matrix: both flows both ways at 9000 and 9001 bytes
# with the don't-fragment bit set, captured again. The plan is gen/trace.json; the judgment and
# TRACE.md are common/trace/railtrace.py's. Changes nothing on any device; every process it starts
# it stops (common/trace/lib-railtrace.sh).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-railtrace.sh
. "$SFAB_COMMON/trace/lib-railtrace.sh"
railtrace_run
