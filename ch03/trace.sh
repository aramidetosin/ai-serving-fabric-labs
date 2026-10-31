#!/usr/bin/env bash
# ch03/trace.sh [--flow ID]: the four-point SYN trace (book Example 3-5; FRAMEWORK.md 4.5), recorded
# as audits/sfab-ch03_trace_<UTC>/ with TRACE.md, verdict.txt and captures/.
#
# One SYN from the enterprise client to the users' VIP, 10.20.11.210 in the ingress VLAN, seen at
# four points: leaving the firewall on one ae1 leg tagged 110, entering the pair on the trunk port
# that leg lands on, leaving that switch tagged 110 on the server port toward the lease holder (an
# ingress node, whose bond carries VLAN 110 tagged beside its untagged node VLAN), and on the
# holder's bond0. The flow and the points are chapter.yaml's trace block; the lease holder, and so
# the server ports, are read when the trace runs. Each point with legs (ae1, the trunk ports, the
# server ports) is captured on both legs, so the point count is the decode count the verdict prints.
# With same_frame the judge also wants one frame at all four points: the same MACs, addresses, IP
# id, TTL and sequence number. Changes nothing on any device; every process it starts it stops
# (common/trace/lib-trace.sh).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-trace.sh
. "$SFAB_COMMON/trace/lib-trace.sh"
trace_run
