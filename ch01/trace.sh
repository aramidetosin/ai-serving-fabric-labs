#!/usr/bin/env bash
# ch01/trace.sh: the request walk (book Examples 1-3 to 1-9; FRAMEWORK.md 4.5), recorded as
# audits/sfab-ch01_trace_<UTC>/ with TRACE.md, verdict.txt, dns/, fw/, pair/, rail/, cluster/,
# sessions/, request/, refuse/ and captures/.
#
# One chat completion from the enterprise client to chat through the users' Gateway, with chat's key
# (the batch caller's, handed to the client from its Secret as a 0600 header file, never printed)
# and its source port pinned, after one warm-up request, walked inward with every device's table:
# the resolver's view and answer; the firewall's route, NAT rulebase and security rule, and the
# session it holds while the connection is held open after the answer, then its traffic log line;
# the SYN on the client's port, on the firewall's enterprise interface and on one leg of ae1 (both
# legs captured), on the pair port that leg lands on and on that switch's port facing the lease
# holder (an ingress node), and on the lease holder's bond0, tagged 110 from the bundle on; the
# pair's MAC tables; the lease, the matched HTTPRoute, the API gateway's route and the key's mark at
# each in-cluster hop, the router's model list, the Service's ready endpoints, the server and its
# workers on the rail the placement table names; the rail switches' counters, cleared before the
# request and read after it, and their MAC tables (the copy the router picks: chat a or chat b keeps
# its RPC inside its node and puts nothing on a rail switch, chat c, which spans both nodes, crosses
# rail-sw1 on rail 7). Then three requests that must be refused, each recorded where it died: the
# admin hostname to the users' Gateway (404 at the Gateway, no API gateway pod sees it), staff's key
# (the helpdesk caller's) on chat's route (401 at the API gateway, no router pod receives it), and
# k8s-gpu1's SSH port (deny-all-log at the firewall, no SYN on either leg). The plan is
# chapter.yaml's trace block, rendered to gen/trace.json (common/trace/lib-walktrace.sh,
# common/trace/walktrace.py). The only change it makes on any device is the rail switches' interface
# counters, cleared before the request; every process it starts it stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-walktrace.sh
. "$SFAB_COMMON/trace/lib-walktrace.sh"
walktrace_run
