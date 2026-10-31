#!/usr/bin/env bash
# ch02/trace.sh: chapter 1's request walk, each hop tagged with the row of the decision table that
# decides there (book Example 2-11; FRAMEWORK.md 4.5), recorded as audits/sfab-ch02_trace_<UTC>/
# with TRACE.md, verdict.txt, dns/, fw/, pair/, rail/, cluster/, sessions/, request/, refuse/ and
# captures/.
#
# The walk is chapter 1's (ch01/trace.sh): one chat completion from the enterprise client to chat
# through the users' Gateway, with chat's key handed to the client from its Secret as a 0600 header
# file, never printed, and its source port pinned, after one warm-up request, walked inward with every
# device's table, then three requests that must be refused, each recorded where it died. The plan,
# gen/trace.json, adds chapter 2's rows (render/trace.py, from decisions: true): TRACE.md's table of
# hops gains a Row column, the resolver view at the resolver, routing, NAT and security policy at the
# firewall, forwarding only at the bundle, the pair and the rail switch, the route set at the
# Gateway, the key at the API gateway and placement at the Service and the copy, and each refusal
# names its row (the route set, the key, security policy). The only change it makes on any device is
# the rail switches' interface counters, cleared before the request; every process it starts it stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init trace "$@"
# shellcheck source=common/trace/lib-walktrace.sh
. "$SFAB_COMMON/trace/lib-walktrace.sh"
walktrace_run
