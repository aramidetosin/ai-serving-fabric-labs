#!/usr/bin/env bash
# ch06/drills.sh [--drills "ID ..."] [--passes N]: the chapter's placement drills (book Examples 6-6,
# 6-7, 6-9 and 6-10; FRAMEWORK.md 4.6), recorded as audits/sfab-ch06_drills_<UTC>/ with
# pass<N>/<drill>/ and DRILLS.md. make drills runs it with PASSES=3.
#
#   dark-switch   every port rail-sw1 uses shut in one KLISH session (interface range
#                 Ethernet0-7, shutdown), held 40 s, then given no shutdown: chat's copy c, which
#                 spans both nodes on rail 7, loses its worker on k8s-gpu2, fails its readiness probe
#                 over the rail and leaves its Services; the node-local copies on rail-sw1's rails
#                 (chat a on rail 3, staff b on rail 5) keep their RPC inside their nodes and stay,
#                 since a KLISH shutdown drops no carrier at the rail NICs (KNOWN L9: on hardware they
#                 would leave too); chat b and staff a, on rail-sw2's rails, keep answering, and no
#                 request through the Gateway fails.
#   worker-port   the one port of rail-sw1 facing chat-c's worker0 on k8s-gpu2 (rail 7) shut, held,
#                 then given no shutdown: chat-c leaves its Services while chat-a and chat-b answer.
#   rail-move     chat-a's worker0 moved to rail 5 in the table: the recipe refuses to render the
#                 manifests from it, and audit.sh against it fails first, nothing in the cluster
#                 having moved; then audit.sh against the table as rendered is green.
#
# Under both faults the gateway probe sends one chat completion every 2 s to each model through the
# users' Gateway from the enterprise client, each request on its own and waiting up to 400 s, and
# the serving Services' EndpointSlices are read every second: the analysis times when each server
# left and rejoined its Services against the readiness bound, counts the requests by when they were
# sent and how they ended, and names the answers the router had to try again for. The restore is
# pushed before the shut, run from the EXIT trap whatever happens. Every time is the lab host's
# clock, and preflight's host tick of 10000 is checked when the result set opens. The plan is
# chapter.yaml's drills block, rendered to gen/drills.json (common/drill/lib-servedrill.sh).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init drills "$@"
# shellcheck source=common/drill/lib-servedrill.sh
. "$SFAB_COMMON/drill/lib-servedrill.sh"
servedrills_main
