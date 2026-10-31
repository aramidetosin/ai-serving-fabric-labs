#!/usr/bin/env bash
# ch05/drills.sh [--drills "ID ..."] [--passes N]: the chapter's dark-switch drill (book Examples 5-8
# and 5-9; FRAMEWORK.md 4.6), recorded as audits/sfab-ch05_drills_<UTC>/ with pass<N>/<drill>/ and
# DRILLS.md. make drills runs it with PASSES=3.
#
#   dark-switch   every port rail-sw1 uses shut in one KLISH session (interface range
#                 Ethernet0-7, shutdown), held 30 s, then given no shutdown. The rails probe runs
#                 from k8s-gpu1 throughout, one ping per row under its own ICMP id: the same rail on all
#                 eight rails, and three cross-rail rows (rail 2 to rail 1, into the dead rail;
#                 rail 1 to rail 2, out of it; rail 2 to rail 4, between live rails). The odd rails
#                 go silent, the even rails keep answering, and both cross-rail rows that touch an
#                 odd rail fail with nothing routing around them; after the no shutdown the odd
#                 rails answer again, timed from the restore's session start as an event.
#
# The restore is pushed before the shut, run from the EXIT trap whatever happens. Every time is the
# lab host's clock: tcpdump on the host in both nodes' container ports on every rail, and preflight's
# host tick of 10000 checked when the result set opens. A lost ping is a round trip. The plan is
# chapter.yaml's drills block, rendered to gen/drills.json (common/drill/lib-raildrill.sh).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init drills "$@"
# shellcheck source=common/drill/lib-raildrill.sh
. "$SFAB_COMMON/drill/lib-raildrill.sh"
raildrills_main
