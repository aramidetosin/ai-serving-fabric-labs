#!/usr/bin/env bash
# ch08/drills.sh [--drills "ID ..."] [--passes N]: the chapter's drill (FRAMEWORK.md 4.6), recorded as
# audits/sfab-ch08_drills_<UTC>/ with pass<N>/<drill>/ and DRILLS.md. make drills runs it with
# PASSES=3.
#
#   lease-holder-loss  the ingress node holding the most of the three Gateway leases (read when the
#                      pass begins) cut from the pair: KLISH shutdown on its two pair ports, fe-sw1's
#                      and fe-sw2's, held, then no shutdown. Measured with probes that need nothing on
#                      the cut node but its lease: a GET of the test backend's /echo every 2 s on a new
#                      connection through the users' Gateway (from the staff client) and through the
#                      internal Gateway (from the operator's client), a TCP connect to each of those
#                      VIPs every 0.5 s, the leases read every 0.5 s for the new holder, the firewall's
#                      ARP table before, during and after; a chat completion every 2 s through the
#                      users' Gateway recorded beside them and reported apart, with the pods' places and
#                      the EndpointSlices through the pass
#
# Every change is undone from the EXIT trap whatever happens, its restore pushed before the change.
# The plan is chapter.yaml's drills block, rendered to gen/drills.json (common/drill/lib-p3drill.sh,
# common/drill/p3drill.py).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init drills "$@"
# shellcheck source=common/drill/lib-p3drill.sh
. "$SFAB_COMMON/drill/lib-p3drill.sh"
p3drills_main
