#!/usr/bin/env bash
# ch11/drills.sh [--drills "ID ..."] [--passes N]: the chapter's drill (FRAMEWORK.md 4.6), recorded as
# audits/sfab-ch11_drills_<UTC>/ with pass<N>/<drill>/ and DRILLS.md. make drills runs it with
# PASSES=3.
#
#   isolation-under-load  every population holds chapter 10's connections and probes its own
#                         Gateway's /echo every 3 s while it tries the matrix's cells it must not
#                         reach (the other Gateways' VIPs, staff's path on the internet Gateway, the
#                         admin hostnames), ten rounds; one line a population with its allowed count
#                         and its zeros; then again at twice the held connections
#   leaked-key            the one cell no network layer holds: a new key of batch, an enterprise
#                         caller, minted by a key Job, sent from the internet client through the
#                         internet Gateway to chat until answered 200 and named under batch in the
#                         API gateway's access log; then revoked, and sent until refused 401
#
# The plan is chapter.yaml's drills block, rendered to gen/drills.json (common/drill/lib-p3drill.sh,
# common/drill/p3drill.py); the held connections are lib-tenancy.sh's.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init drills "$@"
# shellcheck source=common/drill/lib-p3drill.sh
. "$SFAB_COMMON/drill/lib-p3drill.sh"
p3drills_main
