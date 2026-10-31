#!/usr/bin/env bash
# ch07/drills.sh [--drills "ID ..."] [--passes N]: the chapter's gateway drills (book Examples 7-10
# and 7-11; FRAMEWORK.md 4.6), recorded as audits/sfab-ch07_drills_<UTC>/ with pass<N>/<drill>/ and
# DRILLS.md. make drills runs it with PASSES=3; idle-timeout runs in the first pass only (its
# max_passes), since each run rolls Cilium twice.
#
#   key-lifecycle  under the gateway probe (one chat completion every 2 s to chat and every 30 s to
#                  staff through the users' Gateway with each model's key, the first key of the first application
#                  caller that may call it, which must lose nothing): one new key for chat's caller
#                  (batch) minted into the key Secret by a Job of the key tool; the per-pod
#                  probe (every API gateway pod by its address) and requests through the users' VIP
#                  with it, every 2 s, until every pod accepts it: the Secret's write, the first
#                  200 through the VIP and the last pod's acceptance, each on the lab host's clock;
#                  the new key on staff's route, 401 through the VIP and at every pod; then revoked,
#                  until every pod refuses it
#   rejected-code  under the same probe: staff's route made again without the consumer
#                  restriction's rejected code and message (the API gateway's routes ConfigMap, the
#                  render's with those two lines left out), until every API gateway pod answers a
#                  chat key there with the plugin's own default; then the rendered routes back,
#                  until every pod answers 401 again
#   idle-timeout   the test backend's processes stopped (SIGSTOP in their nodes' guests) while one
#                  request from the enterprise client through the users' Gateway waits, silent_s,
#                  then continued: the status, the time and the hop that ended the request as the
#                  chain is rendered (the backend's own pod capture shows who closed its
#                  connection); then the corrected chain (Cilium's two stream idle timeout keys and
#                  the test backend's route timeouts, all outlasting the silence) applied with helm
#                  and the rollouts, the same silence answered, and the rendered chain put back
#
# Every change is undone from the EXIT trap whatever happens, its restore pushed before the change.
# Every time is the lab host's clock, and preflight's host tick of 10000 is checked when the result
# set opens. The plan is chapter.yaml's drills block, rendered to gen/drills.json
# (common/drill/lib-gwdrill.sh, common/drill/gwdrill.py).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init drills "$@"
# shellcheck source=common/drill/lib-gwdrill.sh
. "$SFAB_COMMON/drill/lib-gwdrill.sh"
gwdrills_main
