#!/usr/bin/env bash
# ch10/hold.sh: the session measurement (book Examples 10-10 and 10-11), recorded as
# audits/sfab-ch10_hold_<UTC>/ with HOLD.md and verdict.txt (common/trace/lib-hold.sh, judged by
# common/trace/holdrun.py).
#
# Every population's held connections at once (chapter.yaml tenancy.hold: 8 keep-alive HTTPS
# connections a population to its own Gateway's /echo, used again every 20 s, held 120 s), each
# zone's session count on the firewall and show session info read before, while held, after one chat
# completion a population with its own caller's key, and after the stop; the counts against the
# plan's bound, the TCP timeouts against PAN-OS 12.1's, and Little's law per zone in HOLD.md.
# HOLD_FACTOR=2 doubles the connections. Changes nothing on any device; every process it starts it
# stops.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init hold "$@"
# shellcheck source=common/trace/lib-hold.sh
. "$SFAB_COMMON/trace/lib-hold.sh"
hold_run
