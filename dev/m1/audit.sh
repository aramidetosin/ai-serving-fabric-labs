#!/usr/bin/env bash
# dev/m1/audit.sh: the M1 exit criteria (FRAMEWORK.md 6.2) as checks, recorded as a result set
# under audits/. Criterion 8 (teardown) is recorded separately by `make teardown-check`.
#
#   ./audit.sh            the full audit
#   ./audit.sh --quick    switches and the firewall only, not recorded (finish runs it)
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../../common/lib.sh"
sfab_init audit "$@"

[ "$SFAB_QUICK" = 1 ] || audit_preflight                         # 1: preflight, tick, other labs, budget
audit_collect                                                    # the evidence for 2 to 6
audit_judge                                                      # 2 switches, 4 firewall, 5 guests and rails, 6 VLANs and MAC tables
audit_forwarding_only fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw     # 2: the forwarding-only reads
audit_mclag_pair fe-sw1 fe-sw2                                   # 3: the pair
[ "$SFAB_QUICK" = 1 ] || audit_clean                             # 9: namecheck and sfab check
summary                                                          # 7: the RESULT line
