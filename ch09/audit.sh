#!/usr/bin/env bash
# ch09/audit.sh: the lab's audit (FRAMEWORK.md 4.4), recorded as a result set under audits/.
#
#   ./audit.sh                  the full audit
#   ./audit.sh --quick          switches, the firewall, the container links the MAC tables need, the
#                               placement group and the keys group; not recorded (finish runs it)
#   ./audit.sh --table FILE     the placement group judged against another table than the rendered
#                               bootstrap/k8s/serving.env
#
# Chapter 7's audit as chapter 7's lab runs it, on chapter 9's render (chapter 8's with the
# internet side).
# Part III's own audit groups land with the record
# stage; until then this lab runs the groups chapters 1 to 7 hold.
#
# SFAB_AUDIT_CLEAN=0 leaves the repository checks out.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init audit "$@"
# shellcheck source=common/audit/lib-audit.sh
. "$SFAB_COMMON/audit/lib-audit.sh"

[ "$SFAB_QUICK" = 1 ] || audit_preflight                         # preflight, tick, other labs, budget
if [ "$SFAB_QUICK" = 1 ]; then
  mapfile -t _sc < <(switch_containers)
  audit_collect "${SWITCHES[@]}" ${FW_NODE:+"$FW_NODE"} "${_sc[@]+"${_sc[@]}"}"
else
  audit_collect                                                  # every node's plan
fi
audit_judge                                                      # shared: switches, firewall, guests, rails, VLANs, MAC tables
audit_forwarding_only fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw     # chapter 2's forwarding-only reads
audit_mclag_pair fe-sw1 fe-sw2                                   # the pair, every PortChannel
_judge pair-roles fe-sw1 fe-sw2                                  # chapter 3: roles and the ICCP session
mapfile -t _bl < <(bonded_nodes)
judge_present bond-legs "${_bl[@]}" ${FW_NODE:+"$FW_NODE"}       # chapter 3: every bond's legs
audit_rail_backend rail-sw1 rail-sw2                             # chapter 5: the absences, the ports, the namespaces
audit_placement                                                  # chapter 6: the pods against the placement table
audit_gateway_layer                                              # chapter 7: the keys; in a full audit the gateway layer
if [ "$SFAB_QUICK" = 1 ]; then summary; exit; fi
audit_l2_hygiene fe-sw1 fe-sw2 rail-sw1 rail-sw2                # chapter 3: MTU, BPDU guard, storm control
audit_build_a_cluster                                            # M2's criteria 3 to 9
audit_fw_edge k8s-cp2                                              # chapter 4: the firewall edge
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # namecheck and sfab check
summary
