#!/usr/bin/env bash
# ch01/audit.sh: the lab's audit (FRAMEWORK.md 4.4; book Examples 1-2 and 1-10), recorded as a
# result set under audits/.
#
#   ./audit.sh                  the full audit
#   ./audit.sh --quick          switches, the firewall, storage, the container links the MAC tables
#                               need, the placement group and the keys group; not recorded (finish
#                               runs it)
#   ./audit.sh --table FILE     the placement group judged against another table than the rendered
#                               bootstrap/k8s/serving.env
#
# Build A whole: every check the labs of chapters 3 to 7 run, in one audit. The shared checks and
# chapter 2's forwarding-only reads (the pair, the rail switches and the out-of-band switch with no
# address but Management0 in the management VRF and, on a pair member, its two keepalive /31s in VRF
# VrfMclagKa, and nothing in show ip route), the pair with its roles, its ICCP session over the
# keepalive link, its backup keepalive and every PortChannel, every bond's legs (the storage bonds'
# too), chapter 5's rail-backend group, chapter 6's placement group, chapter 7's keys and
# gateway-layer groups (the identity provider's sign-in among them), chapter 3's Layer 2 hygiene (MTU,
# BPDU guard, storm control), then the rest of M2's build A audit (the cluster and its security, the
# bastion, the platform's DNS and time servers, the uplink side, the clients, storage with a volume
# on each class, the populations, the Gateways and certificates) and chapter 4's firewall edge (every
# gateway Table 1-2 lists on its interface and zone, the rulebase in order, administrative access, an
# egress the allowlist does not name, the service routes, the uplink router's routes to the inside
# prefixes and the operator's refused cells).
#
# SFAB_AUDIT_VOLUMES=0 leaves the volume check out (the line then reads SKIP), and
# SFAB_AUDIT_CLEAN=0 the repository checks.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init audit "$@"
# shellcheck source=common/audit/lib-audit.sh
. "$SFAB_COMMON/audit/lib-audit.sh"

[ "$SFAB_QUICK" = 1 ] || audit_preflight                         # preflight, tick, other labs, budget
if [ "$SFAB_QUICK" = 1 ]; then
  mapfile -t _sc < <(switch_containers)
  audit_collect "${SWITCHES[@]}" ${FW_NODE:+"$FW_NODE"} "${STORAGE[@]+"${STORAGE[@]}"}" "${_sc[@]+"${_sc[@]}"}"
else
  audit_collect                                                  # every node's plan
fi
audit_judge                                                      # shared: switches, firewall, guests, rails, VLANs, MAC tables
audit_forwarding_only fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw     # chapter 2's forwarding-only reads
audit_mclag_pair fe-sw1 fe-sw2                                   # the pair, every PortChannel
_judge pair-roles fe-sw1 fe-sw2                                  # chapter 3: roles and the ICCP session
mapfile -t _bl < <(bonded_nodes)
judge_present bond-legs "${_bl[@]}" ${FW_NODE:+"$FW_NODE"} "${STORAGE[@]+"${STORAGE[@]}"}"   # chapter 3: every bond's legs
audit_rail_backend rail-sw1 rail-sw2                             # chapter 5: the absences, the ports, the namespaces
audit_placement                                                  # chapter 6: the pods against the placement table
audit_gateway_layer                                              # chapter 7: the keys; in a full audit the gateway layer
if [ "$SFAB_QUICK" = 1 ]; then summary; exit; fi
audit_l2_hygiene fe-sw1 fe-sw2 rail-sw1 rail-sw2                # chapter 3: MTU, BPDU guard, storm control
audit_build_a_cluster                                            # M2's criteria 3 to 9, storage and its volumes
audit_fw_edge k8s-cp2                                              # chapter 4: the firewall edge
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # namecheck and sfab check
summary
