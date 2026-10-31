#!/usr/bin/env bash
# ch06/audit.sh: the lab's audit (FRAMEWORK.md 4.4; book Examples 6-2, 6-9 and 6-10), recorded as a
# result set under audits/.
#
#   ./audit.sh                  the full audit
#   ./audit.sh --quick          switches, the firewall, the container links the MAC tables need, and
#                               the placement group; not recorded (finish runs it, and drills.sh)
#   ./audit.sh --table FILE     the placement group judged against another table than the rendered
#                               bootstrap/k8s/serving.env (the rail-move drill's moved table)
#
# Chapter 4's audit comes first, as chapter 4's lab runs it (this lab extends it): the shared
# checks, chapter 2's forwarding-only reads, the pair, its roles, ICCP session and backup keepalive,
# every bond's legs, the Layer 2 hygiene, the rest of M2's build A audit (the cluster and its
# security, the bastion, the platform's DNS and time servers, the uplink side, the clients, the
# populations; this lab holds no storage) and the firewall edge. Then chapter 5's rail-backend group
# on the rail switches and both GPU nodes. Chapter 6 adds the placement group
# (common/audit/lib-audit.sh audit_placement, then judge.py placement), every pod read back
# against the placement table:
#
#   the table       the recipe's rules (every pod of a copy on one rail, one server and at least one
#                   worker a copy, every rail address in its rail's prefix and given once), and each
#                   model's copies on rails of different parity, so on different rail switches: chat
#                   a on k8s-gpu1 rail 3 and chat b on k8s-gpu2 rail 6, staff a on k8s-gpu1 rail 4 and
#                   staff b on k8s-gpu2 rail 5, each wholly inside its node, and chat c, the stand-in
#                   for a model larger than one node, spanning both nodes on rail 7
#   each row        its pod Running and Ready on the row's node, its network-status annotation naming
#                   the row's rail attachment and address, its labels the row's
#   each server     llama-server's --rpc naming its workers' rail addresses, and its readiness probe
#                   the RPC-aware one with the table's timers; each worker bound to its rail address
#   attachments     one macvlan attachment per rail the table uses, master the rail NIC, the static
#                   IPAM plugin and no route; none other
#   Services        one per model and one per copy, each with exactly its servers as ready endpoints
#   routes          in every pod the default route on eth0 and only the rail's connected prefix on its
#                   rail attachment, read in the pod's network namespace on its node
#   the Gateways    one request a model through each model route (the users' Gateway from the
#                   enterprise client, the internal Gateway from the operator's client through the
#                   IPsec tunnel), with the first key of an application caller that may call the
#                   model: HTTP 200 from the router's deployment
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
if [ "$SFAB_QUICK" = 1 ]; then summary; exit; fi
audit_l2_hygiene fe-sw1 fe-sw2 rail-sw1 rail-sw2                # chapter 3: MTU, BPDU guard, storm control
audit_build_a_cluster                                            # M2's criteria 3 to 9
audit_fw_edge k8s-cp2                                              # chapter 4: the firewall edge
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # namecheck and sfab check
summary
