#!/usr/bin/env bash
# ch02/audit.sh: the lab's audit (FRAMEWORK.md 4.4; book Examples 2-2 and 2-12), recorded as a
# result set under audits/.
#
#   ./audit.sh                  the full audit
#   ./audit.sh --quick          switches, the firewall, storage, the container links the MAC tables
#                               need, the placement group and the keys group; not recorded (finish
#                               runs it)
#   ./audit.sh --table FILE     the placement group judged against another table than the rendered
#                               bootstrap/k8s/serving.env
#
# Chapter 1's build A whole, as chapter 1's audit judges it, with chapter 2's forwarding-only reads
# on every switch: the pair, both rail switches and the out-of-band switch each with no address on
# any served VLAN, PortChannel or host port (show ip interfaces lists only Management0, in VRF mgmt,
# and on a pair member its two keepalive addresses, Ethernet12 and Vlan3966, in VRF VrfMclagKa; no
# served VLAN's interface Vlan block carries an address; the kernel holds none on a Vlan, PortChannel
# or Ethernet netdev beyond those two, SONiC's own lo-m, docker-mgmt, redirect and docker0 set
# aside), no routing protocol (no router line, no router block in the FRR view), nothing in show ip
# route and only the two connected keepalive /31s in show ip route vrf VrfMclagKa, read in KLISH.
# Then the pair with its roles, ICCP session, backup keepalive and every PortChannel, every bond's
# legs (the storage bonds' too), chapter 5's rail-backend group, chapter 6's placement group, chapter
# 7's keys and gateway-layer groups, chapter 3's Layer 2 hygiene, M2's build A audit (the cluster and
# its security, the bastion, the platform's DNS and time servers, the uplink side, the clients,
# storage with a volume on each class, the populations, the Gateways and certificates) and chapter
# 4's firewall edge (every gateway on its interface and zone, the rulebase in order, administrative
# access, an egress the allowlist does not name, the service routes, the uplink router's routes to
# the inside prefixes, and the operator's refused cells of the matrix: deny-all-log inside the
# tunnel's proxy IDs, zone protection's strict IP check outside them).
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
