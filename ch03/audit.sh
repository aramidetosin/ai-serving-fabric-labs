#!/usr/bin/env bash
# ch03/audit.sh: the lab's audit (FRAMEWORK.md 4.4; book Example 3-2), recorded as a result set
# under audits/.
#
#   ./audit.sh            the full audit
#   ./audit.sh --quick    switches, the firewall and the container links the MAC tables need,
#                         not recorded (finish runs it, and drills.sh after every drill)
#
# The shared checks every lab gets, chapter 2's forwarding-only reads (on a pair member only its two
# keepalive /31s in VRF VrfMclagKa) and the pair as milestones M1 and M2 judge it (the session in
# VrfMclagKa on the keepalive link, the backup keepalive over Vlan3966) come first, as M2 runs them.
# Chapter 3 adds, without repeating those:
#
#   pair-roles  the domain's roles as the keepalive addresses elect them (the lower source-ip
#               active, the other standby), the ICCP session established on TCP 8888 inside VRF
#               VrfMclagKa between the keepalive link's addresses on both switches, and iccpd's own
#               keepalive state: the alarm the chapter puts on the keepalive, read directly rather
#               than inferred from probe loss
#   bond-legs   both legs of every bond toward the pair aggregated under the mclag-system-mac:
#               each host's bond leg by leg (its own /proc/net/bonding), the firewall's ae1 member
#               by member (show lacp), and TrueNAS's data and management bonds from the switches'
#               side, since its own LACP view is not collected (a SKIP line says so)
#   l2-hygiene  (full audit only) on the pair and both rail switches: spanning-tree mode pvst, every
#               used port at its rendered MTU (9216), BPDU guard with port-shutdown on every edge port
#               and on no other, none tripped, and storm control on every member and access port
#
# Then the rest of M2's build A audit: the cluster's nodes, the bastion, the platform's DNS and time
# servers, the uplink side, the clients, storage, the populations, the cluster and its security, and
# a volume on each class (common/audit/lib-audit.sh).
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
if [ "$SFAB_QUICK" = 1 ]; then summary; exit; fi
audit_l2_hygiene fe-sw1 fe-sw2 rail-sw1 rail-sw2                # chapter 3: MTU, BPDU guard, storm control
audit_build_a_cluster                                            # M2's criteria 3 to 9
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # namecheck and sfab check
summary
