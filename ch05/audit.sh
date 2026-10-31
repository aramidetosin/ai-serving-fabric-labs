#!/usr/bin/env bash
# ch05/audit.sh: the lab's audit (FRAMEWORK.md 4.4; book Examples 5-2 and 5-10), recorded as a
# result set under audits/.
#
#   ./audit.sh            the full audit
#   ./audit.sh --quick    the switches and the container links the MAC tables need, not recorded
#                         (finish runs it, and drills.sh after each drill)
#
# The shared checks every lab gets come first (every switch's launcher line, NUM_NICS, GRO off,
# IPv6 off on its veths, ip vrf mgmt and parity; VLAN membership and MAC tables; the guests' bonds,
# TX offload and management table; the relay namespaces, the 9000-byte DF ping on every rail and
# cross-rail through the relay), then chapter 2's forwarding-only reads on every switch and the
# pair as milestone M1 judges it. Chapter 5 adds, without repeating those, the rail-backend group
# (common/audit/lib-audit.sh audit_rail_backend, then judge.py rail-backend), and in a full audit
# chapter 3's Layer 2 hygiene on the pair and both rail switches (spanning-tree mode pvst, every used
# port at its rendered MTU, BPDU guard with port-shutdown on every edge port, which on a rail switch
# is every rail access port, and storm control on each):
#
#   on each rail switch   the absences the design is made of: no VLAN interface address, no
#                         gateway (no static route, show ip route empty), no router bgp in KLISH or
#                         FRR's view, no inter-switch link (only the rendered GPU access ports up,
#                         every other port admin down, every MAC learned where the render cables
#                         it), only Management0 in the mgmt VRF; every rail port with no shutdown,
#                         at the l2 policy's port MTU, 9216, above the GPU NICs' 9000
#   on each GPU node      every GPU namespace with its connected rail and its relay routes as
#                         rendered, each pinned to the namespace's own rail address; no default
#                         route; reverse-path filtering loose (2) on every interface; the MTU
#                         ceilings: the rail NICs, the relay bridge, and in each namespace the rail
#                         macvlan and the relay veth at 9000
#
# The firewall is not in this lab, so the guests have no gateway to ping and the audit pings none.
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
  audit_collect "${SWITCHES[@]}" "${_sc[@]+"${_sc[@]}"}"
else
  audit_collect                                                  # every node's plan
fi
audit_judge                                                      # shared: switches, guests, rails, VLANs, MAC tables
audit_forwarding_only fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw     # chapter 2's forwarding-only reads
audit_mclag_pair fe-sw1 fe-sw2                                   # the pair the guests' bonds land on
audit_rail_backend rail-sw1 rail-sw2                             # chapter 5: the absences, the ports, the namespaces
if [ "$SFAB_QUICK" = 1 ]; then summary; exit; fi
audit_l2_hygiene fe-sw1 fe-sw2 rail-sw1 rail-sw2                # chapter 3: MTU, BPDU guard, storm control
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # namecheck and sfab check
summary
