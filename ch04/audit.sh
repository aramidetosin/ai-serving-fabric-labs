#!/usr/bin/env bash
# ch04/audit.sh: the lab's audit (FRAMEWORK.md 4.4; book Examples 4-2 and 4-11), recorded as a
# result set under audits/.
#
#   ./audit.sh            the full audit
#   ./audit.sh --quick    switches, the firewall and the container links the MAC tables need,
#                         not recorded (finish runs it, and drills.sh after the drills)
#
# Chapter 3's audit comes first, as chapter 3's lab runs it (this lab extends it): the shared
# checks, chapter 2's forwarding-only reads, the pair, its roles, ICCP session and backup keepalive,
# every bond's legs and the Layer 2 hygiene. Then the rest of M2's build A audit (the cluster and its
# security, the bastion, the platform's DNS and time servers, the uplink side, the clients, storage,
# the populations and a volume on each class). Chapter 4 adds, without repeating those, the fw-edge
# group (common/audit/lib-audit.sh audit_fw_edge, then judge.py fw-edge):
#
#   zone bindings   every layer 3 interface wired here in its zone with its address (show interface all)
#   rule order      the running security and NAT rules in the render's order (show running
#                   security-policy and nat-policy), deny-all-log last, no-nat-public above internet-snat
#   LAND counter    flow_policy_nat_land in the firewall's own show counter global table (nothing
#                   relies on the name before the firewall prints it), at zero, and unmoved while k8s-cp2
#                   pings the public address with every request answered
#   egress          k8s-cp2's connect to an internet host the allowlist does not name (the web
#                   client, 443) times out, and deny-all-log logs it from k8s-nodes to uplink
#   admin access    the bastion VLAN's interface profile (HTTPS, SSH, ping, permitted from the jump
#                   host's own address only) and ping-only everywhere else; the bastion reaches HTTPS
#                   and SSH there, and another inside host does not; the operator finds no SSH on the
#                   public address and no HTTPS there: nothing is published on the uplink
#   service routes  DNS and NTP to the platform's two resolvers, dns-res1 and dns-res2, out of the
#                   services interface ae1.130 in the running configuration, show ntp synched to the
#                   first (read until synched, 20 minutes at most), a name resolved through the DNS
#                   route, and the firewall's own DNS and NTP in the traffic log under the rules that
#                   admit them
#   inside routes   the uplink router's static routes to the inside prefixes via the public
#                   address, installed; the operator's connects to its forbidden cells in chapter 2's
#                   matrix refused: the users' VIP, inside the tunnel's proxy IDs, with its
#                   deny-all-log line (zone operator-vpn); the rest, sent in the clear, dropped by zone
#                   protection's strict IP check on the uplink (its counter rises, no log line)
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
if [ "$SFAB_QUICK" = 1 ]; then summary; exit; fi
audit_l2_hygiene fe-sw1 fe-sw2 rail-sw1 rail-sw2                # chapter 3: MTU, BPDU guard, storm control
audit_build_a_cluster                                            # M2's criteria 3 to 9
audit_fw_edge k8s-cp2                                              # chapter 4: the firewall edge
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # namecheck and sfab check
summary
