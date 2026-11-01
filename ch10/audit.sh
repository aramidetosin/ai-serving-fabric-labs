#!/usr/bin/env bash
# ch10/audit.sh: the lab's audit (FRAMEWORK.md 4.4), recorded as a result set under audits/.
#
#   ./audit.sh                  the full audit
#   ./audit.sh --quick          switches, the firewall, the container links the MAC tables need, the
#                               placement group and the keys group; not recorded (finish runs it)
#   ./audit.sh --table FILE     the placement group judged against another table than the rendered
#                               bootstrap/k8s/serving.env
#
# Chapter 7's audit as chapter 7's lab runs it, on chapter 10's render (chapter 9's with the
# internet users' translation and rule).
#
# Part III's groups follow chapter 7's (common/audit/lib-tenancy.sh, judged by
# common/audit/tenancy.py against gen/tenancy.json), in a full audit only:
#
#   audiences       a Gateway per audience: each Gateway's routes its audience's row, its admin and
#                   identity hostnames where the render puts them, its labelled namespaces (the
#                   internet Gateway's echo and inference alone), the callers each model route
#                   admits within their audiences, a key per Gateway, the three leases on ingress
#                   nodes at the tuned duration, cilium-config's tuned timers, a policy per audience,
#                   and the refused mint (a key for a model outside its caller's audience, refused
#                   by the key tool with the Secret left as it was)
#   split-horizon   the public server's names and nothing else (no admin, internal, identity or
#                   infrastructure name, no wildcard, recursion refused), the ISP resolver for its
#                   customer and refusing the ISP router's link address, every population's typed
#                   names answered A and AAAA NODATA through its own resolver, the uplink side's
#                   server holding no platform name, the ISP router with no inside route, the
#                   internet client's connect to the published address as the firewall's render
#                   says, and Cilium's copies of the Gateway certificates recorded
#   zone-nat        the NAT and security rulebases in the rendered order, the isp zone's one
#                   translation (to the internet Gateway's VIP) and one rule (the published address,
#                   ssl), the published address refused from every inside zone, and each zone's
#                   session count within the plan's bound under the held connections
#
# SFAB_AUDIT_CLEAN=0 leaves the repository checks out.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init audit "$@"
# shellcheck source=common/audit/lib-audit.sh
. "$SFAB_COMMON/audit/lib-audit.sh"
# shellcheck source=common/audit/lib-tenancy.sh
. "$SFAB_COMMON/audit/lib-tenancy.sh"

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
audit_audiences                                                  # chapter 8: a Gateway per audience
audit_split_horizon                                              # chapter 9: split-horizon DNS
audit_zone_nat                                                   # chapter 10: zone-keyed translation and sessions
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # namecheck and sfab check
summary
