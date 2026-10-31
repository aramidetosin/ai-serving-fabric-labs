#!/usr/bin/env bash
# ch07/audit.sh: the lab's audit (FRAMEWORK.md 4.4; book Examples 7-2, 7-3 to 7-6 and 7-12),
# recorded as a result set under audits/.
#
#   ./audit.sh                  the full audit
#   ./audit.sh --quick          switches, the firewall, the container links the MAC tables need, the
#                               placement group and the keys group; not recorded (finish runs it,
#                               and drills.sh)
#   ./audit.sh --table FILE     the placement group judged against another table than the rendered
#                               bootstrap/k8s/serving.env
#
# Chapter 6's audit comes first, as chapter 6's lab runs it (this lab extends it): chapter 4's
# audit (the shared checks, chapter 2's forwarding-only reads, the pair, its roles, ICCP session and
# backup keepalive, every bond's legs, the Layer 2 hygiene, the rest of M2's build A audit with the
# cluster and its security, its Gateways, certificates and populations, and the firewall edge),
# chapter 5's rail-backend group and chapter 6's placement group. Chapter 7 adds three groups
# (common/audit/lib-audit.sh audit_gateway_layer, then judge.py keys, identity and gateway-layer, in
# common/audit/gwlayer.py and common/audit/clustersec.py):
#
#   keys            for each model route a client of the lab reaches: no key, a key no Secret
#                   holds, and each other model's key (a key of a caller the route does not admit),
#                   all answered 401 with the same message (the cross-key check); and the per-pod key
#                   probe, a pod of the key tool in the cluster that sends each model's key (the first
#                   key of the first application caller that may call it: batch for chat, helpdesk
#                   for staff) to every API gateway pod by its address: 200 on the key's own route,
#                   401 on every other (a quick audit too)
#   identity        from each person's client: the identity provider's discovery document through
#                   the person's Gateway; a token with the API gateway's audience answered 200 where
#                   the person's caller may call the model and 401 elsewhere; a token without the
#                   audience and an altered one refused 401 with a Bearer challenge; the API
#                   gateway's access log naming the person's consumer (no token is saved, only its
#                   claims)
#   gateway-layer   the GatewayClass, each Gateway's allowedRoutes and the namespaces labelled for
#                   it, the hostnames and paths each Gateway answers (the internal Gateway the bare
#                   /models prefix and the admin hostnames, the users' Gateway one rule a model),
#                   the leases, held by the ingress nodes, each VIP in VLAN 110 answering ARP and TCP
#                   but no ICMP from the ingress node that does not hold it, each VIP's chain against
#                   the lab root (each Gateway its own key), the lab CA's proof (the leaves outside
#                   the name constraints refused), and the timeout chain as the cluster runs it,
#                   with the stream idle timeout Cilium wrote into each Gateway's listener
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
