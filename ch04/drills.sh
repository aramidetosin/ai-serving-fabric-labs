#!/usr/bin/env bash
# ch04/drills.sh [--drills "ID ..."] [--passes N]: the chapter's firewall drills (book Examples 4-8
# to 4-10; FRAMEWORK.md 4.6), recorded as audits/sfab-ch04_drills_<UTC>/ with pass<N>/<drill>/ and
# DRILLS.md. make drills runs it with PASSES=3.
#
# The drills are chapter.yaml's drills block, rendered to gen/drills.json, in this order:
#
#   land        no-nat-public removed through the XML API and committed. k8s-cp2 pings the public
#               address with the rule in place (answered), then without it, show counter global
#               (every value, CLI and XML) read before and after each probe; packet-diag captures the
#               receive and drop stages filtered on the probe's two addresses, and host-side tcpdump
#               the bundle's legs and the uplink. Then the rendered rule goes back before
#               internet-snat, is committed, the rulebase is checked in the render's order, and the
#               probe is answered again. flow_policy_nat_land is relied on only once this
#               firewall's own counter table has printed it.
#   ntp-uplink  the firewall's NTP service route moved to the uplink interface with the DNS route,
#               whose server is the same address, dns-res1 (moved alone, the NTP route left the NTP
#               on the DNS route's source: RESULTS.md, problem 5), in one commit; a name looked up
#               through the firewall and the traffic log read until the firewall's own DNS and NTP to
#               dns-res1 appear from the public address, under deny-all-log (zone uplink to zone
#               services: no rule admits the uplink's address to the resolvers); host-side tcpdump
#               on the bundle and the uplink; then the routes go back and both are seen allowed
#               again from ae1.130, the services interface, under inside-to-resolvers and
#               inside-to-ntp.
#
# Each change has its restore pushed first, run from the EXIT trap whatever happens. Every time is
# the lab host's clock, and preflight's host tick of 10000 is checked when the result set opens.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init drills "$@"
# shellcheck source=common/drill/lib-fwdrill.sh
. "$SFAB_COMMON/drill/lib-fwdrill.sh"
fwdrills_main
