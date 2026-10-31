#!/usr/bin/env bash
# ch03/drills.sh [--drills "ID ..."] [--passes N]: the chapter's failure drills (book Examples 3-10
# to 3-12, and the keepalive drills revision 2 adds; FRAMEWORK.md 4.6), recorded as
# audits/sfab-ch03_drills_<UTC>/ with pass<N>/<drill>/, compare.txt and DRILLS.md. make drills runs
# it with PASSES=3.
#
# The drills are chapter.yaml's drills block, rendered to gen/drills.json, in this order:
#
#   fw-leg          fe-sw1's member of PortChannel10 (Ethernet2, facing the firewall's
#                   ethernet1/1) shut from the switch side, held 30 s, then no shutdown. The TCP
#                   connects from the enterprise client to the users' VIP are the probe it
#                   exercises: the firewall hashes each new connect onto a leg, and the captures on
#                   both legs locate them; the k8s-gpu1 to k8s-gpu2 ping never crosses the bundle and is the
#                   control. The peer link's counters are read before, during and after.
#   server-member   fe-sw1's member of PortChannel21 (Ethernet6, k8s-gpu1's eth1) shut the same way.
#                   The ping is the probe it exercises, placed with ping -e: eight ICMP ids at once,
#                   each hashed onto a leg by k8s-gpu1's layer3+4 policy, located by capture, restarted
#                   with new ids until some cross fe-sw1 and some do not. The TCP connects are the
#                   control. The peer link's counters are read again.
#   peer-link       both members of fe-sw1's PortChannel1 (interface range Ethernet0-1) shut with the
#                   dedicated keepalive link up. The pings leave k8s-gpu1 on both legs.
#   keepalive-link  fe-sw1's dedicated keepalive link (Ethernet12, VRF VrfMclagKa) shut, held 70 s,
#                   past the 30 s session timeout, with the peer link and the backup keepalive up; then
#                   the drill waits (up to return_max_s) for the pair whole and every bond on two legs,
#                   since the standby shuts its own MCLAG PortChannels and holds them down for
#                   delay-restore once the link is back. The monitor runs throughout.
#   keepalive-and-peer-link
#                   the keepalive link and both peer-link members shut together on fe-sw1, so both
#                   keepalive paths are gone; held and waited for the same way.
#   standby-reboot  sudo reboot, under a timeout, on the switch show mclag brief names standby when
#                   the drill runs. A monitor reads every bond's legs, both switches' MCLAG and
#                   PortChannel state and the firewall's LACP every few seconds; the departure is
#                   timed from it, and the return (every bond back on two legs) is recorded as an
#                   event with the probes lost around it, never as a span from the departure. GRO
#                   and parity are checked on the switch after it returns.
#
# Every drill checks the lab whole first and again after, and runs audit.sh --quick after. Every
# time is the lab host's clock: the captures run on the host, the connect loops in containers, and
# preflight's host tick of 10000 is checked when the result set opens. A lost ping is a round trip.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../common/lib.sh"
sfab_init drills "$@"
# shellcheck source=common/drill/lib-drill.sh
. "$SFAB_COMMON/drill/lib-drill.sh"
drills_main
