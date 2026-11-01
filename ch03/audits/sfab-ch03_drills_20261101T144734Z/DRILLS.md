# Drills sfab-ch03_drills_20261101T144734Z

- Lab: `sfab-ch03`; labs repo commit `323633721b09abf17ff185f83c7a0e862a190b7a`; UTC 2026-11-01T14:47:34Z; host tick 10000
- Probes: a ping from the source guest to the far guest, one ICMP id per process, each placed on a bond leg by the guests' hash; a TCP connect loop from the enterprise client to the users' VIP, a new source port per attempt, placed by the firewall's hash. Captures on the lab host locate every probe before the fault and timestamp it; the guest's own ping log is the second witness.
- A lost ping is a round trip lost, on either leg. A reply later than a second counts as lost. Every shut is a KLISH shutdown from the switch side, which drops no carrier at the far end, so every member figure is an LACP-timeout figure.

## fw-leg: the firewall bundle's leg on fe-sw1 shut from the switch side

| Pass | Placed | Ping ids crossing fe-sw1: lost at the cut | at the restore | Other ids: lost | Longest no-reply stretch at the cut (s) | TCP failed at the cut | at the restore |
|---|---|---|---|---|---|---|---|
| 1 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 0.311, 0.314, 0.302, 0.301 | 3 | 0 |
| 2 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 0.314, 0.314, 0.307, 0.304 | 2 | 1 |
| 3 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 0.308, 0.306, 0.311, 0.306 | 2 | 0 |

Pass 1, peer link packets per second (host-side counters of its member ports): before fe-sw1 tx 3.6/s rx 3.0/s; before fe-sw2 tx 3.3/s rx 3.3/s; during fe-sw1 tx 7.8/s rx 4.6/s; during fe-sw2 tx 4.5/s rx 8.0/s; after fe-sw1 tx 3.4/s rx 3.0/s; after fe-sw2 tx 3.2/s rx 3.5/s

Pass 2, peer link packets per second (host-side counters of its member ports): before fe-sw1 tx 3.6/s rx 3.0/s; before fe-sw2 tx 3.0/s rx 3.3/s; during fe-sw1 tx 8.3/s rx 4.6/s; during fe-sw2 tx 4.6/s rx 8.3/s; after fe-sw1 tx 3.4/s rx 3.1/s; after fe-sw2 tx 3.3/s rx 3.4/s

Pass 3, peer link packets per second (host-side counters of its member ports): before fe-sw1 tx 3.3/s rx 3.3/s; before fe-sw2 tx 3.3/s rx 3.0/s; during fe-sw1 tx 8.1/s rx 4.7/s; during fe-sw2 tx 4.5/s rx 8.0/s; after fe-sw1 tx 3.3/s rx 3.6/s; after fe-sw2 tx 3.7/s rx 3.4/s

Per pass: `pass<N>/fw-leg/analysis.txt` (every probe instance), `placement.txt`, `timeline.txt`, `captures/`, `logs/`, `klish/`.

## server-member: k8s-gpu1's member on fe-sw1 shut from the switch side

| Pass | Placed | Ping ids crossing fe-sw1: lost at the cut | at the restore | Other ids: lost | Longest no-reply stretch at the cut (s) | TCP failed at the cut | at the restore |
|---|---|---|---|---|---|---|---|
| 1 | yes | 9, 9, 9, 9 | 0, 0, 0, 0 | 0, 0, 0, 0 | 3.036, 3.035, 3.035, 3.039 | 0 | 0 |
| 2 | yes | 8, 8, 9, 9 | 0, 1, 0, 0 | 0, 0, 0, 0 | 2.73, 2.73, 3.038, 3.038 | 0 | 0 |
| 3 | yes | 8, 8, 8, 8 | 0, 0, 0, 0 | 0, 0, 0, 0 | 2.738, 2.738, 2.735, 2.738 | 0 | 0 |

Pass 1, peer link packets per second (host-side counters of its member ports): before fe-sw1 tx 3.5/s rx 3.3/s; before fe-sw2 tx 3.3/s rx 3.3/s; during fe-sw1 tx 21.8/s rx 3.8/s; during fe-sw2 tx 3.7/s rx 21.9/s; after fe-sw1 tx 3.4/s rx 3.0/s; after fe-sw2 tx 3.0/s rx 3.5/s

Pass 2, peer link packets per second (host-side counters of its member ports): before fe-sw1 tx 3.9/s rx 3.0/s; before fe-sw2 tx 3.6/s rx 3.6/s; during fe-sw1 tx 22.2/s rx 3.7/s; during fe-sw2 tx 3.7/s rx 22.2/s; after fe-sw1 tx 3.6/s rx 3.1/s; after fe-sw2 tx 3.2/s rx 3.6/s

Pass 3, peer link packets per second (host-side counters of its member ports): before fe-sw1 tx 3.6/s rx 3.0/s; before fe-sw2 tx 3.3/s rx 3.0/s; during fe-sw1 tx 23.0/s rx 4.3/s; during fe-sw2 tx 4.3/s rx 23.1/s; after fe-sw1 tx 3.5/s rx 2.9/s; after fe-sw2 tx 3.1/s rx 3.4/s

Per pass: `pass<N>/server-member/analysis.txt` (every probe instance), `placement.txt`, `timeline.txt`, `captures/`, `logs/`, `klish/`.

## peer-link: the peer link shut on fe-sw1 with the keepalive link up

| Pass | Placed | Ping ids crossing fe-sw1: lost at the cut | at the restore | Other ids: lost | Longest no-reply stretch at the cut (s) | TCP failed at the cut | at the restore |
|---|---|---|---|---|---|---|---|
| 1 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 0.332, 0.335, 0.325, 0.325 | 0 | 0 |
| 2 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 0.313, 0.303, 0.306, 0.301 | 0 | 0 |
| 3 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 0, 0, 0, 0 | 0.316, 0.316, 0.304, 0.304 | 0 | 0 |

Per pass: `pass<N>/peer-link/analysis.txt` (every probe instance), `placement.txt`, `timeline.txt`, `captures/`, `logs/`, `klish/`.

## The passes compared

Passes compared: pass1, pass2, pass3 in sfab-ch03_drills_20261101T144734Z

## fw-leg

| measure | across every pass and probe | agrees? |
|---|---|---|
| placed before the fault | pass 1 yes, pass 2 yes, pass 3 yes | yes |
| ping round trips lost, ids crossing fe-sw1 | 0 | yes |
|   of them at the cut | 0 | yes |
|   of them at the restore | 0 | yes |
| ping round trips lost, ids not crossing fe-sw1 | 0 | yes |
| longest stretch with no reply at the cut, ids crossing fe-sw1 (s) | 0.30 to 0.31 | - |
| ping ids crossing the target, per pass | pass 1 4 of 8, pass 2 4 of 8, pass 3 4 of 8 | - |
| TCP connects failed at the cut | 2 to 3 | yes |
| TCP connects failed at the restore | 0 to 1 | yes |
| TCP connects failed elsewhere | 0 | yes |
| peer link tx packets per second on fe-sw1, before | 3.3 to 3.6 | - |
| peer link tx packets per second on fe-sw2, before | 3 to 3.3 | - |
| peer link tx packets per second on fe-sw1, during | 7.8 to 8.3 | - |
| peer link tx packets per second on fe-sw2, during | 4.5 to 4.6 | - |
| peer link tx packets per second on fe-sw1, after | 3.3 to 3.4 | - |
| peer link tx packets per second on fe-sw2, after | 3.2 to 3.7 | - |

## server-member

| measure | across every pass and probe | agrees? |
|---|---|---|
| placed before the fault | pass 1 yes, pass 2 yes, pass 3 yes | yes |
| ping round trips lost, ids crossing fe-sw1 | 8 to 9 | yes |
|   of them at the cut | 8 to 9 | yes |
|   of them at the restore | 0 to 1 | yes |
| ping round trips lost, ids not crossing fe-sw1 | 0 | yes |
| longest stretch with no reply at the cut, ids crossing fe-sw1 (s) | 2.73 to 3.04 | - |
| ping ids crossing the target, per pass | pass 1 4 of 8, pass 2 4 of 8, pass 3 4 of 8 | - |
| TCP connects failed at the cut | 0 | yes |
| TCP connects failed at the restore | 0 | yes |
| TCP connects failed elsewhere | 0 | yes |
| peer link tx packets per second on fe-sw1, before | 3.5 to 3.9 | - |
| peer link tx packets per second on fe-sw2, before | 3.3 to 3.6 | - |
| peer link tx packets per second on fe-sw1, during | 21.8 to 23 | - |
| peer link tx packets per second on fe-sw2, during | 3.7 to 4.3 | - |
| peer link tx packets per second on fe-sw1, after | 3.4 to 3.6 | - |
| peer link tx packets per second on fe-sw2, after | 3 to 3.2 | - |

## peer-link

| measure | across every pass and probe | agrees? |
|---|---|---|
| placed before the fault | pass 1 yes, pass 2 yes, pass 3 yes | yes |
| ping round trips lost, ids crossing fe-sw1 | 0 | yes |
|   of them at the cut | 0 | yes |
|   of them at the restore | 0 | yes |
| ping round trips lost, ids not crossing fe-sw1 | 0 | yes |
| longest stretch with no reply at the cut, ids crossing fe-sw1 (s) | 0.30 to 0.34 | - |
| ping ids crossing the target, per pass | pass 1 4 of 8, pass 2 4 of 8, pass 3 4 of 8 | - |
| TCP connects failed at the cut | 0 | yes |
| TCP connects failed at the restore | 0 | yes |
| TCP connects failed elsewhere | 0 | yes |

Ranges span every probe instance of every pass. A ping lost is a round trip lost, on either leg.

no disagreement between the passes

## Verdict

```
== pass 1, drill fw-leg: the firewall bundle's leg on fe-sw1 shut from the switch side
  PASS  pass 1 fw-leg: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 fw-leg: probes located before the fault as the drill needs them (try 1): tcp: 5 connects leave the firewall toward fe-sw1, 6 toward the other switch
  PASS  pass 1 fw-leg: KLISH shutdown of Ethernet2 (PortChannel10) on fe-sw1 accepted
  PASS  pass 1 fw-leg: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 1 fw-leg: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 fw-leg: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 1 fw-leg: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== pass 1, drill server-member: k8s-gpu1's member on fe-sw1 shut from the switch side
  PASS  pass 1 server-member: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 server-member: probes located before the fault as the drill needs them (try 1): ping: 4 of 8 ids cross fe-sw1, 4 do not
  PASS  pass 1 server-member: KLISH shutdown of Ethernet6 (PortChannel21) on fe-sw1 accepted
  PASS  pass 1 server-member: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 1 server-member: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 server-member: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 1 server-member: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
  KNOWN pass 1 server-member: 9 duplicate ping replies (peer-link isolation is not enforced): L1
== pass 1, drill peer-link: the peer link shut on fe-sw1 with the keepalive link up
  PASS  pass 1 peer-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 peer-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 1 peer-link: KLISH shutdown of Ethernet0,Ethernet1 (PortChannel1) on fe-sw1 accepted
  PASS  pass 1 peer-link: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 1 peer-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 peer-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 1 peer-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== pass 2, drill fw-leg: the firewall bundle's leg on fe-sw1 shut from the switch side
  PASS  pass 2 fw-leg: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 fw-leg: probes located before the fault as the drill needs them (try 1): tcp: 6 connects leave the firewall toward fe-sw1, 6 toward the other switch
  PASS  pass 2 fw-leg: KLISH shutdown of Ethernet2 (PortChannel10) on fe-sw1 accepted
  PASS  pass 2 fw-leg: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 2 fw-leg: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 fw-leg: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 2 fw-leg: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== pass 2, drill server-member: k8s-gpu1's member on fe-sw1 shut from the switch side
  PASS  pass 2 server-member: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 server-member: probes located before the fault as the drill needs them (try 1): ping: 4 of 8 ids cross fe-sw1, 4 do not
  PASS  pass 2 server-member: KLISH shutdown of Ethernet6 (PortChannel21) on fe-sw1 accepted
  PASS  pass 2 server-member: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 2 server-member: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 server-member: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 2 server-member: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
  KNOWN pass 2 server-member: 25 duplicate ping replies (peer-link isolation is not enforced): L1
== pass 2, drill peer-link: the peer link shut on fe-sw1 with the keepalive link up
  PASS  pass 2 peer-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 peer-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 2 peer-link: KLISH shutdown of Ethernet0,Ethernet1 (PortChannel1) on fe-sw1 accepted
  PASS  pass 2 peer-link: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 2 peer-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 peer-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 2 peer-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== pass 3, drill fw-leg: the firewall bundle's leg on fe-sw1 shut from the switch side
  PASS  pass 3 fw-leg: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 fw-leg: probes located before the fault as the drill needs them (try 1): tcp: 5 connects leave the firewall toward fe-sw1, 6 toward the other switch
  PASS  pass 3 fw-leg: KLISH shutdown of Ethernet2 (PortChannel10) on fe-sw1 accepted
  PASS  pass 3 fw-leg: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 3 fw-leg: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 fw-leg: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 3 fw-leg: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== pass 3, drill server-member: k8s-gpu1's member on fe-sw1 shut from the switch side
  PASS  pass 3 server-member: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 server-member: probes located before the fault as the drill needs them (try 1): ping: 4 of 8 ids cross fe-sw1, 4 do not
  PASS  pass 3 server-member: KLISH shutdown of Ethernet6 (PortChannel21) on fe-sw1 accepted
  PASS  pass 3 server-member: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 3 server-member: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 server-member: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 3 server-member: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
  KNOWN pass 3 server-member: 17 duplicate ping replies (peer-link isolation is not enforced): L1
== pass 3, drill peer-link: the peer link shut on fe-sw1 with the keepalive link up
  PASS  pass 3 peer-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 peer-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 3 peer-link: KLISH shutdown of Ethernet0,Ethernet1 (PortChannel1) on fe-sw1 accepted
  PASS  pass 3 peer-link: no shutdown accepted on fe-sw1 after 30 s
  PASS  pass 3 peer-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 peer-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 3 peer-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== the passes compared
  PASS  compare_passes.py: no disagreement between the passes
```

== RESULT: 55 passed, 0 failed, 12 known platform limitation(s), 0 skipped
