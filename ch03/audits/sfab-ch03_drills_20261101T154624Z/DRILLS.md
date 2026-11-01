# Drills sfab-ch03_drills_20261101T154624Z

- Lab: `sfab-ch03`; labs repo commit `323633721b09abf17ff185f83c7a0e862a190b7a`; UTC 2026-11-01T15:46:24Z; host tick 10000
- Probes: a ping from the source guest to the far guest, one ICMP id per process, each placed on a bond leg by the guests' hash; a TCP connect loop from the enterprise client to the users' VIP, a new source port per attempt, placed by the firewall's hash. Captures on the lab host locate every probe before the fault and timestamp it; the guest's own ping log is the second witness.
- A lost ping is a round trip lost, on either leg. A reply later than a second counts as lost. Every shut is a KLISH shutdown from the switch side, which drops no carrier at the far end, so every member figure is an LACP-timeout figure.

## keepalive-and-peer-link: the keepalive link and the peer link shut together on fe-sw1, both keepalive paths gone

| Pass | Placed | Ping ids crossing fe-sw1: lost at the cut | at the restore | Other ids: lost | Longest no-reply stretch at the cut (s) | TCP failed at the cut | at the restore |
|---|---|---|---|---|---|---|---|
| 1 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 15, 14, 15, 15 | 0.306, 0.309, 0.308, 0.308 | 0 | 1 |
| 2 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 13, 13, 13, 14 | 0.32, 0.322, 0.316, 0.311 | 0 | 1 |
| 3 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 14, 14, 14, 14 | 0.319, 0.317, 0.312, 0.333 | 0 | 0 |

Pass 1, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T15:48:11.55Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T15:48:46.08Z: the peer link up on the active
- 2026-11-01T15:48:46.08Z: the keepalive OK on both switches

Pass 2, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T16:00:30.74Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T16:01:06.28Z: the peer link up on the active
- 2026-11-01T16:01:06.28Z: the keepalive OK on both switches

Pass 3, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T16:12:25.62Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T16:13:00.99Z: the peer link up on the active
- 2026-11-01T16:13:00.99Z: the keepalive OK on both switches

Per pass: `pass<N>/keepalive-and-peer-link/analysis.txt` (every probe instance), `placement.txt`, `timeline.txt`, `captures/`, `logs/`, `klish/`.

## standby-reboot: the standby rebooted

| Pass | Placed | Ping ids crossing fe-sw2: lost at the cut | at the restore | Other ids: lost | Longest no-reply stretch at the cut (s) | TCP failed at the cut | at the restore |
|---|---|---|---|---|---|---|---|
| 1 | yes | 13, 13, 13, 13 | 15, 15, 15, 14 | 0, 0, 0, 0 | 4.252, 4.251, 4.253, 4.26 | 4 | 5 |
| 2 | yes | 13, 14, 14, 12 | 16, 16, 16, 16 | 0, 0, 0, 0 | 3.951, 4.556, 4.556, 3.953 | 4 | 5 |
| 3 | yes | 12, 12, 12, 12 | 14, 15, 15, 15 | 0, 0, 0, 0 | 3.95, 3.95, 3.949, 3.954 | 4 | 5 |

Pass 1, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T15:52:31.92Z: the standby's own MCLAG PortChannels read down or traffic-disabled, the standby still answering
- 2026-11-01T15:52:50.63Z: every bond toward the pair on one leg
- 2026-11-01T15:53:27.70Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T15:53:53.28Z: the standby's management address stops answering
- 2026-11-01T15:55:26.65Z: the peer link up on the active
- 2026-11-01T15:55:34.88Z: the standby's management address answers again
- 2026-11-01T15:56:41.98Z: every bond toward the pair back on two legs: the return
- 2026-11-01T15:56:41.98Z: the firewall's ae1 on both legs
- 2026-11-01T15:56:41.98Z: the keepalive OK on both switches
- 2026-11-01T15:56:41.98Z: every MCLAG PortChannel up on the standby

Pass 2, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T16:04:48.33Z: the standby's own MCLAG PortChannels read down or traffic-disabled, the standby still answering
- 2026-11-01T16:05:06.50Z: every bond toward the pair on one leg
- 2026-11-01T16:05:43.63Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T16:06:09.68Z: the standby's management address stops answering
- 2026-11-01T16:07:37.30Z: the peer link up on the active
- 2026-11-01T16:07:45.90Z: the standby's management address answers again
- 2026-11-01T16:08:43.92Z: every bond toward the pair back on two legs: the return
- 2026-11-01T16:08:43.92Z: the keepalive OK on both switches
- 2026-11-01T16:08:53.51Z: the firewall's ae1 on both legs
- 2026-11-01T16:08:53.51Z: every MCLAG PortChannel up on the standby

Pass 3, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T16:16:46.22Z: the standby's own MCLAG PortChannels read down or traffic-disabled, the standby still answering
- 2026-11-01T16:17:04.44Z: every bond toward the pair on one leg
- 2026-11-01T16:17:41.33Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T16:18:06.87Z: the standby's management address stops answering
- 2026-11-01T16:19:32.60Z: the peer link up on the active
- 2026-11-01T16:19:50.07Z: the standby's management address answers again
- 2026-11-01T16:20:47.56Z: every bond toward the pair back on two legs: the return
- 2026-11-01T16:20:47.56Z: the firewall's ae1 on both legs
- 2026-11-01T16:20:47.56Z: the keepalive OK on both switches
- 2026-11-01T16:20:47.56Z: every MCLAG PortChannel up on the standby

Per pass: `pass<N>/standby-reboot/analysis.txt` (every probe instance), `placement.txt`, `timeline.txt`, `captures/`, `logs/`, `klish/`.

## The passes compared

Passes compared: pass1, pass2, pass3 in sfab-ch03_drills_20261101T154624Z

## keepalive-and-peer-link

| measure | across every pass and probe | agrees? |
|---|---|---|
| placed before the fault | pass 1 yes, pass 2 yes, pass 3 yes | yes |
| ping round trips lost, ids crossing fe-sw1 | 0 | yes |
|   of them at the cut | 0 | yes |
|   of them at the restore | 0 | yes |
| ping round trips lost, ids not crossing fe-sw1 | 13 to 15 | yes |
| longest stretch with no reply at the cut, ids crossing fe-sw1 (s) | 0.31 to 0.33 | - |
| ping ids crossing the target, per pass | pass 1 4 of 8, pass 2 4 of 8, pass 3 4 of 8 | - |
| TCP connects failed at the cut | 0 | yes |
| TCP connects failed at the restore | 0 to 1 | yes |
| TCP connects failed elsewhere | 27 to 28 | yes |
| every bond on one leg, seconds after the fault began (the reboot or the shut) | no data | - |
| the standby returned (every bond back on two legs) | pass 1 no, pass 2 no, pass 3 no | yes |

## standby-reboot

| measure | across every pass and probe | agrees? |
|---|---|---|
| placed before the fault | pass 1 yes, pass 2 yes, pass 3 yes | yes |
| ping round trips lost, ids crossing fe-sw2 | 26 to 30 | yes |
|   of them at the cut | 12 to 14 | yes |
|   of them at the restore | 14 to 16 | yes |
| ping round trips lost, ids not crossing fe-sw2 | 0 | yes |
| longest stretch with no reply at the cut, ids crossing fe-sw2 (s) | 3.95 to 4.56 | - |
| ping ids crossing the target, per pass | pass 1 4 of 8, pass 2 4 of 8, pass 3 4 of 8 | - |
| TCP connects failed at the cut | 4 | yes |
| TCP connects failed at the restore | 5 | yes |
| TCP connects failed elsewhere | 0 | yes |
| every bond on one leg, seconds after the fault began (the reboot or the shut) | 23.2 to 23.7 | - |
| the standby returned (every bond back on two legs) | pass 1 yes, pass 2 yes, pass 3 yes | yes |

Ranges span every probe instance of every pass. A ping lost is a round trip lost, on either leg.

no disagreement between the passes

## Verdict

```
== pass 1, drill keepalive-and-peer-link: the keepalive link and the peer link shut together on fe-sw1, both keepalive paths gone
  PASS  pass 1 keepalive-and-peer-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 keepalive-and-peer-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 1 keepalive-and-peer-link: KLISH shutdown of Ethernet0,Ethernet1,Ethernet12 (PortChannel1 and the keepalive link Ethernet12) on fe-sw1 accepted
  PASS  pass 1 keepalive-and-peer-link: no shutdown accepted on fe-sw1 after 70 s
  PASS  pass 1 keepalive-and-peer-link: the pair whole and every bond back on its legs 32 s after the restore (polls 5 s apart; an event, drill.py analyze times it from the monitor)
  PASS  pass 1 keepalive-and-peer-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 keepalive-and-peer-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 1 keepalive-and-peer-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
  KNOWN pass 1 keepalive-and-peer-link: 1 duplicate ping replies (peer-link isolation is not enforced): L1
== pass 1, drill standby-reboot: the standby rebooted
  PASS  pass 1 standby-reboot: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 standby-reboot: probes located before the fault as the drill needs them (try 1): ping: 4 of 8 ids cross fe-sw2, 4 do not
  PASS  pass 1 standby-reboot: sudo reboot sent to fe-sw2, the standby (the session is cut by the reboot, under a 25 s timeout)
  PASS  pass 1 standby-reboot: fe-sw2 returned: every bond toward the pair back on two legs (an event; drill.py analyze times it)
  PASS  pass 1 standby-reboot: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 standby-reboot: fe-sw2 after its reboot: GRO, rx-gro-hw and LRO off on all 19 data NICs
  PASS  pass 1 standby-reboot: fe-sw2 after its reboot: parity, 0 missing lines
  PASS  pass 1 standby-reboot: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 1 standby-reboot: delay-restore holds nothing down, so the return is boot plus LACP, recorded as an event and never as a span: L2
== pass 2, drill keepalive-and-peer-link: the keepalive link and the peer link shut together on fe-sw1, both keepalive paths gone
  PASS  pass 2 keepalive-and-peer-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 keepalive-and-peer-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 2 keepalive-and-peer-link: KLISH shutdown of Ethernet0,Ethernet1,Ethernet12 (PortChannel1 and the keepalive link Ethernet12) on fe-sw1 accepted
  PASS  pass 2 keepalive-and-peer-link: no shutdown accepted on fe-sw1 after 70 s
  PASS  pass 2 keepalive-and-peer-link: the pair whole and every bond back on its legs 31 s after the restore (polls 5 s apart; an event, drill.py analyze times it from the monitor)
  PASS  pass 2 keepalive-and-peer-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 keepalive-and-peer-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 2 keepalive-and-peer-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== pass 2, drill standby-reboot: the standby rebooted
  PASS  pass 2 standby-reboot: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 standby-reboot: probes located before the fault as the drill needs them (try 1): ping: 4 of 8 ids cross fe-sw2, 4 do not
  PASS  pass 2 standby-reboot: sudo reboot sent to fe-sw2, the standby (the session is cut by the reboot, under a 25 s timeout)
  PASS  pass 2 standby-reboot: fe-sw2 returned: every bond toward the pair back on two legs (an event; drill.py analyze times it)
  PASS  pass 2 standby-reboot: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 standby-reboot: fe-sw2 after its reboot: GRO, rx-gro-hw and LRO off on all 19 data NICs
  PASS  pass 2 standby-reboot: fe-sw2 after its reboot: parity, 0 missing lines
  PASS  pass 2 standby-reboot: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 2 standby-reboot: delay-restore holds nothing down, so the return is boot plus LACP, recorded as an event and never as a span: L2
== pass 3, drill keepalive-and-peer-link: the keepalive link and the peer link shut together on fe-sw1, both keepalive paths gone
  PASS  pass 3 keepalive-and-peer-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 keepalive-and-peer-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 3 keepalive-and-peer-link: KLISH shutdown of Ethernet0,Ethernet1,Ethernet12 (PortChannel1 and the keepalive link Ethernet12) on fe-sw1 accepted
  PASS  pass 3 keepalive-and-peer-link: no shutdown accepted on fe-sw1 after 70 s
  PASS  pass 3 keepalive-and-peer-link: the pair whole and every bond back on its legs 32 s after the restore (polls 5 s apart; an event, drill.py analyze times it from the monitor)
  PASS  pass 3 keepalive-and-peer-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 keepalive-and-peer-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 3 keepalive-and-peer-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
  KNOWN pass 3 keepalive-and-peer-link: 1 duplicate ping replies (peer-link isolation is not enforced): L1
== pass 3, drill standby-reboot: the standby rebooted
  PASS  pass 3 standby-reboot: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 standby-reboot: probes located before the fault as the drill needs them (try 1): ping: 4 of 8 ids cross fe-sw2, 4 do not
  PASS  pass 3 standby-reboot: sudo reboot sent to fe-sw2, the standby (the session is cut by the reboot, under a 25 s timeout)
  PASS  pass 3 standby-reboot: fe-sw2 returned: every bond toward the pair back on two legs (an event; drill.py analyze times it)
  PASS  pass 3 standby-reboot: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 standby-reboot: fe-sw2 after its reboot: GRO, rx-gro-hw and LRO off on all 19 data NICs
  PASS  pass 3 standby-reboot: fe-sw2 after its reboot: parity, 0 missing lines
  PASS  pass 3 standby-reboot: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 3 standby-reboot: delay-restore holds nothing down, so the return is boot plus LACP, recorded as an event and never as a span: L2
  KNOWN pass 3 standby-reboot: 1 duplicate ping replies (peer-link isolation is not enforced): L1
== the passes compared
  PASS  compare_passes.py: no disagreement between the passes
```

== RESULT: 46 passed, 0 failed, 9 known platform limitation(s), 0 skipped
