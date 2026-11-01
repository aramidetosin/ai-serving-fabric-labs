# Drills sfab-ch03_drills_20261101T151630Z

- Lab: `sfab-ch03`; labs repo commit `323633721b09abf17ff185f83c7a0e862a190b7a`; UTC 2026-11-01T15:16:30Z; host tick 10000
- Probes: a ping from the source guest to the far guest, one ICMP id per process, each placed on a bond leg by the guests' hash; a TCP connect loop from the enterprise client to the users' VIP, a new source port per attempt, placed by the firewall's hash. Captures on the lab host locate every probe before the fault and timestamp it; the guest's own ping log is the second witness.
- A lost ping is a round trip lost, on either leg. A reply later than a second counts as lost. Every shut is a KLISH shutdown from the switch side, which drops no carrier at the far end, so every member figure is an LACP-timeout figure.

## keepalive-link: the dedicated keepalive link shut on fe-sw1 with the peer link and the backup keepalive up

| Pass | Placed | Ping ids crossing fe-sw1: lost at the cut | at the restore | Other ids: lost | Longest no-reply stretch at the cut (s) | TCP failed at the cut | at the restore |
|---|---|---|---|---|---|---|---|
| 1 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 20, 20, 20, 20 | 0.307, 0.303, 0.337, 0.332 | 0 | 0 |
| 2 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 21, 21, 21, 21 | 0.308, 0.308, 0.316, 0.308 | 0 | 0 |
| 3 | yes | 0, 0, 0, 0 | 0, 0, 0, 0 | 21, 21, 21, 21 | 0.328, 0.333, 0.321, 0.328 | 0 | 0 |

Pass 1, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T15:18:17.83Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T15:18:53.87Z: every bond toward the pair on one leg
- 2026-11-01T15:18:53.87Z: the keepalive OK on both switches
- 2026-11-01T15:18:53.87Z: the standby's own MCLAG PortChannels read down or traffic-disabled, the standby still answering
- 2026-11-01T15:23:57.28Z: every bond toward the pair back on two legs: the return
- 2026-11-01T15:23:57.28Z: the firewall's ae1 on both legs
- 2026-11-01T15:23:57.28Z: every MCLAG PortChannel up on the standby

Pass 2, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T15:28:09.70Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T15:28:26.77Z: the standby's own MCLAG PortChannels read down or traffic-disabled, the standby still answering
- 2026-11-01T15:28:44.92Z: every bond toward the pair on one leg
- 2026-11-01T15:28:44.92Z: the keepalive OK on both switches
- 2026-11-01T15:33:47.25Z: every bond toward the pair back on two legs: the return
- 2026-11-01T15:33:47.25Z: every MCLAG PortChannel up on the standby
- 2026-11-01T15:33:56.83Z: the firewall's ae1 on both legs

Pass 3, the standby fe-sw2: departure, then its return as an event (host clock):

- 2026-11-01T15:37:58.04Z: the active's iccpd no longer reports the keepalive OK
- 2026-11-01T15:38:15.24Z: the standby's own MCLAG PortChannels read down or traffic-disabled, the standby still answering
- 2026-11-01T15:38:32.88Z: every bond toward the pair on one leg
- 2026-11-01T15:38:32.88Z: the keepalive OK on both switches
- 2026-11-01T15:43:35.24Z: every bond toward the pair back on two legs: the return
- 2026-11-01T15:43:35.24Z: the firewall's ae1 on both legs
- 2026-11-01T15:43:35.24Z: every MCLAG PortChannel up on the standby

Per pass: `pass<N>/keepalive-link/analysis.txt` (every probe instance), `placement.txt`, `timeline.txt`, `captures/`, `logs/`, `klish/`.

## The passes compared

Passes compared: pass1, pass2, pass3 in sfab-ch03_drills_20261101T151630Z

## keepalive-link

| measure | across every pass and probe | agrees? |
|---|---|---|
| placed before the fault | pass 1 yes, pass 2 yes, pass 3 yes | yes |
| ping round trips lost, ids crossing fe-sw1 | 0 | yes |
|   of them at the cut | 0 | yes |
|   of them at the restore | 0 | yes |
| ping round trips lost, ids not crossing fe-sw1 | 20 to 21 | yes |
| longest stretch with no reply at the cut, ids crossing fe-sw1 (s) | 0.30 to 0.34 | - |
| ping ids crossing the target, per pass | pass 1 4 of 8, pass 2 4 of 8, pass 3 4 of 8 | - |
| TCP connects failed at the cut | 0 | yes |
| TCP connects failed at the restore | 0 | yes |
| TCP connects failed elsewhere | 18 to 31 | yes |
| every bond on one leg, seconds after the fault began (the reboot or the shut) | 74.6 to 76.3 | - |
| the standby returned (every bond back on two legs) | pass 1 yes, pass 2 yes, pass 3 yes | yes |

Ranges span every probe instance of every pass. A ping lost is a round trip lost, on either leg.

no disagreement between the passes

## Verdict

```
== pass 1, drill keepalive-link: the dedicated keepalive link shut on fe-sw1 with the peer link and the backup keepalive up
  PASS  pass 1 keepalive-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 keepalive-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 1 keepalive-link: KLISH shutdown of Ethernet12 (the keepalive link Ethernet12) on fe-sw1 accepted
  PASS  pass 1 keepalive-link: no shutdown accepted on fe-sw1 after 70 s
  PASS  pass 1 keepalive-link: the pair whole and every bond back on its legs 327 s after the restore (polls 5 s apart; an event, drill.py analyze times it from the monitor)
  PASS  pass 1 keepalive-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 1 keepalive-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 1 keepalive-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
  KNOWN pass 1 keepalive-link: 2 duplicate ping replies (peer-link isolation is not enforced): L1
== pass 2, drill keepalive-link: the dedicated keepalive link shut on fe-sw1 with the peer link and the backup keepalive up
  PASS  pass 2 keepalive-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 keepalive-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 2 keepalive-link: KLISH shutdown of Ethernet12 (the keepalive link Ethernet12) on fe-sw1 accepted
  PASS  pass 2 keepalive-link: no shutdown accepted on fe-sw1 after 70 s
  PASS  pass 2 keepalive-link: the pair whole and every bond back on its legs 326 s after the restore (polls 5 s apart; an event, drill.py analyze times it from the monitor)
  PASS  pass 2 keepalive-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 2 keepalive-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 2 keepalive-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== pass 3, drill keepalive-link: the dedicated keepalive link shut on fe-sw1 with the peer link and the backup keepalive up
  PASS  pass 3 keepalive-link: the lab whole before the fault: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 keepalive-link: probes located before the fault as the drill needs them (try 1): ping: requests leave fe-sw1, fe-sw2
  PASS  pass 3 keepalive-link: KLISH shutdown of Ethernet12 (the keepalive link Ethernet12) on fe-sw1 accepted
  PASS  pass 3 keepalive-link: no shutdown accepted on fe-sw1 after 70 s
  PASS  pass 3 keepalive-link: the pair whole and every bond back on its legs 343 s after the restore (polls 5 s apart; an event, drill.py analyze times it from the monitor)
  PASS  pass 3 keepalive-link: the lab whole again after the drill: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll 2)
  PASS  pass 3 keepalive-link: audit.sh --quick after the drill: RESULT: 239 passed, 0 failed, 0 known platform limitation(s), 1 skipped
  KNOWN pass 3 keepalive-link: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure: L9
== the passes compared
  PASS  compare_passes.py: no disagreement between the passes
```

== RESULT: 22 passed, 0 failed, 4 known platform limitation(s), 0 skipped
