# Trace enterprise-users-vip

- Lab: `sfab-m2`; labs repo commit `none`; UTC 2026-10-20T06:26:33Z
- Flow: `ent-client` (10.24.10.10) to `https://llm.tarnwick.example/echo?msg=sfab-m2-trace` on 10.20.1.210:443 (Gateway `gw-users`), source port 41443 pinned, after a warm-up from 41442
- Lease holder: `ctrl2`; capture points: 9

## Path

| Depth | Point | Where | Node | Interface | Expected tag |
|---|---|---|---|---|---|
| 1 | `1-ent-client-eth1` | container | ent-client | eth1 | none |
| 2 | `2-fw-ethernet1-4` | container | fw | eth4 | none |
| 3 | `3-fw-ae1-leg1` | container | fw | eth1 | 100 |
| 3 | `3-fw-ae1-leg2` | container | fw | eth2 | 100 |
| 4 | `4-fe-sw1-Ethernet2` | container | fe-sw1 | eth3 | 100 |
| 4 | `4-fe-sw2-Ethernet2` | container | fe-sw2 | eth3 | 100 |
| 5 | `5-fe-sw1-Ethernet4` | container | fe-sw1 | eth5 | none |
| 5 | `5-fe-sw2-Ethernet4` | container | fe-sw2 | eth5 | none |
| 6 | `6-ctrl2-bond0` | guest | ctrl2 | bond0 | none |

## Verdict

```
== trace enterprise-users-vip: ent-client (10.24.10.10) to llm.tarnwick.example on 10.20.1.210:443
  PASS  ent-client resolves llm.tarnwick.example through 10.20.3.10 to the users' VIP 10.20.1.210
  PASS  the gw-users Service's L2 announcement lease holder is a control node (ctrl2)
  PASS  warm-up attempt from source port 41442 made first (HTTP 200; not judged)
  PASS  the recorded SYN leaves ent-client from the pinned source port 41443 (seq 3857828278)
  PASS  9 capture points decoded (9 with a decode)
== the SYN at each point
  PASS  1-ent-client-eth1: the recorded SYN seen (seq 3857828278)
  PASS  2-fw-ethernet1-4: the recorded SYN seen (seq 3857828278)
  PASS  6-ctrl2-bond0: the recorded SYN seen (seq 3857828278)
  PASS  exactly one of the ae1 points carries the SYN (3-fw-ae1-leg1, 3-fw-ae1-leg2)
  PASS  exactly one of the trunk points carries the SYN (4-fe-sw1-Ethernet2, 4-fe-sw2-Ethernet2)
  PASS  exactly one of the server points carries the SYN (5-fe-sw1-Ethernet4, 5-fe-sw2-Ethernet4)
  PASS  the SYN's trunk port is the pair port its ae1 leg lands on (3-fw-ae1-leg1 to fe-sw1:eth3)
  PASS  the SYN leaves the pair on the switch that received it (fe-sw1)
== tags, TTL and addresses
  PASS  1-ent-client-eth1: untagged
  PASS  2-fw-ethernet1-4: untagged
  PASS  3-fw-ae1-leg1: tagged 802.1Q 100
  PASS  4-fe-sw1-Ethernet2: tagged 802.1Q 100
  PASS  5-fe-sw1-Ethernet4: untagged
  PASS  6-ctrl2-bond0: untagged
  PASS  TTL 64 up to the firewall, 63 after it: one routed hop
  PASS  source 10.24.10.10 and destination 10.20.1.210:443 unchanged at every point (no translation)
== the reply and the firewall's witness
  PASS  https://llm.tarnwick.example/echo?msg=sfab-m2-trace answers 200 with the echoed message sfab-m2-trace
  PASS  the firewall's traffic log has the session allowed by enterprise-to-users-gateway (shown as enterprise-to-users), zone enterprise to zone data
```

## Frames per point

| Point | Frames | SYNs with seq 3857828278 | TTL | Tag | Checksum |
|---|---|---|---|---|---|
| `1-ent-client-eth1` | 38 | 1 | 64 | none | correct |
| `2-fw-ethernet1-4` | 38 | 1 | 64 | none | correct |
| `3-fw-ae1-leg1` | 11 | 1 | 63 | 100 | correct |
| `3-fw-ae1-leg2` | 27 | 0 | - | - | - |
| `4-fe-sw1-Ethernet2` | 11 | 1 | 63 | 100 | correct |
| `4-fe-sw2-Ethernet2` | 27 | 0 | - | - | - |
| `5-fe-sw1-Ethernet4` | 11 | 1 | 63 | none | correct |
| `5-fe-sw2-Ethernet4` | 27 | 0 | - | - | - |
| `6-ctrl2-bond0` | 38 | 1 | 63 | none | correct |

## The first SYN at each point

- `1-ent-client-eth1` (`captures/1-ent-client-eth1.txt:40`)

  ```
  2026-10-20 06:26:40.878023 aa:c1:ab:e1:a4:c6 > aa:c1:ab:f3:d7:34, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 64, id 38029, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `2-fw-ethernet1-4` (`captures/2-fw-ethernet1-4.txt:40`)

  ```
  2026-10-20 06:26:40.878026 aa:c1:ab:e1:a4:c6 > aa:c1:ab:f3:d7:34, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 64, id 38029, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `3-fw-ae1-leg1` (`captures/3-fw-ae1-leg1.txt:2`)

  ```
  2026-10-20 06:26:40.878193 ba:db:ee:fb:ad:f0 > 02:5a:66:00:00:01, ethertype 802.1Q (0x8100), length 78: vlan 100, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 63, id 38029, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `3-fw-ae1-leg2`: not seen
- `4-fe-sw1-Ethernet2` (`captures/4-fe-sw1-Ethernet2.txt:2`)

  ```
  2026-10-20 06:26:40.878194 ba:db:ee:fb:ad:f0 > 02:5a:66:00:00:01, ethertype 802.1Q (0x8100), length 78: vlan 100, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 63, id 38029, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `4-fe-sw2-Ethernet2`: not seen
- `5-fe-sw1-Ethernet4` (`captures/5-fe-sw1-Ethernet4.txt:2`)

  ```
  2026-10-20 06:26:40.878256 ba:db:ee:fb:ad:f0 > 02:5a:66:00:00:01, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 63, id 38029, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `5-fe-sw2-Ethernet4`: not seen
- `6-ctrl2-bond0` (`captures/6-ctrl2-bond0.txt:40`)

  ```
  2026-10-20 06:26:40.878994 ba:db:ee:fb:ad:f0 > 02:5a:66:00:00:01, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 63, id 38029, offset 0, flags [DF], proto TCP (6), length 60)
  ```

## Files

- `verdict.txt`, `commands.txt`, `dns.txt`, `warmup.txt`, `request.txt`, `fw-traffic-log.txt`, `points.tsv`
- `captures/<point>.pcap` and `captures/<point>.txt` (decoded with `tcpdump -nn -e -tttt -v -S -r`; guest points decoded in the guest)

== RESULT: 23 passed, 0 failed, 0 known platform limitation(s), 0 skipped
