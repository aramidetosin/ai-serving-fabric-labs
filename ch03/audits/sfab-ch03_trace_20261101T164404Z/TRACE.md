# Trace enterprise-users-vip

- Lab: `sfab-ch03`; labs repo commit `323633721b09abf17ff185f83c7a0e862a190b7a`; UTC 2026-11-01T16:44:04Z
- Flow: `ent-client` (10.24.10.10) to `https://llm.ai.tarnwick.example/echo?msg=sfab-ch03-trace` on 10.20.11.210:443 (Gateway `gw-users`), source port 41443 pinned, after a warm-up from 41442
- Lease holder: `k8s-ingress1`; capture points: 7

## Path

| Depth | Point | Where | Node | Interface | Expected tag |
|---|---|---|---|---|---|
| 1 | `1-fw-ae1-leg1` | container | fw | eth1 | 110 |
| 1 | `1-fw-ae1-leg2` | container | fw | eth2 | 110 |
| 2 | `2-fe-sw1-Ethernet2` | container | fe-sw1 | eth3 | 110 |
| 2 | `2-fe-sw2-Ethernet2` | container | fe-sw2 | eth3 | 110 |
| 3 | `3-fe-sw1-Ethernet13` | container | fe-sw1 | eth14 | 110 |
| 3 | `3-fe-sw2-Ethernet13` | container | fe-sw2 | eth14 | 110 |
| 4 | `4-k8s-ingress1-bond0` | guest | k8s-ingress1 | bond0 | 110 |

## Verdict

```
== trace enterprise-users-vip: ent-client (10.24.10.10) to llm.ai.tarnwick.example on 10.20.11.210:443
  PASS  ent-client resolves llm.ai.tarnwick.example through 10.24.10.53 to the users' VIP 10.20.11.210
  PASS  the gw-users Service's L2 announcement lease holder is an ingress node (k8s-ingress1)
  PASS  warm-up attempt from source port 41442 made first (HTTP 200; not judged)
  PASS  the recorded SYN from ent-client's pinned source port 41443 found at 1-fw-ae1-leg1 (seq 590137068)
  PASS  7 capture points decoded (7 with a decode)
== the SYN at each point
  PASS  4-k8s-ingress1-bond0: the recorded SYN seen (seq 590137068)
  PASS  exactly one of the ae1 points carries the SYN (1-fw-ae1-leg1, 1-fw-ae1-leg2)
  PASS  exactly one of the trunk points carries the SYN (2-fe-sw1-Ethernet2, 2-fe-sw2-Ethernet2)
  PASS  exactly one of the server points carries the SYN (3-fe-sw1-Ethernet13, 3-fe-sw2-Ethernet13)
  PASS  the SYN's trunk port is the pair port its ae1 leg lands on (1-fw-ae1-leg1 to fe-sw1:eth3)
  PASS  the SYN leaves the pair on the switch that received it (fe-sw1)
== tags, TTL and addresses
  PASS  1-fw-ae1-leg1: tagged 802.1Q 110
  PASS  2-fe-sw1-Ethernet2: tagged 802.1Q 110
  PASS  3-fe-sw1-Ethernet13: tagged 802.1Q 110
  PASS  4-k8s-ingress1-bond0: tagged 802.1Q 110
  PASS  source 10.24.10.10 and destination 10.20.11.210:443 unchanged at every point (no translation)
== one frame at every point
  PASS  source MAC ba:db:ee:fb:ad:f0 the same at all 4 points that saw the SYN
  PASS  destination MAC 02:5a:68:00:00:01 the same at all 4 points that saw the SYN
  PASS  source address 10.24.10.10 the same at all 4 points that saw the SYN
  PASS  destination address 10.20.11.210 the same at all 4 points that saw the SYN
  PASS  IP id 18529 the same at all 4 points that saw the SYN
  PASS  TTL 63 the same at all 4 points that saw the SYN
  PASS  destination MAC is k8s-ingress1's bond0 MAC 02:5a:68:00:00:01 (the frame is addressed to the node, not to a router)
== the reply and the firewall's witness
  PASS  https://llm.ai.tarnwick.example/echo?msg=sfab-ch03-trace answers 200 with the echoed message sfab-ch03-trace
  PASS  the firewall's traffic log has the session allowed by staff-to-users-gateway (shown as staff-to-users-gate), zone enterprise to zone ingress
```

## Frames per point

| Point | Frames | SYNs with seq 590137068 | Source MAC | Destination MAC | IP id | TTL | Tag | Checksum |
|---|---|---|---|---|---|---|---|---|
| `1-fw-ae1-leg1` | 33 | 1 | ba:db:ee:fb:ad:f0 | 02:5a:68:00:00:01 | 18529 | 63 | 110 | correct |
| `1-fw-ae1-leg2` | 17 | 0 | - | - | - | - | - | - |
| `2-fe-sw1-Ethernet2` | 33 | 1 | ba:db:ee:fb:ad:f0 | 02:5a:68:00:00:01 | 18529 | 63 | 110 | correct |
| `2-fe-sw2-Ethernet2` | 17 | 0 | - | - | - | - | - | - |
| `3-fe-sw1-Ethernet13` | 27 | 1 | ba:db:ee:fb:ad:f0 | 02:5a:68:00:00:01 | 18529 | 63 | 110 | correct |
| `3-fe-sw2-Ethernet13` | 11 | 0 | - | - | - | - | - | - |
| `4-k8s-ingress1-bond0` | 38 | 1 | ba:db:ee:fb:ad:f0 | 02:5a:68:00:00:01 | 18529 | 63 | 110 | correct |

## The first SYN at each point

- `1-fw-ae1-leg1` (`captures/1-fw-ae1-leg1.txt:18`)

  ```
  2026-11-01 16:44:13.878298 ba:db:ee:fb:ad:f0 > 02:5a:68:00:00:01, ethertype 802.1Q (0x8100), length 78: vlan 110, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 63, id 18529, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `1-fw-ae1-leg2`: not seen
- `2-fe-sw1-Ethernet2` (`captures/2-fe-sw1-Ethernet2.txt:18`)

  ```
  2026-11-01 16:44:13.878305 ba:db:ee:fb:ad:f0 > 02:5a:68:00:00:01, ethertype 802.1Q (0x8100), length 78: vlan 110, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 63, id 18529, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `2-fe-sw2-Ethernet2`: not seen
- `3-fe-sw1-Ethernet13` (`captures/3-fe-sw1-Ethernet13.txt:18`)

  ```
  2026-11-01 16:44:13.878729 ba:db:ee:fb:ad:f0 > 02:5a:68:00:00:01, ethertype 802.1Q (0x8100), length 78: vlan 110, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 63, id 18529, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `3-fe-sw2-Ethernet13`: not seen
- `4-k8s-ingress1-bond0` (`captures/4-k8s-ingress1-bond0.txt:40`)

  ```
  2026-11-01 16:44:13.878586 ba:db:ee:fb:ad:f0 > 02:5a:68:00:00:01, ethertype 802.1Q (0x8100), length 78: vlan 110, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 63, id 18529, offset 0, flags [DF], proto TCP (6), length 60)
  ```

## Files

- `verdict.txt`, `commands.txt`, `dns.txt`, `warmup.txt`, `request.txt`, `fw-traffic-log.txt`, `points.tsv`
- `captures/<point>.pcap` and `captures/<point>.txt` (decoded with `tcpdump -nn -e -tttt -v -S -r`; guest points decoded in the guest)

== RESULT: 25 passed, 0 failed, 0 known platform limitation(s), 0 skipped
