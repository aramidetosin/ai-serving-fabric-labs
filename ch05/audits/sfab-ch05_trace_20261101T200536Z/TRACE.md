# Rail trace

- Lab: `sfab-ch05`; labs repo commit `ebc79b42ed8e7c27efd526eb0362447cb260e449`; UTC 2026-11-01T20:05:36Z
- From k8s-gpu1 to k8s-gpu2: 2 flows at 6 capture points, 3 requests each; the DF matrix 8 pings
- Label: the cross-rail flow rides the lab's IP relay, its stand-in that lets captures show PXN's path: production GPU hosts do not IP-forward between rails (NCCL moves cross-rail collective data over NVLink with PXN, and its IP control traffic uses the frontend), and rp_filter 2 belongs to the relay; production keeps 1 with per-rail policy routing

## Flows

| Flow | From | To | Request rides | Reply rides | TTL | Hops |
|---|---|---|---|---|---|---|
| `same-rail` | k8s-gpu1 `gpu1` 10.21.1.11 | k8s-gpu2 10.21.1.12 | rail 1 (rail-sw1) | rail 1 (rail-sw1) | 64 | 10.21.1.12 |
| `cross-rail` | k8s-gpu1 `gpu1` 10.21.1.11 | k8s-gpu2 10.21.2.12 | rail 2 (rail-sw2) | rail 1 (rail-sw1) | 63 | 10.21.2.11, 10.21.2.12 |

## Capture points

| Point | Where |
|---|---|
| `1-k8s-gpu1-relay0` | k8s-gpu1's relay bridge relay0 |
| `2-rail-sw1-Ethernet0` | rail-sw1 Ethernet0, facing k8s-gpu1 on rail 1 |
| `2-rail-sw2-Ethernet0` | rail-sw2 Ethernet0, facing k8s-gpu1 on rail 2 |
| `3-rail-sw1-Ethernet4` | rail-sw1 Ethernet4, facing k8s-gpu2 on rail 1 |
| `3-rail-sw2-Ethernet4` | rail-sw2 Ethernet4, facing k8s-gpu2 on rail 2 |
| `4-k8s-gpu2-relay0` | k8s-gpu2's relay bridge relay0 |

## Verdict

```
== health: the same rail on every rail, k8s-gpu1's GPU namespaces to k8s-gpu2
  PASS  rail 1 (rail-sw1): k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.1.12: 2 of 2 answered
  PASS  rail 2 (rail-sw2): k8s-gpu1 (gpu2, 10.21.2.11) to 10.21.2.12: 2 of 2 answered
  PASS  rail 3 (rail-sw1): k8s-gpu1 (gpu3, 10.21.3.11) to 10.21.3.12: 2 of 2 answered
  PASS  rail 4 (rail-sw2): k8s-gpu1 (gpu4, 10.21.4.11) to 10.21.4.12: 2 of 2 answered
  PASS  rail 5 (rail-sw1): k8s-gpu1 (gpu5, 10.21.5.11) to 10.21.5.12: 2 of 2 answered
  PASS  rail 6 (rail-sw2): k8s-gpu1 (gpu6, 10.21.6.11) to 10.21.6.12: 2 of 2 answered
  PASS  rail 7 (rail-sw1): k8s-gpu1 (gpu7, 10.21.7.11) to 10.21.7.12: 2 of 2 answered
  PASS  rail 8 (rail-sw2): k8s-gpu1 (gpu8, 10.21.8.11) to 10.21.8.12: 2 of 2 answered
== flow same-rail: k8s-gpu1 namespace gpu1 (10.21.1.11) to k8s-gpu2 10.21.1.12, rail 1 to rail 1
  PASS  the ping: 3 of 3 answered, every reply at TTL 64
  PASS  1-k8s-gpu1-relay0 (k8s-gpu1's relay bridge relay0): no request, no reply
  PASS  2-rail-sw1-Ethernet0 (rail-sw1 Ethernet0, facing k8s-gpu1 on rail 1): 3 requests at TTL 64, 3 replies at TTL 64
  PASS  2-rail-sw2-Ethernet0 (rail-sw2 Ethernet0, facing k8s-gpu1 on rail 2): no request, no reply
  PASS  3-rail-sw1-Ethernet4 (rail-sw1 Ethernet4, facing k8s-gpu2 on rail 1): 3 requests at TTL 64, 3 replies at TTL 64
  PASS  3-rail-sw2-Ethernet4 (rail-sw2 Ethernet4, facing k8s-gpu2 on rail 2): no request, no reply
  PASS  4-k8s-gpu2-relay0 (k8s-gpu2's relay bridge relay0): no request, no reply
  PASS  the request crossed rail-sw1 (rail 1, the destination's rail) and the reply rail-sw1 (rail 1, the source's)
  PASS  the request with seq 1 carries one IP id at every point that saw it (2 points; TTL 64 at 2-rail-sw1-Ethernet0, 64 at 3-rail-sw1-Ethernet4)
  PASS  traceroute: 1 hop, 10.21.1.12
== flow cross-rail: k8s-gpu1 namespace gpu1 (10.21.1.11) to k8s-gpu2 10.21.2.12, rail 1 to rail 2
  PASS  the ping: 3 of 3 answered, every reply at TTL 63
  PASS  1-k8s-gpu1-relay0 (k8s-gpu1's relay bridge relay0): 3 requests at TTL 64, no reply
  PASS  2-rail-sw1-Ethernet0 (rail-sw1 Ethernet0, facing k8s-gpu1 on rail 1): no request, 3 replies at TTL 63
  PASS  2-rail-sw2-Ethernet0 (rail-sw2 Ethernet0, facing k8s-gpu1 on rail 2): 3 requests at TTL 63, no reply
  PASS  3-rail-sw1-Ethernet4 (rail-sw1 Ethernet4, facing k8s-gpu2 on rail 1): no request, 3 replies at TTL 63
  PASS  3-rail-sw2-Ethernet4 (rail-sw2 Ethernet4, facing k8s-gpu2 on rail 2): 3 requests at TTL 63, no reply
  PASS  4-k8s-gpu2-relay0 (k8s-gpu2's relay bridge relay0): no request, 3 replies at TTL 64
  PASS  the request crossed rail-sw2 (rail 2, the destination's rail) and the reply rail-sw1 (rail 1, the source's)
  PASS  the request with seq 1 carries one IP id at every point that saw it (3 points; TTL 64 at 1-k8s-gpu1-relay0, 63 at 2-rail-sw2-Ethernet0, 63 at 3-rail-sw2-Ethernet4)
  PASS  traceroute: 2 hops, 10.21.2.11 (k8s-gpu1's own address on rail 2: its namespace on that rail forwarded the probe and answers from its route's pinned source), then 10.21.2.12
== the DF probe matrix: 2 paths, both directions, at 9000, 9001 bytes, the don't-fragment bit set
  PASS  same-rail forward, 9000 bytes: k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.1.12: 3 of 3 answered
  PASS  ... its requests and replies at 2-rail-sw1-Ethernet0, 3-rail-sw1-Ethernet4 as 9014-byte frames (IP 9000), every request with DF set, and at no other point
  PASS  ... the far node's echo replies carry no DF (recorded: ping sets DF on its requests; the reply is the far kernel's own)
  PASS  same-rail forward, 9001 bytes: k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.1.12: refused at the sender's own interface: message too long, mtu 9000
  PASS  ... and no frame of it at any capture point
  PASS  same-rail reverse, 9000 bytes: k8s-gpu2 (gpu1, 10.21.1.12) to 10.21.1.11: 3 of 3 answered
  PASS  ... its requests and replies at 2-rail-sw1-Ethernet0, 3-rail-sw1-Ethernet4 as 9014-byte frames (IP 9000), every request with DF set, and at no other point
  PASS  ... the far node's echo replies carry no DF (recorded: ping sets DF on its requests; the reply is the far kernel's own)
  PASS  same-rail reverse, 9001 bytes: k8s-gpu2 (gpu1, 10.21.1.12) to 10.21.1.11: refused at the sender's own interface: message too long, mtu 9000
  PASS  ... and no frame of it at any capture point
  PASS  cross-rail forward, 9000 bytes: k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.2.12: 3 of 3 answered
  PASS  ... its requests and replies at 1-k8s-gpu1-relay0, 2-rail-sw1-Ethernet0, 2-rail-sw2-Ethernet0, 3-rail-sw1-Ethernet4, 3-rail-sw2-Ethernet4, 4-k8s-gpu2-relay0 as 9014-byte frames (IP 9000), every request with DF set, and at no other point
  PASS  ... the far node's echo replies carry no DF (recorded: ping sets DF on its requests; the reply is the far kernel's own)
  PASS  cross-rail forward, 9001 bytes: k8s-gpu1 (gpu1, 10.21.1.11) to 10.21.2.12: refused at the sender's own interface: message too long, mtu 9000
  PASS  ... and no frame of it at any capture point
  PASS  cross-rail reverse, 9000 bytes: k8s-gpu2 (gpu2, 10.21.2.12) to 10.21.1.11: 3 of 3 answered
  PASS  ... its requests and replies at 1-k8s-gpu1-relay0, 2-rail-sw1-Ethernet0, 2-rail-sw2-Ethernet0, 3-rail-sw1-Ethernet4, 3-rail-sw2-Ethernet4, 4-k8s-gpu2-relay0 as 9014-byte frames (IP 9000), every request with DF set, and at no other point
  PASS  ... the far node's echo replies carry no DF (recorded: ping sets DF on its requests; the reply is the far kernel's own)
  PASS  cross-rail reverse, 9001 bytes: k8s-gpu2 (gpu2, 10.21.2.12) to 10.21.1.11: refused at the sender's own interface: message too long, mtu 9000
  PASS  ... and no frame of it at any capture point
  PASS  the paths' ceiling: 9000 bytes answered on every path both ways, 9001 the first size refused on every one (the relay's and the rail NICs' MTU is 9000)
```

## Frames per point

| Point | `same-rail` requests (TTL) | replies (TTL) | `cross-rail` requests (TTL) | replies (TTL) |
|---|---|---|---|---|
| `1-k8s-gpu1-relay0` | 0 (-) | 0 (-) | 3 (64) | 0 (-) |
| `2-rail-sw1-Ethernet0` | 3 (64) | 3 (64) | 0 (-) | 3 (63) |
| `2-rail-sw2-Ethernet0` | 0 (-) | 0 (-) | 3 (63) | 0 (-) |
| `3-rail-sw1-Ethernet4` | 3 (64) | 3 (64) | 0 (-) | 3 (63) |
| `3-rail-sw2-Ethernet4` | 0 (-) | 0 (-) | 3 (63) | 0 (-) |
| `4-k8s-gpu2-relay0` | 0 (-) | 0 (-) | 0 (-) | 3 (64) |

## Flow same-rail

- `2-rail-sw1-Ethernet0`, first request (`captures/2-rail-sw1-Ethernet0.txt:2`)

  ```
  2026-11-01 20:05:51.369155 02:5a:6f:01:00:04 > 02:5a:70:01:00:04, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 62251, offset 0, flags [DF], proto ICMP (1), length 84)
      10.21.1.11 > 10.21.1.12: ICMP echo request, id 5101, seq 1, length 64
  ```

- `2-rail-sw1-Ethernet0`, first reply (`captures/2-rail-sw1-Ethernet0.txt:4`)

  ```
  2026-11-01 20:05:51.370566 02:5a:70:01:00:04 > 02:5a:6f:01:00:04, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 62572, offset 0, flags [none], proto ICMP (1), length 84)
      10.21.1.12 > 10.21.1.11: ICMP echo reply, id 5101, seq 1, length 64
  ```

- `3-rail-sw1-Ethernet4`, first request (`captures/3-rail-sw1-Ethernet4.txt:2`)

  ```
  2026-11-01 20:05:51.369674 02:5a:6f:01:00:04 > 02:5a:70:01:00:04, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 62251, offset 0, flags [DF], proto ICMP (1), length 84)
      10.21.1.11 > 10.21.1.12: ICMP echo request, id 5101, seq 1, length 64
  ```

- `3-rail-sw1-Ethernet4`, first reply (`captures/3-rail-sw1-Ethernet4.txt:4`)

  ```
  2026-11-01 20:05:51.370206 02:5a:70:01:00:04 > 02:5a:6f:01:00:04, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 62572, offset 0, flags [none], proto ICMP (1), length 84)
      10.21.1.12 > 10.21.1.11: ICMP echo reply, id 5101, seq 1, length 64
  ```

traceroute (`flows/same-rail/traceroute.txt`)

```
traceroute to 10.21.1.12 (10.21.1.12), 4 hops max, 60 byte packets
 1  10.21.1.12  2.318 ms  2.241 ms  2.194 ms
```

## Flow cross-rail

- `1-k8s-gpu1-relay0`, first request (`captures/1-k8s-gpu1-relay0.txt:2`)

  ```
  2026-11-01 20:05:51.479800 92:f1:7e:f2:2b:e2 > be:d8:b3:98:d9:c2, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 14726, offset 0, flags [DF], proto ICMP (1), length 84)
      10.21.1.11 > 10.21.2.12: ICMP echo request, id 5102, seq 1, length 64
  ```

- `2-rail-sw1-Ethernet0`, first reply (`captures/2-rail-sw1-Ethernet0.txt:14`)

  ```
  2026-11-01 20:05:52.893291 02:5a:70:01:00:04 > 02:5a:6f:01:00:04, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 63, id 3933, offset 0, flags [none], proto ICMP (1), length 84)
      10.21.2.12 > 10.21.1.11: ICMP echo reply, id 5102, seq 1, length 64
  ```

- `2-rail-sw2-Ethernet0`, first request (`captures/2-rail-sw2-Ethernet0.txt:2`)

  ```
  2026-11-01 20:05:52.891688 02:5a:6f:01:00:05 > 02:5a:70:01:00:05, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 63, id 14726, offset 0, flags [DF], proto ICMP (1), length 84)
      10.21.1.11 > 10.21.2.12: ICMP echo request, id 5102, seq 1, length 64
  ```

- `3-rail-sw1-Ethernet4`, first reply (`captures/3-rail-sw1-Ethernet4.txt:14`)

  ```
  2026-11-01 20:05:52.892641 02:5a:70:01:00:04 > 02:5a:6f:01:00:04, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 63, id 3933, offset 0, flags [none], proto ICMP (1), length 84)
      10.21.2.12 > 10.21.1.11: ICMP echo reply, id 5102, seq 1, length 64
  ```

- `3-rail-sw2-Ethernet4`, first request (`captures/3-rail-sw2-Ethernet4.txt:2`)

  ```
  2026-11-01 20:05:52.892145 02:5a:6f:01:00:05 > 02:5a:70:01:00:05, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 63, id 14726, offset 0, flags [DF], proto ICMP (1), length 84)
      10.21.1.11 > 10.21.2.12: ICMP echo request, id 5102, seq 1, length 64
  ```

- `4-k8s-gpu2-relay0`, first reply (`captures/4-k8s-gpu2-relay0.txt:2`)

  ```
  2026-11-01 20:05:52.116932 de:3b:66:32:1c:e3 > 86:5c:49:bb:8f:a9, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 3933, offset 0, flags [none], proto ICMP (1), length 84)
      10.21.2.12 > 10.21.1.11: ICMP echo reply, id 5102, seq 1, length 64
  ```

traceroute (`flows/cross-rail/traceroute.txt`)

```
traceroute to 10.21.2.12 (10.21.2.12), 4 hops max, 60 byte packets
 1  10.21.2.11  0.078 ms  0.014 ms  0.013 ms
 2  10.21.2.12  2.249 ms  2.198 ms  2.167 ms
```

## The DF probe matrix

| Row | Size | Answered | Refusal | Frames at the points | Replies' DF |
|---|---|---|---|---|---|
| `same-rail-forward-9000` | 9000 | 3 of 3 | - | 9014 | not set |
| `same-rail-forward-9001` | 9001 | 0 of 3 | refused at the sender's own interface: message too long, mtu 9000 | none | - |
| `same-rail-reverse-9000` | 9000 | 3 of 3 | - | 9014 | not set |
| `same-rail-reverse-9001` | 9001 | 0 of 3 | refused at the sender's own interface: message too long, mtu 9000 | none | - |
| `cross-rail-forward-9000` | 9000 | 3 of 3 | - | 9014 | not set |
| `cross-rail-forward-9001` | 9001 | 0 of 3 | refused at the sender's own interface: message too long, mtu 9000 | none | - |
| `cross-rail-reverse-9000` | 9000 | 3 of 3 | - | 9014 | not set |
| `cross-rail-reverse-9001` | 9001 | 0 of 3 | refused at the sender's own interface: message too long, mtu 9000 | none | - |

## Files

- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`
- `health/rail<r>.txt`; `flows/<flow>/ping.txt` and `traceroute.txt`; `df/<row>.txt`
- `captures/<point>.pcap` and `.txt` (the flows), `captures-df/<point>.pcap` and `.txt` (the DF matrix), decoded with `tcpdump -nn -e -tttt -v -r` (a guest's in the guest)

== RESULT: 49 passed, 0 failed, 0 known platform limitation(s), 0 skipped
