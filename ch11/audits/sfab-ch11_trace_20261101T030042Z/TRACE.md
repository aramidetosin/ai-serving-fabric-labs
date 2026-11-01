# The capture ladder

- Lab: `sfab-ch11`; labs repo commit `86a59ddfea6f405c4d6d70af509ef75a856ac3a8`; UTC 2026-11-01T03:00:42Z
- 15 flows (every population of the matrix to each Gateway's VIP), 11 rungs; each forbidden flow tried from its own source ports, its SYNs counted by distinct sequence number

| Flow | Mode | `1-isp-rtr-eth1` | `1-uplink-rtr-eth1` | `2-fw-ethernet1-4` | `3-fw-ae1-leg1` | `3-fw-ae1-leg2` | `4-fe-sw1-Ethernet13` | `4-fe-sw1-Ethernet14` | `4-fe-sw2-Ethernet13` | `4-fe-sw2-Ethernet14` | `5-k8s-ingress1-bond0.110` | `5-k8s-ingress2-bond0.110` |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `enterprise/gw-internal` | log-line | 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `enterprise/gw-users` | allowed | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0 |
| `enterprise/gw-inet` | log-line | 0 | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `operator/gw-internal` | allowed | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 1 | 0 |
| `operator/gw-users` | log-line | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `operator/gw-inet` | log-line | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `nodes/gw-internal` | allowed, on the node | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `nodes/gw-users` | allowed, on the node | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `nodes/gw-inet` | allowed, on the node | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `web/gw-internal` | log-line | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `web/gw-users` | log-line | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `web/gw-inet` | log-line | 0 | 3 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `internet/gw-internal` | silence | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `internet/gw-users` | silence | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `internet/gw-inet` | allowed | 1 | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 1 | 0 |

Forbidden tally per rung: `1-isp-rtr-eth1` 0, `1-uplink-rtr-eth1` 0, `2-fw-ethernet1-4` 0, `3-fw-ae1-leg1` 0, `3-fw-ae1-leg2` 0, `4-fe-sw1-Ethernet13` 0, `4-fe-sw1-Ethernet14` 0, `4-fe-sw2-Ethernet13` 0, `4-fe-sw2-Ethernet14` 0, `5-k8s-ingress1-bond0.110` 0, `5-k8s-ingress2-bond0.110` 0

Lease holders: gw-inet k8s-ingress1, gw-internal k8s-ingress1, gw-users k8s-ingress1; the pair's ports facing each, by its MAC: k8s-ingress1: 4-fe-sw1-Ethernet13, 4-fe-sw2-Ethernet13; k8s-ingress2: none

## Verdict

```
== the ladder trace
== the ladder's rungs and the lease holders
  PASS  gw-inet's lease held by k8s-ingress1; the pair's ports facing it by its MAC: 4-fe-sw1-Ethernet13, 4-fe-sw2-Ethernet13
  PASS  gw-internal's lease held by k8s-ingress1; the pair's ports facing it by its MAC: 4-fe-sw1-Ethernet13, 4-fe-sw2-Ethernet13
  PASS  gw-users's lease held by k8s-ingress1; the pair's ports facing it by its MAC: 4-fe-sw1-Ethernet13, 4-fe-sw2-Ethernet13
  PASS  enterprise/gw-internal: log-line at fw (TIMEOUT): 3 SYNs by distinct sequence number reached 2-fw-ethernet1-4 3, and none past it
  PASS  enterprise/gw-users: allowed (CONNECTED), its SYN at 2-fw-ethernet1-4, on one leg (3-fw-ae1-leg1), on the pair's port facing k8s-ingress1 (4-fe-sw1-Ethernet13) and on 5-k8s-ingress1-bond0.110
  PASS  enterprise/gw-inet: log-line at fw (TIMEOUT): 3 SYNs by distinct sequence number reached 2-fw-ethernet1-4 3, and none past it
  PASS  operator/gw-internal: allowed (CONNECTED), its SYN on one leg (3-fw-ae1-leg2), on the pair's port facing k8s-ingress1 (4-fe-sw2-Ethernet13) and on 5-k8s-ingress1-bond0.110
  PASS  operator/gw-users: log-line at fw (TIMEOUT): 3 SYNs by distinct sequence number reached no rung, and none past it
  PASS  operator/gw-inet: log-line at fw (TIMEOUT): 3 SYNs by distinct sequence number reached no rung, and none past it
  PASS  nodes/gw-internal: answered on k8s-cp2 itself (CONNECTED): no SYN at any rung
  PASS  nodes/gw-users: answered on k8s-cp2 itself (CONNECTED): no SYN at any rung
  PASS  nodes/gw-inet: answered on k8s-cp2 itself (CONNECTED): no SYN at any rung
  PASS  web/gw-internal: log-line at fw (TIMEOUT): 3 SYNs by distinct sequence number reached 1-uplink-rtr-eth1 3, and none past it
  PASS  web/gw-users: log-line at fw (TIMEOUT): 3 SYNs by distinct sequence number reached 1-uplink-rtr-eth1 3, and none past it
  PASS  web/gw-inet: log-line at fw (TIMEOUT): 3 SYNs by distinct sequence number reached 1-uplink-rtr-eth1 3, and none past it
  PASS  internet/gw-internal: silence at isp-rtr (ERROR:Network_unreachable, TIMEOUT): 3 SYNs by distinct sequence number reached no rung, and none past it
  PASS  internet/gw-users: silence at isp-rtr (TIMEOUT): 3 SYNs by distinct sequence number reached no rung, and none past it
  PASS  internet/gw-inet: allowed (CONNECTED), its SYN at 1-isp-rtr-eth1, on one leg (3-fw-ae1-leg1), on the pair's port facing k8s-ingress1 (4-fe-sw1-Ethernet13) and on 5-k8s-ingress1-bond0.110
== the forbidden tallies
  PASS  every rung's forbidden tally is zero (11 rungs, 9 forbidden flows)
```

## Files

- `captures/<rung>.pcap` and `.txt`: every rung, captured over the whole run
- `connects/<flow>.txt`: each flow's connects (syn_connect.py, one line a source port); `warmup/`: the warm-up connects
- `pair/<switch>-mac.txt`: the pair's MAC tables after the warm-up; `cluster/leases.json`: the Gateways' leases
