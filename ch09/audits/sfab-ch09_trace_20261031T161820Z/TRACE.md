# Split-horizon trace

- Lab: `sfab-ch09`; labs repo commit `35fdcf25cf7ecee2b977f4eba01022a49d5a4c2b`; UTC 2026-10-31T16:18:20Z
- Each population looks up `llm.ai.tarnwick.example` through its own resolver, then connects toward the answer; 9 capture points

| Population | Client | Resolver | View | Answer | Resolver asked its authority | The connect | Where the SYN went |
|---|---|---|---|---|---|---|---|
| enterprise | ent-client | ent-dns | enterprise | 10.20.11.210 | no, from its cache | CONNECTED | staff-to-users-gateway (allowed), enterprise to ingress |
| nodes | k8s-cp2 | dns-res1 | internal | 10.20.11.200 | no, from its cache | CONNECTED | answered on the node |
| internet | inet-client | inet-dns-res | public-internet | 198.51.100.10 | no, from its cache | TIMEOUT | deny-all-log (refused), isp to isp |

## Verdict

```
== the dns trace
== enterprise: ent-client (10.24.10.10) looks up llm.ai.tarnwick.example through ent-dns (10.24.10.53), view enterprise
  PASS  ent-dns received ent-client's query for llm.ai.tarnwick.example A (1) and answered 10.20.11.210, the view's 10.20.11.210 (`captures/0-ent-dns-eth1.txt:2`)
  PASS  ... from its cache: no query of its to 10.20.13.11, 10.20.14.11 in the window (the name's answer still held)
  PASS  ent-client's own lookup printed 10.20.11.210
  PASS  ent-client's connect to 10.20.11.210:443 from port 42906: CONNECTED
  PASS  ... its SYN at 2-fw-ethernet1-4 (`captures/2-fw-ethernet1-4.txt:2`)
  PASS  ... on exactly one leg of the bundle (3-fw-ae1-leg1), its destination 10.20.11.210
  PASS  ... the traffic log: staff-to-users-gateway (allow), zone enterprise to ingress (`fw/traffic-log-443.txt:6`)
== nodes: k8s-cp2 (10.20.1.12) looks up llm.ai.tarnwick.example through dns-res1 (10.20.13.21), view internal
  PASS  dns-res1 received k8s-cp2's query for llm.ai.tarnwick.example A (1) and answered 10.20.11.200, the view's 10.20.11.200 (`captures/0-dns-res1-bond0.txt:2`)
  PASS  ... from its cache: no query of its to 10.20.13.11, 10.20.14.11 in the window (the name's answer still held)
  PASS  k8s-cp2's own lookup printed 10.20.11.200
  PASS  k8s-cp2's connect to 10.20.11.200:443 from port 42907: CONNECTED (answered on the node)
  PASS  ... no SYN to it left the node: none at 0-k8s-cp2-eth1, 0-k8s-cp2-eth2
== internet: inet-client (203.0.113.2) looks up llm.ai.tarnwick.example through inet-dns-res (203.0.113.10), view public-internet
  PASS  inet-dns-res received inet-client's query for llm.ai.tarnwick.example A (1) and answered 198.51.100.10, the view's 198.51.100.10 (`captures/0-inet-dns-res-eth1.txt:2`)
  PASS  ... from its cache: no query of its to 203.0.113.6 in the window (the name's answer still held)
  PASS  inet-client's own lookup printed 198.51.100.10
  PASS  inet-client's connect to 198.51.100.10:443 from port 42908: TIMEOUT
  PASS  ... its SYN at 1-isp-rtr-eth1 (`captures/1-isp-rtr-eth1.txt:2`)
  PASS  ... nothing of it past the device that refuses it: none at 3-fw-ae1-leg1, 3-fw-ae1-leg2
  PASS  ... the traffic log: deny-all-log (deny), zone isp to isp (`fw/traffic-log-443.txt:14`)
```

## Files

- `captures/<point>.pcap` and `.txt`: each resolver's port (port 53) and each rung the connects cross (tcp 443)
- `lookups/<population>.txt`: the client's own lookup; `connects/<population>.txt`: its connect (syn_connect.py)
- `warmup/<population>.txt`: the warm-up connect before the captures, for each population whose connect is answered, so the pair's MAC tables hold the lease holders' MACs (not captured)
- `fw/traffic-log-443.txt`: the firewall's traffic log after the connects
