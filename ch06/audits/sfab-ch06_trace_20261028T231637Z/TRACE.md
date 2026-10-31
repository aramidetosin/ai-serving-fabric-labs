# Serving trace

- Lab: `sfab-ch06`; labs repo commit `39786511f9876ee9998dd48ca53d91efaf83680d` (with uncommitted changes); UTC 2026-10-28T23:16:37Z
- One chat completion from ent-client (10.24.10.10, source port 42610) to `https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions` through gw-users (10.20.11.210), with chat's key; 19 capture points
- Answer: HTTP 200; the router's deployment `openai/chat` on `http://chat.serving.svc.cluster.local:8080/v1`, retries 0

## The path

| Hop | Point | Node | Address | First data (decode line) |
|---|---|---|---|---|
| Gateway VIP | `1-k8s-ingress2-bond0` | k8s-ingress2 | 10.20.11.210:443 | `captures/1-k8s-ingress2-bond0.txt:2` |
| API gateway | `2-api-gateway-64bc7b94df-4nzm6-eth0` | k8s-ingress2 | 10.22.3.13:9080 | `captures/2-api-gateway-64bc7b94df-4nzm6-eth0.txt:92` |
| router | `3-router-76cf778fb6-gwr7f-eth0` | k8s-ingress1 | 10.22.4.84:4000 | `captures/3-router-76cf778fb6-gwr7f-eth0.txt:150` |
| server | `4-chat-c-server-0-eth0` | k8s-gpu1 | 10.22.1.35:8080 | `captures/4-chat-c-server-0-eth0.txt:8` |
| worker (other node) | `5-chat-c-worker0-0-rail7` | k8s-gpu2 | 10.21.7.101:50052 | `captures/5-chat-c-worker0-0-rail7.txt:2` |
| worker (same node) | `5-chat-c-worker1-0-rail7` | k8s-gpu1 | 10.21.7.102:50052 | `captures/5-chat-c-worker1-0-rail7.txt:2` |
| rail-sw1 Ethernet3 | `6-rail-sw1-Ethernet3` | rail-sw1 | faces k8s-gpu1 | `captures/6-rail-sw1-Ethernet3.txt:2` |
| rail-sw1 Ethernet7 | `6-rail-sw1-Ethernet7` | rail-sw1 | faces k8s-gpu2 | `captures/6-rail-sw1-Ethernet7.txt:2` |

The copy that served it: chat-c, rail 7 (rail7) on rail-sw1: server chat-c-server-0 on k8s-gpu1 at 10.21.7.100, workers chat-c-worker0-0 on k8s-gpu2 at 10.21.7.101, chat-c-worker1-0 on k8s-gpu1 at 10.21.7.102.

## Verdict

```
== the serving trace: chat through gw-users
  PASS  the key for chat handed to ent-client as a 0600 header file, read from its Secret in the cluster (batch.9db711c1 sha256:35a1d5102891)
== the request: ent-client to chat through gw-users
  PASS  HTTP 200 for POST https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions with chat's key
  PASS  answered by the router's openai/chat deployment, on the model's Service http://chat.serving.svc.cluster.local:8080/v1, with no retry
== the users' VIP
  PASS  k8s-ingress2, which holds gw-users's lease: the client's SYN from 10.24.10.10 port 42610 to 10.20.11.210:443 on bond0, and data both ways (4 segments in, 4 out)
== the API gateway and the router
  PASS  one API gateway pod took it: api-gateway-64bc7b94df-4nzm6 on k8s-ingress2 (10.22.3.13:9080), data from the Gateway's proxy at 10.22.3.34, sent on to the router pod router-76cf778fb6-gwr7f (10.22.4.84:4000); api-gateway-64bc7b94df-z4csg took none
  PASS  the router pod router-76cf778fb6-gwr7f on k8s-ingress1 received it from api-gateway-64bc7b94df-4nzm6 and sent it to chat-c-server-0 (10.22.1.35:8080), chat's copy c on rail 7
== the server and its workers on the rail
  PASS  the request landed on copy c, the one the plan pins (try 5 of at most 12; the captures of each miss discarded)
  PASS  chat-c-server-0 on k8s-gpu1 received it on eth0 from router-76cf778fb6-gwr7f and answered (1 data segments in, 1 out)
  PASS  chat-c-server-0's RPC on rail7 (10.21.7.100) to chat-c-worker0-0 at 10.21.7.101:50052, the table's rail 7: 333 data segments out, 96 back
  PASS  chat-c-worker0-0 on k8s-gpu2 saw it on its own rail7 (365 data segments from 10.21.7.100)
  PASS  chat-c-server-0's RPC on rail7 (10.21.7.100) to chat-c-worker1-0 at 10.21.7.102:50052, the table's rail 7: 538 data segments out, 177 back
  PASS  chat-c-worker1-0 on k8s-gpu1 saw it on its own rail7 (538 data segments from 10.21.7.100)
== rail-sw1: the rail switch of rail 7
  PASS  rail-sw1 Ethernet3 (facing k8s-gpu1) carried the RPC between 10.21.7.100 and 10.21.7.101, the worker on the other node (540 data segments)
  PASS  ... and no frame of the RPC to chat-c-worker1-0 (10.21.7.102), beside its server on k8s-gpu1: macvlan's bridge mode keeps it inside the node
  PASS  rail-sw1 Ethernet7 (facing k8s-gpu2) carried the RPC between 10.21.7.100 and 10.21.7.101, the worker on the other node (540 data segments)
  PASS  ... and no frame of the RPC to chat-c-worker1-0 (10.21.7.102), beside its server on k8s-gpu1: macvlan's bridge mode keeps it inside the node
== chat's other copies
  PASS  copy a on rail 3 carried none of it: no data to chat-a-server-0, no RPC on rail3 at its server, its workers or rail-sw1's ports
  PASS  copy b on rail 6 carried none of it: no data to chat-b-server-0, no RPC on rail6 at its server, its workers or rail-sw2's ports
```

## Frames per point

| Point | Kind | Node | Interface | Filter | Frames | Data segments |
|---|---|---|---|---|---|---|
| `1-k8s-ingress2-bond0` | guest | k8s-ingress2 | bond0 | `tcp port 443 and host 10.20.11.210` | 17 | 8 |
| `2-api-gateway-64bc7b94df-4nzm6-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 9080 or tcp port 4000` | 71 | 4 |
| `2-api-gateway-64bc7b94df-z4csg-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 9080 or tcp port 4000` | 60 | 0 |
| `3-router-76cf778fb6-gwr7f-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 4000 or tcp port 8080` | 123 | 24 |
| `3-router-76cf778fb6-n6nk4-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 4000 or tcp port 8080` | 115 | 22 |
| `4-chat-a-server-0-eth0` | pod | k8s-gpu1 | eth0 | `tcp port 8080` | 0 | 0 |
| `4-chat-a-server-0-rail3` | pod | k8s-gpu1 | rail3 | `tcp port 50052` | 0 | 0 |
| `5-chat-a-worker0-0-rail3` | pod | k8s-gpu1 | rail3 | `tcp port 50052` | 0 | 0 |
| `6-rail-sw1-Ethernet1` | host | rail-sw1 | eth2 | `tcp port 50052` | 0 | 0 |
| `4-chat-b-server-0-eth0` | pod | k8s-gpu2 | eth0 | `tcp port 8080` | 0 | 0 |
| `4-chat-b-server-0-rail6` | pod | k8s-gpu2 | rail6 | `tcp port 50052` | 0 | 0 |
| `5-chat-b-worker0-0-rail6` | pod | k8s-gpu2 | rail6 | `tcp port 50052` | 0 | 0 |
| `6-rail-sw2-Ethernet6` | host | rail-sw2 | eth7 | `tcp port 50052` | 0 | 0 |
| `4-chat-c-server-0-eth0` | pod | k8s-gpu1 | eth0 | `tcp port 8080` | 10 | 2 |
| `4-chat-c-server-0-rail7` | pod | k8s-gpu1 | rail7 | `tcp port 50052` | 1763 | 1144 |
| `5-chat-c-worker0-0-rail7` | pod | k8s-gpu2 | rail7 | `tcp port 50052` | 647 | 453 |
| `5-chat-c-worker1-0-rail7` | pod | k8s-gpu1 | rail7 | `tcp port 50052` | 1140 | 715 |
| `6-rail-sw1-Ethernet3` | host | rail-sw1 | eth4 | `tcp port 50052` | 734 | 540 |
| `6-rail-sw1-Ethernet7` | host | rail-sw1 | eth8 | `tcp port 50052` | 734 | 540 |

## Files

- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`
- `cluster/`: the pods of both namespaces, the users' VIP's lease and the serving EndpointSlices, read before the captures
- `request/`: the warm-up's and the request's status (`result.txt`), response headers and body; no request header is saved
- `captures/<point>.pcap` and `.txt`, decoded with `tcpdump -nn -tt -e -v -r` (a guest's and a pod's in the guest); a pod's cluster interface captured at 66 bytes a frame, so no capture holds an HTTP header

== RESULT: 18 passed, 0 failed, 0 known platform limitation(s), 0 skipped
