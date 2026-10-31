# Serving trace

- Lab: `sfab-ch07`; labs repo commit `ad2f14ffba532ff5d8be0be16301f9fbc625f55f` (with uncommitted changes); UTC 2026-10-30T13:20:40Z
- One chat completion from ent-client (10.24.10.10, source port 42706) to `https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions` through gw-users (10.20.11.210), with chat's key; 19 capture points
- Answer: HTTP 200; the router's deployment `openai/chat` on `http://chat.serving.svc.cluster.local:8080/v1`, retries 0

## The path

| Hop | Point | Node | Address | First data (decode line) |
|---|---|---|---|---|
| Gateway VIP | `1-k8s-ingress1-bond0` | k8s-ingress1 | 10.20.11.210:443 | `captures/1-k8s-ingress1-bond0.txt:2` |
| API gateway | `2-api-gateway-64bc7b94df-hm4sq-eth0` | k8s-ingress1 | 10.22.0.7:9080 | `captures/2-api-gateway-64bc7b94df-hm4sq-eth0.txt:80` |
| router | `3-router-76cf778fb6-4mbxs-eth0` | k8s-ingress1 | 10.22.0.229:4000 | `captures/3-router-76cf778fb6-4mbxs-eth0.txt:156` |
| server | `4-chat-a-server-0-eth0` | k8s-gpu1 | 10.22.3.113:8080 | `captures/4-chat-a-server-0-eth0.txt:8` |
| worker (same node) | `5-chat-a-worker0-0-rail3` | k8s-gpu1 | 10.21.3.101:50052 | `captures/5-chat-a-worker0-0-rail3.txt:2` |

The copy that served it: chat-a, rail 3 (rail3) on rail-sw1: server chat-a-server-0 on k8s-gpu1 at 10.21.3.100, workers chat-a-worker0-0 on k8s-gpu1 at 10.21.3.101.

## The keys at the in-cluster hops

Each value in the captures is its keyed mark (`captures/scrub.log` counts the values replaced); the key files under `request/` name each key by its field, fingerprint and mark.

| Hop | Point | Request | Authorization | Key | Decode line |
|---|---|---|---|---|---|
| 1: Gateway to API gateway | `2-api-gateway-64bc7b94df-hm4sq-eth0` | POST `/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions` | `<redacted hmac:efe716422df6>` | the caller's key | `captures/2-api-gateway-64bc7b94df-hm4sq-eth0-payload.txt:245` |
| 2: API gateway to router | `2-api-gateway-64bc7b94df-hm4sq-eth0` | POST `/engines/chat/chat/completions` | `<redacted hmac:b1c432715e9b>` | the router's master key | `captures/2-api-gateway-64bc7b94df-hm4sq-eth0-payload.txt:298` |
| 3: router to server | `3-router-76cf778fb6-4mbxs-eth0` | POST `/v1/chat/completions` | `<redacted hmac:ca169146b0f4>` | the backend key | `captures/3-router-76cf778fb6-4mbxs-eth0-payload.txt:644` |

## The refusal

`https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused` from ent-client (source port 42707) to gw-users: HTTP 404, server envoy; no API gateway pod saw it.

## Verdict

```
== the serving trace: chat through gw-users
  PASS  the key for chat handed to ent-client as a 0600 header file, read from its Secret in the cluster (batch.3915b3b1 sha256:afa4a482f152 <redacted hmac:efe716422df6>)
== the request: ent-client to chat through gw-users
  PASS  HTTP 200 for POST https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions with chat's key
  PASS  answered by the router's openai/chat deployment, on the model's Service http://chat.serving.svc.cluster.local:8080/v1, with no retry
== the users' VIP
  PASS  k8s-ingress1, which holds gw-users's lease: the client's SYN from 10.24.10.10 port 42706 to 10.20.11.210:443 on bond0, and data both ways (4 segments in, 4 out)
== the API gateway and the router
  PASS  one API gateway pod took it: api-gateway-64bc7b94df-hm4sq on k8s-ingress1 (10.22.0.7:9080), data from the Gateway's proxy at 10.22.0.189, sent on to the router pod router-76cf778fb6-4mbxs (10.22.0.229:4000); api-gateway-64bc7b94df-7b74q took none
  PASS  the router pod router-76cf778fb6-4mbxs on k8s-ingress1 received it from api-gateway-64bc7b94df-hm4sq and sent it to chat-a-server-0 (10.22.3.113:8080), chat's copy a on rail 3
== the server and its workers on the rail
  PASS  chat-a-server-0 on k8s-gpu1 received it on eth0 from router-76cf778fb6-4mbxs and answered (1 data segments in, 1 out)
  PASS  chat-a-server-0's RPC on rail3 (10.21.3.100) to chat-a-worker0-0 at 10.21.3.101:50052, the table's rail 3: 504 data segments out, 179 back
  PASS  chat-a-worker0-0 on k8s-gpu1 saw it on its own rail3 (504 data segments from 10.21.3.100)
== rail-sw1: the rail switch of rail 3
  PASS  ... and no frame of the RPC to chat-a-worker0-0 (10.21.3.101), beside its server on k8s-gpu1: macvlan's bridge mode keeps it inside the node
== chat's other copies
  PASS  copy b on rail 6 carried none of it: no data to chat-b-server-0, no RPC on rail6 at its server, its workers or rail-sw2's ports
  PASS  copy c on rail 7 carried none of it: no data to chat-c-server-0, no RPC on rail7 at its server, its workers or rail-sw1's ports
== the keys at the in-cluster hops (the captures' Authorization values replaced by their marks)
  PASS  hop 1, the Gateway's proxy to api-gateway-64bc7b94df-hm4sq: POST /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions with Authorization <redacted hmac:efe716422df6>, the caller's chat key (batch.3915b3b1 sha256:afa4a482f152)
  PASS  hop 2, api-gateway-64bc7b94df-hm4sq to the router pod router-76cf778fb6-4mbxs: POST /engines/chat/chat/completions with Authorization <redacted hmac:b1c432715e9b>, the router's master key (sha256:69f1782fcc04), set in place of the caller's
  PASS  ... and the caller's key nowhere on hop 2 (0 requests to the router carry its mark)
  PASS  ... which router-76cf778fb6-4mbxs received with the same mark
  PASS  hop 3, router-76cf778fb6-4mbxs to the server at 10.22.3.113: Authorization <redacted hmac:ca169146b0f4>, the backend key (sha256:d255557d22d3), neither the caller's nor the master key
  PASS  every Authorization value in the keyed captures is a mark, none a value (4 requests with one, 4 keyed points)
== the refusal: admin.ai.tarnwick.example sent to gw-users, which does not carry it
  PASS  GET https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused from ent-client: HTTP 404 from the Gateway (server envoy)
  PASS  k8s-ingress1: the client's SYN from port 42707 to 10.20.11.210:443
  PASS  no API gateway pod saw it: no request for admin.ai.tarnwick.example at 2 API gateway pods, which received 1 request(s) in all, the keyed one
```

## Frames per point

| Point | Kind | Node | Interface | Filter | Frames | Data segments |
|---|---|---|---|---|---|---|
| `1-k8s-ingress1-bond0` | guest | k8s-ingress1 | bond0 | `tcp port 443 and host 10.20.11.210` | 36 | 15 |
| `2-api-gateway-64bc7b94df-7b74q-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 9080 or tcp port 4000` | 57 | 0 |
| `2-api-gateway-64bc7b94df-hm4sq-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 9080 or tcp port 4000` | 72 | 4 |
| `3-router-76cf778fb6-4mbxs-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 4000 or tcp port 8080` | 127 | 24 |
| `3-router-76cf778fb6-bh7gc-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 4000 or tcp port 8080` | 105 | 20 |
| `4-chat-a-server-0-eth0` | pod | k8s-gpu1 | eth0 | `tcp port 8080` | 10 | 2 |
| `4-chat-a-server-0-rail3` | pod | k8s-gpu1 | rail3 | `tcp port 50052` | 1108 | 683 |
| `5-chat-a-worker0-0-rail3` | pod | k8s-gpu1 | rail3 | `tcp port 50052` | 1108 | 683 |
| `6-rail-sw1-Ethernet1` | host | rail-sw1 | eth2 | `tcp port 50052` | 0 | 0 |
| `4-chat-b-server-0-eth0` | pod | k8s-gpu2 | eth0 | `tcp port 8080` | 0 | 0 |
| `4-chat-b-server-0-rail6` | pod | k8s-gpu2 | rail6 | `tcp port 50052` | 0 | 0 |
| `5-chat-b-worker0-0-rail6` | pod | k8s-gpu2 | rail6 | `tcp port 50052` | 0 | 0 |
| `6-rail-sw2-Ethernet6` | host | rail-sw2 | eth7 | `tcp port 50052` | 0 | 0 |
| `4-chat-c-server-0-eth0` | pod | k8s-gpu1 | eth0 | `tcp port 8080` | 0 | 0 |
| `4-chat-c-server-0-rail7` | pod | k8s-gpu1 | rail7 | `tcp port 50052` | 0 | 0 |
| `5-chat-c-worker0-0-rail7` | pod | k8s-gpu2 | rail7 | `tcp port 50052` | 0 | 0 |
| `5-chat-c-worker1-0-rail7` | pod | k8s-gpu1 | rail7 | `tcp port 50052` | 0 | 0 |
| `6-rail-sw1-Ethernet3` | host | rail-sw1 | eth4 | `tcp port 50052` | 0 | 0 |
| `6-rail-sw1-Ethernet7` | host | rail-sw1 | eth8 | `tcp port 50052` | 0 | 0 |

## Files

- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`
- `cluster/`: the pods of both namespaces, the users' VIP's lease and the serving EndpointSlices, read before the captures
- `request/`: the warm-up's and the request's status (`result.txt`), response headers and body; no request header is saved
- `captures/<point>.pcap` and `.txt`, decoded with `tcpdump -nn -tt -e -v -r` (a guest's and a pod's in the guest); a pod's cluster interface captured at 66 bytes a frame, so no capture holds an HTTP header; the API gateway's and the router's captured whole, each pcap scrubbed of its keys on its way out of the guest and decoded on the lab host, with `-A` as `<point>-payload.txt`

== RESULT: 21 passed, 0 failed, 0 known platform limitation(s), 0 skipped
