# Request walk

- Lab: `sfab-ch01`; labs repo commit `ad2f14ffba532ff5d8be0be16301f9fbc625f55f` (with uncommitted changes); UTC 2026-10-29T15:57:02Z
- One chat completion from ent-client (10.24.10.10, source port 42106) to `https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions` through gw-users (10.20.11.210), with chat's key, held 30 s after its answer; 27 capture points
- Answer: HTTP 200; the router's deployment `openai/chat` on `http://chat.serving.svc.cluster.local:8080/v1`, retries 0

## Hops, devices, tables and decisions

| Hop | Device | Table it consults | Decision | Evidence |
|---|---|---|---|---|
| 1 | ent-client | its resolver (resolv.conf) | asks 10.24.10.53 (ent-dns) for llm.ai.tarnwick.example | `dns/client-dig.txt:18` |
| 2 | ent-dns, the resolver, and dns-auth1 | view enterprise (the resolver's source address) | A 10.20.11.210, gw-users's VIP | `dns/client-dig.txt:15` |
| 3 | fw, in on ethernet1/4 (zone enterprise) | routing table, virtual router core | 10.20.11.0/24 connected on ae1.110: zone ingress | `fw/routing-route.txt:19` |
| 4 | fw | NAT rulebase | no rule from zone enterprise: no translation | `fw/running-nat-policy.txt` |
| 5 | fw | security rulebase | staff-to-users-gateway: allow TCP 443 to 10.20.11.210 | `sessions/walk/session-detail.txt:31`, `sessions/walk/traffic-log.txt:6` |
| 6 | fw, out on ae1.110 over ethernet1/2 | ae1's LACP hash | leg 2, tagged 110, TTL 63 | `captures/3-fw-ae1-leg2.txt:2` |
| 7 | fe-sw2, a pair member | MAC table, VLAN 110 | k8s-ingress2's bond MAC on PortChannel15: bridged out Ethernet14 tagged 110, no address, no route | `pair/fe-sw2-mac-table.txt:21`, `captures/5-fe-sw2-Ethernet14.txt:2` |
| 8 | k8s-ingress2, the lease holder | the lease kube-system/cilium-l2announce-gateways-cilium-gateway-gw-users | answers for 10.20.11.210 on its unit in the Gateway VLAN | `cluster/lease.txt:2`, `captures/6-k8s-ingress2-bond0.txt:2` |
| 9 | gw-users, the Gateway | HTTPRoute inference/models-gw-users, rule 0 | llm.ai.tarnwick.example and /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7: to Service api-gateway:9080 | `cluster/httproutes.json` |
| 10 | api-gateway-64bc7b94df-qh7lp, the API gateway | its route for chat: key authentication, consumer group batch | the caller's key accepted (<redacted hmac:cb748915a02c>); the router's master key set in its place | `cluster/api-gateway-routes.yaml:2`, `captures/7-api-gateway-64bc7b94df-qh7lp-eth0-payload.txt:288`, `captures/7-api-gateway-64bc7b94df-qh7lp-eth0-payload.txt:340` |
| 11 | router-76cf778fb6-z8fq6, the router | its model list | chat on the Service chat | `cluster/router-config.yaml:2`, `request/headers.txt:11` |
| 12 | the Service chat | its EndpointSlices (the ready servers) | chat-a-server-0, chat's copy a | `cluster/endpointslices-serving.json` |
| 13 | chat-a-server-0 on k8s-gpu1 | the placement table: chat-a on rail 3 | RPC to its workers over rail3, fixed before the request | `captures/9-chat-a-server-0-eth0.txt:8` |
| 14 | rail-sw1, a rail switch | its port Ethernet1, facing k8s-gpu1 | no RPC frame: copy a's RPC stays in the node's rail 3 macvlan bridge | `rail/rail-sw1-counters-after.txt` |

## Three refused requests

| Request | Where it died | What the client got | Evidence | Nothing past it |
|---|---|---|---|---|
| `https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused`, no key, port 42107 | the Gateway, gw-users | HTTP 404, server envoy | `request/refuse-headers.txt`, `fw/traffic-log-443.txt:10` | no API gateway pod received it |
| chat's route with staff's key, port 42108 | the API gateway, api-gateway-64bc7b94df-qh7lp | HTTP 401, `Authorization Failed` | `request/refuse-key-body.txt`, `captures/7-api-gateway-64bc7b94df-qh7lp-eth0-payload.txt:949` | the router pods received 1 request in all, the walked one |
| k8s-gpu1 (10.20.1.21) TCP 22, port 42109 | the firewall, deny-all-log | TIMEOUT after 5.001 s | `captures/2-fw-ethernet1-4.txt:116`, `fw/traffic-log-22.txt:6` | no SYN on either bundle leg |

## Verdict

```
== the walk: chat through gw-users, from ent-client
  PASS  the key for chat handed to ent-client as a 0600 header file, read from its Secret in the cluster (batch.4aed4502 sha256:a241a551b901 <redacted hmac:cb748915a02c>)
  PASS  the key for staff handed to ent-client the same way, for the refused request (helpdesk.ef6fb230 sha256:04c11d956cd4 <redacted hmac:2e8388b7e57c>)
== the names: ent-client asks for llm.ai.tarnwick.example
  PASS  ent-client's resolver 10.24.10.53 (ent-dns, the enterprise view) answers llm.ai.tarnwick.example with 10.20.11.210, gw-users's VIP
  PASS  ... while dns-res1, another resolver of the lab asking itself from 10.20.13.21, gets 10.20.11.200 (the internal view): the view, not the name, picks the Gateway
== the firewall's tables: ethernet1/4 (zone enterprise) toward 10.20.11.210
  PASS  show routing route: 10.20.11.210 falls in 10.20.11.0/24, connected (flag C) on ae1.110, zone ingress
  PASS  show running nat-policy: 2 NAT rules, none from zone enterprise: no translation
  PASS  show running security-policy: staff-to-users-gateway, the first rule from enterprise to ingress, allows TCP 443 to 10.20.11.210 alone
== session walk: ent-client (10.24.10.10) to https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions at 10.20.11.210:443
  PASS  the reply: HTTP 200
  PASS  the connection held 30 s after the reply, so the session table still lists it
  PASS  show session all lists it: 10.24.10.10[42106] to 10.20.11.210[443] (id 2421)
  PASS  ... zone enterprise to zone ingress, state ACTIVE
  PASS  ... destination after translation 10.20.11.210 (none), source unchanged 10.24.10.10
  PASS  show session id names the security rule staff-to-users-gateway
  PASS  ... and no NAT rule
  PASS  the traffic log line: staff-to-users-gateway (shown as staff-to-users-gate), allow, zone enterprise to zone ingress, the pre-NAT destination 10.20.11.210
== the wire: the walked SYN from 10.24.10.10 port 42106 to 10.20.11.210:443
  PASS  1-ent-client-eth1, ent-client's own port: the SYN leaves untagged, TTL 64, seq 3078799640
  PASS  2-fw-ethernet1-4, the firewall's ethernet1/4: the same frame (MACs, TTL 64, IP id 598)
  PASS  the same SYN (seq 3078799640) on exactly one leg of ae1: 3-fw-ae1-leg2 (ethernet1/2), captured on both
  PASS  ... tagged 110, its addresses and ports kept (10.24.10.10.42106 > 10.20.11.210.443), TTL 63: one lower, the firewall's routed hop
  PASS  4-fe-sw2-Ethernet2: the same frame, tagged 110, as the leg put it on the wire; the other pair member's port saw none
  PASS  one pair port facing k8s-ingress2's bond carried it, on fe-sw2, the switch the leg lands on: 5-fe-sw2-Ethernet14, tagged 110, the same frame
  PASS  6-k8s-ingress2-bond0: the same frame, tagged 110, to k8s-ingress2's bond MAC 02:5a:69:00:00:01, with the MACs, TTL 63 and IP id the leg carried: no routed hop between the firewall and the Gateway
== the pair: the MAC table each member bridges by, VLAN 110
  PASS  fe-sw1: k8s-ingress2's bond MAC 02:5a:69:00:00:01 in VLAN 110 on PortChannel15
  PASS  fe-sw2: k8s-ingress2's bond MAC 02:5a:69:00:00:01 in VLAN 110 on PortChannel15
== the request: ent-client to chat through gw-users
  PASS  HTTP 200 for POST https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions with chat's key
  PASS  answered by the router's openai/chat deployment, on the model's Service http://chat.serving.svc.cluster.local:8080/v1, with no retry
== the users' VIP
  PASS  k8s-ingress2, which holds gw-users's lease: the client's SYN from 10.24.10.10 port 42106 to 10.20.11.210:443 on bond0, and data both ways (3 segments in, 4 out)
== the API gateway and the router
  PASS  one API gateway pod took it: api-gateway-64bc7b94df-qh7lp on k8s-ingress1 (10.22.3.4:9080), data from the Gateway's proxy at 10.22.4.105, sent on to the router pod router-76cf778fb6-z8fq6 (10.22.4.62:4000); api-gateway-64bc7b94df-pwh6z took none
  PASS  the router pod router-76cf778fb6-z8fq6 on k8s-ingress2 received it from api-gateway-64bc7b94df-qh7lp and sent it to chat-a-server-0 (10.22.1.40:8080), chat's copy a on rail 3
== the server and its workers on the rail
  PASS  chat-a-server-0 on k8s-gpu1 received it on eth0 from router-76cf778fb6-z8fq6 and answered (1 data segments in, 1 out)
  PASS  chat-a-server-0's RPC on rail3 (10.21.3.100) to chat-a-worker0-0 at 10.21.3.101:50052, the table's rail 3: 473 data segments out, 162 back
  PASS  chat-a-worker0-0 on k8s-gpu1 saw it on its own rail3 (473 data segments from 10.21.3.100)
== rail-sw1: the rail switch of rail 3
  PASS  ... and no frame of the RPC to chat-a-worker0-0 (10.21.3.101), beside its server on k8s-gpu1: macvlan's bridge mode keeps it inside the node
== chat's other copies
  PASS  copy b on rail 6 carried none of it: no data to chat-b-server-0, no RPC on rail6 at its server, its workers or rail-sw2's ports (set aside: a router's GET /v1/models from 10.22.4.62:50360)
  PASS  copy c on rail 7 carried none of it: no data to chat-c-server-0, no RPC on rail7 at its server, its workers or rail-sw1's ports (set aside: a router's GET /v1/models from 10.22.3.244:53826)
== the keys at the in-cluster hops (the captures' Authorization values replaced by their marks)
  PASS  hop 1, the Gateway's proxy to api-gateway-64bc7b94df-qh7lp: POST /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions with Authorization <redacted hmac:cb748915a02c>, the caller's chat key (batch.4aed4502 sha256:a241a551b901)
  PASS  hop 2, api-gateway-64bc7b94df-qh7lp to the router pod router-76cf778fb6-z8fq6: POST /engines/chat/chat/completions with Authorization <redacted hmac:0d5729fc6b1f>, the router's master key (sha256:f5dac9622949), set in place of the caller's
  PASS  ... and the caller's key nowhere on hop 2 (0 requests to the router carry its mark)
  PASS  ... which router-76cf778fb6-z8fq6 received with the same mark
  PASS  hop 3, router-76cf778fb6-z8fq6 to the server at 10.22.1.40: Authorization <redacted hmac:6b5d4eb63a7f>, the backend key (sha256:53bc0eb8740d), neither the caller's nor the master key
  PASS  every Authorization value in the keyed captures is a mark, none a value (9 requests with one, 4 keyed points)
== the tables the cluster's hops consult
  PASS  kube-system/cilium-l2announce-gateways-cilium-gateway-gw-users: held by k8s-ingress2, an ingress node, which answers for 10.20.11.210
  PASS  the HTTPRoute gw-users matched: inference/models-gw-users, rule 0, llm.ai.tarnwick.example with path prefix /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7, to Service api-gateway:9080, Accepted
  PASS  the API gateway's route for chat: /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions by key authentication, the consumer groups batch, staff, the walked key's caller batch among them
  PASS  the router's model list: chat on http://chat.serving.svc.cluster.local:8080/v1, the model's Service
  PASS  the Service chat: the server that answered (10.22.1.40) among its ready endpoints (10.22.1.39, 10.22.1.40, 10.22.2.146): the router names only the Service, and the Service's load balancing picked the copy
== the rail switch: its counters and its MAC table
  PASS  copy a sits inside k8s-gpu1: its RPC to chat-a-worker0-0 stays in the node's rail 3 macvlan bridge, and rail-sw1 Ethernet1 (facing k8s-gpu1) carried none of it
== refused at the Gateway: admin.ai.tarnwick.example sent to gw-users, which carries no route for it
  PASS  GET https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused from port 42107: HTTP 404 from the Gateway (server envoy), no key sent
  PASS  ... it crossed the firewall (the traffic log: staff-to-users-gate, allow) and reached the Gateway's VIP on k8s-ingress2 (its SYN on bond0)
  PASS  nothing past the Gateway: no request for admin.ai.tarnwick.example at any of 2 API gateway pods
== refused at the API gateway: chat's route with staff's key
  PASS  POST https://llm.ai.tarnwick.example/models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions from port 42108 with staff's key: HTTP 401 with the unknown key's message (Authorization Failed)
  PASS  ... read by api-gateway: a POST on /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions with Authorization <redacted hmac:2e8388b7e57c>, staff's key (helpdesk.ef6fb230 sha256:04c11d956cd4), at 7-api-gateway-64bc7b94df-qh7lp-eth0
  PASS  nothing past the API gateway: the router pods received 1 request(s) from the API gateway in all, the walked one
== refused at the firewall: k8s-gpu1's port 22 from ent-client
  PASS  the client's view: TIMEOUT after 5.001 s, from port 42109 to 10.20.1.21:22 (recorded, not assumed)
  PASS  its SYN on 1-ent-client-eth1 and on the firewall's ethernet1/4 (5 and 5, its retransmissions with it)
  PASS  nothing past the firewall: no SYN on either leg (3-fw-ae1-leg1, 3-fw-ae1-leg2), at the pair or at the lease holder
  PASS  the traffic log names deny-all-log (shown as deny-all-log), deny, zone enterprise to zone k8s-nodes
```

## Frames per point

| Point | Kind | Node | Interface | Filter | Frames | Data segments |
|---|---|---|---|---|---|---|
| `1-ent-client-eth1` | host | ent-client | eth1 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 62 | 21 |
| `2-fw-ethernet1-4` | host | fw | eth4 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 62 | 21 |
| `3-fw-ae1-leg1` | host | fw | eth1 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 39 | 15 |
| `3-fw-ae1-leg2` | host | fw | eth2 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 18 | 6 |
| `4-fe-sw1-Ethernet2` | host | fe-sw1 | eth3 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 39 | 15 |
| `4-fe-sw2-Ethernet2` | host | fe-sw2 | eth3 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 18 | 6 |
| `5-fe-sw1-Ethernet14` | host | fe-sw1 | eth15 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 39 | 15 |
| `5-fe-sw2-Ethernet14` | host | fe-sw2 | eth15 | `(host 10.24.10.10 and (tcp port 443 or tcp port 22)) or (vlan and (host 10.24.10.10 and (tcp port 443 or tcp port 22)))` | 18 | 6 |
| `6-k8s-ingress2-bond0` | guest | k8s-ingress2 | bond0 | `tcp port 443 and host 10.20.11.210` | 57 | 21 |
| `7-api-gateway-64bc7b94df-pwh6z-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 9080 or tcp port 4000` | 133 | 0 |
| `7-api-gateway-64bc7b94df-qh7lp-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 9080 or tcp port 4000` | 158 | 7 |
| `8-router-76cf778fb6-twzqd-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 4000 or tcp port 8080` | 243 | 46 |
| `8-router-76cf778fb6-z8fq6-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 4000 or tcp port 8080` | 266 | 50 |
| `9-chat-a-server-0-eth0` | pod | k8s-gpu1 | eth0 | `tcp port 8080` | 10 | 2 |
| `9-chat-a-server-0-rail3` | pod | k8s-gpu1 | rail3 | `tcp port 50052` | 1064 | 635 |
| `10-chat-a-worker0-0-rail3` | pod | k8s-gpu1 | rail3 | `tcp port 50052` | 1064 | 635 |
| `11-rail-sw1-Ethernet1` | host | rail-sw1 | eth2 | `tcp port 50052` | 0 | 0 |
| `9-chat-b-server-0-eth0` | pod | k8s-gpu2 | eth0 | `tcp port 8080` | 10 | 2 |
| `9-chat-b-server-0-rail6` | pod | k8s-gpu2 | rail6 | `tcp port 50052` | 0 | 0 |
| `10-chat-b-worker0-0-rail6` | pod | k8s-gpu2 | rail6 | `tcp port 50052` | 0 | 0 |
| `11-rail-sw2-Ethernet6` | host | rail-sw2 | eth7 | `tcp port 50052` | 0 | 0 |
| `9-chat-c-server-0-eth0` | pod | k8s-gpu1 | eth0 | `tcp port 8080` | 10 | 2 |
| `9-chat-c-server-0-rail7` | pod | k8s-gpu1 | rail7 | `tcp port 50052` | 0 | 0 |
| `10-chat-c-worker0-0-rail7` | pod | k8s-gpu2 | rail7 | `tcp port 50052` | 0 | 0 |
| `10-chat-c-worker1-0-rail7` | pod | k8s-gpu1 | rail7 | `tcp port 50052` | 0 | 0 |
| `11-rail-sw1-Ethernet3` | host | rail-sw1 | eth4 | `tcp port 50052` | 0 | 0 |
| `11-rail-sw1-Ethernet7` | host | rail-sw1 | eth8 | `tcp port 50052` | 0 | 0 |

## Files

- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`
- `dns/`: the client's lookup through its resolver, and the resolver's own from its address
- `fw/`: the routing table, the security and NAT rulebases (one CLI session), and the traffic log read for the refused requests
- `sessions/walk/`: the held request's reply and its session as `show session all` and `show session id` print it (CLI and XML), and its traffic log line
- `pair/`, `rail/`: the MAC tables, the rail switches' counters cleared, read before and after the request, and the times of each read
- `cluster/`: the pods, the lease, the EndpointSlices, every HTTPRoute, the API gateway's routes and the router's model list
- `request/`: the warm-up's and the request's status, response headers and body, the refused requests' answers, and each key named by field, fingerprint and mark; no request header is saved
- `refuse/`: the refused connect, as the client saw it
- `captures/<point>.pcap` and `.txt`, decoded with `tcpdump -nn -tt -e -v -S -r` (a guest's and a pod's in the guest); the API gateway's and the router's pods captured whole, each pcap scrubbed of its keys on its way out of the guest and decoded on the lab host, with `-A` as `<point>-payload.txt`

== RESULT: 57 passed, 0 failed, 0 known platform limitation(s), 0 skipped
