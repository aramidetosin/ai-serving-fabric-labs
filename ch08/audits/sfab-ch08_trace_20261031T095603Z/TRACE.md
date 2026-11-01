# Serving trace

- Lab: `sfab-ch08`; labs repo commit `6ed2c330e0393d082e755ddf5137a7b437b6c69f`; UTC 2026-10-31T09:56:03Z
- One chat completion from k8s-cp2 (10.20.1.12, source port 42806) to `https://llm.ai.tarnwick.example/models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions` through gw-users (10.20.11.210), with staff's key; 14 capture points
- Answer: HTTP 200; the router's deployment `openai/staff` on `http://staff.serving.svc.cluster.local:8080/v1`, retries 0

## The path

| Hop | Point | Node | Address | First data (decode line) |
|---|---|---|---|---|
| Gateway VIP (answered on the node) | `0-k8s-cp2-eth1` | k8s-cp2 | 10.20.11.210:443 | - |
| API gateway | `2-api-gateway-764fd87dc-pmq6j-eth0` | k8s-ingress2 | 10.22.5.163:9080 | `captures/2-api-gateway-764fd87dc-pmq6j-eth0.txt:32` |
| router | `3-router-76cf778fb6-q8vvl-eth0` | k8s-ingress1 | 10.22.4.215:4000 | `captures/3-router-76cf778fb6-q8vvl-eth0.txt:70` |
| server | `4-staff-b-server-0-eth0` | k8s-gpu2 | 10.22.3.97:8080 | `captures/4-staff-b-server-0-eth0.txt:8` |
| worker (same node) | `5-staff-b-worker0-0-rail5` | k8s-gpu2 | 10.21.5.101:50052 | `captures/5-staff-b-worker0-0-rail5.txt:2` |

The copy that served it: staff-b, rail 5 (rail5) on rail-sw1: server staff-b-server-0 on k8s-gpu2 at 10.21.5.100, workers staff-b-worker0-0 on k8s-gpu2 at 10.21.5.101.

## The keys at the in-cluster hops

Each value in the captures is its keyed mark (`captures/scrub.log` counts the values replaced); the key files under `request/` name each key by its field, fingerprint and mark.

| Hop | Point | Request | Authorization | Key | Decode line |
|---|---|---|---|---|---|
| 1: Gateway to API gateway | `2-api-gateway-764fd87dc-pmq6j-eth0` | POST `/models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions` | `<redacted hmac:adcda79b7fd1>` | the caller's key | `captures/2-api-gateway-764fd87dc-pmq6j-eth0-payload.txt:101` |
| 2: API gateway to router | `2-api-gateway-764fd87dc-pmq6j-eth0` | POST `/engines/staff/chat/completions` | `<redacted hmac:e23c6eceb501>` | the router's master key | `captures/2-api-gateway-764fd87dc-pmq6j-eth0-payload.txt:154` |
| 3: router to server | `3-router-76cf778fb6-q8vvl-eth0` | POST `/v1/chat/completions` | `<redacted hmac:a2484a20cce9>` | the backend key | `captures/3-router-76cf778fb6-q8vvl-eth0-payload.txt:312` |

## The same key through gw-inet

`https://llm.ai.tarnwick.example/models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions?msg=sfab-trace-also-gw-inet` from k8s-cp2 (source port 42808) to gw-inet (10.20.11.220), with staff's key: HTTP 404, server envoy; no API gateway pod saw it.

## The refusal

`https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused` from k8s-cp2 (source port 42807) to gw-inet: HTTP 404, server envoy; no API gateway pod saw it.

## Verdict

```
== the serving trace: staff through gw-users
  PASS  the key for staff handed to k8s-cp2 as a 0600 header file, read from its Secret in the cluster (helpdesk.a3da6115 sha256:fe2830ecead9 <redacted hmac:adcda79b7fd1>)
== the request: k8s-cp2 to staff through gw-users
  PASS  HTTP 200 for POST https://llm.ai.tarnwick.example/models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions with staff's key
  PASS  answered by the router's openai/staff deployment, on the model's Service http://staff.serving.svc.cluster.local:8080/v1, with no retry
== the users' VIP
  PASS  k8s-cp2 answers gw-users's VIP 10.20.11.210 itself: no SYN to it left the node on its 2 port(s) (0-k8s-cp2-eth1, 0-k8s-cp2-eth2), so the lease holder (k8s-ingress2) never saw the request
== the API gateway and the router
  PASS  one API gateway pod took it: api-gateway-764fd87dc-pmq6j on k8s-ingress2 (10.22.5.163:9080), data from the Gateway's proxy at 10.22.1.125, sent on to the router pod router-76cf778fb6-q8vvl (10.22.4.215:4000); api-gateway-764fd87dc-zqmjz took none
  PASS  the router pod router-76cf778fb6-q8vvl on k8s-ingress1 received it from api-gateway-764fd87dc-pmq6j and sent it to staff-b-server-0 (10.22.3.97:8080), staff's copy b on rail 5
== the server and its workers on the rail
  PASS  staff-b-server-0 on k8s-gpu2 received it on eth0 from router-76cf778fb6-q8vvl and answered (1 data segments in, 1 out)
  PASS  staff-b-server-0's RPC on rail5 (10.21.5.100) to staff-b-worker0-0 at 10.21.5.101:50052, the table's rail 5: 536 data segments out, 307 back
  PASS  staff-b-worker0-0 on k8s-gpu2 saw it on its own rail5 (536 data segments from 10.21.5.100)
== rail-sw1: the rail switch of rail 5
  PASS  ... and no frame of the RPC to staff-b-worker0-0 (10.21.5.101), beside its server on k8s-gpu2: macvlan's bridge mode keeps it inside the node
== staff's other copies
  PASS  copy a on rail 4 carried none of it: no data to staff-a-server-0, no RPC on rail4 at its server, its workers or rail-sw2's ports
== the keys at the in-cluster hops (the captures' Authorization values replaced by their marks)
  PASS  hop 1, the Gateway's proxy to api-gateway-764fd87dc-pmq6j: POST /models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions with Authorization <redacted hmac:adcda79b7fd1>, the caller's staff key (helpdesk.a3da6115 sha256:fe2830ecead9)
  PASS  hop 2, api-gateway-764fd87dc-pmq6j to the router pod router-76cf778fb6-q8vvl: POST /engines/staff/chat/completions with Authorization <redacted hmac:e23c6eceb501>, the router's master key (sha256:876e2d9256d0), set in place of the caller's
  PASS  ... and the caller's key nowhere on hop 2 (0 requests to the router carry its mark)
  PASS  ... which router-76cf778fb6-q8vvl received with the same mark
  PASS  hop 3, router-76cf778fb6-q8vvl to the server at 10.22.3.97: Authorization <redacted hmac:a2484a20cce9>, the backend key (sha256:ad17a62fa831), neither the caller's nor the master key
  PASS  every Authorization value in the keyed captures is a mark, none a value (4 requests with one, 4 keyed points)
== the same key and path through gw-inet, whose route set does not carry staff
  PASS  POST https://llm.ai.tarnwick.example/models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions?msg=sfab-trace-also-gw-inet from k8s-cp2 through gw-inet (10.20.11.220) with staff's key: HTTP 404 from the Gateway (server envoy)
  PASS  no API gateway pod saw it: no request carrying sfab-trace-also-gw-inet at 2 API gateway pods (so no API gateway line names it)
== the refusal: admin.ai.tarnwick.example sent to gw-inet, which does not carry it
  PASS  GET https://admin.ai.tarnwick.example/echo?msg=sfab-trace-refused from k8s-cp2: HTTP 404 from the Gateway (server envoy)
  PASS  k8s-cp2 answered it itself: no SYN from port 42807 to 10.20.11.220 left the node
  PASS  no API gateway pod saw it: no request for admin.ai.tarnwick.example at 2 API gateway pods, which received 1 request(s) in all, the keyed one
```

## Frames per point

| Point | Kind | Node | Interface | Filter | Frames | Data segments |
|---|---|---|---|---|---|---|
| `0-k8s-cp2-eth1` | host | k8s-cp2 | eth1 | `(tcp port 443 and (host 10.20.11.210 or host 10.20.11.220 or host 10.20.11.220)) or (vlan and (tcp port 443 and (host 10.20.11.210 or host 10.20.11.220 or host 10.20.11.220)))` | 0 | 0 |
| `0-k8s-cp2-eth2` | host | k8s-cp2 | eth2 | `(tcp port 443 and (host 10.20.11.210 or host 10.20.11.220 or host 10.20.11.220)) or (vlan and (tcp port 443 and (host 10.20.11.210 or host 10.20.11.220 or host 10.20.11.220)))` | 0 | 0 |
| `2-api-gateway-764fd87dc-pmq6j-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 9080 or tcp port 4000` | 47 | 4 |
| `2-api-gateway-764fd87dc-zqmjz-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 9080 or tcp port 4000` | 33 | 0 |
| `3-router-76cf778fb6-9gt78-eth0` | pod | k8s-ingress2 | eth0 | `tcp port 4000 or tcp port 8080` | 60 | 10 |
| `3-router-76cf778fb6-q8vvl-eth0` | pod | k8s-ingress1 | eth0 | `tcp port 4000 or tcp port 8080` | 73 | 14 |
| `4-staff-a-server-0-eth0` | pod | k8s-gpu1 | eth0 | `tcp port 8080` | 3 | 0 |
| `4-staff-a-server-0-rail4` | pod | k8s-gpu1 | rail4 | `tcp port 50052` | 0 | 0 |
| `5-staff-a-worker0-0-rail4` | pod | k8s-gpu1 | rail4 | `tcp port 50052` | 0 | 0 |
| `6-rail-sw2-Ethernet1` | host | rail-sw2 | eth2 | `tcp port 50052` | 0 | 0 |
| `4-staff-b-server-0-eth0` | pod | k8s-gpu2 | eth0 | `tcp port 8080` | 10 | 2 |
| `4-staff-b-server-0-rail5` | pod | k8s-gpu2 | rail5 | `tcp port 50052` | 1312 | 843 |
| `5-staff-b-worker0-0-rail5` | pod | k8s-gpu2 | rail5 | `tcp port 50052` | 1312 | 843 |
| `6-rail-sw1-Ethernet6` | host | rail-sw1 | eth7 | `tcp port 50052` | 0 | 0 |

## Files

- `verdict.txt`, `commands.txt`, `trace.json` (the plan), `points.tsv`
- `cluster/`: the pods of both namespaces, the users' VIP's lease and the serving EndpointSlices, read before the captures
- `request/`: the warm-up's and the request's status (`result.txt`), response headers and body; no request header is saved
- `captures/<point>.pcap` and `.txt`, decoded with `tcpdump -nn -tt -e -v -r` (a guest's and a pod's in the guest); a pod's cluster interface captured at 66 bytes a frame, so no capture holds an HTTP header; the API gateway's and the router's captured whole, each pcap scrubbed of its keys on its way out of the guest and decoded on the lab host, with `-A` as `<point>-payload.txt`

== RESULT: 22 passed, 0 failed, 0 known platform limitation(s), 0 skipped
