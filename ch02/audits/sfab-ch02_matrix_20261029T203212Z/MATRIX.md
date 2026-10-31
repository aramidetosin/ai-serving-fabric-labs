# Population and endpoint matrix

- Lab: `sfab-ch02`; labs repo commit `ad2f14ffba532ff5d8be0be16301f9fbc625f55f` (with uncommitted changes); UTC 2026-10-29T20:32:12Z
- 4 populations by 11 endpoints: 44 cells, 17 allowed and 27 forbidden (18 log lines, 1 404, 8 silent), and 6 requests with another model's key
- Every cell is tried by TCP connect or HTTP request from the population's own client, never by ping, its mode asserted with its evidence

| Endpoint | Address and port | Staff | Operator | Nodes | Internet host |
|---|---|---|---|---|---|
| Internal Gateway | 10.20.11.200, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed | PASS allowed, on the node | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| Users' Gateway | 10.20.11.210, tcp/443 | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed, on the node | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| Route to chat | the resolver's answer, tcp/443, /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| Route to staff | the resolver's answer, tcp/443, /models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| Admin hostnames | the resolver's answer, tcp/443, /echo | PASS 404, gw-users (route set) | PASS allowed | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| API server | 10.20.1.10, tcp/6443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| A node, k8s-gpu1 | 10.20.1.21, tcp/22 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| A BMC, k8s-gpu1's | 10.20.9.21, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| Storage data | 10.20.12.31, tcp/2049 | PASS silence, fw (routing) | PASS silence, uplink-rtr (routing) | PASS silence, fw (routing) | PASS silence, uplink-rtr (routing) |
| Storage management | 10.20.2.31, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout |
| An internet host, web-client | 192.0.2.18, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed |

## Evidence by cell

| Cell | Mode | Evidence |
|---|---|---|
| `enterprise/gw-internal` | log line | `requests/enterprise-gw-internal-connect-a1.txt:1`, `fw/traffic-log-443.txt:266` |
| `enterprise/gw-users` | allowed | `requests/enterprise-gw-users-connect-a1.txt:1` |
| `enterprise/chat` | allowed | `lookups/enterprise-llm-ai-tarnwick-example.txt:14`, `requests/enterprise-chat-own-a1.txt:1`, `requests/enterprise-chat-own-a1-headers.txt:1`, `requests/enterprise-chat-other-a1-body.txt:1` |
| `enterprise/staff` | allowed | `lookups/enterprise-llm-ai-tarnwick-example.txt:14`, `requests/enterprise-staff-own-a1.txt:1`, `requests/enterprise-staff-own-a1-headers.txt:1`, `requests/enterprise-staff-other-a1-body.txt:1` |
| `enterprise/admin` | 404 | `lookups/enterprise-admin-ai-tarnwick-example.txt`, `requests/enterprise-admin-request-a1.txt:1`, `requests/enterprise-admin-request-a1-headers.txt:1` |
| `enterprise/api-server` | log line | `requests/enterprise-api-server-connect-a1.txt:1`, `fw/traffic-log-6443.txt:22` |
| `enterprise/node` | log line | `requests/enterprise-node-connect-a1.txt:1`, `fw/traffic-log-22.txt:22` |
| `enterprise/bmc` | log line | `requests/enterprise-bmc-connect-a1.txt:1`, `fw/traffic-log-443.txt:238` |
| `enterprise/stor-data` | silence | `requests/enterprise-stor-data-connect-a1.txt:1`, `fw/routing-route.txt:10` |
| `enterprise/stor-mgmt` | log line | `requests/enterprise-stor-mgmt-connect-a1.txt:1`, `fw/traffic-log-443.txt:210` |
| `enterprise/egress` | log line | `requests/enterprise-egress-connect-a1.txt:1`, `fw/traffic-log-443.txt:194` |
| `operator/gw-internal` | allowed | `requests/operator-gw-internal-connect-a1.txt:1` |
| `operator/gw-users` | log line | `requests/operator-gw-users-connect-a1.txt:1`, `fw/traffic-log-443.txt:178` |
| `operator/chat` | allowed | `lookups/operator-llm-ai-tarnwick-example.txt`, `requests/operator-chat-own-a1.txt:1`, `requests/operator-chat-own-a1-headers.txt:1`, `requests/operator-chat-other-a1-body.txt:1` |
| `operator/staff` | allowed | `lookups/operator-llm-ai-tarnwick-example.txt`, `requests/operator-staff-own-a1.txt:1`, `requests/operator-staff-own-a1-headers.txt:1`, `requests/operator-staff-other-a1-body.txt:1` |
| `operator/admin` | allowed | `lookups/operator-admin-ai-tarnwick-example.txt`, `requests/operator-admin-request-a1.txt:1`, `requests/operator-admin-request-a1-headers.txt:1` |
| `operator/api-server` | silence | `requests/operator-api-server-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/node` | silence | `requests/operator-node-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/bmc` | silence | `requests/operator-bmc-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/stor-data` | silence | `requests/operator-stor-data-connect-a1.txt:1`, `routers/uplink-rtr-ip-route.txt:1` |
| `operator/stor-mgmt` | silence | `requests/operator-stor-mgmt-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/egress` | allowed | `requests/operator-egress-connect-a1.txt:1` |
| `nodes/gw-internal` | allowed | `requests/nodes-gw-internal-connect-a1.txt:1`, `fw/traffic-log-443.txt` |
| `nodes/gw-users` | allowed | `requests/nodes-gw-users-connect-a1.txt:1`, `fw/traffic-log-443.txt` |
| `nodes/chat` | allowed | `lookups/nodes-llm-ai-tarnwick-example.txt:1`, `requests/nodes-chat-own-a1.txt:1`, `requests/nodes-chat-own-a1-headers.txt:1`, `fw/traffic-log-443.txt`, `requests/nodes-chat-other-a1-body.txt:1` |
| `nodes/staff` | allowed | `lookups/nodes-llm-ai-tarnwick-example.txt:1`, `requests/nodes-staff-own-a1.txt:1`, `requests/nodes-staff-own-a1-headers.txt:1`, `fw/traffic-log-443.txt`, `requests/nodes-staff-other-a1-body.txt:1` |
| `nodes/admin` | allowed | `lookups/nodes-admin-ai-tarnwick-example.txt:1`, `requests/nodes-admin-request-a1.txt:1`, `requests/nodes-admin-request-a1-headers.txt:1`, `fw/traffic-log-443.txt` |
| `nodes/api-server` | allowed | `requests/nodes-api-server-connect-a1.txt:1` |
| `nodes/node` | allowed | `requests/nodes-node-connect-a1.txt:1` |
| `nodes/bmc` | log line | `requests/nodes-bmc-connect-a1.txt:1`, `fw/traffic-log-443.txt:138` |
| `nodes/stor-data` | silence | `requests/nodes-stor-data-connect-a1.txt:1`, `fw/routing-route.txt:10` |
| `nodes/stor-mgmt` | allowed | `requests/nodes-stor-mgmt-connect-a1.txt:1` |
| `nodes/egress` | log line | `requests/nodes-egress-connect-a1.txt:1`, `fw/traffic-log-443.txt:122` |
| `web/gw-internal` | log line | `requests/web-gw-internal-connect-a1.txt:1`, `fw/traffic-log-443.txt:106`, `routers/uplink-rtr-ip-route.txt:13` |
| `web/gw-users` | log line | `requests/web-gw-users-connect-a1.txt:1`, `fw/traffic-log-443.txt:90`, `routers/uplink-rtr-ip-route.txt:13` |
| `web/chat` | log line | `lookups/web-llm-ai-tarnwick-example.txt`, `requests/web-chat-connect-a1.txt:1`, `fw/traffic-log-443.txt:70` |
| `web/staff` | log line | `lookups/web-llm-ai-tarnwick-example.txt`, `requests/web-staff-connect-a1.txt:1`, `fw/traffic-log-443.txt:54` |
| `web/admin` | log line | `lookups/web-admin-ai-tarnwick-example.txt`, `requests/web-admin-connect-a1.txt:1`, `fw/traffic-log-443.txt:38` |
| `web/api-server` | log line | `requests/web-api-server-connect-a1.txt:1`, `fw/traffic-log-6443.txt:6`, `routers/uplink-rtr-ip-route.txt:9` |
| `web/node` | log line | `requests/web-node-connect-a1.txt:1`, `fw/traffic-log-22.txt:6`, `routers/uplink-rtr-ip-route.txt:9` |
| `web/bmc` | log line | `requests/web-bmc-connect-a1.txt:1`, `fw/traffic-log-443.txt:22`, `routers/uplink-rtr-ip-route.txt:12` |
| `web/stor-data` | silence | `requests/web-stor-data-connect-a1.txt:1`, `routers/uplink-rtr-ip-route.txt:1` |
| `web/stor-mgmt` | log line | `requests/web-stor-mgmt-connect-a1.txt:1`, `fw/traffic-log-443.txt:6`, `routers/uplink-rtr-ip-route.txt:10` |
| `web/egress` | allowed | `requests/web-egress-connect-a1.txt:1` |

Silence: enterprise/stor-data, operator/api-server, operator/node, operator/bmc, operator/stor-data, operator/stor-mgmt, nodes/stor-data, web/stor-data; its evidence is a capture at the hop, beside the route table or drop counter of the device without the route.

## Verdict

```
== the matrix: 44 cells, 17 allowed and 27 forbidden
== Staff: ent-client (10.24.10.10), resolver ent-dns, view enterprise
  PASS  [policy] Staff / Internal Gateway: log line, deny-all-log (deny), zone enterprise to ingress, for port 43000; the client: timed out, at its connect timeout
  PASS  [allowed] Staff / Users' Gateway: connected to 10.20.11.210:443, attempt 1 from port 43004
  PASS  [view] Staff / Route to chat: llm.ai.tarnwick.example answers 10.20.11.210 through ent-dns (view enterprise)
  PASS  [allowed] Staff / Route to chat: HTTP 200 from gw-users (models-gw-users), from port 43008
  PASS  [key] Staff / Route to chat: 401 with staff's key, `Authorization Failed`, from port 43010
  PASS  [view] Staff / Route to staff: llm.ai.tarnwick.example answers 10.20.11.210 through ent-dns (view enterprise)
  PASS  [allowed] Staff / Route to staff: HTTP 200 from gw-users (models-gw-users), from port 43012
  PASS  [key] Staff / Route to staff: 401 with chat's key, `Authorization Failed`, from port 43014
  PASS  [view] Staff / Admin hostnames: admin.ai.tarnwick.example has no answer through ent-dns (view enterprise holds no record for it); the request pinned to 10.20.11.210
  PASS  [routeset] Staff / Admin hostnames: 404 from gw-users, server envoy, from port 43016
  PASS  [routeset] Staff / Admin hostnames: no line for sfab-matrix-enterprise-admin in the API gateway's log, which holds the run's model requests
  PASS  [policy] Staff / API server: log line, deny-all-log (deny), zone enterprise to k8s-nodes, for port 43020; the client: timed out, at its connect timeout
  PASS  [policy] Staff / A node, k8s-gpu1: log line, deny-all-log (deny), zone enterprise to k8s-nodes, for port 43024; the client: timed out, at its connect timeout
  PASS  [policy] Staff / A BMC, k8s-gpu1's: log line, deny-all-log (deny), zone enterprise to oob, for port 43028; the client: timed out, at its connect timeout
  PASS  [routing] Staff / Storage data: fw discards 10.20.12.31 by its route 10.0.0.0/8, before any rule
  PASS  [routing] Staff / Storage data: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [policy] Staff / Storage management: log line, deny-all-log (deny), zone enterprise to stor-mgmt, for port 43036; the client: timed out, at its connect timeout
  PASS  [policy] Staff / An internet host, web-client: log line, deny-all-log (deny), zone enterprise to uplink, for port 43040; the client: timed out, at its connect timeout
== Operator: ops-client (192.0.2.2), resolver ops-dns, view public-operator
  PASS  [allowed] Operator / Internal Gateway: connected to 10.20.11.200:443, attempt 1 from port 43044
  PASS  [policy] Operator / Users' Gateway: log line, deny-all-log (deny), zone operator-vpn to ingress, for port 43048; the client: timed out, at its connect timeout
  PASS  [view] Operator / Route to chat: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 10.20.11.200
  PASS  [allowed] Operator / Route to chat: HTTP 200 from gw-internal (models-gw-internal), from port 43052
  PASS  [key] Operator / Route to chat: 401 with staff's key, `Authorization Failed`, from port 43054
  PASS  [view] Operator / Route to staff: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 10.20.11.200
  PASS  [allowed] Operator / Route to staff: HTTP 200 from gw-internal (models-gw-internal), from port 43056
  PASS  [key] Operator / Route to staff: 401 with chat's key, `Authorization Failed`, from port 43058
  PASS  [view] Operator / Admin hostnames: admin.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 10.20.11.200
  PASS  [allowed] Operator / Admin hostnames: HTTP 200 from gw-internal (echo-gw-internal), from port 43060
  PASS  [routing] Operator / API server: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / API server: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / API server: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Operator / A node, k8s-gpu1: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / A node, k8s-gpu1: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / A node, k8s-gpu1: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Operator / A BMC, k8s-gpu1's: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / A BMC, k8s-gpu1's: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / A BMC, k8s-gpu1's: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Operator / Storage data: uplink-rtr holds no route to 10.20.12.31 (9 routes read)
  PASS  [routing] Operator / Storage data: silence at uplink-rtr; no traffic log line names it; the client: an error, Network unreachable
  PASS  [routing] Operator / Storage management: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / Storage management: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / Storage management: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [allowed] Operator / An internet host, web-client: connected to 192.0.2.18:443, attempt 1 from port 43084
== Nodes: k8s-cp2 (10.20.1.12), resolver dns-res1, view internal
  PASS  [allowed] Nodes / Internal Gateway: connected to 10.20.11.200:443, attempt 1 from port 43088
  PASS  [allowed] Nodes / Internal Gateway: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43088
  PASS  [allowed] Nodes / Users' Gateway: connected to 10.20.11.210:443, attempt 1 from port 43092
  PASS  [allowed] Nodes / Users' Gateway: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43092
  PASS  [view] Nodes / Route to chat: llm.ai.tarnwick.example answers 10.20.11.200 through dns-res1 (view internal)
  PASS  [allowed] Nodes / Route to chat: HTTP 200 from gw-internal (models-gw-internal), from port 43096
  PASS  [allowed] Nodes / Route to chat: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43096
  PASS  [key] Nodes / Route to chat: 401 with staff's key, `Authorization Failed`, from port 43098
  PASS  [view] Nodes / Route to staff: llm.ai.tarnwick.example answers 10.20.11.200 through dns-res1 (view internal)
  PASS  [allowed] Nodes / Route to staff: HTTP 200 from gw-internal (models-gw-internal), from port 43100
  PASS  [allowed] Nodes / Route to staff: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43100
  PASS  [key] Nodes / Route to staff: 401 with chat's key, `Authorization Failed`, from port 43102
  PASS  [view] Nodes / Admin hostnames: admin.ai.tarnwick.example answers 10.20.11.200 through dns-res1 (view internal)
  PASS  [allowed] Nodes / Admin hostnames: HTTP 200 from gw-internal (echo-gw-internal), from port 43104
  PASS  [allowed] Nodes / Admin hostnames: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43104
  PASS  [allowed] Nodes / API server: connected to 10.20.1.10:6443, attempt 1 from port 43108
  PASS  [allowed] Nodes / A node, k8s-gpu1: connected to 10.20.1.21:22, attempt 1 from port 43112
  PASS  [policy] Nodes / A BMC, k8s-gpu1's: log line, deny-all-log (deny), zone k8s-nodes to oob, for port 43116; the client: timed out, at its connect timeout
  PASS  [routing] Nodes / Storage data: fw discards 10.20.12.31 by its route 10.0.0.0/8, before any rule
  PASS  [routing] Nodes / Storage data: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [allowed] Nodes / Storage management: connected to 10.20.2.31:443, attempt 1 from port 43124
  PASS  [policy] Nodes / An internet host, web-client: log line, deny-all-log (deny), zone k8s-nodes to uplink, for port 43128; the client: timed out, at its connect timeout
== Internet host: web-client (192.0.2.18), resolver ops-dns, view public-operator
  PASS  [policy] Internet host / Internal Gateway: log line, deny-all-log (deny), zone uplink to ingress, for port 43132; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / Internal Gateway: uplink-rtr routes 10.20.11.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [policy] Internet host / Users' Gateway: log line, deny-all-log (deny), zone uplink to ingress, for port 43136; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / Users' Gateway: uplink-rtr routes 10.20.11.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [view] Internet host / Route to chat: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 198.51.100.2
  PASS  [policy] Internet host / Route to chat: log line, deny-all-log (deny), zone uplink to uplink, for port 43140; the client: timed out, at its connect timeout
  PASS  [view] Internet host / Route to staff: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 198.51.100.2
  PASS  [policy] Internet host / Route to staff: log line, deny-all-log (deny), zone uplink to uplink, for port 43144; the client: timed out, at its connect timeout
  PASS  [view] Internet host / Admin hostnames: admin.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 198.51.100.2
  PASS  [policy] Internet host / Admin hostnames: log line, deny-all-log (deny), zone uplink to uplink, for port 43148; the client: timed out, at its connect timeout
  PASS  [policy] Internet host / API server: log line, deny-all-log (deny), zone uplink to k8s-nodes, for port 43152; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / API server: uplink-rtr routes 10.20.1.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [policy] Internet host / A node, k8s-gpu1: log line, deny-all-log (deny), zone uplink to k8s-nodes, for port 43156; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / A node, k8s-gpu1: uplink-rtr routes 10.20.1.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [policy] Internet host / A BMC, k8s-gpu1's: log line, deny-all-log (deny), zone uplink to oob, for port 43160; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / A BMC, k8s-gpu1's: uplink-rtr routes 10.20.9.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [routing] Internet host / Storage data: uplink-rtr holds no route to 10.20.12.31 (9 routes read)
  PASS  [routing] Internet host / Storage data: silence at uplink-rtr; no traffic log line names it; the client: an error, Network unreachable
  PASS  [policy] Internet host / Storage management: log line, deny-all-log (deny), zone uplink to stor-mgmt, for port 43168; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / Storage management: uplink-rtr routes 10.20.2.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [allowed] Internet host / An internet host, web-client: connected to 192.0.2.18:443, attempt 1 from port 43172
== the matrix
  PASS  44 of 44 cells in their mode (17 allowed, 18 log lines, 1 404, 8 silent)
```

## Files

- `verdict.txt`, `commands.txt`, `matrix.json` (the plan), `requests.tsv` (one line an attempt)
- `lookups/`: each client's lookup of the names it asks for, through its own resolver
- `requests/`: each attempt as the client saw it, and each answer's headers and body; no request header is saved
- `fw/`: the traffic log read for the refused cells; `routers/`: the routing table of each router in front of the firewall
- `api-gateway/access.txt`: the API gateway pods' access log over the run
