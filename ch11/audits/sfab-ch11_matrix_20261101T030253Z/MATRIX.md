# Population and endpoint matrix

- Lab: `sfab-ch11`; labs repo commit `86a59ddfea6f405c4d6d70af509ef75a856ac3a8`; UTC 2026-11-01T03:02:53Z
- 5 populations by 12 endpoints: 60 cells, 20 allowed and 40 forbidden (21 log lines, 3 404, 16 silent), and 7 requests with another model's key
- Every cell is tried by TCP connect or HTTP request from the population's own client, never by ping, its mode asserted with its evidence

| Endpoint | Address and port | Staff | Operator | Nodes | Internet host | Internet users |
|---|---|---|---|---|---|---|
| Internal Gateway | 10.20.11.200, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed | PASS allowed, on the node | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, isp-rtr (routing) |
| Users' Gateway | 10.20.11.210, tcp/443 | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed, on the node | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, isp-rtr (routing) |
| Internet Gateway | 10.20.11.220, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed, on the node | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed, at the public address |
| Route to chat | the resolver's answer, tcp/443, /models/a48b3df9-3b7f-58f0-9c52-c6f3004f05f7/v1/chat/completions | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS 200 with inetapp's key; 401 with the other model's key (key) |
| Route to staff | the resolver's answer, tcp/443, /models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS 200; 401 with the other model's key (key) | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS 404, gw-inet (route set) |
| Admin hostnames | the resolver's answer, tcp/443, /echo | PASS 404, gw-users (route set) | PASS allowed | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS 404, gw-inet (route set) |
| API server | 10.20.1.10, tcp/6443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, isp-rtr (routing) |
| A node, k8s-gpu1 | 10.20.1.21, tcp/22 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, isp-rtr (routing) |
| A BMC, k8s-gpu1's | 10.20.9.21, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, isp-rtr (routing) |
| Storage data | 10.20.12.31, tcp/2049 | PASS silence, fw (routing) | PASS silence, uplink-rtr (routing) | PASS silence, fw (routing) | PASS silence, uplink-rtr (routing) | PASS silence, isp-rtr (routing) |
| Storage management | 10.20.2.31, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, fw (routing) | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS silence, isp-rtr (routing) |
| An internet host, web-client | 192.0.2.18, tcp/443 | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed | PASS log line, deny-all-log (policy); timed out, at its connect timeout | PASS allowed | PASS silence, isp-rtr (routing) |

## Evidence by cell

| Cell | Mode | Depth | The layers that would refuse it | Evidence |
|---|---|---|---|---|
| `enterprise/gw-internal` | log line | 1 | fw (policy): deny-all-log (enterprise to ingress) | `requests/enterprise-gw-internal-connect-a1.txt:1`, `fw/traffic-log-443.txt:334` |
| `enterprise/gw-users` | allowed | 0 | none: allowed | `requests/enterprise-gw-users-connect-a1.txt:1` |
| `enterprise/gw-inet` | log line | 1 | fw (policy): deny-all-log (enterprise to ingress) | `requests/enterprise-gw-inet-connect-a1.txt:1`, `fw/traffic-log-443.txt:318` |
| `enterprise/chat` | allowed | 0 | none: allowed | `lookups/enterprise-llm-ai-tarnwick-example.txt:14`, `requests/enterprise-chat-own-a1.txt:1`, `requests/enterprise-chat-own-a1-headers.txt:1`, `requests/enterprise-chat-other-a1-body.txt:1` |
| `enterprise/staff` | allowed | 0 | none: allowed | `lookups/enterprise-llm-ai-tarnwick-example.txt:14`, `requests/enterprise-staff-own-a1.txt:1`, `requests/enterprise-staff-own-a1-headers.txt:1`, `requests/enterprise-staff-other-a1-body.txt:1` |
| `enterprise/admin` | 404 | 1 | gw-users (routeset): no HTTPRoute for admin.ai.tarnwick.example and /echo | `lookups/enterprise-admin-ai-tarnwick-example.txt`, `requests/enterprise-admin-request-a1.txt:1`, `requests/enterprise-admin-request-a1-headers.txt:1` |
| `enterprise/api-server` | log line | 1 | fw (policy): deny-all-log (enterprise to k8s-nodes) | `requests/enterprise-api-server-connect-a1.txt:1`, `fw/traffic-log-6443.txt:22` |
| `enterprise/node` | log line | 1 | fw (policy): deny-all-log (enterprise to k8s-nodes) | `requests/enterprise-node-connect-a1.txt:1`, `fw/traffic-log-22.txt:22` |
| `enterprise/bmc` | log line | 1 | fw (policy): deny-all-log (enterprise to oob) | `requests/enterprise-bmc-connect-a1.txt:1`, `fw/traffic-log-443.txt:298` |
| `enterprise/stor-data` | silence | 1 | fw (routing): no route to 10.20.12.31 | `requests/enterprise-stor-data-connect-a1.txt:1`, `fw/routing-route.txt:10` |
| `enterprise/stor-mgmt` | log line | 1 | fw (policy): deny-all-log (enterprise to stor-mgmt) | `requests/enterprise-stor-mgmt-connect-a1.txt:1`, `fw/traffic-log-443.txt:262` |
| `enterprise/egress` | log line | 1 | fw (policy): deny-all-log (enterprise to uplink) | `requests/enterprise-egress-connect-a1.txt:1`, `fw/traffic-log-443.txt:246` |
| `operator/gw-internal` | allowed | 0 | none: allowed | `requests/operator-gw-internal-connect-a1.txt:1` |
| `operator/gw-users` | log line | 1 | fw (policy): deny-all-log (operator-vpn to ingress) | `requests/operator-gw-users-connect-a1.txt:1`, `fw/traffic-log-443.txt:230` |
| `operator/gw-inet` | log line | 1 | fw (policy): deny-all-log (operator-vpn to ingress) | `requests/operator-gw-inet-connect-a1.txt:1`, `fw/traffic-log-443.txt:214` |
| `operator/chat` | allowed | 0 | none: allowed | `lookups/operator-llm-ai-tarnwick-example.txt`, `requests/operator-chat-own-a1.txt:1`, `requests/operator-chat-own-a1-headers.txt:1`, `requests/operator-chat-other-a1-body.txt:1` |
| `operator/staff` | allowed | 0 | none: allowed | `lookups/operator-llm-ai-tarnwick-example.txt`, `requests/operator-staff-own-a1.txt:1`, `requests/operator-staff-own-a1-headers.txt:1`, `requests/operator-staff-other-a1-body.txt:1` |
| `operator/admin` | allowed | 0 | none: allowed | `lookups/operator-admin-ai-tarnwick-example.txt`, `requests/operator-admin-request-a1.txt:1`, `requests/operator-admin-request-a1-headers.txt:1` |
| `operator/api-server` | silence | 2 | fw (routing): strict IP check (zp-internet): 192.0.2.2 is routed by 192.0.2.0/30 out tunnel.1 (operator-site), not over ethernet1/5; fw (policy): deny-all-log (uplink to k8s-nodes) | `requests/operator-api-server-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/node` | silence | 2 | fw (routing): strict IP check (zp-internet): 192.0.2.2 is routed by 192.0.2.0/30 out tunnel.1 (operator-site), not over ethernet1/5; fw (policy): deny-all-log (uplink to k8s-nodes) | `requests/operator-node-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/bmc` | silence | 2 | fw (routing): strict IP check (zp-internet): 192.0.2.2 is routed by 192.0.2.0/30 out tunnel.1 (operator-site), not over ethernet1/5; fw (policy): deny-all-log (uplink to oob) | `requests/operator-bmc-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/stor-data` | silence | 3 | uplink-rtr (routing): no route to 10.20.12.31; fw (routing): strict IP check (zp-internet): 192.0.2.2 is routed by 192.0.2.0/30 out tunnel.1 (operator-site), not over ethernet1/5; fw (routing): no route to 10.20.12.31 | `requests/operator-stor-data-connect-a1.txt:1`, `routers/uplink-rtr-ip-route.txt:1` |
| `operator/stor-mgmt` | silence | 2 | fw (routing): strict IP check (zp-internet): 192.0.2.2 is routed by 192.0.2.0/30 out tunnel.1 (operator-site), not over ethernet1/5; fw (policy): deny-all-log (uplink to stor-mgmt) | `requests/operator-stor-mgmt-connect-a1.txt:1`, `fw/routing-route.txt:30`, `fw/drops.txt:12` |
| `operator/egress` | allowed | 0 | none: allowed | `requests/operator-egress-connect-a1.txt:1` |
| `nodes/gw-internal` | allowed | 0 | none: allowed | `requests/nodes-gw-internal-connect-a1.txt:1`, `fw/traffic-log-443.txt` |
| `nodes/gw-users` | allowed | 0 | none: allowed | `requests/nodes-gw-users-connect-a1.txt:1`, `fw/traffic-log-443.txt` |
| `nodes/gw-inet` | allowed | 0 | none: allowed | `requests/nodes-gw-inet-connect-a1.txt:1`, `fw/traffic-log-443.txt` |
| `nodes/chat` | allowed | 0 | none: allowed | `lookups/nodes-llm-ai-tarnwick-example.txt:1`, `requests/nodes-chat-own-a1.txt:1`, `requests/nodes-chat-own-a1-headers.txt:1`, `fw/traffic-log-443.txt`, `requests/nodes-chat-other-a1-body.txt:1` |
| `nodes/staff` | allowed | 0 | none: allowed | `lookups/nodes-llm-ai-tarnwick-example.txt:1`, `requests/nodes-staff-own-a1.txt:1`, `requests/nodes-staff-own-a1-headers.txt:1`, `fw/traffic-log-443.txt`, `requests/nodes-staff-other-a1-body.txt:1` |
| `nodes/admin` | allowed | 0 | none: allowed | `lookups/nodes-admin-ai-tarnwick-example.txt:1`, `requests/nodes-admin-request-a1.txt:1`, `requests/nodes-admin-request-a1-headers.txt:1`, `fw/traffic-log-443.txt` |
| `nodes/api-server` | allowed | 0 | none: allowed | `requests/nodes-api-server-connect-a1.txt:1` |
| `nodes/node` | allowed | 0 | none: allowed | `requests/nodes-node-connect-a1.txt:1` |
| `nodes/bmc` | log line | 1 | fw (policy): deny-all-log (k8s-nodes to oob) | `requests/nodes-bmc-connect-a1.txt:1`, `fw/traffic-log-443.txt:174` |
| `nodes/stor-data` | silence | 1 | fw (routing): no route to 10.20.12.31 | `requests/nodes-stor-data-connect-a1.txt:1`, `fw/routing-route.txt:10` |
| `nodes/stor-mgmt` | allowed | 0 | none: allowed | `requests/nodes-stor-mgmt-connect-a1.txt:1` |
| `nodes/egress` | log line | 1 | fw (policy): deny-all-log (k8s-nodes to uplink) | `requests/nodes-egress-connect-a1.txt:1`, `fw/traffic-log-443.txt:158` |
| `web/gw-internal` | log line | 1 | fw (policy): deny-all-log (uplink to ingress) | `requests/web-gw-internal-connect-a1.txt:1`, `fw/traffic-log-443.txt:142`, `routers/uplink-rtr-ip-route.txt:13` |
| `web/gw-users` | log line | 1 | fw (policy): deny-all-log (uplink to ingress) | `requests/web-gw-users-connect-a1.txt:1`, `fw/traffic-log-443.txt:126`, `routers/uplink-rtr-ip-route.txt:13` |
| `web/gw-inet` | log line | 1 | fw (policy): deny-all-log (uplink to ingress) | `requests/web-gw-inet-connect-a1.txt:1`, `fw/traffic-log-443.txt:106`, `routers/uplink-rtr-ip-route.txt:13` |
| `web/chat` | log line | 1 | fw (policy): deny-all-log (uplink to uplink) | `lookups/web-llm-ai-tarnwick-example.txt`, `requests/web-chat-connect-a1.txt:1`, `fw/traffic-log-443.txt:90` |
| `web/staff` | log line | 1 | fw (policy): deny-all-log (uplink to uplink) | `lookups/web-llm-ai-tarnwick-example.txt`, `requests/web-staff-connect-a1.txt:1`, `fw/traffic-log-443.txt:74` |
| `web/admin` | log line | 1 | fw (policy): deny-all-log (uplink to uplink) | `lookups/web-admin-ai-tarnwick-example.txt`, `requests/web-admin-connect-a1.txt:1`, `fw/traffic-log-443.txt:58` |
| `web/api-server` | log line | 1 | fw (policy): deny-all-log (uplink to k8s-nodes) | `requests/web-api-server-connect-a1.txt:1`, `fw/traffic-log-6443.txt:6`, `routers/uplink-rtr-ip-route.txt:9` |
| `web/node` | log line | 1 | fw (policy): deny-all-log (uplink to k8s-nodes) | `requests/web-node-connect-a1.txt:1`, `fw/traffic-log-22.txt:6`, `routers/uplink-rtr-ip-route.txt:9` |
| `web/bmc` | log line | 1 | fw (policy): deny-all-log (uplink to oob) | `requests/web-bmc-connect-a1.txt:1`, `fw/traffic-log-443.txt:42`, `routers/uplink-rtr-ip-route.txt:12` |
| `web/stor-data` | silence | 2 | uplink-rtr (routing): no route to 10.20.12.31; fw (routing): no route to 10.20.12.31 | `requests/web-stor-data-connect-a1.txt:1`, `routers/uplink-rtr-ip-route.txt:1` |
| `web/stor-mgmt` | log line | 1 | fw (policy): deny-all-log (uplink to stor-mgmt) | `requests/web-stor-mgmt-connect-a1.txt:1`, `fw/traffic-log-443.txt:26`, `routers/uplink-rtr-ip-route.txt:10` |
| `web/egress` | allowed | 0 | none: allowed | `requests/web-egress-connect-a1.txt:1` |
| `internet/gw-internal` | silence | 2 | isp-rtr (routing): no route to 10.20.11.200; fw (policy): deny-all-log (isp to ingress) | `requests/internet-gw-internal-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |
| `internet/gw-users` | silence | 2 | isp-rtr (routing): no route to 10.20.11.210; fw (policy): deny-all-log (isp to ingress) | `requests/internet-gw-users-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |
| `internet/gw-inet` | allowed | 0 | none: allowed | `requests/internet-gw-inet-connect-a1.txt:1` |
| `internet/chat` | allowed | 0 | none: allowed | `lookups/internet-llm-ai-tarnwick-example.txt:15`, `requests/internet-chat-own-a1.txt:1`, `api-gateway/access.txt:18`, `requests/internet-chat-own-a1-headers.txt:1`, `requests/internet-chat-other-a1-body.txt:1` |
| `internet/staff` | 404 | 2 | gw-inet (routeset): no HTTPRoute for llm.ai.tarnwick.example and /models/8242d5c4-9bce-5497-8414-f5bad94fdd84/v1/chat/completions; api-gateway (key): inetapp's key: staff's route admits helpdesk, staff | `lookups/internet-llm-ai-tarnwick-example.txt:15`, `requests/internet-staff-request-a1.txt:1`, `requests/internet-staff-request-a1-headers.txt:1` |
| `internet/admin` | 404 | 1 | gw-inet (routeset): no HTTPRoute for admin.ai.tarnwick.example and /echo | `lookups/internet-admin-ai-tarnwick-example.txt`, `requests/internet-admin-request-a1.txt:1`, `requests/internet-admin-request-a1-headers.txt:1` |
| `internet/api-server` | silence | 2 | isp-rtr (routing): no route to 10.20.1.10; fw (policy): deny-all-log (isp to k8s-nodes) | `requests/internet-api-server-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |
| `internet/node` | silence | 2 | isp-rtr (routing): no route to 10.20.1.21; fw (policy): deny-all-log (isp to k8s-nodes) | `requests/internet-node-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |
| `internet/bmc` | silence | 2 | isp-rtr (routing): no route to 10.20.9.21; fw (policy): deny-all-log (isp to oob) | `requests/internet-bmc-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |
| `internet/stor-data` | silence | 2 | isp-rtr (routing): no route to 10.20.12.31; fw (routing): no route to 10.20.12.31 | `requests/internet-stor-data-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |
| `internet/stor-mgmt` | silence | 2 | isp-rtr (routing): no route to 10.20.2.31; fw (policy): deny-all-log (isp to stor-mgmt) | `requests/internet-stor-mgmt-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |
| `internet/egress` | silence | 2 | isp-rtr (routing): no route to 192.0.2.18; fw (policy): deny-all-log (isp to uplink) | `requests/internet-egress-connect-a1.txt:1`, `routers/isp-rtr-ip-route.txt:1` |

Silence: enterprise/stor-data, operator/api-server, operator/node, operator/bmc, operator/stor-data, operator/stor-mgmt, nodes/stor-data, web/stor-data, internet/gw-internal, internet/gw-users, internet/api-server, internet/node, internet/bmc, internet/stor-data, internet/stor-mgmt, internet/egress; its evidence is a capture at the hop, beside the route table or drop counter of the device without the route.

Cells by depth: depth 1 25, depth 2 14, depth 3 1.

## Verdict

```
== the matrix: 60 cells, 20 allowed and 40 forbidden
== Staff: ent-client (10.24.10.10), resolver ent-dns, view enterprise
  PASS  [policy] Staff / Internal Gateway: log line, deny-all-log (deny), zone enterprise to ingress, for port 43000; the client: timed out, at its connect timeout
  PASS  [allowed] Staff / Users' Gateway: connected to 10.20.11.210:443, attempt 1 from port 43004
  PASS  [policy] Staff / Internet Gateway: log line, deny-all-log (deny), zone enterprise to ingress, for port 43008; the client: timed out, at its connect timeout
  PASS  [view] Staff / Route to chat: llm.ai.tarnwick.example answers 10.20.11.210 through ent-dns (view enterprise)
  PASS  [allowed] Staff / Route to chat: HTTP 200 from gw-users (models-gw-users), from port 43012
  PASS  [key] Staff / Route to chat: 401 with staff's key, `Authorization Failed`, from port 43014
  PASS  [view] Staff / Route to staff: llm.ai.tarnwick.example answers 10.20.11.210 through ent-dns (view enterprise)
  PASS  [allowed] Staff / Route to staff: HTTP 200 from gw-users (models-gw-users), from port 43016
  PASS  [key] Staff / Route to staff: 401 with chat's key, `Authorization Failed`, from port 43018
  PASS  [view] Staff / Admin hostnames: admin.ai.tarnwick.example has no answer through ent-dns (view enterprise holds no record for it); the request pinned to 10.20.11.210
  PASS  [routeset] Staff / Admin hostnames: 404 from gw-users, server envoy, from port 43020
  PASS  [routeset] Staff / Admin hostnames: no line for sfab-matrix-enterprise-admin in the API gateway's log, which holds the run's model requests
  PASS  [policy] Staff / API server: log line, deny-all-log (deny), zone enterprise to k8s-nodes, for port 43024; the client: timed out, at its connect timeout
  PASS  [policy] Staff / A node, k8s-gpu1: log line, deny-all-log (deny), zone enterprise to k8s-nodes, for port 43028; the client: timed out, at its connect timeout
  PASS  [policy] Staff / A BMC, k8s-gpu1's: log line, deny-all-log (deny), zone enterprise to oob, for port 43032; the client: timed out, at its connect timeout
  PASS  [routing] Staff / Storage data: fw discards 10.20.12.31 by its route 10.0.0.0/8, before any rule
  PASS  [routing] Staff / Storage data: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [policy] Staff / Storage management: log line, deny-all-log (deny), zone enterprise to stor-mgmt, for port 43040; the client: timed out, at its connect timeout
  PASS  [policy] Staff / An internet host, web-client: log line, deny-all-log (deny), zone enterprise to uplink, for port 43044; the client: timed out, at its connect timeout
== Operator: ops-client (192.0.2.2), resolver ops-dns, view public-operator
  PASS  [allowed] Operator / Internal Gateway: connected to 10.20.11.200:443, attempt 1 from port 43048
  PASS  [policy] Operator / Users' Gateway: log line, deny-all-log (deny), zone operator-vpn to ingress, for port 43052; the client: timed out, at its connect timeout
  PASS  [policy] Operator / Internet Gateway: log line, deny-all-log (deny), zone operator-vpn to ingress, for port 43056; the client: timed out, at its connect timeout
  PASS  [view] Operator / Route to chat: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 10.20.11.200
  PASS  [allowed] Operator / Route to chat: HTTP 200 from gw-internal (models-gw-internal), from port 43060
  PASS  [key] Operator / Route to chat: 401 with staff's key, `Authorization Failed`, from port 43062
  PASS  [view] Operator / Route to staff: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 10.20.11.200
  PASS  [allowed] Operator / Route to staff: HTTP 200 from gw-internal (models-gw-internal), from port 43064
  PASS  [key] Operator / Route to staff: 401 with chat's key, `Authorization Failed`, from port 43066
  PASS  [view] Operator / Admin hostnames: admin.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 10.20.11.200
  PASS  [allowed] Operator / Admin hostnames: HTTP 200 from gw-internal (echo-gw-internal), from port 43068
  PASS  [routing] Operator / API server: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / API server: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / API server: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Operator / A node, k8s-gpu1: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / A node, k8s-gpu1: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / A node, k8s-gpu1: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Operator / A BMC, k8s-gpu1's: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / A BMC, k8s-gpu1's: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / A BMC, k8s-gpu1's: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Operator / Storage data: uplink-rtr holds no route to 10.20.12.31 (21 routes read)
  PASS  [routing] Operator / Storage data: silence at uplink-rtr; no traffic log line names it; the client: an error, Network unreachable
  PASS  [routing] Operator / Storage management: fw routes the source 192.0.2.2 by 192.0.2.0/30 out tunnel.1 (operator-site), not over the interface the request arrived on
  PASS  [routing] Operator / Storage management: zone protection's strict IP check dropped it before any rule (flow_dos_pf_strictip 16 over the run, fw/drops.txt)
  PASS  [routing] Operator / Storage management: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [allowed] Operator / An internet host, web-client: connected to 192.0.2.18:443, attempt 1 from port 43092
== Nodes: k8s-cp2 (10.20.1.12), resolver dns-res1, view internal
  PASS  [allowed] Nodes / Internal Gateway: connected to 10.20.11.200:443, attempt 1 from port 43096
  PASS  [allowed] Nodes / Internal Gateway: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43096
  PASS  [allowed] Nodes / Users' Gateway: connected to 10.20.11.210:443, attempt 1 from port 43100
  PASS  [allowed] Nodes / Users' Gateway: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43100
  PASS  [allowed] Nodes / Internet Gateway: connected to 10.20.11.220:443, attempt 1 from port 43104
  PASS  [allowed] Nodes / Internet Gateway: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43104
  PASS  [view] Nodes / Route to chat: llm.ai.tarnwick.example answers 10.20.11.200 through dns-res1 (view internal)
  PASS  [allowed] Nodes / Route to chat: HTTP 200 from gw-internal (models-gw-internal), from port 43108
  PASS  [allowed] Nodes / Route to chat: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43108
  PASS  [key] Nodes / Route to chat: 401 with staff's key, `Authorization Failed`, from port 43110
  PASS  [view] Nodes / Route to staff: llm.ai.tarnwick.example answers 10.20.11.200 through dns-res1 (view internal)
  PASS  [allowed] Nodes / Route to staff: HTTP 200 from gw-internal (models-gw-internal), from port 43112
  PASS  [allowed] Nodes / Route to staff: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43112
  PASS  [key] Nodes / Route to staff: 401 with chat's key, `Authorization Failed`, from port 43114
  PASS  [view] Nodes / Admin hostnames: admin.ai.tarnwick.example answers 10.20.11.200 through dns-res1 (view internal)
  PASS  [allowed] Nodes / Admin hostnames: HTTP 200 from gw-internal (echo-gw-internal), from port 43116
  PASS  [allowed] Nodes / Admin hostnames: answered on k8s-cp2 itself, no line in the firewall's traffic log for port 43116
  PASS  [allowed] Nodes / API server: connected to 10.20.1.10:6443, attempt 1 from port 43120
  PASS  [allowed] Nodes / A node, k8s-gpu1: connected to 10.20.1.21:22, attempt 1 from port 43124
  PASS  [policy] Nodes / A BMC, k8s-gpu1's: log line, deny-all-log (deny), zone k8s-nodes to oob, for port 43128; the client: timed out, at its connect timeout
  PASS  [routing] Nodes / Storage data: fw discards 10.20.12.31 by its route 10.0.0.0/8, before any rule
  PASS  [routing] Nodes / Storage data: silence at fw; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [allowed] Nodes / Storage management: connected to 10.20.2.31:443, attempt 1 from port 43136
  PASS  [policy] Nodes / An internet host, web-client: log line, deny-all-log (deny), zone k8s-nodes to uplink, for port 43140; the client: timed out, at its connect timeout
== Internet host: web-client (192.0.2.18), resolver ops-dns, view public-operator
  PASS  [policy] Internet host / Internal Gateway: log line, deny-all-log (deny), zone uplink to ingress, for port 43144; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / Internal Gateway: uplink-rtr routes 10.20.11.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [policy] Internet host / Users' Gateway: log line, deny-all-log (deny), zone uplink to ingress, for port 43148; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / Users' Gateway: uplink-rtr routes 10.20.11.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [policy] Internet host / Internet Gateway: log line, deny-all-log (deny), zone uplink to ingress, for port 43152; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / Internet Gateway: uplink-rtr routes 10.20.11.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [view] Internet host / Route to chat: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 198.51.100.2
  PASS  [policy] Internet host / Route to chat: log line, deny-all-log (deny), zone uplink to uplink, for port 43156; the client: timed out, at its connect timeout
  PASS  [view] Internet host / Route to staff: llm.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 198.51.100.2
  PASS  [policy] Internet host / Route to staff: log line, deny-all-log (deny), zone uplink to uplink, for port 43160; the client: timed out, at its connect timeout
  PASS  [view] Internet host / Admin hostnames: admin.ai.tarnwick.example has no answer through ops-dns (view public-operator holds no record for it); the request pinned to 198.51.100.2
  PASS  [policy] Internet host / Admin hostnames: log line, deny-all-log (deny), zone uplink to uplink, for port 43164; the client: timed out, at its connect timeout
  PASS  [policy] Internet host / API server: log line, deny-all-log (deny), zone uplink to k8s-nodes, for port 43168; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / API server: uplink-rtr routes 10.20.1.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [policy] Internet host / A node, k8s-gpu1: log line, deny-all-log (deny), zone uplink to k8s-nodes, for port 43172; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / A node, k8s-gpu1: uplink-rtr routes 10.20.1.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [policy] Internet host / A BMC, k8s-gpu1's: log line, deny-all-log (deny), zone uplink to oob, for port 43176; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / A BMC, k8s-gpu1's: uplink-rtr routes 10.20.9.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [routing] Internet host / Storage data: uplink-rtr holds no route to 10.20.12.31 (21 routes read)
  PASS  [routing] Internet host / Storage data: silence at uplink-rtr; no traffic log line names it; the client: an error, Network unreachable
  PASS  [policy] Internet host / Storage management: log line, deny-all-log (deny), zone uplink to stor-mgmt, for port 43184; the client: timed out, at its connect timeout
  PASS  [routing] Internet host / Storage management: uplink-rtr routes 10.20.2.0/24 via 198.51.100.2, so the request meets the firewall
  PASS  [allowed] Internet host / An internet host, web-client: connected to 192.0.2.18:443, attempt 1 from port 43188
== Internet users: inet-client (203.0.113.2), resolver inet-dns-res, view public-internet
  PASS  [routing] Internet users / Internal Gateway: isp-rtr holds no route to 10.20.11.200 (8 routes read)
  PASS  [routing] Internet users / Internal Gateway: silence at isp-rtr; no traffic log line names it; the client: an error, Network unreachable
  PASS  [routing] Internet users / Users' Gateway: isp-rtr holds no route to 10.20.11.210 (8 routes read)
  PASS  [routing] Internet users / Users' Gateway: silence at isp-rtr; no traffic log line names it; the client: an error, Network unreachable
  PASS  [allowed] Internet users / Internet Gateway: connected to 198.51.100.10:443 (tried at the population's answer, 198.51.100.10, which the firewall translates to 10.20.11.220), attempt 1 from port 43200
  PASS  [view] Internet users / Route to chat: llm.ai.tarnwick.example answers 198.51.100.10 through inet-dns-res (view public-internet)
  PASS  [allowed] Internet users / Route to chat: HTTP 200 from gw-inet (models-gw-inet), from port 43204
  PASS  [key] Internet users / Route to chat: with inetapp's key, the population's own caller: the API gateway's access log names caller inetapp (1 answered line(s))
  PASS  [key] Internet users / Route to chat: 401 with staff's key, `Authorization Failed`, from port 43206
  PASS  [view] Internet users / Route to staff: llm.ai.tarnwick.example answers 198.51.100.10 through inet-dns-res (view public-internet)
  PASS  [routeset] Internet users / Route to staff: 404 from gw-inet, server envoy, from port 43208
  PASS  [routeset] Internet users / Route to staff: no line for sfab-matrix-internet-staff in the API gateway's log, which holds the run's model requests
  PASS  [view] Internet users / Admin hostnames: admin.ai.tarnwick.example has no answer through inet-dns-res (view public-internet holds no record for it); the request pinned to 198.51.100.10
  PASS  [routeset] Internet users / Admin hostnames: 404 from gw-inet, server envoy, from port 43212
  PASS  [routeset] Internet users / Admin hostnames: no line for sfab-matrix-internet-admin in the API gateway's log, which holds the run's model requests
  PASS  [routing] Internet users / API server: isp-rtr holds no route to 10.20.1.10 (8 routes read)
  PASS  [routing] Internet users / API server: silence at isp-rtr; no traffic log line names it; the client: an error, Network unreachable
  PASS  [routing] Internet users / A node, k8s-gpu1: isp-rtr holds no route to 10.20.1.21 (8 routes read)
  PASS  [routing] Internet users / A node, k8s-gpu1: silence at isp-rtr; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Internet users / A BMC, k8s-gpu1's: isp-rtr holds no route to 10.20.9.21 (8 routes read)
  PASS  [routing] Internet users / A BMC, k8s-gpu1's: silence at isp-rtr; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Internet users / Storage data: isp-rtr holds no route to 10.20.12.31 (8 routes read)
  PASS  [routing] Internet users / Storage data: silence at isp-rtr; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Internet users / Storage management: isp-rtr holds no route to 10.20.2.31 (8 routes read)
  PASS  [routing] Internet users / Storage management: silence at isp-rtr; no traffic log line names it; the client: timed out, at its connect timeout
  PASS  [routing] Internet users / An internet host, web-client: isp-rtr holds no route to 192.0.2.18 (8 routes read)
  PASS  [routing] Internet users / An internet host, web-client: silence at isp-rtr; no traffic log line names it; the client: timed out, at its connect timeout
== the matrix
  PASS  60 of 60 cells in their mode (20 allowed, 21 log lines, 3 404, 16 silent)
  PASS  the cells' isolation depth as the render computes it: depth 1 25, depth 2 14, depth 3 1 (and 20 allowed at depth 0)
```

## Files

- `verdict.txt`, `commands.txt`, `matrix.json` (the plan), `requests.tsv` (one line an attempt)
- `lookups/`: each client's lookup of the names it asks for, through its own resolver
- `requests/`: each attempt as the client saw it, and each answer's headers and body; no request header is saved
- `fw/`: the traffic log read for the refused cells; `routers/`: the routing table of each router in front of the firewall
- `api-gateway/access.txt`: the API gateway pods' access log over the run
