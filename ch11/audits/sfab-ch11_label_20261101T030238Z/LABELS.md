# Decision labels

- Lab: `sfab-ch11`; labs repo commit `86a59ddfea6f405c4d6d70af509ef75a856ac3a8`; UTC 2026-11-01T03:02:38Z
- The live object behind each of the decision table's 7 rows, and the switches, which implement none, each with the decision id it carries

| Row | Live object | Decision | Evidence |
|---|---|---|---|
| Resolver view | ent-client's lookup: view enterprise answers llm.ai.tarnwick.example 10.20.11.210 | `dec-view-enterprise` | `view/enterprise-lookup.txt:14` |
| Resolver view | ops-client's lookup: view public-operator answers llm.ai.tarnwick.example NXDOMAIN | `dec-view-public` | `view/operator-lookup.txt:5` |
| Resolver view | k8s-cp2's lookup: view internal answers llm.ai.tarnwick.example 10.20.11.200 | `dec-view-internal` | `view/nodes-lookup.txt:1` |
| Resolver view | web-client's lookup: view public-operator answers llm.ai.tarnwick.example NXDOMAIN | `dec-view-public` | `view/web-lookup.txt:5` |
| Resolver view | inet-client's lookup: view public-internet answers llm.ai.tarnwick.example 198.51.100.10 | `dec-view-public` | `view/internet-lookup.txt:15` |
| Resolver view | dns-auth1's zone file db.internal.ai.tarnwick.example, the entry for llm.ai.tarnwick.example | `dec-view-internal` | `view/dns-auth1-db.internal.ai.tarnwick.example.txt:28` |
| Resolver view | dns-auth1's zone file db.enterprise.ai.tarnwick.example, the entry for llm.ai.tarnwick.example | `dec-view-enterprise` | `view/dns-auth1-db.enterprise.ai.tarnwick.example.txt:15` |
| Resolver view | ops-dns's zone file db.public-operator.ai.tarnwick.example, no entry for llm.ai.tarnwick.example | `dec-view-public` | `view/ops-dns-db.public-operator.ai.tarnwick.example.txt:2` |
| Resolver view | inet-dns-auth's zone file db.public-internet.ai.tarnwick.example, the entry for llm.ai.tarnwick.example | `dec-view-public` | `view/inet-dns-auth-db.public-internet.ai.tarnwick.example.txt:13` |
| Routing | fw's route 10.20.1.0/24 connected on ae1.100 | `dec-route-connected-ae1-100` | `fw/routing-route.txt:11` |
| Routing | fw's route 10.20.11.0/24 connected on ae1.110 | `dec-route-connected-ae1-110` | `fw/routing-route.txt:19` |
| Routing | fw's route 10.20.2.0/24 connected on ae1.200 | `dec-route-connected-ae1-200` | `fw/routing-route.txt:13` |
| Routing | fw's route 10.20.3.0/24 connected on ae1.300 | `dec-route-connected-ae1-300` | `fw/routing-route.txt:15` |
| Routing | fw's route 10.20.13.0/24 connected on ae1.130 | `dec-route-connected-ae1-130` | `fw/routing-route.txt:21` |
| Routing | fw's route 10.20.14.0/24 connected on ae1.131 | `dec-route-connected-ae1-131` | `fw/routing-route.txt:23` |
| Routing | fw's route 10.20.9.0/24 connected on ethernet1/3 | `dec-route-connected-ethernet1-3` | `fw/routing-route.txt:17` |
| Routing | fw's route 10.24.10.8/30 connected on ethernet1/4 | `dec-route-connected-ethernet1-4` | `fw/routing-route.txt:25` |
| Routing | fw's route 10.24.10.52/30 connected on ethernet1/7 | `dec-route-connected-ethernet1-7` | `fw/routing-route.txt:27` |
| Routing | fw's route 198.51.100.0/29 connected on ethernet1/5 | `dec-route-connected-ethernet1-5` | `fw/routing-route.txt:32` |
| Routing | fw's route 198.51.100.8/30 connected on ethernet1/6 | `dec-route-connected-ethernet1-6` | `fw/routing-route.txt:34` |
| Routing | fw's route 0.0.0.0/0 via 198.51.100.1 on ethernet1/5 | `dec-route-default-uplink` | `fw/routing-route.txt:9` |
| Routing | fw's route 192.0.2.0/30 via None on tunnel.1 | `dec-route-operator-site` | `fw/routing-route.txt:30` |
| Routing | fw's route 203.0.113.0/26 via 198.51.100.9 on ethernet1/6 | `dec-route-isp-customers` | `fw/routing-route.txt:36` |
| Routing | fw's route 10.0.0.0/8 via None on None | `dec-route-discard-10` | `fw/routing-route.txt:10` |
| Routing | fw's route 172.16.0.0/12 via None on None | `dec-route-discard-172-16` | `fw/routing-route.txt:29` |
| Routing | fw's route 192.168.0.0/16 via None on None | `dec-route-discard-192-168` | `fw/routing-route.txt:31` |
| Routing | uplink-rtr's static route 192.0.2.0/30 via 192.0.2.22 | `dec-route-operator-site` | `routing/uplink-rtr-frr.conf:9` |
| Routing | uplink-rtr's static route 10.20.1.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:11` |
| Routing | uplink-rtr's static route 10.20.11.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:13` |
| Routing | uplink-rtr's static route 10.20.2.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:15` |
| Routing | uplink-rtr's static route 10.20.3.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:17` |
| Routing | uplink-rtr's static route 10.20.13.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:19` |
| Routing | uplink-rtr's static route 10.20.14.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:21` |
| Routing | uplink-rtr's static route 10.20.9.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:23` |
| Routing | uplink-rtr's static route 10.24.10.0/24 via 198.51.100.2 | `dec-route-inside-via-fw` | `routing/uplink-rtr-frr.conf:25` |
| NAT | nat rule dnat-internet-gateway | `dec-nat-internet` | `fw/running-nat-policy.txt:3` |
| NAT | nat rule no-nat-public | `dec-nat-no-land` | `fw/running-nat-policy.txt:17` |
| NAT | nat rule internet-snat | `dec-nat-internet-snat` | `fw/running-nat-policy.txt:30` |
| Security policy | security rule staff-to-users-gateway | `dec-policy-enterprise-users` | `fw/running-security-policy.txt:2` |
| Security policy | security rule ent-dns-to-platform-dns | `dec-policy-ent-dns-to-platform-dns` | `fw/running-security-policy.txt:21` |
| Security policy | security rule staff-to-enterprise-dns | `dec-policy-staff-to-enterprise-dns` | `fw/running-security-policy.txt:40` |
| Security policy | security rule admins-to-bastion | `dec-policy-admins-to-bastion` | `fw/running-security-policy.txt:59` |
| Security policy | security rule bastion-to-firewall-admin | `dec-policy-bastion-to-firewall-admin` | `fw/running-security-policy.txt:78` |
| Security policy | security rule bastion-to-nodes | `dec-policy-bastion-to-nodes` | `fw/running-security-policy.txt:97` |
| Security policy | security rule bastion-to-api | `dec-policy-bastion-to-api` | `fw/running-security-policy.txt:116` |
| Security policy | security rule bastion-to-internal-gateway | `dec-policy-bastion-to-internal-gateway` | `fw/running-security-policy.txt:135` |
| Security policy | security rule bastion-to-stor-mgmt | `dec-policy-bastion-to-stor-mgmt` | `fw/running-security-policy.txt:154` |
| Security policy | security rule bastion-to-bmc | `dec-policy-bastion-to-bmc` | `fw/running-security-policy.txt:173` |
| Security policy | security rule bastion-to-services-admin | `dec-policy-bastion-to-services-admin` | `fw/running-security-policy.txt:192` |
| Security policy | security rule inside-to-gateway-ping | `dec-policy-inside-to-gateway-ping` | `fw/running-security-policy.txt:211` |
| Security policy | security rule inside-to-resolvers | `dec-policy-inside-to-resolvers` | `fw/running-security-policy.txt:230` |
| Security policy | security rule inside-to-ntp | `dec-policy-inside-to-ntp` | `fw/running-security-policy.txt:249` |
| Security policy | security rule resolvers-to-auth | `dec-policy-resolvers-to-auth` | `fw/running-security-policy.txt:268` |
| Security policy | security rule auth-zone-transfer | `dec-policy-auth-zone-transfer` | `fw/running-security-policy.txt:287` |
| Security policy | security rule ntp-upstream | `dec-policy-ntp-upstream` | `fw/running-security-policy.txt:306` |
| Security policy | security rule nts-ke-upstream | `dec-policy-nts-ke-upstream` | `fw/running-security-policy.txt:325` |
| Security policy | security rule nodes-to-registry | `dec-policy-nodes-to-registry` | `fw/running-security-policy.txt:344` |
| Security policy | security rule nodes-to-internal-gateway | `dec-policy-nodes-to-internal-gateway` | `fw/running-security-policy.txt:363` |
| Security policy | security rule csi-to-storage-api | `dec-policy-csi-to-storage-api` | `fw/running-security-policy.txt:382` |
| Security policy | security rule operator-ike | `dec-policy-operator-ike` | `fw/running-security-policy.txt:401` |
| Security policy | security rule operator-to-internal-gateway | `dec-policy-operator-vpn` | `fw/running-security-policy.txt:420` |
| Security policy | security rule isp-to-internet-gateway | `dec-nat-internet` | `fw/running-security-policy.txt:439` |
| Security policy | security rule deny-all-log | `dec-policy-deny-all-log` | `fw/running-security-policy.txt:458` |
| Route set | HTTPRoute inference/models-gw-internal on gw-internal | `dec-routeset-internal` | `routeset/httproutes.txt:8` |
| Route set | HTTPRoute inference/models-gw-users on gw-users | `dec-routeset-enterprise` | `routeset/httproutes.txt:9` |
| Route set | HTTPRoute inference/models-gw-inet on gw-inet | `dec-routeset-internet` | `routeset/httproutes.txt:7` |
| Route set | HTTPRoute serving/serving on gw-internal | `dec-routeset-internal` | `routeset/httproutes.txt:10` |
| Route set | HTTPRoute echo/echo-gw-internal on gw-internal | `dec-routeset-internal` | `routeset/httproutes.txt:3` |
| Route set | HTTPRoute echo/echo-gw-users on gw-users | `dec-routeset-enterprise` | `routeset/httproutes.txt:4` |
| Route set | HTTPRoute echo/echo-gw-inet on gw-inet | `dec-routeset-internet` | `routeset/httproutes.txt:2` |
| Caller | consumer group batch in api-gateway-routes | `dec-key-batch` | `key/api-gateway-routes.yaml:126` |
| Caller | consumer group helpdesk in api-gateway-routes | `dec-key-helpdesk` | `key/api-gateway-routes.yaml:136` |
| Caller | consumer group inetapp in api-gateway-routes | `dec-key-inetapp` | `key/api-gateway-routes.yaml:156` |
| Caller | consumer group staff in api-gateway-routes | `dec-key-staff` | `key/api-gateway-routes.yaml:146` |
| Placement | copy chat-a's row of the placement table | `dec-place-chat` | `placement/serving.env:31` |
| Placement | copy chat-b's row of the placement table | `dec-place-chat` | `placement/serving.env:33` |
| Placement | copy chat-c's row of the placement table | `dec-place-chat` | `placement/serving.env:35` |
| Placement | copy staff-a's row of the placement table | `dec-place-staff` | `placement/serving.env:38` |
| Placement | copy staff-b's row of the placement table | `dec-place-staff` | `placement/serving.env:40` |
| Placement | rail attachment rail3 | `dec-place-chat` | `placement/nads.json` |
| Placement | rail attachment rail4 | `dec-place-staff` | `placement/nads.json` |
| Placement | rail attachment rail5 | `dec-place-staff` | `placement/nads.json` |
| Placement | rail attachment rail6 | `dec-place-chat` | `placement/nads.json` |
| Placement | rail attachment rail7 | `dec-place-chat` | `placement/nads.json` |
| forwarding only | fe-sw1's startup file | `dec-forwarding-only` | `forwarding/fe-sw1-startup.txt:2` |
| forwarding only | fe-sw2's startup file | `dec-forwarding-only` | `forwarding/fe-sw2-startup.txt:2` |
| forwarding only | rail-sw1's startup file | `dec-forwarding-only` | `forwarding/rail-sw1-startup.txt:2` |
| forwarding only | rail-sw2's startup file | `dec-forwarding-only` | `forwarding/rail-sw2-startup.txt:2` |
| forwarding only | oob-sw's startup file | `dec-forwarding-only` | `forwarding/oob-sw-startup.txt:2` |

## Verdict

```
== the decision table: 7 rows, the live object behind each
== Resolver view (resolver): which address a population gets for a name
  PASS  [view] enterprise (ent-client): llm.ai.tarnwick.example answers 10.20.11.210 through 10.24.10.53, view enterprise
  PASS  [view] operator (ops-client): llm.ai.tarnwick.example answers NXDOMAIN through 192.0.2.10, view public-operator
  PASS  [view] nodes (k8s-cp2): llm.ai.tarnwick.example answers 10.20.11.200 through 10.20.13.21, view internal
  PASS  [view] web (web-client): llm.ai.tarnwick.example answers NXDOMAIN through 192.0.2.10, view public-operator
  PASS  [view] internet (inet-client): llm.ai.tarnwick.example answers 198.51.100.10 through 203.0.113.10, view public-internet
  PASS  [view] dns-auth1, view internal: the zone file's entry for llm.ai.tarnwick.example carries decision dec-view-internal
  PASS  [view] dns-auth1, view enterprise: the zone file's entry for llm.ai.tarnwick.example carries decision dec-view-enterprise
  PASS  [view] ops-dns, view public-operator: the zone file is labelled dec-view-public and holds no entry for llm.ai.tarnwick.example
  PASS  [view] inet-dns-auth, view public-internet: the zone file's entry for llm.ai.tarnwick.example carries decision dec-view-public
== Routing (firewall, and the routers in front of it): whether a route to the destination exists, looked up on ingress
  PASS  [routing] fw: 10.20.1.0/24 connected on ae1.100 (dec-route-connected-ae1-100, in the decision table only)
  PASS  [routing] fw: 10.20.11.0/24 connected on ae1.110 (dec-route-connected-ae1-110, in the decision table only)
  PASS  [routing] fw: 10.20.2.0/24 connected on ae1.200 (dec-route-connected-ae1-200, in the decision table only)
  PASS  [routing] fw: 10.20.3.0/24 connected on ae1.300 (dec-route-connected-ae1-300, in the decision table only)
  PASS  [routing] fw: 10.20.13.0/24 connected on ae1.130 (dec-route-connected-ae1-130, in the decision table only)
  PASS  [routing] fw: 10.20.14.0/24 connected on ae1.131 (dec-route-connected-ae1-131, in the decision table only)
  PASS  [routing] fw: 10.20.9.0/24 connected on ethernet1/3 (dec-route-connected-ethernet1-3, in the decision table only)
  PASS  [routing] fw: 10.24.10.8/30 connected on ethernet1/4 (dec-route-connected-ethernet1-4, in the decision table only)
  PASS  [routing] fw: 10.24.10.52/30 connected on ethernet1/7 (dec-route-connected-ethernet1-7, in the decision table only)
  PASS  [routing] fw: 198.51.100.0/29 connected on ethernet1/5 (dec-route-connected-ethernet1-5, in the decision table only)
  PASS  [routing] fw: 198.51.100.8/30 connected on ethernet1/6 (dec-route-connected-ethernet1-6, in the decision table only)
  PASS  [routing] fw: 0.0.0.0/0 via 198.51.100.1 on ethernet1/5 (dec-route-default-uplink, in the decision table only)
  PASS  [routing] fw: 192.0.2.0/30 via None on tunnel.1 (dec-route-operator-site, in the decision table only)
  PASS  [routing] fw: 203.0.113.0/26 via 198.51.100.9 on ethernet1/6 (dec-route-isp-customers, in the decision table only)
  PASS  [routing] fw: 10.0.0.0/8 via None on None (dec-route-discard-10, in the decision table only)
  PASS  [routing] fw: 172.16.0.0/12 via None on None (dec-route-discard-172-16, in the decision table only)
  PASS  [routing] fw: 192.168.0.0/16 via None on None (dec-route-discard-192-168, in the decision table only)
  PASS  [routing] uplink-rtr: 192.0.2.0/30 via 192.0.2.22 (operator-site), labelled dec-route-operator-site
  PASS  [routing] uplink-rtr: 10.20.1.0/24 via 198.51.100.2 (inside-nodes), labelled dec-route-inside-via-fw
  PASS  [routing] uplink-rtr: 10.20.11.0/24 via 198.51.100.2 (inside-ingress), labelled dec-route-inside-via-fw
  PASS  [routing] uplink-rtr: 10.20.2.0/24 via 198.51.100.2 (inside-stor-mgmt), labelled dec-route-inside-via-fw
  PASS  [routing] uplink-rtr: 10.20.3.0/24 via 198.51.100.2 (inside-bastion), labelled dec-route-inside-via-fw
  PASS  [routing] uplink-rtr: 10.20.13.0/24 via 198.51.100.2 (inside-services-a), labelled dec-route-inside-via-fw
  PASS  [routing] uplink-rtr: 10.20.14.0/24 via 198.51.100.2 (inside-services-b), labelled dec-route-inside-via-fw
  PASS  [routing] uplink-rtr: 10.20.9.0/24 via 198.51.100.2 (inside-oob), labelled dec-route-inside-via-fw
  PASS  [routing] uplink-rtr: 10.24.10.0/24 via 198.51.100.2 (inside-enterprise), labelled dec-route-inside-via-fw
== NAT (firewall): which address a request leaves or lands with, keyed on the pre-nat zone
  PASS  [nat] the running nat rulebase in the rendered order (3 rules)
  PASS  [nat] dnat-internet-gateway: description dec-nat-internet
  PASS  [nat] no-nat-public: description dec-nat-no-land
  PASS  [nat] internet-snat: description dec-nat-internet-snat
== Security policy (firewall): allow or deny, and log, on the original addresses and the post-nat zone
  PASS  [policy] the running security rulebase in the rendered order (25 rules)
  PASS  [policy] staff-to-users-gateway: description dec-policy-enterprise-users
  PASS  [policy] ent-dns-to-platform-dns: description dec-policy-ent-dns-to-platform-dns
  PASS  [policy] staff-to-enterprise-dns: description dec-policy-staff-to-enterprise-dns
  PASS  [policy] admins-to-bastion: description dec-policy-admins-to-bastion
  PASS  [policy] bastion-to-firewall-admin: description dec-policy-bastion-to-firewall-admin
  PASS  [policy] bastion-to-nodes: description dec-policy-bastion-to-nodes
  PASS  [policy] bastion-to-api: description dec-policy-bastion-to-api
  PASS  [policy] bastion-to-internal-gateway: description dec-policy-bastion-to-internal-gateway
  PASS  [policy] bastion-to-stor-mgmt: description dec-policy-bastion-to-stor-mgmt
  PASS  [policy] bastion-to-bmc: description dec-policy-bastion-to-bmc
  PASS  [policy] bastion-to-services-admin: description dec-policy-bastion-to-services-admin
  PASS  [policy] inside-to-gateway-ping: description dec-policy-inside-to-gateway-ping
  PASS  [policy] inside-to-resolvers: description dec-policy-inside-to-resolvers
  PASS  [policy] inside-to-ntp: description dec-policy-inside-to-ntp
  PASS  [policy] resolvers-to-auth: description dec-policy-resolvers-to-auth
  PASS  [policy] auth-zone-transfer: description dec-policy-auth-zone-transfer
  PASS  [policy] ntp-upstream: description dec-policy-ntp-upstream
  PASS  [policy] nts-ke-upstream: description dec-policy-nts-ke-upstream
  PASS  [policy] nodes-to-registry: description dec-policy-nodes-to-registry
  PASS  [policy] nodes-to-internal-gateway: description dec-policy-nodes-to-internal-gateway
  PASS  [policy] csi-to-storage-api: description dec-policy-csi-to-storage-api
  PASS  [policy] operator-ike: description dec-policy-operator-ike
  PASS  [policy] operator-to-internal-gateway: description dec-policy-operator-vpn
  PASS  [policy] isp-to-internet-gateway: description dec-nat-internet
  PASS  [policy] deny-all-log: description dec-policy-deny-all-log
  PASS  [policy] the rulebase closes with deny-all-log
== Route set (Gateway): whether a hostname and path exist for the audience behind that gateway
  PASS  [routeset] HTTPRoute inference/models-gw-internal on gw-internal: label decision.tarnwick.example/id=dec-routeset-internal
  PASS  [routeset] HTTPRoute inference/models-gw-users on gw-users: label decision.tarnwick.example/id=dec-routeset-enterprise
  PASS  [routeset] HTTPRoute inference/models-gw-inet on gw-inet: label decision.tarnwick.example/id=dec-routeset-internet
  PASS  [routeset] HTTPRoute serving/serving on gw-internal: label decision.tarnwick.example/id=dec-routeset-internal
  PASS  [routeset] HTTPRoute echo/echo-gw-internal on gw-internal: label decision.tarnwick.example/id=dec-routeset-internal
  PASS  [routeset] HTTPRoute echo/echo-gw-users on gw-users: label decision.tarnwick.example/id=dec-routeset-enterprise
  PASS  [routeset] HTTPRoute echo/echo-gw-inet on gw-inet: label decision.tarnwick.example/id=dec-routeset-internet
== Caller (API gateway): whether the caller may use the model
  PASS  [key] consumer group batch: desc labelled dec-key-batch
  PASS  [key] consumer group batch: its consumer composed in api-gateway-7dc68d586f-g7kz8 (batch.4bba878c sha256:1df7a5c7ea0d)
  PASS  [key] consumer group helpdesk: desc labelled dec-key-helpdesk
  PASS  [key] consumer group helpdesk: its consumer composed in api-gateway-7dc68d586f-g7kz8 (helpdesk.77a33a1c sha256:ba11730bec62)
  PASS  [key] consumer group inetapp: desc labelled dec-key-inetapp
  PASS  [key] consumer group inetapp: its consumer composed in api-gateway-7dc68d586f-g7kz8 (inetapp.366eb68e sha256:77069427f66d)
  PASS  [key] consumer group staff: desc labelled dec-key-staff
  PASS  [key] consumer group staff: its consumer staff_ent_client in the routes (key/api-gateway-routes.yaml:166)
== Placement (cluster): which rail a replica's workers answer from
  PASS  [placement] copy chat-a: 2 pods labelled dec-place-chat
  PASS  [placement] copy chat-b: 2 pods labelled dec-place-chat
  PASS  [placement] copy chat-c: 3 pods labelled dec-place-chat
  PASS  [placement] copy staff-a: 2 pods labelled dec-place-staff
  PASS  [placement] copy staff-b: 2 pods labelled dec-place-staff
  PASS  [placement] rail attachment rail3: annotation decision.tarnwick.example/id=dec-place-chat
  PASS  [placement] rail attachment rail4: annotation decision.tarnwick.example/id=dec-place-staff
  PASS  [placement] rail attachment rail5: annotation decision.tarnwick.example/id=dec-place-staff
  PASS  [placement] rail attachment rail6: annotation decision.tarnwick.example/id=dec-place-chat
  PASS  [placement] rail attachment rail7: annotation decision.tarnwick.example/id=dec-place-chat
== the switches: forwarding only, no row
  PASS  [forwarding] fe-sw1: its startup file labelled dec-forwarding-only
  PASS  [forwarding] fe-sw1: show ip route prints nothing
  PASS  [forwarding] fe-sw2: its startup file labelled dec-forwarding-only
  PASS  [forwarding] fe-sw2: show ip route prints nothing
  PASS  [forwarding] rail-sw1: its startup file labelled dec-forwarding-only
  PASS  [forwarding] rail-sw1: show ip route prints nothing
  PASS  [forwarding] rail-sw2: its startup file labelled dec-forwarding-only
  PASS  [forwarding] rail-sw2: show ip route prints nothing
  PASS  [forwarding] oob-sw: its startup file labelled dec-forwarding-only
  PASS  [forwarding] oob-sw: show ip route prints nothing
```
