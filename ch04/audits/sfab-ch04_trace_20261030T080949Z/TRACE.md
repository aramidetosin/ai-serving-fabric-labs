# Firewall trace

- Lab: `sfab-ch04`; labs repo commit `ad2f14ffba532ff5d8be0be16301f9fbc625f55f` (with uncommitted changes); UTC 2026-10-30T08:09:49Z
- Firewall `fw`, public address 198.51.100.2; 2 sessions, one image pull at 3 capture points

## Sessions

| Session | Client | To | Translated to | Rule expected | NAT rule expected | Hold (s) |
|---|---|---|---|---|---|---|
| `enterprise` | ent-client 10.24.10.10[42443] | 10.20.11.210:443 | none | `staff-to-users-gateway` | none | 30 |
| `operator` | ops-client 192.0.2.2[42444] | 10.20.11.200:443 | none | `operator-to-internal-gateway` | none | 30 |

## Verdict

```
== session enterprise: ent-client (10.24.10.10) to https://llm.ai.tarnwick.example/echo?msg=sfab-ch04-enterprise at 10.20.11.210:443
  PASS  the reply: HTTP 200 with the echoed message sfab-ch04-enterprise
  PASS  the connection held 30 s after the reply, so the session table still lists it
  PASS  show session all lists it: 10.24.10.10[42443] to 10.20.11.210[443] (id 1197)
  PASS  ... zone enterprise to zone ingress, state ACTIVE
  PASS  ... destination after translation 10.20.11.210 (none), source unchanged 10.24.10.10
  PASS  show session id names the security rule staff-to-users-gateway
  PASS  ... and no NAT rule
  PASS  the traffic log line: staff-to-users-gateway (shown as staff-to-users-gate), allow, zone enterprise to zone ingress, the pre-NAT destination 10.20.11.210
== session operator: ops-client (192.0.2.2) to https://llm.ai.tarnwick.example/echo?msg=sfab-ch04-operator at 10.20.11.200:443
  PASS  the reply: HTTP 200 with the echoed message sfab-ch04-operator
  PASS  the connection held 30 s after the reply, so the session table still lists it
  PASS  show session all lists it: 192.0.2.2[42444] to 10.20.11.200[443] (id 1225)
  PASS  ... zone operator-vpn to zone ingress, state ACTIVE
  PASS  ... destination after translation 10.20.11.200 (none), source unchanged 192.0.2.2
  PASS  show session id names the security rule operator-to-internal-gateway
  PASS  ... and no NAT rule
  PASS  the traffic log line: operator-to-internal-gateway (shown as operator-to-interna), allow, zone operator-vpn to zone ingress, the pre-NAT destination 10.20.11.200
== pull: k8s-gpu2 (10.20.1.22) pulls docker.io/alpine/helm@sha256:e29ba4b553fa9648d0a35a9e29c8744c597a3e400d5574daf0f20a4c3854b852 from the registry 192.0.2.6:5000
  PASS  crictl pulled it through k8s-gpu2's CRI
  PASS  the node's first SYN to 192.0.2.6:5000 seen inside, from 10.20.1.22 at 1-fw-ae1-leg2 (seq 1286421902, source port 51508)
  PASS  ... tagged 100
  PASS  the same SYN (seq 1286421902) seen on the uplink at 2-fw-ethernet1-5
  PASS  ... its source rewritten to 198.51.100.2 (port 51508 became 12232), its destination 192.0.2.6:5000 unchanged
  PASS  the registry's replies: 5847268 bytes to 198.51.100.2 on the uplink, 7452268 bytes to 10.20.1.22 inside (IP lengths summed over the captures, snaplen 256)
  PASS  the traffic log has the pull's session (source port 51508) under nodes-to-registry, allow, zone k8s-nodes to zone uplink
  PASS  the image removed from k8s-gpu2 again, so the next trace pulls it whole (time="2026-10-30T08:12:59Z" level=warning msg="Config \"/etc/crictl.yaml\" does ; not judged)
```

## Session enterprise

show session all, the session's row (`sessions/enterprise/session-all.txt:6`)

```
1197         ssl            ACTIVE  FLOW       10.24.10.10[42443]/enterprise/6  (10.24.10.10[42443])
vsys1                                          10.20.11.210[443]/ingress  (10.20.11.210[443])
```

show session id (`sessions/enterprise/session-detail.txt:4`)

```
        c2s flow:
                source:      10.24.10.10 [enterprise]
                dst:         10.20.11.210
                proto:       6
                sport:       42443           dport:      443
                state:       ACTIVE          type:       FLOW
                src user:    unknown
                dst user:    unknown

        s2c flow:
                source:      10.20.11.210 [ingress]
                dst:         10.24.10.10
                proto:       6
                sport:       443             dport:      42443
                state:       ACTIVE          type:       FLOW
                src user:    unknown
                dst user:    unknown

        start time                           : Fri Oct 30 08:09:49 2026
        timeout                              : 1800 sec
        time to live                         : 1778 sec
        total byte count(c2s)                : 1372
        total byte count(s2c)                : 4334
        layer7 packet count(c2s)             : 9
        layer7 packet count(s2c)             : 15
        vsys                                 : vsys1
        application                          : ssl
        rule                                 : staff-to-users-gateway
        service timeout override(index)      : False
        session is promoted                  : False
        session to be logged at end          : True
        session in session ager              : True
        session updated by HA peer           : False
        layer7 processing                    : completed
        URL filtering enabled                : False
        session via syn-cookies              : False
        session terminated on host           : False
        session traverses tunnel             : False
        session terminate tunnel             : False
        captive portal session               : False
```

the traffic log (`sessions/enterprise/traffic-log.txt:6`)

```
2026/10/30 08:10:33 ssl             enterprise                      42443             10.24.10.10
staff-to-users-gate allow           ingress                         443               10.20.11.210
                                                tcp-rst-from-client
277fd6ab-0280-4c23-b355-12c89409a659
```

## Session operator

show session all, the session's row (`sessions/operator/session-all.txt:6`)

```
1225         ssl            ACTIVE  FLOW       192.0.2.2[42444]/operator-vpn/6  (192.0.2.2[42444])
vsys1                                          10.20.11.200[443]/ingress  (10.20.11.200[443])
```

show session id (`sessions/operator/session-detail.txt:4`)

```
        c2s flow:
                source:      192.0.2.2 [operator-vpn]
                dst:         10.20.11.200
                proto:       6
                sport:       42444           dport:      443
                state:       ACTIVE          type:       FLOW
                src user:    unknown
                dst user:    unknown

        s2c flow:
                source:      10.20.11.200 [ingress]
                dst:         192.0.2.2
                proto:       6
                sport:       443             dport:      42444
                state:       ACTIVE          type:       FLOW
                src user:    unknown
                dst user:    unknown

        start time                           : Fri Oct 30 08:10:52 2026
        timeout                              : 1800 sec
        time to live                         : 1779 sec
        total byte count(c2s)                : 1292
        total byte count(s2c)                : 2465
        layer7 packet count(c2s)             : 8
        layer7 packet count(s2c)             : 7
        vsys                                 : vsys1
        application                          : ssl
        rule                                 : operator-to-internal-gateway
        service timeout override(index)      : False
        session is promoted                  : False
        session to be logged at end          : True
        session in session ager              : True
        session updated by HA peer           : False
        layer7 processing                    : enabled
        ctd version                          : 1
        URL filtering enabled                : False
        session via syn-cookies              : False
        session terminated on host           : False
        session traverses tunnel             : True
        session terminate tunnel             : False
```

the traffic log (`sessions/operator/traffic-log.txt:6`)

```
2026/10/30 08:11:37 ssl             operator-vpn                    42444             192.0.2.2
operator-to-interna allow           ingress                         443               10.20.11.200
                                                tcp-rst-from-client
5188b751-e22a-419c-a9e9-ce21d9b02ad2
```

## The image pull

| Point | Side | Frames |
|---|---|---|
| `1-fw-ae1-leg1` | inside | 5000 |
| `1-fw-ae1-leg2` | inside | 5000 |
| `2-fw-ethernet1-5` | outside | 5000 |

- `1-fw-ae1-leg2` (`pull/captures/1-fw-ae1-leg2.txt:2`)

  ```
  2026-10-30 08:11:59.984816 02:5a:70:00:00:01 > ba:db:ee:fb:ad:f0, ethertype 802.1Q (0x8100), length 78: vlan 100, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 64, id 34580, offset 0, flags [DF], proto TCP (6), length 60)
  ```

- `2-fw-ethernet1-5` (`pull/captures/2-fw-ethernet1-5.txt:2`)

  ```
  2026-10-30 08:11:59.985408 aa:c1:ab:3d:2c:5d > aa:c1:ab:f4:0e:b5, ethertype IPv4 (0x0800), length 74: (tos 0x0, ttl 63, id 34580, offset 0, flags [DF], proto TCP (6), length 60)
  ```

## Files

- `verdict.txt`, `commands.txt`; per session `sessions/<id>/`: `request.txt`, `session-all.txt` and `.xml`, `session-detail.txt` and `.xml`, `traffic-log.txt`
- `pull/`: `pull.txt`, `rmi.txt`, `points.tsv`, `traffic-log.txt`, `captures/<point>.pcap` and `.txt` (decoded with `tcpdump -nn -e -tttt -v -S -r`); each point keeps the pull's first 5000 frames on the registry's port (`tcpdump -c`), so the frame counts and the reply bytes are of those frames

== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 0 skipped
