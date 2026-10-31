# Gateway drills

- Lab: `sfab-ch07`; labs repo commit `ad2f14ffba532ff5d8be0be16301f9fbc625f55f` (with uncommitted changes); UTC 2026-10-30T13:22:24Z

## key-lifecycle: one key for chat from mint to revoke under the gateway probe, at every API gateway pod and through the users' VIP

### pass1

- accepted: `{"api-gateway-64bc7b94df-7b74q": 69.7, "api-gateway-64bc7b94df-hm4sq": 48.5}`
- cross: `"staff"`
- field: `"batch.fd000001"`
- first_vip: `52.1`
- last_pod: `69.7`
- last_vip_200: `54.4`
- model: `"chat"`
- probe: `[{"failed": 0, "model": "chat", "sent": 90}, {"failed": 0, "model": "staff", "sent": 6}]`
- refused: `{"api-gateway-64bc7b94df-7b74q": 57.4, "api-gateway-64bc7b94df-hm4sq": 45.3}`
- vip_401_between: `5`

### pass2

- accepted: `{"api-gateway-64bc7b94df-7b74q": 32.4, "api-gateway-64bc7b94df-hm4sq": 71.7}`
- cross: `"staff"`
- field: `"batch.fd000002"`
- first_vip: `34.2`
- last_pod: `71.7`
- last_vip_200: `75.5`
- model: `"chat"`
- probe: `[{"failed": 0, "model": "chat", "sent": 101}, {"failed": 0, "model": "staff", "sent": 7}]`
- refused: `{"api-gateway-64bc7b94df-7b74q": 78.9, "api-gateway-64bc7b94df-hm4sq": 65.3}`
- vip_401_between: `9`

### pass3

- accepted: `{"api-gateway-64bc7b94df-7b74q": 23.4, "api-gateway-64bc7b94df-hm4sq": 58.4}`
- cross: `"staff"`
- field: `"batch.fd000003"`
- first_vip: `26.2`
- last_pod: `58.4`
- last_vip_200: `43.2`
- model: `"chat"`
- probe: `[{"failed": 0, "model": "chat", "sent": 77}, {"failed": 0, "model": "staff", "sent": 6}]`
- refused: `{"api-gateway-64bc7b94df-7b74q": 15.1, "api-gateway-64bc7b94df-hm4sq": 44.8}`
- vip_401_between: `9`


## rejected-code: staff's route without its rejected code, a chat key answered with the plugin's default, then the rendered 401

### pass1

- default: `{"api-gateway-64bc7b94df-7b74q": {"after_s": 56.4, "message": "The consumer_group_id is forbidden."}, "api-gateway-64bc7b94df-hm4sq": {"after_s": 51.4, "message": "The consumer_group_id is forbidden."}}`
- key_model: `"chat"`
- model: `"staff"`
- probe: `[{"failed": 0, "model": "chat", "sent": 103}, {"failed": 0, "model": "staff", "sent": 7}]`
- rendered: `{"api-gateway-64bc7b94df-7b74q": {"after_s": 71.3, "message": "Authorization Failed"}, "api-gateway-64bc7b94df-hm4sq": {"after_s": 74.3, "message": "Authorization Failed"}}`

### pass2

- default: `{"api-gateway-64bc7b94df-7b74q": {"after_s": 26.4, "message": "The consumer_group_id is forbidden."}, "api-gateway-64bc7b94df-hm4sq": {"after_s": 32.4, "message": "The consumer_group_id is forbidden."}}`
- key_model: `"chat"`
- model: `"staff"`
- probe: `[{"failed": 0, "model": "chat", "sent": 88}, {"failed": 0, "model": "staff", "sent": 6}]`
- rendered: `{"api-gateway-64bc7b94df-7b74q": {"after_s": 66.4, "message": "Authorization Failed"}, "api-gateway-64bc7b94df-hm4sq": {"after_s": 76.4, "message": "Authorization Failed"}}`

### pass3

- default: `{"api-gateway-64bc7b94df-7b74q": {"after_s": 25.4, "message": "The consumer_group_id is forbidden."}, "api-gateway-64bc7b94df-hm4sq": {"after_s": 34.4, "message": "The consumer_group_id is forbidden."}}`
- key_model: `"chat"`
- model: `"staff"`
- probe: `[{"failed": 0, "model": "chat", "sent": 82}, {"failed": 0, "model": "staff", "sent": 6}]`
- rendered: `{"api-gateway-64bc7b94df-7b74q": {"after_s": 72.5, "message": "Authorization Failed"}, "api-gateway-64bc7b94df-hm4sq": {"after_s": 57.5, "message": "Authorization Failed"}}`


## idle-timeout: the test backend silent past Envoy's stream idle timeout through the users' Gateway, then the corrected chain

### pass1

- halves: `{"corrected": {"backend_bytes_before_continue": 1, "closed_by": null, "idle": "600s", "server": "envoy", "status": 200, "total_s": 330.948217, "upstream_closed_s": null}, "rendered": {"backend_bytes_before_continue": 0, "closed_by": "10.22.0.47:34147", "idle": "300s", "server": "envoy", "status": 504, "total_s": 300.015558, "upstream_closed_s": 300.0}}`
- helm: `{"corrected": {"cilium-envoy_s": 35.0, "cilium-operator_s": 5.7, "cilium_s": 49.9, "upgrade_s": 3.0}, "rendered": {"cilium-envoy_s": 35.4, "cilium-operator_s": 4.4, "cilium_s": 51.9, "upgrade_s": 31.1}}`
- leases: `{"after-corrected": {"gw-internal": "k8s-ingress2, 1 transitions", "gw-users": "k8s-ingress2, 1 transitions"}, "after-rendered": {"gw-internal": "k8s-ingress2, 3 transitions", "gw-users": "k8s-ingress2, 3 transitions"}, "before-corrected": {"gw-internal": "k8s-ingress1, 0 transitions", "gw-users": "k8s-ingress1, 0 transitions"}, "before-rendered": {"gw-internal": "k8s-ingress2, 1 transitions", "gw-users": "k8s-ingress2, 1 transitions"}}`
- silent_s: `330`

## Verdict

```
== pass 1, drill key-lifecycle: one key for chat from mint to revoke under the gateway probe, at every API gateway pod and through the users' VIP
  PASS  pass 1 key-lifecycle: the gateway layer whole before the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 1 key-lifecycle: the gateway layer whole again after the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 1 key-lifecycle: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 1 key-lifecycle: the key Job minted batch.fd000001 into the key Secret (sha256:06cc6f9a0318), on the host clock at 1793366575.0265658
  PASS  pass 1 key-lifecycle: every API gateway pod accepted it, each on its own schedule: api-gateway-64bc7b94df-7b74q 69.7 s, api-gateway-64bc7b94df-hm4sq 48.5 s after the Secret's write; the last pod's acceptance 69.7 s
  PASS  pass 1 key-lifecycle: the first 200 through llm.ai.tarnwick.example came 52.1 s after the write, once a pod held the key (the first pod 48.5 s), and 5 of the VIP's requests were refused 401 between it and the last pod's acceptance: a first 200 shows one pod holds a key, the last pod's acceptance that all do
  PASS  pass 1 key-lifecycle: the new chat key on staff's route: 401 at every API gateway pod (api-gateway-64bc7b94df-7b74q 401, api-gateway-64bc7b94df-hm4sq 401) and through the VIP (HTTP 401)
  PASS  pass 1 key-lifecycle: the key Job revoked batch.fd000001 (sha256:06cc6f9a0318), on the host clock at 1793366669.632314
  PASS  pass 1 key-lifecycle: after the revoke every API gateway pod refused it: api-gateway-64bc7b94df-7b74q 57.4 s, api-gateway-64bc7b94df-hm4sq 45.3 s; the last pod's refusal 57.4 s after the revoke
  PASS  pass 1 key-lifecycle: through the VIP the last 200 with it came 54.4 s after the revoke, and every request after the last pod's refusal was refused (8 requests)
  PASS  pass 1 key-lifecycle: chat through gw-users: 0 of 90 requests failed
  PASS  pass 1 key-lifecycle: staff through gw-users: 0 of 6 requests failed
  PASS  pass 1 key-lifecycle: the key Secret holds the same fields and fingerprints after the drill as before (2 fields)
== pass 1, drill rejected-code: staff's route without its rejected code, a chat key answered with the plugin's default, then the rendered 401
  PASS  pass 1 rejected-code: the gateway layer whole before the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 1 rejected-code: the gateway layer whole again after the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 1 rejected-code: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 1 rejected-code: staff's route without rejected_code: a chat key answered HTTP 403 at every API gateway pod (api-gateway-64bc7b94df-7b74q 56.4 s, api-gateway-64bc7b94df-hm4sq 51.4 s after the change), the plugin's own message: The consumer_group_id is forbidden.
  PASS  pass 1 rejected-code: ... and through the VIP: HTTP 403
  PASS  pass 1 rejected-code: the rendered routes back: HTTP 401 at every pod again, with the unknown key's message (Authorization Failed)
  PASS  pass 1 rejected-code: ... through the VIP HTTP 401, and staff's own key there HTTP 200
  PASS  pass 1 rejected-code: chat through gw-users: 0 of 103 requests failed
  PASS  pass 1 rejected-code: staff through gw-users: 0 of 7 requests failed
  PASS  pass 1 rejected-code: the routes ConfigMap is the render's again
== pass 1, drill idle-timeout: the test backend silent past Envoy's stream idle timeout through the users' Gateway, then the corrected chain
  PASS  pass 1 idle-timeout: the gateway layer whole before the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 1 idle-timeout: Cilium upgraded with the corrected values from the in-lab registry, its operator, agents and Envoy rolled out
  PASS  pass 1 idle-timeout: the listener's stream idle timeout 600s, both Gateways Programmed, the route answering (corrected, 4 s)
  PASS  pass 1 idle-timeout: Cilium upgraded with the rendered values from the in-lab registry, its operator, agents and Envoy rolled out
  PASS  pass 1 idle-timeout: the listener's stream idle timeout 300s, both Gateways Programmed, the route answering (restored, 4 s)
  PASS  pass 1 idle-timeout: the gateway layer whole again after the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 1 idle-timeout: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 1 idle-timeout, as rendered (the listener's stream idle timeout 300s): the request silent for 330 s ended HTTP 504 after 300.015558 s, answered by envoy: the Gateway ended it, the backend having sent 0 bytes' segments before it was continued
  PASS  pass 1 idle-timeout, as rendered: the Gateway's proxy closed its connection to the test backend 300.0 s after the request was sent (10.22.0.47:34147)
  PASS  pass 1 idle-timeout, corrected (the listener's stream idle timeout 600s, the route's request 420 s and backendRequest 400 s): the same silence answered HTTP 200 after 330.948217 s
  PASS  pass 1 idle-timeout: the rendered chain back: idle 300s (before the drill 300s), the same; route timeouts none; helm values rendered
== pass 2, drill key-lifecycle: one key for chat from mint to revoke under the gateway probe, at every API gateway pod and through the users' VIP
  PASS  pass 2 key-lifecycle: the gateway layer whole before the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 2 key-lifecycle: the gateway layer whole again after the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 2 key-lifecycle: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 2 key-lifecycle: the key Job minted batch.fd000002 into the key Secret (sha256:ec8f5df23969), on the host clock at 1793368592.7735677
  PASS  pass 2 key-lifecycle: every API gateway pod accepted it, each on its own schedule: api-gateway-64bc7b94df-7b74q 32.4 s, api-gateway-64bc7b94df-hm4sq 71.7 s after the Secret's write; the last pod's acceptance 71.7 s
  PASS  pass 2 key-lifecycle: the first 200 through llm.ai.tarnwick.example came 34.2 s after the write, once a pod held the key (the first pod 32.4 s), and 9 of the VIP's requests were refused 401 between it and the last pod's acceptance: a first 200 shows one pod holds a key, the last pod's acceptance that all do
  PASS  pass 2 key-lifecycle: the new chat key on staff's route: 401 at every API gateway pod (api-gateway-64bc7b94df-7b74q 401, api-gateway-64bc7b94df-hm4sq 401) and through the VIP (HTTP 401)
  PASS  pass 2 key-lifecycle: the key Job revoked batch.fd000002 (sha256:ec8f5df23969), on the host clock at 1793368689.9912577
  PASS  pass 2 key-lifecycle: after the revoke every API gateway pod refused it: api-gateway-64bc7b94df-7b74q 78.9 s, api-gateway-64bc7b94df-hm4sq 65.3 s; the last pod's refusal 78.9 s after the revoke
  PASS  pass 2 key-lifecycle: through the VIP the last 200 with it came 75.5 s after the revoke, and every request after the last pod's refusal was refused (7 requests)
  PASS  pass 2 key-lifecycle: chat through gw-users: 0 of 101 requests failed
  PASS  pass 2 key-lifecycle: staff through gw-users: 0 of 7 requests failed
  PASS  pass 2 key-lifecycle: the key Secret holds the same fields and fingerprints after the drill as before (2 fields)
== pass 2, drill rejected-code: staff's route without its rejected code, a chat key answered with the plugin's default, then the rendered 401
  PASS  pass 2 rejected-code: the gateway layer whole before the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 2 rejected-code: the gateway layer whole again after the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 2 rejected-code: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 2 rejected-code: staff's route without rejected_code: a chat key answered HTTP 403 at every API gateway pod (api-gateway-64bc7b94df-7b74q 26.4 s, api-gateway-64bc7b94df-hm4sq 32.4 s after the change), the plugin's own message: The consumer_group_id is forbidden.
  PASS  pass 2 rejected-code: ... and through the VIP: HTTP 403
  PASS  pass 2 rejected-code: the rendered routes back: HTTP 401 at every pod again, with the unknown key's message (Authorization Failed)
  PASS  pass 2 rejected-code: ... through the VIP HTTP 401, and staff's own key there HTTP 200
  PASS  pass 2 rejected-code: chat through gw-users: 0 of 88 requests failed
  PASS  pass 2 rejected-code: staff through gw-users: 0 of 6 requests failed
  PASS  pass 2 rejected-code: the routes ConfigMap is the render's again
== pass 3, drill key-lifecycle: one key for chat from mint to revoke under the gateway probe, at every API gateway pod and through the users' VIP
  PASS  pass 3 key-lifecycle: the gateway layer whole before the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 3 key-lifecycle: the gateway layer whole again after the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 3 key-lifecycle: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 3 key-lifecycle: the key Job minted batch.fd000003 into the key Secret (sha256:ce91c8b1eda2), on the host clock at 1793369424.227345
  PASS  pass 3 key-lifecycle: every API gateway pod accepted it, each on its own schedule: api-gateway-64bc7b94df-7b74q 23.4 s, api-gateway-64bc7b94df-hm4sq 58.4 s after the Secret's write; the last pod's acceptance 58.4 s
  PASS  pass 3 key-lifecycle: the first 200 through llm.ai.tarnwick.example came 26.2 s after the write, once a pod held the key (the first pod 23.4 s), and 9 of the VIP's requests were refused 401 between it and the last pod's acceptance: a first 200 shows one pod holds a key, the last pod's acceptance that all do
  PASS  pass 3 key-lifecycle: the new chat key on staff's route: 401 at every API gateway pod (api-gateway-64bc7b94df-7b74q 401, api-gateway-64bc7b94df-hm4sq 401) and through the VIP (HTTP 401)
  PASS  pass 3 key-lifecycle: the key Job revoked batch.fd000003 (sha256:ce91c8b1eda2), on the host clock at 1793369505.9298298
  PASS  pass 3 key-lifecycle: after the revoke every API gateway pod refused it: api-gateway-64bc7b94df-7b74q 15.1 s, api-gateway-64bc7b94df-hm4sq 44.8 s; the last pod's refusal 44.8 s after the revoke
  PASS  pass 3 key-lifecycle: through the VIP the last 200 with it came 43.2 s after the revoke, and every request after the last pod's refusal was refused (8 requests)
  PASS  pass 3 key-lifecycle: chat through gw-users: 0 of 77 requests failed
  PASS  pass 3 key-lifecycle: staff through gw-users: 0 of 6 requests failed
  PASS  pass 3 key-lifecycle: the key Secret holds the same fields and fingerprints after the drill as before (2 fields)
== pass 3, drill rejected-code: staff's route without its rejected code, a chat key answered with the plugin's default, then the rendered 401
  PASS  pass 3 rejected-code: the gateway layer whole before the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 3 rejected-code: the gateway layer whole again after the drill: every API gateway and router pod Ready, both Gateways Programmed, the test backend ready (poll 2)
  PASS  pass 3 rejected-code: audit.sh --quick after the drill: RESULT: 337 passed, 0 failed, 0 known platform limitation(s), 0 skipped
  PASS  pass 3 rejected-code: staff's route without rejected_code: a chat key answered HTTP 403 at every API gateway pod (api-gateway-64bc7b94df-7b74q 25.4 s, api-gateway-64bc7b94df-hm4sq 34.4 s after the change), the plugin's own message: The consumer_group_id is forbidden.
  PASS  pass 3 rejected-code: ... and through the VIP: HTTP 403
  PASS  pass 3 rejected-code: the rendered routes back: HTTP 401 at every pod again, with the unknown key's message (Authorization Failed)
  PASS  pass 3 rejected-code: ... through the VIP HTTP 401, and staff's own key there HTTP 200
  PASS  pass 3 rejected-code: chat through gw-users: 0 of 82 requests failed
  PASS  pass 3 rejected-code: staff through gw-users: 0 of 6 requests failed
  PASS  pass 3 rejected-code: the routes ConfigMap is the render's again
```

== RESULT: 80 passed, 0 failed, 0 known platform limitation(s), 0 skipped
