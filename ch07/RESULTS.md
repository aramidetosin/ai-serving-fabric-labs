# Chapter 7 results

What lab `sfab-ch07` proved on its one recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-10-30 on the second lab host, from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4`, `sfab/client:2`, `sfab/frr:10.5.4-3`, `sfab/registry:3`, `sfab/resolver:3` and `sfab/vpngw:3` (each id in every `RUN.json`), and in the cluster `sfab/serving:b11382-2`, `sfab/keys:3`, APISIX 3.9.1, LiteLLM v1.104.0, the identity provider and the test backend from the in-lab registry: `make down` and `make wipe` from 12:02, `make up` from 12:08:46 to 13:05:10, `make audit`, `make trace`, `make drills PASSES=3` (the idle-timeout drill in the first pass only), `make serve`, `make client`, `make load USERS=10 SECONDS=60`, `make break-7a`, `make heal-7a`, and `make record` from 14:45:57 to 15:02:55, then `make down`. Every command ran in tmux under `script`, so each journal shows the command exactly as typed (`audits/sfab-ch07_record-run_20261030T120209Z/chain.log`). No container restarted between the end of `make up` and the end of `make record` (the start times in `audits/sfab-ch07_record-run_20261030T120209Z/startedat-*.txt` are identical, every one `restarts=0`). Times are the lab host's clock.

The short names are the index's: N is `audits/sfab-ch07_record-run_20261030T120209Z/`, U `audits/sfab-ch07_audit_20261030T124945Z/` (the audit `make up` ran), A `audits/sfab-ch07_audit_20261030T130520Z/`, T `audits/sfab-ch07_trace_20261030T132040Z/`, R `audits/sfab-ch07_drills_20261030T132224Z/`, B `audits/sfab-ch07_break-7a_20261030T142452Z/`, H `audits/sfab-ch07_heal-7a_20261030T142940Z/`, HA `audits/sfab-ch07_audit_20261030T143046Z/` (the chapter audit H ran), RA `audits/sfab-ch07_audit_20261030T144557Z/` and RT `audits/sfab-ch07_trace_20261030T150112Z/` (the audit and trace `make record` ran).

## What the lab proved

| Claim | Verdict lines |
|---|---|
| GatewayClass `cilium` is Accepted, and each Gateway's HTTPS listener admits HTTPRoutes only from the namespaces labelled for it (`allowedRoutes` from `Selector` on `routes.tarnwick.example/<gateway>: "true"`); exactly the namespaces the render labels carry each label (`echo`, `identity`, `inference` and `serving` for gw-internal; `echo`, `identity` and `inference` for gw-users), and every route on each Gateway is Accepted with its references resolved, the listener counting them | A/verdict.txt:669 to :672, :674 to :676; A/gateway-layer/namespaces.txt:1 to :12 |
| Each Gateway answers exactly the render's hostname and path pairs: the internal Gateway the bare `/models` prefix, the recipe's `serve` paths and the admin hostnames; the users' Gateway the identity provider, one rule a model and the test backend's `/echo`; no route on the users' Gateway names an admin hostname | A/verdict.txt:673, :677 to :679 |
| Each VIP is announced by an ingress node holding its L2 announcement lease (k8s-ingress1 for both after launch, k8s-ingress2 after the idle drill's Cilium rolls), answers ARP and TCP 443 from the other ingress node, and answers no ICMP echo; the echoes it does not answer, the lease holder answers with an ICMP redirect | A/verdict.txt:681, :682, :684, :685; A/gateway-layer/vip-gw-users.txt:1 to :9; RA/verdict.txt:681, :684 |
| Each Gateway holds its own certificate for `*.ai.tarnwick.example` from the platform intermediate, the two with different keys, and each VIP's chain for `llm.ai.tarnwick.example` verifies against the lab root; the lab CA refuses every leaf its intermediates sign outside their name constraints with `permitted subtree violation` | A/verdict.txt:683, :686 to :694, :1002 to :1004; A/cluster-security/gateway-certs.txt:1 to :12; A/gateway-layer/ca-proof.txt:1 to :21 |
| The three populations get their own answers through their own resolvers: the enterprise LAN the users' VIP from ent-dns, with no admin and no infrastructure name; the nodes the internal VIP for both `llm` and `admin` from dns-res1, which also holds the infrastructure records; the operator's resolver no platform name at all, so the operator's client pins the internal VIP; `admin` at the users' Gateway is 404 | A/verdict.txt:931 to :948 |
| A request with no key, with a key no Secret holds, and with the other model's key is each answered 401 on each model's route through each Gateway, the other model's key with the unknown key's own message; every API gateway pod, probed by its address from inside the cluster, answers each model's first key 200 on its own route and 401 on the other | A/verdict.txt:638 to :655 |
| A person signs in at the identity provider through the users' Gateway and the API gateway takes the token on both models' routes for caller staff; a token without the API gateway's audience and a token altered by one character are each refused 401 with `WWW-Authenticate: Bearer realm="llm.ai.tarnwick.example"`; the API gateway's access log names the person | A/verdict.txt:656 to :667 |
| The timeout chain nests as the cluster runs it: the router's 2 attempts of 280 s inside the API gateway's upstream read of 600 s, inside the model routes' backendRequest of 620 s, equal to their request of 620 s; each Gateway's listener runs Cilium's stream idle timeout of 300 s | A/verdict.txt:695 to :700 |
| Secrets are encrypted at rest (secretbox, read back by the API server); WireGuard runs on every node with 6 peers; 12 CiliumNetworkPolicies refuse a pod outside every policed namespace at each serving and inference Service and the identity provider while kube-dns stays reachable; the API gateway, router and identity provider run on the ingress nodes only, whose traffic leaves by their own table on VLAN 110 | A/verdict.txt:987 to :1018 |
| One keyed request from the enterprise client crosses three in-cluster hops with a key in each, captured at each pod's own interface: the caller's chat key from the Gateway's proxy to one API gateway pod, the router's master key in its place from that pod to the router (the caller's key on no request to the router), and the backend key from the router to the server; every `Authorization` value in the keyed captures is a keyed mark, written before the capture left its guest | T/verdict.txt:20 to :26; T/TRACE.md:23 to :27 |
| An admin hostname sent to the users' VIP with no key is answered 404 by the Gateway (server `envoy`), its SYN seen at the lease holder, and no API gateway pod sees a request for it | T/verdict.txt:27 to :30 |
| A new key for chat's caller, minted into the key Secret under a probe of both models' first keys that loses nothing (0 failed of 77 to 101 chat and 6 or 7 staff requests a pass), is accepted by each API gateway pod on its own schedule, 23.4 to 71.7 s after the Secret's write over three passes; the first 200 through the VIP came before the last pod's acceptance in every pass, with 5 to 9 of the VIP's requests refused 401 between them; the new key is refused 401 on staff's route at every pod and through the VIP; after the revoke every pod refuses it, 15.1 to 78.9 s after it | R/verdict.txt:5 to :13 (pass 1), :42 to :50 (pass 2), :67 to :75 (pass 3) |
| Without the consumer restriction's `rejected_code` and `rejected_msg`, a chat key on staff's route is answered by the plugin's own default, 403 with `The consumer_group_id is forbidden.`, at every API gateway pod and through the VIP; the rendered routes back, every pod answers 401 with the unknown key's message, staff's own key answers 200, and no request of the probe fails; the same in all three passes | R/verdict.txt:19 to :25, :56 to :62, :81 to :87 |
| As rendered, a test backend silent for 330 s is cut at the users' Gateway's stream idle timeout: HTTP 504 after 300.016 s with the body `stream timeout`, server `envoy`; the backend sent nothing before it was continued, and the Gateway's proxy closed its connection to the backend 300.0 s after its request; with Cilium's stream idle timeout at 600 s and the route's request and backendRequest timeouts at 420 s and 400 s, the same silence is answered 200 after 330.948 s; the rendered chain is back afterwards (300s, no route timeouts, the helm values the render's) | R/verdict.txt:34 to :37; R/pass1/idle-timeout/rendered/headers.txt:1 to :5, body.txt:1 |
| break-7a: with the API gateway pod at place 1 of 2 by name held and a new key for chat's caller minted, only the held pod never accepts it and 10 of 20 requests with it through the users' VIP fail; the held pod's sidecar says it is held; the heal replaces the held pod, every pod then accepts the key and every request answers, and the cleanup revokes the key before the chapter audit, which is green | B/verdict.txt:2 to :10; B/record/broken-sidecar-api-gateway-64bc7b94df-hm4sq.txt:13; H/verdict.txt:2 to :13 |
| An OpenAI-compatible client given only the base URL and the key gets a finished answer: `POST /chat/v1/chat/completions`, HTTP 200, `finish_reason: stop`; `make load USERS=10 SECONDS=60` from the same client fails no request and cuts no stream | N/rec-make-client.txt:5 to :11; N/rec-make-load.txt:6 to :11 |
| The trace and the audit after the drills and the break, on the same deployment, as before them | RA/verdict.txt:638 to :700, :1074; RT/verdict.txt:20 to :31 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster and named by fingerprint and keyed mark only | N/rec-make-up.txt:418 to :422; T/request/key.txt:1, master-key.txt:1, backend-key.txt:1 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch07_audit_20261030T124945Z` (the audit `make up` ran) | `== RESULT: 982 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| A, `sfab-ch07_audit_20261030T130520Z` (`make audit`) | `== RESULT: 982 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| T, `sfab-ch07_trace_20261030T132040Z` (`make trace`) | `== RESULT: 21 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| R, `sfab-ch07_drills_20261030T132224Z` (`make drills PASSES=3`) | `== RESULT: 80 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| B, `sfab-ch07_break-7a_20261030T142452Z` (`make break-7a`) | `== RESULT: 6 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch07_heal-7a_20261030T142940Z` (`make heal-7a`) | `== RESULT: 7 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch07_audit_20261030T143046Z` (the chapter audit heal-7a ran) | `== RESULT: 982 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| RA, `sfab-ch07_audit_20261030T144557Z` (the audit `make record` ran) | `== RESULT: 982 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| RT, `sfab-ch07_trace_20261030T150112Z` (the trace `make record` ran) | `== RESULT: 21 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA and RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:1167) |
| `common/audit/gate.sh` on U, A, T, R, B, H and HA | `== RESULT: 42 passed, 0 failed, 0 known platform limitation(s), 15 skipped` (N/gate-sets.txt) |
| `make serve`, `make client`, `make load USERS=10 SECONDS=60` | `== RESULT: 25 passed, 0 failed, ...` (N/rec-make-serve.txt:33), `== RESULT: 1 passed, 0 failed, ...` (N/rec-make-client.txt:11), `== RESULT: 3 passed, 0 failed, ...` (N/rec-make-load.txt:11) |

The drills print no KNOWN line: no gateway drill shuts a port. Every SKIP is namecheck, which reads `skipped, no scrub list` on a host without the author's list, as on a reader's, the literal scan, which needs the author's literals file, and in the audits also the LAND counter, which this lab's drills plan does not name.

## The result sets

All under `audits/`, each with its `RUN.json` (lab, spec and render sha256, image ids, containerlab version, host tick 10000, UTC start and end), `verdict.txt`, `RESULT.txt` and `commands.txt`. Every `RUN.json` carries one spec sha256 (`b0a19e32e0f0...`) and one render sha256 (`d2313b08c5f8...`), so neither changed during the deployment. The labs repository commit in each, from the checkout's stamp (FRAMEWORK.md 4.4), is a commit of the pre-release history, which is not in this repository, with `dirty: true`: the runs used the code of a later pre-release commit, which the stamp predates, and the repository's first public commit holds the same lab code but for two later changes that leave these runs as they were (`audits/INDEX.md`).

| Directory | What it holds |
|---|---|
| `sfab-ch07_record-run_20261030T120209Z/` | plain files: `chain.log`, the host before and after, the plain journal of every recorded command and the typescripts it was made from, the serving recipe's and the inference step's output from `make up`'s finish stage, container start times, each VM guest's time sync, containerlab's host writes, disk and container-layer readings, the gate on the sets `make record` does not gate, the memory watchdog's log |
| `sfab-ch07_audit_20261030T124945Z/`, `..._130520Z/`, `..._143046Z/`, `..._144557Z/` | the four full audits: every node's reads, both forms, chapter 6's `placement/`, `keys/` (each route's refusals, status and body only, and the per-pod probe's log), `identity/` (the discovery document, each token's claims, each answer and its challenge, the access log), `gateway-layer/` (the GatewayClasses, Gateways, routes, namespaces, leases, the Gateways' CiliumEnvoyConfigs, cilium-config and the inference ConfigMaps, each VIP from the other ingress node, each VIP's chain, the CA's proof) and `cluster-security/` (encryption at rest, WireGuard, each Gateway's certificate, the network policies and the refusals, the ingress nodes' routing and reply capture) |
| `sfab-ch07_trace_20261030T132040Z/`, `..._150112Z/` | the two keyed traces: `TRACE.md`, `cluster/`, `request/` (the keys by field, fingerprint and mark; status and response headers, never a request header; the refusal) and `captures/` (pcaps, their decodes, the API gateway's and the router's `-payload.txt` decodes, and `scrub.log`) |
| `sfab-ch07_drills_20261030T132224Z/` | three passes of `key-lifecycle` and `rejected-code` and one of `idle-timeout`, `pass<N>/<drill>/` (timeline, the per-pod probe's rounds, the gateway probe's records, the key Jobs' logs, the VIP's answers, the ConfigMaps applied, for the idle drill each half's request, captures and listener reads, helm's and the rollouts' output, the leases around them; Warning events, the quick audit, the analysis), `drills.json` (the plan as run) and `DRILLS.md` |
| `sfab-ch07_break-7a_20261030T142452Z/`, `sfab-ch07_heal-7a_20261030T142940Z/` | the break and the heal: the per-pod probe, the requests through the VIP, the Secret's fields and fingerprints, each API gateway pod's sidecar log, the checks |

Sets made before the recorded deployment are not published; `audits/INDEX.md` lists each with its RESULT line and why, the revision 1 sets among them.

## What the deploys found

Each was met on a revision 2 attempt before the recorded deployment and fixed before it (`audits/INDEX.md`, "Superseded sets").

1. **The committed render was stale.** Chapter 4's recording added its LAND probe rule to `spec/profile-a.yaml`, which changed the spec's hash that `gen/RENDER.json` records, so preflight refused `make up` (`render: sfab check -> 1 file(s) drifted`). No file ch07 boots from changed; the lab was rendered again and `gen/RENDER.json` committed.
2. **Staff could not take one request every 2 s on this host.** Under pass 1 of `key-lifecycle`, staff's first requests took over 200 s each on the second lab host's CPUs, the queue grew, and 51 of 65 staff requests ended 504 at the users' Gateway's 300 s stream idle timeout; the quick audit after the drill then met staff still busy. Chapter 6 had met the same and sends staff one request every 15th interval; the gateway drills' probe (`common/drill/lib-gwdrill.sh`) did not pass the plan's `every` on, as the serving drills' does. It now does, and ch07's plan sends staff one request every 30 s (`chapter.yaml`, `every: {staff: 15}`). Tried once on the same deployment (`key-lifecycle` and `rejected-code`, 23 passed, 0 of 5 and 0 of 6 staff requests failed), then the whole sequence ran again from `make down` and `make wipe`.

Facts the recordings show and a reader should know:

- **Envoy's stream idle timeout answers 504 on a request it has whole**, with the idle timeout's own body, `stream timeout` (R/pass1/idle-timeout/rendered/headers.txt:1, body.txt:1). Cilium 1.19.7 sets no route timeout on a route without one: the cut came at the listener's 300 s.
- **The backend's late answer meets a closed connection.** Continued after 330 s, the test backend sent its answer to the connection the Gateway's proxy had closed 30 s before, and the proxy reset it (R/pass1/idle-timeout/rendered/captures/echo-echo-c876b5585-vktp5.txt:634, :635, :734, :735, :909, :910).
- **Rolling Cilium's agents moves the VIPs' leases.** Both leases moved from k8s-ingress1 to k8s-ingress2 during the corrected roll and stayed there through the restore, with 1 and then 3 transitions (R/pass1/idle-timeout/analysis.txt:4); the helm upgrade took 3.0 s and 31.1 s, the agents' rollouts 49.9 s and 51.9 s (:3).
- **A VIP's lease holder answers the ping a VIP does not.** The two echoes the VIP never answered drew ICMP redirects from 10.20.11.11, k8s-ingress1, the lease holder (A/gateway-layer/vip-gw-users.txt:2, :3).
- **The Gateway's proxy tells the API gateway its route bound**, `x-envoy-expected-rq-timeout-ms: 620000`, which APISIX passes on to the router (T/captures/2-api-gateway-64bc7b94df-hm4sq-eth0-payload.txt:252, :297). The model routes' request and backendRequest are both 620 s, so the recording does not show which of the two Envoy enforces.
- **Kubelet's Secret and ConfigMap updates reach the API gateway pods on their own schedules**: a minted key reached a pod 23.4 to 71.7 s after the Secret's write, a revoke 15.1 to 78.9 s after it, and the routes ConfigMap 25.4 to 76.4 s after its apply, over three passes (R/pass<N>/key-lifecycle/analysis.txt, rejected-code/analysis.txt).
- **Both of Cilium's stream idle keys** were raised together in the correction (`http-stream-idle-timeout`, which the chart writes, and `proxy-stream-idle-timeout-seconds`, through `extraConfig`), so the recordings do not show which one the operator reads; as rendered only the first is set, at 300, and the listener reads 300s (R/pass1/idle-timeout/rendered/cilium-config.txt:1, :2, corrected/cilium-config.txt:1, :2).
- **The request path can stay on one node.** In T the users' Gateway, the API gateway pod and the router pod were all on k8s-ingress1, so only the router's request to the server crossed nodes, inside WireGuard; in RT the same held on k8s-ingress2 (T/verdict.txt:7, :9, :10; RT/verdict.txt:7, :9, :10).

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and the `sfab/*` images with the in-lab registry seeded, the two models in `images/models`, 178.75 GiB of MemAvailable (the inventory's 162.75 GiB budget plus the 16 GiB floor) and no other `sfab-` lab running:

```
cd ch07
make up
make audit
make trace
make drills
make serve
make client
make load USERS=10 SECONDS=60
make break-7a
make heal-7a
make record
make down
```

`make up` took 56 min 24 s here from wiped disks: boot 1480 s (the switches 537 s, the firewall 460 s, the secondary DNS zones 291 s), finish 956 s (the serving recipe 233 s, the inference step 75 s), the audit 925 s (N/rec-make-up.txt:303, :330, :377, :379, :416, :425, :825, :1930). `make drills` took 60 min 53 s for three passes (N/chain.log); the idle-timeout drill's two halves and the rolls between them took 15 min 51 s (R/pass1/idle-timeout/timeline.txt:1, :22). `state/` held 24132720 kB before the down, 2945776 and 3229760 kB of it the two GPU nodes' disks (N/state-du.txt).

## What the recordings do not show

- **A GPU.** The models run on CPU, split over RPC workers; nothing here measures a GPU or publishes a throughput figure, and `make load` counts requests by how they ended, never how fast.
- **A key in clear.** Every key is made in the cluster and every capture that could hold one is scrubbed before it is written: the sets hold each key's fingerprint and mark, never its value, so a reader cannot replay a request from them.
- **The status of any timeout but the stream idle timeout's.** No drill here fires the router's attempt, the API gateway's read, or the route's backendRequest or request timeout.
- **A cold prompt's own silence.** The idle-timeout drill silences the test backend by stopping its processes, not a model reading a long prompt.
- **A lease failover's time.** The leases moved while Cilium's agents rolled, and no drill here times an announcement moving from one ingress node to another.
- **A route refused for its namespace.** Every route the lab renders sits in a labelled namespace, so no recording shows a listener refusing a route from an unlabelled one.
- **WireGuard's own bytes.** The audit reads each agent's WireGuard status and peers; no capture here is taken on a node's wire between two nodes, so the encrypted packets themselves are not shown.
- **A key refusal's headers.** The key checks keep the status and body of each refusal; only the identity checks read the `WWW-Authenticate` header.
- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's (`../README.md`, "Clone, build, deploy"); Example 7-1 opens at `cd ch07`.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge. No recorded run exercised the redirect path a stock kernel takes (`../README.md`, "The host").
