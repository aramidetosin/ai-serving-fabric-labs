# Chapter 8 results

What lab `sfab-ch08` proved on its one recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-10-31 on the first lab host (chapter 7's ran on the second), from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4`, `sfab/client:2`, `sfab/frr:10.5.4-3`, `sfab/registry:3`, `sfab/resolver:3` and `sfab/vpngw:3` (each id in every `RUN.json`), and in the cluster `sfab/serving:b11382-2`, `sfab/keys:4` (the in-lab registry's manifest `sha256:c6c2bcfc256d...`, `audits/sfab-ch08_audit_20261031T094426Z/k8s-cp1/26_nodes.json`:766), APISIX 3.9.1, LiteLLM v1.104.0, the identity provider and the test backend from the in-lab registry: `make down` and `make wipe` at 09:11:18, `make up` from 09:11:20 to 09:44:23, `make audit`, `make trace`, `make drills PASSES=3`, `make break-8a`, `make heal-8a`, and `make record` from 10:18:57 to 10:31:24, then `make down`. Every command ran in tmux under `script`, so each journal shows the command exactly as typed (`audits/sfab-ch08_record-run_20261031T091118Z/chain.log`). No container restarted between the end of `make up` and the end of `make record` (the start times in `audits/sfab-ch08_record-run_20261031T091118Z/startedat-*.txt` are identical, every one `restarts=0`). Times are the lab host's clock.

The short names are the index's: N is `audits/sfab-ch08_record-run_20261031T091118Z/`, U `audits/sfab-ch08_audit_20261031T093250Z/` (the audit `make up` ran), A `audits/sfab-ch08_audit_20261031T094426Z/`, T `audits/sfab-ch08_trace_20261031T095603Z/`, R `audits/sfab-ch08_drills_20261031T095651Z/`, B `audits/sfab-ch08_break-8a_20261031T100635Z/`, H `audits/sfab-ch08_heal-8a_20261031T100658Z/`, HA `audits/sfab-ch08_audit_20261031T100720Z/` (the chapter audit H ran), RA `audits/sfab-ch08_audit_20261031T101857Z/` and RT `audits/sfab-ch08_trace_20261031T103036Z/` (the audit and trace `make record` ran).

## What the lab proved

| Claim | Verdict lines |
|---|---|
| Three Gateways run side by side on class `cilium`, each Programmed at its own VIP from its own pool in VLAN 110: gw-internal 10.20.11.200 (.200 to .209), gw-users 10.20.11.210 (.210 to .214) and the new internet Gateway gw-inet 10.20.11.220 (.220 to .224) | A/verdict.txt:669, :987 to :992; A/audiences/gateways.txt:1 to :4 |
| Each Gateway's route set is its audience's row and nothing else: gw-inet carries chat's path and the test backend's `/echo` on `llm` alone, with no admin hostname and no identity provider; gw-users both models' paths, `/echo` and the identity provider; gw-internal the bare `/models` prefix, the admin hostnames, the identity provider and the serving recipe's paths. The namespaces labelled for gw-inet are `echo` and `inference` alone, never `identity` or `serving` | A/verdict.txt:670 to :684, :1088 to :1099 |
| Every caller carries an audience, and each model route admits only callers whose audience may call it: batch, helpdesk and staff the enterprise audience (chat and staff), inetapp the internet audience (chat alone); chat's route admits batch, staff and inetapp, staff's route helpdesk and staff | A/verdict.txt:1100 to :1105; N/rec-make-up.txt:419 to :424 |
| The key tool refuses a key for a model outside the caller's audience and leaves the Secret as it was: a key Job asked for inetapp's key for staff fails with `refused: caller inetapp is in audience internet, which may call chat; staff is outside it`, and the Secret holds the same three fields and fingerprints after it | A/verdict.txt:1117, :1118; A/audiences/refused-mint.log:1, keys-before.txt, keys-after.txt |
| Each Gateway has its own certificate from the platform intermediate with a key of its own: three distinct public-key fingerprints; gw-inet's chain for `llm.ai.tarnwick.example` verifies against the lab root, read from k8s-cp2 | A/verdict.txt:688, :1019, :1020, :1106; A/audiences/certs.txt:1 to :12; A/gateway-layer/tls-from-gw-inet.txt:1, tls-gw-inet.txt:1 to :8 |
| One announcement policy per audience, each selecting its own Gateway's Service on `^bond0\.110$` from the ingress nodes; each VIP its own lease, held by an ingress node, at Cilium's tuned 3 s; cilium-config holds the tuned timers 3s, 1s and 200ms; each VIP answers ARP and TCP 443 from the other ingress node and no ICMP echo | A/verdict.txt:686, :687, :1107 to :1116; A/audiences/leases.json:118 to :121, cilium-config.json:122 to :124 |
| The internet Gateway's column for the populations this lab has: the staff client's and the operator's connects to 10.20.11.220 are refused by `deny-all-log` (from `enterprise` and from `operator-vpn` to `ingress`), each with its traffic log lines; k8s-cp2 connects, its own datapath answering | A/verdict.txt:1119 to :1121; A/audiences/traffic-log-443.txt:6 to :37 |
| One key and one path through two Gateways from k8s-cp2: staff's path with helpdesk's key through gw-users answered 200 across three in-cluster hops, each with its own key's mark (the caller's, the router's master key, the backend key); the same key and path through gw-inet answered 404 by the Gateway, and neither API gateway pod saw a request for it; an admin hostname on gw-inet answered 404 the same way; no SYN to either VIP left k8s-cp2 | T/verdict.txt:2 to :32; T/TRACE.md:3 to :35 |
| With the lease holder cut from the pair (KLISH `shutdown` on its two pair ports), the other ingress node took all three leases 2.751 to 3.729 s after both ports were shut, over three passes; each echo probe through gw-users and gw-internal lost at most one request at its 2 s interval (gaps 2.0 to 4.0 s) and each connect loop 3 or 4 connects at its 0.5 s interval (gaps 3.5 to 4.5 s), all answered again before the ports came back; the firewall's ARP entries for all three VIPs named the new holder's bond MAC while the node was cut; the model probe, reported apart, answered 32 to 37 of 49 or 50 requests over each pass | R/verdict.txt:6 to :20, :26 to :40, :46 to :60 |
| break-8a: with the internet audience's policy naming `^bond0\.111$`, the lease stays held and renewed and the Gateway stays Programmed, while an ARP request for 10.20.11.220 from the other ingress node goes unanswered; the users' VIP keeps its holder's answer, the staff's requests through gw-users all succeed, and the firewall keeps its cached entry for 10.20.11.220; the heal puts `^bond0\.110$` back and the VIP is answered by its holder's bond MAC again, then the chapter audit is green | B/verdict.txt:2 to :9; B/record/broken-lease-gw-inet.yaml:11, :12, :14, broken-fw1-show_arp_all.txt:32; H/verdict.txt:2 to :10 |
| The trace and the audit after the drills and the break, on the same deployment, as before them | RA/verdict.txt:668 to :710, :1087 to :1122, :1126; RT/verdict.txt:1 to :33 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster and named by fingerprint and keyed mark only | N/rec-make-up.txt:418 to :426; T/request/key.txt:1, master-key.txt:1, backend-key.txt:1 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch08_audit_20261031T093250Z` (the audit `make up` ran) | `== RESULT: 1032 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| A, `sfab-ch08_audit_20261031T094426Z` (`make audit`) | `== RESULT: 1032 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| T, `sfab-ch08_trace_20261031T095603Z` (`make trace`) | `== RESULT: 22 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| R, `sfab-ch08_drills_20261031T095651Z` (`make drills PASSES=3`) | `== RESULT: 54 passed, 0 failed, 3 known platform limitation(s), 0 skipped` |
| B, `sfab-ch08_break-8a_20261031T100635Z` (`make break-8a`) | `== RESULT: 6 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch08_heal-8a_20261031T100658Z` (`make heal-8a`) | `== RESULT: 6 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch08_audit_20261031T100720Z` (the chapter audit heal-8a ran) | `== RESULT: 1032 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RA, `sfab-ch08_audit_20261031T101857Z` (the audit `make record` ran) | `== RESULT: 1032 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RT, `sfab-ch08_trace_20261031T103036Z` (the trace `make record` ran) | `== RESULT: 22 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA and RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:1218) |
| `common/audit/gate.sh` on U, A, T, R, B, H and HA | `== RESULT: 42 passed, 0 failed, 0 known platform limitation(s), 15 skipped` (N/gate-sets.txt:66) |

The three KNOWN lines are the drill's L9, once a pass: the virtual switch gives the cut node no loss of carrier, so it loses its leases because it cannot renew them (R/verdict.txt:3, :23, :43). The audits' three SKIPs are the LAND counter, which this lab's drills plan does not name, the internet host's cell at the internet Gateway, since this lab's slice has no client of that population, and namecheck, which reads `skipped, no scrub list` on a host without the author's list, as on a reader's. The gates' SKIPs are namecheck and the literal scan, which needs the author's literals file.

## The result sets

All under `audits/`, each with its `RUN.json` (lab, labs commit with its dirty flag, spec and render sha256, image ids, containerlab version, host tick 10000, UTC start and end), `verdict.txt`, `RESULT.txt` and `commands.txt`. Every `RUN.json` carries one spec sha256 (`8f314deb6bce...`) and one render sha256 (`9fe04e7f27af...`), so neither changed during the deployment, and one labs commit from the checkout's stamp (FRAMEWORK.md 4.4) with `dirty: false`: a commit of the development history, which is not in this repository; the commit that adds these sets holds the same lab code.

| Directory | What it holds |
|---|---|
| `sfab-ch08_record-run_20261031T091118Z/` | plain files: `chain.log`, the host before and after, the plain journal of every recorded command and the typescripts it was made from, the serving recipe's and the inference step's output from `make up`'s finish stage, container start times, each VM guest's time sync, containerlab's host writes, disk and container-layer readings, the gate on the sets `make record` does not gate, the lab's memory watchdog's log and a second watcher's readings |
| `sfab-ch08_audit_20261031T093250Z/`, `..._094426Z/`, `..._100720Z/`, `..._101857Z/` | the four full audits: every node's reads, both forms, chapter 6's `placement/`, chapter 7's `keys/`, `identity/`, `gateway-layer/` (now with gw-inet: its VIP, ARP, TCP and chain read from k8s-cp2) and `cluster-security/`, and chapter 8's `audiences/` (the Gateways, routes, namespaces, leases, policies, cilium-config and the API gateway's routes, each Gateway certificate's issuer and key fingerprint, the key Secret's fields before and after the refused mint with the refusal's log and its Job's events, the internet Gateway's column with the firewall's traffic log) |
| `sfab-ch08_trace_20261031T095603Z/`, `..._103036Z/` | the two keyed traces from k8s-cp2: `TRACE.md`, `cluster/`, `request/` (the keys by field, fingerprint and mark; status and response headers of each request, never a request header; the same key through gw-inet; the refusal) and `captures/` (k8s-cp2's own ports, every API gateway and router pod's interface whole, the servers and workers; pcaps, their decodes, the `-payload.txt` decodes, and `scrub.log`) |
| `sfab-ch08_drills_20261031T095651Z/` | three passes of `lease-holder-loss`, `pass<N>/lease-holder-loss/` (timeline, the cut node, the KLISH shut and restore sessions, the leases read every 0.5 s, the EndpointSlices every 2 s, the pods' places, the firewall's ARP table before, during and after, the echo, connect and model probes' records, the Warning events saved and cleared, the lab whole before and after, the quick audit, the analysis), `drills.json` (the plan as run) and `DRILLS.md` |
| `sfab-ch08_break-8a_20261031T100635Z/`, `sfab-ch08_heal-8a_20261031T100658Z/` | the break and the heal: the policy patch, the policies, leases, Gateway and Service read whole, the firewall's ARP table and session, the ARP checks from the ingress node not holding the lease, the staff's requests, the checks |

Sets made on the two attempts before the recorded deployment are not published; `audits/INDEX.md` lists each with its RESULT line and why.

## What the deploys found

Each was met on an attempt before the recorded deployment and fixed before it (`audits/INDEX.md`, "Sets not published").

1. **The lease drill left Warning events where the next audit reads them.** Cutting an ingress node from the pair leaves NodeNotReady events on its pods, the identity provider's among them; the drill saved and cleared the Warning events of the test backend's namespace and `kube-system` only, so on the first attempt the chapter audit after `make heal-8a` failed one check on the event in `identity`. The drill now saves and clears the Warning events of every namespace that holds one when its pass ends (pass 2 of the recorded drills cleared `inference`'s as well: R/pass2/lease-holder-loss/events/).
2. **The trace's refusal heading named the wrong Gateway.** With the hostname refusal sent to gw-inet, the verdict's section heading still named the trace's main Gateway, gw-users, while the checks under it named 10.20.11.220. The heading now names the Gateway the refusal goes to (T/verdict.txt:29).
3. **The drill's gaps were timed from the cut's start.** The two pair ports are shut one switch after the other, and the bond keeps a leg until the second, so on the second attempt a request sent between the two shuts was still answered and became the first answer after the cut: the requests lost after the second shut fell outside the gap, and the verdicts read 0 lost where the probe records held one timed-out echo request a pass through each Gateway and 3 to 5 failed connects. A verdict its own records contradict is not published. The gaps and the leases' moves are now timed from the moment both ports are shut, and each probe also reports its slowest answer and connect while the node was cut (FRAMEWORK.md 4.6); the whole sequence ran again from `make down` and `make wipe`.

Facts the recordings show and a reader should know:

- **All three leases sit on one ingress node, and move together.** In every audit the three VIPs' leases were held by the same ingress node, and in every drill pass all three moved to the other one in the same lease read (A/audiences/leases.txt:7 to :9; R/verdict.txt:6 to :8, :26 to :28, :46 to :48). A policy per audience separates the faults of one audience's policy (break-8a), not where the leases land.
- **The leases do not move back.** After each restore the leases stayed with the node that took them, so each pass cut the other ingress node, and HA and RA read them on k8s-ingress1 (R/verdict.txt:4, :24, :44).
- **The node answers its Gateways' VIPs itself.** k8s-cp2's requests to 10.20.11.210 and 10.20.11.220 never left the node, and the API gateway pod received them from the Envoy address on the node (T/verdict.txt:7, :9, :31).
- **The firewall's ARP entry moved for the VIP nothing drove through it.** No probe sends traffic to 10.20.11.220 through the firewall in this chapter, yet in every pass its entry named the new holder's MAC while the node was cut, as the other two VIPs' did (R/verdict.txt:15, :35, :55).
- **A policy that matches no device keeps its lease alive.** While gateways-internet named `^bond0\.111$`, the lease for gw-inet stayed held by k8s-ingress1 and kept renewing, the Gateway stayed Programmed, and only a neighbour asking by ARP went unanswered; the firewall's entry for 10.20.11.220, learned before the break, stayed complete (B/record/broken-lease-gw-inet.yaml:11, :14, broken-gateway-gw-inet.yaml:58, broken-fw1-show_arp_all.txt:32; B/verdict.txt:7).
- **The model probe loses more than the lease gap.** The API gateway, the router and the identity provider run on the ingress nodes, so a cut node takes its share of them until their endpoints leave the Services, which no pass saw within its 34 s of cut for the inference Services (R/verdict.txt:18, :20, :38, :40, :58, :60). The drill reports those requests apart from the echo and connect probes, which need nothing on the cut node but its lease.

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and the `sfab/*` images with the in-lab registry seeded (`sfab/keys:4` among them, `make -C images keys`), the two models in `images/models`, 178.75 GiB of MemAvailable (the inventory's 162.75 GiB budget plus the 16 GiB floor) and no other `sfab-` lab running:

```
cd ch08
make up
make audit
make trace
make drills
make break-8a
make heal-8a
make record
make down
```

`make up` took 33 min 3 s here from wiped disks: boot 773 s (the switches 302 s, the firewall 327 s, the secondary DNS zones 28 s), finish 503 s (the serving recipe 87 s, the inference step 28 s), the audit 694 s (N/rec-make-up.txt:303, :330, :377, :379, :416, :429, :827, :1982). `make drills` took 9 min 45 s for three passes (N/chain.log:20). The running lab took about 80 GiB of the host's memory: MemAvailable read 338.6 GiB before `make up` and 258.6 GiB after `make record` (N/host-before-up.txt:4, N/host-after-record.txt:4). `state/` held 23580644 kB before the down (N/state-du.txt:2).

## What the recordings do not show

- **A GPU.** The models run on CPU, split over RPC workers; nothing here measures a GPU or publishes a throughput figure.
- **A key in clear.** Every key is made in the cluster and every capture that could hold one is scrubbed before it is written: the sets hold each key's fingerprint and mark, never its value.
- **An internet user.** No population reaches the internet Gateway through the firewall until chapter 10; here its requests come from k8s-cp2, whose own datapath answers the VIP, and its column is read only for the staff, the operator and the nodes.
- **The API gateway's access log for the refused requests.** The trace shows each refused request absent from the API gateway pods' captures; it does not read their access log.
- **A failover time finer than the probes.** The echo probes send every 2 s and the connect loops every 0.5 s, so each gap is a count of intervals; the lease reads every 0.5 s time the leases' moves.
- **Carrier loss.** The virtual switch's ports give the cut node no link-down event, so the drill never shows a node seeing its links fail.
- **The leases on two nodes.** No recording here shows the three audiences' leases held by different ingress nodes.
- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's (`../README.md`, "Clone, build, deploy"); Example 8-1 opens at `cd ch08`.
