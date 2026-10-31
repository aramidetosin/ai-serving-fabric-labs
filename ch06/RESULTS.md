# Chapter 6 results

What lab `sfab-ch06` proved on its recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-10-28 from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4`, `sfab/resolver:3`, `sfab/vpngw:3`, `sfab/client:2`, `sfab/frr:10.5.4-3` and `sfab/registry:3`, and in the cluster `sfab/serving:b11382-2` (llama.cpp b11382, no model in the image), `sfab/keys:3`, APISIX 3.9.1, LiteLLM v1.104.0 and Dex v2.46.0 from the in-lab registry, with the two models, LFM2.5-24B-A2B (chat) and Qwen3.8-27B (staff), read from the lab host's models directory through each GPU node's read-only share. Every command ran in tmux under `script`, so each journal shows the command exactly as typed: `make down` and `make wipe` from 20:19:11, `make up` from 20:22:47 to 21:10:33, `make audit`, `make trace`, `make drills PASSES=3`, `make break-6a`, `make heal-6a`, `make attach`, `make break-6b`, `make heal-6b`, `make record` from 23:03:14 to 23:25:54, and `make down` to 23:29:31 (`audits/sfab-ch06_record-run_20261028T201911Z/chain.log`). No container restarted between the end of `make up` and the end of `make record`. Times are the lab host's clock, UTC.

The short names are the index's: N is `audits/sfab-ch06_record-run_20261028T201911Z/`, U `audits/sfab-ch06_audit_20261028T205709Z/` (the audit `make up` ran), A `audits/sfab-ch06_audit_20261028T211034Z/`, T `audits/sfab-ch06_trace_20261028T212405Z/`, R `audits/sfab-ch06_drills_20261028T212555Z/`, B and H break-6a and heal-6a, HA the chapter audit H ran, AT `make attach`, B2 and H2 break-6b and heal-6b, HA2 the chapter audit H2 ran, RA and RT the audit and trace `make record` ran.

## The lab host

The deployment ran on the second of the book's two lab hosts, the one with room for a lab with serving on (162.5 GiB for the nodes, 178.5 GiB with the floor; N/rec-make-up.txt:29 read 304.4 GiB available). Its CPUs are older and slower than those of the host where the serving timers were measured, and staff, the dense model, answers there in tens of seconds a request: an 8-token answer from one of staff's copies took about half a minute, idle, and four at once each took over a minute and a half. Chat, a mixture of experts with about 2B parameters active, answered in about 2 s. The drills' and breaks' gateway probe therefore sends staff one request on every 15th of its 2 s intervals (every 30 s) and chat one every 2 s (`chapter.yaml` `drills.probes.gateway.every`, `breaks/6a.yaml`, `breaks/6b.yaml`; "What the deploy found", 2). The router's attempt timeout, the API gateway's read and the routes' timeouts are as rendered (`../README.md`, "The API gateway and the router"). No figure here is a throughput measurement, and none is published: the llama-server timings in the traces' saved answers are redacted.

## Revision 2, against revision 1

Revision 1's sets (two deployments, 2026-10-22 and 2026-10-27) are superseded and out of the repository (`audits/INDEX.md`, "Superseded sets"). What revision 2 changes in what the chapter shows:

| Part | Revision 1 | Revision 2 |
|---|---|---|
| Placement | 12 pods of 4 copies of 2 models, every copy spanning both GPU nodes, bare Pods | 11 pods of 5 copies: each model's copies a and b node-local, on different nodes and on rails of different parity; chat c spans both nodes on rail 7, the stand-in for a model too large for one node; one StatefulSet of one replica a row |
| Models | Qwen2.5-0.5B baked into the serving image | LFM2.5-24B-A2B (chat) and Qwen3.8-27B (staff) from a read-only share, mounted at `/models` through a local PersistentVolume per GPU node |
| Trace | unpinned; the router picked a copy that spanned the nodes | pinned to chat c, the one copy whose RPC crosses a rail switch, sent again until chat-c's server took it |
| Dark switch | chat a and staff b left their Services | chat c alone leaves; chat a and staff b, node-local on rail-sw1's rails, stay (KNOWN L9, below) |
| Worker port | the port facing chat a's worker0 | the port facing chat c's worker0 (rail-sw1 Ethernet7, facing k8s-gpu2) |
| attach and break-6b | chat-a-server, connected to from another server | chat-c-server-0, connected to from a router pod, which network policy admits to a server |
| Gateway probe | one request a second a model, 40 in a break | chat every 2 s, staff every 30 s; 22 requests in a break (20 to chat, 2 to staff) |
| Keys | per model | per caller (`../ch07/README.md`) |

## What the lab proved

| Claim | Verdict lines |
|---|---|
| The placement table keeps the recipe's rules: 11 pods of 5 copies of 2 models, every copy on one rail with one server and one or more workers, every rail address inside its rail's prefix and given once; and each model keeps a copy through the loss of either rail switch and of any one GPU node (chat a rail 3 on k8s-gpu1, b rail 6 on k8s-gpu2, c rail 7 on both; staff a rail 4 on k8s-gpu1, b rail 5 on k8s-gpu2) | A/verdict.txt:560, :561 |
| Every row's pod runs Ready on the row's node, is its StatefulSet's pod 0, and its network-status annotation names the row's attachment with the row's address and MAC; one StatefulSet a row, one replica, updating on delete, and none other | A/verdict.txt:563 to :576 |
| Each server's `--rpc` list names its workers' rail addresses, llama-server is bound to the pod's cluster address and listens there alone, reads its model from its node's models volume read-only, and runs the RPC-aware readiness probe with the table's timers (every 2 s, out after 2 failures, each up to 2 s); each worker is bound to its own rail address and listens there alone | A/verdict.txt:578 to :614 |
| Each GPU node's models claim is Bound to a local PersistentVolume of `/srv/models` on that node, read-only many | A/verdict.txt:616, :617 |
| One macvlan attachment per rail the table uses (rails 3 to 7): the rail NIC as master, bridge mode, MTU 9000, the static IPAM plugin and no route; no other attachment | A/verdict.txt:619, :620; A/placement/rendered/00-base.yaml:11 to :19 |
| Each model's Service holds all its copies' servers and each copy's Service its own server as ready endpoints | A/verdict.txt:622 to :628 |
| Inside every pod, read in its own network namespace on its node, the default route is on `eth0` and the rail attachment holds only its rail's connected prefix | A/verdict.txt:630; A/placement/pod-chat-c-server-0-route.txt:1 to :3 |
| One request a model through each Gateway answers HTTP 200 from the router's deployment for that model: the users' Gateway from the enterprise client, the internal Gateway from the operator's client through the IPsec tunnel | A/verdict.txt:633 to :636 |
| The rail switches learn each pod's fixed MAC at the port facing the pod's node on the pod's rail | A/rail-sw1/12_mac_table.txt:8 to :19, A/rail-sw2/12_mac_table.txt:8 to :14; A/verdict.txt:148 to :151 |
| One chat completion from the enterprise client goes to the users' VIP at its lease holder (k8s-ingress2), through one API gateway pod and one router pod, to chat-c-server-0 on k8s-gpu1; that server's RPC goes over rail 7, the table's, to both its workers; rail-sw1's ports facing both nodes carry the RPC to the worker on the other node and no frame of the RPC to the worker beside the server; chat's other copies carry none of it | T/verdict.txt:1 to :26 |
| With every port of rail-sw1 shut in one KLISH session, chat-c-server-0 leaves chat and chat-c 4.2 to 7.8 s after the shut session began and comes back 6.4 to 17.9 s after the restore session began; every other server stays, in every one of three passes; no request of the gateway probe fails (178 sent over the three passes) | R/verdict.txt:3, :9 to :23 (pass 1), :55, :61 to :75 (pass 2), :107, :113 to :127 (pass 3); R/DRILLS.md:6 to :26 |
| With the one port facing chat c's worker0 shut, chat c alone leaves its Services (5.9 to 7.9 s after the shut session began), chat a, chat b and both staff copies stay, and no request fails | R/verdict.txt:25 to :47 (pass 1), :77 to :99 (pass 2), :129 to :151 (pass 3); R/DRILLS.md:42 to :62 |
| A KLISH shutdown drops no carrier: while the ports read `down admin-down`, both nodes' kernels read every rail NIC `UP`, so readiness over the rail is the only detector, and chat a and staff b, node-local on rail-sw1's rails, keep their in-node RPC and stay in their Services | R/verdict.txt:19, :24 (KNOWN L9); R/pass1/dark-switch/klish/during-rail-sw1.txt:12 to :19, links-during-k8s-gpu1.txt:1 to :8, links-during-k8s-gpu2.txt:1 to :8 |
| A request sent to chat c while its worker was cut off stalled and was answered after the restore, with no router retry: request 15 of pass 1's dark switch, sent 2 s after the shut began, took 54.9 s | R/pass1/dark-switch/records-chat.jsonl:41; R/DRILLS.md:19 |
| One worker moved to rail 5 in a copy of the table: the recipe refuses to render it, and the audit against it fails seven lines naming chat-a-worker0-0 and its copy while nothing in the cluster moved; the audit against the table as rendered is green; the same in all three passes | R/verdict.txt:48 to :52, :100 to :104, :152 to :156; R/pass1/rail-move/audit-moved.txt:291 to :368 |
| break-6a: with chat-b-worker0-0 made again on rail 8, chat-b holds no endpoint, chat holds chat-a's and chat-c's servers, staff both, and all 22 requests through the users' Gateway answer; the heal runs the recipe, which makes chat-b's server again and puts the worker back on rail 6, every Service whole and every request answering, and waits until rail-sw2 has aged out the MAC the moved worker had on rail 8 (231 s) | B/verdict.txt:2 to :12; H/verdict.txt:2 to :13 |
| `make attach`: chat-c-server-0's network-status names eth0 the default at its pod IP and rail7 at 10.21.7.100 with 02:5a:fe:07:00:64; its routes hold the default on eth0 and on rail7 only 10.21.7.0/24; the EndpointSlices of chat and chat-c hold its eth0 address and not 10.21.7.100; chat-c's DNS name answers its ClusterIP in a router pod; rail-sw1 learned the server's and worker0's MACs in Vlan107 on the ports facing their nodes | AT/verdict.txt:3 to :15 |
| break-6b: chat-c-server-0 made again through rail7-route is Ready; its routes hold `10.22.0.0/16 via 10.21.7.101 dev rail7`; a router pod's connect to it fails while rail7 carries 7 packets from its eth0 address; chat-c, chat and staff each hold all their servers; no request through the Gateway fails, and two of chat's were answered after one router retry; the heal makes the server again through rail7 and removes rail7-route, every Service whole, 22 of 22 requests | B2/verdict.txt:2 to :12; B2/probes/users-break-pass1-chat.jsonl:19, :20; H2/verdict.txt:2 to :16 |
| The trace and the audit after the drills and both breaks, on the same deployment, as before them | RA/verdict.txt:559 to :636, :1003; RT/verdict.txt:1 to :26 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster and named by fingerprint only | N/rec-make-up.txt:390 to :393; N/finish/serving.txt:6, :7 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch06_audit_20261028T205709Z` (the audit `make up` ran) | `== RESULT: 916 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| A, `sfab-ch06_audit_20261028T211034Z` (`make audit`) | `== RESULT: 916 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| T, `sfab-ch06_trace_20261028T212405Z` (`make trace`) | `== RESULT: 18 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| R, `sfab-ch06_drills_20261028T212555Z` (`make drills PASSES=3`) | `== RESULT: 138 passed, 0 failed, 9 known platform limitation(s), 0 skipped` |
| B, `sfab-ch06_break-6a_20261028T221246Z` (`make break-6a`) | `== RESULT: 9 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch06_heal-6a_20261028T221416Z` (`make heal-6a`) | `== RESULT: 9 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch06_audit_20261028T222300Z` (the chapter audit heal-6a ran) | `== RESULT: 916 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| AT, `sfab-ch06_attach_20261028T223637Z` (`make attach`) | `== RESULT: 9 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| B2, `sfab-ch06_break-6b_20261028T223652Z` (`make break-6b`) | `== RESULT: 8 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H2, `sfab-ch06_heal-6b_20261028T224412Z` (`make heal-6b`) | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA2, `sfab-ch06_audit_20261028T224944Z` (the chapter audit heal-6b ran) | `== RESULT: 916 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| RA, `sfab-ch06_audit_20261028T230314Z` (the audit `make record` ran) | `== RESULT: 916 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| RT, `sfab-ch06_trace_20261028T231637Z` (the trace `make record` ran) | `== RESULT: 18 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA, RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:1095) |
| `common/audit/gate.sh` on U, A, T, R, B, H, HA, AT, B2, H2 and HA2 | `== RESULT: 66 passed, 0 failed, 0 known platform limitation(s), 23 skipped` (N/gate-sets.txt) |
| `make up`, `make down` and `make wipe` | 916 passed (the audit's), 4 passed, 4 passed (N/chain.log:4, :6, :9, :34) |

The nine KNOWN lines are L9, three a pass: in the dark switch, the node-local copies on rail-sw1's rails stay because a KLISH shutdown drops no carrier at the rail NICs, and the rail NICs read `UP` throughout; in the worker port, the same carrier note. The one SKIP of `make attach` is chat-c-worker1-0's MAC on rail-sw1 (AT/verdict.txt:16): its copy's peers all sit on k8s-gpu1, so macvlan's bridge mode keeps its traffic inside the node. Every other SKIP is namecheck, which reads `skipped, no scrub list` on a host without the author's list, as on a reader's, and in the audits also the LAND counter, which this lab's drills plan does not name.

## The result sets

All under `audits/`, each with its `RUN.json` (lab, spec and render sha256, image ids, containerlab version, host tick 10000, UTC start and end), `verdict.txt`, `RESULT.txt` and `commands.txt`. Every `RUN.json` carries one render sha256 (`d1d77139b26a...`) and one spec sha256 (`c165f4c98695...`, the spec hash in the `gen/RENDER.json` committed with the recording), so the render did not change during the deployment; later re-renders changed only the recorded spec and generator hashes and the Multus manifest's header comment, with that file's hash, so the lab still boots what it booted. The labs repository commit in each, from the checkout's stamp (FRAMEWORK.md 4.4), is a commit of the pre-release history, which is not in this repository. U, A, T and R read `dirty: false`; B and every set after it read `dirty: true`, because three files of another chapter's later commit reached the lab host's checkout (`common/drill/lib-drill.sh`'s pair-drill function `drill_events_archive`, `common/tests/shims-m2/_m2.py` and `common/tests/test_ch03.py`; the record journal names them as 3 files differing from the stamp). None is on a path the break, heal, attach, audit or serving trace runs; the serving drills had finished at 22:12:46 on the stamped tree. The repository's first public commit holds that code with later changes on this lab's path: the serving trace's judge reads the router's upstream only inside the request's life at the router, so a model-list read just before the request is not taken for it; the serving drills' PROBES timeline line names the gateway and endpoints probe intervals each by its own name; the VM node image's `netsetup.sh` waits for udev before it sets a bond's MAC; `make up`'s boot stage gains a last step, dns-zones, which waits for every secondary DNS zone to load; the audit's firewall NTP line names the server `show ntp` reports as synched, not the first one configured; the judge no longer reads revision 1's file names for the operator's cells, which no set here carries; and the Multus manifest's header comment names all three of its changes.

| Directory | What it holds |
|---|---|
| `sfab-ch06_record-run_20261028T201911Z/` | plain files: the chain's log, the host before and after, the plain journal of every recorded command and the typescripts it was made from, the serving recipe's and the inference step's output from `make up`'s finish stage, container start times, `state/`'s size and the containers' layers before the down, the gate on the sets `make record` does not gate, the memory watchdog's log |
| `sfab-ch06_audit_20261028T205709Z/`, `..._211034Z/`, `..._222300Z/`, `..._224944Z/`, `..._230314Z/` | the five full audits: every node's reads, both forms, `rail-backend/` and `placement/` (the serving pods, StatefulSets, volumes, Services, EndpointSlices and attachments, each pod's addresses, routes and listening sockets, the recipe's render of the table, and one answer a model through each Gateway) |
| `sfab-ch06_trace_20261028T212405Z/`, `..._231637Z/` | the two traces: `TRACE.md`, `cluster/`, `request/` (the tries, status and response headers, never a request header) and `captures/` (pcaps and their decodes) |
| `sfab-ch06_drills_20261028T212555Z/` | three passes of `dark-switch`, `worker-port` and `rail-move`, `pass<N>/<drill>/` (timeline, endpoint reads, the gateway probe's records, KLISH and cluster snapshots, the nodes' link reads, Warning events, parity, the quick audit, the analysis; for `rail-move` the moved table, the recipe's refusal and the two audits), and `DRILLS.md` |
| `sfab-ch06_break-6a_20261028T221246Z/`, `sfab-ch06_heal-6a_20261028T221416Z/`, `sfab-ch06_break-6b_20261028T223652Z/`, `sfab-ch06_heal-6b_20261028T224412Z/` | the breaks and heals: the pods, EndpointSlices, network-status and events read, the route tables and rail captures (6b), the checks, the probes |
| `sfab-ch06_attach_20261028T223637Z/` | `make attach`: each read file opens with the command that made it, at the prompt of the host that ran it; the GPU node reads run as the user admin |

Sets made before the recorded deployment are not published; `audits/INDEX.md` lists each with its RESULT line and why.

## What the deploy found

Each was met on the lab host on 2026-10-28 before the recorded deployment and fixed before it; the sets that show them are not published (`audits/INDEX.md`).

1. **The operator check still expected no nodes.** The full audit judged that the operators' group may not list nodes (the built-in `view` role reads namespaced objects only); the render now also binds the group to `operators-cluster-view`, which reads nodes and the other cluster-scoped objects and no Secret. The first recorded `make up` failed that one line (915 passed, 1 failed: `list nodes: yes`). `common/audit/judge.py` now wants `list nodes: yes` with still no create, no Secret and no delete of a node.
2. **Staff queued without bound under the probe.** On this host one of staff's copies answers an 8-token request in about half a minute idle and does not gain from batching, so the design's one request every 2 s a model queued staff's two copies: in an unrecorded pass 45 of 60 and 43 of 59 of staff's requests ended 504 at 300 s, Envoy's stream idle timeout cutting a non-streamed request whose router attempt and retry outlast it, before any fault was injected, and the quick audits after each drill timed out on staff. The gateway probe now takes `every: {MODEL: K}` (`common/drill/probe_gateway.py --every`, the render, the drill and break libraries), and this lab sends staff one request every 15th interval; chat keeps one every 2 s. One unrecorded dark-switch pass with it read 0 failed for both models.
3. **`make attach`'s DNS read had no egress.** It asked for chat-c's name from inside chat-c-server-0 with `getent`, which answered nothing (exit 2): revision 2's network policy in `serving` gives a server ingress from the router and the Gateways' Envoy and no egress, cluster DNS included, and the serving pods resolve no name. `common/reads/attach.sh` now asks the Service's own client, a router pod (its namespace and selector from `gen/trace.json`), with python3's resolver, the final dot kept (AT/dns/2-resolve.txt:1).
4. **A router's own read of a model's list reached another copy during the trace.** In the second recorded attempt, the trace `make record` ran failed one line: both router pods sent chat-b-server-0 a 233-byte request 5 s after the trace's request was answered, exactly 2.5 h after both routers started, the size of the router's own `GET /v1/models` that chapter 1's keyed walk decodes; staff's Service saw the same. The serving trace captures a pod's cluster interface at 66 bytes a frame and cannot read the request line, so `common/trace/servetrace.py` now also sets aside a router's connection to another copy's server when all its data falls more than 1 s outside the request's life at the router (from the request's arrival from the API gateway pod to the router's last data back), and names it on the line; a retry of the request falls inside that life and still fails the check. The whole sequence was then run again from wiped disks; neither trace of the recorded deployment met one (T/verdict.txt:24, :25; RT/verdict.txt:24, :25).

Facts the recordings show and a reader should know:

- **`kubectl get endpointslices -o wide` lists not-ready endpoints too** (`audits/INDEX.md`, the first note).
- **The pod's default route carries Cilium's MTU with WireGuard**, `mtu 8855`, while the pod's `eth0` and rail attachment both read MTU 9000 (A/placement/pod-chat-c-server-0-route.txt:1, pod-chat-c-server-0-addr.txt:7, :13).
- **A node-local copy's MACs age out of the rail switch.** Soon after the deploy the rail switches held every pod's MAC at the port facing its node (A/rail-sw1/12_mac_table.txt:8 to :19); by `make attach`, about 85 minutes later, rail-sw1 held only rail 7's server and worker0, the pair whose RPC crosses it (AT/switch/1-mac-table.txt:11 to :14).
- **Each drill pass's `timeline.txt`:2 misnames the endpoints probe's interval** (`audits/INDEX.md`, the second note); the label is fixed in `common/drill/lib-servedrill.sh` for the next recording.

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and the `sfab/*` images with the in-lab registry seeded, the two models in `images/models` (`make -C images models-fetch`), 178.5 GiB of MemAvailable and no other `sfab-` lab running:

```
cd ch06
make up
make audit
make trace
make drills PASSES=3
make break-6a
make heal-6a
make attach
make break-6b
make heal-6b
make record
make down
```

`make up` took 47 min 45 s here from wiped disks: boot 1158 s (the switches 537 s, the firewall 426 s), finish 881 s (the serving recipe 216 s, the API gateway and the router 64 s), the audit 803 s (N/rec-make-up.txt:291, :318, :351, :388, :397, :777, :1808). `make drills` took 46 min 51 s for three passes, `make heal-6a` 22 min 21 s, most of it rail-sw2's MAC aging and the chapter audit, and `make heal-6b` 19 min 1 s (N/chain.log:16, :20, :26). `state/` held 23388148 kB before the down (N/state-du.txt:2). On a host with faster CPUs the probe's `every` can come down; staff's answers set it.

## What the recordings do not show

- **A GPU.** The models run on CPU, split over ggml RPC workers so that chat c's traffic rides a rail; nothing here measures a GPU or publishes a throughput figure.
- **A node loss.** The placement keeps a copy of each model through the loss of either GPU node (A/verdict.txt:561 judges the table for it), but no drill here takes a node down.
- **The node-local copies leaving on hardware.** On the virtual switch a KLISH shutdown drops no carrier, so the node-local copies on rail-sw1's rails keep their in-node RPC and stay (KNOWN L9). On hardware their NICs would lose carrier and they would leave too, and each model's copy on rail-sw2's rails would answer; no recording shows that.
- **Any readiness timers but the lab's.** Every drill ran with a probe every 2 s, out after 2 failures, each up to 2 s; a removal time for any other setting is computed, not measured.
- **The probe swap** (the chapter's exercise 3) is the reader's: no target here runs it.
- **`make load`.** It is not part of this chapter's sequence; chapter 7's lab records it.
- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's; Example 6-1 opens at `cd ch06`.
- **Which copy answered a retried request.** The probe's records name the router's deployment, not the copy, so the record does not show where break-6b's two retried requests landed.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge. No recorded run exercised the redirect path a stock kernel takes (`../README.md`, "The host").
