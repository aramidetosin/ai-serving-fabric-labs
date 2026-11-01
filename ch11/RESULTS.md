# Chapter 11 results

What lab `sfab-ch11` proved on its one recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-11-01 on the first lab host (chapters 8 to 10 ran on the same host), from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `vrnetlab/truenas_truenas:27.0.0-RC.1` (d0b0a42ff2d3), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4`, `sfab/client:2`, `sfab/frr:10.5.4-3`, `sfab/registry:3`, `sfab/resolver:3` and `sfab/vpngw:3` (each id in every `RUN.json`), and in the cluster `sfab/serving:b11382-2`, `sfab/keys:4`, APISIX 3.9.1, LiteLLM v1.104.0, the identity provider and the test backend from the in-lab registry: `make down` and `make wipe` at 01:14:04, `make up` from 01:14:06 to 01:51:47, `make audit`, `make label`, `make matrix`, `make trace`, `make drills PASSES=3`, `make break-11a`, `make heal-11a`, and `make record` from 02:46:17 to 03:06:02, then `make down`. Every command ran in tmux under `script`, so each journal shows the command exactly as typed (`audits/sfab-ch11_record-run_20261101T011404Z/chain.log`). No container restarted between the end of `make up` and the end of `make record` (the start times in `audits/sfab-ch11_record-run_20261101T011404Z/startedat-*.txt` are identical, every one `restarts=0`). Times are the lab host's clock.

The short names are the index's: N is `audits/sfab-ch11_record-run_20261101T011404Z/`, U `audits/sfab-ch11_audit_20261101T013709Z/` (the audit `make up` ran), A `audits/sfab-ch11_audit_20261101T015150Z/`, L `audits/sfab-ch11_label_20261101T020626Z/`, M `audits/sfab-ch11_matrix_20261101T020644Z/`, T `audits/sfab-ch11_trace_20261101T020951Z/`, D `audits/sfab-ch11_drills_20261101T021147Z/`, B `audits/sfab-ch11_break-11a_20261101T023058Z/`, H `audits/sfab-ch11_heal-11a_20261101T023112Z/`, HA `audits/sfab-ch11_audit_20261101T023127Z/` (the chapter audit H ran), and RA `audits/sfab-ch11_audit_20261101T024617Z/`, RT `audits/sfab-ch11_trace_20261101T030042Z/`, RL `audits/sfab-ch11_label_20261101T030238Z/` and RM `audits/sfab-ch11_matrix_20261101T030253Z/` (the audit, trace, label run and matrix `make record` ran).

## What the lab proved

| Claim | Verdict lines |
|---|---|
| Every one of the 60 cells (5 populations by 12 endpoints) is in the mode the render computes: 20 allowed, 21 log lines, 3 route-set 404s and 16 silent, each tried from the population's own client by TCP connect or HTTP request, and each forbidden cell's isolation depth is the render's: 25 at depth 1, 14 at depth 2, 1 at depth 3 | M/verdict.txt:127, :128; M/MATRIX.md:4, :24 to :89 |
| The same inside VIP has a different depth from each side: from the internet users it is depth 2 (the ISP router holds no route to it, and behind that the firewall's `deny-all-log` from isp), from the internet host on the uplink side depth 1 (the uplink router routes the inside prefixes inward, and the firewall refuses it), and from the staff the internet Gateway's VIP is depth 1, held by policy alone | M/MATRIX.md:74, :75, :63, :28; `gen/matrix.yaml`:2388 to :2418 |
| The internet users reach their own Gateway and nothing else: their connect to the published address is translated and answered; chat answers 200 with their own caller's key, inetapp's, and the API gateway's access log names inetapp; staff's path and the admin hostnames are gw-inet's own 404 with no line at the API gateway; every inside address and the uplink side's internet host end at the ISP router, which holds no route to them | M/verdict.txt:98 to :125; M/api-gateway/access.txt:31; M/routers/isp-rtr-ip-route.txt:8 to :16 |
| The internet Gateway's column from every other population: the staff, the operator and the internet host are refused by `deny-all-log` with a traffic log line, the nodes are answered by their own datapath | M/verdict.txt:5, :25, :54, :55, :79; A/verdict.txt:1222 to :1225 |
| The capture ladder: every population's connect to each Gateway's VIP, with all eleven rungs capturing; each allowed SYN on exactly one leg, on the pair's port facing the lease holder (read from the MAC tables by the holder's MAC) and on the holder's VLAN 110 unit; each forbidden SYN reached the rungs before the device that refuses it and none past it; every rung's forbidden tally is zero | T/verdict.txt:1 to :23; T/TRACE.md:6 to :26 |
| One internet SYN keeps its sequence number, source and IP id from the ISP link to the lease holder: 203.0.113.2:44142, seq 3421620721, id 7980, to 198.51.100.10 on the ISP link and to 10.20.11.220 tagged VLAN 110 on leg 1, on fe-sw1's Ethernet13 and untagged on k8s-ingress1's bond0.110 | T/captures/1-isp-rtr-eth1.txt:2, :3, 3-fw-ae1-leg1.txt:98, :99, 4-fe-sw1-Ethernet13.txt:14, :15, 5-k8s-ingress1-bond0.110.txt:28, :29 |
| Isolation under load: with 8 and then 16 keep-alive HTTPS connections a population held to its own Gateway (every reply 200, each zone's session count 8 and 16, within the plan's bound), each population's own Gateway answered 10 of 10 while every forbidden try (the other Gateways' VIPs, staff's path on the internet Gateway, the admin hostnames) got 0 of 10 through, in all three passes | D/verdict.txt:6 to :24, :37 to :55, :68 to :86 |
| The one cell no network layer holds: a new key of batch, an enterprise caller, sent from inet-client through the internet Gateway to chat, is answered 200 and logged under caller batch by its own consumer; after its revoke it is refused 401; the key Secret's fields and fingerprints are the same after as before, in all three passes | D/verdict.txt:27 to :31, :58 to :62, :89 to :93 |
| The negative checks hold: no route for staff's path and no admin or identity hostname on gw-inet, no enterprise allow rule beyond the users' VIP reaching another Gateway's pool, the isp zone translated to the internet Gateway's VIP alone, the ISP router with no route into 10.0.0.0/8 | A/verdict.txt:1267 to :1272; RA/verdict.txt:1267 to :1272 |
| break-11a: with staff's path added to the internet Gateway's model route, the route's rules are no longer its audience's row and the internet users' staff request no longer gets the Gateway's own 404: it reaches the API gateway, which answers its own 404 (its routes take POST alone), told apart by Envoy's upstream header; the heal writes the rendered rule back, the staff cell is the Gateway's own 404 again, chat is allowed, and the chapter audit is green | B/verdict.txt:2 to :8; H/verdict.txt:2 to :11 |
| The audit, the trace, the decision table and the matrix after the drills, the break and the heal, on the same deployment, as before them | RA/verdict.txt:1276; RT/verdict.txt:1 to :23; RL/verdict.txt; RM/verdict.txt:127 to :129 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster and named by fingerprint only, and every keyed request hands the key to the client as a file the transcript leaves out | N/rec-make-up.txt:485 to :492; D/pass1/leaked-key/key.txt:1 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch11_audit_20261101T013709Z` (the audit `make up` ran) | `== RESULT: 1169 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| A, `sfab-ch11_audit_20261101T015150Z` (`make audit`) | `== RESULT: 1169 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| L, `sfab-ch11_label_20261101T020626Z` (`make label`) | `== RESULT: 101 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| M, `sfab-ch11_matrix_20261101T020644Z` (`make matrix`) | `== RESULT: 121 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| T, `sfab-ch11_trace_20261101T020951Z` (`make trace`) | `== RESULT: 19 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| D, `sfab-ch11_drills_20261101T021147Z` (`make drills PASSES=3`) | `== RESULT: 75 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| B, `sfab-ch11_break-11a_20261101T023058Z` (`make break-11a`) | `== RESULT: 5 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch11_heal-11a_20261101T023112Z` (`make heal-11a`) | `== RESULT: 7 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch11_audit_20261101T023127Z` (the chapter audit heal-11a ran) | `== RESULT: 1169 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RA, `sfab-ch11_audit_20261101T024617Z` (the audit `make record` ran) | `== RESULT: 1169 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RT, `sfab-ch11_trace_20261101T030042Z` (the trace `make record` ran) | `== RESULT: 19 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| RL, `sfab-ch11_label_20261101T030238Z` (the label run `make record` ran) | `== RESULT: 101 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| RM, `sfab-ch11_matrix_20261101T030253Z` (the matrix `make record` ran) | `== RESULT: 121 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA, RT, RL, RM and the repository | `== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 9 skipped` (N/rec-make-record.txt:1635) |
| `common/audit/gate.sh` on U, A, L, M, T, D, B, H and HA | `== RESULT: 54 passed, 0 failed, 0 known platform limitation(s), 19 skipped` (N/gate-sets.txt:84) |

The audits' three SKIPs are TrueNAS's view of its own bond legs, which the lab does not collect, the LAND counter, which this lab's drills plan does not name, and namecheck, which reads `skipped, no scrub list` on a host without the author's list, as on a reader's. The gates' SKIPs are namecheck and the literal scan, which needs the author's literals file.

## The result sets

All under `audits/`, each with its `RUN.json` (lab, labs commit with its dirty flag, spec and render sha256, image ids, containerlab version, host tick 10000, UTC start and end), `verdict.txt`, `RESULT.txt` and `commands.txt`. Every `RUN.json` carries one spec sha256 (`8f314deb6bce...`) and one render sha256 (`1b858d1b3d66...`), so neither changed during the deployment, and one labs commit from the checkout's stamp (FRAMEWORK.md 4.4) with `dirty: false`: a commit of the development history, which is not in this repository; the commit that adds these sets holds the same lab code.

| Directory | What it holds |
|---|---|
| `sfab-ch11_record-run_20261101T011404Z/` | plain files: `chain.log`, the host before and after, the plain journal of every recorded command and the typescripts it was made from, the files `make up`'s finish stage wrote, container start times, each VM guest's time sync, containerlab's host writes, disk and container-layer readings, the gate on the sets `make record` does not gate, the lab's memory watchdog's log and a second watcher's readings |
| `sfab-ch11_audit_20261101T013709Z/`, `..._015150Z/`, `..._023127Z/`, `..._024617Z/` | the four full audits: every node's reads, both forms, chapters 6 to 10's groups, and chapter 11's negative checks, read from the files of the audiences, split-horizon and zone-nat groups |
| `sfab-ch11_label_20261101T020626Z/`, `..._030238Z/` | the decision table's live objects, chapter 2's runner on this render: `LABELS.md` and one directory a row |
| `sfab-ch11_matrix_20261101T020644Z/`, `..._030253Z/` | the 60 cells: `MATRIX.md` with each cell's mode, depth, layers and evidence, the plan (`matrix.json`), each request and connect (`requests/`), each lookup, the firewall's traffic logs and routing table, the routers' tables and the API gateway's access log |
| `sfab-ch11_trace_20261101T020951Z/`, `..._030042Z/` | the two capture ladders: `TRACE.md`, `warmup/` (one connect a population and Gateway it may reach, before the captures), `connects/` (each flow's connects), `pair/` (the pair's MAC tables), `cluster/` (the leases) and `captures/` (every rung's pcap and decode) |
| `sfab-ch11_drills_20261101T021147Z/` | three passes of the two drills: for isolation-under-load at each load factor each population's held connections (`hold-*.jsonl`), its tries (`iso-*.jsonl`) and each zone's count while held and after the tries, with the entries' states; for leaked-key the mint and revoke logs, the timeline, every request's status, the API gateway's access log and the key Secret's fields before and after; `DRILLS.md` |
| `sfab-ch11_break-11a_20261101T023058Z/`, `sfab-ch11_heal-11a_20261101T023112Z/` | the break and the heal: the route's merge patch, the route read whole while broken and healed, the internet users' chat and staff cells with their headers and bodies and the API gateway's log; the heal's Warning events saved and cleared before its chapter audit |

Sets made on the two attempts before the recorded deployment, and the trial sets on the first, are not published; `audits/INDEX.md` lists each with its RESULT line and why.

## What the deploys found

Each was met on an attempt before the recorded deployment and fixed before the sets were published (`audits/INDEX.md`, "Sets not published").

1. **The matrix read a router with only connected routes as no table.** Its route reader matched routes via a next hop alone, and the ISP router holds only its connected links, so the internet users' eight silence cells at it read "no routing table read". The reader now takes connected and local routes too, and the cells are judged on the table as read (M/verdict.txt:99 to :102, :114 to :125).
2. **The drill counted its own probes as held load.** It read each zone's session count after the isolation tries, whose own connections to the population's own VIP stay listed, still ACTIVE, for a time after they close, so the counts were 14 to 16 where 8 were held. The held count is now read before the tries; the count after them is saved with the entries' states, recorded and not judged (D/pass1/isolation-under-load/x1/counts-held-*.txt, counts-tries-*.txt, sessions-tries-*.txt).
3. **The leaked key's log line was looked for in the wrong form.** The check wanted the access log's status as a quoted string; the API gateway writes a number. It now reads each JSON line and wants the new key's own consumer (D/verdict.txt:29).
4. **The break read a 404 as the route set's.** With staff's path on the internet Gateway, the matrix's staff request (a GET) passes the Gateway and reaches the API gateway, whose routes take POST alone, and it answers its own 404. The check wanted the status to change. It now tells the Gateway's own 404 from an upstream's by Envoy's `x-envoy-upstream-service-time` header (B/verdict.txt:7, H/verdict.txt:7).
5. **The drill wrote beside the render.** It kept its hold plan in the lab's `gen/`, a file the repository does not carry, so every later run on that copy read `dirty: true`. The plan now goes into the drill's own pass directory (D/pass1/isolation-under-load/hold-plan.json); the deployment that ran with the stray file was not published.

Facts the recordings show and a reader should know:

- **All three Gateway leases sit on one ingress node here.** k8s-ingress1 held all three in every audit and both traces (A/verdict.txt:1210 to :1212, T/TRACE.md:26). No step of this lab places them.
- **"Silence" at the ISP router is not always a timeout.** The internet users' connects to inside addresses end either at once with `Network_unreachable` or at the 4 s connect timeout, from one source port to the next (M/requests/internet-gw-users-connect-a1.txt:1, T/connects/internet-gw-users.txt:1 to :3, internet-gw-internal.txt:1 to :3). No set captures the ICMP message or the ISP router's customer side.
- **A leaked key's revoke takes effect when the API gateway reloads it.** In two of the three passes one request sent after the Secret's write was still answered 200 before the refusals began; the first 401 came 0.149 s to 2.41 s after the revoke ended. The new key itself was refused for up to about 17 s after its mint before it was first answered (D/pass1/leaked-key/requests-minted.txt, requests-revoked.txt, timeline.txt).
- **The API gateway's log says who, not from where.** Its client field is the Gateway proxy's address in the cluster, never the internet client's (D/pass1/leaked-key/api-gateway-access.txt:139).
- **The broken route still answers 404, from the layer behind.** break-11a's staff request gets the API gateway's `{"error_msg":"404 Route Not Found"}` behind Envoy, where the healed route gets the Gateway's own empty 404 (B/probes/cells-break/requests/internet-staff-request-a1-headers.txt:1 to :6, H/probes/cells-heal/requests/internet-staff-request-a1-headers.txt:1 to :4).
- **The ISP router's link to the firewall was renewed twice.** Its eth1 routes were installed again at about 02:12 and 03:02, each about when a trace ended, while its other links' routes kept their age (A, HA and RM's `isp-rtr-ip-route.txt`:9, :11); no set records a link event, and no verdict depends on it.

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` and the `sfab/*` images with the in-lab registry seeded (`sfab/keys:4` among them, `make -C images keys`), the two models in `images/models`, 196 GiB of MemAvailable (the inventory's 180 GiB budget plus the 16 GiB floor) and no other `sfab-` lab running:

```
cd ch11
make up
make audit
make label
make matrix
make trace
make drills
make break-11a
make heal-11a
make record
make down
```

`make up` took 37 min 41 s here from wiped disks: boot 784 s (the switches 332 s, the firewall 298 s, the DNS zones 33 s), finish 585 s (storage 76 s, the serving recipe 77 s, the inference step 32 s, settle 179 s), the audit 878 s (N/rec-make-up.txt:362, :389, :438, :440, :480, :483, :496, :500, :910, :2224). The running lab took about 89 GiB of the host's memory: MemAvailable read 336.2 GiB before `make up` and 247.6 GiB after `make record` (N/host-before-up.txt:4, N/host-after-record.txt:4). `state/` held 32928056 kB before the down (N/state-du.txt:2).

## What the recordings do not show

- **A GPU.** The models run on CPU, split over RPC workers; nothing here measures a GPU or publishes a throughput figure.
- **A rate.** The firewall's own measured rate and llama-server's token rates are redacted; the drills count answers and tries, never a rate.
- **A key in clear.** Every key is made in the cluster and named by fingerprint; each keyed request hands the key to its client as a file the transcript leaves out.
- **Packet tallies while broken.** break-11a records the route and two cells; it runs no ladder, so no set shows the rungs while the route was broken.
- **The ISP router's customer side.** The ladder's ISP rung is the router's link to the firewall; where the internet users' forbidden SYNs arrived at the router, and the ICMP answers some of them got, is not captured.
- **A compromised internet-facing proxy.** No cell or drill reads another audience's key from a proxy; the leaked-key drill is the recorded case of a key used outside its audience.
- **A public CA or a second public server.** inet-client trusts the lab root, so no public CA is on its path, and the platform has one public authoritative server, on a customer port of the ISP router, a lab simplification labelled in `spec/profile-a.yaml`.
- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's (`../README.md`, "Clone, build, deploy"); Example 11-1 opens at `cd ch11`.
