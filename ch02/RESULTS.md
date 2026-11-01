# Chapter 2 results

What lab `sfab-ch02` proved on its two recorded deployments under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The earlier deployment ran on 2026-10-29 from wiped disks, at host tick 10000 on containerlab 0.82.0, on the second lab host, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `vrnetlab/truenas_truenas:27.0.0-RC.1` (d0b0a42ff2d3), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4` (0e82fde37b3d), `sfab/client:2` (737f846b3e7f), `sfab/resolver:3` (d0fabd25e229), `sfab/registry:3` (74db9faf8fd4), `sfab/vpngw:3` (d5db2071ca65) and `sfab/frr:10.5.4-3` (234239dc64b1), the ten its `RUN.json` files name, and in the cluster the serving image `sfab/serving:b11382-2` with the models LFM2.5-24B-A2B (chat) and Qwen3.8-27B (staff), the keys image, the API gateway, the router and the test backend from the in-lab registry. One chain ran every command in tmux under `script`, so each journal shows the command exactly as typed (`audits/INDEX.md` gives the times). No container restarted between the end of `make up` and the end of `make record`: all 28 read `restarts=0` with the same start times after `make up` and after `make record` (`audits/sfab-ch02_record-run_20261029T190618Z/startedat-after-up.txt`, `startedat-after-record.txt`). Times are the lab host's clock, UTC. No set carries a `host-tick` stamp.

The deployment from the public repository ran on 2026-11-01 from wiped disks, from a clone of https://github.com/aramidetosin/ai-serving-fabric-labs at commit `117812b3b322acd33b6c7b80cdd8416f5259a43d` with no tracked file changed (every `RUN.json` of its sets reads that commit, `dirty: false`), at host tick 10000 on containerlab 0.82.0, with the same images at the same IDs and the same two models. Its chain began with the reader's `git clone` of that URL, recorded under `script` (`audits/sfab-ch02_record-run_20261101T111531Z/rec-git-clone.txt`), then `make down`, `make wipe`, `make up`, `make audit`, `make trace`, `make label`, `make matrix`, `make break-2a`, `make heal-2a`, `make record` and `make down`, every step 0 failed. It carries the book's launch, launch audit and closing exhibits (Examples 2-1, 2-2, 2-11 and 2-12); the earlier deployment carries the others. Its short names start with C (`audits/INDEX.md`, "The deployment from the public repository"): CN `audits/sfab-ch02_record-run_20261101T111531Z/`, CU `audits/sfab-ch02_audit_20261101T120238Z/`, CA `audits/sfab-ch02_audit_20261101T122021Z/`, CT `audits/sfab-ch02_trace_20261101T123813Z/`, CL `audits/sfab-ch02_label_20261101T124225Z/`, CM `audits/sfab-ch02_matrix_20261101T124304Z/`, CB `audits/sfab-ch02_break-2a_20261101T124807Z/`, CH `audits/sfab-ch02_heal-2a_20261101T124927Z/`, CHA `audits/sfab-ch02_audit_20261101T125037Z/`, and CRA, CRT, CRL and CRM `audits/sfab-ch02_audit_20261101T130804Z/`, `audits/sfab-ch02_trace_20261101T132537Z/`, `audits/sfab-ch02_label_20261101T132948Z/` and `audits/sfab-ch02_matrix_20261101T133029Z/`.

The earlier deployment's short names are the index's: N is `audits/sfab-ch02_record-run_20261029T190618Z/`, U `audits/sfab-ch02_audit_20261029T195216Z/` (the audit `make up` ran), A `audits/sfab-ch02_audit_20261029T200955Z/`, T `audits/sfab-ch02_trace_20261029T202730Z/`, L `audits/sfab-ch02_label_20261029T203133Z/`, M `audits/sfab-ch02_matrix_20261029T203212Z/`, B `audits/sfab-ch02_break-2a_20261029T203645Z/`, H `audits/sfab-ch02_heal-2a_20261029T203804Z/`, HA `audits/sfab-ch02_audit_20261029T203913Z/` (the chapter audit H ran), and RA `audits/sfab-ch02_audit_20261029T205639Z/`, RT `audits/sfab-ch02_trace_20261029T211401Z/`, RL `audits/sfab-ch02_label_20261029T211803Z/` and RM `audits/sfab-ch02_matrix_20261029T211842Z/`, the audit, trace, label run and matrix `make record` ran.

## Revision 2, against revision 1

Revision 1's sets (one deployment on 2026-10-27) are superseded and out of the repository (`audits/INDEX.md`, "Superseded sets"). What revision 2 changes in what the chapter shows:

| Part | Revision 1 | Revision 2 |
|---|---|---|
| Node names | ctrl1 to ctrl3, gpu1, gpu2; 18 containers | k8s-cp1 to k8s-cp3, k8s-gpu1, k8s-gpu2, the ingress nodes, the DNS and time servers, ops-gw and the web client; 28 containers |
| The view row | three views on the bastion | the authoritative pair dns-auth1 (primary) and dns-auth2 (by transfer) with the internal and enterprise views; ops-dns on the uplink side publishing no platform name, so the operator and the internet host get NXDOMAIN for the users' name |
| The routing row | six connected subnets and the default route; the uplink router's five routes | ten connected subnets, the default, the route to the operator's site through tunnel.1 and three discard routes for RFC 1918 space; the uplink router's nine static routes, each labelled |
| NAT | three rules, the operator's destination NAT among them | two: `no-nat-public` and `internet-snat`, from the inside zones to uplink only |
| Security policy | fifteen rules, port-based services | 24 rules, every allow an App-ID, closing with `deny-all-log`; PAN-OS prints its predefined rules after it as `vsys1+intrazone-default` and `vsys1+interzone-default`, overridden to log |
| The key row | a consumer group per model | a consumer group per caller: the batch and helpdesk applications (keys) and the staff people (an OIDC consumer) |
| The matrix | three populations by ten endpoints, 30 cells: 15 allowed, 14 log lines, one 404, none silent | four populations (the internet host added) by eleven endpoints (an egress column added), 44 cells: 17 allowed, 18 log lines, one 404, eight silent; six requests with another caller's key, each 401 `Authorization Failed` |
| The forwarding-only switches | KLISH lists only Management0 | the pair members also hold their two keepalive /31s in VRF VrfMclagKa and nothing else; the default table empty on every switch |
| The audit | 691 checks | 1036 |
| break-2a | the bastion's enterprise view, 10.20.1.210 to 10.20.1.200 | dns-auth1's enterprise view, dns-auth2 by transfer, 10.20.11.210 to 10.20.11.200; the heal makes dns-auth2 transfer again (`rndc retransfer`), since the rendered serial is behind the break's |

## What the lab proved

| Claim | Verdict lines |
|---|---|
| Build A deploys whole from wiped disks in one `make up`: 28 containers, every switch with its KLISH startup configuration applied and in parity with the render, the firewall's delivered configuration byte for byte as rendered, the IPsec tunnel to the operator's site, the cluster, storage, the serving recipe, the API gateway and the router, then an audit with no FAIL | N/rec-make-up.txt:41, :313, :390, :453, :854, :2020; A/verdict.txt:70, :77, :158, :169 to :173 |
| The pair, both rail switches and the out-of-band switch forward only: the default table empty, no `router` line, no address on any served VLAN, PortChannel or host port, no router block in FRR and no address in the kernel but, on a pair member, its two keepalive /31s in VRF VrfMclagKa | A/verdict.txt:363 to :417; L/verdict.txt:90 to :100 |
| Every row of the decision table has a live object carrying its decision id: the views answering each population's client (NXDOMAIN from the public view) and each zone file labelled; the firewall's connected subnets, default, tunnel and discard routes; the uplink router's nine static routes, each with its comment line; both rulebases in the render's order with each rule's description its id, `deny-all-log` the last rule before PAN-OS's predefined rules; all five HTTPRoutes labelled; each caller's consumer group labelled and its consumer present; every pod of each copy labelled and each rail attachment annotated; each switch's startup file labelled forwarding only | L/verdict.txt:1 to :101; L/LABELS.md:8 to :86 (`audits/INDEX.md`, "Notes", the label summary) |
| Every cell of the matrix is in its planned mode with its evidence: 44 cells, 17 allowed and 27 forbidden, 18 log lines from `deny-all-log` with the zones the plan computes, one 404 from the users' Gateway with no line in the API gateway's log, eight silent (the firewall's discard route, zone protection's strict IP check, the uplink router without a route); every model cell's other caller's key refused with `Authorization Failed`; the nodes' VIP cells answered on the node, with no firewall log line | M/verdict.txt:1 to :94; M/MATRIX.md:4 to :68 |
| One chat completion from the enterprise client, walked inward with each hop tagged with its row: the enterprise view, the firewall's connected route, no NAT rule from `enterprise`, `staff-to-users-gateway`, one leg of ae1 and one pair member bridging, the users' Gateway's route, the caller's key, the Service's pick and chat's copy a on rail 3; and the three refusals, each at its row | T/verdict.txt:1 to :76; T/TRACE.md:9 to :32 |
| break-2a: with the enterprise view answering `admin` and `grafana` with the internal Gateway's VIP, every user request is still answered, the staff's admin cell moves from the users' Gateway's 404 to a `deny-all-log` line and a timeout, and the other three cells stay allowed; the heal puts the rendered zones back on both servers, the cell returns to the 404, and the chapter audit is green | B/verdict.txt:2 to :14; H/verdict.txt:2 to :16 |
| The audit, trace, label run and matrix after the break and heal, on the same deployment, as before them | RA/verdict.txt:1133; RT/verdict.txt:76; RL/verdict.txt:101; RM/verdict.txt:94 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster, handed to each client through pipes into a 0600 file, and named by fingerprint and keyed mark only | N/rec-make-up.txt:437 to :441; L/verdict.txt:74, :76; T/verdict.txt:2, :3 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch02_audit_20261029T195216Z` (the audit `make up` ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| A, `sfab-ch02_audit_20261029T200955Z` (`make audit`) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| T, `sfab-ch02_trace_20261029T202730Z` (`make trace`) | `== RESULT: 57 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| L, `sfab-ch02_label_20261029T203133Z` (`make label`) | `== RESULT: 91 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| M, `sfab-ch02_matrix_20261029T203212Z` (`make matrix`) | `== RESULT: 87 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| B, `sfab-ch02_break-2a_20261029T203645Z` (`make break-2a`) | `== RESULT: 10 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch02_heal-2a_20261029T203804Z` (`make heal-2a`) | `== RESULT: 11 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch02_audit_20261029T203913Z` (the chapter audit heal-2a ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RA, `sfab-ch02_audit_20261029T205639Z` (the audit `make record` ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RT, `sfab-ch02_trace_20261029T211401Z` (the trace `make record` ran) | `== RESULT: 57 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| RL, `sfab-ch02_label_20261029T211803Z` (the label run `make record` ran) | `== RESULT: 91 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| RM, `sfab-ch02_matrix_20261029T211842Z` (the matrix `make record` ran) | `== RESULT: 87 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA, RT, RL, RM and the repository | `== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 9 skipped` (N/rec-make-record.txt:1508) |
| `common/audit/gate.sh` on U, A, T, L, M, B, H and HA | `== RESULT: 48 passed, 0 failed, 0 known platform limitation(s), 17 skipped` (N/gate-sets.txt:75) |
| the clean-up `make down` and `make wipe` | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (N/rec-clean-down.txt:1204); `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (N/rec-clean-wipe.txt:10) |
| the closing `make down` | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (N/rec-make-down.txt:1205) |
| CU, `sfab-ch02_audit_20261101T120238Z` (the audit `make up` ran, from the public repository) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| CA, `sfab-ch02_audit_20261101T122021Z` (`make audit`) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| CT, `sfab-ch02_trace_20261101T123813Z` (`make trace`, chat's copy a) | `== RESULT: 57 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CL, `sfab-ch02_label_20261101T124225Z` (`make label`) | `== RESULT: 91 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CM, `sfab-ch02_matrix_20261101T124304Z` (`make matrix`) | `== RESULT: 87 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CB, `sfab-ch02_break-2a_20261101T124807Z` (`make break-2a`) | `== RESULT: 10 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CH, `sfab-ch02_heal-2a_20261101T124927Z` (`make heal-2a`) | `== RESULT: 11 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CHA, `sfab-ch02_audit_20261101T125037Z` (the chapter audit heal-2a ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| CRA, `sfab-ch02_audit_20261101T130804Z` (the audit `make record` ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| CRT, `sfab-ch02_trace_20261101T132537Z` (the trace `make record` ran, chat's copy c) | `== RESULT: 63 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CRL, `sfab-ch02_label_20261101T132948Z` (the label run `make record` ran) | `== RESULT: 91 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CRM, `sfab-ch02_matrix_20261101T133029Z` (the matrix `make record` ran) | `== RESULT: 87 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on CRA, CRT, CRL, CRM and the repository | `== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 9 skipped` (CN/rec-make-record.txt:1506) |
| `common/audit/gate.sh` on CU, CA, CT, CL, CM, CB, CH and CHA | `== RESULT: 48 passed, 0 failed, 0 known platform limitation(s), 17 skipped` (CN/gate-sets.txt:75) |
| the clean-up `make down` and `make wipe` of that deployment | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (CN/rec-clean-down.txt:1202); `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (CN/rec-clean-wipe.txt:10) |
| its closing `make down` | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (CN/rec-make-down.txt:1202) |

Every `RUN.json` of the earlier deployment carries one spec sha256 (`c165f4c98695...`) and one render sha256 (`5c5cc19b62b1...`), so neither changed during the deployment, and containerlab 0.82.0. The labs repository commit in each, from the checkout's stamp (FRAMEWORK.md 4.4), is a commit of the pre-release history, which is not in this repository, with `dirty: true`: the runs used that commit plus uncommitted work, this lab's fixes below among it, and the repository's first public commit holds that code with the later changes `audits/INDEX.md` names. Every `RUN.json` of the deployment from the public repository names the public commit `117812b3`, `dirty: false`, with one spec sha256 (`8f314deb6bce...`) and one render sha256 (`4b9e209e1324...`).

## What the deploys found

One revision 2 deployment on this host stopped before the recorded one; each fault was fixed in the lab code with `make test-quick` green and tried on that deployment outside the chain; then the sequence started again from `make down` and `make wipe`. Its sets are not published (FRAMEWORK.md 4.4).

1. **The label plan still read revision 1's design** (`sfab-ch02_label_20261029T174129Z`, 81 passed, 10 failed). It wanted ops-dns's public view to answer the users' hostname (revision 2 publishes no platform name there: the server answers NXDOMAIN, and its zone file carries the view's label in its header only), wanted PAN-OS's predefined rules by their bare names (revision 2 overrides them to log, and PAN-OS then prints them as `vsys1+intrazone-default`), read the consumer groups by revision 1's "the keys for model" desc, and looked for the staff people's consumer among the composed keys (it is an `oidc-consumer` in the routes). And the uplink router's route to the operator's site carried no decision line, where the decision table derives one. `common/sfab/render/decisions.py`'s label plan, `common/matrix/label.py` and `common/sfab/render/frr.py` were fixed: in a decisions lab a route without its own decision now carries the derived one, so only this lab's `bootstrap/uplink-rtr/frr.conf` changed.
2. **A cluster node's connect to a Gateway VIP never reaches the firewall** (`sfab-ch02_matrix_20261029T175638Z`, 80 passed, 2 failed). The plan wanted the nodes' Users' Gateway cell refused under `deny-all-log`; it connected in under a millisecond. k8s-cp2 is a node of the cluster, and Cilium, which replaces kube-proxy, translates the VIP to a Gateway pod at connect(): a tcpdump on k8s-cp2 saw no packet to 10.20.11.210 while the connect succeeded (an unrecorded check), and the firewall logged nothing for it while it logs the operator's allowed requests to the same VIP. `decisions.py`'s path now models a cluster node asking its own cluster's Gateway VIP as answered on the node, and `common/matrix/matrix.py` asserts that no traffic-log line names such a cell's source port. Table 2-2 moved from 16 allowed and 19 log lines to 17 and 18.
3. **The heal's serial was behind the break's** (`sfab-ch02_heal-2a_20261029T181627Z`, 9 passed, 2 failed, and its chapter audit 1033 passed, 3 failed). The zone's serial follows its data: the break's enterprise zone had 756238120, the rendered one 261946292, behind it in RFC 1982 serial arithmetic, so dns-auth2 kept the break's zone and ignored the NOTIFY. `common/break/breakheal.sh` now tells the secondary to `rndc retransfer` the zone when the primary's serial is behind after 10 s; the next break and heal on that deployment passed (10 and 11, the chapter audit 1036).

4. **The matrix's delta view missed the strict IP drops** (the deployment from the public repository, its first attempt: `make record`'s matrix 82 passed, 5 failed). The matrix read the four operator cells that zone protection's strict IP check drops from the drop counters' delta view, read before the requests and after them. The view read after them began its sampling 76.9 s before it was read, 194 s after its baseline and after the four cells' drops, so it did not list `flow_dos_pf_strictip`, and on the same deployment, with nothing of the lab reading counters, three reads of the view 251 s apart showed the firewall starting a new sampling between two of them on its own. The cells were dropped as planned: no log line, every client timed out. `common/matrix/matrix.sh` now reads every counter's value (`show counter global filter value all`) before and after the requests (`fw/counters-before.txt`, `fw/counters-after.txt`) and `matrix.py` judges the rise between them, the delta view recorded beside them; a matrix on that deployment with the fix read 87 passed, 0 failed, and the deployment was then taken down and the chain started again from `make down` and `make wipe`. Its sets are not published.

Facts the recordings show and a reader should know (`audits/INDEX.md`, "Notes", has the lines):

- **The nodes' VIP cells are answered on the node**, so `nodes-to-internal-gateway` is on no matrix cell's path.
- **A silence at the uplink router reaches the client as `Network_unreachable`** within about a millisecond: a router on the path answers with an unreachable, which no set captured.
- **The earlier deployment's walks took the same leg**, ethernet1/2 and fe-sw2, to k8s-ingress2, and landed on node-local copies (T on chat a, RT on chat b), so neither crossed a rail switch.
- **The deployment from the public repository's walks** took leg 1 and fe-sw1 to chat's node-local copy a (CT) and leg 2 and fe-sw2 to the spanning copy c (CRT), whose RPC crossed rail-sw1 on rail 7; its two Gateway VIPs' leases were on k8s-ingress1 (gw-internal) and k8s-ingress2 (gw-users).
- **containerlab's writes on the host.** While the lab ran, containerlab's block in `/etc/hosts` and its SSH configuration file named every node (N/clab-writes-before-down.txt); `make down` removed both (N/host-after-down.txt:11, :12).

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` and the `sfab/*` images with the in-lab registry seeded, the two models in `images/models`, 195 GiB of MemAvailable and no other `sfab-` lab running:

```
git clone https://github.com/aramidetosin/ai-serving-fabric-labs.git
cd ai-serving-fabric-labs/ch02
make up
make audit
make trace
make label
make matrix
make break-2a
make heal-2a
make record
make down
```

On the earlier deployment `make up` took 56 min 16 s from wiped disks: boot 1153 s (the switches 507 s, the ICCP listeners 4 s, the firewall 488 s), finish 1149 s (storage 132 s, the serving recipe 235 s, the API gateway and the router 70 s, the settle 235 s, the Warning events 109 s), the audit 1049 s (N/rec-make-up.txt:1, :324, :342, :351, :391, :432, :435, :444, :448, :452, :856, :2022, :2024). `make audit` took 17 min 35 s, `make trace` 4 min 3 s, `make label` 38 s, `make matrix` 4 min 32 s, `make break-2a` 1 min 20 s, `make heal-2a` 18 min 33 s with its chapter audit, `make record` 26 min 40 s and the closing `make down` 3 min 30 s (N/chain.log). `state/` held 32G after `make record` (N/host-after-record.txt:16). These times are the second lab host's, whose CPUs serve the models more slowly than the first's.

## What the recordings do not show

- **A GPU.** The models run on CPU, split over RPC workers for the one spanning copy; nothing here measures a GPU or publishes a throughput figure.
- **A key in clear.** Every key is made in the cluster and every capture that could hold one is scrubbed before it is written.
- **A `git clone` line in the earlier deployment.** Its chain began at `make down`; the recorded clone is the deployment from the public repository's (CN/rec-git-clone.txt), which made a clone of its own in an empty directory and deployed from a clone of the same commit and tree (CN/clone-check.txt:2 to :7).
- **A capture of a silent cell.** The matrix records each silence by the route table, the drop counter and the absent log line, not by a capture at the hop, and not the unreachable a router returned for the uplink router's cells.
- **The packet path inside a cluster node.** That Cilium translates the VIP at connect() rests on the render (`kubeProxyReplacement`), the connect's time and the absent log line; the tcpdump that saw no packet to the VIP was an unrecorded check.
- **Exercise 2's cell with logging off.** The lab records `deny-all-log` with logging on only.
- **A public commit in the earlier deployment's `RUN.json`.** Each of its `RUN.json` files names, from the copy's stamp, a commit of the pre-release history, which is not in this repository, with `dirty: true`; the runs used that commit plus the uncommitted changes `audits/INDEX.md` names, and the repository's first public commit holds that code with the later changes the same page names. The deployment from the public repository's `RUN.json` files name the public commit `117812b3`, `dirty: false`.
- **A `make up` on kept disks.** The recorded deployment came from wiped disks.
- **The many-tenant state.** This lab is build A with one tenant; the other audiences and their isolation come with chapters 8 to 11.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge. No recorded run exercised the redirect path a stock kernel takes (`../README.md`, "The host").
