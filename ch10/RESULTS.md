# Chapter 10 results

What lab `sfab-ch10` proved on its one recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-10-31 on the first lab host (chapters 8 and 9 ran on the same host), from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4`, `sfab/client:2`, `sfab/frr:10.5.4-3`, `sfab/registry:3`, `sfab/resolver:3` and `sfab/vpngw:3` (each id in every `RUN.json`), and in the cluster `sfab/serving:b11382-2`, `sfab/keys:4`, APISIX 3.9.1, LiteLLM v1.104.0, the identity provider and the test backend from the in-lab registry: `make down` and `make wipe` at 18:30:06, `make up` from 18:33:28 to 19:07:32, `make audit`, `make trace`, `make hold`, `make break-10a`, `make heal-10a`, and `make record` from 19:41:57 to 19:56:47, then `make down`. Every command ran in tmux under `script`, so each journal shows the command exactly as typed (`audits/sfab-ch10_record-run_20261031T183006Z/chain.log`). No container restarted between the end of `make up` and the end of `make record` (the start times in `audits/sfab-ch10_record-run_20261031T183006Z/startedat-*.txt` are identical, every one `restarts=0`). Times are the lab host's clock.

The short names are the index's: N is `audits/sfab-ch10_record-run_20261031T183006Z/`, U `audits/sfab-ch10_audit_20261031T185444Z/` (the audit `make up` ran), A `audits/sfab-ch10_audit_20261031T190736Z/`, T `audits/sfab-ch10_trace_20261031T192013Z/`, M `audits/sfab-ch10_hold_20261031T192231Z/`, B `audits/sfab-ch10_break-10a_20261031T192529Z/`, H `audits/sfab-ch10_heal-10a_20261031T192742Z/`, HA `audits/sfab-ch10_audit_20261031T192908Z/` (the chapter audit H ran), RA `audits/sfab-ch10_audit_20261031T194157Z/` and RT `audits/sfab-ch10_trace_20261031T195429Z/` (the audit and trace `make record` ran).

## What the lab proved

| Claim | Verdict lines |
|---|---|
| One routing table holds every interface: the firewall has one virtual router, `core`, with the bundle's six units, the BMC subnet, both enterprise ports, the uplink's default route, the tunnel and the ISP link with its customers' route; each interface is in exactly one zone | A/fw/13_routing_route.txt:7 to :38; A/fw/05_interface_all.txt:24 to :39; A/verdict.txt:1079 to :1089 |
| The internet users are translated, keyed on their arrival zone: `dnat-internet-gateway`, first of the NAT rulebase, is the `isp` zone's only translation (from isp to isp, 198.51.100.10 on tcp/443 to 10.20.11.220), and `isp-to-internet-gateway`, rule 24, is the zone's only allow rule (the pre-NAT address, the post-NAT zone `ingress`, ssl); both rulebases run in the rendered order and the predefined defaults after `deny-all-log` deny | A/verdict.txt:1090 to :1094, :1190 to :1195; A/fw/15_running_nat.txt:4 to :16; A/fw/14_running_security.txt:440 to :457 |
| The staff and the operator are untranslated: each reaches its own Gateway's VIP under its own rule with no NAT rule, from its own zone | T/verdict.txt:13 to :33; T/TRACE.md:8 to :10 |
| The published address from inside is not translated and is refused: the staff client and a node meet `deny-all-log` from their own zone to `isp`, and the operator's connect dies at the uplink router, which holds no route to it | A/verdict.txt:1197 to :1199; A/zone-nat/traffic-log-443.txt:6 to :37 |
| One internet SYN through the destination NAT keeps its source address, sequence number and IP id: on the ISP link it is 203.0.113.2:42936 to 198.51.100.10:443, and on exactly one leg of the bundle, tagged VLAN 110, it is 203.0.113.2:42936 to 10.20.11.220:443; the session entry holds both flows, the NAT rule, the security rule, ingress ethernet1/6 and egress ae1.110 | T/verdict.txt:2 to :12; T/captures/internet/1-isp-rtr-eth1.txt:2, :3, 3-fw-ae1-leg2.txt:2, :3; T/sessions/internet/session-detail.txt:2 to :50 |
| The pinned release prints its TCP timeouts in `show session info`: default 3600 s, before SYN-ACK 5 s, before the handshake 10 s, half-closed 30 s (PAN-OS 12.1 help gives 120 s), TIME_WAIT 15 s, and 90 s for a TCP session in the discard state; a held HTTPS session carries the ssl application's 1800 s | M/verdict.txt:13 to :19; M/session-info-held.txt:26 to :44; T/sessions/internet/session-detail.txt:23 |
| Each zone holds what its held connections need: 8 keep-alive HTTPS connections a population, held the whole 120 s and used every 20 s (48 replies each, every one 200), are 8 sessions a zone while held and 9 with the population's chat request, within the plan's bound; Little's law from the run's own events predicts 7.9 a zone | M/verdict.txt:1 to :12; M/HOLD.md:6 to :20; M/counts-held-*.txt:2, counts-chat-*.txt:2 |
| break-10a: with `isp-to-internet-gateway` naming the translated address 10.20.11.220 in place of the published one, the NAT rule still translates and no rule matches, so every internet request fails, the internet SYNs reach the ISP link and neither leg, and the log names `deny-all-log` from isp to ingress; the staff are unaffected; the heal writes the published address back, every internet connect is allowed under `isp-to-internet-gateway`, and the chapter audit is green | B/verdict.txt:2 to :13; B/record/broken-fw1-show_running_security_policy.txt:444, check-break-tlog-syn.txt:6 to :9; H/verdict.txt:2 to :16 |
| The trace and the audit after the break and the heal, on the same deployment, as before them | RA/verdict.txt:1190 to :1210; RT/verdict.txt:1 to :34 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster and named by fingerprint only, and the hold's chat requests hand the key to the client as a file the transcript leaves out | N/rec-make-up.txt:456 to :463; M/chat-*-key.txt |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch10_audit_20261031T185444Z` (the audit `make up` ran) | `== RESULT: 1108 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| A, `sfab-ch10_audit_20261031T190736Z` (`make audit`) | `== RESULT: 1108 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| T, `sfab-ch10_trace_20261031T192013Z` (`make trace`) | `== RESULT: 29 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| M, `sfab-ch10_hold_20261031T192231Z` (`make hold`) | `== RESULT: 15 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| B, `sfab-ch10_break-10a_20261031T192529Z` (`make break-10a`) | `== RESULT: 10 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch10_heal-10a_20261031T192742Z` (`make heal-10a`) | `== RESULT: 11 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch10_audit_20261031T192908Z` (the chapter audit heal-10a ran) | `== RESULT: 1108 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RA, `sfab-ch10_audit_20261031T194157Z` (the audit `make record` ran) | `== RESULT: 1108 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RT, `sfab-ch10_trace_20261031T195429Z` (the trace `make record` ran) | `== RESULT: 29 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA and RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:1314) |
| `common/audit/gate.sh` on U, A, T, M, B, H and HA | `== RESULT: 42 passed, 0 failed, 0 known platform limitation(s), 15 skipped` (N/gate-sets.txt:66) |

The audits' three SKIPs are the LAND counter, which this lab's drills plan does not name, the web population's cell at the internet Gateway, since this lab's slice has no client of that population, and namecheck, which reads `skipped, no scrub list` on a host without the author's list, as on a reader's. The gates' SKIPs are namecheck and the literal scan, which needs the author's literals file.

## The result sets

All under `audits/`, each with its `RUN.json` (lab, labs commit with its dirty flag, spec and render sha256, image ids, containerlab version, host tick 10000, UTC start and end), `verdict.txt`, `RESULT.txt` and `commands.txt`. Every `RUN.json` carries one spec sha256 (`8f314deb6bce...`) and one render sha256 (`d3615a1d5599...`), so neither changed during the deployment, and one labs commit from the checkout's stamp (FRAMEWORK.md 4.4) with `dirty: false`: a commit of the development history, which is not in this repository; the commit that adds these sets holds the same lab code with one redaction rule added (below).

| Directory | What it holds |
|---|---|
| `sfab-ch10_record-run_20261031T183006Z/` | plain files: `chain.log`, the host before and after, the plain journal of every recorded command and the typescripts it was made from, the serving recipe's and the inference step's output from `make up`'s finish stage, container start times, each VM guest's time sync, containerlab's host writes, disk and container-layer readings, the gate on the sets `make record` does not gate, the lab's memory watchdog's log and a second watcher's readings |
| `sfab-ch10_audit_20261031T185444Z/`, `..._190736Z/`, `..._192908Z/`, `..._194157Z/` | the four full audits: every node's reads, both forms, chapters 6 to 9's groups, and chapter 10's `zone-nat/` (the running NAT and security rulebases, each inside population's connect to the published address and the traffic log, the uplink router's table, the group's own held connections with each zone's count and `show session info`) |
| `sfab-ch10_trace_20261031T192013Z/`, `..._195429Z/` | the two zone-keyed NAT traces: `TRACE.md`, `warmup/` (one connect per population before the captures), `sessions/<population>/` (the held request, `show session all` and `show session id` in CLI and XML, the traffic log) and `captures/<population>/` (the ISP router's link or the firewall's enterprise port, and both legs of the bundle; pcaps and their decodes) |
| `sfab-ch10_hold_20261031T192231Z/` | the measurement: `HOLD.md` with Little's law per zone, each client's events (`hold-<population>.jsonl`), each zone's count and `show session info` before, held, after the chat and after the stop, the entries still listed after the stop with their states (`sessions-after-*.txt`), each chat request's status and the key's fingerprint |
| `sfab-ch10_break-10a_20261031T192529Z/`, `sfab-ch10_heal-10a_20261031T192742Z/` | the break and the heal: the rule's edit and commit, the running security and NAT rulebases while broken and healed, the internet and staff requests, the pinned-port connects captured on the ISP router's link and both legs, the traffic log; the heal's Warning events saved and cleared before its chapter audit |

Sets made on the attempt before the recorded deployment, and the trial sets on it, are not published; `audits/INDEX.md` lists each with its RESULT line and why.

## What the deploys found

Each was met on the attempt before the recorded deployment, or on its sets after recording, and fixed before the sets were published (`audits/INDEX.md`, "Sets not published").

1. **The measurement stopped its connections early.** `hold.sh` stopped every client's load as soon as the chat requests were done, about 40 s in, while its verdict and `HOLD.md` said the connections were held 120 s; the run's own events showed a mean hold of 40.6 s. A line its own files contradict is not published. The run now waits for each client to end its own load at the plan's hold before the stop, and the recorded window and mean hold are the plan's (M/HOLD.md:18 to :20).
2. **`HOLD.md` claimed a term the release does not show.** It said a denied attempt holds its entry for the discard timeout, so a zone's denied arrivals add to its total; on the pinned release a SYN refused by `deny-all-log` at its first packet leaves no session. It now states the discard timeout as `show session info` prints it and that the run makes no denied attempt (M/HOLD.md:22).
3. **The firewall prints its own rate.** `show session info`'s `Throughput:` line carries the dataplane's measured rate in kbps, a form the throughput rule did not catch. The repository publishes no throughput figure: the value was replaced with `[redacted: throughput]` in the recorded sets after recording (each set's `REDACTIONS.md`), and `redact.py` now replaces it while a set is recorded. The packet and connection rates on the same output are kept.
4. **A warm-up for the trace.** As a precaution against the pair flooding a frame whose MAC it has aged out (spec/known.yaml L1, met by chapter 9's trace), the trace now makes one uncaptured connect per population before its captures; the attempt's trace did not meet the flood (each SYN on one leg), and the recorded one does not either (T/verdict.txt:12, :23, :33).

Facts the recordings show and a reader should know:

- **All three Gateway leases sit on one ingress node here.** In every audit of this deployment k8s-ingress1 held the leases of gw-inet, gw-internal and gw-users (A/verdict.txt:1151 to :1153); chapter 9's recording had gw-inet's on k8s-ingress2. No step of this lab places them.
- **The broken rule's denials carry the post-NAT zone.** During break-10a the log names `deny-all-log` from `isp` to `ingress`, not to `isp`: the translation ran before the security lookup, and no rule from isp to ingress names the address the session held before translation (B/record/check-break-tlog-syn.txt:6 to :9). The staff's connect to the same published address, never translated, is denied from `enterprise` to `isp` (A/zone-nat/traffic-log-443.txt:22 to :37).
- **The rule column is 19 characters wide.** The traffic log prints `isp-to-internet-gateway` as `isp-to-internet-gat`; `show session id` prints the whole name (T/sessions/internet/traffic-log.txt:7, session-detail.txt:31).
- **The firewall rewrites the SYN's MSS.** Every SYN reached the bundle leg with MSS 1360, from 9460 on the ISP link and 1460 from the staff client (T/captures/internet/1-isp-rtr-eth1.txt:3, 3-fw-ae1-leg2.txt:3; T/captures/enterprise/2-fw-ethernet1-4.txt:3, 3-fw-ae1-leg1.txt:3); source, sequence number and IP id are kept.
- **A closed connection stays listed a few seconds.** The first read after the clients closed listed the staff's 8 sessions as ACTIVE, and every count read 5 s later and after was 0 (M/sessions-after-enterprise.txt:6 to :21, M/counts-after-*.txt:2).

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and the `sfab/*` images with the in-lab registry seeded (`sfab/keys:4` among them, `make -C images keys`), the two models in `images/models`, 179.75 GiB of MemAvailable (the inventory's 163.75 GiB budget plus the 16 GiB floor) and no other `sfab-` lab running:

```
cd ch10
make up
make audit
make trace
make hold
make break-10a
make heal-10a
make record
make down
```

`make up` took 34 min 4 s here from wiped disks: boot 776 s (the switches 272 s, the firewall 357 s, the DNS zones 28 s), finish 487 s (the serving recipe 70 s, the inference step 27 s, settle 171 s), the audit 768 s (N/rec-make-up.txt:341, :368, :415, :417, :454, :467, :471, :869, :2115). The running lab took about 79 GiB of the host's memory: MemAvailable read 336.2 GiB before `make up` and 257.4 GiB after `make record` (N/host-before-up.txt:4, N/host-after-record.txt:4). `state/` held 23575404 kB before the down (N/state-du.txt:2).

## What the recordings do not show

- **A GPU.** The models run on CPU, split over RPC workers; nothing here measures a GPU or publishes a throughput figure.
- **A rate.** The firewall's own measured rate is redacted, `HOLD.md` prints no request or connection rate (the packet and connection rates on `show session info`'s output are kept as the firewall printed them), and the arrivals in `HOLD.md` are the plan's own load, not a measure of what the path can carry.
- **A key in clear.** Every key is made in the cluster and named by fingerprint; the hold hands each key to its client as a file the transcript leaves out.
- **The API gateway's line for an internet caller.** No set saves the API gateway's access line for the internet population's caller; the firewall's log and the captures carry the internet client's own address.
- **A denied attempt holding a session.** No step here makes a denied attempt and reads the session table for it; the discard timeout is the value `show session info` prints.
- **A documented ceiling.** `show session info` prints this VM's supported-sessions figure (M/session-info-held.txt:4); it is the lab VM's, not a model's documented ceiling.
- **A public CA or a second public server.** inet-client trusts the lab root, and the platform has one public authoritative server, on a customer port of the ISP router; both are lab simplifications, labelled in `README.md`.
- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's (`../README.md`, "Clone, build, deploy"); Example 10-1 opens at `cd ch10`.
