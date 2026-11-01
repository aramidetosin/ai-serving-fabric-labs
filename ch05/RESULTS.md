# Chapter 5 results

What lab `sfab-ch05` proved on its two recorded deployments under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The earlier deployment ran on 2026-10-29 from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277) and `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669). Every command ran in tmux under `script`, so each journal shows the command exactly as typed: `make down` and `make wipe` at 00:00:46, `make up` from 00:02:47 to 00:10:29, `make audit`, `make trace`, `make drills PASSES=3`, `make break-5a`, `make heal-5a`, `make rpf`, `make record` from 00:20:21 to 00:21:50, and `make down` to 00:21:58 (`audits/sfab-ch05_record-run_20261029T000046Z/chain.log`). No container restarted between the end of `make up` and the end of `make record` (the start times in `audits/sfab-ch05_record-run_20261029T000046Z/startedat-*.txt` are identical, every one `restarts=0`). Times are the lab host's clock, UTC. The deployment ran on the first of the book's two lab hosts, the one where the serving timers were measured; preflight read 116.6 GiB available against the lab's 55.0 GiB and the 16.0 GiB floor (N/rec-make-up.txt:19).

The deployment from the public repository ran on 2026-11-01 from wiped disks, from a clone of https://github.com/aramidetosin/ai-serving-fabric-labs at commit `ebc79b42ed8e7c27efd526eb0362447cb260e449` with no tracked file changed (every `RUN.json` of its sets reads that commit, `dirty: false`), at host tick 10000 on containerlab 0.82.0, with the same images at the same IDs, on the second of the book's two lab hosts. Its chain began with the reader's `git clone` of that URL, recorded under `script` (`audits/sfab-ch05_record-run_20261101T193612Z/rec-git-clone.txt`), then `make down`, `make wipe`, `make up`, `make audit`, `make trace`, `make drills PASSES=3`, `make break-5a`, `make heal-5a`, `make rpf`, `make record` and `make down`, each in tmux under `script` (`audits/sfab-ch05_record-run_20261101T193612Z/chain.log`). No container restarted between the end of `make up` and the end of `make record`. Its short names start with C: CN is `audits/sfab-ch05_record-run_20261101T193612Z/`, CU `audits/sfab-ch05_audit_20261101T194844Z/`, CA `audits/sfab-ch05_audit_20261101T194956Z/`, CT `audits/sfab-ch05_trace_20261101T195106Z/`, CR `audits/sfab-ch05_drills_20261101T195202Z/`, CB `audits/sfab-ch05_break-5a_20261101T200044Z/`, CH `audits/sfab-ch05_heal-5a_20261101T200215Z/`, CHA `audits/sfab-ch05_audit_20261101T200301Z/`, CPF `audits/sfab-ch05_rpf_20261101T200412Z/`, and CRA `audits/sfab-ch05_audit_20261101T200426Z/` and CRT `audits/sfab-ch05_trace_20261101T200536Z/`, the audit and trace its `make record` ran. It carries the book's Examples 5-1, 5-2 and 5-11; the earlier deployment carries every other exhibit (`audits/INDEX.md`).

The earlier deployment's short names are the index's: N is `audits/sfab-ch05_record-run_20261029T000046Z/`, U `audits/sfab-ch05_audit_20261029T000940Z/` (the audit `make up` ran), A `audits/sfab-ch05_audit_20261029T001030Z/`, T `audits/sfab-ch05_trace_20261029T001119Z/`, R `audits/sfab-ch05_drills_20261029T001158Z/`, B `audits/sfab-ch05_break-5a_20261029T001754Z/`, H `audits/sfab-ch05_heal-5a_20261029T001855Z/`, HA the chapter audit H ran, PF `audits/sfab-ch05_rpf_20261029T002014Z/`, RA and RT the audit and trace `make record` ran.

## Revision 2, against revision 1

Revision 1's sets (a deployment on 2026-10-21 and a second, for `make rpf` alone, on 2026-10-27) are superseded and out of the repository (`audits/INDEX.md`, "Superseded sets"). What revision 2 changes in what the chapter shows:

| Part | Revision 1 | Revision 2 |
|---|---|---|
| Node names | gpu1, gpu2 | k8s-gpu1, k8s-gpu2; the namespaces keep their names, gpu1 to gpu8 |
| Rail ports | the factory MTU 9100, no `mtu` line, no spanning tree, edge port, BPDU guard or storm control | `mtu 9216` typed, `spanning-tree mode pvst`, every rail port `spanning-tree portfast` and `spanning-tree bpduguard port-shutdown`, broadcast, unknown-unicast and unknown-multicast storm control at 10000 kbps (`bootstrap/rail-sw1/startup-config.cfg`, 104 lines, was 55) |
| The audit | 285 checks | 346, the Layer 2 hygiene group on the pair and both rail switches among the new ones |
| The rails | as revision 2 | unchanged: the VLANs, the addresses, the relay, its routes and their pins, `rp_filter` 2 and the GPU NICs' 9000 |
| The trace | 49 passed | 49 passed, the same verdicts at the same lines; the same frames per point and DF matrix |
| The drill's return | each dark row's first answered request 0.488 to 1.809 s after the restore's session began | 3.942 to 6.079 s after it (below) |
| `make rpf` | a second deployment | the same deployment as every other set |

## What the lab proved

| Claim | Verdict lines |
|---|---|
| Each rail switch routes nothing: its rails are VLANs with no address of any kind, `show ip interfaces` lists Management0 alone, there is no static route and `show ip route` prints nothing, neither KLISH nor FRR's view holds `router bgp`, only Management0 sits in the mgmt VRF, and the kernel holds no address on any Vlan, PortChannel or Ethernet netdev | A/verdict.txt:259 to :267, :317 to :322 (rail-sw1); :268 to :276, :329 to :334 (rail-sw2) |
| No inter-switch link: on each rail switch only the eight rendered GPU access ports are up, the other 48 admin down, each up port's description names the GPU NIC cabled there, and every MAC learned on a rail port is one the render cables to it | A/verdict.txt:323, :324, :326 (rail-sw1), :335, :336, :338 (rail-sw2) |
| Every rail port runs `no shutdown` at the rendered MTU 9216, above the GPU NICs' 9000 | A/verdict.txt:325, :327, :337, :339 |
| The rail switches' Layer 2 hygiene: PVST, every used port at 9216, BPDU guard with port-shutdown on every edge port and on no other, none tripped, storm control of each type on every access port | A/verdict.txt:368 to :374 (rail-sw1), :375 to :381 (rail-sw2); the pair's :352 to :367 |
| Every GPU namespace on both nodes holds its connected rail and seven relay routes, each pinned to the namespace's own rail address, no default route, and `rp_filter` 2 on every interface | A/verdict.txt:341 to :343 (k8s-gpu1), :347 to :349 (k8s-gpu2) |
| The MTU ceilings: the rail NICs, the relay bridge, and in every namespace the rail macvlan and the relay veth at 9000 | A/verdict.txt:344, :345, :350, :351 |
| Same-rail traffic crosses one switch at TTL 64; a cross-rail request is relayed in the source node and crosses the destination rail's switch at TTL 63, its reply relayed in the far node and crossing the source rail's switch at TTL 63, and one IP id marks the same request at every point that saw it | T/verdict.txt:11 to :19 (same-rail), :22 to :30 (cross-rail) |
| traceroute across rails shows two hops, the source node's own address on the destination rail (10.21.2.11), then the destination; on one rail, one hop | T/verdict.txt:20, :31 |
| 9000 bytes cross both paths in both directions with DF set on every request, as 9014-byte frames; 9001 bytes is refused on every path at the sender's own interface (`message too long, mtu 9000`) and no frame of it reaches any capture point; the far kernel's echo replies carry no DF | T/verdict.txt:33 to :53 |
| The kernel uses the larger of `all` and the interface's `rp_filter` on the cross-rail request at k8s-gpu2's namespace gpu2, whose route back leaves on `relay`: all 2 with rail2 2 answers 3 of 3; all 1 with rail2 0 answers none and IPReversePathFilter rises from 0 to 3; all 1 with rail2 2 answers 3 of 3 with the counter unchanged; restored, 3 of 3 | PF/verdict.txt:1 to :22 |
| With every port of rail-sw1 shut in one KLISH session, the odd rails go silent (their requests leave k8s-gpu1 and none reaches k8s-gpu2), the even rails and the cross-rail row between even rails answer every request, a cross-rail ping into a dead rail fails, and so does one out of it, whose requests reach the far node and whose replies never come back; after `no shutdown` every dark row answers again, in every one of three passes | R/verdict.txt:8 to :52 (pass 1), :61 to :106 (pass 2), :115 to :159 (pass 3); R/DRILLS.md:45 |
| The switch's sessions and the return, on the lab host's clock: the shut session took 1.21 to 1.29 s and the restore session 1.22 to 1.24 s, the switch was dark 28.64 to 28.72 s between them, and each dark row's first answered request was sent 3.942 to 6.079 s after the restore's session began (the row whose request rail stayed up, rail 1 to rail 2, first in every pass, at 4.795, 3.942 and 4.363 s) | R/pass1/dark-switch/analysis.txt:1, pass2/dark-switch/analysis.txt:1, pass3/dark-switch/analysis.txt:1; the return lines in R/verdict.txt |
| A KLISH shutdown drops no carrier: while rail-sw1's ports read `down admin-down`, both nodes' kernels read all sixteen rail NICs `UP` | R/verdict.txt:53, :107, :160 (KNOWN L9); R/pass1/dark-switch/klish/during-rail-sw1.txt:12 to :19, links-during-k8s-gpu1.txt, links-during-k8s-gpu2.txt |
| break-5a: with the source pin removed from one relay route on one node, rail 1 to rail 2 fails from that node only, its requests reaching the far node from the relay address 10.21.250.1 and the far node's replies going into its own relay bridge; rail 1 to rail 3, the reverse direction and the same rail everywhere keep working, and parity holds on both rail switches; the heal puts the pin back and the requests arrive from 10.21.1.11 again | B/verdict.txt:26 to :35; H/verdict.txt:15 to :23 |
| The trace and the audit after the drills, the break, the heal and `make rpf`, on the same deployment, as before them | RA/verdict.txt:1 to :385; RT/verdict.txt:1 to :54 |
| From a clone of the public repository with no tracked file changed, the same lab deploys from wiped disks and passes the same audit, trace, drills, break, heal and rp_filter run: every set 0 failed, the audits and traces with the same verdict lines at the same numbers | CA/verdict.txt:1 to :385, CRA/verdict.txt:1 to :385 (`audits/INDEX.md` lists what differs); CT/verdict.txt:1 to :54, CRT/verdict.txt:1 to :54; CR/verdict.txt:1 to :160; CPF/verdict.txt:1 to :22; CN/chain.log:1 to :42; CN/clone-check.txt:2 to :7 |

Facts the deployment from the public repository shows and a reader should know (`audits/INDEX.md`, "The deployment from the public repository", has the lines):

- **The drill's sessions and return** were slower on this host than on the first: the shut session took 2.73 to 2.91 s and the restore session 2.79 to 3.01 s, the switch was dark 26.92 to 27.10 s between them, and each dark row's first answered request was sent 6.295 to 7.419 s after the restore's session began (CR/pass1/dark-switch/analysis.txt:1, pass2/dark-switch/analysis.txt:1, pass3/dark-switch/analysis.txt:1; the return lines in CR/verdict.txt). The same rows went dark in every pass, as in the earlier deployment (CR/DRILLS.md:45).
- **The second witness agreed in every pass.** The earlier deployment's one disagreement, in pass 2, has no counterpart here, so CR reads 153 passed where R read 154.
- **Node sync replaced `netsetup.sh` on both guests** at boot and ran it again (CN/rec-make-up.txt:140 to :147); the guests then matched the repository, and every audit passed.
- **Boot's dns-zones step** found no secondary DNS zone in this lab and said so, so boot reads 24 passed where the earlier deployment read 23 (CN/rec-make-up.txt:148 to :151).

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch05_audit_20261029T000940Z` (the audit `make up` ran) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| A, `sfab-ch05_audit_20261029T001030Z` (`make audit`) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| T, `sfab-ch05_trace_20261029T001119Z` (`make trace`) | `== RESULT: 49 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| R, `sfab-ch05_drills_20261029T001158Z` (`make drills PASSES=3`) | `== RESULT: 154 passed, 0 failed, 3 known platform limitation(s), 0 skipped` |
| B, `sfab-ch05_break-5a_20261029T001754Z` (`make break-5a`) | `== RESULT: 32 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch05_heal-5a_20261029T001855Z` (`make heal-5a`) | `== RESULT: 19 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch05_audit_20261029T001925Z` (the chapter audit heal-5a ran) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| PF, `sfab-ch05_rpf_20261029T002014Z` (`make rpf`) | `== RESULT: 16 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| RA, `sfab-ch05_audit_20261029T002021Z` (the audit `make record` ran) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| RT, `sfab-ch05_trace_20261029T002111Z` (the trace `make record` ran) | `== RESULT: 49 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA and RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:478) |
| the gate on U, A, T, R, B, H, HA and PF | `== RESULT: 48 passed, 0 failed, 0 known platform limitation(s), 17 skipped` (N/gate-sets.txt) |
| CU, `sfab-ch05_audit_20261101T194844Z` (the audit `make up` ran, from the public repository) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| CA, `sfab-ch05_audit_20261101T194956Z` (`make audit`) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| CT, `sfab-ch05_trace_20261101T195106Z` (`make trace`) | `== RESULT: 49 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CR, `sfab-ch05_drills_20261101T195202Z` (`make drills PASSES=3`) | `== RESULT: 153 passed, 0 failed, 3 known platform limitation(s), 0 skipped` |
| CB, `sfab-ch05_break-5a_20261101T200044Z` (`make break-5a`) | `== RESULT: 32 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CH, `sfab-ch05_heal-5a_20261101T200215Z` (`make heal-5a`) | `== RESULT: 19 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CHA, `sfab-ch05_audit_20261101T200301Z` (the chapter audit heal-5a ran) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| CPF, `sfab-ch05_rpf_20261101T200412Z` (`make rpf`) | `== RESULT: 16 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CRA, `sfab-ch05_audit_20261101T200426Z` (the audit `make record` ran) | `== RESULT: 346 passed, 0 failed, 0 known platform limitation(s), 1 skipped` |
| CRT, `sfab-ch05_trace_20261101T200536Z` (the trace `make record` ran) | `== RESULT: 49 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on CRA, CRT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (CN/rec-make-record.txt:476) |
| the gate on CU, CA, CT, CR, CB, CH, CHA and CPF | `== RESULT: 48 passed, 0 failed, 0 known platform limitation(s), 17 skipped` (CN/gate-sets.txt:75) |
| the clean-up `make down` and `make wipe` of that deployment | `== RESULT: 3 passed, 0 failed, 0 known platform limitation(s), 1 skipped` (CN/rec-clean-down.txt:9, nothing deployed yet in the new clone); `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (CN/rec-clean-wipe.txt:10) |
| its closing `make down` | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (CN/rec-make-down.txt:336) |

The three KNOWN lines in each deployment's drills are L9, one in each drill pass: a KLISH shutdown drops no carrier at the far end. The one SKIP in every audit is namecheck, which the lab host runs without the author's scrub list; the gates' SKIPs are namecheck and the literal scan for the same reason. A run with the scrub and literals lists, over every committed set, found nothing (`audits/INDEX.md`).

## The result sets

All under `audits/`, each with its `RUN.json` (lab, spec and render sha256, image ids, containerlab version, host tick 10000, UTC start and end), `verdict.txt`, `RESULT.txt` and `commands.txt`. Each of the earlier deployment's `RUN.json` files names, from the copy's stamp, a commit of the pre-release history, which is not in this repository, with `dirty: true`; `audits/INDEX.md` says why, and names the later changes the repository's first public commit holds on this lab's path.

| Directory | What it holds |
|---|---|
| `sfab-ch05_record-run_20261029T000046Z/` | plain files: `chain.log`, the host before and after, the plain journal of every recorded command and the typescripts it was made from, container start times, disk and container-layer readings, the memory watchdog's log, the gate on the sets `make record` does not gate |
| `sfab-ch05_audit_20261029T000940Z/`, `..._001030Z/`, `..._001925Z/`, `..._002021Z/` | the four full audits: every node's reads, both forms, and `rail-backend/` (each GPU namespace's links) |
| `sfab-ch05_trace_20261029T001119Z/`, `..._002111Z/` | the two traces: `TRACE.md`, `health/`, `flows/`, `df/`, `captures/` and `captures-df/` (pcaps and their decodes) |
| `sfab-ch05_drills_20261029T001158Z/` | the drill's three passes, `pass<N>/dark-switch/` (timeline, host-side captures and decodes, the guest's ping logs, KLISH snapshots, the nodes' link reads, parity, the analysis), and `DRILLS.md` |
| `sfab-ch05_break-5a_20261029T001754Z/`, `sfab-ch05_heal-5a_20261029T001855Z/` | the break and the heal: the route reads, the pings, the far node's captures, parity |
| `sfab-ch05_rpf_20261029T002014Z/` | `make rpf`: `FOLLOWED.txt`, the reads of each case, each opening with the command at `admin`'s prompt |
| `sfab-ch05_record-run_20261101T193612Z/` and the ten `..._20261101T...` sets | the deployment from the public repository, laid out as the sets above, with the recorded `git clone` and `clone-check.txt` in its plain files; every `RUN.json` names the public commit `ebc79b42` with `dirty: false` |

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0` and `sfab/vm-node:6-k8s1.35.8`, 71 GiB of MemAvailable and no other `sfab-` lab running:

```
git clone https://github.com/aramidetosin/ai-serving-fabric-labs.git
cd ai-serving-fabric-labs/ch05
make down && make wipe
make up
make audit
make trace
make drills
make break-5a
make heal-5a
make rpf
make record
make down
```

On the earlier deployment, `make up` took 7 min 42 s, its switches' boot 271 s of it. A full audit took 49 s without the author's scrub list; with it, the repository's namecheck takes most of an audit's time. `make drills` took 5 min 56 s for three passes.

## What the recordings do not show

- **The pod half of Example 5-4.** This lab runs no cluster and renders no rail attachment, so no pod's rail leg or relay leg comes from it.
- **A `git clone` line in the earlier deployment.** Its chain began at `make down`; the recorded clone is the deployment from the public repository's (CN/rec-git-clone.txt), which made a clone of its own in an empty directory and deployed from a clone of the same commit and tree (CN/clone-check.txt:2 to :7).
- **Why the return took longer than in revision 1.** Revision 2's dark rows answered again 3.942 to 6.079 s after the restore's session began, against revision 1's 0.488 to 1.809 s on the same rails and rows; revision 2 adds PVST with edge ports, BPDU guard and storm control on the rail ports. No read in the drill shows the switch's spanning-tree or port state between the `no shutdown` and the first answer, so the recordings time the return and do not say where those seconds went. The deployment from the public repository's return, 6.295 to 7.419 s on the second lab host, is no more explained.
- **A switch refusing an oversized frame.** Every 9001-byte DF ping was refused at the sender's own 9000-byte interface, so no frame larger than 9014 bytes ever reached a rail switch, and the switch ports' 9216 was never the limit on either path.
- **A BPDU guard trip.** No BPDU reached a rail port; the audit reads BPDU guard configured and no port shut by it.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge. A stock kernel refuses that mask, and on such a host `vm-init.sh` joins the data NICs, the bond members among them, to their taps with a tc mirred redirect instead. No recorded run exercised that path; `guest.nic_link: tc` in `spec/common.yaml`, with the lab rendered again, forces it, for testing (`../README.md`, "The host").
