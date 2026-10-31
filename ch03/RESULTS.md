# Chapter 3 results

What lab `sfab-ch03` proved on its recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-10-29 from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `vrnetlab/truenas_truenas:27.0.0-RC.1` (d0b0a42ff2d3) and `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669) among the ten its `RUN.json` files name. Every command ran in tmux under `script`, so each journal shows the command exactly as typed: `make down` and `make wipe` from 03:51:41, `make up` from 03:56:49 to 04:30:33, `make audit`, `make trace`, `make dbs`, `make drills` three times with `PASSES=3` (04:35:53 to 06:10:51), `make break-3a`, `make heal-3a`, `make break-3b`, `make heal-3b`, `make record` from 06:27:55 to 06:32:22, and `make down` to 06:34:27 (`audits/sfab-ch03_record-run_20261029T035141Z/chain.log`). No container restarted between the end of `make up` and the end of `make record` (the start times in `audits/sfab-ch03_record-run_20261029T035141Z/startedat-*.txt` are identical, every one `restarts=0`). Times are the lab host's clock, UTC. It ran on the second of the book's two lab hosts; preflight read 304.1 GiB available against the lab's 126.5 GiB and the 16.0 GiB floor (N/rec-make-up.txt:28).

The short names are the index's: N is `audits/sfab-ch03_record-run_20261029T035141Z/`, U `audits/sfab-ch03_audit_20261029T042635Z/` (the audit `make up` ran), A `audits/sfab-ch03_audit_20261029T043034Z/`, T `audits/sfab-ch03_trace_20261029T043426Z/`, DB `audits/sfab-ch03_dbs_20261029T043514Z/`, R1 to R3 the three drill sets (`..._drills_20261029T043553Z`, `..._050430Z`, `..._053410Z`), B and H break-3a and heal-3a, HA the chapter audit H ran, B3 and H3 break-3b and heal-3b, HB the chapter audit H3 ran, RA and RT the audit and trace `make record` ran.

## Revision 2, against revision 1

Revision 1's sets (deployments on 2026-10-20 and 2026-10-27) are superseded and out of the repository (`audits/INDEX.md`, "Superseded sets"). What revision 2 changes in what the chapter shows:

| Part | Revision 1 | Revision 2 |
|---|---|---|
| Node names | ctrl1 to ctrl3, gpu1, gpu2 | k8s-cp1 to k8s-cp3, k8s-gpu1, k8s-gpu2, and the ingress nodes k8s-ingress1 and k8s-ingress2 and the DNS servers dns-auth1, dns-res1, dns-auth2, dns-res2 on the pair |
| The keepalive | the ICCP session in VRF `mgmt` between the switches' management addresses, no backup | a dedicated routed link on Ethernet12 (10.20.255.0/31) in VRF VrfMclagKa, and a backup session on Vlan3966 over the peer link (10.20.255.4/31, `mclag-separate-ip`), both in VrfMclagKa |
| The port plan | fe-sw1 12 data ports, fe-sw2 11; TrueNAS's management port single-attached on fe-sw1 | 19 data ports on each switch; TrueNAS's management address on a bond with one leg on each (PortChannel32), so no port is an orphan |
| Layer 2 hygiene | the factory MTU 9100 on the peer link and the host PortChannels, no spanning tree, BPDU guard or storm control | `mtu 9216` on every used port and PortChannel, PVST, every host PortChannel an edge port with BPDU guard (port-shutdown), storm control on every member port; the startup file is 368 lines |
| The audit | 517 checks | 799, the forwarding-only checks of the keepalive VRF and the Layer 2 hygiene groups among the new ones |
| The trace | the users' VIP in VLAN 100, held by a control node, the SYN untagged after the pair | the users' VIP 10.20.11.210 in VLAN 110, held by an ingress node, the SYN tagged 110 to the holder's bond |
| The drills | fw-leg, server-member, peer-link with an orphan probe, standby-reboot | the same four without the orphan, and keepalive-link and keepalive-and-peer-link |
| The breaks | break-3a | break-3a and break-3b (one leg of TrueNAS's management bond shut) |

## What the lab proved

| Claim | Verdict lines |
|---|---|
| M2's whole audit holds on chapter 3's lab: the switches, the firewall, the guests, the cluster, the bastion, the DNS and time servers, the uplink side, the clients, storage, the populations, a volume on each class and the cluster's security | A/verdict.txt:1 to :358, :563 to :867 |
| The pair routes nothing but its keepalives: on each switch only Management0 (VRF mgmt) and two keepalive addresses, Ethernet12 and Vlan3966, both in VrfMclagKa, whose table holds only its two connected /31s; the default table is empty; no router block in KLISH or FRR; no address on a served VLAN, a PortChannel or a host port | A/verdict.txt:359 to :386 |
| The pair as rendered: domain 1, the session and the peer link up, the keepalive in VrfMclagKa from each switch's Ethernet12 address to the other's, the backup keepalive session up on Vlan3966, the system MAC 02:5a:00:00:00:01, 15 MLAG interfaces up/up and 16 PortChannels up with their members on both switches | A/verdict.txt:414 to :495 |
| The roles follow the keepalive source addresses: fe-sw1 (10.20.255.0) active, fe-sw2 standby; the ICCP session established on TCP 8888 in VrfMclagKa on both, and iccpd's keepalive OK | A/verdict.txt:496 to :504 |
| Every bond toward the pair has two legs in one aggregator under the system MAC, with fast LACP both ways: the seven cluster nodes, the bastion, the four DNS servers, the firewall's ae1 member by member, and TrueNAS's two bonds from the pair's side | A/verdict.txt:505 to :531 (TrueNAS's own LACP view is not collected, the SKIP at :532) |
| The pair's Layer 2 hygiene: PVST, all 19 used ports and 16 PortChannels at 9216, BPDU guard with port-shutdown on the 14 edge PortChannels and on no other port, none tripped, storm control of each type at 10000 kbps on the 15 member and access ports | A/verdict.txt:533 to :548; the rail switches :549 to :562 |
| One HTTPS SYN from the enterprise client to the users' VIP is the same frame at all four points: it leaves the firewall on one ae1 leg tagged 110, enters the pair on the trunk port that leg lands on, and leaves that switch tagged 110 toward the lease holder k8s-ingress2's bond0, on exactly one leg of each group | T/TRACE.md:22 to :51; RT/TRACE.md:22 to :51 |
| SONiC's databases hold PortChannel21 from CONFIG_DB through APPL_DB and STATE_DB to ASIC_DB: the member Ethernet6's port object, its LAG member, the LAG with one member, its bridge port and an untagged VLAN member in VLAN 100 | DB/verdict.txt:1 to :42 |
| fw-leg: with fe-sw1's member facing the firewall shut, 3, 3 and 2 TCP connects failed at the cut and the ping control lost nothing | R1/DRILLS.md:7 to :21 |
| server-member: with fe-sw1's member facing k8s-gpu1 shut, each ping id crossing fe-sw1 lost 9 to 10, 8 and 7 round trips in the three passes, all at the cut, the longest stretch with no reply 2.43 to 3.34 s; the other ids and the TCP control lost nothing | R1/DRILLS.md:23 to :37 |
| peer-link: with both peer-link members shut and the keepalive link up, no ping and no TCP connect was lost in any pass | R1/DRILLS.md:39 to :47 |
| keepalive-link: with only the keepalive link shut for 70 s, the backup up, iccpd lost the keepalive at +39.4 to +40.1 s, the standby (fe-sw2) shut its MCLAG PortChannels and every bond went to the active's leg at +73.8 to +74.6 s, and the standby held them down past the restore for delay-restore: every bond was back on two legs at +377.1 to +380.9 s; the ids on the active's legs lost nothing, those on the standby's 19 to 22 round trips each | R2/pass1/keepalive-link/analysis.txt:5 to :14 and the same file of passes 2 and 3; R2/DRILLS.md:9 to :13; R2/verdict.txt:6, :16, :25 |
| keepalive-and-peer-link: with the keepalive link and the peer link shut together, iccpd lost the keepalive at +40.4 to +40.6 s and the session was back at +75.5 to +76.9 s; the standby shut nothing and held nothing down, and the pair was whole 31 to 32 s after the restore; the ids on fe-sw2's legs lost 13 to 14 round trips each, those on fe-sw1's none | R3/pass1/keepalive-and-peer-link/analysis.txt:5 to :27 and passes 2 and 3; R3/DRILLS.md:7 to :13; R3/verdict.txt:6, :26, :46 |
| standby-reboot: the standby, fe-sw2 each time, rebooted; every bond went to one leg 23.4 to 23.8 s after the reboot command, the ids crossing fe-sw2 lost 11 to 14 round trips at the cut and 13 to 17 at the return, and its return, every bond back on two legs at +248.4 to +254.4 s, is recorded as an event (KNOWN L2); after it, GRO off and parity 0 missing on fe-sw2 | R3/DRILLS.md:35 to :82, :105 to :120; R3/verdict.txt:13 to :19, :34 to :40, :53 to :59 |
| The three passes agree in every drill set: no loss row conflicts between passes, and the guest's ping and the host's captures agree on every round trip both saw | R1/DRILLS.md:112, R2/DRILLS.md:70, R3/DRILLS.md:124 |
| break-3a: with VLAN 200 removed from PortChannel10 on fe-sw2 only, the bastion's connects to TrueNAS's management address failed 31, 31 and 29 of 60 by the firewall's hash; heal-3a replayed the rendered line, parity held, 60 of 60 succeeded, and the chapter audit passed | B/verdict.txt:2 to :11; H/verdict.txt:2 to :13 |
| break-3b: with fe-sw1's leg of TrueNAS's management bond shut, `show mclag brief` read PortChannel32 down/up on fe-sw1 and up/down on fe-sw2, and all 180 connects succeeded over the fe-sw2 leg; heal-3b brought it back up/up on both, parity held, and the chapter audit passed | B3/verdict.txt:2 to :11; H3/verdict.txt:2 to :12 |
| The trace and the audit after every drill, both breaks and both heals, on the same deployment, as after launch | RA/verdict.txt:1 to :868; RT/TRACE.md:22 to :51, :100 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch03_audit_20261029T042635Z` (the audit `make up` ran) | `== RESULT: 799 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| A, `sfab-ch03_audit_20261029T043034Z` (`make audit`) | `== RESULT: 799 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| T, `sfab-ch03_trace_20261029T043426Z` (`make trace`) | `== RESULT: 25 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| DB, `sfab-ch03_dbs_20261029T043514Z` (`make dbs`) | `== RESULT: 34 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| R1, `sfab-ch03_drills_20261029T043553Z` (fw-leg, server-member, peer-link) | `== RESULT: 55 passed, 0 failed, 11 known platform limitation(s), 0 skipped` |
| R2, `sfab-ch03_drills_20261029T050430Z` (keepalive-link) | `== RESULT: 22 passed, 0 failed, 5 known platform limitation(s), 0 skipped` |
| R3, `sfab-ch03_drills_20261029T053410Z` (keepalive-and-peer-link, standby-reboot) | `== RESULT: 46 passed, 0 failed, 8 known platform limitation(s), 0 skipped` |
| B, `sfab-ch03_break-3a_20261029T061052Z` | `== RESULT: 7 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch03_heal-3a_20261029T061553Z` | `== RESULT: 8 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch03_audit_20261029T061712Z` (the chapter audit heal-3a ran) | `== RESULT: 799 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| B3, `sfab-ch03_break-3b_20261029T062058Z` | `== RESULT: 7 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H3, `sfab-ch03_heal-3b_20261029T062301Z` | `== RESULT: 7 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HB, `sfab-ch03_audit_20261029T062408Z` (the chapter audit heal-3b ran) | `== RESULT: 799 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| RA, `sfab-ch03_audit_20261029T062756Z` (the audit `make record` ran) | `== RESULT: 799 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| RT, `sfab-ch03_trace_20261029T063134Z` (the trace `make record` ran) | `== RESULT: 25 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA, RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:957) |
| the gate on U, A, T, DB, R1 to R3, B, H, HA, B3, H3 and HB | `== RESULT: 78 passed, 0 failed, 0 known platform limitation(s), 27 skipped` (N/gate-sets.txt) |

The KNOWN lines are L9 on each of the 15 shuts (a KLISH shutdown drops no carrier at the far end, so every member figure is an LACP-timeout figure), L2 on each of the three reboots (delay-restore holds nothing down after a reboot, so the return is an event), and L1 on the 6 drills that saw duplicate ping replies (peer-link isolation is not enforced). The two SKIPs in every audit are TrueNAS's own LACP view, which is not collected, and namecheck, which the lab host runs without the author's scrub list; the gates' SKIPs are namecheck and the literal scan for the same reason. A run with the scrub and literals lists, over every committed set, found nothing (`audits/INDEX.md`).

## What the deploys found

1. **sonic-cli ended drill sessions early.** The first revision 2 recording on this host (attempt 1, not published, FRAMEWORK.md 4.4) failed keepalive-link's first pass: fe-sw1's restore session echoed `interface Ethernet12` and nothing after it, so the drill, finding no `% Error`, took the session as accepted and Ethernet12 stayed shut. `drill_shut` now wants the session's echo to reach the closing `exit` and types a session cut short again. The second recording (attempt 2) then failed keepalive-link's return wait: fe-sw1's pair read echoed `show PortChannel summary` and printed nothing, so every PortChannel read absent through the 600 s wait, while the monitor saw the return about 310 s after the restore. `pair_poll` now types a read cut short again too, each drill session is bounded at 90 s (`SFAB_DRILL_SESSION_S`), and the return wait keeps each poll's outcome in `return/polls.txt`. In this recording 27 sessions were typed again, every one on its second try (`audits/INDEX.md`, "How to read the drill sets").
2. **The drill summary named the target as the standby.** In the keepalive drills, whose target is the active, `DRILLS.md` heads each pass's events "the standby fe-sw1"; the monitor's standby was fe-sw2 (each pass's `analysis.txt`). `common/drill/summarize.py` and `common/drill/compare_passes.py` are fixed for later runs; the recorded files are kept as written.
3. **Revision 1's STATE_DB reads were never committed.** The repository's `**/state/` rule, meant for each lab's runtime `state/`, also caught `make dbs`'s `state/` directory in its result set. `.gitignore` now re-includes it, and DB/state/ is committed.

The platform facts the drills depend on are in `README.md`, "Platform notes for this lab".

## How to reproduce

With the requirements in `README.md` met:

```
cd ch03
make up
make audit
make trace
make dbs
make drills DRILLS='fw-leg server-member peer-link' PASSES=3
make drills DRILLS=keepalive-link PASSES=3
make drills DRILLS='keepalive-and-peer-link standby-reboot' PASSES=3
make break-3a
make heal-3a
make break-3b
make heal-3b
make record
make down
```

A plain `make drills` runs all six drills in one set; the recording ran them as three sets, as above, so that each fits the recording size policy's set cap (`chapter.yaml`, the comment on the drills block). From wiped disks `make up` took 33 min 44 s to the end of its audit (N/rec-make-up.txt:1 to :1590); the three drill runs took 28 min 36 s, 29 min 40 s and 36 min 41 s.

## What the recordings do not show

- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's (`../README.md`, "Clone, build, deploy").
- **A public commit in `RUN.json`.** Each `RUN.json` names, from the copy's stamp, a commit of the pre-release history, which is not in this repository, with `dirty: true`; the runs used that commit plus the uncommitted changes `audits/INDEX.md` names, and the repository's first public commit holds that code with the later changes the same page names.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge. A stock kernel refuses that mask, and on such a host `vm-init.sh` joins the data NICs to their taps with a tc mirred redirect instead; no recorded run exercised that path (`../README.md`, "The host").
