# Chapter 4 results

What lab `sfab-ch04` proved on its two recorded deployments under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The earlier deployment ran on 2026-10-30 from wiped disks, at host tick 10000 on containerlab 0.82.0, on the second lab host, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `vrnetlab/truenas_truenas:27.0.0-RC.1` (d0b0a42ff2d3), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4` (0e82fde37b3d), `sfab/client:2` (737f846b3e7f), `sfab/resolver:3` (d0fabd25e229), `sfab/registry:3` (74db9faf8fd4), `sfab/vpngw:3` (d5db2071ca65) and `sfab/frr:10.5.4-3` (234239dc64b1), the ten its `RUN.json` files name. Serving is off in this lab: the requests reach the test backend behind both Gateways. One chain ran every command in tmux under `script`, so each journal shows the command exactly as typed (`audits/INDEX.md` gives the times).

The deployment from the public repository ran on 2026-11-01 from wiped disks, from a clone of https://github.com/aramidetosin/ai-serving-fabric-labs at commit `752b5f49473ea95b14596f7100948f538c2ae5aa` with no tracked file changed (every `RUN.json` of its sets reads that commit, `dirty: false`), at host tick 10000 on containerlab 0.82.0, with the same images at the same IDs. Its chain began with the reader's `git clone` of that URL, recorded under `script` (`audits/sfab-ch04_record-run_20261101T170608Z/rec-git-clone.txt`), then `make down`, `make wipe`, `make up`, `make audit`, `make trace`, `make drills PASSES=3`, `make break-4a`, `make heal-4a`, `make record` and `make down`, every step 0 failed. It carries the book's launch, launch audit and closing exhibits (Examples 4-1, 4-2 and 4-11); the earlier deployment carries the others. Its short names start with C (`audits/INDEX.md`, "The deployment from the public repository"): CN `audits/sfab-ch04_record-run_20261101T170608Z/`, CU `audits/sfab-ch04_audit_20261101T174026Z/`, CA `audits/sfab-ch04_audit_20261101T175413Z/`, CT `audits/sfab-ch04_trace_20261101T180743Z/`, CR `audits/sfab-ch04_drills_20261101T181057Z/`, CB `audits/sfab-ch04_break-4a_20261101T184232Z/`, CH `audits/sfab-ch04_heal-4a_20261101T184549Z/`, CHA the chapter audit CH ran (`audits/sfab-ch04_audit_20261101T184755Z/`), and CRA `audits/sfab-ch04_audit_20261101T190139Z/` and CRT `audits/sfab-ch04_trace_20261101T191537Z/`, the audit and trace `make record` ran. Preflight read 304.4 GiB available against the lab's 126.75 GiB and the 16.0 GiB floor (CN/rec-make-up.txt:28).

The earlier deployment's short names are the index's: N is `audits/sfab-ch04_record-run_20261030T070513Z/`, U `audits/sfab-ch04_audit_20261030T074232Z/` (the audit `make up` ran), A `audits/sfab-ch04_audit_20261030T075617Z/`, T `audits/sfab-ch04_trace_20261030T080949Z/`, R `audits/sfab-ch04_drills_20261030T081303Z/`, B `audits/sfab-ch04_break-4a_20261030T084414Z/`, H `audits/sfab-ch04_heal-4a_20261030T084733Z/`, HA `audits/sfab-ch04_audit_20261030T084940Z/` (the chapter audit H ran), and RA `audits/sfab-ch04_audit_20261030T090327Z/` and RT `audits/sfab-ch04_trace_20261030T091701Z/`, the audit and trace `make record` ran.

## Revision 2, against revision 1

Revision 1's sets (two deployments on 2026-10-20 and 21) are superseded and out of the repository (`audits/INDEX.md`, "Superseded sets"). What revision 2 changes in what the chapter shows:

| Part | Revision 1 | Revision 2 |
|---|---|---|
| Node names | ctrl1 to ctrl3, gpu1, gpu2; 17 containers | k8s-cp1 to k8s-cp3, k8s-gpu1, k8s-gpu2, the ingress nodes, the DNS and time servers, ops-gw and the web client; 27 containers |
| Zones on the bundle | one zone `data` on ae1.100 for the nodes and the VIPs alike; `stor-mgmt`, `bastion` | `k8s-nodes` (ae1.100), `ingress` (ae1.110, the VIPs, MSS adjusted by 140), `services` (ae1.130 and ae1.131, the DNS and time servers), `stor-mgmt`, `bastion`; `operator-vpn` on tunnel.1 (MTU 1400); a second `enterprise` port, ethernet1/7, to the corporate resolver |
| Security policy | fifteen port-based rules, one intrazone allow per zone, an open egress (`inside-to-internet`) | 25 rules, every allow an App-ID with `application-default` or an explicit service and the profile group `bp-default`, closing with `deny-all-log`; the predefined rules overridden to deny and log (printed `vsys1+intrazone-default`, `vsys1+interzone-default`); no rule admits the inside to an internet host but the registry and the time reference. The 25th rule, `nodes-to-public-ping`, is this lab's own (below) |
| NAT | three rules, the operator's destination NAT first | two: `no-nat-public` above `internet-snat`; nothing published on the public address |
| The operator | HTTPS to the public address, translated to the internal Gateway's VIP | an IPsec tunnel from ops-gw into zone `operator-vpn`, untranslated to 10.20.11.200; anything outside the tunnel's proxy IDs dropped on the uplink by zone protection's strict IP check before any rule |
| Administrative access | the out-of-band interface, the bastion's out-of-band address | ae1.300 with `bastion-admin`, from the bastion's own address 10.20.3.10 only; every other interface ping only |
| The firewall's own DNS and NTP | to the bastion, from the out-of-band interface | to dns-res1 and dns-res2, from ae1.130 (10.20.13.1) under `inside-to-resolvers` and `inside-to-ntp` |
| The audit | 561 checks | 862, with the egress refusal and the operator's cells by the strict IP check's counter |
| The trace | the operator's session translated by `dnat-operator-gateway`; the pull under `inside-to-internet` | the operator's session through the tunnel, untranslated; the pull under `nodes-to-registry`, judged by its own session's log line, its first 5000 frames at each capture point |
| ntp-uplink | the deny zone uplink to bastion, restored from ethernet1/3 | zone uplink to services, restored from ae1.130 |
| break-4a | the NAT rulebase held three rules, two after the delete | two, one after the delete |

## What the lab proved

| Claim | Verdict lines |
|---|---|
| Build A's one-tenant state deploys whole from wiped disks in one `make up`: 27 containers, every switch with its KLISH startup configuration applied, the firewall's delivered configuration byte for byte as rendered and every enforced line running, the IPsec tunnel to the operator's site, every secondary DNS zone loaded, the cluster and storage, then an audit with no FAIL | N/rec-make-up.txt:299, :337, :377 to :387, :435, :716, :1688; A/verdict.txt:153 to :170 |
| Chapter 3's whole audit holds on the same slice with this chapter's groups | A/verdict.txt:1 to :876 |
| Every layer 3 interface sits in its zone with its address | A/verdict.txt:877 to :887 |
| The running security and NAT rules run in the render's order, `deny-all-log` last before the predefined defaults and `no-nat-public` above `internet-snat` | A/verdict.txt:888 to :892 |
| `flow_policy_nat_land` is in this firewall's own counter table and does not move while k8s-cp2 pings the public address, every ping answered, with `no-nat-public` in place | A/verdict.txt:893 to :897 |
| An egress the allowlist does not name, k8s-cp2 to the web client on 443, times out and is logged under `deny-all-log`, zone k8s-nodes to uplink | A/verdict.txt:898 to :900 |
| Administrative access is on ae1.300 from the bastion's own address only: HTTPS and SSH answer it, HTTPS does not answer k8s-cp2, and nothing answers on the public address | A/verdict.txt:901 to :908 |
| The firewall's own DNS and NTP leave from ae1.130 to the lab's resolvers, its NTP synched to one of them, both allowed by their rules, the bastion's name resolved through the route | A/verdict.txt:909 to :915 |
| The uplink router routes the eight inside prefixes to the public address and the operator's site to ops-gw; each of the operator's five forbidden cells behind the firewall is refused: the users' VIP inside the tunnel by `deny-all-log` (zone operator-vpn to ingress), the other four outside the proxy IDs by the strict IP check (`flow_dos_pf_strictip` risen, no log line) | A/verdict.txt:916 to :936 |
| One request from each side of the firewall, read while its connection is held: the enterprise's to the users' VIP under `staff-to-users-gateway` (ethernet1/4 to ae1.110), the operator's through tunnel.1 to the internal Gateway's VIP under `operator-to-internal-gateway`, neither translated, each with its traffic log line | T/verdict.txt:1 to :18; T/TRACE.md:45 to :169 |
| A node's image pull leaves through the source NAT: the same first SYN inside (tagged 100, from 10.20.1.22) and on the uplink with its source rewritten to 198.51.100.2 and its port translated, logged as that session under `nodes-to-registry` | T/verdict.txt:19 to :27 |
| land: with `no-nat-public` deleted and committed, none of k8s-cp2's five pings to the public address is answered, `flow_policy_nat_land` rises by 5, the drop-stage capture holds the five requests and nothing leaves on the uplink; with the rule back in its place, all five are answered and the counter does not rise, in each of three passes | R/DRILLS.md:5 to :15; R/verdict.txt:1 to :19, :33 to :51, :65 to :83 |
| ntp-uplink: with the NTP and DNS service routes moved to ethernet1/5, the firewall's own NTP and DNS from 198.51.100.2 are logged under `deny-all-log`, zone uplink to services, and no frame of them reaches the bundle; with the routes back, both are allowed again from 10.20.13.1, in each of three passes | R/DRILLS.md:17 to :26; R/verdict.txt:20 to :32, :52 to :64, :84 to :96 |
| After the drills the rulebase is as rendered and the quick audit is green | R/verdict.txt:97 to :100 |
| break-4a: with `no-nat-public` deleted, every ping from k8s-cp2 to the public address goes unanswered and `flow_policy_nat_land` rises by 30 over three passes, while every user request answers 200; heal-4a puts the rule back before `internet-snat`, every ping is answered, the counter does not rise, and the chapter audit is green | B/verdict.txt:1 to :15; H/verdict.txt:1 to :16 |
| The audit and trace after the drills and the break, on the same deployment, as before them | RA/verdict.txt:877 to :940; RT/verdict.txt:1 to :28; the gate on both, N/rec-make-record.txt:1014 to :1034 |
| From a clone of the public repository with no tracked file changed, the same lab deploys from wiped disks and passes the same audit, trace, drills, break and heal: every set 0 failed, the audits with the same verdict lines at the same numbers | CA/verdict.txt:1 to :940, CRA/verdict.txt:1 to :940 (`audits/INDEX.md` lists what differs); CT/verdict.txt:1 to :28, CRT/verdict.txt:1 to :28; CN/chain.log:1 to :40; CN/clone-check.txt:2 to :7 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch04_audit_20261030T074232Z` (the audit `make up` ran) | `== RESULT: 862 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| A, `sfab-ch04_audit_20261030T075617Z` (`make audit`) | `== RESULT: 862 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| T, `sfab-ch04_trace_20261030T080949Z` (`make trace`) | `== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| R, `sfab-ch04_drills_20261030T081303Z` (`make drills PASSES=3`) | `== RESULT: 92 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| B, `sfab-ch04_break-4a_20261030T084414Z` (`make break-4a`) | `== RESULT: 11 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch04_heal-4a_20261030T084733Z` (`make heal-4a`) | `== RESULT: 11 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch04_audit_20261030T084940Z` (the chapter audit heal-4a ran) | `== RESULT: 861 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RA, `sfab-ch04_audit_20261030T090327Z` (the audit `make record` ran) | `== RESULT: 861 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RT, `sfab-ch04_trace_20261030T091701Z` (the trace `make record` ran) | `== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA, RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:1034) |
| `common/audit/gate.sh` on U, A, T, R, B, H and HA | `== RESULT: 42 passed, 0 failed, 0 known platform limitation(s), 15 skipped` (N/gate-sets.txt:66) |
| the clean-up `make down` and `make wipe` | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (N/rec-clean-down.txt:9); `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (N/rec-clean-wipe.txt:10) |
| the closing `make down` | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (N/rec-make-down.txt:1213) |
| CU, `sfab-ch04_audit_20261101T174026Z` (the audit `make up` ran, from the public repository) | `== RESULT: 862 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| CA, `sfab-ch04_audit_20261101T175413Z` (`make audit`) | `== RESULT: 862 passed, 0 failed, 0 known platform limitation(s), 2 skipped` |
| CT, `sfab-ch04_trace_20261101T180743Z` (`make trace`) | `== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CR, `sfab-ch04_drills_20261101T181057Z` (`make drills PASSES=3`) | `== RESULT: 92 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CB, `sfab-ch04_break-4a_20261101T184232Z` (`make break-4a`) | `== RESULT: 11 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CH, `sfab-ch04_heal-4a_20261101T184549Z` (`make heal-4a`) | `== RESULT: 11 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| CHA, `sfab-ch04_audit_20261101T184755Z` (the chapter audit heal-4a ran) | `== RESULT: 861 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| CRA, `sfab-ch04_audit_20261101T190139Z` (the audit `make record` ran) | `== RESULT: 861 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| CRT, `sfab-ch04_trace_20261101T191537Z` (the trace `make record` ran) | `== RESULT: 24 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on CRA, CRT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (CN/rec-make-record.txt:1030) |
| `common/audit/gate.sh` on CU, CA, CT, CR, CB, CH and CHA | `== RESULT: 42 passed, 0 failed, 0 known platform limitation(s), 15 skipped` (CN/gate-sets.txt:66) |
| the clean-up `make down` and `make wipe` of that deployment | `== RESULT: 3 passed, 0 failed, 0 known platform limitation(s), 1 skipped` (CN/rec-clean-down.txt:9, nothing deployed yet in the new clone); `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (CN/rec-clean-wipe.txt:10) |
| its closing `make down` | `== RESULT: 4 passed, 0 failed, 0 known platform limitation(s), 0 skipped` (CN/rec-make-down.txt:1201) |

The SKIPs: TrueNAS's own view of its bond's partner, which is not collected, and namecheck, which the lab host runs without the author's scrub list, in every audit; in HA and RA also `flow_policy_nat_land reads 0`, since the drills and break-4a raised it to 55 on purpose (RA/verdict.txt:895). Every `RUN.json` of the earlier deployment carries one spec sha256 (`b0a19e32e0f0...`) and one render sha256 (`e667bd66ffb0...`), and containerlab 0.82.0; every one of the deployment from the public repository carries `8f314deb6bce...` and `b8cb9e1bfe0e...`, containerlab 0.82.0 and the public commit `752b5f49`, `dirty: false`. The labs repository commit in each of the earlier deployment's, from the checkout's stamp (FRAMEWORK.md 4.4), is a commit of the pre-release history, which is not in this repository, with `dirty: true`: the runs used that commit plus later work, this lab's fixes below among it, and the repository's first public commit holds that code with the one later change `audits/INDEX.md` names.

## What the deploys found

Five revision 2 deployments on this host came before the earlier deployment's recording. Each fault was fixed in the lab code, tested and committed, and the sequence started again from `make down` and `make wipe`. Their sets are not published (FRAMEWORK.md 4.4; `audits/INDEX.md`, "Superseded sets").

1. **No rule let a node ping the public address** (`make up`'s audit, 861 passed, 1 failed). k8s-cp2's five pings to 198.51.100.2 went unanswered and the firewall logged `ping k8s-nodes 10.20.1.12 deny-all-log deny uplink 198.51.100.2 policy-deny`. Revision 2's rulebase admits nothing from the inside to the public address, and the LAND discard is a source NAT allocation result, which comes only after a rule has allowed the session, so the audit's LAND check, the land drill and break-4a could not show it. `spec/profile-a.yaml` adds `nodes-to-public-ping` (zone k8s-nodes to uplink, the nodes' segment to the public address, ping, `bp-default`) after `inside-to-gateway-ping`, marked `drill: land`; `common/sfab/model.py` renders a rule with `drill:` only in a lab whose drills plan runs that drill, so this lab has 25 rules and every other lab's render is unchanged (`common/sfab/tests/test_firewall.py`).
2. **dns-auth2's internal forward zone was not loaded when the audit read it** (`make up`'s audit, 860 passed, 2 failed). Its primary, dns-auth1, sits behind the firewall; every transfer failed `host unreachable` until the firewall was up, and BIND then backed off the retries of the never-loaded zones, so they loaded one by one, the last about 13 minutes after boot had found the firewall committed and the pair up, a minute after the audit's read. `common/stages/boot.sh` has a new last step, `dns-zones` (FRAMEWORK.md 3.3, item 10): every secondary zone of each rendered `named.conf`, read by `rndc zonestatus` until loaded, an unloaded one told `rndc retransfer` (`common/tests/test_m2.py`).
3. **The pull's capture decodes were over the 10 MiB text cap** (`make record`'s gate, 11 passed, 1 failed). The node helm image's whole pull is about 30,000 frames at a point, about 11 MiB decoded, and the policy commits a decode whole, so the trace captures less: each point now keeps the pull's first 5000 frames on the registry's port (`tcpdump -c`, `common/trace/lib-fwtrace.sh`), and TRACE.md says so.
4. **The audit's NTP line named a server the firewall had not synched to** (every step 0 failed; found in the desk work). `make audit`'s verdict read `show ntp: synched to 10.20.13.21` while its own `fw-edge/ntp.txt` read `NTP synched to 10.20.14.21`: the judge printed the first configured server and checked only that the firewall was synched to something. `common/audit/judge.py` now names the server `show ntp` reports and passes only when it is one of the configured ones (`common/tests/test_ch04.py`).
5. **Both traces passed the pull's log line on other sessions' entries** (every step 0 failed; found in the desk work). PAN-OS writes the line at session end, containerd kept its connection to the registry open after the pull, and the judge matched any entry from the node to the registry: the only ones in the file were the audit's earlier pulls. `common/trace/fwtrace.py` now takes the first SYN's source port and passes only on that session's own line, and the trace reads the log for that port for up to 300 s (`common/tests/test_ch04.py`).

Facts the deployment from the public repository shows and a reader should know (`audits/INDEX.md`, "The deployment from the public repository", has the lines):

- **The internal Gateway's lease** was on k8s-ingress2 in every audit of this deployment, where every audit of the earlier deployment read k8s-ingress1 (CA/verdict.txt:838); the users' Gateway's lease was on k8s-ingress2 in both. Every audit passed either way.
- **The firewall's NTP took either resolver** here too: dns-res1 in CU, CHA and CRA, dns-res2 in CA (each set's `fw-edge/ntp.txt:3`).
- **The walks.** CT's pull SYN came in on ae1 leg 1 and CRT's on leg 2, the other way round from the earlier deployment's T and RT.

Facts the earlier deployment's recordings show and a reader should know (`audits/INDEX.md`, "Notes", has the lines):

- **`nodes-to-public-ping` is this lab's own rule**, there for the probe; Chapter 4's rulebase has one rule more than the other chapters' labs.
- **The firewall's NTP took either resolver**: dns-res1 in U and A, dns-res2 in HA and RA.
- **The pull's frames ran on both legs**: the node's SYN came in on one leg of ae1 and the registry's answers went back on the other, each side choosing by its own hash.
- **The MSS is not adjusted on the pull's path**: the node's SYN keeps MSS 8960 across the source NAT and the registry answers 1460.
- **containerlab's writes on the host.** While the lab ran, containerlab's block in `/etc/hosts` and its SSH configuration file named every node; `make down` removed both.

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` and the `sfab/*` images with the in-lab registry seeded, 142.75 GiB of MemAvailable and no other `sfab-` lab running:

```
git clone https://github.com/aramidetosin/ai-serving-fabric-labs.git
cd ai-serving-fabric-labs/ch04
make down && make wipe
make up
make audit
make trace
make drills PASSES=3
make break-4a
make heal-4a
make record
make down
```

On the earlier deployment, `make up` took 47 min 48 s from wiped disks: boot 1464 s (the switches 507 s, the firewall 454 s, the secondary zones 303 s), finish 565 s (storage 143 s, the settle 233 s, the Warning events 108 s), the audit 815 s (N/rec-make-up.txt:310, :337, :386, :388, :426, :430, :434, :718, :1690). `make audit` took 13 min 32 s, `make trace` 3 min 15 s, `make drills PASSES=3` 31 min 11 s, `make break-4a` 3 min 19 s, `make heal-4a` 15 min 53 s with its chapter audit, `make record` 16 min 52 s and the closing `make down` 1 min 56 s (N/chain.log). `state/` held 22G after `make record` (N/host-after-record.txt:16).

## What the recordings do not show

- **A `git clone` line in the earlier deployment.** Its chain began at `make down`; the recorded clone is the deployment from the public repository's (CN/rec-git-clone.txt), which made a clone of its own in an empty directory and deployed from a clone of the same commit and tree (CN/clone-check.txt:2 to :7).
- **The whole image pull.** Each capture point kept the pull's first 5000 frames; the frame counts and reply bytes in T, RT, CT and CRT are of those frames.
- **Why the firewall's NTP picked one resolver or the other.** The lab records only which one `show ntp` named.
- **Why the firewall's NTP follows the DNS service route** when both servers are one address (revision 1's problem 5, not published, FRAMEWORK.md 4.4); the drill moves both routes, as before.
- **A licensed firewall.** The PA-VM runs unlicensed on its factory content: App-ID works, the profiles carry no signatures, and nothing here tests threat prevention.
- **A public commit in the earlier deployment's `RUN.json`.** Each of its `RUN.json` files names, from the copy's stamp, a commit of the pre-release history, which is not in this repository, with `dirty: true`; the runs used that commit plus the later work `audits/INDEX.md` names, and the repository's first public commit holds that code with the one later change the same page names. The deployment from the public repository's `RUN.json` files name the public commit `752b5f49`, `dirty: false`.
- **A `make up` on kept disks.** Both recorded deployments came from wiped disks.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge. No recorded run exercised the redirect path a stock kernel takes (`../README.md`, "The host").
