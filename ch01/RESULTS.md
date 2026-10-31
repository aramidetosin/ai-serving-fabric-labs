# Chapter 1 results

What lab `sfab-ch01` proved on its recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-10-29 from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `vrnetlab/truenas_truenas:27.0.0-RC.1` (d0b0a42ff2d3), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4` (0e82fde37b3d), `sfab/resolver:3` (d0fabd25e229), `sfab/vpngw:3` (d5db2071ca65) and `sfab/frr:10.5.4-3` (234239dc64b1) among the ten its `RUN.json` files name, and in the cluster the serving image `sfab/serving:b11382-2` with the models LFM2.5-24B-A2B (chat) and Qwen3.8-27B (staff). Every command ran in tmux under `script`, so each journal shows the command exactly as typed: `make down` and `make wipe` from 13:56:15, `make up` from 13:59:21 to 14:55:23, `make audit`, `make trace`, `make break-1a`, `make heal-1a`, `make record` from 15:39:19 to 16:01:05 and `make down` to 16:04:46 (UTC, the lab host's clock). No container restarted between the end of `make up` and the end of `make record`.

The short names are the index's: N is `audits/sfab-ch01_record-run_20261029T135614Z/`, U `audits/sfab-ch01_audit_20261029T143747Z/` (the audit `make up` ran), A `audits/sfab-ch01_audit_20261029T145533Z/`, T `audits/sfab-ch01_trace_20261029T151312Z/`, B `audits/sfab-ch01_break-1a_20261029T151716Z/`, H `audits/sfab-ch01_heal-1a_20261029T152005Z/`, HA `audits/sfab-ch01_audit_20261029T152145Z/` (the chapter audit H ran), RA and RT `audits/sfab-ch01_audit_20261029T153920Z/` and `audits/sfab-ch01_trace_20261029T155702Z/` (the audit and trace `make record` ran).

## Revision 2, against revision 1

Revision 1's sets (one deployment on 2026-10-27) are superseded and out of the repository (`audits/INDEX.md`, "Superseded sets"). What revision 2 changes in what the chapter shows:

| Part | Revision 1 | Revision 2 |
|---|---|---|
| Node names | ctrl1 to ctrl3, gpu1, gpu2; 18 containers | k8s-cp1 to k8s-cp3, k8s-gpu1, k8s-gpu2, the ingress nodes k8s-ingress1 and k8s-ingress2, the DNS and time servers dns-auth1, dns-auth2, dns-res1, dns-res2, ent-dns, inet-ntp, the operator's ops-gw and the web client; 28 containers |
| Names and resolvers | `llm.tarnwick.example`; the bastion the clients' resolver | `llm.ai.tarnwick.example` under the delegated subdomain; ent-client asks ent-dns, which forwards the platform's names to the authoritative pair |
| The users' VIP | 10.20.1.210 in VLAN 100, held by a control node, the SYN untagged after the pair; zone `data`, rule `enterprise-to-users-gateway` | 10.20.11.210 in VLAN 110, held by an ingress node (k8s-ingress2), the SYN tagged 110 to its bond; zone `ingress`, rule `staff-to-users-gateway`, by App-ID `ssl` |
| The pair | the keepalive in VRF mgmt, MTU 9100, no loop protection | a dedicated keepalive link and a backup over Vlan3966, both in VRF VrfMclagKa; MTU 9216, PVST, BPDU guard, storm control |
| The keys | per-model keys; the refusal `Invalid API key in request` | per-caller keys (chat's route admits the batch and staff callers' groups); the refusal `Authorization Failed` |
| The models and placement | Qwen2.5-0.5B, each copy spanning both GPU nodes; chat b answered | LFM2.5-24B-A2B and Qwen3.8-27B; four copies node-local and chat c spanning both nodes; T landed on chat c (RPC across rail-sw1), RT on chat a (none on the rails) |
| The audit | 691 checks | 1036, the DNS and time servers, Layer 2 hygiene, the egress refusal, the cluster's security, sign-in and the operator's tunnel among the new ones |
| break-1a | `enterprise-to-users-gateway`, 10.20.1.210 to 10.20.1.211 | `staff-to-users-gateway`, 10.20.11.210 to 10.20.11.211 |

## What the lab proved

| Claim | Verdict lines |
|---|---|
| Build A deploys whole from wiped disks in one `make up`: 28 containers, every switch with its KLISH startup configuration applied and in parity with the render, the firewall's delivered configuration byte for byte as rendered and its IPsec tunnel to the operator's site up, the cluster, storage, the serving recipe, the API gateway and the router, then an audit with no FAIL | N/rec-make-up.txt:41, :313, :390, :452, :853, :2019; A/verdict.txt:70, :77, :158, :169 to :173 |
| The pair, both rail switches and the out-of-band switch forward only: no address but Management0 in VRF mgmt and, on a pair member, its two keepalive /31s in VRF VrfMclagKa, whose table holds only them; nothing in `show ip route`, no `router` line, no address on a served VLAN, a PortChannel or a host port | A/verdict.txt:363 to :417 |
| The firewall holds every gateway of build A's plan on its interface and zone: ae1.100, .110, .130, .131, .200 and .300 on the bundle the pair terminates under its system MAC, ethernet1/3 for the out-of-band network, ethernet1/4 and ethernet1/7 for the enterprise LAN and ethernet1/5 for the uplink; the 24 security rules and 2 NAT rules run in the render's order with `deny-all-log` last | A/verdict.txt:161 to :168, :1073 to :1088 |
| The pair runs its session with active and standby roles from the keepalive addresses, the keepalive and its backup in VRF VrfMclagKa and the ICCP session there; every PortChannel on its members, every bond on two legs under the system MAC with fast LACP; the Layer 2 hygiene on every switch | A/verdict.txt:418 to :536, :714 to :743 |
| The cluster's audits of chapters 5 to 7 pass inside build A whole: the rail backend's absences, the placement table, the callers' keys, sign-in and the Gateway layer; the three populations get their own answers through their own resolvers; TrueNAS serves a volume on each class; Secrets at rest, WireGuard, the Gateways' keys and network policy as rendered | A/verdict.txt:537 to :713, :976 to :993, :1035 to :1072 |
| The edge refuses what it must: an egress the allowlist does not name is dropped and logged; nothing administrative answers on the uplink; the operator's forbidden cells die at the firewall | A/verdict.txt:1091 to :1101, :1119 to :1129 |
| One chat completion from the enterprise client, walked inward, is decided by one table at each device: ent-dns answers the users' VIP (another resolver's view answers the internal one), the firewall's connected route on ae1.110, no NAT rule from `enterprise`, and `staff-to-users-gateway` first; the session in zones `enterprise` to `ingress` with no translation, and its traffic log line | T/verdict.txt:5 to :19; T/TRACE.md:11 to :15 |
| The same SYN, by sequence number, crosses the firewall onto exactly one leg of ae1 tagged 110 with its addresses and ports kept and its TTL one lower, then the pair port that leg lands on and that switch's port facing the lease holder, tagged 110, and reaches the lease holder's bond with the MACs, TTL and IP id the leg carried: no routed hop between the firewall and the Gateway | T/verdict.txt:21 to :30; RT/verdict.txt:21 to :30 (the other leg and the other pair member) |
| Inside the cluster: k8s-ingress2 holds the users' VIP's lease, the first rule of `inference/models-gw-users` matched, the API gateway accepted the batch caller's key and set the router's master key in its place, the router's model list named chat's Service, and the answering server was among its ready endpoints, its RPC on the rail the placement table names | T/verdict.txt:34 to :65 |
| The rail switch carries a spanning copy's RPC and nothing of a node-local one: for chat c the port facing the remote worker counted at least the RPC frames its capture saw between the counter reads, with the worker's rail MAC on that port; for chat a the port facing its node carried no RPC frame | T/verdict.txt:45 to :49, :67, :68; RT/verdict.txt:62 |
| Three requests that must fail each died at its own layer, with nothing of it past the device that refused it: the admin hostname at the users' Gateway (404, no API gateway pod saw it), staff's key on chat's route at the API gateway (401, `Authorization Failed`, no router pod received it), k8s-gpu1's SSH port at the firewall (`deny-all-log`, deny, no SYN on either leg) | T/verdict.txt:69 to :81; T/TRACE.md:26 to :32 |
| break-1a: with `staff-to-users-gateway`'s destination moved to 10.20.11.211, every request and every connect from the enterprise client fails, the connects' SYNs reach ethernet1/4 and neither leg, and the traffic log names `deny-all-log` for each; the heal puts the rendered destination back and every request and connect answers, with the rule named allow, and the chapter audit is green | B/verdict.txt:2 to :12; H/verdict.txt:2 to :14 |
| The trace and the audit after the break and heal, on the same deployment, as before them | RA/verdict.txt:1133; RT/verdict.txt:76 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster and named by field, fingerprint and keyed mark only | T/request/key.txt:1, master-key.txt:1, backend-key.txt:1, key-staff.txt:1 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch01_audit_20261029T143747Z` (the audit `make up` ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| A, `sfab-ch01_audit_20261029T145533Z` (`make audit`) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| T, `sfab-ch01_trace_20261029T151312Z` (`make trace`) | `== RESULT: 63 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| B, `sfab-ch01_break-1a_20261029T151716Z` (`make break-1a`) | `== RESULT: 8 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch01_heal-1a_20261029T152005Z` (`make heal-1a`) | `== RESULT: 9 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch01_audit_20261029T152145Z` (the chapter audit heal-1a ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RA, `sfab-ch01_audit_20261029T153920Z` (the audit `make record` ran) | `== RESULT: 1036 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RT, `sfab-ch01_trace_20261029T155702Z` (the trace `make record` ran) | `== RESULT: 57 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA, RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:1279) |
| the gate on U, A, T, B, H and HA | `== RESULT: 36 passed, 0 failed, 0 known platform limitation(s), 13 skipped` (N/gate-sets.txt:57) |

The three SKIPs in every audit are TrueNAS's own LACP view, which is not collected, the LAND counter, which this lab has no drills plan for, and namecheck, which the lab host runs without the author's scrub list; the gates' SKIPs are namecheck and the literal scan for the same reason. A run with the scrub and literals lists, over every committed set, found nothing (`audits/INDEX.md`).

## What the deploys found

Four revision 2 attempts on this host stopped before the recorded deployment; each was fixed in the lab code with `make test-quick` green, and the sequence started again from `make down` and `make wipe`. Their sets are not published (FRAMEWORK.md 4.4).

1. **The walk's judge still read revision 1's design** (attempt 1, `make trace` 55 passed, 2 failed). It wanted the users' VIP's lease held by a control node, while revision 2's L2 announcement policy selects the ingress nodes, and chat's API gateway route to admit the consumer group `chat` alone, while revision 2 has a group per caller (batch and staff). `common/trace/walktrace.py` now takes the announcing nodes from the inventory (`k8s.l2_announce.nodes`, as the Gateway layer audit does) and wants the walked key's caller among the route's groups (`common/tests/test_ch01.py`, `ClusterTables`).
2. **udev gave an ingress node's bond its own MAC** (attempt 2, finish's quick audit 345 passed, 2 failed). Both pair members' MAC tables held k8s-ingress2's bond on a MAC that was not the rendered one. On that guest's first boot `netsetup.sh` set the rendered MAC right after creating the bond, and udev, handling the bond's add event late under the image's default `MACAddressPolicy=persistent`, then set its own; the members and bond0.110 took it. `images/vm-node/node-files/netsetup.sh` now waits for udev (`udevadm settle`) after creating the bond and reads the MAC back once the bond is up, setting it again with a warning if it changed. node-sync installs the checkout's copy on every guest at boot (N/rec-make-up.txt:372 to :389), so no image was rebuilt.
3. **A router's model-list read taken for the request** (attempt 3, `make record`'s trace 55 passed, 8 failed). 8.4 s before the request reached the router, the router read two copies' model lists, chat c's among them; `common/trace/servetrace.py` took the router's first data to any server of the model as the request's upstream and judged chat c, which never ran the request. The judge now reads the router's upstream only inside the request's life at the router, both ends from the router's own capture (`common/tests/test_ch06.py`, `test_the_routers_upstream_is_read_inside_the_request`). The walk's Service line also stopped saying the router picked the copy: the router names only the Service, and the Service's load balancing picks it.
4. **A node-local copy left the trace without `TRACE.md`** (attempt 4, every step 0 failed). `make trace` landed on chat b, node-local, and the TRACE.md writer stopped on a `KeyError` after the verdict was written; the shell hid it and the set closed without its table. The hop table now writes row 14 for a node-local copy (the rail switch port facing its node, no RPC frame), and `common/trace/lib-walktrace.sh` fails the trace when the judge leaves no `TRACE.md`. In the recorded deployment T landed on chat c and RT on chat a, so both forms of row 14 are on record.

Facts the recordings show and a reader should know:

- **The two walks took different legs.** T's SYN left on ethernet1/1 and crossed fe-sw1, RT's on ethernet1/2 and crossed fe-sw2, both to k8s-ingress2 with the same addresses and ports (source port 42106) (T/verdict.txt:23 to :27; RT/verdict.txt:23 to :27).
- **The firewall rewrites the SYN's MSS.** 1460 at the client and on ethernet1/4, 1360 on the bundle leg and beyond (T/captures/2-fw-ethernet1-4.txt:3, 3-fw-ae1-leg1.txt:3).
- **A held session ends with a reset.** The walk holds its connection 30 s after the answer and its client then closes it; the traffic log's end reason reads `tcp-rst-from-client` (T/sessions/walk/traffic-log.txt:8).
- **The refused SSH connect retransmits.** Its SYN was captured five times on the client's port and the firewall's interface within the client's 5 s timeout (T/verdict.txt:79), and break-1a's three connects fifteen times on ethernet1/4 (B/verdict.txt:10).
- **containerlab's writes on the host.** While the lab ran, containerlab's block in `/etc/hosts` and its SSH configuration file named every node (N/clab-writes-before-down.txt); `make down` removed both (N/host-after-down.txt:11, :12).

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` and the `sfab/*` images with the in-lab registry seeded, the two models in `images/models`, 195 GiB of MemAvailable and no other `sfab-` lab running:

```
cd ch01
make up
make audit
make trace
make break-1a
make heal-1a
make record
make down
```

`make up` took 56 min 2 s here from wiped disks: boot 1146 s (the switches 507 s, the firewall 454 s after them), finish 1135 s (storage 141 s, the serving recipe 236 s, the API gateway and the router 67 s, the settle 236 s), the audit 1056 s (N/rec-make-up.txt:1, :324, :351, :391, :431, :434, :443, :447, :855, :2021, :2023). `make audit` took 17 min 38 s, `make trace` 4 min 5 s, `make break-1a` 2 min 48 s and `make heal-1a` 19 min 14 s with its chapter audit, and `make record` 21 min 46 s (N/chain.log). `state/` held 32689480 kB before the down, the VM guests' disks 32676876 kB of it (N/state-du.txt).

## What the recordings do not show

- **A GPU.** The models run on CPU, split over RPC workers for the one spanning copy; nothing here measures a GPU or publishes a throughput figure.
- **A key in clear.** Every key is made in the cluster and every capture that could hold one is scrubbed before it is written.
- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's (`../README.md`, "Clone, build, deploy"); Example 1-1 opens at `cd ch01`.
- **ent-dns's own query to the authoritative pair.** The trace captures the client's lookup and its answer, not the forwarded query; the forwarding is the render's (`bootstrap/ent-dns/dnsmasq.conf`) and the audit's (A/verdict.txt:907).
- **The setting behind the MSS rewrite.** The captures show the firewall changing 1460 to 1360; no recorded read names the option that does it.
- **A public commit in `RUN.json`.** Each `RUN.json` names, from the copy's stamp, a commit of the pre-release history, which is not in this repository, with `dirty: true`; the runs used that commit plus the uncommitted changes `audits/INDEX.md` names, and the repository's first public commit holds that code with the later changes the same page names.
- **A `make up` on kept disks.** The recorded deployment came from wiped disks.
- **The many-tenant state.** This lab is build A with one tenant; the other audiences and their isolation come with chapters 8 to 11.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge. No recorded run exercised the redirect path a stock kernel takes (`../README.md`, "The host").
