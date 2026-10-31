# Chapter 3: Layer 2 Frontend with MCLAG

Lab `sfab-ch03`, the companion lab of the book's Chapter 3, "Layer 2 Frontend with MCLAG". It runs build A's one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`), as milestone M2 renders it, and adds what the chapter teaches about the pair: the domain's roles and its ICCP session over the pair's own keepalive link, the backup keepalive over the peer link, every bond's legs under the system MAC, the pair's Layer 2 hygiene (MTU, BPDU guard, storm control), one SYN traced at four points, the pair's failure drills in three passes, break-3a and break-3b.

Status: build A revision 2 is rendered, tested against the stand-ins (`common/tests/test_ch03.py`, `common/sfab/tests/test_drills_render.py`) and recorded on 2026-10-29 in one deployment from wiped disks: `make up`, `make audit`, `make trace`, `make dbs`, the six drills in three passes, break-3a, heal-3a, break-3b, heal-3b and `make record`, every step 0 failed (`RESULTS.md`, `audits/INDEX.md`). The revision 1 sets are superseded and out of the repository.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, ent-client, truenas1]`, M2's; its closure adds the ingress nodes, the platform's DNS and time servers (dns-auth1, dns-auth2, dns-res1, dns-res2), the corporate resolver ent-dns, the operator's site router ops-gw and the time reference inet-ntp |
| Features | `{k8s: true, serving: false, storage_setup: true}` |
| Prints | `fe-sw1`, `fe-sw2`: the chapter prints both pair members, so both deploy whole |
| Containers | `sfab-ch03-<node>` (26); containerlab directory `clab-sfab-ch03/` |

`make show WHAT=ports` prints the pair's port plan, the book's Table 3-2: both switches use the same 19 data ports (the peer link on Ethernet0 and Ethernet1, the firewall's ae1 leg on Ethernet2, k8s-cp1 to k8s-cp3 on Ethernet3 to Ethernet5, k8s-gpu1 and k8s-gpu2 on Ethernet6 and Ethernet7, the bastion on Ethernet8, TrueNAS's data bond on Ethernet9 and Ethernet10, TrueNAS's management bond on Ethernet11, the dedicated keepalive link on Ethernet12, k8s-ingress1 and k8s-ingress2 on Ethernet13 and Ethernet14, and dns-auth1, dns-res1, dns-auth2 and dns-res2 on Ethernet15 to Ethernet18).

## The pair (build A revision 2)

| Element | Configuration |
|---|---|
| Peer link | PortChannel1 on Ethernet0 and Ethernet1: the served VLANs and Vlan3966 only, MTU 9216 |
| Keepalive | the dedicated routed link Ethernet12 on both switches, in VRF `VrfMclagKa`: fe-sw1 10.20.255.0/31, fe-sw2 10.20.255.1/31; `source-ip`, `peer-ip`, `session-vrf VrfMclagKa` |
| Backup keepalive | `interface Vlan 3966` on the peer link only, in `VrfMclagKa` with `mclag-separate-ip`: fe-sw1 10.20.255.4/31, fe-sw2 10.20.255.5/31; `backup-keepalive source-ip`, `peer-ip`, `session-vrf VrfMclagKa`, `interval 1` |
| MTU | 9216 on every PortChannel and every member (a member's `mtu` typed before its `channel-group`), on the keepalive link, and on every rail access port |
| Loop protection | `spanning-tree mode pvst` on both pair members and both rail switches; every host-facing PortChannel and rail access port an edge port (`spanning-tree portfast`) with `spanning-tree bpduguard port-shutdown`; the peer link (outside spanning tree under MCLAG) and the firewall's trunk are not edge ports |
| Storm control | `storm-control broadcast`, `unknown-unicast` and `unknown-multicast 10000` (kbps) on each member of a host-facing PortChannel and on each rail access port (SONiC 4.6.0 refuses it on a PortChannel) |

The pair owns no gateway and runs no routing protocol. Its only addresses are the four keepalive /31s above, all in `VrfMclagKa`, whose table holds only their two connected routes; nothing routes into that VRF. VLANs 3967 to 4094 are reserved on SONiC 4.6.0 (`show system vlan reserved`), so the backup keepalive's VLAN is 3966. The switch takes `mclag-separate-ip` only once the MCLAG domain exists, so the startup file types it in a second `interface Vlan 3966` block right after the domain.

## Requirements

The same as milestone M2 (`dev/m2/README.md`): the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` (`images/VENDOR-IMAGES.md`) and the `sfab/*` images from `make -C images all`, with the registry seeded; 126.5 GiB of memory budget plus the 16 GiB floor, 142.5 GiB of MemAvailable in all (preflight refuses below it, and neither figure is lowered to fit); 62 vCPUs within twice the host's CPU count; 95 GiB of growth under `state/` and 56 GiB of container layers; the host tick at 10000 (read and recorded, never refused on); containerlab 0.82.0 (the revision 1 sets were recorded on 0.81.1 and 0.82.0); no other `sfab-` lab running.

## Running it

```
cd ch03
make render          # topo.clab.yml, bootstrap/ and gen/ (gen/drills.json and gen/breaks.json among them)
make up              # preflight, up, boot, finish, audit (book Example 3-1)
make audit           # audits/sfab-ch03_audit_<UTC>/ (Example 3-2)
make trace           # audits/sfab-ch03_trace_<UTC>/ with TRACE.md (Example 3-5)
make dbs             # audits/sfab-ch03_dbs_<UTC>/: k8s-gpu1's member Ethernet6 on fe-sw1 through SONiC's databases, read-only (Examples 3-6 to 3-9, Table 3-3)
make drills          # audits/sfab-ch03_drills_<UTC>/ with DRILLS.md, three passes (Examples 3-10 to 3-12)
make record          # after the drills: audit, trace, then the gate on both sets (Example 3-13)
make break-3a        # audits/sfab-ch03_break-3a_<UTC>/ (Exercise 4)
make heal-3a         # audits/sfab-ch03_heal-3a_<UTC>/, then the chapter audit
make break-3b        # audits/sfab-ch03_break-3b_<UTC>/ (Exercise 5)
make heal-3b         # audits/sfab-ch03_heal-3b_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make drills DRILLS="fw-leg server-member" PASSES=1` runs a subset. The recorded drills ran as three sets of three passes each, `DRILLS="fw-leg server-member peer-link"`, `DRILLS="keepalive-link"` and `DRILLS="keepalive-and-peer-link standby-reboot"`, so each set fits the recording size policy's 64 MiB cap (FRAMEWORK.md 4.4): the keepalive drills keep their captures running through the 300 s hold-down, and both probes run every 0.3 s for the same reason. `make up BG=1` runs the deploy as the transient unit `sfab-ch03-up`.

Once the lab is up, `ssh admin@sfab-ch03-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## The audit

`audit.sh` runs M2's audit (the shared checks, chapter 2's forwarding-only reads, the pair, then the cluster and its security, the bastion, the platform's DNS and time servers, the uplink side, the clients, storage, the populations and a volume on each class) and adds three groups of `common/audit/judge.py`:

- **pair-roles**: the switch with the lower keepalive source address (10.20.255.0, fe-sw1) is active and the other standby, as `show mclag brief` prints them; on both switches, the ICCP session established on TCP 8888 inside VRF `VrfMclagKa` between the two keepalive addresses, and iccpd listening there (`sudo ss -tanp | grep 8888`); and iccpd's own keepalive state (`docker exec iccpd mclagdctl -i 1 dump state`). The chapter puts its alarm on the keepalive's session state, so the audit reads it directly.
- **bond-legs**: each leg of every bond toward the pair, aggregated under the mclag-system-mac 02:5a:00:00:00:01: each host's `bond0` leg by leg from its own `/proc/net/bonding/bond0` (the control, ingress and GPU nodes, the bastion and dns-auth1, dns-auth2, dns-res1 and dns-res2; the leg in the active aggregator, its partner's system MAC, both port states aggregating, and the short timeout set on both sides, fast LACP both ways); the firewall's ae1 member by member from `show lacp aggregate-ethernet all`; TrueNAS's data bond and its management bond from the pair's side only (each PortChannel up with every member selected on both switches), with a SKIP line saying its own LACP view is not collected.

- **l2-hygiene** (not in the quick audit): on both pair members and both rail switches, `spanning-tree mode pvst`; every used port at its rendered MTU (9216) by `show interface status`; BPDU guard with port-shutdown on every edge port, none shut by it, and on no other port (`show spanning-tree bpdu-guard`); storm control of each type at 10000 kbps on every member and access port the policy names (`show storm-control`).

M2's pair check (`mclag-pair`) reads the session in `VrfMclagKa` on the keepalive link's addresses and the backup keepalive's own session (up, its source, peer and VRF), and chapter 2's forwarding-only reads now allow exactly the keepalive addresses: `show ip interfaces` lists Management0 (VRF mgmt), Ethernet12 and Vlan3966 (both in `VrfMclagKa`, at their rendered addresses) and nothing else; `show ip route` prints nothing; `show ip route vrf VrfMclagKa` holds only the two connected /31s; no served VLAN's `interface Vlan` block, no PortChannel and no host port holds an address; and the kernel holds no other address on a Vlan, PortChannel or Ethernet netdev.

`audit.sh --quick` reads the switches, the firewall and the container links the MAC tables need, and is not recorded.

## The trace

`trace.sh` (`common/trace/lib-trace.sh`, `common/trace/trace-md.py`) follows one HTTPS SYN from `ent-client` (10.24.10.10) to the users' VIP 10.20.11.210, in the ingress VLAN 110, with the recorded attempt's source port pinned to 41443 after a warm-up from 41442. The four points are chapter.yaml's: the SYN leaving the firewall on one ae1 leg (`1-fw-ae1-leg1` or `leg2`, tagged 110), entering the pair on the trunk port that leg lands on (`2-fe-sw1-Ethernet2` or `2-fe-sw2-Ethernet2`, tagged 110), leaving that switch on the server port toward the Gateway's lease holder, an ingress node (`3-<switch>-<port>`, tagged 110: the ingress nodes' bonds carry their node VLAN 100 untagged and VLAN 110 tagged), and on the holder's `bond0` (`4-<holder>-bond0`, tagged 110). Each point with legs is captured on both legs (the trace prints how many captures it ran), and the judge wants the SYN on exactly one leg of each. With `same_frame` it also wants one frame at all four points: the same source and destination MACs, addresses, IP id, TTL and sequence number, and the holder's bond MAC as the destination. The lease holder and the ae1 leg change between deploys and between traces (M2), so both are read from the run.

## The drills

`drills.sh` (`common/drill/`) runs chapter.yaml's six drills, in the plan's order, once per pass (`PASSES=3` by default). The method: probes placed by address and bond leg, each probe located before the cut, round trips rather than one-way loss, and the passes printed side by side with their disagreements.

Every drill runs two probes. The **ping** runs in k8s-gpu1 toward k8s-gpu2 (10.20.1.22): eight `ping -D -O -i 0.3 -W 1 -e <id>` processes at once, one ICMP id each, which the guests' layer3+4 bond hash places on a leg. The **TCP connect loop** (`probe_tcp.py`) runs in `ent-client` toward the users' VIP 10.20.11.210:443 every 0.3 s, a new source port each time, which the firewall's own hash places on an ae1 leg. tcpdump on the lab host, in the guests' and the firewall's container ports, records every request, reply, SYN and SYN-ACK with the host's clock; the guest's own ping log is the second witness of each round trip.

Each drill, in order: the lab whole (the pair's session, roles and every PortChannel as rendered, every bond on two legs under the system MAC, in two consecutive polls); captures and probes started; after `lead_s` the captures so far are decoded and `drill.py place` says whether the probes sit where the drill needs them (not placed, the pings restart with new ICMP ids, up to `place_tries`); the fault; the restore, or the reboot's return; the probes and captures stopped; the lab whole again; `audit.sh --quick`; `drill.py analyze`.

| Drill | Fault | The probe it exercises | Placed when |
|---|---|---|---|
| `fw-leg` | fe-sw1 Ethernet2 (PortChannel10's member facing the firewall's ethernet1/1) `shutdown`, held 30 s, then `no shutdown` | the TCP connects; the ping never crosses the bundle and is the control | connects leave the firewall on both legs |
| `server-member` | fe-sw1 Ethernet6 (PortChannel21's member facing k8s-gpu1's eth1), the same way | the ping; the TCP connects are the control | some ping ids cross fe-sw1, some do not |
| `peer-link` | fe-sw1 `interface range Ethernet0-1` (both peer-link members) `shutdown`, the keepalive link up | both | requests leave k8s-gpu1 on both legs |
| `keepalive-link` | fe-sw1 Ethernet12 (the dedicated keepalive link) `shutdown`, held 70 s (past the 30 s session timeout), then `no shutdown`; the peer link and the backup keepalive stay up; then a wait of up to 600 s for the pair whole and every bond on two legs | both: the standby shuts its own MCLAG PortChannels | requests leave k8s-gpu1 on both legs |
| `keepalive-and-peer-link` | fe-sw1 Ethernet0, Ethernet1 and Ethernet12 `shutdown` together (both keepalive paths gone), held 70 s, then the same wait | both | requests leave k8s-gpu1 on both legs |
| `standby-reboot` | `sudo reboot` (under a 25 s timeout) on the switch `show mclag brief` names standby when the drill runs | both | some ping ids cross the standby |

The member drills read the peer link's counters before, during and after the fault (the host-side counters of its member ports, and `show interface counters` on both switches), so the peer link can be sized as a path. The two keepalive drills run the same monitor through the cut, the hold and the wait, and record the standby's events from it (the session lost, its own MCLAG PortChannels down, every bond on one leg, the session back, its PortChannels up again) with the drill's own return poll. The reboot drill runs a monitor every few seconds (every bond's legs, both switches' MCLAG and PortChannel state through `sonic-db-cli` and `mclagdctl` on the switch's Linux side, the firewall's LACP); its departure is timed from the reboot command, and its return, every bond back on two legs, is recorded as an event with the probes lost around it. After it returns, GRO and parity are checked on that switch.

Each pass writes `pass<N>/<drill>/` (timeline, placement, captures and their decodes, the probe logs, the KLISH snapshots, the counters, the monitor, `analysis.json` and `analysis.txt`); `compare.txt` and `DRILLS.md` close the set.

## break-3a

`breaks/3a.yaml`, rendered to `gen/breaks.json`: fe-sw2 drops VLAN 200 from PortChannel10's allowed list, so the firewall's PortChannel allows VLAN 200 on fe-sw1 only. `make break-3a` types it (`switchport trunk allowed Vlan remove 200`, else the fallback `no switchport trunk allowed Vlan 200`; the set records which form the switch took, and the break file is then fixed to it), records `show vlan`, `show running-configuration interface PortChannel 10` and `show mclag brief` on both switches, and runs 60 connects from the bastion to 10.20.2.31:443 in each of three passes, printing each pass's failing share. It passes when fe-sw2's VLAN 200 lacks PortChannel10, fe-sw1's still has it, and some connects fail while others succeed. `make heal-3a` replays fe-sw2's render where its running configuration misses it, checks parity and both switches' VLAN 200, runs the connects again (all must succeed), then the chapter audit.

## break-3b

`breaks/3b.yaml`, rendered to `gen/breaks.json` (Exercise 5): one leg of TrueNAS's management bond unplugged. Its management address, 10.20.2.31 in VLAN 200, is a bond with one leg on each switch (eth5 on fe-sw1 Ethernet11, eth6 on fe-sw2 Ethernet11, PortChannel32 on both, an MCLAG interface of the domain), so no port of the pair is an orphan. `make break-3b` types `shutdown` on fe-sw1's Ethernet11, records `show mclag brief`, `show interface status` and `show running-configuration interface PortChannel 32` on both switches, and runs 60 connects from the bastion to 10.20.2.31:443 in each of three passes. It passes when `show mclag brief` reads PortChannel32 `down/up` (Local/Remote) on fe-sw1 and `up/down` on fe-sw2, and every connect succeeds: the bond runs on its fe-sw2 leg, and frames that reach fe-sw1 for it cross the peer link. A KLISH `shutdown` drops no carrier at TrueNAS's NIC (L9 below), so TrueNAS keeps sending on the shut leg until its fast LACP times out, about 3 s; the connects start after the break's settle and the switches' reads. `make heal-3b` types `no shutdown`, wants PortChannel32 `up/up` on both switches, parity on fe-sw1 and every connect answered, then runs the chapter audit. The check reads `show mclag brief` with the parser the pair's audit uses (`breakheal.py mclag`). The recorded run: `audits/sfab-ch03_break-3b_20261029T062058Z/` and `audits/sfab-ch03_heal-3b_20261029T062301Z/`, 0 of 180 connects failed while broken.

## Platform notes for this lab

M1's and M2's notes hold here (`dev/m1/README.md`, `dev/m2/README.md`). For the pair and its drills:

- **Duplicate replies** in a ping across the pair are the peer-link isolation limit (L1): the virtual switch does not isolate, so broadcast that crosses the peer link comes back out the MCLAG bonds. The drills count each sequence number once and print the duplicates as a KNOWN L1 line.
- **A KLISH `shutdown` drops no carrier at the far end** (L9). The host or the firewall keeps sending on a shut member until its LACP partner times out, so every member figure is an LACP-timeout figure; the drill sets say so on a KNOWN L9 line.
- **`delay-restore 300` and a reboot** (L2). A rebooted standby rejoins as soon as it boots and LACP converges, so its return is recorded as an event, never as a span from its departure. After a keepalive-only cut, by contrast, the standby held its MCLAG PortChannels down for about 300 s after the keepalive came back, in each of the three passes of the recorded set (`audits/sfab-ch03_drills_20261029T050430Z/`, `keepalive-link`: the session back at T0+74.5 to +82.6 s, every bond back on two legs at +377.1 to +380.9 s, as the monitor read them every few seconds); the drill waits for that return and records it as an event.
- **The trade-off of the backup keepalive.** With the backup up, losing only the keepalive link loses the session (iccpd's keepalive not OK at T0+39.4 to +40.1 s across the three recorded passes), and the standby then shuts every MCLAG PortChannel (every bond on one leg at +73.8 to +74.6 s) and keeps them down for delay-restore once the link is back, so every host runs on the active switch alone until about T0+377 s; the ping ids on the standby's legs lost 19 to 22 round trips each, those on the active's none. Losing the keepalive link and the peer link together loses the session as well (+40.4 to +40.6 s) but shuts nothing and holds nothing down: the ids on fe-sw2's legs lost 13 to 14 round trips each, and the pair was whole again 31 to 32 s after the restore (`audits/sfab-ch03_drills_20261029T053410Z/`). Each pass's `analysis.txt` times these events from the monitor, on the host's clock; loss is counted in round trips of one flow per ICMP id. The probes run every 0.3 s, so these counts are not comparable with the 0.1 s probes of earlier sets.
- **`sudo reboot` hangs the SSH session** ("Reboot failed! Trying systemctl --force reboot"), so the drill sends it under a 25 s timeout and reads the switch's state from the monitor.
- **GRO, rx-gro-hw and LRO must stay off** inside every switch, or bulk TCP crashes syncd; the launcher's unit turns them off at every boot, and the reboot drill checks it on the switch that rebooted.
- **The keepalive no longer rides the containerlab management bridge.** The session runs on Ethernet12 in `VrfMclagKa` and its backup on Vlan3966; `CLAB_MGMT_PASSTHROUGH` stays on the pair only so the stages reach Management0 on its harness address.
- **A BPDU on one leg of a bond shuts the bond on both switches.** In the revision 2 run, IEEE 802.1D BPDUs sent out k8s-cp1's leg to fe-sw1 tripped BPDU guard on PortChannel11 of fe-sw1 and fe-sw2 alike (`show spanning-tree bpdu-guard`: shut due to BPDU guard on both, `show mclag brief`: PortChannel11 down/down), cutting k8s-cp1 off; `shutdown` then `no shutdown` on PortChannel11 of both switches brought it back. Turning PVST on in a running lab blocks every port for listening and learning (about 30 s), so it is in the startup file and every host port is an edge port.
- **sonic-cli can end a session before its closing `exit`.** In the recording it did so 27 times in the keepalive drills, on pair reads, on one restore (the echo stopped at `interface Ethernet12` and the port stayed shut) and on two faults. The drills want each session's echo to reach `exit`, type a session cut short again (a `RETYPED` line in `timeline.txt`), and bound each at 90 s (`SFAB_DRILL_SESSION_S`); every retyped session in the recording took on its second try.
- **The MCLAG domain is never deleted and re-created.** If iccpd logs "mclag config is not complete or conflicting" every second, restart iccpd (`sudo systemctl restart iccpd`); replay never touches a live domain.
- **Times are the lab host's.** The ping runs in a VM guest, whose clock is its own, so the drills time it from the host-side captures of the guest's container ports; the connect loops run in containers, on the host's clock. The switches' clocks differ from the host's and from each other, so no figure is computed across two switches' logs.
- **The firewall's hash is its own.** Each connect is a new flow, and which ae1 leg it takes, and its ARP, is the PA-VM's choice; the drills read it from the captures on both legs, and break-3a's share depends on it.
- **The switches' MAC tables** list the containers' own veth MACs and VLAN 1 entries on trunks; the MAC-table check sets both aside.

Two platform behaviors the revision 1 deploys found hold in revision 2:

- **`show mclag brief` prints one `System Mac` on both switches**: 0c:00:a4:7a:3a:14 on fe-sw1 and on fe-sw2 alike in the recorded deployment, the switches' own MAC changing between deploys. The bonds' partner is the line below it, `Mclag System Mac`, 02:5a:00:00:00:01 (`audits/sfab-ch03_audit_20261029T043034Z/fe-sw1/18_mclag_brief.txt:14`, `:15`, and the same lines of `fe-sw2/`).
- **The two witnesses of the ping can disagree at a restore.** In 9 of 12 runs of an ICMP id crossing fe-sw1 in revision 1's server-member drill, the guest's ping printed "no answer yet" for one sequence number whose reply the host captured on the restored leg; a drill set prints each such round trip as a DISAGREE line and resolves none. The revision 2 recording printed none: the guest's ping and the host's captures agree on every round trip both saw.
