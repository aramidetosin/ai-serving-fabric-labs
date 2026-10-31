# Chapter 5: Rail-Only Backend with VLANs

Lab `sfab-ch05`, the companion lab of the book's Chapter 5, "Rail-Only Backend with VLANs". It runs build A's backend from the one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`): two standalone SONiC 4.6.0 rail switches whose rails are plain VLANs, and the two GPU nodes whose cross-rail traffic is relayed inside the node. It audits the absences the design is made of and the rail ports' Layer 2 hygiene, traces same-rail and cross-rail traffic hop by hop with the DF probe matrix, darkens one rail switch in a drill, and ships break-5a.

Status: build A revision 2, deployed and recorded on 2026-10-29 from wiped disks (`RESULTS.md`; `audits/INDEX.md` maps the book's exhibits to its sets). Revision 2 changes the rail switches' ports (MTU 9216, edge ports with BPDU guard, storm control) and nothing of the rails themselves: the VLANs, the addresses, the relay and its routes are as they were. The revision 1 sets are superseded and no longer in the repository (`audits/INDEX.md`, "Superseded sets").

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[rail, k8s-gpu1, k8s-gpu2]`; the closure adds the switches the nodes' other links land on: the pair (`fe-sw1`, `fe-sw2`, their bonds) and `oob-sw` |
| Features | `{k8s: false, serving: false, storage_setup: false}` |
| Prints | `rail-sw1`, `rail-sw2`: the chapter prints both rail switches, so both deploy whole |
| Extends | none |
| Containers | `sfab-ch05-<node>` (7); containerlab directory `clab-sfab-ch05/` |

The firewall is not in this lab. A VLAN's gateway is rendered only while the node that holds it is in the lab, so the GPU nodes get no gateway on their bond or out-of-band NIC: their main table holds no default route, and management stays in table 150 as in every lab.

## What the spec renders for this chapter

Rail *r* is VLAN 10*r* (101 to 108) on 10.21.*r*.0/24 with no gateway; GPU node *n* holds .(10+*n*) on every rail. Odd rails sit on `rail-sw1`, even rails on `rail-sw2`; k8s-gpu1's four NICs on a switch take Ethernet0 to Ethernet3 in the order of that switch's rails, k8s-gpu2's Ethernet4 to Ethernet7 (`make show WHAT=ports`).

- **Each rail switch** (`bootstrap/rail-sw1/startup-config.cfg`, `role_rail_vlan` in `render/klish.py`): `ip vrf mgmt` first, then `spanning-tree mode pvst`, the switch's four rail VLANs created with no address, and its eight access ports, each with a description naming the GPU NIC, `mtu 9216`, `switchport access Vlan 10r`, `spanning-tree portfast` and `spanning-tree bpduguard port-shutdown` (an edge port that shuts itself on any BPDU), `storm-control broadcast`, `unknown-unicast` and `unknown-multicast 10000` (kbps), and `no shutdown`. Nothing else: no `interface Vlan` address, no `ip route`, no `router bgp`, no PortChannel, no trunk and no link to the other switch.
- **Each GPU node** (`bootstrap/k8s-gpu1/node.env`, `render/host.py`): eight rail NICs at MTU 9000 with no address; eight network namespaces, `gpu1` to `gpu8`, namespace `gpuR` holding rail R's address on a macvlan over rail NIC R and a veth into the node-local bridge `relay0` with 10.21.250.R; in each namespace one route to every other rail via that rail's namespace on the bridge, each pinned to the namespace's own rail address (`RELAYR_ROUTES`: destination, next hop, device, source); no default route; `ip_forward` 1 and `rp_filter` 2 (loose) in every namespace. `sfab-netsetup` builds them at every boot.

**The relay is the lab's stand-in, labeled wherever it is shown** (the trace's `TRACE.md` and the rp_filter stage's `FOLLOWED.txt` carry the label too). It lets the captures show the path PXN gives a cross-rail transfer. Production GPU hosts do not IP-forward between rails: NCCL moves cross-rail collective data over NVLink with PXN, and its IP control traffic (bootstrap over `NCCL_SOCKET_IFNAME`, health probes) uses the frontend network. On a rail-only fabric NCCL also takes `NCCL_CROSS_NIC=0`, which its documentation describes as suited to networks with per-NIC switches (rails) and a slow inter-rail connection (the default is 2). `rp_filter` 2 belongs to the relay: production keeps 1 with per-rail policy routing. The lab's probes are exec probes that stay on one rail; none of them needs the relay.

## Requirements

The images `vrnetlab/dell_sonic:4.6.0` (built from your own copy of the switch image with `platform/dell-sonic-4.6.0/`) and `sfab/vm-node:6-k8s1.35.8` (`make -C images vm-node`); no firewall, storage or cluster image. Memory: the inventory's budget is 55 GiB (five switches at 4.6 GiB, two GPU nodes at 16: the GPU nodes are sized for the models only in a lab with serving on), and preflight wants MemAvailable to cover it plus the 16 GiB floor, 71 GiB in all; 26 vCPUs within twice the host's CPU count. Disk: 25 GiB of expected growth under `state/` and 40 GiB of container layers. The host tick at 10000 (read and recorded, never refused on), containerlab 0.82.0 (the revision 1 sets were recorded on 0.81.1 and 0.82.0), and no other `sfab-` lab running.

## Running it

```
cd ch05
make render          # topo.clab.yml, bootstrap/ and gen/ (gen/trace.json, gen/drills.json, gen/breaks.json among them)
make up              # preflight, up, boot, finish, audit (book Example 5-1)
make audit           # audits/sfab-ch05_audit_<UTC>/ (Example 5-2)
make trace           # audits/sfab-ch05_trace_<UTC>/ with TRACE.md (Examples 5-5 to 5-7)
make drills          # audits/sfab-ch05_drills_<UTC>/ with DRILLS.md, three passes (Examples 5-9 and 5-10)
make record          # after the drills: audit, trace, then the gate on both sets (Example 5-11)
make rpf             # audits/sfab-ch05_rpf_<UTC>/: rp_filter's all and per-interface values on the cross-rail flow, three cases, then put back (Example 5-8)
make break-5a        # audits/sfab-ch05_break-5a_<UTC>/ (Exercises 1 and 4)
make heal-5a         # audits/sfab-ch05_heal-5a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make drills PASSES=1` runs the drill once. `make up BG=1` runs the deploy as the transient unit `sfab-ch05-up`.

Once the lab is up, `ssh admin@sfab-ch05-<node>` from the lab host logs in to `k8s-gpu1` and `k8s-gpu2` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches keep their kinds' default logins.

## The audit

`audit.sh` runs the shared checks (every switch's launcher line, NUM_NICS, GRO off, IPv6 off on its veths, `ip vrf mgmt` and parity; VLAN membership and MAC tables; the guests' bonds, TX offload and management table; the relay namespaces, the 9000-byte DF ping on every rail and cross-rail through the relay), chapter 2's forwarding-only reads on every switch, and the pair as milestone M1 judges it. In a full audit it runs chapter 3's Layer 2 hygiene group on the pair and both rail switches (`l2-hygiene`: `spanning-tree mode pvst`, every used port at its rendered MTU, BPDU guard with port-shutdown on every edge port and on no other, none tripped, storm control of each type at 10000 kbps on every access port; `ch03/README.md`, "The audit"). It adds the group `rail-backend` (`audit_rail_backend` in `common/audit/lib-audit.sh`, then `common/audit/judge.py rail-backend`):

- **On each rail switch, the absences.** Its rails are its VLANs, one `interface Vlan` block each, and none of the blocks holds an address of any kind; `show ip interfaces` lists no Vlan interface; no static route in the running configuration and `show ip route` (the default VRF) prints nothing: no gateway; no `router bgp` in the KLISH running configuration or FRR's own view (`vtysh show running-config`); `show ip vrf` lists Management0 alone in VRF `mgmt` and no interface in any other VRF.
- **No inter-switch link.** `show interface status` lists only the eight rendered GPU access ports up, every other port admin down; each up port's description names the GPU NIC the render cables there; every MAC learned on a rail port is a GPU NIC or relay macvlan the render cables to that port (`gen/expect/<switch>.json`, `known_macs`).
- **The rail ports.** Each port's running block carries `no shutdown`, and `show interface status` reads it at MTU 9216, the port MTU the spec's Layer 2 policy sets (revision 1 typed no `mtu` line and the ports ran the factory 9100).
- **On each GPU node, the namespaces.** Every GPU namespace holds its connected rail and seven relay routes, one to each other rail via that rail's namespace, every one pinned to the namespace's own rail address as `node.env` renders it; none holds a default route; `rp_filter` reads 2 on every interface of every namespace (the effective value, the larger of `all` and the interface's own).
- **The MTU ceilings.** The eight rail NICs and `relay0` at 9000 (`ip -j addr`), and in each namespace the macvlan and the relay veth at 9000 (`ip -n <ns> -j link show`, saved under the set's `rail-backend/`). The switch ports' 9216 sits above them, so a GPU NIC's 9000 is the ceiling on one rail, and the relay's 9000 across rails.

`audit.sh --quick` reads the switches only, and judges the rail switches' half of `rail-backend`; it is not recorded.

## The trace

`trace.sh` (`common/trace/lib-railtrace.sh`, `common/trace/railtrace.py`, the plan in `gen/trace.json`):

1. **Health.** One ping from each of k8s-gpu1's eight namespaces to k8s-gpu2's address on the same rail, retried once.
2. **Two flows**, each a ping of three requests from k8s-gpu1's namespace `gpu1` (10.21.1.11) under the flow's own ICMP id (`ping -e`), with six capture points running: both nodes' `relay0`, captured and decoded inside the guest, and the rail switches' ports facing each node on rails 1 and 2, captured on the lab host in the switch container (`1-k8s-gpu1-relay0`, `2-rail-sw1-Ethernet0`, `2-rail-sw2-Ethernet0`, `3-rail-sw1-Ethernet4`, `3-rail-sw2-Ethernet4`, `4-k8s-gpu2-relay0`).
   - `same-rail`, to k8s-gpu2's 10.21.1.12: the plan wants request and reply on rail-sw1's two ports only, at TTL 64, and nothing on either bridge or on rail-sw2.
   - `cross-rail`, to k8s-gpu2's 10.21.2.12: the plan wants the request on k8s-gpu1's `relay0` at TTL 64 and on rail-sw2's two ports at TTL 63 (k8s-gpu1's namespace `gpu2` forwarded it onto rail 2), the reply on k8s-gpu2's `relay0` at TTL 64 and on rail-sw1's two ports at TTL 63 (k8s-gpu2's namespace `gpu1` forwarded it onto rail 1), so the request crosses the destination rail's switch and the reply the source rail's; and the request with sequence number 1 carrying one IP id at every point that saw it.
3. **traceroute** from the same namespace to each destination (`traceroute -n -w 2 -q 3 -m 4`): one hop on the same rail; across rails, k8s-gpu1's own address on rail 2 (10.21.2.11), then the destination.
4. **The DF probe matrix**, captured again: each flow forward and reversed (k8s-gpu2's namespace on the flow's request rail pinging back) at 9000 and 9001 bytes with the don't-fragment bit set (`ping -M do -s <size - 28>`). The judge wants every 9000-byte row answered, its requests and replies at the points as 9014-byte frames, every request with DF set (the far kernel's echo replies carry no DF, which the trace records on its own line), and every 9001-byte row refused with no frame of it anywhere, and it prints where each refusal came from: the sender's own interface (ping's "message too long" with the MTU), a hop's fragmentation-needed message, or silence.

The relay is the lab's stand-in for what PXN does over NVLink on a GPU host, as the section above says; the rails and the switches are what a rail-only fabric runs.

## The drill

`drills.sh` (`common/drill/lib-raildrill.sh`, `common/drill/raildrill.py`) runs `dark-switch` once per pass (`PASSES=3` by default):

| Step | What happens |
|---|---|
| Whole | every same-rail row answered and every rail switch's rendered ports up and oper-up, in two consecutive polls 5 s apart |
| Probes | from k8s-gpu1, one `ping -D -O -i 0.2 -W 1 -e <id> -c <count>` per row, all at once, the count outlasting the drill (never `-w`, below): the same rail on all eight rails, and rail 2 to rail 1 (into the dead rail), rail 1 to rail 2 (out of it) and rail 2 to rail 4 (between live rails); tcpdump on the lab host in both nodes' container ports on every rail |
| Cut | after 10 s, one KLISH session on rail-sw1: `interface range Ethernet0-7`, `shutdown`; its start and return stamped on the host clock |
| Dark | at 15 s, `show interface status` on both rail switches and both nodes' rail NICs as their kernels see them (`ip -br link`) |
| Restore | at 30 s, `interface range Ethernet0-7`, `no shutdown`; the probes run 20 s more |
| After | the rails whole again, parity on rail-sw1, `audit.sh --quick`, then `raildrill.py analyze` |

The plan marks a row dark when its request or its reply rides one of rail-sw1's rails. For each row the analysis follows the request out of k8s-gpu1's container port on the rail it rides and into k8s-gpu2's, and the reply back on the rail it rides, groups the requests by when they were sent (before the cut, during the cut's session, dark, during the restore's session, after), and judges: every row answered before the cut; while dark, the dark rows answer nothing (a same-rail row's requests leave k8s-gpu1 and none reach k8s-gpu2; rail 1 to rail 2's requests reach k8s-gpu2 and its replies leave on rail 1 and never reach k8s-gpu1) and every other row answers all; after the restore every dark row answers again, its first answered request timed from the restore's session start as an event; and the guest's own ping log as the second witness of each row's count. Beside the counts it prints, for each dark row, the ARP requests the node facing the dead rail sent for the far address while dark, and the guest log's Destination Host Unreachable lines (below, in the platform notes). Each pass writes `pass<N>/dark-switch/` (timeline, captures and their decodes, the guest's ping logs, the KLISH snapshots, the nodes' link reads, parity, `analysis.json`, `analysis.txt`); `DRILLS.md` closes the set.

## rpf

`rpf.sh` (through `common/reads/rpf.sh`) shows how the kernel combines `conf/all/rp_filter` with an interface's own value: the max of the two is used for source validation on that interface (the kernel's `ip-sysctl.rst`). It follows the trace's cross-rail flow, from k8s-gpu1's namespace `gpu1` (10.21.1.11) to k8s-gpu2's rail 2 address (10.21.2.12): the request reaches k8s-gpu2's namespace `gpu2` on its macvlan `rail2`, while that namespace's route back to 10.21.1.0/24 leaves on `relay`. In that namespace it reads `all`, `default`, `rail2` and `relay`, and the kernel's reverse-path drop counter (`nstat -asz TcpExtIPReversePathFilter` inside the namespace), then runs three cases, each a 3-request ping with the counter read before and after: as built (all 2, rail2 2) answered; all 1 with rail2 0 dropped, the counter rising, since the interface's 0 cannot take the effective mode below all's 1; all 1 with rail2 2 answered, the max being 2. It then writes back the values it read as built (also on any exit, from a trap), reads them and pings once more. Each read is saved as `<step>/<n>-<what>.txt`, the first line the command at `admin`'s prompt.

## break-5a

`breaks/5a.yaml`, rendered to `gen/breaks.json`: in k8s-gpu1's namespace `gpu1`, the relay route to rail 2 replaced without its source pin (`ip -n gpu1 route replace 10.21.2.0/24 via 10.21.250.2 dev relay`). `make break-5a` records the namespace's routes and `route get` for k8s-gpu2's rail 2 and rail 3 addresses, pings from k8s-gpu1's rail 1 namespace to k8s-gpu2's rail 2 address in three passes with k8s-gpu2's `rail2` NIC and `relay0` captured in the guest around each, then the controls once each: rail 1 to rail 3 from k8s-gpu1, rail 1 to rail 2 from k8s-gpu2, and the same rail on every rail from both nodes. It passes when the route reads with no source pin (and the rail 3 route still with it), every rail 1 to rail 2 ping from k8s-gpu1 fails, k8s-gpu2's capture shows the requests arriving from a relay-segment address and k8s-gpu2's replies going into its own `relay0` toward that address, every control succeeds, and parity holds on both rail switches: the switches are untouched. `make heal-5a` puts the rendered route back with its pin, runs the same reads (the requests now arrive from 10.21.1.11), then the chapter audit. A guest reboot heals it too: `sfab-netsetup` puts every rendered route back at boot.

## Platform notes for this lab

M1's notes hold here (`dev/m1/README.md`), and chapter 3's on BPDU guard (`ch03/README.md`: a BPDU on an edge port shuts it, and a bond's shut legs need `shutdown` then `no shutdown`). For the rails, each read in this lab's revision 2 recording:

- **A KLISH `shutdown` drops no carrier at the far end** (L9). The GPU nodes' rail NICs stay up while their switch's ports are shut, so a dark rail shows only as silence: requests leave the node and nothing answers. In every pass of the drill, `show interface status` on rail-sw1 read its eight ports `down` and `admin-down` (`audits/sfab-ch05_drills_20261029T001158Z/pass1/dark-switch/klish/during-rail-sw1.txt:12` to `:19`) while both nodes' kernels read all sixteen rail NICs `UP` (`links-during-k8s-gpu1.txt`, `links-during-k8s-gpu2.txt` beside it); the drill prints them on its KNOWN L9 line. Nothing in this lab says a node saw a link go down.
- **On a dark rail the node keeps asking.** The source's requests leave its rail NIC and none reaches the far node until the source's neighbor entry for the far address fails; from then on the node sends ARP requests for that address instead, unicast and then broadcast, none answered until the restore (`audits/sfab-ch05_drills_20261029T001158Z/pass1/dark-switch/captures/k8s-gpu1-eth4.txt:454` to `:489`; the first reply from 10.21.1.12, `:508`, came after the `no shutdown`), and ping prints `Destination Host Unreachable` from the namespace's own address (`logs/ping-same-1.log:199`): its own kernel's report, not a message from the network. So the number of dark requests that left the node differs by row and by pass, and `DRILLS.md` prints each row's ARP requests and unreachable lines beside its counts. A row whose reply rides the dark rail behaves the same way at the far node.
- **Never `ping -w` on a dark rail.** With a deadline, iputils ping also exits at the first error the network reports, and the dark rail produces one; the drill bounds each row's ping by a count instead.
- **`interface range` reports what it configures.** Both sessions print `%Info: Configuring only existing interfaces in range` after the range line (`audits/sfab-ch05_drills_20261029T001158Z/pass1/dark-switch/fault.txt:16`, `restore.txt:16`); each session took 1.21 to 1.29 s on the lab host's clock in every pass (`audits/sfab-ch05_drills_20261029T001158Z/pass1/dark-switch/analysis.txt:1` and the same line in passes 2 and 3), and one range line with one `shutdown` took all eight ports admin down, as one `no shutdown` brought them back.
- **Echo replies carry no DF.** ping sets DF on its requests, its default and `-M do` alike; the far kernel's echo replies carry none (`flags [none]`), and a `-M do` request's IP id reads 0 (`audits/sfab-ch05_trace_20261029T001119Z/captures-df/2-rail-sw1-Ethernet0.txt:2`, `:4`). The trace judges DF on the requests, and the DF matrix's reversed rows send DF requests the other way.
- **The ceiling is the sender's own interface, on both paths.** A 9001-byte DF ping is refused before it leaves the namespace, by its own 9000-byte link: `ping: local error: message too long, mtu=9000`, on the same rail as across (`audits/sfab-ch05_trace_20261029T001119Z/df/same-rail-forward-9001.txt:5`), so no frame of it reaches a switch. The switch ports' MTU (9100 in revision 1, 9216 in revision 2) is above every GPU NIC's 9000 and is never the limit.
- **A guest's capture carries the guest's clock.** Both relay bridges are captured inside the guests, so their times are the guests' own: the cross-rail request reached k8s-gpu1's `relay0` at 00:11:30.530 on k8s-gpu1's clock and rail-sw2's port facing k8s-gpu1 at 00:11:31.067 on the lab host's, and k8s-gpu2's `relay0` read its reply at 00:11:29.732, before the request was sent (`audits/sfab-ch05_trace_20261029T001119Z/TRACE.md:136`, `:150`, `:171`). Compare times only between host-side points; every drill time is the host's.
- **The running configuration prints values the render does not type.** Every rail port block reads `speed 25000` and `unreliable-los auto` beside the rendered lines, and a port the render does not use reads the factory `mtu 9100` and `shutdown` (`audits/sfab-ch05_audit_20261029T001030Z/rail-sw1/09_running_config.txt:244` to `:256`, `:348` to `:352`; milestone M1's settle item 3). Revision 1 typed no `mtu` line, and its ports ran the factory 9100. The audit judges the MTU from `show interface status`, against the render's `mtu` line.
- **Management0 inside a rail switch reads 10.0.0.15/24 in VRF `mgmt`**, not the lab's management address: the rail switches run without management passthrough, which only the pair carries (the stages reach the pair on its harness address; since revision 2 its keepalive runs on its own link) (`audits/sfab-ch05_audit_20261029T001030Z/rail-sw1/06_ip_interfaces.txt:6`). `show ip vrf` lists `default` with no interface and `mgmt` with Management0 (`08_ip_vrf.txt:4`, `:5`).
- **`show vlan`'s first line runs the command into the table's title** (`rail-sw1# show vlanVlan`, `audits/sfab-ch05_audit_20261029T001030Z/rail-sw1/11_vlan.txt:1`); the rows start at line 4.
- **FRR's view on a switch names its host `sonic`** (`audits/sfab-ch05_audit_20261029T001030Z/rail-sw1/14_frr_running.txt:7`); the audit reads it only for `router` lines.
- **The rail switches learn the GPU NICs' own MACs** on their access ports (`audits/sfab-ch05_audit_20261029T001030Z/rail-sw1/12_mac_table.txt:5` to `:28`, the containers' own veth MACs among them, which the audit sets aside); the frames the trace captures carry the namespaces' macvlan MACs (`audits/sfab-ch05_trace_20261029T001119Z/captures/2-rail-sw1-Ethernet0.txt:2`), and the audit allows those beside them, each on the port the render cables it to.
- **GRO, rx-gro-hw and LRO must stay off** inside every switch, or bulk TCP crashes syncd; the launcher's unit turns them off at every boot, and the audit checks them. Nothing in this lab sends bulk TCP over a rail.
- **No gateway.** The nodes' main tables hold no default route in this lab, and the GPU namespaces never have one; every probe here stays inside 10.21.0.0/16 and the relay segment.
- **Times are the lab host's.** The drill's pings run in a VM guest, whose clock is its own, so every time is taken from the host-side captures of the guests' container ports; the guest's ping log is the second witness of each count, a disagreement printed and never resolved.
- **A full audit is mostly the repository checks.** With the author's scrub list, the namecheck and `sfab check` take most of a full audit; without it, as on the lab host, `audits/sfab-ch05_audit_20261029T001030Z` took 49 s in all (`audits/sfab-ch05_record-run_20261029T000046Z/chain.log:13`).
