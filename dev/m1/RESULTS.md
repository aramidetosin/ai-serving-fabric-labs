# Milestone M1 results

What lab `sfab-m1` proved, the verdict lines that meet each exit criterion, the answers to the twelve questions the first deploy settled, the RESULT line of every set, and how to reproduce them. FRAMEWORK.md section 6.2 states the milestone and its criteria; `README.md` says what the lab builds.

M1 ran on 2026-10-14 on one lab host, at host tick 10000 on containerlab 0.81.0, the pin then (the pin is 0.81.1 since 2026-10-20, and M1 has not run on it; M2 read the same containerlab facts on 0.81.1, `dev/m2/RESULTS.md`, settle item 5). The record run brought the lab up with `make up BG=1` at 16:41:11 UTC, ran `make record` (the audit, then the gate) at 16:55:32, then `make down` and `make teardown-check`. Its images were `sfab/vm-node:1-k8s1.35.8` 85c7107872fd, `vrnetlab/dell_sonic:4.6.0` c0214f532277 and `vrnetlab/paloalto_pa-vm:12.1.2` d1ca9a0f1687 (R/RUN.json:8, :12, :16). Times are the lab host's clock.

Paths are relative to `audits/`. The short names:

| Name | Directory | What it is |
|---|---|---|
| R | `sfab-m1_audit_20261014T165532Z/` | the record set: the audit `make record` ran, then gated |
| U | `sfab-m1_audit_20261014T165320Z/` | the audit `make up` ran at the end of the same deploy |
| T | `sfab-m1_teardown_20261014T165915Z/` | criterion 8, from `make teardown-check` after `make down` |
| E | `sfab-m1_record-run_20261014T164111Z/` | plain files from the record run: the `make up` journal, the `make record` and `make down` output, the stage logs, host tick reads, container start times, sysctls and bridge flags |
| S | `sfab-m1_settle_20261014T155439Z/` | the settle set (`make settle`), with its evidence under `settle/` |
| X | `sfab-m1_exit-checks_20261014T155654Z/` | plain files from the idempotence and recovery checks |

## What the lab proved

| # | Criterion | Verdict lines |
|---|---|---|
| 1 | Preflight: tick 10000, no other sfab lab, the memory budget | R/verdict.txt:1 to :17 (tick :9; no other sfab lab's container :10 to :12; MemAvailable 326.8 GiB covers 71.5 GiB plus the 16.0 GiB floor :17); read again at the audit, :24 to :27 |
| 2 | Every switch: launcher line, parity 0 missing, GRO off, forwarding only, `ip vrf mgmt`, NUM_NICS as rendered | launcher R/verdict.txt:38, 47, 56, 64, 72; NUM_NICS 8, 8, 3, 8, 8 at :39, 48, 57, 65, 73; GRO, rx-gro-hw and LRO off at :42, 51, 59, 67, 75; `ip vrf mgmt` at :44, 53, 61, 69, 77; parity 55 of 55, 55 of 55, 14 of 14, 37 of 37, 37 of 37 at :45, 54, 62, 70, 78; forwarding only :231 to :269 |
| 3 | The pair: session up, one active and one standby, the keepalive in VRF mgmt on the passthrough addresses, the peer link, PortChannel10, 21 and 22 up with their member on each switch | R/verdict.txt:272 to :301 (R/fe-sw1/18_mclag_brief.txt:4 to :9, R/fe-sw1/19_portchannel_summary.txt:8 to :10) |
| 4 | The firewall: commit marker, the delivered XML byte for byte, every `enforced.txt` line, ethernet1/1 and 1/2 in ae1 with the pair's system MAC as partner, ae1.100, .200 and .300 up | R/verdict.txt:115 to :123 (R/fw/06_lacp.txt:8, :9, :20; R/fw/05_interface_all.txt:10, :23 to :25) |
| 5 | The guests: bond under one aggregator, TX checksum offload off on both sides, table 150, 10.20.1.1 one hop away, the out-of-band gateway, 8 namespaces, 9000-byte DF pings on every rail, cross-rail through the relay | k8s-gpu1 R/verdict.txt:125 to :134, k8s-gpu2 :136 to :145; relay and rails :147 to :227 |
| 6 | Rail and out-of-band switches: VLAN membership as rendered, MAC tables holding host MACs only | R/verdict.txt:89 to :103 and :108 to :113 |
| 7 | The RESULT line | R/verdict.txt:305 and R/RESULT.txt:5: `== RESULT: 274 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| 8 | Teardown: no container, no `clab-sfab-m1/`, `state/` kept | T/verdict.txt:2 to :4 (`state/` kept at 322M); `make down`'s own check, E/down.txt:310 to :313 |
| 9 | Clean: namecheck and `sfab check` | R/verdict.txt:303, :304; R/repo/namecheck.txt:1 (0 fail; see R/REDACTIONS.md); R/repo/sfab-check.txt:2 |
| | Idempotence: a second `make up` acts on nothing | every step printed its marker (X/second-make-up.txt:29, :33 to :37, :40, :41); the container start times before and after are identical (X/startedat-before-second-up.txt, X/startedat-after-second-up.txt) |
| | Recovery: `docker rm -f sfab-m1-k8s-gpu1 && make recover` | boot saw the lost links and redeployed (X/recover.txt:7), 24 passed, 0 failed, 1 skipped (:89); the next audit 274 passed (X/audit-after-recover.txt:317) |
| | The audit touched nothing | E/startedat-before-record.txt and E/startedat-after-record.txt are identical |

The one expected KNOWN line, L1 (`spec/known.yaml`: a ping across the pair can show duplicate replies, since the virtual switch does not enforce peer-link isolation), appeared once, in `sfab-m1_audit_20261014T155134Z/verdict.txt:144`.

## The RESULT lines

| Set | RESULT | Note |
|---|---|---|
| `sfab-m1_audit_20261014T150004Z` | 270 passed, 4 failed, 0 known, 0 skipped | problem 7 below: the gateway ping and its one-hop check on both guests |
| `sfab-m1_audit_20261014T150250Z` | 272 passed, 2 failed, 0 known, 0 skipped | problem 9 |
| `sfab-m1_audit_20261014T151741Z` | 274 passed, 0 failed, 0 known, 0 skipped | the first green audit |
| `sfab-m1_settle_20261014T152031Z` | 66 passed, 1 failed, 0 known, 0 skipped | a trial `make settle`; its own rule-description check wanted a description on every rule, and `settle.sh` now checks the descriptions the render sets |
| `sfab-m1_audit_20261014T155134Z` | 274 passed, 0 failed, 1 known, 0 skipped | the KNOWN line is L1 |
| `sfab-m1_audit_20261014T155320Z` | 274 passed, 0 failed, 0 known, 0 skipped | `make audit` |
| S, `sfab-m1_settle_20261014T155439Z` | 67 passed, 0 failed, 0 known, 0 skipped | the settle answers below |
| `sfab-m1_audit_20261014T155719Z` | 274 passed, 0 failed, 0 known, 0 skipped | the second `make up` |
| `sfab-m1_audit_20261014T161159Z` | 274 passed, 0 failed, 0 known, 0 skipped | after `make recover` |
| `sfab-m1_audit_20261014T162601Z` | 274 passed, 0 failed, 0 known, 0 skipped | the `make down && make up && make down` cycle |
| `sfab-m1_teardown_20261014T162745Z` | 3 passed, 0 failed, 0 known, 0 skipped | that cycle's teardown |
| U, `sfab-m1_audit_20261014T165320Z` | 274 passed, 0 failed, 0 known, 0 skipped | the record run's `make up` |
| R, `sfab-m1_audit_20261014T165532Z` | 274 passed, 0 failed, 0 known, 0 skipped | `make record`; its gate 5 passed, 0 failed (E/record.txt:315, :325, :326) |
| T, `sfab-m1_teardown_20261014T165915Z` | 3 passed, 0 failed, 0 known, 0 skipped | the gate on U and T: 9 passed, 0 failed (E/gate-other-sets.txt:13) |

Every set's `RUN.json` gives the lab, the spec and render sha256, the image ids, the containerlab release, the host tick and the UTC start and end. The labs repository commit reads `none` (R/RUN.json:22): the lab host's copy of the tree had no `.git`, and its `dirty: false` (:23) was never checked (FRAMEWORK.md 4.4). The README's "Redactions in the recorded sets" says what was replaced in the sets after they were recorded; each set with a replacement has `REDACTIONS.md`.

## The settle answers

Each answer is a line of S/verdict.txt (67 passed, 0 failed, :80), with its evidence under S/settle/.

1. **containerlab `${VAR}` expansion and `devices:` on kind linux.** Both work on 0.81.0 (S/verdict.txt:2, :5, :6; S/settle/1-fw-env.txt:1, :2, presence and hash only; S/settle/1-k8s-gpu1-devices.txt:2, :4, :5). The PA-VM never read the expanded env: its launcher's `--password` came from the kind (S/verdict.txt:3; S/settle/1-fw-env.txt:3). Since then the topology passes the firewall no credential at all (FRAMEWORK.md 2.4), and `settle.sh` item 1 checks that; S keeps the answer as recorded before the change.
2. **dell_sonic credentials.** The kind's defaults: every switch got `--username admin` and a password that is not `SFAB_SW_PASSWORD`, and the topology passes none (S/settle/2-switch-credentials.txt:1 to :12); `show version` logged in on all five (S/verdict.txt:9 to :13).
3. **The first rows of `spec/klish-normalize.yaml`.** None are needed: parity found 0 missing lines with the empty table on every switch (S/verdict.txt:15 to :19). The switch prints lines the render does not type, in the same blocks: `mtu 9100`, `speed 25000` and `unreliable-los auto` on ports, and `keepalive-interval 1`, `session-timeout 30`, `delay-restore 300` and `backup-keepalive interval 30` in the MCLAG domain (S/settle/3-fe-sw1-parity.txt:3 to :20).
4. **Guest-side TX checksum offload.** Not needed on M1's paths: iperf3 from k8s-gpu1 to k8s-gpu2 completed over bond0, over rail 1 and through the relay, with the guests' offload off and again on, the container side off throughout (S/verdict.txt:56 to :62; S/settle/4-tcp-off-bond0.txt:10). M1 has no routed path; M2 answered the routed case (`dev/m2/RESULTS.md`, settle item 2).
5. **The pair facing the PA-VM's ae1.** Bundled: ethernet1/1 and 1/2 with partner 02:5a:00:00:00:01, PortChannel10 up with Ethernet2 on both switches, and 8 SYNs from k8s-gpu1 to 10.20.1.1:443 tagged VLAN 100 on each ae1 member (S/verdict.txt:21 to :27).
6. **The MCLAG keepalive in VRF mgmt.** Up from 172.21.40.11 to 172.21.40.12 and back (S/verdict.txt:29, :30; R/fe-sw1/18_mclag_brief.txt:5 to :9).
7. **`mtu 9216` with `mclag 1` on PortChannel10.** Kept on PortChannel10 and its member Ethernet2; PortChannel1 has no `mtu` line and its members print 9100 (S/verdict.txt:32 to :35; S/settle/7-fe-sw1-mtu.txt:1 to :5).
8. **`ip vrf mgmt` on the VLAN-only switches.** rail-sw1, rail-sw2 and oob-sw list only Management0, in VRF mgmt, and `show ip route` prints nothing (S/verdict.txt:37 to :39).
9. **The PA-VM steps.** The image's own launcher turned jumbo frames on, rebooted and committed the XML (S/settle/9-fw-launcher.txt:2, :5, :6), so `fw-startup.py` did not run. The one rule description the render sets is in the running configuration (S/verdict.txt:42); jumbo frame mode reads `on` in the CLI and the XML API (S/settle/9-fw-jumbo-cli.txt:21 to :23; S/settle/9-fw-jumbo-xml.xml:1).
10. **The vm-node image end to end.** Overlays of the baked base (S/verdict.txt:65, :68); every data NIC bridged with `group_fwd_mask 0x4004`, no tc fallback (:66, :69); hostname, netplan's `lookup 150` rule and the table 150 default on first boot (:67, :70); 9000-byte DF pings through the relay on all 8 rail pairs (:71 to :78); NIC names and MACs unchanged after a reboot of k8s-gpu2 (:79).
11. **The launcher's extra `end`.** The only error in each typed session is one `% Error: Invalid input detected` after the launcher's own `end` (S/verdict.txt:46 to :50; S/settle/11-fe-sw1-typed-session.txt:304, :308).
12. **Steps that SKIP until their part exists.** `up` ran without the memory watchdog and boot's node-sync printed SKIP (S/settle/12-stage-lines.txt:1, :4); no audit has a SKIP line from either. Both parts were built for M2.

## What the first deploy found

Each problem stopped a run or failed a check, and its fix is in the tree. Unless a set is named, the evidence was the run's own logs under `state/`, which are not committed.

1. **ethtool is not on the switch login's PATH.** The `admin` login's PATH has no sbin, so boot's GRO check could not run ethtool. `common/stages/boot.sh` and `common/audit/cmds/dell_sonic.list` call `/usr/sbin/ethtool` (R/commands.txt:1393).
2. **Deleting the lab directory under a running lab.** A copy of the tree made with `rsync --delete` removed `clab-sfab-m1/`, which holds the firewall's bound `/config`, while the lab ran, so the next `make up` failed at `boot.fw`. Nothing may delete a `clab-*/` or `audits/` directory under a running lab; the lab was taken down and deployed again.
   - Found in the same run: `qemu-img info --output=json` lists the backing file's `virtual-size` before the overlay's own, so `vm-init.sh`'s disk grow check read two numbers. It now reads the first `virtual size:` line of the text form.
3. **The fabric wait could never pass.** It waited for the guests' PortChannels while the guests were still held. `judge.py` takes `--except-peers`, `boot.sh` leaves the held guests out of `boot.fabric` and waits for every PortChannel in a new step after the guests answer, `boot.bonds`. A quoting error the change brought (problem 3a) was fixed the same hour.
4. **The PA-VM keeps the kind's default login.** containerlab's `paloalto_panos` kind passes the launcher its login on its command line, and the launcher reads only that, never `USERNAME` or `PASSWORD` from its environment. `common/fw/fw-startup.py` reads the launcher's arguments first, as the harness does; the topology no longer passes the firewall any credential.
5. **The PAN-OS CLI under scripting mode.** With `set cli scripting-mode on` the CLI prints each prompt with no command echo, so the splitter found no command; and `show interface ae1.100` prints no state for a sub-interface. The harness leaves scripting mode off (R/fw/06_lacp.txt:1 shows the echo), and the judge reads a unit from `show interface all` and its parent `ae1`.
6. **The switches learned the guest containers' own MACs.** The guests' data veths carried IPv6 until `vm-init.sh` turned it off, and sent router solicitations meanwhile. The render gives every vm-node container `net.ipv6.conf.default.disable_ipv6` "1".
7. **A guest could not reach its gateway.** The pair floods a guest's own broadcast back to it over its other bond leg (L1), so the per-NIC bridge in the guest's container learned the guest's MAC on the wrong port and dropped every frame sent back to it (the gateway lines of `sfab-m1_audit_20261014T150004Z`). `vm-init.sh` turns learning off on both ports of every guest bridge; all 48 bridge ports of the two guests read `learning off` in the record run (E/bridge-learning.txt).
8. **The switches' shell reads were never saved.** The first vtysh call over ssh read the rest of the collect plan from standard input. `VT` and `SH` run `ssh -n`, `collect.sh` reads the plan on file descriptor 3, and a planned command with no saved file fails collect.
9. **The rail MAC tables failed on the relay's macvlan MACs.** The judge also accepts every MAC in the switch's `gen/expect` `known_macs` (`sfab-m1_audit_20261014T150250Z`).
10. **containerlab sets `net.ipv6.conf.all.disable_ipv6` to 0 on kind linux** whatever the topology says, and keeps the topology's `default` 1 (E/sysctls.txt:1, :2). The `default` key is the one a veth moved into the namespace takes, so the render names only it.
11. **One switch veth kept IPv6.** The launcher lists the container's veths before it writes the namespace default, so a veth containerlab moves in between keeps IPv6 on. Every switch container gets `net.ipv6.conf.default.disable_ipv6` "1" from the topology too, and every veth reads 1 (R/oob-sw/04_container_ipv6.txt:1 to :3).
12. **The saved namecheck output doubled with each audit.** Each warning quoted the line it matched, so every audit quoted the earlier sets' saved warnings again. `audit_clean` in `common/lib.sh` saves the fail lines and the summary only, and the ten recorded files were cut to that form (README.md, "Redactions in the recorded sets").

## How to reproduce

With the requirements in `README.md` met:

```
cd dev/m1
make render && make up && make audit
make up                                       # every step reports its marker and acts on nothing
docker rm -f sfab-m1-k8s-gpu1 && make recover     # links lost: boot redeploys, the audit returns green
make down && make up && make down
make teardown-check
make up && make settle && make down
```

In the record run `make up` from a down lab to a recorded audit took 830 s: preflight 0 s, `up.deploy` 4 s, boot 713 s (the firewall's step, 398 s, is the longest), finish 12 s and the audit 101 s (E/make-up.txt:26, :102, :132, :148, :327, :643). `make down` took 9 s (E/down.txt:314).

The committed render is not the one R recorded: the topology no longer passes the firewall the two credential variables its launcher never read, and later spec changes moved the spec sha256, so R/RUN.json's render and spec sha256 are not today's. A run today records its own.

## What the recordings do not show

- **`fw-startup.py` against the box.** The image's own launcher committed the XML in every deploy, so the script's partial load in replace mode, its retries and its poll across a web server restart are tested only against the stand-ins.
- **`make exit-criteria` as one target.** Its steps ran one by one, with their evidence in X.
- **A run on containerlab 0.81.1.** M1 ran on 0.81.0 only.
- **The labs repository commit** in any `RUN.json`.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge: each `wired` line `images/vm-node/vm-init.sh` logged in these sets names `bridge` for every NIC, and settle item 10 checked it (S/verdict.txt:66, :69). A stock kernel refuses that mask, and on such a host `vm-init.sh` joins the data NICs, the bond members among them, to their taps with a tc mirred redirect instead. No recorded run exercised that path; `guest.nic_link: tc` in `spec/common.yaml`, with the lab rendered again, forces it, for testing (the repository's `README.md`, "The host").
