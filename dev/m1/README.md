# Milestone M1: the framework proven

M1 is not a chapter. It is the first lab the framework deploys (FRAMEWORK.md section 6.2), lab `sfab-m1`: build A's five switches, the PA-VM and two GPU nodes, with no cluster, no serving and no storage. It proves the generator, the stages and the harness on the book's real images before any chapter depends on them, and it retires the chapters 1, 3 and 4 risk: the Dell MCLAG pair facing the PA-VM's `ae1`.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2]` |
| Features | `{k8s: false, serving: false, storage_setup: false}` |
| Containers | `sfab-m1-<node>`; containerlab directory `clab-sfab-m1/` |

`make show WHAT=nodes` lists the nodes and `make show WHAT=ports` the port plan of every switch.

Status: build A revision 2 is rendered and tested for M1's slice; M1 has not been deployed under it. The committed result sets under `audits/` are revision 1's, recorded on 2026-10-14 under the node names and the pair design of that time (`RESULTS.md`; `../../README.md`, "Build A, revision 2"); the chapter labs' revision 2 recordings, not M1's, replace them as the build's evidence.

## What it builds

- **The MCLAG pair** `fe-sw1` and `fe-sw2`: peer link PortChannel1 on Ethernet0 and Ethernet1, MCLAG domain 1 with, since build A revision 2, the keepalive on the dedicated link Ethernet12 in VRF `VrfMclagKa` and the backup keepalive on Vlan3966 over the peer link (M1's recorded sets predate it and show the keepalive in VRF `mgmt` on the containerlab management addresses, under `CLAB_MGMT_PASSTHROUGH`, which the pair keeps for the stages), PortChannel10 to the firewall's `ae1` (trunk of VLANs 100, 200 and 300, MTU 9216), PortChannel21 and PortChannel22 to k8s-gpu1 and k8s-gpu2 (access VLAN 100).
- **Two rail switches**, `rail-sw1` (rails 1, 3, 5, 7) and `rail-sw2` (rails 2, 4, 6, 8): rail r is VLAN 100+r, access ports only, no VLAN interface address.
- **The out-of-band switch** `oob-sw`: VLAN 90 on three access ports (k8s-gpu1, k8s-gpu2, the firewall's ethernet1/3).
- **The PA-VM** `fw`: `ae1` over ethernet1/1 and ethernet1/2 with units `.100`, `.200` and `.300` as the VLAN gateways, ethernet1/3 to the out-of-band network, the zones, the intrazone allows and `deny-all-log`.
- **Two VM guests**, `k8s-gpu1` and `k8s-gpu2`: `bond0` across the pair, an out-of-band NIC, eight rail NICs, and the in-node relay (namespaces gpu1 to gpu8).

## Requirements

- The images `vrnetlab/dell_sonic:4.6.0` (built from your own Dell image with `platform/dell-sonic-4.6.0/`), `vrnetlab/paloalto_pa-vm:12.1.2` (built from your own PA-VM image with `platform/paloalto-pa-vm-12.1.2/`) and `sfab/vm-node:4-k8s1.35.8` (`make -C images vm-node`). `images/VENDOR-IMAGES.md` says where to get the vendor images. Preflight checks each one and never pulls a vrnetlab image.
- Memory: the inventory's budget is 71.5 GiB (five switches at 4.6, the PA-VM at 16.5, two GPU nodes at 16), and preflight wants MemAvailable to cover it plus a 16 GiB floor, 87.5 GiB in all. 34 vCPUs against twice the host's CPU count. Disk: 25 GiB of expected growth under `state/` (two GPU nodes at 12, the lab's own files 1) and 56 GiB of container layers under Docker's data root (five switches at 8, the PA-VM at 16), on one filesystem where they share one; the guests' 80 GiB root disks are their virtual size, not the budget (FRAMEWORK.md 3.1).
- The host tick at 10000 (preflight reads it with `common/bin/tick.py`), containerlab at the pin in `spec/versions.yaml` (0.81.1 since 2026-10-20; M1 itself ran on 0.81.0), and no other `sfab-` lab running.

## Running it

```
cd dev/m1
make render          # writes topo.clab.yml, bootstrap/ and gen/ from the spec
make up              # preflight, up, boot, finish (only the quick audit here), audit
make status
make audit           # records audits/sfab-m1_audit_<UTC>/
make down            # keeps state/ disks; make wipe removes them
```

`make up BG=1` runs the same as the transient unit `sfab-m1-up`; follow it with `journalctl -fu sfab-m1-up`.

`make settle` records the answers to the twelve questions the first deploy settles (`RESULTS.md`, "The settle answers") as `audits/sfab-m1_settle_<UTC>/`; it turns the guests' TX checksum offload on and back off, and reboots k8s-gpu2. `RESULTS.md` holds the milestone's results with the evidence for each, and what the first deploy found.

The milestone's full sequence, which `make exit-criteria` runs in order:

```
make render && make up && make audit
make up                                       # second run: every step reports its marker and acts on nothing
docker rm -f sfab-m1-k8s-gpu1 && make recover     # links lost: boot redeploys, the audit returns green
make down && make up && make down
make teardown-check                           # records criterion 8 as its own result set
```

Once the lab is up, `ssh admin@sfab-m1-<node>` from the lab host logs in to `k8s-gpu1` and `k8s-gpu2` with the lab's key or your own (`../../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins.

## The exit criteria, as verdict lines

Every criterion is a set of lines in the audit's `verdict.txt` (criterion 8 in the teardown set's).

| Criterion | Section in verdict.txt | Lines |
|---|---|---|
| 1 Preflight | `preflight, as run at ...` and `preflight, read again now` | the identity, tools, `/dev/kvm`, `host tick 10000`, `no other sfab lab's container running`, the subnet, the images, `free memory`, CPU, disk, modules, secrets, render |
| 2 Every switch | `<switch>: switch`, `<switch>: forwarding only` | `launcher log: KLISH startup config applied`, `parity: 0 missing lines`, `GRO, rx-gro-hw and LRO off on all N data NICs`, `ip vrf mgmt present`, `NUM_NICS in the container env is N` (fe-sw1 and fe-sw2 8, rail switches 8, oob-sw 3), `show ip interfaces lists only Management0`, `show ip route prints nothing`, `no router line ...`, `kernel holds no address ...` |
| 3 Pair | `pair fe-sw1 fe-sw2` | session up, `roles: one active, one standby`, the keepalive in VRF mgmt on the passthrough addresses, peer link up, `PortChannel10` and `PortChannel21`, `PortChannel22` up with their member on each switch |
| 4 Firewall | `fw: firewall` | `commit marker present`, `delivered /config/startup-config.cfg matches the render byte for byte`, `enforced.txt present`, `ethernet1/1 and ethernet1/2 in the aggregate (bundled, current, selected)`, `LACP partner is the pair's mclag-system-mac`, `ae1.100 up: tag 100, ...` and the other units (a sub-interface is up when it stands in `show interface all` with its tag, address and zone and its parent `ae1` is up) |
| 5 Guests | `<gpu>: guest`, `<gpu>: relay and rails` | bond0's two slaves under one aggregator ID with the system MAC as partner, TX checksum offload off on both sides, management default in table 150, `10.20.1.1 answers ping` and is one hop away, `10.20.9.254 answers over the out-of-band network`, 8 relay namespaces with no default route and rp_filter 2, the 9000-byte DF ping on all 8 rails, cross-rail through the relay |
| 6 Rail and out-of-band switches | `<switch>: VLAN membership`, `<switch>: MAC table` | each VLAN's ports as rendered, `MAC table holds host MACs only` |
| 7 Result | the last line | `== RESULT: N passed, 0 failed, K known platform limitation(s), 0 skipped` (1 skipped, namecheck, without a scrub list) |
| 8 Teardown | `teardown sfab-m1 (fast)` in `audits/sfab-m1_teardown_<UTC>/` | `no sfab-m1-* container remains`, `no clab-sfab-m1/ remains`, `state/ disks kept until wipe` |
| 9 Clean | `repository` | `namecheck clean` (a SKIP without a scrub list in `$SFAB_SCRUB_LIST`), `sfab check clean` |

A KNOWN line names an id from `spec/known.yaml`. Here the expected one is L1: a ping across the pair can show duplicate replies, because the virtual switch does not enforce peer-link isolation.

## What M1 settles

`RESULTS.md` gives each answer with its evidence file. Among them: whether containerlab 0.81.0 expands `${VAR}` in the topology and accepts `devices:` on kind `linux`; whether `dell_sonic` honors generated credentials or keeps the kind's defaults (the harness reads whatever the switch container was given, so it works either way); the first rows of `spec/klish-normalize.yaml`; and whether TX checksum offload must also be off inside the guests.

## Platform notes for this lab

- A duplicate reply in a ping across the pair is the peer-link isolation limit (L1), not a fault.
- Switch MAC tables list the containers' own veth MACs and VLAN 1 entries on trunks; the MAC-table check sets both aside and fails on anything else that is not a host's.
- The switch's Linux side holds lo-m, docker-mgmt, redirect and docker0 addresses that KLISH hides; the forwarding-only check whitelists exactly those.
- GRO, rx-gro-hw and LRO must stay off inside every switch or bulk TCP crashes syncd; boot checks it after every deploy, and the audit again.
- Every failover figure on this image is an LACP-timeout figure, since a shut port drops no carrier at the far end (L9).

## Redactions in the recorded sets

The ten audit sets in `audits/` were recorded before `audit_clean` stopped saving namecheck's warnings, so each set's `repo/namecheck.txt` held every warning, each quoting the text it matched, and quoted the earlier sets' saved files again: 19 lines in the first set and 19439 in the tenth (`RESULTS.md`, problem 12). On 2026-10-21 each file was cut with `common/audit/redact_tree.py --class namecheck-summary` to the form later sets save: its one summary line, as recorded, which reads 0 fail in every set. That file's lines were renumbered, so each set's `REDACTIONS.md` gives its length as recorded and the recorded number of the line it kept (FRAMEWORK.md section 4.3). The cut changed no other file.

The two settle sets, `sfab-m1_settle_20261014T152031Z/` and `sfab-m1_settle_20261014T155439Z/`, were recorded before `redact.py` replaced measured throughput figures, which the repository does not publish. On 2026-10-21 iperf3's transfer and bitrate columns were replaced in place with `common/audit/redact_tree.py --class throughput` by `[redacted: throughput]`, on 66 lines in each set: five lines of each of the six `settle/4-tcp-*.txt` files (the three one-second lines and the sender and receiver lines), the same 30 lines in `commands.txt`, and the six TCP lines of `verdict.txt`. What item 4 proved reads as recorded: every run printed its receiver line, so TCP completed on all three paths with the guests' offload off and on, and the retransmit counts and congestion windows are kept. Every line keeps its number, and each settle set's `REDACTIONS.md` lists the file, line and class (FRAMEWORK.md section 4.3).

The ten audit sets were also recorded before `redact.py` replaced the PA-VM's `vm-cpuid`, the CPU signature the VM passes through from the lab host's processor, which the repository does not publish. On 2026-10-21 its value was replaced in place with `common/audit/redact_tree.py --class host-cpuid` by `[redacted: host-cpuid]` on three lines of each set: line 22 of `fw/04_system_info.txt` (`show system info`), and the same output in `commands.txt` and in the firewall's raw session under `raw/`. Every line keeps its number, and each set's `REDACTIONS.md` lists the file, line and class (FRAMEWORK.md section 4.3).

## Recording size

On 2026-10-21 the ten audit sets in `audits/` were brought to the repository's recording size policy (FRAMEWORK.md section 4.4): their per-node `00_ALL_OUTPUT.txt` files and their `ALL_DEVICES_OUTPUT.txt`, which only joined the per-command files beside them, were removed. No other file changed.
