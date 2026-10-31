# Milestone M2 results

What lab `sfab-m2` proved, the verdict lines that meet each of its sixteen exit criteria, the answers to the six questions its deploys settled, the RESULT line of every set, and how to reproduce them. FRAMEWORK.md section 6.3 (first row) places the milestone; `README.md` says what the lab builds.

M2 ran on 2026-10-20 on one lab host, at host tick 10000 on containerlab 0.81.1. The last deploy of the day, the record run, brought the lab up with `make up BG=1` at 09:04:09 UTC on the disks the earlier deploys kept, ran `make record` (the audit, the trace, then the gate) at 09:26:58, then `make down` at 09:39:15 and `make teardown-check`. Its images were `sfab/bastion:1` 61f795ccbaa1, `sfab/client:1` 65f9d5060772, `sfab/frr:10.5.4-1` b8cd88419a8a, `sfab/registry:1` ee8b09575ec0, `sfab/vm-node:1-k8s1.35.8` c638745d801c, `vrnetlab/dell_sonic:4.6.0` c0214f532277, `vrnetlab/paloalto_pa-vm:12.1.2` d1ca9a0f1687 and `vrnetlab/truenas_truenas:27.0.0-RC.1` d0b0a42ff2d3 (R/verdict.txt:14 to :21). Times are the lab host's clock.

Paths are relative to `audits/`. The short names:

| Name | Directory | What it is |
|---|---|---|
| R | `sfab-m2_audit_20261020T092658Z/` | the record set: the audit `make record` ran, then gated |
| T | `sfab-m2_trace_20261020T093153Z/` | the trace the same `make record` ran, then gated |
| U | `sfab-m2_audit_20261020T092038Z/` | the audit `make up` ran at the end of the same deploy |
| K | `sfab-m2_teardown_20261020T094121Z/` | criterion 15, from `make teardown-check` after `make down` |
| G | `sfab-m2_record-stage_20261020T090354Z/` | plain files from the record run: host readings before and after, the `make up` journal, the `make record`, `make down` and `make teardown-check` output, start times, disk readings, the memory watchdog's log and its dry run, `make node-sync CHECK=1`, the TrueNAS setup output, and the gate on U and on K |
| F | `sfab-m2_final-run_20261020T075610Z/` | plain files from the deploy before it, which ended with its own `make record` |
| E | `sfab-m2_record-run_20261020T063637Z/` | plain files from the second deploy and, under `exit-checks/`, the second `make up`, the recovery, the audit after it and the down, up, down cycle |
| D | `sfab-m2_deploy-run_20261020T054503Z/` | plain files from the first deploy (`first-up/`) and the settle evidence (`settle2/`, `settle4/`, `settle5/`) |

## What the lab proved

Every criterion is a set of lines in a result set, quoted as the judge prints them.

| # | Criterion | Section of `verdict.txt` | Verdict lines |
|---|---|---|---|
| 1 | Preflight, including tick 10000, no other sfab lab, every image, the memory budget and the disk budget | `preflight, as run at ...`, `preflight, read again now` | R/verdict.txt:1 to :34 (tick :9; MemAvailable 301.4 GiB covers 112.75 GiB plus the 16.0 GiB floor :23; disk :25); the stage's own result, 28 passed, G/make-up.txt:31 |
| 2 | M1's criteria 2 to 6 hold on M2's port plan | `<switch>: switch`, `<switch>: forwarding only`, `pair fe-sw1 fe-sw2`, `fw: firewall`, `<node>: guest`, `<gpu>: relay and rails` and the VLAN and MAC-table sections | R/verdict.txt:53 to :370 (NUM_NICS 12, 11, 7, 8, 8 at :55, 64, 73, 81, 89; parity 113 of 113 and 109 of 109 on the pair at :61, :70; PortChannel1 to 31 at :336 to :344 and :361 to :369) |
| 3 | The cluster's nodes: the bootstrap unit, kubelet, the registry mirrors, NTP from the bastion, the internal view, TrueNAS on NFS | `<node>: cluster node` | R/verdict.txt:371 to :420, nine lines for each of k8s-cp1 to k8s-cp3, k8s-gpu1 and k8s-gpu2 |
| 4 | The bastion: its bond and routes, named, chronyd and sshd, the lab root and its two name-constrained intermediates, no private key under `state/shared/`, kubectl through the API VIP, helm, TrueNAS's web interface | `bastion: bastion` | R/verdict.txt:421 to :443 |
| 5 | The uplink side: the router's VRF, links and forwarding, the firewall by ARP, the registry's catalog, charts and the pulls from the firewall's public address | `uplink-rtr: router`, `inet-registry: registry` | R/verdict.txt:444 to :467 (the firewall by ARP :457; pulls from 198.51.100.2 :467) |
| 6 | The clients | `<client>: client` | R/verdict.txt:468 to :483 |
| 7 | The populations reach their Gateways, each probed from its own node, and the enterprise gets a 404 from `gw-users` for the admin name | `population <name>` | R/verdict.txt:487 to :501 (the 404 :492) |
| 8 | The cluster: five nodes Ready, Cilium without kube-proxy, the API VIP, cert-manager and the wildcard, both Gateways programmed and announced, the backend and routes, the storage classes, no Warning event | `cluster` | R/verdict.txt:502 to :536 |
| 9 | Storage: TrueNAS healthy, and a volume on each class written and read back, with NVMe/TCP 4420 answering every node while the claim is bound | `truenas1: storage`, `storage: a volume on each class` | R/verdict.txt:484 to :486, :537 to :541 |
| 10 | Finish: the bootstrap, every node Ready, kubeadm's keys retracted, Cilium, the manifests, the CA Secret, the charts, TrueNAS set up, the storage bonds, democratic-csi, the settle sweeps, the Warning events held at 0 | the finish stage's own lines | G/make-up.txt:236 to :274 (15 passed), its quick audit :472 (165 passed) |
| 11 | The trace: the enterprise client to the users' VIP, hop by hop, with the firewall's traffic log as a second witness | the trace set | T/verdict.txt:1 to :28; T/TRACE.md |
| 12 | Every set's RESULT line reads 0 failed | `== RESULT` | R/verdict.txt:545, T/verdict.txt:28, U/verdict.txt:545, K/verdict.txt:6 |
| 13 | Idempotence: a second `make up` acts on nothing | the stage markers | E/exit-checks/second-make-up.txt:35 to :63; the 17 start times identical (E/exit-checks/startedat-before-second-up.txt, startedat-after-second-up.txt); its audit `sfab-m2_audit_20261020T065924Z`, 495 passed |
| 14 | Recovery: after `docker rm -f sfab-m2-k8s-gpu1 && make recover`, k8s-gpu1 rejoins Ready and the next audit is green | boot, node-sync, finish | E/exit-checks/recover.txt:4, :230, :240, :243, :473; the next audit `sfab-m2_audit_20261020T072043Z`, 495 passed, `k8s-gpu1 Ready` (E/exit-checks/audit-after-recover.txt:525, :564) |
| 15 | Teardown: no container, no `clab-sfab-m2/`, the memory watchdog stopped, `state/` kept | the teardown set | K/verdict.txt:2 to :5; `down: stopped sfab-m2-memwatch` (G/down.txt:796) |
| 16 | Clean: namecheck and `sfab check` | `repository` | R/verdict.txt:543, :544 |

The audit touched nothing: the 17 containers' start times were the same before and after `make record` (G/startedat-before-record.txt and G/startedat-after-record.txt are identical). The memory watchdog started with the deploy (G/make-up.txt:36), logged only its `watching:` line and one dry-run poll (G/memwatch.log:7, :8) and stopped no guest. Boot's node-sync and `make node-sync CHECK=1` both found the five guests' boot-time files as rendered (G/make-up.txt:224 to :230, G/node-sync-check.txt:1 to :6).

## The RESULT lines

| Set | RESULT | Note |
|---|---|---|
| `sfab-m2_audit_20261020T061338Z` | 486 passed, 8 failed, 0 known, 0 skipped | the first deploy's first full audit: problems 2 to 4 below |
| `sfab-m2_trace_20261020T062508Z` | 23 passed, 0 failed, 0 known, 0 skipped | the first trace |
| `sfab-m2_trace_20261020T062633Z`, `..._062719Z` | 23 passed, 0 failed, 0 known, 0 skipped | the traces of settle item 2, the guests' offload on, then off |
| `sfab-m2_audit_20261020T062905Z` | 495 passed, 0 failed, 0 known, 0 skipped | the first green audit |
| `sfab-m2_audit_20261020T065408Z` | 495 passed, 0 failed, 0 known, 0 skipped | the second deploy's `make up` |
| `sfab-m2_trace_20261020T065818Z` | 23 passed, 0 failed, 0 known, 0 skipped | `make trace` |
| `sfab-m2_audit_20261020T065924Z` | 495 passed, 0 failed, 0 known, 0 skipped | the second `make up` (criterion 13) |
| `sfab-m2_audit_20261020T072043Z` | 495 passed, 0 failed, 0 known, 0 skipped | after `make recover` (criterion 14) |
| `sfab-m2_audit_20261020T074356Z` | 495 passed, 0 failed, 0 known, 0 skipped | the down, up, down cycle |
| `sfab-m2_teardown_20261020T075002Z` | 4 passed, 0 failed, 0 known, 0 skipped | that cycle's teardown; the gate on these six sets 25 passed, 0 failed (E/gate.txt:33) |
| `sfab-m2_audit_20261020T081249Z` | 495 passed, 0 failed, 0 known, 0 skipped | the `make up` of the deploy before the record run (F) |
| `sfab-m2_audit_20261020T081735Z`, `sfab-m2_trace_20261020T082153Z` | 495 passed; 23 passed; 0 failed, 0 known, 0 skipped | its `make record`; the gate 9 passed (F/record.txt:563, :596, :611) |
| `sfab-m2_teardown_20261020T082708Z` | 4 passed, 0 failed, 0 known, 0 skipped | its teardown |
| U, `sfab-m2_audit_20261020T092038Z` | 495 passed, 0 failed, 0 known, 0 skipped | the record run's `make up`; its gate 5 passed (G/gate-make-up-audit.txt:8) |
| R and T | 495 passed; 23 passed; 0 failed, 0 known, 0 skipped | `make record`; the gate 9 passed, 0 failed (G/record.txt:563, :596, :611) |
| K | 4 passed, 0 failed, 0 known, 0 skipped | its gate 5 passed (G/gate-teardown.txt:8) |

Every set's `RUN.json` gives the lab, the spec and render sha256, the image ids, the containerlab release, the host tick and the UTC start and end; R and the sets of the deploy before it carry the same render and spec sha256 (R/RUN.json:45, :46). The labs repository commit reads `none` (R/RUN.json:42): the lab host's copy of the tree had no `.git`, and its `dirty: false` (:43) was never checked (FRAMEWORK.md 4.4). The README's "Redactions in the recorded sets" says what was replaced in the sets after they were recorded; each set with a replacement has `REDACTIONS.md`.

Two folders of plain files come from before the first deploy: `sfab-m2_record-refused_20261020T044237Z/`, where preflight refused the lab twice (`logs/preflight-20261020T042713Z.log:32` and `logs/preflight-20261020T044237Z.log:30`, 26 passed, 2 failed: containerlab 0.81.1 against a pin of 0.81.0 at :5, and a disk budget of 420 GiB at :25, which summed the guests' virtual disk sizes), and `sfab-m2_stage-fix_20261020T052831Z/`, where it passed once the pin followed the host's containerlab and the budget became the growth a deploy writes (FRAMEWORK.md 3.1): `logs/preflight-20261020T052831Z.log:5`, :25 and :30, 28 passed, 0 failed.

## The settle answers

1. **TrueNAS's launcher credentials: the generated ones.** containerlab's `generic_vm` kind gave the container `USERNAME` and `PASSWORD` from `state/secrets.env` (D/settle5/1-truenas-env.txt:1 to :4, presence and sha256 prefix only), and the launcher's own arguments carry the same prefixes (R/truenas1/02_launcher_login.txt:1, :2). `truenas-setup.py` logged in once with them (G/truenas-setup.txt:1, :14).
2. **TX checksum offload on a routed path: not needed either way on this path.** With the container side off throughout, the guests' side was turned on (D/settle2/1-guest-tx-on.txt), then off again (D/settle2/4-guest-tx-off.txt), with a trace each way: `sfab-m2_trace_20261020T062633Z` and `..._062719Z`, both 23 passed, and 5 of 5 HTTPS requests answered with the offload on (D/settle2/3-curl-offload-on.txt). With it on, only the lease holder's own capture of its outgoing replies read `incorrect`, and the same replies read correct at the switch port beyond it (D/settle2/6-checksums-on.txt); with it off every frame read correct (D/settle2/6-checksums-off.txt). The guests keep the offload off, as rendered, and T reads `correct` at every point (T/TRACE.md:57 to :65).
3. **The time from `make up` to a green audit.** 1268 s in the record run, on kept disks: preflight 1 s, up 7 s, boot 702 s (the firewall's step 383 s), finish 279 s, the audit 279 s (G/make-up.txt:32, :175, :233, :474, :1039). The deploy before it took 1247 s and the second deploy 1257 s. The first deploy, from empty disks, took 822 s for boot alone and needed problem 1's fix live (D/first-up/make-up.txt).
4. **ICMP on a Gateway VIP: no answer.** `ping -c 3` to 10.20.1.200 and 10.20.1.210 from k8s-cp1 and k8s-gpu1 received 0 of 3, while ARP resolved each VIP and TCP 443 opened; the API VIP 10.20.1.10 answered 3 of 3 (D/settle4/icmp-vips.txt:8 to :25). Cilium 1.19.7 answers no echo on a Gateway VIP, so every check uses TCP.
5. **M1's containerlab facts on 0.81.1: unchanged.** `${VAR}` expansion (D/settle5/1-truenas-env.txt:3, :4); `devices:` on kind linux, each vm-node container holding `/dev/kvm` and `/dev/net/tun` (D/settle5/2-devices.txt); and the sysctls, the topology's `net.ipv6.conf.default.disable_ipv6` "1" kept and `net.ipv6.conf.all.disable_ipv6` "0" added on kind linux (D/settle5/3-sysctls.txt:1 to :10).
6. **The disk the deploy used against its budget.** After the record run, which reused the day's disks: the control nodes 3.16 to 3.35 GiB of 6 each, the GPU nodes 3.08 and 3.23 GiB of 12, TrueNAS 0.99 GiB of 40, all of `state/` 16.97 GiB of 83 (G/state-du.txt); the switches' container layers 1.1 to 1.15 GB of 8 GiB each and the PA-VM's 1.76 GB of 16 (G/container-layers.txt). Every figure is inside its budget.

## What the deploys found

Each problem stopped a run or failed a check, and its fix is in the tree.

1. **The init node could not copy helm out of its image.** `ctr images mount` fails through containerd 2.2.1's mount manager (`fstype: bind ... err: no such device`, D/first-up/k8s-cp1-sfab-cluster-journal.txt:95). `cluster-bootstrap.sh` copies helm out with a short-lived container of the image; on the first deploy the fix reached the running guests through `make node-sync`, and `dev/m2/Makefile` reads node-sync's exit 3 (a cluster file changed) as success.
2. **The pair's MAC tables held addresses the check did not know.** lldpd 1.0.18 sends LLDP on a bond member from one fixed address when the member's own MAC is locally administered, as every lab MAC is, and its `bond-slave-src-mac-type` is `local`, its default (D/first-up/quick-audit/verdict.txt). The guests and the bastion set it to `real`. A container's bond member also sends LACPDUs from its own MAC, which `ip -j link` does not show and `ip -d -j link` does (`perm_hwaddr`), so `collect.sh` reads links with `ip -d` and the judge sets those MACs aside; the quick audit now collects TrueNAS's container links too.
3. **TrueNAS listens on NVMe/TCP 4420 only while a subsystem exists.** The node check reads NFS 2049 only, and the audit's volume check reads 4420 from every node while its claim is bound (`sfab-m2_audit_20261020T061338Z` against R/verdict.txt:538).
4. **The firewall does not answer ping on its public address from the uplink.** ethernet1/5 carries the `ping-only` profile, but no rule admits zone uplink to zone uplink, so `deny-all-log` drops it. The router reads the firewall by ARP (R/verdict.txt:457).
5. **The TrueNAS password in `make down`'s output.** `containerlab destroy` prints the output of every lab container that exited, and the TrueNAS launcher's output lists its environment. `clab()` in `common/lib.sh` passes containerlab's output through `redact.py --stream`, and the record run's `make down` shows the value as `<redacted sha256:c77982cf125a>` (G/down.txt:126).

## How to reproduce

With the requirements in `README.md` met, the registry seeded and 128.75 GiB of MemAvailable:

```
cd dev/m2
make render && make up && make trace
make up                                       # every step reports its marker and acts on nothing
docker rm -f sfab-m2-k8s-gpu1 && make recover     # links lost: boot redeploys, k8s-gpu1 rejoins
make audit
make down && make up && make down
make teardown-check
```

`make exit-criteria` runs the same sequence and stops at the first failure. On kept disks `make up` to a green audit took 1247 to 1268 s, `make record` spent 326 s on the audit and the trace before its gate, and `make down` took 109 s (G/record.txt:565, :598; G/down.txt:803).

## What the recordings do not show

- **A green run from empty disks.** The first deploy started from empty disks and needed problem 1's fix live; every green run after it reused the disks. Chapter 3's lab, on the same slice, deployed green from empty disks (`ch03/RESULTS.md`).
- **node-sync changing a running guest** as a saved file. On the first deploy it printed `UPDATED`, `BOOTSTRAP-CHANGED` and `APPLIED` lines on all five guests; G keeps only the `CHECK=1` reading.
- **`make exit-criteria` as one target.** Its steps ran one by one.
- **The labs repository commit** in any `RUN.json`.
- **The VM nodes' tc redirect.** The lab host's kernel accepted `group_fwd_mask 0x4004`, so every data NIC of every VM node took its bridge: each `wired` line `images/vm-node/vm-init.sh` logged in these sets names `bridge` for every NIC. A stock kernel refuses that mask, and on such a host `vm-init.sh` joins the data NICs, the bond members among them, to their taps with a tc mirred redirect instead. No recorded run exercised that path; `guest.nic_link: tc` in `spec/common.yaml`, with the lab rendered again, forces it, for testing (the repository's `README.md`, "The host").
