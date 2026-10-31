# Milestone M2: build A with the cluster

M2 is not a chapter. It is the second framework milestone (FRAMEWORK.md section 6.3, first row), lab `sfab-m2`: build A's one-tenant state with Kubernetes on and no serving layer. It puts on top of M1's switches, PA-VM and GPU nodes everything chapters 1 to 7 stand on: the control nodes, the platform's DNS and time servers, the bastion as a jump host, the lab CA on the lab host, the uplink side with the in-lab registry and the time reference, the operator's and the enterprise's clients, TrueNAS, the cluster with its two Gateways and a test backend, and the first hop-by-hop trace. `RESULTS.md` holds its sixteen exit criteria, each met by lines of a result set, with the evidence.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, web-client, ent-client, truenas1]` |
| Features | `{k8s: true, serving: false, storage_setup: true}` |
| Containers | `sfab-m2-<node>` (27: the slice's 18, the ingress nodes k8s-ingress1 and k8s-ingress2 that the cluster brings, the DNS and time servers its nodes require, dns-auth1, dns-auth2, dns-res1, dns-res2, ent-dns and inet-ntp, and ops-gw, the operator site's VPN router ops-client sits behind); containerlab directory `clab-sfab-m2/` |

`make show WHAT=nodes` lists the nodes, `make show WHAT=ports` the port plan of every switch, and `make show WHAT=budget` the budget.

Status: build A revision 2 is rendered and tested, and M2 was deployed under it on 2026-10-27 and 28 (its audits and traces not published, FRAMEWORK.md 4.4): the firewall policy, the operator's tunnel, the DNS and time servers, the ingress nodes and TrueNAS's dual-attached management ran there. The committed result sets under `audits/` are revision 1's, recorded on 2026-10-20 under the node names and the design of that time (`RESULTS.md`; `../../README.md`, "Build A, revision 2"); the chapter labs' revision 2 recordings, not M2's, replace them as the build's evidence.

## What it builds

- **M1's fabric**, on the full pair port plan: fe-sw1 and fe-sw2 use the same 19 data ports each (the dedicated MCLAG keepalive link on Ethernet12, routed in VRF `VrfMclagKa`, fe-sw1 10.20.255.0/31 and fe-sw2 .1, with the backup keepalive on Vlan3966 over the peer link, .4 and .5; every port at MTU 9216, PVST with BPDU guard on each host-facing PortChannel, storm control on each member, as `ch03/README.md` describes; PortChannel10 to the firewall's `ae1`, trunking VLANs 100, 110, 130, 131, 200 and 300; PortChannel11 to 13 to the control nodes; 14 and 15 to the ingress nodes, VLAN 100 untagged and 110 tagged; 21 and 22 to the GPU nodes, VLAN 100 untagged and 120 tagged; 30 to the bastion; 31 to TrueNAS's data bond in VLAN 120 with two members on each switch; 32 to TrueNAS's management bond in VLAN 200, one leg on each switch; 41 to 44 to dns-auth1, dns-res1, dns-auth2 and dns-res2). The peer link carries every served VLAN, VLAN 120 included, and VLAN 3966. The out-of-band switch gains the control and ingress nodes (8 ports); the bastion has no out-of-band leg.
- **The segments** (spec/profile-a.yaml, FRAMEWORK.md 1.5): nodes in VLAN 100 (IP MTU 9000, zone k8s-nodes), the Gateway VIPs in VLAN 110 (1500, zone ingress), storage data in VLAN 120 (9000, Layer 2 only, no gateway), storage management in VLAN 200, the bastion in VLAN 300 and the services in VLANs 130 and 131 (1500 each). Each guest's BMC stand-in is a network namespace (`bmc`) holding the out-of-band NIC with its address and answering SSH and HTTPS there; the host OS keeps no address on the BMC VLAN.
- **The ingress nodes**, `k8s-ingress1` and `k8s-ingress2` (nodes .31 and .32, VLAN 110 .11 and .12): Kubernetes workers, tainted NoSchedule on their role label, that hold the Gateway VIPs' L2 announcement leases on `bond0.110`; a policy rule sends what is sourced from VLAN 110 out of that unit by table 110.
- **Three control nodes**, `k8s-cp1` to `k8s-cp3` (data .11 to .13): `bond0` across the pair and an out-of-band NIC. `k8s-cp1` initializes the cluster, the other two join it as control nodes, and the GPU nodes join as workers.
- **The DNS and time servers** (`sfab/resolver:3`): dns-auth1 (10.20.13.11, VLAN 130) and dns-auth2 (10.20.14.11, VLAN 131), the authoritative pair for `ai.tarnwick.example`, dns-auth1 primary and dns-auth2 its secondary by NOTIFY and AXFR under a TSIG key per view; the internal view answers dns-res1 and dns-res2, the enterprise view ent-dns. dns-res1 (10.20.13.21) and dns-res2 (10.20.14.21), the recursive resolvers every inside host names, also serve time with chrony, following inet-ntp (192.0.2.14 on the uplink side) over NTS. ent-dns (10.24.10.53 on the firewall's ethernet1/7) is the enterprise's corporate resolver: its own hosts under `tarnwick.example`, the platform zone forwarded to the pair.
- **The bastion** (10.20.3.10, VLAN 300): a jump host only, one leg, sshd, kubectl and helm, the lab root trusted, and each operator's short-lived kubeconfig (8 hours, ClusterRole view) that finish issues on the init node. It serves no DNS, time or CA and holds no admin kubeconfig; the harness's kubectl runs on k8s-cp1.
- **The lab CA** on the lab host (`common/ca/sfab-ca`, `make ca-status`): the root, the platform, kubernetes and internet intermediates, and leaves for the registry and inet-ntp.
- **The uplink side**: `uplink-rtr` (198.51.100.1/29 to the firewall's public address .2, 192.0.2.5/30 to the registry, 192.0.2.13/30 to inet-ntp, 192.0.2.17/30 to web-client, 192.0.2.21/30 to ops-gw, and a route to the operator's site 192.0.2.0/30 via ops-gw), `ops-gw` (192.0.2.22, strongSwan, an IKEv2 tunnel to the firewall's public address protecting the site to the ingress and bastion VLANs), `ops-client` (192.0.2.2, behind ops-gw), `web-client` (192.0.2.18, an internet host that is not the operator, listening on 443) and `inet-registry` (192.0.2.6:5000, HTTPS with a leaf of the internet intermediate; nodes verify it against the lab root). A node's pull leaves through the firewall's source NAT under nodes-to-registry, the one egress rule beside the resolvers' to `inet-ntp` (192.0.2.14).
- **The enterprise client** `ent-client` (10.24.10.10/30 on the firewall's ethernet1/4), resolving through ent-dns.
- **TrueNAS** `truenas1`: data 10.20.12.31 on the four-leg bond in VLAN 120, management 10.20.2.31 on the two-leg bond in VLAN 200, where alone its web interface and API answer; `common/storage/truenas-setup.py` sets it up in finish, and democratic-csi serves the `truenas-nvmeof` (default) and `truenas-nfs` classes, calling the API over HTTPS through the firewall (csi-to-storage-api) and moving data on VLAN 120 from the GPU nodes.
- **The cluster**: Cilium without kube-proxy, with the Gateway API and L2 announcements on `bond0.110` from the ingress nodes (VLANs 110 and 120 passed through Cilium's datapath); kube-vip on the API VIP 10.20.1.10; cert-manager with a CA ClusterIssuer on the platform intermediate and the wildcard certificate; the internal Gateway on 10.20.11.200 and the users' Gateway on 10.20.11.210; the test backend `echo` (agnhost netexec) behind both.
- **The firewall**: a zone per segment (k8s-nodes, ingress, stor-mgmt, bastion, services, oob, enterprise, uplink with zone protection, operator-vpn on tunnel.1), App-ID rules with application-default and the profile group bp-default, deny-all-log last and the predefined intrazone and interzone rules set to deny; discard routes for RFC 1918; the IKE gateway and IPsec tunnel to ops-gw set by boot through the API with the lab's pre-shared key (state/secrets/ipsec, never rendered).

## Requirements

- The images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and `vrnetlab/truenas_truenas:27.0.0-RC.1` (`images/VENDOR-IMAGES.md` says where to get and how to build each; preflight never pulls a vrnetlab image), and `sfab/vm-node:6-k8s1.35.8`, `sfab/bastion:4`, `sfab/resolver:3`, `sfab/frr:10.5.4-3`, `sfab/registry:3`, `sfab/client:2` and `sfab/vpngw:3` from `make -C images all`. `images/registry/data/` must be seeded (`make -C images registry-seed`) before the lab deploys: the registry binds it read-only.
- Memory: the inventory's budget is 126.75 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 142.75 GiB in all. If other workloads on the host leave less, preflight refuses; do not lower the budget or the floor to fit. 62 vCPUs against twice the host's CPU count. Disk: 95 GiB of expected growth under `state/` (TrueNAS 40, three control nodes and two ingress nodes at 6, two GPU nodes at 12, the lab's own files 1) and 56 GiB of container layers under Docker's data root (five switches at 8, the PA-VM at 16), on one filesystem where they share one; the guests' 40 and 80 GiB root disks are their virtual size, not the budget, and the registry's seeded data is not budgeted (FRAMEWORK.md 3.1).
- The host tick at 10000, containerlab 0.82.0 (the pin preflight checks), the host's `bonding` and `vrf` modules (preflight loads them; the router puts its management port in a VRF), and no other `sfab-` lab running.

## Running it

```
cd dev/m2
make render          # writes topo.clab.yml, bootstrap/ and gen/ from the spec
make up              # preflight, up, boot, finish, audit
make trace           # records audits/sfab-m2_trace_<UTC>/ with TRACE.md and the captures
make status
make audit           # records audits/sfab-m2_audit_<UTC>/
make down            # keeps state/ disks; make wipe removes them
```

`make up BG=1` runs the same as the transient unit `sfab-m2-up`; follow it with `journalctl -fu sfab-m2-up`. `make exit-criteria` runs the milestone's sequence (`RESULTS.md`, "How to reproduce") and stops at the first failure.

Two targets reach the parts M1 left out: `make memwatch-check` runs one dry-run poll of the memory watchdog (its floor, its victim order and the guest it would stop), and `make node-sync` brings the guests' boot-time files up to the current render (`CHECK=1` only compares).

Once the lab is up, `ssh admin@sfab-m2-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## The stages with the cluster on

- **up** starts the memory watchdog as the unit `sfab-m2-memwatch` before the deploy. Below the 16 GiB floor it stops one guest per poll, k8s-gpu2 first, then k8s-gpu1, k8s-cp3, k8s-cp2 and k8s-cp1, never a switch, the firewall, storage or a container. Its log is `state/logs/memwatch.log`.
- **up** runs `sfab-ca init` on the lab host before the deploy (it publishes `state/shared/ca/root.crt`, the kubernetes intermediate for the init node and the node leaves in `state/tls/`). **boot** runs M1's steps, then the lab's kubeadm join token from `state/secrets.env` into `state/shared/cluster/kubeadm.env` (0600), and after the guests answer, node-sync. TrueNAS's data bond is made by its setup in finish, so boot's fabric and bond waits leave PortChannel31 to finish.
- **The guests' cluster files**: `vm-init.sh` seeds `bootstrap/<node>/k8s/` into `/etc/sfab/k8s/`, `cluster-bootstrap.sh` and `sfab-cluster.service`, and the registry mirrors (`bootstrap/<node>/containerd/<upstream>/hosts.toml`) into `/etc/containerd/certs.d/`; `seed-sync.sh` enables and starts the unit the first time it installs it, so every later boot runs the bootstrap after `sfab-netsetup.service`. Each guest takes its time from dns-res1 and dns-res2 (`NTP_SERVERS` in node.env) and resolves through them (`DNS_SERVERS`).
- **finish**: the cluster bootstrap finished in this boot; every node Ready; kubeadm's keys retracted from `state/shared/` (`sfab-ca retract`: the kubernetes intermediate's key and the init node's shared control-plane keys, which boot and the init node publish again at the next boot); Cilium's devices and agents against the spec; `bootstrap/k8s/` applied server-side by kubectl on k8s-cp1; the platform intermediate's key pair written as cert-manager's issuer Secret (`sfab-ca k8s-secret` on the lab host, through a pipe to kubectl on k8s-cp1, from `ca-secrets.list`); the operators' kubeconfigs (`kubeadm kubeconfig user` on k8s-cp1, to `state/operators/<user>/kubeconfig`, 0600, which the bastion installs); the charts from the in-lab registry; `truenas-setup.py all`, then the pair again with PortChannel31, then democratic-csi; the settle sweeps (node to node, the storage address, TCP 443 to each VIP, each population's client); the Warning events archived, cleared and held at 0; the quick audit.

## The audit

`audit.sh` records the exit criteria 1 to 10 and 12 and 16; the sections of its `verdict.txt` are named in `RESULTS.md`. The full audit also writes a volume on each storage class from a GPU node and reads it back from a second pod, in the namespace `sfab-audit`, which it deletes again; while the NVMe-oF claim is bound it connects to TrueNAS's NVMe/TCP port from every node, since TrueNAS listens there only while a volume exists. `audit.sh --quick` (run by finish) reads the switches and the firewall, and the bastion's, the DNS servers' and TrueNAS's container links, which the MAC-table check needs because the switches learn those containers' MACs (a bond member's own MAC included).

What it reads, by node kind, is in `common/audit/cmds/` (README.md there): the bastion's container and its operator's certificate and role, the DNS and time servers (zones and serials, answers, NTS), kubectl on k8s-cp1 for the cluster, vtysh and a shell in the router, the registry's catalog and request log, the clients, TrueNAS's container state and the launcher's login (presence and a keyed mark, never a value), and per population the probe from its own node.

## The trace

`trace.sh` reads the flow and the capture points from `chapter.yaml`'s `trace:` block. The points at the lease holder are found when it runs: the ingress node holding the users' Gateway Service's L2 announcement lease, its two pair ports, and its own `bond0`, captured and decoded inside the guest. The warm-up attempt uses source port 41442 and the recorded one 41443. `trace-md.py` judges the evidence: the SYN with the recorded sequence number at every point, exactly one leg of each group, the tags, one TTL step at the firewall, no translation, the reply, and the firewall's traffic log as a second witness. Its entries are written when a session ends, with rule names cut to 19 characters, so the trace reads the log until the entry appears.

## What M2 settles

`RESULTS.md` gives each answer with its evidence file: whether TrueNAS's launcher reads `USERNAME` and `PASSWORD` from its environment or keeps a default; TX checksum offload on a routed path (the trace through the firewall, with the guests' offload on, then off); the time from `make up` to a green audit with the cluster, step by step; whether the pinned Cilium answers ICMP on a Gateway VIP (every check uses TCP); M1's containerlab facts (the `${VAR}` expansion, `devices:`, the sysctls) again on containerlab 0.81.1; and the disk the deploy used against its budget, under `state/` and in the container layers.

## Platform notes for this lab

M1's notes hold here too (`dev/m1/README.md`): duplicate replies across the pair are the peer-link isolation limit (L1); the switches' MAC tables learn the containers' own veth MACs and VLAN 1 entries, which the MAC-table check sets aside; GRO, rx-gro-hw and LRO must stay off inside every switch; every failover figure is an LACP-timeout figure (L9). The deploys of 2026-10-20 (`RESULTS.md`) added these:

- containerd 2.2.1 in the guests cannot `ctr images mount`; the init node copies helm out of its image with a short-lived container of it.
- lldpd on a bond member sends from the member's own MAC (`bond-slave-src-mac-type real`); its default sends every bonded node's LLDP from one fixed address. A container's bond member also sends LACPDUs from its own MAC, which the MAC-table check reads with `ip -d`.
- TrueNAS listens on NVMe/TCP 4420 only while a volume exists, so the audit reads that port with a claim bound.
- The firewall's public address answers ARP but no ping from the uplink side: no rule allows zone uplink to zone uplink, so `deny-all-log` drops it.
- Cilium 1.19.7 answers no ICMP echo on a Gateway VIP; every check uses TCP.
- `containerlab destroy` prints the output of every exited lab container, the TrueNAS launcher's environment and password among it; `clab()` in `common/lib.sh` redacts containerlab's output.

## Redactions in the recorded sets

The ten audit sets in `audits/` were recorded before the client image wrote the lab's own search line, so ops-client's resolv.conf held the lab host's own DNS search domain. In each set it is replaced in place by `[redacted: host-search-domain]` on one line of each of two files: `ops-client/07_resolv_conf.txt` and `commands.txt`, and it was on one line of `ops-client/00_ALL_OUTPUT.txt` and `ALL_DEVICES_OUTPUT.txt` too, which were removed from the sets the same day (below). Every line keeps its number, and each set's `REDACTIONS.md` lists the file, line and class (FRAMEWORK.md section 4.3).

The same ten sets were recorded before `redact.py` replaced the lab host's kernel release, which the bastion and uplink-rtr containers print as their own. In each set it is replaced in place by `[redacted: host-kernel]` on four lines: line 1 of `bastion/02_bonding.txt` (the bonding driver's header) and of `uplink-rtr/01_frr_version.txt` (FRR's `show version`), and the same output on two lines of `commands.txt`. It was replaced the same way in `bastion/00_ALL_OUTPUT.txt`, `uplink-rtr/00_ALL_OUTPUT.txt` and `ALL_DEVICES_OUTPUT.txt`, which were removed from the sets the same day. The VM nodes' own kernel is kept.

The same ten sets were recorded before `redact.py` replaced the PA-VM's `vm-cpuid`, the CPU signature the VM passes through from the lab host's processor, which the repository does not publish. In each set its value is replaced in place by `[redacted: host-cpuid]` on three lines: line 22 of `fw/04_system_info.txt` (`show system info`), and the same output in `commands.txt` and in the firewall's raw session under `raw/`.

The record-refused folder of 2026-10-20 04:42 UTC holds preflight's two refusals and the host's readings. One line of those readings, written by hand about the lab host outside the lab, is replaced in place by `[redacted: host-note]` (`host-readings.txt:24`), and two words of the hand-written header of the record run's disk reading, in set G of `RESULTS.md`, by `[redacted: work-note]` (`state-du.txt:1`); each folder's `REDACTIONS.md` lists them.

## Recording size

On 2026-10-21 the sets in `audits/` were brought to the repository's recording size policy (FRAMEWORK.md section 4.4). Each audit's per-node `00_ALL_OUTPUT.txt` files and its `ALL_DEVICES_OUTPUT.txt`, which only joined the per-command files beside them, were removed, and each audit's `bastion/18_pods.json` is stored compressed, as `18_pods.json.gz` holding the same bytes (`gzip -dc` reads it). No other file changed.
