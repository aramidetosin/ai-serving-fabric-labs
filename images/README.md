# images

The container images the labs run besides the vendor images, which `VENDOR-IMAGES.md` covers: where to get the switch, firewall and storage images and how to build each with vrnetlab. Each is built from this directory on the lab host, with every pin read from `spec/versions.yaml`. The images hold no password, no key, no lab name and no organization name: a node learns all of those from the files the generator renders into its `bootstrap/<node>/` directory, and from the lab key under `state/secrets/`.

| Image | Tag (versions.yaml) | What it is | Directory |
|---|---|---|---|
| VM node | `sfab/vm-node:6-k8s1.35.8` | a KVM Ubuntu 24.04 guest inside a container: the control and GPU nodes (a GPU node that runs a model server mounts the models share read-only at `/srv/models`) | `vm-node/` |
| Client | `sfab/client:2` | pinned Alpine with the test tools: the operator's, the enterprise's and the internet's clients | `client/` |
| Bastion | `sfab/bastion:4` | pinned Ubuntu with sshd, kubectl, helm and cilium-cli at their pins: the operators' jump host, one leg, no DNS, time, CA or admin kubeconfig | `bastion/` |
| Resolver | `sfab/resolver:3` | pinned Alpine with BIND, dnsmasq and chrony at their package pins: the authoritative pair (dns-auth1 primary, dns-auth2 secondary over TSIG), the two recursive resolvers that also serve time (dns-res1, dns-res2), the corporate resolver stand-in (ent-dns), the public servers and the upstream time reference with NTS (inet-ntp) | `resolver/` |
| VPN router | `sfab/vpngw:3` | sfab/client plus strongSwan 5.9.13 (charon and swanctl), openssh-server and sudo, the packages it adds checked by sha256 before they install: the operator site's router, ops-gw, holding an IKEv2 tunnel to the firewall with the pre-shared key the topology binds from state/secrets/ipsec, and taking the `admin` SSH login (key only, on its management address only) like the FRR routers | `vpngw/` |
| FRR | `sfab/frr:10.5.4-3` | FRR 10.5.4 by digest, with its management port in VRF `mgmt`: the uplink router, the ISP router and the carrier | `frr/` |
| Registry | `sfab/registry:3` | distribution 2.8.3 by digest over TLS (a leaf of the lab's internet intermediate), a read-only mirror of every pinned image and chart (`registry-seed` fills its data) | `registry/` |
| Serving | `sfab/serving:b11382-2` | pinned Debian 12 slim with llama.cpp b11382's `llama-server` and `ggml-rpc-server` and the readiness probes, and no model (the recipe mounts the weights from the models share at `/models`): the model server and its RPC workers, which the cluster pulls from the in-lab registry (chapter 6 on) | `../serving-layer/image/` |
| Keys | `sfab/keys:3` | `sfab/client` with `sfab-keys` and PyYAML from its pinned wheel: the API key tool, which the cluster pulls from the in-lab registry (chapter 6 on) | `keys/` |

Each of the last six brings its own targets and README in its directory (`<image>/image.mk`, which `images/Makefile` includes; the serving image's is `serving-layer/image/image.mk`, and its README is `serving-layer/README.md`).

## Building

```
make -C images all             # every image and the registry seed; the one step that needs the internet
make -C images pins            # the pins the Makefile reads
make -C images check           # namecheck and shellcheck over the build contexts
```

An image is rebuilt only when it is missing or a file it is built from is newer than the image; `FORCE=1` rebuilds anyway. The serving image and the key tool are built from pinned files in `VENDOR_DIR` (`vendor/` in the checkout, which git ignores; the lab host keeps it outside the checkout, as it does the disks): `make -C images serving-fetch` and `keys-fetch` put each file there (below), and `make -C images registry-seed` pushes both images into the in-lab registry after it copies the upstream pins, since the cluster pulls them from there. Builds and the bake use the host's network (`BUILD_NETWORK=host`, the default) and need BuildKit (docker 23 or later). After `make -C images all` a lab needs no internet.

The VM node takes three steps, which `make -C images vm-node` runs in order:

1. `vm-node-fetch` makes sure the pinned Ubuntu 24.04 cloud image (`guest.ubuntu_cloud_image` in versions.yaml: release, serial and sha256) is in place under its official name, `ubuntu-24.04-server-cloudimg-amd64.img`. A copy already there whose sha256 matches is used as it is; otherwise the image is downloaded from `cloud-images.ubuntu.com/releases/24.04/release-<serial>/` and refused unless its sha256 matches.
2. `vm-node-base` bakes `node.qcow2` (below). It runs again only when the bake scripts or the pins change.
3. `vm-node` builds the image with the baked disk at `/base/node.qcow2`, so the disk lives once, in Docker. The disk reaches the build as the named build context `base`.

By default the cloud image sits in `vm-node/base/cache/`, and `vm-node/base/` holds the baked disk, its sha256 (`node.id`), its package list (`node.manifest`), the pins it was baked from (`node.pins`) and the bake's logs. Git ignores all of it. A host that syncs its checkout with `rsync --delete` would lose those files at every sync, so it keeps them outside the checkout with `SFAB_IMAGE_STORE=<dir>`: the cloud image is then `<dir>/ubuntu-24.04-server-cloudimg-amd64.img` (used when present, fetched there when not) and the bake writes `<dir>/vm-node-base/`. `CLOUD_IMAGE_DIR` and `VM_NODE_BASE` set the two places one at a time, and `make -C images pins` prints where they are.

### When the pinned cloud image is gone

`vm-node-fetch` downloads `release-<serial>` from cloud-images.ubuntu.com. On 2026-10-21 that site's `releases/noble/` directory held 57 serials of Ubuntu 24.04, from the release's first, `20240423`, to `20261017`, and the directories of the two earlier LTS releases still reached back to their first serials (`jammy` to `20220420`, `focal` to `20200423`). If the pinned serial is no longer there:

- **A copy you already have** is used as it is when its sha256 matches the pin: put it at `vm-node/base/cache/ubuntu-24.04-server-cloudimg-amd64.img`, or at `<dir>/ubuntu-24.04-server-cloudimg-amd64.img` under `SFAB_IMAGE_STORE=<dir>`.
- **A newer serial** otherwise. Pick one from https://cloud-images.ubuntu.com/releases/noble/ and take its sha256 from that serial's `SHA256SUMS` line for `ubuntu-24.04-server-cloudimg-amd64.img`. Set `guest.ubuntu_cloud_image.serial` and `sha256` in `spec/versions.yaml`, or give `UBUNTU_SERIAL=<serial> UBUNTU_SHA256=<sha256>` to `make -C images all` for one build. Then re-check:
  1. **The archive snapshot.** The bake installs `linux-modules-extra` for the cloud image's own kernel from `ubuntu_archive.snapshot`, and stops when the snapshot has no such package. A snapshot taken before the serial's kernel was published has none, so move `ubuntu_archive.snapshot` to a moment after the serial when needed. A new snapshot also changes every package the vm-node runtime image and the bake install.
  2. **The kernel.** The comment above `guest.ubuntu_cloud_image` records the pinned image's kernel (6.8.0-138-generic); the new bake's `node.manifest` records the new one. Update the comment to match.
  3. **The rebuild.** `make -C images vm-node` bakes again when the pins change. A lab's existing node disks were made from the old base disk, and `vm-init.sh` refuses them, so run `make wipe` in the lab before its next `make up`.
  4. **The lab.** Run the lab's `make up`, `make audit` and `make trace`, and compare them with its recorded runs, whose guests all ran the pinned serial's kernel.

## Pinned downloads for the serving image and the key tool

`images/fetch.py <pin> <directory>` puts one pinned file in place: a copy already there is used when its sha256 matches the pin, and nothing is downloaded; otherwise the file is downloaded from the pin's URL and refused unless its sha256 (and its size) match. `make -C images serving-fetch` runs it for the llama.cpp release and the two packages below into `VENDOR_DIR/serving/` (the packages into `debs/`), `models-fetch` for the two models into `images/models/` (git ignores it; `SFAB_MODELS_STORE=<dir>` keeps them in `<dir>` with `images/models` a link to it, which `models-link` puts back after a sync), and `keys-fetch` for the wheel into `VENDOR_DIR/keys/`. Each comes from its publisher, by the pins in `spec/versions.yaml`:

| File | Pin | Source | sha256 |
|---|---|---|---|
| `llama-b11382-bin-ubuntu-x64.tar.gz` (17,669,957 bytes, MIT) | `serving.llama_cpp` | llama.cpp release b11382 on GitHub, `https://github.com/ggml-org/llama.cpp/releases/download/b11382/llama-b11382-bin-ubuntu-x64.tar.gz`; GitHub lists the same sha256 for the asset | `34407d59947ed4ab35fe4ab2db5f61bb4d5aedfe25e6a72f702f3ae9758a396d` |
| `LFM2.5-24B-A2B-Q4_K_M.gguf` (14,526,258,464 bytes, LFM Open License v1.0) | `serving.models.chat` | Hugging Face, `LiquidAI/LFM2.5-24B-A2B-GGUF` at revision `0912d33141f77e10705345a6732bfd83f0252fdc` | `d3334405b96228eb9908cdebb5c6194908f2da64282bda852afc3a3910c64e7d` |
| `Qwen3.8-27B-UD-Q4_K_M.gguf` (16,464,440,224 bytes, Apache-2.0) | `serving.models.staff` | Hugging Face, `unsloth/Qwen3.8-27B-GGUF` at revision `4ca720788d1e01f1bff70c033e0d0028fd02e502` (Qwen publishes no GGUF) | `322e194ff79741c7baa497c240f677f54b201b0efab44ca8e50f122b39123482` |
| `libgomp1_12.2.0-14+deb12u1_amd64.deb` (115,772 bytes) | `serving.debs.libgomp1` | Debian 12, `deb.debian.org/debian/pool/main/g/gcc-12/` | `48fec46bda7f5b1638b9e959889bfbc20491247d402d120bb152687eb48143d7` |
| `libssl3_3.0.22-1~deb12u1_amd64.deb` (2,039,240 bytes) | `serving.debs.libssl3` | Debian 12 security updates, `deb.debian.org/debian-security/pool/updates/main/o/openssl/` | `f0a8aa8429209e556c278a9936bbd5f7d2cdb9f7e4e23b1e43ed399217ba80c1` |
| `pyyaml-6.0.3-cp312-cp312-musllinux_1_2_x86_64.whl` (790,181 bytes, MIT) | `keys.pyyaml` | PyPI, PyYAML 6.0.3; PyPI lists the same sha256 for the file | `41715c910c881bc081f1e8872880d3c650acf13dfa8214bad49ed4cede7c34ea` |

The two packages are the ones the base image's own apt sources named on 2026-10-21, and each sha256 is the archive's own Packages entry. The base image needs them because the release's two programs link `libgomp.so.1`, `libssl.so.3` and `libcrypto.so.3`, which Debian 12 slim does not carry (`ldd` in the pinned base); the build runs `ldd` again and stops on a library not found. If a pinned `.deb` is no longer on `deb.debian.org` when you build, a copy you already have is used as it is when its sha256 matches, and `snapshot.debian.org` keeps Debian's past package versions under the same file names.

The serving image's base and the three images the cluster pulls from upstream are pinned by digest in the same file, and `make -C images serving` and `registry-seed` take them from their registries:

| Image | Pin | What it is |
|---|---|---|
| `docker.io/library/debian:12-slim` | `images.debian_base` | the serving image's base, index `sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8` |
| `ghcr.io/k8snetworkplumbingwg/multus-cni:v4.3.0-thick` | `kubernetes.multus` | Multus's thick plugin; the manifest is the tag's `deployments/multus-daemonset-thick.yml`, kept in the repo (`common/sfab/render/upstream/`) |
| `docker.io/apache/apisix:3.9.1-debian` | `kubernetes.apisix` | the API gateway (chapter 7) |
| `ghcr.io/berriai/litellm:v1.104.0` | `kubernetes.litellm` | the model router (chapter 7) |

The registry seed copies the linux/amd64 manifest of each of the last three (`platforms: one`), and the pods name it by that manifest's digest (`platform_digest`).

## The base disk

`vm-node/bake/bake.sh` runs in the runtime stage of the vm-node image with `/dev/kvm`. It boots the cloud image once on a qcow2 overlay with `bake/user-data-bake.tmpl`, and the guest runs `bake/provision.sh`:

- it points apt at the Ubuntu archive as `snapshot.ubuntu.com` served it at `ubuntu_archive.snapshot` in versions.yaml, so the same pins always bake the same packages (the runtime image installs QEMU from the same snapshot); every download retries, since the snapshot service answers 5xx now and then;
- it holds every installed kernel package first, so the disk boots the kernel `linux-modules-extra` was installed for;
- it installs containerd, open-iscsi, multipath-tools, nfs-common, nvme-cli, lldpd, linux-modules-extra for the running kernel, and the tools the audits use (ethtool, tcpdump, iperf3, traceroute, jq, dig, conntrack);
- it installs kubelet, kubeadm and kubectl at `kubernetes.version` (v1.35.8, package `kubernetes.packages.kubeadm`, 1.35.8-1.1) from pkgs.k8s.io with kubernetes-cni and cri-tools at their pinned versions, and holds them;
- it configures containerd with systemd cgroups and one registry `config_path` directory (`/etc/containerd/certs.d`), loads overlay, br_netfilter, iscsi_tcp and nvme_tcp at boot, sets the Kubernetes sysctls, and runs sshd as a plain service with no password login;
- it turns off unattended upgrades and the apt timers and removes snapd;
- it puts the image's own apt sources back, cleans cloud-init's state and the machine id, so every node boots as a new instance, trims the disk and powers off.

The guest reports through a directory shared over 9p: its log, the package manifest and a status line. bake.sh then flattens the overlay into `node.qcow2`. The bake has no user, no password and no key; it is reached only through its console log.

## sfab/vm-node

`vm-init.sh` is PID 1. The topology (`render/clab.py`) gives it:

| What | Where in the container | From |
|---|---|---|
| node.env and anything else rendered for the node | `/sfab/bootstrap/` (read-only) | `bootstrap/<node>/` |
| the root disk, the seed, the console log | `/vm` | `state/nodes/<node>/` |
| the guest hold flag and the cluster hand-off | `/shared` | `state/shared/` |
| the authorized keys: the lab key and the deploying user's own (`~/.ssh/*.pub`, read at every preflight) | `/sfab/authorized_keys` (read-only) | `state/secrets/authorized_keys` |
| KVM and taps | `devices: [/dev/kvm, /dev/net/tun]` | |
| sizing | `SFAB_NODE`, `VM_MEMORY_MB`, `VM_SMP`, `VM_DISK_GIB`, `VM_NICS`, `VM_TX_OFF` | the model |

node.env carries the same sizing under the same names; when the two disagree, vm-init.sh logs it and uses node.env.

At every start it:

1. waits while `/shared/hold-guests` exists (polled every `HOLD_POLL_S`, at most `HOLD_S`), and only then waits for its links, so every link exists when it is wired;
2. bridges each NIC to a tap. The data bridges forward LACP and LLDP (`group_fwd_mask 0x4004`), and the container's own data devices carry no IPv6 and have TX checksum offload off. eth0 gives its address up: the guest takes the management address itself. A stock Linux kernel refuses bit 2 of that mask (LACP's address), so on such a host a data NIC is joined to its tap by a tc mirred redirect both ways instead, the way vrnetlab wires its VMs; the log names the mode of every NIC, and `SFAB_NIC_LINK=tc`, which the render gives every VM node when `spec/common.yaml` sets `guest.nic_link: tc`, forces the redirect everywhere;
3. creates `/vm/root.qcow2` as an overlay of `/base/node.qcow2` the first time, grows it to `VM_DISK_GIB` when it is smaller (never shrinks it), and refuses to start when the disk was made from another base disk (`/vm/base.id` against `/base/node.id`); `make wipe` clears it;
4. writes the NoCloud seed, `/vm/seed.iso`;
5. boots the guest (`-uuid VM_UUID`, so every node has its own product UUID) and waits for it. `docker stop` presses the guest's power button over the QEMU monitor; when the guest powers off the container stops, and with `restart-policy: "no"` it stays stopped.

### Inside the guest

| Path | What |
|---|---|
| `/etc/sfab/node.env` | the rendered node.env |
| `/opt/sfab/bin/netsetup.sh` | builds the network from node.env |
| `/opt/sfab/bin/seed-sync.sh` | installs the files the seed carries, at every boot |
| `sfab-netsetup.service` | runs seed-sync.sh, then netsetup.sh, once per boot after networkd |
| `/etc/systemd/network/10-sfab-<name>.link` | names each NIC by its MAC: eth1, eth2, eth3, rail1 to rail8 |
| `/etc/systemd/network/05-sfab-unmanaged.network` | networkd leaves the data NICs, the bond and the relay alone |
| `/etc/systemd/networkd.conf.d/10-sfab-foreign.conf` | networkd keeps other owners' rules and routes |
| `/etc/lldpd.d/sfab.conf` | lldpd on the lab wiring only |
| `/etc/containerd/certs.d/<upstream>/hosts.toml` | a Kubernetes node's registry mirrors, one per upstream registry host, and in a lab that runs the serving recipe one for the mirror itself, `/etc/containerd/certs.d/<mirror>/hosts.toml`, for the images built here (`bootstrap/<node>/containerd/`) |
| `/etc/sfab/k8s/*` | a Kubernetes node's cluster files (`bootstrap/<node>/k8s/`: cluster.env, kubeadm.yaml, kube-vip and, on the init node, the CRDs and Cilium's values) |
| `/opt/sfab/bin/cluster-bootstrap.sh`, `sfab-cluster.service` | kubeadm init or join, kube-vip, and on the init node the CRDs and Cilium; seed-sync.sh enables and starts the unit the first time it installs it, so every boot runs it after sfab-netsetup.service |

cloud-init writes its files once per instance, so a guest on an existing disk would keep its first boot's files. The seed therefore carries every node file under `sfab/root/` with a `sfab/MANIFEST` of their sha256, mode and owner, and seed-sync.sh installs any that differ before netsetup.sh runs. A redeploy on existing disks boots the current render; node-sync still applies a change live, without a reboot.

The user is `admin` (`guest.user` in common.yaml), the user the containerlab VS Code extension's Connect (SSH) logs in as on a `linux` node, with the bound authorized keys and passwordless sudo, and no password. Its primary group is the group of its own name, made when missing: Ubuntu's cloud image already holds a group `admin`, and without that line cloud-init fails to create the user (vm-node `1-k8s1.35.8` did, which `2-k8s1.35.8` fixes). cloud-init makes the user once per disk, so a disk made for another user keeps that one: preflight refuses such a disk (`pf_guest_user`), and `make wipe` clears it.

### The network netsetup.sh builds

- **Management:** networkd puts eth0's default in table 150 behind a rule for the management address, so the main table holds no management default (Cilium flushes table 200).
- **Bond:** `bond0`, 802.3ad over eth1 and eth2 with `lacp_rate fast`, `miimon 100` and the `layer3+4` hash, MTU 9000, the members at 10000 Mb/s full duplex (virtio reports no speed, and 802.3ad needs one). The node's address and the main default route via the VLAN's gateway on the firewall.
- **Out-of-band:** the BMC address on eth3 answers only from table 100; the main table has no route to the out-of-band subnet, so a data-side packet to it crosses the firewall. Reach the out-of-band network from the node with `ping -I <BMC address>` or `ping -I eth3`.
- **Rails and the in-node relay (build A):** the rail NICs rail1 to rail8 carry no address. Namespace `gpuR` holds rail R's address on a macvlan named `railR` (MAC `02:5a:<management octet>:01:00:<NIC index>`), and a veth `relay` whose peer `rlR` is a port of the bridge `relay0`, at `10.21.250.R`. A route to every other rail goes via that rail's namespace with the source pinned to the namespace's own rail address; there is no default route; forwarding is on and rp_filter is loose (2).
- **Routed rails (build B):** each rail NIC holds its address, and traffic sourced from it leaves on that rail through table 300 + r.
- **TX checksum offload** is off on every data NIC inside the guest as well.
- The node's own iSCSI initiator name, `iqn.2026-10.<org domain reversed>:<node>`; nvme_tcp and iscsi_tcp loaded; sshd always listening.

## sfab/client

PID 1 is tini with an idle loop. The topology runs `/usr/local/sbin/sfab-init.sh` as the node's exec, after the links are attached; it reads `/sfab/bootstrap/init.env` (bound from `bootstrap/<node>/`) and:

- writes resolv.conf first, before it waits for anything (below);
- waits for its data NICs, addresses each port in `IFACES`, or builds the bond and the out-of-band port when the env describes them (the bastion's shape, so other images can reuse the script);
- moves the management default into table 150 behind a rule for the management address, and sets the main default to the data gateway;
- adds the static routes and turns TX checksum offload off on every data NIC;
- writes resolv.conf: its search line is always `SEARCH`, the lab's domain, never the one Docker copies from the lab host's own file; the nameservers and options are `DNS_SERVERS` and `RESOLV_OPTIONS` when the lab has the node's resolver, and Docker's own lines otherwise. The registry and resolver images run the same script, and `sfab/frr`'s `frr-init.sh` and `sfab/bastion`'s `bastion-init.sh` carry the same function;
- when `CA_ROOT` is set, appends the lab root CA to the system bundle once the bastion has published it, in the background so the exec returns. The client then needs `state/shared` bound at `/shared`.

## The env files

`render/host.py` writes `bootstrap/<node>/node.env` for every VM guest and `bootstrap/<node>/init.env` for the bastion, the clients, the resolvers, the registry and the VPN router (with its `swanctl.conf`, the firewall's proxy IDs mirrored, and `IPSEC_DIR`, `IPSEC_PSK` and `IPSEC_PEER_ID`). Each holds one header comment line, then `KEY=value` lines sorted by key, so `sort` leaves the file unchanged. Lists are space-separated; a route is `dest,via,dev,src`. The main keys:

| Keys | Meaning |
|---|---|
| `LAB`, `NODE_NAME`, `NODE_KIND`, `NODE_ROLE`, `DOMAIN`, `FQDN` | identity |
| `MGMT_IF`, `MGMT_ADDR`, `MGMT_GW`, `MGMT_TABLE` | management, table 150 |
| `VM_MEMORY_MB`, `VM_SMP`, `VM_DISK_GIB`, `VM_NICS`, `VM_TX_OFF`, `VM_UUID`, `MGMT_MAC` | the guest (node.env) |
| `NICkk_MAC`, `NICkk_NAME`, `NICkk_ROLE`, `NICkk_MTU`, `NICkk_RAIL` | container port ethk: its guest MAC and name |
| `BOND_*` | the bond: name, members, mode, lacp_rate, miimon, hash, MTU, address, gateway, MAC |
| `OOB_IF`, `OOB_ADDR`, `OOB_GW`, `OOB_TABLE` | out-of-band, table 100; with `OOB_NETNS` (the BMC stand-in, `bmc`) the NIC moves into that namespace with the address and a default route, and `OOB_SERVICES` (`ssh https`) names what the namespace answers |
| `BOND_VLANS`, `VLAN<id>_ADDR`, `_MTU`, `_TABLE`, `_PREFIX`, `_GW` | the bond's tagged units (bond0.120 on the GPU nodes, bond0.110 on the ingress nodes); a unit with a table sends what is sourced from its segment out of itself by that table |
| `RAILS`, `RAIL_MODE`, `RAIL_MTU`, `RAILr_IF`, `RAILr_ADDR`, `RAILr_TABLE`, `RAILr_GW` | rails; the tables only when routed |
| `RELAY_*`, `RELAYr_NS`, `RELAYr_MACVLAN`, `RELAYr_MACVLAN_MAC`, `RELAYr_VETH`, `RELAYr_PORT`, `RELAYr_ADDR`, `RELAYr_ROUTES` | the in-node relay |
| `IFACES`, `ETHn_ADDR`, `ETHn_MTU`, `GATEWAY`, `GATEWAY_DEV`, `ROUTES`, `TX_OFF` | a container's ports (init.env) |
| `DNS_SERVERS`, `SEARCH`, `RESOLV_OPTIONS`, `DNS_ROLE`, `CA_ROOT` | names and trust |
| `K8S_*`, `HOSTS` | the node's Kubernetes role, the API address and name, the registry mirror (when the lab runs Kubernetes) |
| `NTP_SERVERS` | the resolvers' chrony (spec `ntp.servers`: dns-res1 and dns-res2), when they are in the lab; netsetup.sh points systemd-timesyncd at both |

## Testing without a lab

`vm-init.sh`, `netsetup.sh` and `sfab-init.sh` each take `SFAB_DRY_RUN=1`: vm-init.sh writes the seed tree and prints the QEMU command, the other two print every change they would make, as if nothing existed yet. `common/sfab/tests/test_hosts.py` drives all three against the rendered files of `dev/m1` and a full build A lab.

## What the milestone runs settled

The bake runs end to end on the pinned cloud image and archive snapshot (`node.pins` and `node.manifest` record what it installed, including linux-modules-extra for the image's own kernel), and milestone M1's guests booted from the baked disk as overlays of it. M1's settle set answered the questions about the vm-node image (`dev/m1/RESULTS.md`, "The settle answers"):

- **Guest-side TX checksum offload** is not needed beside the container-side setting. TCP completed over bond0, over rail 1 and through the relay with the guests' offload off and again on (item 4), and M2 found the same on a routed path through the firewall (`dev/m2/RESULTS.md`, settle item 2). The guests keep it off, as rendered.
- **The data NICs.** On M1's lab host every data NIC took the bridge with `group_fwd_mask 0x4004`, and none fell back to the tc redirect (item 10): no recorded run has had a data NIC of a VM node fall back to `vm-init.sh`'s tc redirect, so that path, the one a stock kernel takes, is untested. (The switches' vrnetlab launcher, whose connection mode is tc by default, wires its VM's NICs with a tc redirect in every run.) LACP runs through the bridge: each guest's bond0 aggregates under one aggregator (M1's exit criterion 5).
- **`devices:` on kind linux.** containerlab accepts it (item 1).
- **NIC naming and the relay.** A reboot of k8s-gpu2 left its NIC names and MACs unchanged, and 9000-byte DF pings crossed the relay on all 8 rail pairs (item 10).
