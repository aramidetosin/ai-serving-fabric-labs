# The AI Serving Fabric: the labs

The companion lab repository of the book *The AI Serving Fabric: A Platform Engineer's Guide to Multi-Tenant Inference Networks*. Each chapter's lab lives in its own directory, `chNN`. A lab deploys the chapter's state of the book's running example from the files committed here: a containerlab topology and every node's bootstrap configuration, all rendered from one specification, with nothing typed by hand. Each lab also carries the scripts that check it (an audit, a path trace, failure drills and the chapter's break exercises) and the recorded runs behind every output the chapter prints.

## Status

| Chapter | Title | Running example | Lab |
|---|---|---|---|
| 1 | Introducing the AI Serving Fabric | build A (enterprise), one tenant | recorded under revision 2, [`ch01/`](ch01/) |
| 2 | Multi-Tenant Access Design | build A (enterprise), one tenant | recorded under revision 2, [`ch02/`](ch02/) |
| 3 | Layer 2 Frontend with MCLAG | build A (enterprise), one tenant | recorded under revision 2, [`ch03/`](ch03/) |
| 4 | Firewall-Hosted Gateways | build A (enterprise), one tenant | recorded under revision 2, [`ch04/`](ch04/) |
| 5 | Rail-Only Backend with VLANs | build A (enterprise), one tenant | recorded under revision 2, [`ch05/`](ch05/) |
| 6 | Rail-Aware Model Placement | build A (enterprise), one tenant | recorded under revision 2, [`ch06/`](ch06/) |
| 7 | Inference Gateways with the Kubernetes Gateway API | build A (enterprise), one tenant | recorded under revision 2, [`ch07/`](ch07/) |
| 8 | Multi-Tenant Inference Gateways | build A (enterprise), many tenants | planned |
| 9 | Split-Horizon DNS | build A (enterprise), many tenants | planned |
| 10 | Tenant Isolation on the Firewall | build A (enterprise), many tenants | planned |
| 11 | Validating Tenant Isolation | build A (enterprise), many tenants | planned |
| 12 | EVPN VXLAN Frontend Fabric | build B (cloud provider), one tenant | planned |
| 13 | Single-Plane and Dual-Plane Rail Fabrics | build B (cloud provider), one tenant | planned |
| 14 | Backend Traffic for Distributed Inference | build B (cloud provider), one tenant | planned |
| 15 | Storage and Out-of-Band Networks | build B (cloud provider), one tenant | planned |
| 16 | Scaling the Inference Platform | build B (cloud provider), one tenant | planned |
| 17 | Customer Connectivity over MPLS L3VPN | build B (cloud provider), many tenants | planned |
| 18 | Multi-Tenancy in an EVPN VXLAN Fabric | build B (cloud provider), many tenants | planned |
| 19 | Failure Testing and Acceptance | operations | planned |
| 20 | Observability for Inference Fabrics | operations | planned |
| 21 | Infrastructure as Code for the Serving Fabric | operations | planned |
| 22 | Evaluating Emerging Technologies | none | no lab: the chapter applies an evaluation worksheet |

Built means the lab's directory, render and checks are in the repository and its tests pass. Recorded means the lab deployed green and its runs are committed in its `audits/` directory: the lab's `RESULTS.md` says what the runs prove, line by line, and `audits/INDEX.md` maps the chapter's exhibits to the files and lines they quote. Chapters 1 to 7 are built for build A revision 2 (below) and recorded under it; their revision 1 sets have left the repository, as each chapter's README says. Planned means the lab is designed and not in the repository yet. FRAMEWORK.md section 6.3 gives the order the labs are built in.

## Build A, revision 2

A technical review of the book's Parts I and II found lab conveniences in build A written up as design, and every build A lab now renders revision 2:

- **Services off the bastion.** The bastion is a jump host only. The platform's names live in the delegated zone `ai.tarnwick.example`, served by its own authoritative pair, dns-auth1 and dns-auth2, with two views (the enterprise view answers the corporate resolver, ent-dns, which staff keep using); the inside clients ask the recursive pair, dns-res1 and dns-res2, which are also their NTP servers, fed by a time reference on the uplink side, inet-ntp. The root CA's key stays on the lab host.
- **Segments.** The Gateways' VIPs sit in an ingress VLAN, 110, held by two ingress nodes, k8s-ingress1 and k8s-ingress2, which also run the API gateway, the router and the identity provider. Storage data moves to VLAN 120, Layer 2 only, TrueNAS's management address is dual-attached in VLAN 200, and the DNS servers sit in VLANs 130 and 131.
- **The MCLAG pair.** The keepalive runs on a dedicated link in VRF `VrfMclagKa`, with a backup session over the peer link in Vlan3966; every pair port runs MTU 9216; PVST, BPDU guard and storm control guard the host and rail ports.
- **The firewall.** Every allow rule names its App-ID and a profile group, egress is allowlisted (the registry and the time reference), intrazone traffic is denied by default, zone protection guards the uplink, and the operator reaches the internal Gateway through an IPsec tunnel from its site router, ops-gw, into a zone of its own: nothing is published on the public address.
- **The cluster.** Network policy denies by default, Secrets are encrypted at rest, WireGuard encrypts pod traffic between nodes, each Gateway has its own certificate and key, applications call with per-caller keys and people sign in through an identity provider, Dex, with tokens the API gateway checks.
- **Serving.** chat is LFM2.5-24B-A2B and staff Qwen3.8-27B. Each model's copies sit wholly inside one node each (chat a and staff a on k8s-gpu1, chat b and staff b on k8s-gpu2), so the loss of one node or one rail switch leaves a copy of each; chat c spans both nodes on rail 7, the stand-in for a model larger than one node, and is the copy whose RPC crosses a rail switch.

Nodes were renamed with the revision, so every name says what the node is: ctrl1 to ctrl3 are k8s-cp1 to k8s-cp3, gpu1 and gpu2 are k8s-gpu1 and k8s-gpu2, the registry node is inet-registry, and op-client and op-dns are ops-client and ops-dns. A GPU node's eight rail namespaces keep their names, gpu1 to gpu8, after the GPU and rail each serves. Every committed recording keeps the names, addresses and verdicts it was recorded with; each lab's `RESULTS.md` says, set by set, what revision 2 changed.

Two more labs are not chapters. They proved the framework before any chapter depended on it, and both are recorded:

| Lab | What it deploys |
|---|---|
| [`dev/m1`](dev/m1/) | milestone M1: build A's five switches, the PA-VM and two GPU node stand-ins, with no cluster, serving or storage. It ran on containerlab 0.81.0, the pin at the time, and has not run on 0.81.1. |
| [`dev/m2`](dev/m2/) | milestone M2: build A's one-tenant state with the Kubernetes cluster, the bastion, the in-lab registry, the uplink router, the operator's and the enterprise's clients and TrueNAS, which chapters 3 and 4 deploy too |

The model-serving recipe, `serving-layer/`, is built and unit-tested, with its two images. Chapter 6's lab, recorded, is the first to run it, through the lab's own `make serve` and `make load`, with the API gateway and the model router in front of it (`render/inference.py`); chapter 7's lab, recorded, runs the same, adds `make client` (one request as an OpenAI-compatible client sends it), and checks the Gateways, the names, the certificate, the keys and the timeouts in front of it.

## What is in the repository

Every lab is rendered by one framework from one specification. `FRAMEWORK.md` describes both.

| Path | What it holds |
|---|---|
| `spec/` | the specification every lab is rendered from: build A, Tarnwick (`tarnwick.example`), an enterprise, and build B, Corvane (`corvane.example`), a cloud provider; `spec/versions.yaml` holds every version pin |
| `common/` | the generator (`common/sfab/`), the deploy stages, the audit, trace, drill and break harness, and their tests |
| `images/` | the `sfab/*` container images the labs build: the VM node, the client, the bastion, the resolver, the VPN router, FRR, the registry and the API key tool (`images/README.md`; the serving image is `serving-layer/image/`); `images/VENDOR-IMAGES.md` says where to get the four vendor images and how to build each |
| `platform/dell-sonic-4.6.0/` | how to build the switch image every lab runs, from your own copy of SONiC 4.6.0, with the launcher changes the labs need |
| `platform/paloalto-pa-vm-12.1.2/` | how to build the firewall image every lab with a firewall runs, from your own copy of the PA-VM, with the launcher the labs need |
| `dev/m1`, `dev/m2` | the milestone labs |
| `chNN/` | one chapter's lab |
| `serving-layer/` | the model-serving recipe: `make serve` (llama-server and its RPC workers on one rail per copy, readiness over the rail, a key made in the cluster, Services and an HTTPRoute), `make load` (concurrent streaming clients, failed and cut requests counted), `make client` (one chat completion as an OpenAI-compatible client sends it, with the base URL and the key alone), and the serving image in `image/` |

A lab directory holds:

- `README.md`: what the lab builds, what it needs, how to run it, and the platform notes for its nodes;
- `RESULTS.md`: what the recorded runs prove, with the verdict lines that prove it;
- `chapter.yaml`: the lab's slice of its build (profile, state, nodes, features); `make render` writes `topo.clab.yml`, `bootstrap/` and `gen/` from it and the spec, and all three are committed;
- `topo.clab.yml`, the containerlab topology, and `bootstrap/`, each node's configuration, applied at first boot;
- `Makefile`: one line that includes `common/mk/chapter.mk`, whose targets every lab shares (`make up`, `make audit`, `make trace`, `make drills`, `make record`, `make break-<N><letter>`, `make heal-<N><letter>`, `make down`, `make wipe`; `make help` lists them);
- `audit.sh`, `trace.sh`, `drills.sh` and `breaks/`: the lab's checks, failure drills and break exercises;
- `audits/`: the recorded runs, one directory per result set, with a `TRACE.md` per trace and a `DRILLS.md` per drill run.

Lab names follow `sfab-chNN` (a variant adds a letter, as in `sfab-ch12m`; milestone M1 is `sfab-m1`). Below, `<lab>` stands for a lab's name, and each of its containers is `<lab>-<node>`, for example `sfab-ch04-fw`. Runtime state under `state/` and `clab-sfab-*/` is never committed.

## What the labs run

The stack is one platform per layer (FRAMEWORK.md section 0):

| Role | Platform | Image tag |
|---|---|---|
| Every switch: build A's MCLAG pair, rail switches and out-of-band switch; build B's EVPN-VXLAN frontend, routed rail Clos and out-of-band switches | SONiC 4.6.0, configured through KLISH | `vrnetlab/dell_sonic:4.6.0`, built from your own copy of Dell's image with `platform/dell-sonic-4.6.0/` |
| Edge firewall | Palo Alto PAN-OS | `vrnetlab/paloalto_pa-vm:12.1.2`, built from your own copy of the PA-VM with `platform/paloalto-pa-vm-12.1.2/` |
| Carrier WAN (build B) | FRR routers | `sfab/frr`, built from this repository |
| Storage, build A | TrueNAS | `vrnetlab/truenas_truenas:27.0.0-RC.1` |
| Storage, build B | NetApp ONTAP simulator | `vrnetlab/netapp_ontap:9.17.1` (candidate) |
| GPU, control and ingress nodes, bastion, DNS and time servers, VPN router, clients | Linux VMs and containers | built from this repository |
| Kubernetes | kubeadm, Cilium, Gateway API | v1.35.8, baked into `sfab/vm-node:6-k8s1.35.8`; the add-on pins are in `spec/versions.yaml` |

The vendor images are not in this repository and never will be. You obtain the SONiC 4.6.0, PAN-OS, TrueNAS and ONTAP images from their vendors yourself, under whatever licence each vendor grants you, and build each into a containerlab image with vrnetlab (https://github.com/srl-labs/vrnetlab). `images/VENDOR-IMAGES.md` gives, for each image, where to get it, what the vendor's public terms say, the file, the vrnetlab directory and commit, and the tag. Preflight checks every tag a lab names and never pulls a vrnetlab image. Every recorded lab ran with the SONiC tag above, every one but chapter 5's with the PA-VM tag, and milestone M2 and chapters 1 to 4 with the TrueNAS tag. The ONTAP tag is a candidate: no recorded lab has run it yet, and it becomes the pin in the commit that lands the first chapter that runs it.

Each switch is a 4 GiB, two-vCPU virtual machine, so a lab's switch count sets most of its memory: build A runs five switches, build B 24.

## Getting started

### The host

- An x86-64 Linux host with systemd and hardware virtualization: preflight wants `/dev/kvm` readable and writable.
- A root shell. The labs run as root: they load kernel modules, start transient systemd units and drive containerlab.
- Docker Engine 23 or later (the image builds need BuildKit).
- containerlab 0.82.0, the latest release and the only one preflight accepts (each lab's `RESULTS.md` names the release it was recorded on). Install that release's package and check it against the release's checksums:

  ```
  curl -fLO https://github.com/srl-labs/containerlab/releases/download/v0.82.0/containerlab_0.82.0_linux_amd64.deb
  curl -fLO https://github.com/srl-labs/containerlab/releases/download/v0.82.0/checksums.txt
  sha256sum --ignore-missing -c checksums.txt
  apt install ./containerlab_0.82.0_linux_amd64.deb
  ```

  The release also ships `containerlab_0.82.0_linux_amd64.rpm` and a `.tar.gz` for other distributions.
- Python 3.10 or later, and PyYAML (`python3-yaml` on Debian and Ubuntu, or `pip install pyyaml`). PyYAML is needed to render a lab, for `sfab check` and for `make test`. The stages read only the committed JSON, so without PyYAML preflight prints SKIP for its render check and the committed render still deploys.
- The tools preflight checks for: `sshpass`, `tcpdump`, `nsenter`, `ethtool`, `openssl`, `ssh`, `ssh-keygen`, `curl`, `flock`, `timeout`, `systemd-run` and `ip`, plus `make` and `git`. On Debian and Ubuntu:

  ```
  apt install make git python3 python3-yaml sshpass tcpdump util-linux ethtool openssl openssh-client curl coreutils iproute2
  ```
- The kernel tick at 10000, which preflight reads with `common/bin/tick.py` and which a stock kernel has. Preflight and every result set record the reading and never refuse on it; a set whose reading was not 10000 carries a `host-tick` stamp, and its lab's `RESULTS.md` says so. If it reads anything else, `python3 common/bin/tick.py --set` as root sets it. It changes nothing under `/etc`, so after a reboot the host's own boot sets the tick again.
- A kernel that lets a Linux bridge forward LACP, if you want the path the recordings took. The recorded runs' host kernel accepted `group_fwd_mask 0x4004` on the VM nodes' data bridges, which passes LACP and LLDP through them. A stock kernel refuses that mask, and on such a host `images/vm-node/vm-init.sh` joins every data NIC of a VM node to its tap with a tc mirred redirect instead, so the nodes' bonds run through the redirect. No recorded run exercised that path (`dev/m1/RESULTS.md`, settle item 10, and each lab's `RESULTS.md`, "What the recordings do not show"). Preflight does not check the mask; each VM node's container log names the mode of every data NIC. To test that path on any kernel, set `guest.nic_link: tc` in `spec/common.yaml` and run `make render` in the lab: the render then gives every VM node `SFAB_NIC_LINK=tc`, which makes `vm-init.sh` take the redirect, and preflight's render check still passes (every other lab needs `make render` too before it deploys).
- Memory, CPUs and disk for the lab, which preflight checks before every deploy. The smallest lab, `ch05`, wants 71 GiB of MemAvailable (its 55 GiB budget plus a 16 GiB floor), 26 vCPUs within twice the host's CPU count, and 65 GiB of disk: 25 GiB under the lab's `state/` and 40 GiB of container layers under Docker's data root. Milestone M1 wants 87.5 GiB of MemAvailable, 34 vCPUs and 81 GiB of disk (25 GiB and 56 GiB), chapters 3 and 4 about 142.5 GiB, 62 vCPUs and 151 GiB (95 GiB and 56 GiB), chapters 6 and 7, whose GPU nodes are sized for the models, 178.5 GiB and 178.75 GiB, 62 vCPUs and 111 GiB (55 GiB and 56 GiB), and chapters 1 and 2, build A whole with storage and serving, 195 GiB, 70 vCPUs and 151 GiB. Each lab's README states its own figures, and the images come on top.

### Clone, build, deploy

```
git clone https://github.com/aramidetosin/ai-serving-fabric-labs.git
cd ai-serving-fabric-labs
```

Then build in this order:

1. **The switch image.** Follow `platform/dell-sonic-4.6.0/README.md` to build `vrnetlab/dell_sonic:4.6.0` from your own copy of the image. Every lab needs it. Dell's support site serves the image to a Dell account, by the route Dell describes for a purchase's entitlement (`images/VENDOR-IMAGES.md`).
2. **The other vendor images** the lab names: `vrnetlab/paloalto_pa-vm:12.1.2` for every lab with a firewall, all but chapter 5's (`platform/paloalto-pa-vm-12.1.2/README.md`), and `vrnetlab/truenas_truenas:27.0.0-RC.1` for milestone M2 and chapters 1 to 4, each built with vrnetlab from your own copy (`images/VENDOR-IMAGES.md`). The PA-VM download needs a Palo Alto Networks support account and a registered VM-Series firewall; the TrueNAS ISO needs no account.
3. **The `sfab/*` images and the models.** `make -C images all` builds every image and seeds the in-lab registry. The serving labs, chapters 1, 2, 6 and 7, also need the two models in `images/models`, about 31 GB: `make -C images models-fetch` fetches them and checks each against its pin, and preflight refuses those labs without them. Both need the internet, and after them a lab needs none. `images/README.md` describes each image.
4. **A lab.** `cd ch04 && make up` runs preflight, deploys, brings every node to its rendered state, finishes the cluster and runs the audit. The lab's README lists its other targets; `make down` takes it down and keeps its disks, and `make wipe` removes them.

`make test` at the top of the repository runs the generator's unit tests, the serving recipe's and the key tool's, and the harness tests, in parallel processes; `make test-full` also runs the checks that read every recorded set, and `make test-quick` only the tests for the files a change touches (FRAMEWORK.md section 2.6). They need no lab, no root and no vendor image, but they need PyYAML (without it, every test that reads the spec is skipped) and read every lab's committed render, so run them in a full checkout.

## Getting the labs

Most of the repository is recorded evidence, plain text and packet captures under each lab's `audits/`. With milestones M1 and M2 and chapters 1 to 7 recorded, a full clone downloads about 43 MiB and checks out about 576 MiB in 34,912 files, 97% of it under `*/audits/`; the code, the spec and the documentation are 19 MiB in 1,486 files. Every recorded chapter adds to both, within the recording size policy (FRAMEWORK.md section 4.4).

A lab needs only `common`, `spec`, `images`, `platform` and its own directory. A partial clone with a sparse checkout fetches only those files:

```
git clone --filter=blob:none --sparse https://github.com/aramidetosin/ai-serving-fabric-labs.git
cd ai-serving-fabric-labs
git sparse-checkout set common spec images platform ch04
```

The files at the top of the repository always come along. `git sparse-checkout add ch03` adds another lab later, and `git sparse-checkout disable` checks out everything. With the same measurements:

| Directories checked out | Download | Checkout |
|---|---|---|
| `common spec images platform dev/m1` | about 2.7 MiB | about 25 MiB |
| `common spec images platform ch01` | about 3.9 MiB | about 46 MiB |
| `common spec images platform ch02` | about 3.9 MiB | about 47 MiB |
| `common spec images platform ch03` | about 19 MiB | about 183 MiB |
| `common spec images platform ch04` | about 18 MiB | about 146 MiB |
| `common spec images platform ch05` | about 3.3 MiB | about 24 MiB |
| `common spec images platform ch06` | about 3.8 MiB | about 51 MiB |
| `common spec images platform ch07` | about 3.6 MiB | about 42 MiB |

`make test` reads every lab's committed render (`dev/m1`, `dev/m2`, `ch01`, `ch02`, `ch03`, `ch04`, `ch05`, `ch06` and `ch07`), so run the tests in a full checkout.

## What `make up` changes on the host

A lab changes these. `make down` undoes the units and containerlab's writes; the module loads, the lock file and the lab's own files stay.

- **Kernel modules.** Preflight loads the modules the lab needs with `modprobe` (`bonding`, and `vrf` from milestone M2 on). The load is not persistent. The kernel may also load further modules on demand for the containers' links and for the traffic-control filters the switches' vrnetlab launcher wires each VM's NICs with.
- **Transient systemd units.** `make up` starts the lab's memory watchdog as the unit `<lab>-memwatch`, and `make up BG=1` runs the deploy as `<lab>-up`. The watchdog reads MemAvailable, and below the 16 GiB floor it stops one of this lab's VM guests per poll, the highest-numbered GPU guest first. It never stops a switch, the firewall, storage, a container, or anything outside the lab. `make down` stops it.
- **containerlab's own writes.** `containerlab deploy` creates the lab's containers, the Docker management network and bridge its `topo.clab.yml` names, the `clab-<lab>/` directory inside the lab directory, a block in `/etc/hosts`, and the file `/etc/ssh/ssh_config.d/clab-<lab>.conf`. containerlab's documentation says it also adds a rule to the `DOCKER-USER` chain for the management network and removes it with the network, and Docker installs its usual NAT masquerade and forwarding rules for the management subnet when the network is created and removes them with it. `containerlab destroy` removes the containers, the network and the two entries under `/etc`, and `make down` then removes `clab-<lab>/`.
- **The lab's own files.** `state/` in the lab directory holds the lab's generated credentials (`state/secrets.env`, mode 0600), its SSH key, the authorized keys of the nodes' login (`state/secrets/authorized_keys`), the VM disks, the logs and the stage markers. Git ignores it. `make down` keeps the disks, and `make wipe` removes them.
- **A lock file**, `/run/lock/sfab.lock`, which keeps two labs from deploying or destroying at once. Preflight also refuses while another `sfab-` lab runs.

`make down` runs `containerlab destroy` on the lab's own topology, never with `--cleanup` or `--all`, removes `clab-<lab>/` only when it is that exact directory inside the lab, and removes leftover containers by exact name or by the exact `<lab>-` prefix. The labs' own scripts never prune Docker, add or flush a firewall rule, write a host sysctl (the topology's sysctls apply inside each container's own namespace) or pipe a download into a shell. The labs need no internet at run time, and every containerlab call they make runs with `CLAB_VERSION_CHECK=disable`, so containerlab's own check for a newer release never runs.

Building the images adds them to Docker. `make -C images all` also keeps the Ubuntu cloud image and the baked node disk under `images/vm-node/base/`, the in-lab registry's seed data under `images/registry/data/`, and under `vendor/` the charts the seed caches and the pinned files the serving image and the key tool are built from (`VENDOR_DIR` moves them), all of which git ignores; with `SFAB_IMAGE_STORE` set, the disks and the registry data go under that directory instead, and `images/registry/data` is a link to it.

## Default logins

The switches and the PA-VM keep their containerlab kinds' published default logins: the topology passes them no credential. Each switch's FRR also keeps the vty `password` and `enable password` lines SONiC ships with, so the FRR running configuration an audit saves for each switch (`<switch>/14_frr_running.txt`) shows them; the lab sets neither. TrueNAS, ONTAP and the Kubernetes join token get generated values in the lab's `state/secrets.env`.

The VM guests (the GPU, control and ingress nodes), the bastion, the FRR routers and the operator site's VPN router (ops-gw) take one SSH login, `admin`, with a key and never a password. Its authorized keys are the lab's own key and every public key in `~/.ssh/*.pub` of the user who runs `make up` (and of the user who called `sudo`, when it runs under `sudo`), read again at every preflight into `state/secrets/authorized_keys`. containerlab puts each node's name in the lab host's `/etc/hosts`, so from the lab host `ssh admin@sfab-ch04-k8s-gpu1` logs in to `k8s-gpu1` of chapter 4's lab with your own key, and `admin` then has passwordless `sudo`. The containerlab VS Code extension's Connect (SSH) on a node runs exactly that: `ssh <user>@<node name>`, where the user is its `containerlab.node.sshUserMapping` setting for the node's kind, else its built-in map, else `admin`, and these nodes are of kind `linux`, which neither map names. The switches and the PA-VM answer the same user with their kinds' passwords. The clients, the resolvers and the registry run no SSH server: the extension's Attach shell, `docker exec` into the container, opens a shell in them. cloud-init makes a guest's login user once per disk, so a lab whose disks were made before the user was `admin` (it was `sfab` until 2026-10-27) needs `make wipe` before its next `make up`; preflight refuses it until then.

So a lab must never be reachable from an untrusted network: keep the host, and the lab's management network on it, away from any network you do not trust.

## Recorded runs

A recorded file keeps its text as recorded (FRAMEWORK.md section 4.3). Where a recording held a value the repository does not publish, such as the lab host's own DNS search domain or kernel release, or a measured throughput figure, the value is replaced in place by a `[redacted: <class>]` marker, so every line keeps its number. Milestone M1's saved namecheck outputs were cut to their summary line instead (`dev/m1/README.md`). Each result set with a change has a `REDACTIONS.md` listing each changed file, with the line and class of each marker, and the lab's README or `audits/INDEX.md` says which sets have one. A recorded XML or JSON file of 256 KiB or more, and a transcript over 10 MiB, is stored compressed as `NAME.gz` holding the same bytes, so `gzip -dc NAME.gz` reads it and its line numbers are those of the plain file (FRAMEWORK.md section 4.4). The largest plain recordings, transcripts of several MiB such as chapter 4's audit `commands.txt` files, are easiest to read by line from a clone: `sed -n 'A,Bp' FILE`, or `gzip -dc NAME.gz | sed -n 'A,Bp'` for a compressed one.

Each `RUN.json` of chapters 1 to 7 names the labs repository commit its run started from, and most add `dirty: true` for the uncommitted changes the lab host's copy held. Those commits belong to the pre-release history, which is not in this repository. The first public commit holds the code that ran with the later changes each lab's `audits/INDEX.md` names. M1's and M2's sets name no commit (FRAMEWORK.md section 4.4), and they ran earlier code than the first public commit holds. A later re-render can move the hashes in a lab's committed `gen/RENDER.json` without changing what the lab boots, so a `RUN.json` keeps the hashes of the render that ran.

The round-trip, boot and failover timings in the recordings are functional checks of the build, not performance benchmarks, and every throughput figure and inference timing in them is redacted.

## Reporting problems

Report a problem, or a lab that does not do what its README says, as a GitHub issue: https://github.com/aramidetosin/ai-serving-fabric-labs/issues. Name the lab and the command, and paste the failing lines of the stage output or of the result set's `verdict.txt`. Never paste anything from a lab's `state/` directory: it holds the lab's generated credentials and SSH key.

## Copyright

Copyright © 2026 Oluwatosin Aramide.

The Gateway API manifest (`common/sfab/render/upstream/gateway-api-v1.4.1-standard-install.yaml` and its rendered copies; Apache License 2.0, `LICENSE.gateway-api` beside it), the Multus manifest (`common/sfab/render/upstream/multus-v4.3.0-daemonset-thick.yml` and its rendered copies; Apache License 2.0, `LICENSE.multus` and `NOTICE.multus` beside it) and the vrnetlab-derived files in `platform/dell-sonic-4.6.0/` and `platform/paloalto-pa-vm-12.1.2/` (MIT License, `LICENSE.vrnetlab` in each) keep their own licences. The models and binaries pinned in `spec/versions.yaml` are not in this repository: the image builds and `make -C images models-fetch` fetch them at build time, each under its own licence.
