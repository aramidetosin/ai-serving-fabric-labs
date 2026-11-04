# The AI Serving Fabric: the labs

The companion lab repository for the book *The AI Serving Fabric: A Platform Engineer's Guide to Multi-Tenant Inference Networks*. It holds what builds each chapter's lab: the generator, the specification, the containerlab topologies, every node's bootstrap configuration, the image builds, the Kubernetes manifests and the scripts that deploy, operate and check each lab. Everything a lab deploys is rendered from `spec/` by the generator in `common/sfab/`; nothing is typed by hand.

| Chapter | Title | Lab |
|---|---|---|
| 1 | Introducing the AI Serving Fabric | [`ch01/`](ch01/) |
| 2 | Multi-Tenant Access Design | [`ch02/`](ch02/) |
| 3 | Layer 2 Frontend with MCLAG | [`ch03/`](ch03/) |
| 4 | Firewall-Hosted Gateways | [`ch04/`](ch04/) |
| 5 | Rail-Only Backend with VLANs | [`ch05/`](ch05/) |
| 6 | Rail-Aware Model Placement | [`ch06/`](ch06/) |
| 7 | Inference Gateways with the Kubernetes Gateway API | [`ch07/`](ch07/) |
| 8 | Multi-Tenant Inference Gateways | [`ch08/`](ch08/) |
| 9 | Split-Horizon DNS | [`ch09/`](ch09/) |
| 10 | Tenant Isolation on the Firewall | [`ch10/`](ch10/) |
| 11 | Validating Tenant Isolation | [`ch11/`](ch11/) |

## What's here

| Path | What it is |
|---|---|
| `spec/` | The specification every lab is rendered from: addresses, VLANs, nodes, firewall, cluster, models, and every version pin in `spec/versions.yaml` |
| `common/sfab/` | The generator (`common/bin/sfab render`, `check`, `lint`, `show`) |
| `common/stages/`, `common/lib.sh`, `common/mk/chapter.mk` | The deploy stages and the make targets every lab shares |
| `common/audit/`, `common/trace/`, `common/drill/`, `common/break/`, `common/matrix/` | The audit, trace, failure drill, break exercise and matrix harness |
| `images/` | The Dockerfiles and init scripts of the lab's own `sfab/*` images (`images/README.md`), and where to get the vendor images (`images/VENDOR-IMAGES.md`) |
| `platform/` | How to build the switch and firewall images from your own licensed copies, with the launcher changes the labs need |
| `serving-layer/` | The model-serving recipe: `make serve`, `make load` and `make client` |
| `chNN/` | One chapter's lab: `chapter.yaml` (its slice of the specification), `topo.clab.yml`, `bootstrap/` and `gen/` (rendered), a one-line `Makefile`, `audit.sh`, `trace.sh`, `drills.sh`, `breaks/` and a `README.md` |

## Requirements

- An x86-64 Linux host with systemd and KVM (`/dev/kvm` readable and writable), and a root shell: the labs load kernel modules, start transient systemd units and drive containerlab.
- Docker Engine 23 or later (the image builds need BuildKit).
- containerlab 0.82.0, the release preflight accepts:

  ```
  curl -fLO https://github.com/srl-labs/containerlab/releases/download/v0.82.0/containerlab_0.82.0_linux_amd64.deb
  curl -fLO https://github.com/srl-labs/containerlab/releases/download/v0.82.0/checksums.txt
  sha256sum --ignore-missing -c checksums.txt
  apt install ./containerlab_0.82.0_linux_amd64.deb
  ```

- Python 3.10 or later and PyYAML. PyYAML is needed to render a lab and for `sfab check`; the stages read only the committed JSON.
- The tools preflight checks for. On Debian and Ubuntu:

  ```
  apt install make git python3 python3-yaml sshpass tcpdump util-linux ethtool openssl openssh-client curl coreutils iproute2
  ```

- The kernel tick at 10000, which a stock kernel has. Preflight reads it with `common/bin/tick.py` and never refuses on it; a result set taken at another value is stamped. `python3 common/bin/tick.py --set` as root sets it until the next reboot.
- A kernel that lets a Linux bridge forward LACP (`group_fwd_mask 0x4004`), if you want the path the book's runs took. A stock kernel refuses that mask, and `images/vm-node/vm-init.sh` then joins each data NIC of a VM node to its tap with a tc mirred redirect instead. Each VM node's container log names the mode of every data NIC. To force the redirect on any kernel, set `guest.nic_link: tc` in `spec/common.yaml` and run `make render` in the lab.
- Memory, CPUs and disk for the lab, which preflight checks before every deploy. Memory is MemAvailable, the lab's budget plus a 16 GiB floor; vCPUs must fit within twice the host's CPU count. The images come on top of the disk figures.

| Lab | Memory | vCPUs | Disk |
|---|---|---|---|
| `ch01` | 195 GiB | 70 | 95 GiB under `state/`, 56 GiB of container layers |
| `ch02` | 195 GiB | 70 | 95 GiB under `state/`, 56 GiB of container layers |
| `ch03` | 142.5 GiB | 62 | 95 GiB under `state/`, 56 GiB of container layers |
| `ch04` | 142.75 GiB | 62 | 95 GiB under `state/`, 56 GiB of container layers |
| `ch05` | 71 GiB | 26 | 25 GiB under `state/`, 40 GiB of container layers |
| `ch06` | 178.5 GiB | 62 | 55 GiB under `state/`, 56 GiB of container layers |
| `ch07` | 178.75 GiB | 62 | 55 GiB under `state/`, 56 GiB of container layers |
| `ch08` | 178.75 GiB | 62 | 55 GiB under `state/`, 56 GiB of container layers |
| `ch09` | 179.75 GiB | 62 | 55 GiB under `state/`, 56 GiB of container layers |
| `ch10` | 179.75 GiB | 62 | 55 GiB under `state/`, 56 GiB of container layers |
| `ch11` | 196 GiB | 70 | 95 GiB under `state/`, 56 GiB of container layers |

## Images

The vendor images are not in this repository. Obtain each from its vendor under the licence it grants you, and build it into a containerlab image with vrnetlab (https://github.com/srl-labs/vrnetlab).

| Image | Used by | How to build it |
|---|---|---|
| `vrnetlab/dell_sonic:4.6.0` | Every lab | From your own licensed copy of SONiC 4.6.0: `platform/dell-sonic-4.6.0/README.md` |
| `vrnetlab/paloalto_pa-vm:12.1.2` | Every lab but `ch05` | From your own licensed copy of the PA-VM: `platform/paloalto-pa-vm-12.1.2/README.md` |
| `vrnetlab/truenas_truenas:27.0.0-RC.1` | `ch01` to `ch04`, `ch11` | From the TrueNAS ISO: `images/VENDOR-IMAGES.md` |
| `sfab/*` | Every lab | `make -C images all` builds every image and seeds the in-lab registry; `images/README.md` describes each |
| The two models in `images/models`, about 31 GB | The serving labs | `make -C images models-fetch` fetches them and checks each against its pin; each stays under its own licence |

`images/VENDOR-IMAGES.md` gives, for each vendor image, where to get it, the file, the vrnetlab directory and commit, and the tag. The image builds and the model fetch need the internet; after them a lab needs none.

## Running a chapter

```
git clone https://github.com/aramidetosin/ai-serving-fabric-labs.git
cd ai-serving-fabric-labs/ch04
make up        # preflight, deploy, boot, finish, audit
make audit     # the lab's audit
make trace     # the lab's path trace
make drills    # the lab's failure drills, three passes
make record    # audit, trace, label and matrix (each the lab has), then the closing checks
make break-4a  # the chapter's break exercise; make heal-4a undoes it
make down      # keeps the disks; make wipe removes them
```

`make help` in a lab lists every target. `make up BG=1` runs the deploy as the transient unit `<lab>-up`; follow it with `journalctl -fu <lab>-up`. A lab's containers are named `<lab>-<node>`, for example `sfab-ch04-fw`, and only one `sfab-` lab can run at a time.

Every check prints to the terminal and saves its files in a timestamped directory under the lab's `audits/`, which git ignores: for example `ch04/audits/sfab-ch04_trace_<UTC>/` with `trace.md`, `verdict.txt`, `RESULT.txt`, `RUN.json` and the saved outputs. Redaction replaces each secret in those files with a keyed mark before the run ends. `make check` at the top of the repository confirms every lab's committed files match a fresh render, with no lab, no root and no vendor image.

## What `make up` changes on the host

`make down` undoes the units and containerlab's writes; the module loads, the lock file and the lab's own files stay.

- **Kernel modules.** Preflight loads the modules the lab needs with `modprobe` (`bonding`, `vrf`); the load is not persistent.
- **Transient systemd units.** The lab's memory watchdog runs as `<lab>-memwatch`. Below the 16 GiB floor it stops one of this lab's VM guests per poll, the highest-numbered GPU guest first, and never anything outside the lab.
- **containerlab's own writes.** The lab's containers, its Docker management network, a `clab-<lab>/` directory, a block in `/etc/hosts`, the file `/etc/ssh/ssh_config.d/clab-<lab>.conf`, and the rules containerlab and Docker add for the management network. `containerlab destroy` removes them.
- **The lab's own files.** `state/` in the lab directory holds the generated credentials (`state/secrets.env`, mode 0600), the SSH key, the VM disks, the logs and the stage markers. Git ignores it.
- **A lock file**, `/run/lock/sfab.lock`, which keeps two labs from deploying or destroying at once.

The scripts never prune Docker, add or flush a firewall rule outside containerlab's own, or pipe a download into a shell.

## Default logins

No password, key or token is stored in this repository. A lab generates what it needs into `state/` at first use.

The switches and the PA-VM keep their containerlab kinds' published default logins. The VM guests, the bastion, the FRR routers and the operator site's VPN router take one SSH login, `admin`, with a key and never a password: the lab's own key and every public key in `~/.ssh/*.pub` of the user who runs `make up`. So `ssh admin@sfab-ch04-k8s-gpu1` from the lab host logs in to that node. The clients, the resolvers and the registry run no SSH server; use `docker exec`.

Keep the host and the lab's management network away from any network you do not trust.

## Conventions

- `spec/` is the single source: change an address, a port or a size there, run `make render` in the lab and redeploy. Never edit a rendered file by hand.
- A stage that fails can run again.
- Runtime state (node disks, `state/`, `clab-*` directories, `audits/`) is never committed.
- The timing figures a lab prints are functional checks of the build, not benchmarks. Measured throughput figures and model server timings are replaced in the saved files by a `[redacted: <class>]` marker.

## Reporting problems

Report a lab that does not do what its README says as a GitHub issue: https://github.com/aramidetosin/ai-serving-fabric-labs/issues. Name the lab and the command, and paste the failing lines. Never paste anything from a lab's `state/` directory.

## Copyright

Copyright (c) 2026 Oluwatosin Aramide.

The Gateway API manifest (`common/sfab/render/upstream/gateway-api-v1.4.1-standard-install.yaml` and its rendered copies; Apache License 2.0, `LICENSE.gateway-api` beside it), the Multus manifest (`common/sfab/render/upstream/multus-v4.3.0-daemonset-thick.yml` and its rendered copies; Apache License 2.0, `LICENSE.multus` and `NOTICE.multus` beside it) and the vrnetlab-derived files in `platform/dell-sonic-4.6.0/` and `platform/paloalto-pa-vm-12.1.2/` (MIT License, `LICENSE.vrnetlab` in each) keep their own licences. The models and binaries pinned in `spec/versions.yaml` are not in this repository.
