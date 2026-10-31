# SONiC 4.6.0 under containerlab

Every switch in the book's labs runs SONiC 4.6.0, the image Dell distributes (`SONiC-OS-4.6.0-Enterprise_Base`), built into a containerlab image with vrnetlab's `dell/dell_sonic` launcher (https://github.com/srl-labs/vrnetlab) and the changes below.

**The image is not in this repository and never will be.** Every reader obtains their own copy from Dell, under whatever licence Dell grants them. `images/VENDOR-IMAGES.md` says where Dell distributes it.

## What the image is

- The GNS3 bundle `Enterprise_SONiC_OS_4.6.0_gns3.zip` contains `Enterprise_SONiC_OS_4.6.0.img`, a QCOW2 v3 disk with a 64 GiB virtual size despite its extension. MD5 of the `.img` used for the book: `ae5c2439d1ae76e51abdaa94b5245436`.
- It emulates a Dell S5248F (HwSKU `DellEMC-S5248f-P-25G-DPB`, ASIC `vs`) with 56 front-panel ports. Container `ethN` is native `Ethernet(N-1)` for N 1 to 48, then `eth49` to `eth56` are `Ethernet48, 52, ... 76`; the standard name is `Eth1/N`. Only the NICs a topology connects exist inside the VM.
- Each switch is a 4096 MB, 2 vCPU guest: about 3.75 GiB resident per switch on the host. Boot to a configured, SSH-reachable switch takes about 3 minutes.

## Building it

The build uses vrnetlab at commit `3a34fa63d73843c871f248e2df2ffa5c038183ce` (2026-09-13), pinned in `spec/versions.yaml` as `images.dell_sonic.vrnetlab`. The pin covers every file the build takes from vrnetlab: the `dell/dell_sonic` directory, `common/` (the build copies `common/` into `docker/`, and the Dockerfile copies its Python files, `vrnetlab.py`, `healthcheck.py` and `test_vrnetlab.py`, into the image; the patched launcher relies on `vrnetlab.py` for the management gateway and passthrough) and the top-level makefiles. The vrnetlab copy the book's switch image was built from matches that commit, blob for blob, in every file the build uses except `dell/dell_sonic/docker/launch.py`, which was the patched launcher described at the end of this section. vrnetlab is under the MIT License: `LICENSE.vrnetlab` holds its copyright and permission notice, which applies to the two launcher copies here and to the lines `patch_launch.py` keeps from vrnetlab's launcher.

In the commands below, `LABS` holds the path of your checkout of this repository.

1. Clone vrnetlab at the pin and put the image in place:

   ```
   git clone https://github.com/srl-labs/vrnetlab
   cd vrnetlab
   git checkout 3a34fa63d73843c871f248e2df2ffa5c038183ce
   cp /path/to/Enterprise_SONiC_OS_4.6.0.img dell/dell_sonic/dell-sonic-4.6.0.qcow2
   cd dell/dell_sonic
   ```

2. Start from `launch.py.upstream-plus-numnics`, not from the launcher in the checkout. The checkout's `docker/launch.py` is vrnetlab's file as it is at the pin (`git rev-parse HEAD:dell/dell_sonic/docker/launch.py` prints `055afa9f5a2cd5336395abc2774ad549b3c3ad6e`), and it fixes the data NIC count at 10. `launch.py.upstream-plus-numnics` is that file with three additions: a header comment naming its source, a comment on the factory-default login, and, in place of the fixed count, a line that reads it from `NUM_NICS`, with a comment above it. Copy it over the checkout's launcher, patch it, and compare the result with `launch.py.patched`:

   ```
   cp "$LABS/platform/dell-sonic-4.6.0/launch.py.upstream-plus-numnics" docker/launch.py
   python3 "$LABS/platform/dell-sonic-4.6.0/patch_launch.py" docker/launch.py
   cmp docker/launch.py "$LABS/platform/dell-sonic-4.6.0/launch.py.patched"
   ```

   `cmp` prints nothing when the two files are the same. Run on the checkout's own launcher, `patch_launch.py` writes the `NUM_NICS` line itself, and the result differs from `launch.py.patched` only in comment lines.

3. `make docker-image` builds `vrnetlab/dell_sonic:4.6.0`. The Dockerfile at the pin builds from `ghcr.io/srl-labs/vrnetlab-base:0.3.0`, which Docker pulls by that tag.

The image the book's recordings ran on was built from `launch.py.patched` as it was before its header comment, the comment on the factory-default login and the `SONiC 4.6.0` wording of one docstring were added (sha256 `4bb48f97f2787f18b7b2660aa53fb6308cf1adb987da11875ccdbe36683fa042`). The two files differ in nothing else.

## What the launcher changes, and why

Each change answers a failure this image showed, or a need of the labs, under the upstream launcher.

| Change | Why |
|---|---|
| `NUM_NICS` sets the data NIC count per node | the upstream launcher fixes 10; a rail leaf needs 12 |
| disable the `ntpsec-ntpdate` if-up hook at first login | it deadlocks first boot: `ifup` waits for the hook, the hook waits for ntpsec, ntpsec waits for networking; `eth0` stays down, `hostcfgd` never starts, sshd listens on IPv6 only |
| mask `fstrim.timer` and clear a hung `smartctl` | at first boot the timer's `log_ssd_health` runs `docker exec pmon smartctl`, which never returns on the virtual disk; 9 of 18 first boots in the image test before the first lab, whose records are not in this repository, took 10:57 to 20:11 instead of about 3 minutes |
| `ztp disable -y` | ZTP otherwise keeps rewriting port-group speeds and floods the console |
| wait for `systemctl is-system-running` = running or degraded | the launcher's login prompt arrives minutes before SONiC is ready |
| GRO, rx-gro-hw and LRO off on every data NIC, at every boot (`sfab-gro-off.service`) | GRO-merged TCP frames over 16384 bytes make the vs SAI abort `syncd` (`addVlanTagPvid: pvid packet size ... exceeds the ETH_FRAME_BUFFER_SIZE`) |
| Management 0 and the hostname set through KLISH, with the real address under `CLAB_MGMT_PASSTHROUGH=true` | the stages reach a pair member on its own management address (the first labs also ran the MCLAG keepalive in the management VRF; build A revision 2 moves it to a dedicated link); the default slirp address is 10.0.0.15 on every switch |
| `terminal length 0` in every scripted `sonic-cli` session | piped sessions stop at `--more--` otherwise |
| `/config/startup-config.cfg` with KLISH lines is typed into `sonic-cli` and saved | the book's configurations are KLISH; the upstream path accepts only a full `config_db.json` |
| IPv6 off on the container's own data veths | otherwise they answer as hosts on the switch's VLANs and appear in MAC and neighbor tables |

Proven together on a fresh two-switch topology before the first lab was built, in the same test: boot in 2:52 and 2:58 with no stall, `fstrim.timer` masked, GRO off and staying off across a reboot, an 8-stream TCP run through both switches that completed with no `syncd` restart, 9000-byte frames forwarded, Management 0 on the real address under passthrough, no IPv6 on the container veths. Every lab's audit has checked GRO on every switch since (FRAMEWORK.md section 4.4, the shared checks).

## What every topology must also do

- Linux hosts: `ethtool -K eth1 tx off` (with containerlab's default TX checksum offload, TCP never connects through the fabric).
- Keep data-plane addresses out of 10.0.0.0/24 (Management 0's slirp network), or put Management 0 in the mgmt VRF (`ip vrf mgmt`).
- Drills place flows by source or destination address (the virtual data plane hashes ECMP on IP addresses only) and fail ports with KLISH `shutdown` (a port shut inside the VM drops no carrier at the far end; BFD or LACP is the detector).

## Known on this image

- `l2mcd` (Layer 2 multicast) segfaulted once during a first boot; not used by the book.
- The SONiC reboot script prints "Reboot failed! Trying systemctl --force reboot" and then reboots.

## The console helper

`console.py` is a debugging aid, for a switch whose SSH does not answer; no lab script runs it. It connects to 127.0.0.1:5000, the switch VM's serial console as vrnetlab serves it inside the switch's container, so it runs inside that container. It sends an empty line, logs in with the user and password given when the console answers with a login prompt, sends each command given after them and prints what the console returns, then sends `exit`. The login travels on its command line (`console.py <user> <password> <command>...`), so anyone who can list the host's processes sees it while it runs. The switches keep their kind's default login (Default logins in the repository's `README.md`).
