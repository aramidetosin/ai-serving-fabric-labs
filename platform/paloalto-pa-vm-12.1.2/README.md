# PAN-OS 12.1.2 under containerlab

The edge firewall of every lab that has one (all but chapter 5's) is a Palo Alto Networks PA-VM running PAN-OS 12.1.2, built into a containerlab image with vrnetlab's `paloalto/pan` launcher (https://github.com/srl-labs/vrnetlab) and the changes below.

**The image is not in this repository and never will be.** Every reader downloads their own copy from Palo Alto Networks, under the terms Palo Alto Networks grants them. `images/VENDOR-IMAGES.md` says where to get it and what the terms say.

## What the image is

- `PA-VM-KVM-12.1.2.qcow2`, the PA-VM base image for KVM. The copy used for the book is 5,890,310,144 bytes, sha256 `32cd28e3164da338cd48e919d841ccf8fb4da7a0235c2219bb8217e493a47edb`, MD5 `c3fb210992f51ba78decf2d5aad17a91`.
- The labs run it as containerlab's `paloalto_panos` kind with 16 GiB of memory and 8 vCPUs: the topology sets `QEMU_MEMORY`, `QEMU_SMP` and `QEMU_CPU: host`, which vrnetlab's `vrnetlab.py` reads in place of the launcher's own defaults (6144 MB and 2 vCPUs). They install no licence and no authorization code: the recordings show `serial: unknown` and `vm-license: none` (for example `ch04/audits/sfab-ch04_audit_20261030T075617Z/fw/04_system_info.txt`, lines 18 and 23).

## Building it

The build uses vrnetlab at commit `fd759f10587de4dd131815c8b7066ce3f957c749` (2026-08-19), pinned in `spec/versions.yaml` as `images.pa_vm.vrnetlab`. The image the book's recordings ran on was built from that commit: its `vrnetlab-version` label names it, and its `vrnetlab.py`, `healthcheck.py` and `test_vrnetlab.py` are that commit's files, blob for blob. The pin covers every file the build takes from vrnetlab: the `paloalto/pan` directory, `common/` (the build copies its files into the image, and the launcher runs on `vrnetlab.py`) and the top-level makefiles. vrnetlab is under the MIT License: `LICENSE.vrnetlab` holds its copyright and permission notice, which applies to `launch.py.patched`.

In the commands below, `LABS` holds the path of your checkout of this repository.

1. Clone vrnetlab at the pin and put the image in place:

   ```
   git clone https://github.com/srl-labs/vrnetlab vrnetlab-pan
   cd vrnetlab-pan
   git checkout fd759f10587de4dd131815c8b7066ce3f957c749
   cd paloalto/pan
   cp /path/to/PA-VM-KVM-12.1.2.qcow2 .
   ```

2. Replace the launcher. The checkout's `docker/launch.py` is vrnetlab's file as it is at the pin (`git rev-parse HEAD:paloalto/pan/docker/launch.py` prints `817ca9f79ba29cd71275796cde006c67671c7e02`). `launch.py.patched` is that file with the changes below and a header comment naming its source:

   ```
   cp "$LABS/platform/paloalto-pa-vm-12.1.2/launch.py.patched" docker/launch.py
   git diff --stat
   ```

   `git diff` then shows every change against vrnetlab's file. Later vrnetlab commits change the launcher too (commit `4baf0a6fc0b0`, 2026-09-22, reads the VM's UUID from the environment); `launch.py.patched` replaces the file whole, so build at the pin.

3. `make docker-image` builds `vrnetlab/paloalto_pa-vm:12.1.2`: the makefile takes the version from the file name. The Dockerfile at the pin builds from `ghcr.io/srl-labs/vrnetlab-base:0.3.0`, which Docker pulls by that tag.

`docker image inspect --format '{{index .Config.Labels "vrnetlab-version"}}' vrnetlab/paloalto_pa-vm:12.1.2` prints the commit the image was built from.

The image the book's recordings ran on was built from `launch.py.patched` as it was before its header comment and the comment above its command-line defaults were added, and before six comments, one docstring and the descriptions of its two commits were reworded. Its code is the same as this file's apart from those two descriptions.

## What the launcher changes, and why

The reasons come from the launcher's own comments and from how the labs use it.

| Change | Why |
|---|---|
| The login prompt matches `admin@` followed by any text up to `>`, not only `admin@PA-VM>` | PAN-OS 12's prompt can carry another hostname or the HA state |
| Two empty lines go to the console 3 s and 5 s after the new password is confirmed | PAN-OS 12 prints no prompt after "Password changed" until a key arrives |
| An empty line goes to the console after 20 reads with no match | the console library drops unmatched output at each read timeout, so a prompt split across two reads would never match |
| The wait for PAN-OS's first auto-commit sends `show jobs processed` before each read and reads for 15 s | the console read blocks, so it needs output to return |
| A `startup-config` that holds an XML `<config>` tree is loaded through the XML API: import, a partial merge of `deviceconfig`, `network`, `vsys` and `shared`, a full validate, then a commit polled to its end, logged as `XML startup config commit finished: result=<result>` | containerlab delivers the kind's `startup-config` as `/config/startup-config.cfg`, and vrnetlab's launcher types that file as set-format lines; the labs render the firewall's configuration as XML (`bootstrap/fw/startup-config.xml`), and the boot stage looks for that log line (FRAMEWORK.md section 3.3) |
| When that tree sets `<jumbo-frame>`, the launcher first turns jumbo-frame mode on (`set system setting jumbo-frame on`) with an MTU of 9216, commits, waits for that commit and for PAN-OS's auto-commit, restarts PAN-OS through the API (a QEMU `system_reset` if it does not go down) and waits for the API and the next auto-commit | PAN-OS validates an interface MTU above 1500 only in jumbo-frame mode, which takes effect after a restart |
| An SSH public key at `/bootstrap-keys/authorized_keys`, when the file exists, goes to the `admin` user in the same commit | none of the labs binds that file, so this step never runs in them |

Milestone M1 recorded the launcher turning jumbo-frame mode on, restarting and committing the XML, so `common/fw/fw-startup.py` did not run (`dev/m1/RESULTS.md`, settle item 9). When the launcher's commit does not take, the boot stage runs `fw-startup.py`, which repeats the same steps with the wait for the auto-commit closed (FRAMEWORK.md section 3.3, step 5).

## Known on this image

- The firewall keeps the `paloalto_panos` kind's published default login: containerlab passes the launcher `--username` and `--password` on its command line, and the launcher reads no login from its environment (`dev/m1/RESULTS.md`, problem 4).
- The VM's UUID is the launcher's fixed `aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`, which `show system info` prints in capitals as `vm-uuid`.
