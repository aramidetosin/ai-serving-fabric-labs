# Vendor images

The labs run four images this repository cannot ship: the switch, the firewall and the two storage systems. You download each from its vendor, under the terms that vendor grants you, and build it into a containerlab image with vrnetlab (https://github.com/srl-labs/vrnetlab, MIT License) on the lab host. `spec/versions.yaml` names the tag each lab uses and, under each image's `vrnetlab` key, the vrnetlab commit its build uses, with the blobs of the launcher and the common files the image runs. Preflight refuses a lab whose image is missing and never pulls a vrnetlab image.

| Image | Tag (`spec/versions.yaml`) | Vendor file | vrnetlab directory and commit | Labs |
|---|---|---|---|---|
| SONiC 4.6.0 | `vrnetlab/dell_sonic:4.6.0` (`images.dell_sonic`) | `Enterprise_SONiC_OS_4.6.0.img`, inside `Enterprise_SONiC_OS_4.6.0_gns3.zip` | `dell/dell_sonic` at `3a34fa63d738`, with the changes in `platform/dell-sonic-4.6.0/` | every lab |
| PAN-OS 12.1.2 | `vrnetlab/paloalto_pa-vm:12.1.2` (`images.pa_vm`) | `PA-VM-KVM-12.1.2.qcow2` | `paloalto/pan` at `fd759f10587d`, with the launcher in `platform/paloalto-pa-vm-12.1.2/` | every lab but `ch05` (`dev/m1`, `dev/m2`, `ch01`, `ch02`, `ch03`, `ch04`, `ch06`, `ch07`, `ch08`, `ch09`, `ch10`, `ch11`) |
| TrueNAS 27.0.0-RC.1 | `vrnetlab/truenas_truenas:27.0.0-RC.1` (`images.truenas`) | `TrueNAS-27.0.0-RC.1.iso` | `truenas/truenas` at `c89aa5e8cdb3`, with `common/` from `da55d7cf48c1` | `dev/m2`, `ch01`, `ch02`, `ch03`, `ch04`, `ch11` |
| ONTAP 9.17.1 simulator | `vrnetlab/netapp_ontap:9.17.1` (`images.ontap`, a candidate) | `vsim-netapp-DOT9.17.1-cm_nodar.ova` | `netapp/ontap` at `c89aa5e8cdb3`, with `common/` from `da55d7cf48c1` | build B's storage; no recorded lab has run it yet |

Build each image in its own vrnetlab clone: the builds use different commits and change tracked files. Every Dockerfile at these commits builds from `ghcr.io/srl-labs/vrnetlab-base:0.3.0`, which Docker pulls by that tag. A lab's preflight prints each image's ID (`PASS image <tag> present (<id>)`) and every result set records the IDs in its `RUN.json`; yours differ from the recorded ones, since every build makes its own image.

The vendors' pages below were read on 2026-10-21. Each vendor's own terms are the ones that apply to you; this page only says where they are and what their public parts say.

## SONiC 4.6.0 (Dell)

- **Where:** Dell's support site; a Dell account is needed. Dell's knowledge base article 000263481, "PowerSwitch: Enterprise SONiC: Getting Started and Basics Guide" (https://www.dell.com/support/kbdoc/en-us/000263481/dell-networking-enterprise-sonic-getting-started-and-basics-guide), describes the route for a purchase: the order's notification email carries an entitlement ID and a link to My Account, where the software appears under Software Licenses and Subscriptions, and the article asks you to download the version that matches your switch and your licence agreement.
- **Terms:** the licence comes with the download, behind the Dell sign-in, and this repository restates none of its terms. The image is never committed, shared or published here.
- **File:** the GNS3 bundle `Enterprise_SONiC_OS_4.6.0_gns3.zip`, which holds `Enterprise_SONiC_OS_4.6.0.img`, a QCOW2 disk despite its extension. MD5 of the `.img` used for the book: `ae5c2439d1ae76e51abdaa94b5245436`.
- **Build:** `platform/dell-sonic-4.6.0/README.md`, Building it: vrnetlab's `dell/dell_sonic` at commit `3a34fa63d73843c871f248e2df2ffa5c038183ce`, the disk renamed `dell-sonic-4.6.0.qcow2`, the patched launcher, then `make docker-image`.
- **Tag:** `vrnetlab/dell_sonic:4.6.0`.

## PAN-OS 12.1.2 (Palo Alto Networks)

- **Where:** the Palo Alto Networks Customer Support Portal (https://support.paloaltonetworks.com). You need a support account and a registered VM-Series firewall: Palo Alto Networks' guide "Install the VM-Series Firewall on KVM" (https://docs.paloaltonetworks.com/vm-series/deployment/private-cloud/set-up-the-vm-series-firewall-on-kvm/install-the-vm-series-firewall-on-kvm) asks you to purchase the VM-Series model and register its authorization code on the Customer Support web site first. The portal lists the KVM base images among its software updates.
- **Terms:** Palo Alto Networks' End User License Agreement, the August 2026 version at https://www.paloaltonetworks.com/legal/eula. It governs Palo Alto Networks products however they were acquired, and binds from the first download, installation, registration or evaluation. Section 12 limits an evaluation to 30 days unless Palo Alto Networks extends it, and the use restrictions of section 2 forbid publishing any benchmark, performance or comparison test you run on the products. The labs install no licence or authorization code on the firewall.
- **File:** `PA-VM-KVM-12.1.2.qcow2`. The copy used for the book is 5,890,310,144 bytes, sha256 `32cd28e3164da338cd48e919d841ccf8fb4da7a0235c2219bb8217e493a47edb`.
- **Build:** `platform/paloalto-pa-vm-12.1.2/README.md`, Building it: vrnetlab's `paloalto/pan` at commit `fd759f10587de4dd131815c8b7066ce3f957c749`, with `launch.py.patched` in place of vrnetlab's launcher, then `make docker-image`. The labs depend on the patched launcher: it loads the firewall's rendered XML configuration and turns jumbo-frame mode on, which vrnetlab's own launcher does not.
- **Tag:** `vrnetlab/paloalto_pa-vm:12.1.2`, from the version in the file name.

## TrueNAS Community Edition 27.0.0-RC.1

- **Where:** https://www.truenas.com/download/, TrueNAS Community Edition; no account is needed. On 2026-10-21 the page offers 27.0.0-RC.1, a release candidate, beside the 25.10.7 release, and shows a newsletter sign-up before the download. The same ISO sits on TrueNAS's download server, https://download.truenas.com/TrueNAS-27-RC/27.0.0-RC.1/, beside its `.sha256` file and `.gpg` signature. That server also still holds earlier lines' release candidates (for example `TrueNAS-ElectricEel-RC/24.10-RC.1`).
- **Terms:** the download page calls Community Edition free and open and names no licence. The TrueNAS EULA in TrueNAS's documentation for release 25.10 (https://www.truenas.com/docs/scale/25.10/gettingstarted/useragreements/scaleeula/) says the software is made available as open source software, each component under its own licence terms, and that it may not be commercially distributed or sold without an addendum licence agreement. TrueNAS's source repositories on GitHub carry the GPL-3.0 (`truenas/scale-build`, `truenas/webui`) and the LGPL-3.0 (`truenas/middleware`).
- **File:** `TrueNAS-27.0.0-RC.1.iso`, 2,683,439,104 bytes, sha256 `515a0252e72f1a6c86d603fa4d1661333029fe9a4804d0a7a28d24fe4f63498e` as the download server publishes it.
- **Build:** vrnetlab's `truenas/truenas`, unchanged:

  ```
  git clone https://github.com/srl-labs/vrnetlab vrnetlab-truenas
  cd vrnetlab-truenas
  git checkout c89aa5e8cdb3805fbc94b04f120d68847e2d377b
  git checkout da55d7cf48c1674422100a3bec2612f375dc1f4f -- common/
  cd truenas/truenas
  cp /path/to/TrueNAS-27.0.0-RC.1.iso .
  make
  ```

  `make` builds a base image with an empty boot disk, runs it once privileged to install TrueNAS from the ISO, and commits the installed disk into the image; the build needs KVM, and vrnetlab's README for the directory says it takes about 4 minutes and makes an image of about 3.8 GB. The second `checkout` takes vrnetlab's `common/` as it was at `da55d7cf48c1`, the parent of `ddaac4582052`, which moved `common/test_vrnetlab.py` out of `common/`, and before `d142be03fe3b` changed `common/vrnetlab.py` the same day (a console read that returns when the console is silent, and QEMU started with `exec`). With it, the image holds exactly the files the TrueNAS image the recordings ran on holds: `launch.py` and `tnrpc.py` from `truenas/truenas/docker/`, and `vrnetlab.py`, `healthcheck.py` and `test_vrnetlab.py` from `common/`, the last a test file the launcher never imports (the blobs under `images.truenas.vrnetlab`). That image carries no `vrnetlab-version` label, so its files were compared one by one. Skip the second `checkout` and the image takes the newer `vrnetlab.py`, which no recorded lab has run, and no `test_vrnetlab.py`; either way the image's `vrnetlab-version` label names commit `c89aa5e8`.
- **Tag:** `vrnetlab/truenas_truenas:27.0.0-RC.1`, from the version in the file name.

## ONTAP 9.17.1 simulator (NetApp)

- **Where:** the NetApp Support Site (https://mysupport.netapp.com), Simulate ONTAP. A customer or partner login is needed, as vrnetlab's README for `netapp/ontap` says.
- **Terms:** the simulator's terms are behind that login, so this repository restates none. The labs never commit ONTAP licence keys: they read them from `~/.config/sfab/ontap-licenses.txt`, which you supply (FRAMEWORK.md section 2.2).
- **File:** `vsim-netapp-DOT9.17.1-cm_nodar.ova`, the file vrnetlab's README for the directory names as tested.
- **Build:** vrnetlab's `netapp/ontap`, unchanged, at the same commits as TrueNAS:

  ```
  git clone https://github.com/srl-labs/vrnetlab vrnetlab-ontap
  cd vrnetlab-ontap
  git checkout c89aa5e8cdb3805fbc94b04f120d68847e2d377b
  git checkout da55d7cf48c1674422100a3bec2612f375dc1f4f -- common/
  cd netapp/ontap
  cp /path/to/vsim-netapp-DOT9.17.1-cm_nodar.ova .
  make
  ```

  The build unpacks the OVA and converts its four VMDK disks to QCOW2 in a first stage built from `public.ecr.aws/docker/library/debian:trixie-slim`.
- **Tag:** `vrnetlab/netapp_ontap:9.17.1`, from the version in the file name. It is a candidate: it becomes the pin in the commit that lands the first chapter that runs it.
