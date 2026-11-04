# Chapter 4: Firewall-Hosted Gateways

Lab `sfab-ch04`, the companion lab of the book's Chapter 4, "Firewall-Hosted Gateways". It runs build A's one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`), as chapter 3's lab deploys it, and reads the firewall from the inside, in order: route, then translation, then rule. It adds the firewall's edge to the audit, a trace that reads one request's session and log line from each side of the firewall and an image pull through the source NAT, two drills (the LAND discard and the firewall's own NTP sent out of the uplink), and break-4a.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, web-client, ent-client, truenas1]`: chapter 3's with the web client, the internet host the egress check connects to; its closure adds the ingress nodes, the DNS and time servers, ent-dns and ops-gw |
| Features | `{k8s: true, serving: false, storage_setup: true}` |
| Containers | `sfab-ch04-<node>` (27); containerlab directory `clab-sfab-ch04/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`).

Memory: a budget of 126.75 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 142.75 GiB in all. CPUs: 62 vCPUs within twice the host's CPU count. Disk: 95 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch04
make render          # topo.clab.yml, bootstrap/ and gen/ (gen/trace.json, gen/drills.json, gen/breaks.json among them)
make up              # preflight, up, boot, finish, audit
make audit           # runs/sfab-ch04_audit_<UTC>/
make trace           # runs/sfab-ch04_trace_<UTC>/ with trace.md
make drills          # runs/sfab-ch04_drills_<UTC>/ with drills.md, three passes
make verify          # after the drills: audit, trace, then the results check on both sets
make break-4a        # runs/sfab-ch04_break-4a_<UTC>/
make heal-4a         # runs/sfab-ch04_heal-4a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make drills DRILLS=land PASSES=1` runs one drill once. `make up BG=1` runs the deploy as the transient unit `sfab-ch04-up`.

Once the lab is up, `ssh admin@sfab-ch04-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"; on ops-gw, `sudo swanctl --list-sas` shows the tunnel), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `runs/` in this directory, which git ignores. `spec/limitations.yaml` lists the known limits of the virtual platforms.
