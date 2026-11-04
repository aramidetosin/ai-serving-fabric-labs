# Chapter 8: Multi-Tenant Inference Gateways

Lab `sfab-ch08`, the companion lab of the book's Chapter 8, "Multi-Tenant Inference Gateways". It runs build A's state many at step 8 (Tarnwick, the platform's names under `ai.tarnwick.example`), with serving on: chapter 7's deployment with a Gateway per audience. The internet audience gets its own Gateway, pool, announcement policy, lease, certificate, route set and caller; every caller carries its audience, and the key tool refuses a key for a model outside it.

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 8 |
| Slice | chapter 7's: `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, ops-dns, ent-client]` |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Containers | `sfab-ch08-<node>` (26); containerlab directory `clab-sfab-ch08/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 162.75 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 178.75 GiB in all. CPUs: 62 vCPUs within twice the host's CPU count. Disk: 55 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch08
make render          # topo.clab.yml, bootstrap/ and gen/
make up              # preflight, up, boot, finish, audit
make audit           # runs/sfab-ch08_audit_<UTC>/
make trace           # runs/sfab-ch08_trace_<UTC>/ (the keyed trace from k8s-cp2 through two Gateways)
make drills          # runs/sfab-ch08_drills_<UTC>/ (lease-holder-loss, PASSES=3)
make break-8a        # runs/sfab-ch08_break-8a_<UTC>/
make heal-8a         # runs/sfab-ch08_heal-8a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `runs/` in this directory, which git ignores. `spec/limitations.yaml` lists the known limits of the virtual platforms.
