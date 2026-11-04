# Chapter 10: Tenant Isolation on the Firewall

Lab `sfab-ch10`, the companion lab of the book's Chapter 10, "Tenant Isolation on the Firewall". It runs build A's state many at step 10: chapter 9's deployment with the internet users' translation and rule. Three populations share one firewall and one routing table, and the zone each arrives in keeps them apart: internet users translated, the staff routed, the operator tunneled.

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 10 |
| Slice | chapter 9's |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Containers | `sfab-ch10-<node>` (30); containerlab directory `clab-sfab-ch10/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 163.75 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 179.75 GiB in all. CPUs: 62 vCPUs within twice the host's CPU count. Disk: 55 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch10
make render
make up
make audit
make trace           # audits/sfab-ch10_trace_<UTC>/ (the zone-keyed NAT trace)
make hold            # audits/sfab-ch10_hold_<UTC>/ (the sessions under held connections)
make break-10a       # Exercise 5
make heal-10a
make down
```

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
