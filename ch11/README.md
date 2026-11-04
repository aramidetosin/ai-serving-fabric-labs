# Chapter 11: Validating Tenant Isolation

Lab `sfab-ch11`, the companion lab of the book's Chapter 11, "Validating Tenant Isolation". It runs build A's state many at step 11 with the decision table and the matrix (`decisions: true`, as chapter 2's lab): chapter 10's deployment, the internet users' row and the internet Gateway's column, 60 cells, each with its isolation depth.

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 11 |
| Slice | chapter 10's, with `web-client` (the internet host row) and `truenas1` (the two storage columns) |
| Features | `{k8s: true, serving: true, storage_setup: true}` |
| Containers | `sfab-ch11-<node>` (32); containerlab directory `clab-sfab-ch11/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 180 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 196 GiB in all. CPUs: 70 vCPUs within twice the host's CPU count. Disk: 95 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch11
make render
make up
make audit
make label           # audits/sfab-ch11_label_<UTC>/
make matrix          # audits/sfab-ch11_matrix_<UTC>/
make trace           # audits/sfab-ch11_trace_<UTC>/ (the capture ladder)
make drills          # audits/sfab-ch11_drills_<UTC>/ (isolation-under-load and leaked-key, PASSES=3)
make break-11a       # Exercise 4
make heal-11a
make down
```

`matrix.sh` and `label.sh` are chapter 2's runners on this render: a cell's own caller (`key_caller`) carries that caller's key, and `matrix.md` prints each cell's depth and its layers.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
