# Chapter 9: Split-Horizon DNS

Lab `sfab-ch09`, the companion lab of the book's Chapter 9, "Split-Horizon DNS". It runs build A's state many at step 9: chapter 8's deployment with the internet side. Everyone types `llm.ai.tarnwick.example`: the staff get the users' VIP, the nodes the internal VIP, internet users the firewall's published address, and the operator's tools name the internal VIP through its tunnel.

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 9 |
| Slice | chapter 8's, with `isp-rtr`, `inet-client`, `inet-dns-auth` and `inet-dns-res` |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Containers | `sfab-ch09-<node>` (30); containerlab directory `clab-sfab-ch09/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 163.75 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 179.75 GiB in all. CPUs: 62 vCPUs within twice the host's CPU count. Disk: 55 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch09
make render
make up
make audit
make trace           # audits/sfab-ch09_trace_<UTC>/ (the split-horizon trace)
make break-9a        # Exercise 4
make heal-9a
make down
```

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
