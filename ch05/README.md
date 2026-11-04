# Chapter 5: Rail-Only Backend with VLANs

Lab `sfab-ch05`, the companion lab of the book's Chapter 5, "Rail-Only Backend with VLANs". It runs build A's backend from the one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`): two standalone SONiC 4.6.0 rail switches whose rails are plain VLANs, and the two GPU nodes whose cross-rail traffic is relayed inside the node. It audits the absences the design is made of and the rail ports' Layer 2 hygiene, traces same-rail and cross-rail traffic hop by hop with the DF probe matrix, darkens one rail switch in a drill, and ships break-5a.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[rail, k8s-gpu1, k8s-gpu2]`; the closure adds the switches the nodes' other links land on: the pair (`fe-sw1`, `fe-sw2`, their bonds) and `oob-sw` |
| Features | `{k8s: false, serving: false, storage_setup: false}` |
| Containers | `sfab-ch05-<node>` (7); containerlab directory `clab-sfab-ch05/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and `sfab/vm-node:6-k8s1.35.8` (`make -C images vm-node`). This lab has no firewall, storage or cluster.

Memory: a budget of 55 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 71 GiB in all. CPUs: 26 vCPUs within twice the host's CPU count. Disk: 25 GiB of growth under `state/` and 40 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch05
make render          # topo.clab.yml, bootstrap/ and gen/ (gen/trace.json, gen/drills.json, gen/breaks.json among them)
make up              # preflight, up, boot, finish, audit
make audit           # runs/sfab-ch05_audit_<UTC>/
make trace           # runs/sfab-ch05_trace_<UTC>/ with trace.md
make drills          # runs/sfab-ch05_drills_<UTC>/ with drills.md, three passes
make verify          # after the drills: audit, trace, then the results check on both sets
make rpf             # runs/sfab-ch05_rpf_<UTC>/: rp_filter's all and per-interface values on the cross-rail flow, three cases, then put back
make break-5a        # runs/sfab-ch05_break-5a_<UTC>/
make heal-5a         # runs/sfab-ch05_heal-5a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make drills PASSES=1` runs the drill once. `make up BG=1` runs the deploy as the transient unit `sfab-ch05-up`.

Once the lab is up, `ssh admin@sfab-ch05-<node>` from the lab host logs in to `k8s-gpu1` and `k8s-gpu2` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches keep their kinds' default logins.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `runs/` in this directory, which git ignores. `spec/limitations.yaml` lists the known limits of the virtual platforms.
