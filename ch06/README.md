# Chapter 6: Rail-Aware Model Placement

Lab `sfab-ch06`, the companion lab of the book's Chapter 6, "Rail-Aware Model Placement". It runs build A's one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`), with serving on: two models, chat in three copies and staff in two, each copy's llama.cpp server and RPC workers on one rail, placed by a table the render writes and every check reads back. A request reaches a model through a Gateway, the API gateway, the model router and the model's Service. The lab audits the pods against the table, traces one request from the users' Gateway to the spanning copy's server and its workers over the table's rail, runs three drills (chapter 5's dark rail switch and the spanning copy's worker port, each under a steady Gateway probe with the Services' endpoints read every second, and one worker's rail moved in the table), and ships break-6a and break-6b.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, ent-client]`: chapter 4's, without TrueNAS and the web client; its closure adds the ingress nodes, the DNS and time servers, ent-dns and ops-gw |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Containers | `sfab-ch06-<node>` (25); containerlab directory `clab-sfab-ch06/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 162.5 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 178.5 GiB in all. CPUs: 62 vCPUs within twice the host's CPU count. Disk: 55 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch06
make render          # topo.clab.yml, bootstrap/ and gen/ (serving.env, the inference files, trace.json, drills.json, breaks.json)
make up              # preflight, up, boot, finish (the cluster, the serving recipe, the API gateway and router), audit (Example 6-1)
make audit           # audits/sfab-ch06_audit_<UTC>/ (Example 6-2)
make trace           # audits/sfab-ch06_trace_<UTC>/ with trace.md (Example 6-5)
make drills          # audits/sfab-ch06_drills_<UTC>/ with drills.md, three passes (Examples 6-7, 6-8, 6-10 and 6-11)
make record          # after the drills: audit, trace, then the gate on both sets (Example 6-9)
make break-6a        # audits/sfab-ch06_break-6a_<UTC>/ (Exercise 4)
make heal-6a         # audits/sfab-ch06_heal-6a_<UTC>/, then the chapter audit
make attach          # audits/sfab-ch06_attach_<UTC>/: chat-c-server-0's two networks, read-only
make break-6b        # audits/sfab-ch06_break-6b_<UTC>/: chat-c-server-0's rail attachment with a route to the pod network
make heal-6b         # audits/sfab-ch06_heal-6b_<UTC>/, then the chapter audit
make serve           # the serving recipe again with bootstrap/k8s/serving.env (it acts only on what changed)
make load USERS=10 SECONDS=60   # concurrent streaming clients from the operator's client, through the IPsec tunnel to the internal Gateway
make down            # keeps state/ disks; make wipe removes them
```

`make drills DRILLS=worker-port PASSES=1` runs one drill once. `make up BG=1` runs the deploy as the transient unit `sfab-ch06-up`.

Once the lab is up, `ssh admin@sfab-ch06-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
