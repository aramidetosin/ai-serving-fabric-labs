# Chapter 1: Introducing the AI Serving Fabric

Lab `sfab-ch01`, the companion lab of the book's Chapter 1, "Introducing the AI Serving Fabric". It runs build A's one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`), whole: every switch, the firewall with chapter 4's configuration, the cluster with its ingress nodes, storage and serving, the bastion, the platform's DNS and time servers, the registry, the uplink router, the operator's site with its IPsec router, and every population's client and resolver. The chapter follows one chat completion from the enterprise client to a model and names the device behind each decision, so the lab audits build A as chapters 3 to 7 audit their parts, walks one request inward with every device's table (`trace.sh`), sends three requests that must be refused and records where each died, and ships break-1a.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, web-client, ops-dns, ent-client, truenas1]`: build A whole, chapter 7's with TrueNAS and the web client; its closure adds the ingress nodes, the DNS and time servers, ent-dns and ops-gw |
| Features | `{k8s: true, serving: true, storage_setup: true}` |
| Containers | `sfab-ch01-<node>` (28); containerlab directory `clab-sfab-ch01/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 179 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 195 GiB in all. CPUs: 70 vCPUs within twice the host's CPU count. Disk: 95 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch01
make render          # topo.clab.yml, bootstrap/ and gen/ (trace.json, breaks.json)
make up              # preflight, up, boot, finish (the cluster, storage, the Gateway layer, the serving recipe, the API gateway, router and identity provider), audit (Example 1-1)
make audit           # audits/sfab-ch01_audit_<UTC>/ (Example 1-2)
make trace           # audits/sfab-ch01_trace_<UTC>/ with trace.md (Examples 1-3 to 1-9)
make record          # audit, trace, then the gate on both sets (Example 1-10)
make break-1a        # audits/sfab-ch01_break-1a_<UTC>/ (Exercise 4)
make heal-1a         # audits/sfab-ch01_heal-1a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make serve`, `make client` and `make load` run the serving recipe with this lab's `bootstrap/k8s/serving.env`, as in chapter 7's lab. The lab has no drills: chapters 3 to 7 drill the parts.

Once the lab is up, `ssh admin@sfab-ch01-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
