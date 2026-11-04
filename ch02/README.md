# Chapter 2: Multi-Tenant Access Design

Lab `sfab-ch02`, the companion lab of the book's Chapter 2, "Multi-Tenant Access Design". It runs chapter 1's build A, Tarnwick (the platform's names under `ai.tarnwick.example`), whole: every switch, the firewall with chapter 4's configuration, the cluster with its ingress nodes, storage and serving, the bastion, the platform's DNS and time servers, the registry, the uplink router, the operator's site with its IPsec router, and every population's client and resolver. The chapter writes build A's decision table, one decision per layer with the evidence its refusal leaves, and the matrix of populations against endpoints that every later audit checks. So the lab renders both from the spec (`gen/decisions.yaml` and `gen/matrix.yaml`), labels every object of every row with its decision, names the live object behind each row (`label.sh`), tries every cell of the matrix and asserts its mode (`matrix.sh`), walks chapter 1's request with each hop tagged with its row (`trace.sh`), and ships break-2a.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, web-client, ops-dns, ent-client, truenas1]`: build A whole, chapter 1's |
| Features | `{k8s: true, serving: true, storage_setup: true}` |
| Decisions | `true`: the decision table, the matrix and the labels (`render/decisions.py`) |
| Containers | `sfab-ch02-<node>` (28); containerlab directory `clab-sfab-ch02/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 179 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 195 GiB in all. CPUs: 70 vCPUs within twice the host's CPU count. Disk: 95 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch02
make render          # topo.clab.yml, bootstrap/ and gen/ (decisions.yaml, matrix.yaml, trace.json, breaks.json)
make up              # preflight, up, boot, finish, audit (Example 2-1)
make audit           # audits/sfab-ch02_audit_<UTC>/ (Examples 2-2 and 2-12)
make label           # audits/sfab-ch02_label_<UTC>/ with labels.md (Examples 2-3 and 2-5 to 2-8)
make matrix          # audits/sfab-ch02_matrix_<UTC>/ with matrix.md (Examples 2-9 and 2-10)
make trace           # audits/sfab-ch02_trace_<UTC>/ with trace.md (Example 2-11)
make record          # audit, trace, label, matrix, then the gate on the four sets
make break-2a        # audits/sfab-ch02_break-2a_<UTC>/ (Exercise 5)
make heal-2a         # audits/sfab-ch02_heal-2a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

Example 2-4's `show ip route` on the five switches is in every full audit set (each switch's `show ip route` file) and in the label set's `forwarding/`. `make serve`, `make client` and `make load` run the serving recipe with this lab's `bootstrap/k8s/serving.env`, as in chapter 1's lab. The lab has no drills.

Once the lab is up, `ssh admin@sfab-ch02-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"). The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the containerlab VS Code extension's Attach shell opens a shell in each.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
