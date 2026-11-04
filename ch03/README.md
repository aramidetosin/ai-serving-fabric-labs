# Chapter 3: Layer 2 Frontend with MCLAG

Lab `sfab-ch03`, the companion lab of the book's Chapter 3, "Layer 2 Frontend with MCLAG". It runs build A's one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`), and adds what the chapter teaches about the pair: the domain's roles and its ICCP session over the pair's own keepalive link, the backup keepalive over the peer link, every bond's legs under the system MAC, the pair's Layer 2 hygiene (MTU, BPDU guard, storm control), one SYN traced at four points, the pair's failure drills in three passes, break-3a and break-3b.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, ent-client, truenas1]`; its closure adds the ingress nodes, the platform's DNS and time servers (dns-auth1, dns-auth2, dns-res1, dns-res2), the corporate resolver ent-dns, the operator's site router ops-gw and the time reference inet-ntp |
| Features | `{k8s: true, serving: false, storage_setup: true}` |
| Containers | `sfab-ch03-<node>` (26); containerlab directory `clab-sfab-ch03/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2`, `vrnetlab/truenas_truenas:27.0.0-RC.1` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`).

Memory: a budget of 126.5 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 142.5 GiB in all. CPUs: 62 vCPUs within twice the host's CPU count. Disk: 95 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch03
make render          # topo.clab.yml, bootstrap/ and gen/ (gen/drills.json and gen/breaks.json among them)
make up              # preflight, up, boot, finish, audit (book Example 3-1)
make audit           # audits/sfab-ch03_audit_<UTC>/ (Example 3-2)
make trace           # audits/sfab-ch03_trace_<UTC>/ with trace.md (Example 3-5)
make dbs             # audits/sfab-ch03_dbs_<UTC>/: k8s-gpu1's member Ethernet6 on fe-sw1 through SONiC's databases, read-only (Examples 3-6 to 3-9, Table 3-3)
make drills          # audits/sfab-ch03_drills_<UTC>/ with drills.md, three passes (Examples 3-10 to 3-12)
make record          # after the drills: audit, trace, then the gate on both sets (Example 3-13)
make break-3a        # audits/sfab-ch03_break-3a_<UTC>/ (Exercise 4)
make heal-3a         # audits/sfab-ch03_heal-3a_<UTC>/, then the chapter audit
make break-3b        # audits/sfab-ch03_break-3b_<UTC>/ (Exercise 5)
make heal-3b         # audits/sfab-ch03_heal-3b_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make drills DRILLS="fw-leg server-member" PASSES=1` runs a subset. `make up BG=1` runs the deploy as the transient unit `sfab-ch03-up`.

Once the lab is up, `ssh admin@sfab-ch03-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
