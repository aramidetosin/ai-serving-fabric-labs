# Chapter 7: Inference Gateways with the Kubernetes Gateway API

Lab `sfab-ch07`, the companion lab of the book's Chapter 7, "Inference Gateways with the Kubernetes Gateway API". It runs build A's one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`), with serving on, as chapter 6's lab does, and checks the chain from the firewall to the model: the Gateways, the names, the certificates, the callers' keys and sign-in, and the timeouts. The lab audits the Gateway layer, the callers' keys and the identity provider, traces one keyed request through both in-cluster hops with every key replaced by its mark, sends an admin hostname to the users' Gateway, runs three drills (one key from mint to revoke under a probe that must lose nothing, the consumer restriction's default status against the rendered 401, and a silent backend past Envoy's stream idle timeout, then the corrected chain), and ships break-7a.

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, ops-dns, ent-client]`: chapter 6's, with the operator's resolver; its closure adds the ingress nodes, the DNS and time servers, ent-dns and ops-gw |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Containers | `sfab-ch07-<node>` (26); containerlab directory `clab-sfab-ch07/` |

## Requirements

Images: `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` built with vrnetlab from your own licensed copies (`images/VENDOR-IMAGES.md`), and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`). The two models in `images/models` (`make -C images models-fetch`).

Memory: a budget of 162.75 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 178.75 GiB in all. CPUs: 62 vCPUs within twice the host's CPU count. Disk: 55 GiB of growth under `state/` and 56 GiB of container layers. containerlab 0.82.0, and no other `sfab-` lab running.

## Running it

```
cd ch07
make render          # topo.clab.yml, bootstrap/ and gen/ (the Gateways, the inference files, trace.json, drills.json, breaks.json)
make up              # preflight, up, boot, finish (the cluster, the Gateway layer, the serving recipe, the API gateway, router and identity provider), audit (Example 7-1)
make audit           # audits/sfab-ch07_audit_<UTC>/ (Examples 7-2 to 7-6)
make serve           # the serving recipe again with bootstrap/k8s/serving.env (Example 7-7)
make client          # one chat completion from the operator's client as an OpenAI-compatible client sends it, base URL and key only (Example 7-7)
make load USERS=10 SECONDS=60   # concurrent streaming clients from the operator's client, through the IPsec tunnel (Example 7-7)
make trace           # audits/sfab-ch07_trace_<UTC>/ with trace.md (Examples 7-8 and 7-9)
make drills          # audits/sfab-ch07_drills_<UTC>/ with drills.md (Examples 7-10 and 7-11)
make record          # after the drills: audit, trace, then the gate on both sets (Example 7-12)
make break-7a        # audits/sfab-ch07_break-7a_<UTC>/ (Exercise 4)
make heal-7a         # audits/sfab-ch07_heal-7a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make drills DRILLS=key-lifecycle PASSES=1` runs one drill once. `make up BG=1` runs the deploy as the transient unit `sfab-ch07-up`. `make client` and `make load` run on the operator's client, whose resolver, `ops-dns`, publishes no platform name, so both pin `serve.ai.tarnwick.example` to the internal Gateway's VIP (`SERVING_LOAD_RESOLVE` in this lab's `serving.env`) and reach it through the tunnel. `client.py` and `load.py` speak the OpenAI chat completions API: an OpenAI-compatible client changes only its base URL (`https://serve.ai.tarnwick.example/chat/v1` for the recipe's route, `https://llm.ai.tarnwick.example/models/<route id>/v1` through the API gateway) and its key.

Once the lab is up, `ssh admin@sfab-ch07-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## What the checks do

`audit.sh`, `trace.sh`, the other scripts in this directory and `breaks/` each open with a description of what they check and change. Each run prints to the terminal and saves its files under `audits/` in this directory, which git ignores. `spec/known.yaml` lists the known limits of the virtual platforms.
