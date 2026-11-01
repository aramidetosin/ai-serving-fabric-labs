# Chapter 8: Multi-Tenant Inference Gateways

Lab `sfab-ch08`, the companion lab of the book's Chapter 8, "Multi-Tenant Inference Gateways". It runs build A's state many at step 8 (Tarnwick, the platform's names under `ai.tarnwick.example`), with serving on: chapter 7's deployment with a Gateway per audience. The internet audience gets its own Gateway, pool, announcement policy, lease, certificate, route set and caller; every caller carries its audience, and the key tool refuses a key for a model outside it.

Status: recorded under build A revision 2 on 2026-10-31 on the first lab host, one deployment from wiped disks that ran `make up`, `make audit`, `make trace`, three passes of the lease drill, break-8a and its heal, and `make record`, every set green (`RESULTS.md`; `audits/INDEX.md` maps the chapter's exhibits to their files and lines); tested against the stand-ins too (`common/sfab/tests/test_part3_render.py`, `test_part3_tools_render.py`, `common/tests/test_part3_labs.py`).

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 8 |
| Slice | chapter 7's: `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, ops-dns, ent-client]` |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Prints | none |
| Extends | `ch07` (metadata only: `make up` deploys the whole step from wiped disks) |
| Containers | `sfab-ch08-<node>` (26); containerlab directory `clab-sfab-ch08/` |

## What the spec renders for this chapter

Everything chapter 7's lab renders (`ch07/README.md`), and from step 8:

| Gateway | Audience | VIP and pool | Announcement policy | Certificate | Routes |
|---|---|---|---|---|---|
| `gw-internal` | internal | 10.20.11.200, .200 to .209 | `gateways-internal` | `gw-internal-tls` | the bare `/models` prefix, the admin names, `/echo`, the identity provider |
| `gw-users` | enterprise | 10.20.11.210, .210 to .214 | `gateways-enterprise` | `gw-users-tls` | one rule a model (chat, staff), `/echo`, the identity provider |
| `gw-inet` | internet | 10.20.11.220, .220 to .224 | `gateways-internet` | `gw-inet-tls` | chat's path alone, `/echo` on `llm` |

- **One announcement policy per audience** (`bootstrap/k8s/31-l2-announcement.yaml`, the spec's `k8s.l2_announce.policies: per-audience`): each selects its own Gateway's Service by the audience label `tarnwick.example/audience`, on the ingress nodes' `bond0.110`, in place of chapter 7's single `gateways` policy, so a fault in one touches one audience.
- **Tuned lease timers** (`20-cilium-values.yaml` `l2announcements`): Cilium's documented example, duration 3 s, renew deadline 1 s, retry 200 ms, from the spec's `k8s.l2_announce.lease` (`tuned: true`). That block is the one switch: `tuned: false` renders Cilium's defaults again (15 s, 5 s, 2 s), as chapters 1 to 7 were recorded with. `gen/k8s.json` `l2_lease` gives the renew rate the three Gateway Services ask of the agents' client, 3 x (1 / 1 s) = 3 queries a second against the rendered limit of 50, and the failover window Cilium's page gives, 2 s to 4 s.
- **The internet Gateway** (`50-gateways.yaml`, `30-lb-pools.yaml`, `40-pki.yaml`): class `cilium`, its listener admitting routes only from the namespaces labelled `routes.tarnwick.example/gw-inet` (`echo` and `inference`, never `identity` or `serving`), its own ECDSA P-256 key from the lab's platform intermediate.
- **Callers by audience** (`60-inference-base.yaml` to `62-inference.yaml`): batch, helpdesk and staff carry the enterprise audience; `inetapp`, an application with its own keys, owner, expiry and limit, carries the internet audience and may call chat. The caller id is `inetapp`, not the design's `inet-app`: a caller id names a consumer group and its key fields (`<caller>.<id>`), which the render and the key tool hold to lower case letters and digits. No caller's credential is bound to a Gateway: the Gateway says from where, the caller says who.
- **The key tool's refusal** (`61-inference-keys.yaml`, `sfab/keys:4`): the key Job's mint names each caller's audience and the models that audience may call (`--for`, `--audience`, `--audience-models`), and a mint for a model outside the audience is refused with exit status 3 before the Secret is read. `common/trace/keyprobe.py job --caller inetapp --model staff --mint` makes the Job that shows it.

## Requirements

Chapter 7's lab's (`ch07/README.md`), and `sfab/keys:4` built on the lab host (`make -C images keys`, from `images/keys` and the pinned PyYAML wheel already in the vendor directory) and pushed into the in-lab registry with the rest (`make -C images registry-seed`; preflight checks that the registry holds the key image `serving.env` names). Memory: the inventory's budget is 162.75 GiB for 26 nodes, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 178.75 GiB in all; on a shared lab host the author's rule keeps about 40 GiB beyond that free before `make up`. containerlab 0.82.0, the host tick at 10000 (read and recorded, never refused on), and no other `sfab-` lab running.

## The audit, the trace and the drill

- `audit.sh` runs chapter 7's audit, then the `audiences` group (`common/audit/lib-tenancy.sh`, judged by `common/audit/tenancy.py` against `gen/tenancy.json`): each Gateway's routes its audience's row, the admin and identity hostnames only where the render puts them, the namespaces labelled for `gw-inet` (`echo` and `inference` alone), every caller a model route admits within its audience, a key per Gateway (three public key fingerprints, none equal), each lease on an ingress node at the tuned 3 s, `cilium-config`'s tuned timers, a policy per audience, and the refused mint: a key Job asked for `inetapp`'s key for staff, outside the internet audience, fails with the key tool's refusal, and the key Secret holds the same fields and fingerprints after it.
- `trace.sh` (chapter 7's keyed trace from `k8s-cp2`, `chapter.yaml` `trace.serving` with `pin: true`): staff's path through the users' Gateway with helpdesk's key, the keys at the three in-cluster hops; the same key and path through `gw-inet` (`also`), its 404 with no request at any API gateway pod; an admin hostname on `gw-inet` (`refuse.gateway`), its 404. The node's own ports are captured to show no SYN to a VIP leaves it.
- `drills.sh` (`lease-holder-loss`, `common/drill/lib-p3drill.sh`): the ingress node holding the most leases cut from the pair by KLISH `shutdown` on its two pair ports, its leases taken by the other; the gap measured by echo probes and TCP connects through each Gateway, the model probe reported apart, the firewall's ARP table before, during and after.

## Running it

```
cd ch08
make render          # topo.clab.yml, bootstrap/ and gen/
make up              # preflight, up, boot, finish, audit
make audit           # audits/sfab-ch08_audit_<UTC>/
make trace           # audits/sfab-ch08_trace_<UTC>/ (the keyed trace from k8s-cp2 through two Gateways)
make drills          # audits/sfab-ch08_drills_<UTC>/ (lease-holder-loss, PASSES=3)
make break-8a        # audits/sfab-ch08_break-8a_<UTC>/ (Exercise 5)
make heal-8a         # audits/sfab-ch08_heal-8a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

## break-8a

`breaks/8a.yaml`: the internet audience's policy, `gateways-internet`, patched to name `^bond0\.111$`, an interface no ingress node has (`kubectl patch --type merge`, `common/break/lib-k8sbreak.sh`). The Gateway stays programmed, and no agent answers ARP for 10.20.11.220; the other audiences keep theirs. The break records the policy, both leases, the Gateway and its Service whole and the firewall's ARP table. While its policy matches no device the lease stays held and renewed and the Gateway stays programmed, and the firewall keeps the entry it learned before the break (`RESULTS.md`). No population reaches 10.20.11.220 through the firewall in this chapter, so the break checks the symptom where it shows: the VIP asked for by ARP from the ingress node that does not hold its lease, on `bond0.110`, gets no answer, the users' VIP keeps its holder's answer, and the staff's requests through `gw-users` stay answered (`vip_arp`, `probe_share`). `make heal-8a` patches the rendered interface back and checks the internet VIP answered by its lease holder's bond MAC again.
