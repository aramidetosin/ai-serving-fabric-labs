# Chapter 1: Introducing the AI Serving Fabric

Lab `sfab-ch01`, the companion lab of the book's Chapter 1, "Introducing the AI Serving Fabric". It runs build A's one-tenant state, Tarnwick (the platform's names under `ai.tarnwick.example`), whole: every switch, the firewall with chapter 4's configuration, the cluster with its ingress nodes, storage and serving, the bastion, the platform's DNS and time servers, the registry, the uplink router, the operator's site with its IPsec router, and every population's client and resolver. The chapter follows one chat completion from the enterprise client to a model and names the device behind each decision, so the lab audits build A as chapters 3 to 7 audit their parts, walks one request inward with every device's table (`trace.sh`), sends three requests that must be refused and records where each died, and ships break-1a.

Status: recorded under build A revision 2: one deployment from wiped disks on 2026-10-29, at host tick 10000 on containerlab 0.82.0, every step 0 failed (`make up`, `make audit`, `make trace`, `make break-1a`, `make heal-1a`, `make record`). `RESULTS.md` says what it proved, line by line, and `audits/INDEX.md` maps the chapter's exhibits to the files and lines they quote. The revision 1 sets left the repository (`audits/INDEX.md`, "Superseded sets"). The walk's plan and break-1a are tested from the render (`common/sfab/tests/test_ch01_render.py`), the walk's judge and break-1a's checks against made-up evidence in the devices' recorded shapes (`common/tests/test_ch01.py`).

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, web-client, ops-dns, ent-client, truenas1]`: build A whole, chapter 7's with TrueNAS and the web client; its closure adds the ingress nodes, the DNS and time servers, ent-dns and ops-gw |
| Features | `{k8s: true, serving: true, storage_setup: true}` |
| Prints | none: the chapter prints tables, sessions, frames and answers, not a device's configuration |
| Extends | `ch07`: the same deploy with storage set up, chapter 3's to 7's audits in one, the request walk and break-1a |
| Containers | `sfab-ch01-<node>` (28); containerlab directory `clab-sfab-ch01/` |

## What the spec renders for this chapter

Nothing the earlier labs do not render: this lab's `bootstrap/` is chapter 7's (`ch07/README.md`: the Gateways, the names, the certificates, the callers and the identity provider, the router and the timeout chain; `ch06/README.md`: the placement table and the serving recipe) with chapter 4's storage beside it (`bootstrap/truenas1/setup.json`, the democratic-csi values `60-democratic-csi-nfs.yaml` and `60-democratic-csi-nvmeof.yaml`, TrueNAS's data address in the storage VLAN 120 and its API on the management address in VLAN 200). The firewall is chapter 4's (`ch04/README.md`): ae1 with its six units as the gateways of VLANs 100, 110, 130, 131, 200 and 300, ethernet1/3 for the out-of-band network, ethernet1/4 and ethernet1/7 for the enterprise client and its corporate resolver, ethernet1/5 for the uplink with the public address and zone protection, tunnel.1 for the operator's IPsec tunnel, the NAT rulebase (`no-nat-public`, `internet-snat`) and the security rulebase of App-ID rules ending in `deny-all-log`.

What the chapter adds is the trace plan (`gen/trace.json`, `render/trace.py`, the `walk:` form) and break-1a (`gen/breaks.json`). The walk's plan is resolved from the spec alone, before any request is sent:

| Hop | Device | Table it consults | What the render resolves |
|---|---|---|---|
| 1 | `ent-client` | its resolver | the corporate resolver ent-dns, 10.24.10.53 |
| 2 | ent-dns, forwarding the platform zone to the authoritative pair | view `enterprise` on dns-auth1 (the asking resolver's address, ent-dns's) | `llm.ai.tarnwick.example` A 10.20.11.210, the users' Gateway's VIP; asked by dns-res1, the platform's own resolver, view `internal` answers 10.20.11.200 |
| 3 | `fw`, in on ethernet1/4, zone `enterprise` | the routing table of virtual router `core` | 10.20.11.0/24 connected on ae1.110, zone `ingress` |
| 4 | `fw` | the NAT rulebase | no rule from zone `enterprise`: no translation |
| 5 | `fw` | the security rulebase | `staff-to-users-gateway`, the first rule from `enterprise` to `ingress`: ssl to 10.20.11.210 alone |
| 6 | `fw`, out on ae1.110 | ae1's members | ethernet1/1 to fe-sw1 Ethernet2, ethernet1/2 to fe-sw2 Ethernet2, tagged 110 |
| 7 | the pair | its MAC table, VLAN 110 | found when the trace runs: the lease holder's bond |
| 8 onward | the lease holder (an ingress node), the Gateway, the API gateway, the router, the Service, the copy | chapter 7's keyed trace | chat's route `models-gw-users`, the consumer groups that may call chat, the router's model list, chat's copies a (k8s-gpu1, rail 3), b (k8s-gpu2, rail 6) and c (both nodes, rail 7) |

The router picks the copy, and the walk takes the one it is given: a node-local copy (a or b) keeps its RPC inside its node and puts nothing on a rail switch, and chat c, the stand-in for a model larger than one node, crosses rail-sw1 on rail 7. The three refusals are resolved the same way, each with the device that must refuse it: `admin.ai.tarnwick.example` to the users' Gateway (the enterprise view publishes no admin name, so the request is pinned to the users' VIP: 404 at the Gateway, which carries no route for it), chat's route with staff's key, the helpdesk caller's (401 at the API gateway, `Authorization Failed`), and k8s-gpu1's SSH port, 10.20.1.21 TCP 22, from the enterprise LAN (the render's first matching rule is `deny-all-log`, zone `enterprise` to `k8s-nodes`; the port must sit behind the bundle whose legs the walk captures). A walk the render would translate, a key refusal naming the walked model, or a port the rulebase allows is refused at render time.

## Requirements

Chapter 7's lab's and chapter 4's storage: the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and `vrnetlab/truenas_truenas:27.0.0-RC.1` (`images/VENDOR-IMAGES.md`) and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`) and the two models in `images/models` (`make -C images models-fetch`; preflight checks them). Memory: the inventory's budget is 179 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 195 GiB in all; 70 vCPUs within twice the host's CPU count; 95 GiB of growth under `state/` and 56 GiB of container layers. The host tick at 10000 (read and recorded, never refused on: a set stamped `host-tick` says so in `RESULTS.md`), containerlab 0.82.0 (the pin `spec/versions.yaml` holds; the revision 1 set was recorded on 0.81.1), and no other `sfab-` lab running.

## Running it

```
cd ch01
make render          # topo.clab.yml, bootstrap/ and gen/ (trace.json, breaks.json)
make up              # preflight, up, boot, finish (the cluster, storage, the Gateway layer, the serving recipe, the API gateway, router and identity provider), audit (Example 1-1)
make audit           # audits/sfab-ch01_audit_<UTC>/ (Example 1-2)
make trace           # audits/sfab-ch01_trace_<UTC>/ with TRACE.md (Examples 1-3 to 1-9)
make record          # audit, trace, then the gate on both sets (Example 1-10)
make break-1a        # audits/sfab-ch01_break-1a_<UTC>/ (Exercise 4)
make heal-1a         # audits/sfab-ch01_heal-1a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

`make serve`, `make client` and `make load` run the serving recipe with this lab's `bootstrap/k8s/serving.env`, as in chapter 7's lab. The lab has no drills: chapters 3 to 7 drill the parts.

Once the lab is up, `ssh admin@sfab-ch01-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"), and the containerlab VS Code extension's Connect (SSH) runs the same command. The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the extension's Attach shell opens a shell in each.

## The audit

`audit.sh` runs every check the labs of chapters 3 to 7 run, in one audit: the shared checks and chapter 2's forwarding-only reads (the pair, the rail switches and the out-of-band switch with no address but Management0 in the management VRF and, on a pair member, its two keepalive /31s in VRF `VrfMclagKa`, and nothing in `show ip route`), the pair with its roles, its ICCP session over the keepalive link, its backup keepalive and every PortChannel, every bond's legs (the storage bonds' too), chapter 5's `rail-backend` group, chapter 6's `placement` group, chapter 7's `keys`, `identity` and `gateway-layer` groups, chapter 3's Layer 2 hygiene, then M2's build A audit (the cluster and its security, the bastion, the platform's DNS and time servers, the uplink side, the clients, storage with a volume on each class, the populations, the Gateways and their certificates) and chapter 4's firewall edge (every gateway of Table 1-2 on its interface and zone, the rulebase in order, administrative access, an egress the allowlist does not name, the service routes, the uplink router's routes to the inside prefixes and the operator's refused cells). `audit.sh --quick`, which the finish stage runs and which is not recorded, reads the switches, the firewall, storage, the container links the MAC tables need, and the `placement` and `keys` groups.

## The trace

`trace.sh` (`common/trace/lib-walktrace.sh`, judged by `common/trace/walktrace.py`) walks one chat completion from the enterprise client to `chat` through the users' Gateway, with chat's key (the batch caller's) handed to the client from its Secret as a 0600 header file (never printed) and its source port pinned (42106), after one warm-up request. In order:

1. The cluster's reads (chapter 6's: both namespaces' pods, the Gateway's lease, the serving EndpointSlices), then every HTTPRoute, the lease as kubectl prints it, the API gateway's routes and the router's model list (`cluster/`).
2. The client's own lookup of `llm.ai.tarnwick.example` through its resolver, ent-dns, and dns-res1's lookup of the same name asking itself, which another view answers (`dns/`).
3. The firewall's routing table, security rulebase and NAT rulebase, in one CLI session (`fw/`).
4. On each rail switch the model's copies use, `clear counters interface all` (answered `y`), then `show interface counters`; each read stamped on the lab host's clock (`rail/`).
5. Captures on the lab host at the client's port, the firewall's ethernet1/4, both legs of ae1, the pair ports those legs land on and the pair ports facing the lease holder's bond, then chapter 7's points (the lease holder's `bond0`, the API gateway's and the router's pods whole with every key replaced by its mark, the servers and workers on their rails, the rail switch ports).
6. The request, its connection held 30 s after the answer as chapter 4's trace holds one: while it is held, `show session all` and `show session id`, then the rail switches' counters and MAC tables and the pair's MAC tables; after it closes, its traffic log line (`sessions/walk/`).
7. Three refused requests from their own pinned source ports: the admin hostname with no key (42107, pinned to the users' VIP), chat's route with staff's key (42108), and a connect to k8s-gpu1's port 22 (42109, `common/trace/syn_connect.py`, the client's view recorded: a timeout, an error or a reset). Then the traffic log read for the refused requests (`fw/traffic-log-22.txt`, `traffic-log-443.txt`).

The judge reads the saved files only. It wants the view's answer and the other view's; the connected route on ae1.110, no NAT rule from `enterprise` and `staff-to-users-gateway` first; the held session in zones `enterprise` to `ingress` with no translation and the rule named, and its traffic log line; the same SYN, by sequence number, on the client's port and the firewall's interface, then on exactly one leg of ae1, tagged 110 with its addresses and ports kept and its TTL one lower, on the pair port that leg lands on, on that switch's port facing the lease holder and on the holder's `bond0`, tagged 110 (the ingress nodes carry VLAN 110 tagged on their bonds), with the holder's bond MAC as its destination and the MACs, TTL and IP id the leg carried (no routed hop between the firewall and the Gateway); the holder's bond MAC in both pair members' MAC tables on its PortChannel, VLAN 110; chapter 6's and 7's hops and key marks; the lease held by an ingress node, the HTTPRoute that matched, chat's route and its consumer groups, the router's model list and the answering server among its Service's ready endpoints; on the rail switch, for chat c the port facing the remote worker's node counting at least the RPC frames its capture saw between the two reads and the worker's rail MAC on that port, and for a node-local copy no RPC frame on the port facing its node. For each refusal it wants the client's answer, the evidence at the refusing device, and nothing of the request past it: no request for the admin hostname at any API gateway pod; staff's key's mark at the API gateway pod and no request at any router pod but the walked one; the SSH connect's SYN on the client's port and the firewall's interface and on no leg, pair port or lease holder, with `deny-all-log` (deny, `enterprise` to `k8s-nodes`) in the traffic log. `TRACE.md` prints the table of hops, devices, tables and decisions with each decision's evidence by file and line, the three refusals, the verdict and the frames per point.

The only change the trace makes on any device is the rail switches' interface counters, cleared before the request; every process it starts it stops, and no file it writes holds a key. The trace took 4 min 5 s on the recorded deployment (`RESULTS.md`, "How to reproduce"). The router names only the model's Service, so the copy that serves the walk is the Service's pick: the recording's `make trace` landed on chat c, whose RPC crosses rail-sw1, and the trace `make record` ran on chat a, node-local on k8s-gpu1, where the judge wants no RPC frame on the rail switch port facing the node. KLISH never reads an `exit` typed ahead of the `y` that confirms the clear, so the clear's session types one line every 5 s (`WT_CLEAR_PACE_S`); typed all at once, each clear's session waited out the runner's 600 s timeout (`RESULTS.md`, "What the deploys found").

## break-1a

`breaks/1a.yaml`, rendered to `gen/breaks.json` (Exercise 4): `staff-to-users-gateway`'s destination is edited through the XML API from 10.20.11.210 to 10.20.11.211, the next address of the users' Gateway's pool, where no Gateway listens, and committed. The rule still exists, still logs and still reads right at a glance; the staff's requests now match no allow rule and fall to `deny-all-log`. `make break-1a` records ten requests from the enterprise client to `https://llm.ai.tarnwick.example/echo` through its own resolver, then three connects to the users' VIP from pinned source ports (42150 to 42152) while the firewall's ethernet1/4 and both legs of ae1 are captured on the lab host, and the running security rulebase. It passes when every request and every connect fails, the connects' SYNs are on ethernet1/4 and on neither leg, and the traffic log names `deny-all-log`, deny, for each connect. `make heal-1a` edits the rendered destination back, commits, and wants every request answered, the connects' SYNs on a leg, and `staff-to-users-gateway`, allow, in the log; then the chapter audit.

## Platform notes for this lab

M1's, chapter 3's, chapter 4's, chapter 5's, chapter 6's and chapter 7's notes hold here (`dev/m1/README.md`, `ch03/README.md`, `ch04/README.md`, `ch05/README.md`, `ch06/README.md`, `ch07/README.md`), with M2's for storage and the Gateways (`dev/m2/README.md`). Two the walk relies on: PAN-OS writes an allowed session's traffic log line when the session ends, so the walk holds the connection open while the session table is read and reads the log after the client closes it, and cuts rule names to 19 characters in the log (`staff-to-users-gateway` reads `staff-to-users-gate`); and `clear counters interface all` asks to confirm in KLISH, so the trace types `y`, its lines paced as above.
