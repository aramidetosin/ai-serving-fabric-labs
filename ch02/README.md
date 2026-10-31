# Chapter 2: Multi-Tenant Access Design

Lab `sfab-ch02`, the companion lab of the book's Chapter 2, "Multi-Tenant Access Design". It runs chapter 1's build A, Tarnwick (the platform's names under `ai.tarnwick.example`), whole: every switch, the firewall with chapter 4's configuration, the cluster with its ingress nodes, storage and serving, the bastion, the platform's DNS and time servers, the registry, the uplink router, the operator's site with its IPsec router, and every population's client and resolver. The chapter writes build A's decision table, one decision per layer with the evidence its refusal leaves, and the matrix of populations against endpoints that every later audit checks. So the lab renders both from the spec (`gen/decisions.yaml` and `gen/matrix.yaml`), labels every object of every row with its decision, names the live object behind each row (`label.sh`), tries every cell of the matrix and asserts its mode (`matrix.sh`), walks chapter 1's request with each hop tagged with its row (`trace.sh`), and ships break-2a.

Status: recorded under build A revision 2: one deployment from wiped disks on 2026-10-29, at host tick 10000 on containerlab 0.82.0, every step 0 failed (`make up`, `make audit`, `make trace`, `make label`, `make matrix`, `make break-2a`, `make heal-2a`, `make record`). `RESULTS.md` says what it proved, line by line, and `audits/INDEX.md` maps the chapter's exhibits to the files and lines they quote. The revision 1 sets left the repository (`audits/INDEX.md`, "Superseded sets"). The decision table, the matrix, the labels, the walk's rows and break-2a are tested from the render (`common/sfab/tests/test_ch02_render.py`), and the matrix's and the label run's judges and break-2a's check against made-up evidence in the devices' recorded shapes (`common/tests/test_ch02.py`).

| Selection | Value |
|---|---|
| Profile, state | `a` (Tarnwick), `one` |
| Slice | `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2, k8s-cp1, k8s-cp2, k8s-cp3, bastion, inet-registry, uplink-rtr, ops-client, web-client, ops-dns, ent-client, truenas1]`: build A whole, chapter 1's |
| Features | `{k8s: true, serving: true, storage_setup: true}` |
| Decisions | `true`: the decision table, the matrix and the labels (`render/decisions.py`) |
| Prints | none: the chapter prints tables, rulebases, routes, labels and verdicts, not a device's whole configuration |
| Extends | `ch01`: the same deploy, chapter 1's audit, its walk with the rows, the label run, the matrix and break-2a |
| Containers | `sfab-ch02-<node>` (28); containerlab directory `clab-sfab-ch02/` |

## What the spec renders for this chapter

The devices run what chapter 1's lab runs (`ch01/README.md`), with one difference: `decisions: true` in `chapter.yaml` labels every object of the decision table's rows, and every switch, with its decision id. An object takes the id its spec element carries (`decision:` in `spec/profile-a.yaml`), else `dec-<row>-<its name>`. A lab without `decisions: true` renders as before.

| Object | Where the label is | Example |
|---|---|---|
| Security and NAT rules | each rule's description in `bootstrap/fw/startup-config.xml` (and `enforced.txt`) | `deny-all-log`: `dec-policy-deny-all-log`; `bastion-to-nodes`: `dec-policy-bastion-to-nodes` |
| HTTPRoutes | the label `decision.tarnwick.example/id` on every route of both Gateways, the serving recipe's included (`SERVING_ROUTE_DECISION`) | `models-gw-users`: `dec-routeset-enterprise` |
| Zone file entries | the comment on each entry a view answers, in each zone file on dns-auth1 (dns-auth2 serves the same zones by transfer) and ops-dns, and each view's comment in `named.conf` | `llm IN A 10.20.11.210 ; decision dec-view-enterprise: a name users type` |
| Consumer groups | each group's `desc` in the API gateway's routes ConfigMap | `dec-key-batch: ...`, one group a caller |
| Rail attachments, pods | the attachment's annotation (`SERVING_NAD_DECISIONS`), each pod's label and the placement table's decision column | `rail3`: `dec-place-chat` |
| Router routes | the comment line above each static route in `bootstrap/uplink-rtr/frr.conf` | `! inside-nodes: dec-route-inside-via-fw` |
| Switches | the comment under the header of each `startup-config.cfg` | `! decision dec-forwarding-only: forwards frames and decides nothing, ...` |

The firewall's connected subnets and its static routes carry their ids in `gen/decisions.yaml` only: the render stamps nothing on them.

### The decision table, `gen/decisions.yaml`

Table 2-1's seven rows, in the order a request meets them, each with its layer, owner, object, decision, evidence and refusal as the chapter states them, and the objects of this lab that implement it, each with its decision id and where the id is stamped: the three views (`internal` and `enterprise` on the authoritative pair, written on dns-auth1; `public-operator` on `ops-dns`); the firewall's ten connected subnets (ae1's six units, ethernet1/3, ethernet1/4, ethernet1/7 and ethernet1/5), its default route, its route to the operator's site through the tunnel and its three discard routes, and the uplink router's route to the operator's site and its eight static routes to the inside prefixes via the public address; the two NAT rules; the 24 security rules, `deny-all-log` last; the five HTTPRoutes; the three consumer groups, one a caller (the applications batch and helpdesk, the people of the staff group); and the five model copies (chat a, b and c, staff a and b) with their rail attachments. The five switches are listed as forwarding only, with the ids their own ports carry, and the one id the spec gives an object of no row (`dec-storage-data-address`, the storage system's data address) is listed with why. An id under no row and not listed is a render error. `gen/decisions.json` holds the same data with `label.sh`'s plan of reads.

### The matrix, `gen/matrix.yaml`

Table 2-2: the staff (from `ent-client`, asking ent-dns), the operator (from `ops-client`, behind its site's IPsec router ops-gw, asking ops-dns), the nodes (from `k8s-cp2`, in VLAN 100, asking dns-res1) and an internet host that is not the operator (from `web-client`, asking ops-dns) against eleven endpoints. Each cell's mode is computed from the spec as the request meets the layers: the population's resolver view answers the name, or, where the view holds no record for it, the request is pinned to the population's answer for the users' hostname; the client's gateway, the operator's tunnel when the destination is in one of its proxy IDs, or the uplink router's static route takes the request to the firewall, which checks its source against its route back (zone protection's strict IP check on the uplink), looks up the route on ingress, matches a NAT rule on the pre-NAT zones and the first security rule on the original addresses and the post-NAT zone; the Gateway's HTTPRoutes match the hostname and path; the API gateway matches the caller's key. As the render resolves it:

| Endpoint | Address and port | Staff | Operator | Nodes | Internet host |
|---|---|---|---|---|---|
| Internal Gateway | 10.20.11.200, tcp/443 | log line, `deny-all-log`, enterprise to ingress | allowed | allowed | log line, `deny-all-log`, uplink to ingress |
| Users' Gateway | 10.20.11.210, tcp/443 | allowed | log line, `deny-all-log`, operator-vpn to ingress | allowed, on the node (Cilium) | log line, `deny-all-log`, uplink to ingress |
| Route to chat | the resolver's answer, tcp/443, the model's route | 200; 401 with the other model's key (key) | 200; 401 with the other model's key (key) | 200; 401 with the other model's key (key) | log line, `deny-all-log`, uplink to uplink |
| Route to staff | the resolver's answer, tcp/443, the model's route | 200; 401 with the other model's key (key) | 200; 401 with the other model's key (key) | 200; 401 with the other model's key (key) | log line, `deny-all-log`, uplink to uplink |
| Admin hostnames | the resolver's answer, tcp/443, /echo | 404, gw-users (route set) | allowed | allowed | log line, `deny-all-log`, uplink to uplink |
| API server | 10.20.1.10, tcp/6443 | log line, `deny-all-log`, enterprise to k8s-nodes | silence, fw (zone protection's strict IP check) | allowed | log line, `deny-all-log`, uplink to k8s-nodes |
| A node, k8s-gpu1 | 10.20.1.21, tcp/22 | log line, `deny-all-log`, enterprise to k8s-nodes | silence, fw (zone protection's strict IP check) | allowed | log line, `deny-all-log`, uplink to k8s-nodes |
| A BMC, k8s-gpu1's | 10.20.9.21, tcp/443 | log line, `deny-all-log`, enterprise to oob | silence, fw (zone protection's strict IP check) | log line, `deny-all-log`, k8s-nodes to oob | log line, `deny-all-log`, uplink to oob |
| Storage data | 10.20.12.31, tcp/2049 | silence, fw (discard route) | silence, uplink-rtr (no route) | silence, fw (discard route) | silence, uplink-rtr (no route) |
| Storage management | 10.20.2.31, tcp/443 | log line, `deny-all-log`, enterprise to stor-mgmt | silence, fw (zone protection's strict IP check) | allowed | log line, `deny-all-log`, uplink to stor-mgmt |
| An internet host, web-client | 192.0.2.18, tcp/443 | log line, `deny-all-log`, enterprise to uplink | allowed | log line, `deny-all-log`, k8s-nodes to uplink | allowed |

44 cells: 17 allowed and 27 forbidden, 18 log lines, one 404 and eight silent, beside six requests with another model's key, each the API gateway's 401. The operator reaches the internal Gateway through its tunnel, untranslated, in zone `operator-vpn`; nothing is published on the public address, so the internet host's model and admin cells, pinned there, meet `deny-all-log`. An operator cell inside the tunnel's proxy IDs (the users' Gateway) meets the firewall's policy in zone `operator-vpn`; one outside them leaves ops-gw in the clear for the uplink router, which routes it to the public address, and since the firewall routes the operator's site through the tunnel, zone protection's strict IP check drops it on ethernet1/5 before any rule: silence, whose evidence is the firewall's route back and its drop counter. The storage data VLAN, 120, has no gateway: the firewall discards its prefix (10.0.0.0/8) and the uplink router holds no route to it. The nodes' allowed cells stay inside VLAN 100, cross the firewall under their own rule (the storage management API), or never leave the node: k8s-cp2 is a node of the cluster, and Cilium, which replaces kube-proxy, translates either Gateway's VIP to a Gateway pod at connect(), so a node's connect to a VIP sends no packet to the VIP and no firewall sees it (the users' Gateway's cell is allowed for that reason, and `nodes-to-internal-gateway` is not on the path of any node cell). `gen/matrix.json` holds the same data, which `matrix.sh` reads.

### The walk's rows, `gen/trace.json`

Chapter 1's walk plan (`ch01/README.md`, "The trace"), with each hop tagged with the row of the decision table that decides there: the resolver view at the resolver, routing, NAT and security policy at the firewall, forwarding only at the bundle's leg, the pair and the rail switch, the route set at the Gateway, the caller's key at the API gateway and placement at the Service and the copy. Each of the three refusals names its row: the route set (the admin hostname's 404), the key (another caller's key, 401) and security policy (the node's SSH port, `deny-all-log`).

### break-2a, `gen/breaks.json`

The enterprise view's forward zone rendered with `admin` and `grafana` answering the internal Gateway's VIP, 10.20.11.200, where the render publishes neither name in that view, and its heal restoring dns-auth1's render (dns-auth2 follows by NOTIFY and transfer).

## Requirements

Chapter 1's lab's: the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and `vrnetlab/truenas_truenas:27.0.0-RC.1` (`images/VENDOR-IMAGES.md`) and the `sfab/*` images from `make -C images all`, with the in-lab registry seeded (`make -C images registry-seed`) and the two models in `images/models` (`make -C images models-fetch`; preflight checks them). Memory: the inventory's budget is 179 GiB, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 195 GiB in all; 70 vCPUs within twice the host's CPU count; 95 GiB of growth under `state/` and 56 GiB of container layers. The host tick at 10000 (read and recorded, never refused on: a set stamped `host-tick` says so in its lab's results page), containerlab 0.82.0 (the pin `spec/versions.yaml` holds), and no other `sfab-` lab running.

## Running it

```
cd ch02
make render          # topo.clab.yml, bootstrap/ and gen/ (decisions.yaml, matrix.yaml, trace.json, breaks.json)
make up              # preflight, up, boot, finish, audit (Example 2-1)
make audit           # audits/sfab-ch02_audit_<UTC>/ (Examples 2-2 and 2-12)
make label           # audits/sfab-ch02_label_<UTC>/ with LABELS.md (Examples 2-3 and 2-5 to 2-8)
make matrix          # audits/sfab-ch02_matrix_<UTC>/ with MATRIX.md (Examples 2-9 and 2-10)
make trace           # audits/sfab-ch02_trace_<UTC>/ with TRACE.md (Example 2-11)
make record          # audit, trace, label, matrix, then the gate on the four sets
make break-2a        # audits/sfab-ch02_break-2a_<UTC>/ (Exercise 5)
make heal-2a         # audits/sfab-ch02_heal-2a_<UTC>/, then the chapter audit
make down            # keeps state/ disks; make wipe removes them
```

Example 2-4's `show ip route` on the five switches is in every full audit set (each switch's `show ip route` file) and in the label set's `forwarding/`. `make serve`, `make client` and `make load` run the serving recipe with this lab's `bootstrap/k8s/serving.env`, as in chapter 1's lab. The lab has no drills.

Once the lab is up, `ssh admin@sfab-ch02-<node>` from the lab host logs in to `bastion`, `k8s-cp1` to `k8s-cp3`, `k8s-ingress1`, `k8s-ingress2`, `k8s-gpu1`, `k8s-gpu2`, `uplink-rtr` and `ops-gw` with the lab's key or your own (`../README.md`, "Default logins"). The switches and the firewall keep their kinds' default logins, and the clients, the DNS and time servers and `inet-registry` run no SSH server: the containerlab VS Code extension's Attach shell opens a shell in each.

## The audit

`audit.sh` is chapter 1's (`ch01/README.md`, "The audit"), with chapter 2's forwarding-only reads on every switch: the pair, both rail switches and the out-of-band switch each with no address on any served VLAN, PortChannel or host port (`show ip interfaces` lists only Management0, in VRF `mgmt`, and on a pair member its two keepalive addresses, Ethernet12 and Vlan3966, in VRF `VrfMclagKa`; no served VLAN's `interface Vlan` block carries an address; the kernel holds none on a Vlan, PortChannel or Ethernet netdev beyond those two, SONiC's own `lo-m`, `docker-mgmt`, `redirect` and `docker0` set aside), no routing protocol (no `router` line, no router block in the FRR view), nothing in `show ip route`, and on a pair member only the two connected keepalive /31s in `show ip route vrf VrfMclagKa`, read in KLISH, never with `ip route` on the switch's Linux side.

## The label run

`label.sh` (`common/matrix/label.sh`, judged by `common/matrix/label.py`) reads, for each row of `gen/decisions.json`, the live object behind it, and changes nothing on any device:

1. The resolver view: each population's client looks up `llm.ai.tarnwick.example` through its own resolver (`dig` in a container, `getent ahostsv4` in a VM guest), and each authoritative BIND server's zone file as it serves it (`view/`).
2. Routing, NAT and security policy: `show routing route`, `show running nat-policy` and `show running security-policy` in one CLI session, and the running rulebase through the XML API, whose rules carry their descriptions (`fw/`); the uplink router's `show ip route` and the configuration bound into it (`routing/`).
3. The route set: every HTTPRoute with its audience and decision labels as columns (`routeset/`).
4. The key: the API gateway's routes ConfigMap with its consumer groups, and one API gateway pod's key logs (its `compose` init container's, which composed the keys at the pod's start, and its sidecar's, which logs a change only), which name each consumer by its key's fingerprint (`key/`).
5. Placement: the placement table as rendered, the serving pods with their decision label, and the rail attachments with their annotation (`placement/`).
6. The switches: each switch's delivered startup file, its first lines, and its `show ip route` (`forwarding/`).

The judge wants each population's answer from its view and each zone file's entry labelled; every connected subnet and route of the firewall in its routing table, and each of the uplink router's routes live with its comment line; both rulebases in the rendered order, `deny-all-log` last, each rule's description its decision id; every HTTPRoute labelled; each consumer group's desc labelled and a consumer of it composed; every pod of each copy labelled and each rail attachment annotated; and each switch's startup file labelled forwarding only with nothing in `show ip route`. `LABELS.md` prints one line per object: its row, the live object, its decision and the file and line that show it.

## The matrix

`matrix.sh` (`common/matrix/matrix.sh`, judged by `common/matrix/matrix.py`) tries every cell from the population's own client, by TCP connect from a pinned source port (`common/trace/syn_connect.py`) or by HTTP request by name through the client's own resolver, its source port pinned with curl's `--local-port`, never by ping, since a Gateway's VIP answers TCP and not ICMP on the pinned Cilium (chapter 7). Each request takes its own source port from 43000 on. In order:

1. Each client looks up every name its cells ask for, which also warms its path to its resolver (`lookups/`).
2. Both models' keys (each the first key of an application caller that may call the model) are handed to each client a model cell runs from, through pipes from their Secret in the cluster into a 0600 header file in the client (in `k8s-cp2` over the same pipe through ssh): no key is on a command line, in the transcript or on the lab host, and each is named by its fingerprint only (`keys/`).
3. Every request of every cell, each attempt logged in `requests.tsv`; an attempt that was to be answered and was not is tried once more from the next source port after a pause, since the first packets of a new flow are lost to ARP (`requests/`: what the client saw, and each answer's headers and body, never a request header). Where a cell of the run is dropped by zone protection's strict IP check, the firewall's drop counters are read around the requests (`fw/drops-before.txt`, `fw/drops.txt`: the delta view of `show counter global filter delta yes severity drop`).
4. The firewall's traffic log for every destination port an unanswered attempt crossed, read until it holds each of them (`fw/`); the firewall's routing table (`fw/routing-route.txt`) and the uplink router's (`routers/`); the API gateway pods' access log over the run (`api-gateway/`).
5. The keys' files removed from every client.

The judge asserts each cell's mode with its evidence, never only its outcome: an allowed connect opened, an allowed request answered 200 from the Gateway and route the plan names; a log line is the traffic log's entry for the attempt's source port naming `deny-all-log`, deny, with the zones the plan computes, beside the client's view (a timeout or an error such as an ICMP unreachable, recorded as the client saw it), and for a cell that reaches the firewall through the uplink router, the router's static route for the destination's prefix via the public address; a silent cell names the device that dropped it with that device's evidence: a router's routing table without the route, the firewall's discard route covering the destination, or, for the strict IP check, the firewall's route back to the source out the tunnel and `flow_dos_pf_strictip` risen over the run, with no traffic log line for the request in each case; the 404 comes from the users' Gateway with no line for the request's marker in the API gateway's log, which must hold the run's model requests, or the absence would prove nothing; every model cell's second request, with the other model's key, is the API gateway's 401 with its own message, `Authorization Failed`. A cell in another mode than the plan's fails, whatever its outcome: a 404 cell that times out fails, because the wrong layer acted. `MATRIX.md` prints the matrix turned on its side, every cell's verdict, and the evidence of each cell by file and line.

## The trace

`trace.sh` is chapter 1's walk (`ch01/README.md`, "The trace"), run by `common/trace/lib-walktrace.sh` and judged by `common/trace/walktrace.py`; `TRACE.md`'s table of hops and its table of refusals gain a Row column from the plan's rows. The walk inherits chapter 1's counter clears, typed a line every 5 s, since KLISH reads the `y` that confirms the clear and not the session's closing `exit` (`ch01/README.md`, "The trace").

## break-2a

`breaks/2a.yaml`, rendered to `gen/breaks.json` (Exercise 5): the enterprise view answers the admin hostnames, `admin` and `grafana`, with the internal Gateway's VIP, 10.20.11.200, where as rendered it holds neither name (the matrix's staff cell for them is pinned to the users' VIP, 10.20.11.210, and answered 404 there). The names users type still answer as rendered, so no staff request to a model or to the users' hostname changes. A staff request for an admin hostname now resolves and goes to the internal Gateway, which no rule admits the enterprise to: it falls to `deny-all-log` and times out at the client, where the users' Gateway answered 404. The cell's mode moved from the route set to security policy, and only the matrix notices, since no user calls an admin hostname.

The break writes the view's forward zone, as the render makes it with the two names added, into a copy of dns-auth1's render inside its container, the primary, and reloads BIND on that copy (`sfab-dns reload`, which checks every file before named sees it); the new serial reaches dns-auth2 by NOTIFY and transfer, and the resolvers' caches are flushed. `make break-2a` records ten requests from the enterprise client to `https://llm.ai.tarnwick.example/echo` through its own resolver, then the matrix's cells for the staff's admin hostnames, the users' Gateway and both model routes, tried as `matrix.sh` tries them, from their own source ports. It passes when every request is answered, the admin cell is a log line from `deny-all-log` and the other three cells stay allowed. `make heal-2a` installs dns-auth1's render again and reloads it (the zone's serial follows its data, so the rendered serial can be behind the break's in RFC 1982 arithmetic; dns-auth2 then ignores the NOTIFY and keeps the break's zone, and the heal tells it to transfer the zone again with `rndc retransfer`), and wants every request answered, the admin cell back at the users' Gateway's 404 and the other three allowed; then the chapter audit.

## Platform notes for this lab

Chapter 1's notes hold here (`ch01/README.md`), with M1's, chapters 3 to 7's and M2's behind them. Three the matrix relies on: PAN-OS writes a denied session's traffic log line a few seconds after the attempt and an allowed one's when the session ends, so the matrix reads the log after every cell, until it holds each unanswered attempt; the CLI cuts rule names to 19 characters in the log, which `deny-all-log` fits; and a drop by zone protection writes no traffic log line at all, only a global counter (`ch04/README.md`, platform notes), so the strict IP check's cells are judged by the counter. The API gateway writes its access log to its standard output (nginx's line a request, and file-logger's JSON line naming the consumer and its caller, with no header in it), which is where the matrix reads the model requests and the 404 cell's absence.
