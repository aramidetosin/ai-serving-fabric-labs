# Chapter 9: Split-Horizon DNS

Lab `sfab-ch09`, the companion lab of the book's Chapter 9, "Split-Horizon DNS". It runs build A's state many at step 9: chapter 8's deployment with the internet side. Everyone types `llm.ai.tarnwick.example`: the staff get the users' VIP, the nodes the internal VIP, internet users the firewall's published address, and the operator's tools name the internal VIP through its tunnel.

Status: rendered and unit-tested (`common/sfab/tests/test_part3_render.py`); not deployed or recorded yet. Part III's own audit groups, trace forms and drills land with the record stage; until then `audit.sh` and `trace.sh` run chapter 7's groups and chapter 7's keyed trace on this render.

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 9 |
| Slice | chapter 8's, with `isp-rtr`, `inet-client`, `inet-dns-auth` and `inet-dns-res` |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Prints | none |
| Extends | `ch08` (metadata only) |
| Containers | `sfab-ch09-<node>` (30); containerlab directory `clab-sfab-ch09/` |

## What the spec renders for this chapter

Everything chapter 8's lab renders (`ch08/README.md`), and from step 9 the internet side:

| Node | One job | Address | On |
|---|---|---|---|
| `isp-rtr` | the internet users' provider: its customers' /30s and the firewall's link, all connected; no route to any inside prefix and no static route at all | 198.51.100.9/30 (fw ethernet1/6), 203.0.113.1/30, .5/30, .9/30 | `sfab/frr` |
| `inet-client` | an internet user's client; resolver inet-dns-res; trusts the lab root (labeled: production uses a public CA) | 203.0.113.2/30 | `sfab/client:2` |
| `inet-dns-auth` | the platform's public authoritative server: `llm` alone, answered 198.51.100.10, recursion off, no admin, identity or infrastructure name, no wildcard, no AAAA record | 203.0.113.6/30 | `sfab/resolver:3`, BIND |
| `inet-dns-res` | the provider's recursive resolver: recursion for 203.0.113.0/26 only, `ai.tarnwick.example` sent to inet-dns-auth (static-stub, standing in for the parent zone's delegation), every other name NXDOMAIN at once | 203.0.113.10/30 | `sfab/resolver:3`, BIND |

On the firewall (`bootstrap/fw/`): ethernet1/6, 198.51.100.10/30, in zone `isp` with zone protection `zp-internet` and the profile `ping-only`, and the route `isp-customers` (203.0.113.0/26 via 198.51.100.9), which zone protection's strict IP check needs before the internet client's first SYN can reach a rule. No rule and no NAT are added: the internet client's SYN to 198.51.100.10 meets `deny-all-log` (from isp to isp) until chapter 10. `ops-dns`, the uplink side's public server, still publishes no platform name (a lab simplification, labeled: the lab's two provider sides are separate internets).

Lab simplifications on the internet side: one public authoritative server, on a customer port of the ISP router, outside the firewall (production runs at least two on different networks); the ISP resolver reaches the zone by a static-stub, not by recursion from the root; it answers every other name NXDOMAIN, as dns-res1 and dns-res2 do.

## Requirements

Chapter 7's lab's (`ch07/README.md`), and `sfab/keys:4` built on the lab host (`make -C images keys`, from `images/keys` and the pinned PyYAML wheel already in the vendor directory) and pushed into the in-lab registry with the rest (`make -C images registry-seed`; preflight checks that the registry holds the key image `serving.env` names). Memory: the inventory's budget is 163.75 GiB for 30 nodes, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 179.75 GiB in all; on a shared lab host the author's rule keeps about 40 GiB beyond that free before `make up`. containerlab 0.82.0, the host tick at 10000 (read and recorded, never refused on), and no other `sfab-` lab running.

## Running it

```
cd ch09
make render
make up
make audit
make trace
make break-9a        # Exercise 4
make heal-9a
make down
```

## break-9a

`breaks/9a.yaml`: on `ent-dns`, the corporate resolver, the platform zone's `server=/ai.tarnwick.example/...` lines are removed and `llm` and `id` pinned with `address=` to the users' VIP (`dnsmasq_pin`, installed in a copy of the node's render and the server restarted on it with `sfab-dns reload`). dnsmasq answers A for a pinned name itself and, from 2.86, sends other types upstream. The render's `local=/tarnwick.example/` (the corporate domain) stays as the corporate team would leave it, and it covers the platform's subdomain too, so the AAAA status the break gives on dnsmasq 2.90-r3 is read from the recording, not assumed. The break records the staff client's lookups of `llm.ai.tarnwick.example` by each stub it has (`probe_lookup`: dig for A and AAAA, python3's getaddrinfo through musl, curl through its own resolver library, each timed, with the client's resolv.conf). `make heal-9a` installs the rendered `dnsmasq.conf` again and checks A answered, AAAA NODATA (NOERROR with no record), both stubs resolving and curl connecting.
