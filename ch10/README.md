# Chapter 10: Tenant Isolation on the Firewall

Lab `sfab-ch10`, the companion lab of the book's Chapter 10, "Tenant Isolation on the Firewall". It runs build A's state many at step 10: chapter 9's deployment with the internet users' translation and rule. Three populations share one firewall and one routing table, and the zone each arrives in keeps them apart: internet users translated, the staff routed, the operator tunneled.

Status: recorded under build A revision 2 on 2026-10-31 on the first lab host, one deployment from wiped disks that ran `make up`, `make audit`, `make trace`, `make hold`, break-10a and its heal, and `make record`, every set green (`RESULTS.md`; `audits/INDEX.md` maps the chapter's exhibits to their files and lines); tested against the stand-ins too (`common/sfab/tests/test_part3_render.py`, `test_part3_tools_render.py`, `common/tests/test_part3_labs.py`). The outputs of `show session info` and `show session all ... count yes` are the pinned PA-VM 12.1.2's as recorded; the measured rate on `show session info`'s `Throughput:` line is redacted, as every throughput figure is.

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 10 |
| Slice | chapter 9's |
| Features | `{k8s: true, serving: true, storage_setup: false}` |
| Prints | none |
| Extends | `ch09` (metadata only) |
| Containers | `sfab-ch10-<node>` (30); containerlab directory `clab-sfab-ch10/` |

## What the spec renders for this chapter

Everything chapter 9's lab renders (`ch09/README.md`), and from step 10 on the firewall (`bootstrap/fw/startup-config.xml`, `enforced.txt`):

- **NAT `dnat-internet-gateway`**, first of the NAT rulebase: from `isp` to `isp`, source any, destination 198.51.100.10 (the firewall's own isp address, the published address), service `tcp-443`, destination translated to 10.20.11.220, the internet Gateway's VIP. The route lookup for 198.51.100.10 finds the firewall's own interface, so the pre-NAT destination zone is `isp`; the second lookup for 10.20.11.220 finds ae1.110, zone `ingress`. Then `no-nat-public` and `internet-snat`, as chapter 4 recorded.
- **Security rule `isp-to-internet-gateway`**, rule 24: from `isp` to `ingress`, source any, destination 198.51.100.10 (the pre-NAT address with the post-NAT zone, as PAN-OS matches a rule after a destination NAT), application `ssl`, service application-default, profile group `bp-default`, log at session end; `deny-all-log` is rule 25. Nothing else is opened from `isp`, and no inbound source NAT is written, so the internet client's address reaches the Gateway and the API gateway's log.

## Requirements

Chapter 7's lab's (`ch07/README.md`), and `sfab/keys:4` built on the lab host (`make -C images keys`, from `images/keys` and the pinned PyYAML wheel already in the vendor directory) and pushed into the in-lab registry with the rest (`make -C images registry-seed`; preflight checks that the registry holds the key image `serving.env` names). Memory: the inventory's budget is 163.75 GiB for 30 nodes, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 179.75 GiB in all; on a shared lab host the author's rule keeps about 40 GiB beyond that free before `make up`. containerlab 0.82.0, the host tick at 10000 (read and recorded, never refused on), and no other `sfab-` lab running.

## The audit, the trace and the measurement

- `audit.sh` runs chapter 9's, then the `zone-nat` group: both rulebases in the rendered order, the `isp` zone's one translation and one rule, the published address refused from every inside zone (`deny-all-log` from the population's own zone to `isp`, or silence at the uplink router), and each zone's session count under the held connections within the plan's bound.
- `trace.sh` (`chapter.yaml` `trace.nat`): one uncaptured warm-up connect per population, then one held HTTPS request per population with its capture pair, each SYN followed by its sequence number to the one leg that carries it.
- `hold.sh` (`make hold`, `chapter.yaml` `tenancy.hold`, `common/trace/lib-hold.sh`): 8 keep-alive connections a population held the whole 120 s, each zone's session count and `show session info` before, while held, after a chat request per population with its own caller's key and after the stop; `HOLD.md` with Little's law per zone. `HOLD_FACTOR=2` doubles the connections.

## Running it

```
cd ch10
make render
make up
make audit
make trace           # audits/sfab-ch10_trace_<UTC>/ (the zone-keyed NAT trace)
make hold            # audits/sfab-ch10_hold_<UTC>/ (the sessions under held connections)
make break-10a       # Exercise 5
make heal-10a
make down
```

## break-10a

`breaks/10a.yaml`: `isp-to-internet-gateway` edited through the firewall's API to name 10.20.11.220, the translated destination, in place of the published address (`panos_api`, as chapter 1's break edits a destination). The NAT rule still translates; no rule then matches the internet users' sessions. The break records requests from the internet client and from the staff client to `llm.ai.tarnwick.example`, three connects from the internet client to 198.51.100.10 from pinned source ports (42310 on) captured on the ISP router's link and both legs of the bundle, and the running security and NAT rulebases. It passes when every internet request fails, every staff request answers, the SYNs are seen on the ISP link and on neither bundle leg, and the traffic log names `deny-all-log` (recorded from zone `isp` to `ingress`: the translation still applies, so the denied sessions carry the post-NAT zone). `make heal-10a` writes the rendered destination back and checks the reverse, the log naming `isp-to-internet-gateway`.
