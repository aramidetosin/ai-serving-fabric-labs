# Chapter 11: Validating Tenant Isolation

Lab `sfab-ch11`, the companion lab of the book's Chapter 11, "Validating Tenant Isolation". It runs build A's state many at step 11 with the decision table and the matrix (`decisions: true`, as chapter 2's lab): chapter 10's deployment, the internet users' row and the internet Gateway's column, 60 cells, each with its isolation depth.

Status: rendered, unit-tested (`common/sfab/tests/test_part3_render.py`, `test_part3_tools_render.py`) and run against the stand-ins (`common/tests/test_part3_labs.py`); not deployed or recorded yet.

| Selection | Value |
|---|---|
| Profile, state, step | `a` (Tarnwick), `many`, 11 |
| Slice | chapter 10's, with `web-client` (the internet host row) and `truenas1` (the two storage columns) |
| Features | `{k8s: true, serving: true, storage_setup: true}` |
| Prints | none |
| Extends | `ch10` (metadata only) |
| Containers | `sfab-ch11-<node>` (32); containerlab directory `clab-sfab-ch11/` |

TrueNAS is in this lab, unlike chapters 8 to 10: the matrix's storage data and storage management columns are tried at the storage system, as in chapter 2's lab. Its memory cost is in the requirements below.

## What the spec renders for this chapter

Everything chapter 10's lab renders (`ch10/README.md`), and:

- **The matrix** (`gen/matrix.yaml`, `gen/matrix.json`, `render/decisions.py`): five rows (Staff from ent-client, Operator from ops-client, Nodes from k8s-cp2, Internet host from web-client, Internet users from inet-client) against twelve columns (chapter 2's eleven and the internet Gateway, tried by the internet users at their answer, the published address, which the firewall translates to its VIP). Counts: 60 cells, 20 allowed, 21 log lines, three 404s, 16 silent. Each forbidden cell carries `depth` and `depth_layers`: the layers that would refuse it if every earlier layer let it through (a router without a route, the firewall's strict IP check, its route, its first security rule after NAT, then for an HTTP request the Gateway's route set and the API gateway's consumer restriction for the key the population holds). The internet users reach an inside VIP at depth 2 (the ISP router holds no route, then `deny-all-log`), the internet host on the uplink side at depth 1 (the uplink router routes the inside prefixes inward), and the staff reach the internet Gateway's VIP at depth 1 (policy alone). The internet users' chat cell is asked with their own caller's key, `inetapp` (`key_caller` in the cell's request), not the model's first caller's.
- **The decision table** (`gen/decisions.yaml`): the state many rows name the internet side's public server, the ISP router, the internet users' destination NAT and the internet Gateway's one route.

## Requirements

Chapter 7's lab's (`ch07/README.md`), and `sfab/keys:4` built on the lab host (`make -C images keys`, from `images/keys` and the pinned PyYAML wheel already in the vendor directory) and pushed into the in-lab registry with the rest (`make -C images registry-seed`; preflight checks that the registry holds the key image `serving.env` names). Memory: the inventory's budget is 180 GiB for 32 nodes, and preflight wants MemAvailable to cover it plus the 16 GiB floor, 196 GiB in all; on a shared lab host the author's rule keeps about 40 GiB beyond that free before `make up`. containerlab 0.82.0, the host tick at 10000 (read and recorded, never refused on), and no other `sfab-` lab running.

## The audit, the trace, the matrix and the drill

- `audit.sh` runs chapter 10's, then the `isolation` group's negative checks (no route for staff on `gw-inet`, no admin or identity hostname on it, no enterprise rule beyond the users' VIP reaching another Gateway's pool, the `isp` zone translated to `gw-inet` alone, `isp-rtr` with no inside route).
- `trace.sh` (`chapter.yaml` `trace.ladder`): the capture ladder, every population to each Gateway's VIP, the forbidden tallies per rung.
- `matrix.sh`: the 60 cells, each with its depth and layers in `MATRIX.md`; the internet users' chat cell asked with `inetapp`'s key, its own caller, and the API gateway's access log naming it.
- `drills.sh`: `isolation-under-load`, every population's held connections and its own Gateway probed while it tries the cells it must not reach, at the plan's load and at twice it, one line a population with its allowed count and its zeros; and `leaked-key`, a new key of batch (an enterprise caller) used from the internet client through the internet Gateway, answered 200 and logged under batch, then refused 401 after its revoke: the one cell no network layer holds.

## Running it

```
cd ch11
make render
make up
make audit
make label           # audits/sfab-ch11_label_<UTC>/
make matrix          # audits/sfab-ch11_matrix_<UTC>/
make trace           # audits/sfab-ch11_trace_<UTC>/ (the capture ladder)
make drills          # audits/sfab-ch11_drills_<UTC>/ (isolation-under-load and leaked-key, PASSES=3)
make break-11a       # Exercise 4
make heal-11a
make down
```

`matrix.sh` and `label.sh` are chapter 2's runners on this render: a cell's own caller (`key_caller`) carries that caller's key, and `MATRIX.md` prints each cell's depth and its layers.

## break-11a

`breaks/11a.yaml`: the internet Gateway's model route, `inference/models-gw-inet`, patched to carry staff's path beside chat's (`route_rules`, the rules the render makes with staff's added, applied with `kubectl patch --type merge`). Every network layer is unchanged, so every packet tally stays zero; the layer that should have refused the request is the route set. The break records the route whole and the internet users' chat and staff cells tried as `matrix.sh` tries them; the broken modes are recorded before the exercise names them. `make heal-11a` patches the rendered rules back and checks the staff cell 404 and the chat cell allowed.
