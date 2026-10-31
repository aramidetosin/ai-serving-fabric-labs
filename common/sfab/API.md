# The sfab model API

This is the contract between the generator core (`spec.py`, `model.py`, `validate.py`) and everything that reads a lab's model: the renderers under `sfab/render/`, the stage scripts through `gen/inventory.json`, and the tests. Every example value below is what profile A (Tarnwick) produces today; `common/bin/sfab show <labdir> json` prints the whole model for any lab.

The core is Python 3.10 and the standard library, plus PyYAML inside `spec.py` only. Renderers import nothing outside the standard library and `sfab`.

## 1. Getting a model

Inside a renderer the registry hands you the model. Anywhere else:

```python
from sfab.spec import load, select

spec = load("/path/to/ai-serving-fabric-labs")      # the repo root, holding spec/
m = select(spec, "dev/m1")                           # a lab directory, its chapter.yaml, a Chapter, or a dict
m = select(spec, {"lab": "sfab-ch09", "profile": "a", "state": "many"})
m = select(spec, "ch12", variant="m")                # a key of the chapter's variants: mapping
```

`select()` returns a validated `Model` or raises one of:

| Exception | Module | Meaning |
|---|---|---|
| `SpecError` | `sfab.spec` | the spec or chapter.yaml is malformed (bad YAML, duplicate key, unknown key, bad `when:`, a reference to a node that does not exist) |
| `SelectError` (a `SpecError`) | `sfab.spec` | the selection cannot be honored: unknown slice token, a feature switched on, a printed device that lost an attachment, a placeholder profile |
| `ValidationError` | `sfab.validate` | the model breaks a rule of FRAMEWORK.md 2.5; `.problems` is a list of messages |
| `PortError` (a `ValueError`) | `sfab.ports` | a port number outside eth1 to eth56 |

From the shell, `common/bin/sfab show dev/m1 nodes` (or `links`, `ports [SWITCH ...]`, `dropped`, `features`, `budget`, `json`, or a dotted path such as `nodes.fe-sw1.mgmt`).

### 1.1 What selection does

1. Merge `spec/common.yaml` with `spec/profile-<x>.yaml` (`deep_merge`), then the variant overlay from `spec/variants/<file>.yaml` when one is named.
2. Pick the step. A `fixed` state (A/one) always uses its last step (7). A `cumulative` state uses the chapter number when it is one of its steps, else its last step: `sfab-ch09` in state `many` is step 9, `sfab-ch19` is step 11, `sfab-m1` in state `one` is step 7. A chapter.yaml may set `step:` explicitly.
3. Drop every element whose `when:` is false for that state and step (section 1.2).
4. Resolve features: the state's defaults (`states.<state>.features`), with the chapter's `features:` applied. A chapter may only switch a feature off, and `serving` and `storage_setup` need `k8s`.
5. Build the full model (every node of the state) and validate it, so a slice can never hide a spec error.
6. Compute the slice: the chapter's `slice.nodes` (node ids, group names, or `all`; the default is `all`) minus `slice.except`, plus the closure:
   - every node a feature that is on lists (`features.k8s.nodes`: k8s-cp1 to k8s-cp3, the bastion, the registry and the uplink router),
   - every node a kept node lists in `requires:`,
   - for a kept non-switch node, every switch its links land on,
   - for a kept switch in a pair, the pair partner.
   A node that the closure needs and `except:` removes is an error.
7. Build the sliced model. Links with an end outside the slice are dropped (`model.dropped`), and switch configuration is derived only from the links that remain. Port numbers never move: k8s-cp1 is eth4 (Ethernet3) on both pair switches in every lab.
8. Refuse if a device in `prints:` lost any link, then validate the sliced model.

### 1.2 The `when` grammar

`when:` is a string: one or more terms joined by `|`, each term a state name or `state<op>step` with op one of `>= <= == != > <`. There is no eval.

```python
from sfab.spec import when
when("one", "one", 7)              # True
when("many>=9", "many", 8)         # False
when("one | many<=8", "many", 8)   # True
when(None, "many", 11)             # True: no when means every state of the profile
```

An element is a mapping inside a list, or a mapping that is the value of a key (a node under `hosts:`). `filter_when(tree, state, step)` removes elements whose `when:` is false and strips the `when` key from the rest; the model never shows `when`.

### 1.3 `deep_merge(base, over)`

Mappings merge key by key. Lists whose elements are all mappings with an `id` merge by id: a known id is deep-merged in place, a new id is appended, and `{id: x, _delete: true}` removes element x. A mapping value `{_delete: true}` removes its key. Any other overlay value replaces the base value. Neither input is changed.

## 2. The renderer contract

A renderer is the module `sfab/render/<name>.py` exporting:

```python
def render(model, ctx) -> dict[str, str | bytes]:
    ...
```

The registry runs, in order: `clab, klish, expect, panos, host, frr, storage, dns, ca, k8s, trace, drills, decisions, inventory`. `trace` writes `gen/trace.json` only for chapter 4's form of the trace block (`sessions:` and `pull:`) and chapter 5's (`rails:`), resolved against the model. `drills` reads the chapter, not the spec: chapter.yaml's `drills:` block becomes `gen/drills.json` and the lab's `breaks/<id>.yaml` files `gen/breaks.json`, each resolved against the inventory (FRAMEWORK.md 4.6, 4.7); a lab with neither gets neither file. `decisions` writes `gen/decisions.yaml`, `gen/decisions.json`, `gen/matrix.yaml` and `gen/matrix.json` only for a lab whose chapter.yaml says `decisions: true` (chapter 2 on): the spec's `decisions:` and `matrix:` blocks resolved against the model (FRAMEWORK.md 2.2, 4.8); in such a lab `panos`, `klish`, `dns`, `inference` and `k8s` also stamp a decision label on every object of the table's rows and on every switch, through `decisions.label_of`. A module that does not exist yet is skipped with a warning (and listed under `generator.renderers.skipped` in RENDER.json), so the core runs while renderers are being written. A module that exists but fails to import, or raises, stops the render.

Rules every renderer follows:

- **Return, never write.** Keys are posix paths relative to the lab's output directory; values are the file contents. A path must be `topo.clab.yml`, or under `bootstrap/` or `gen/`. Two renderers may not return the same path. `gen/RENDER.json` is reserved.
- **Byte-stable.** No timestamps, no random values, no dependence on dict order from outside the model, sorted keys in every JSON (`json.dumps(..., indent=2, sort_keys=True) + "\n"`), a trailing newline on every text file, `\n` line endings. The DNS SOA serial is derived from the zone content.
- **No secrets.** Credentials are `${SFAB_*}` references (containerlab expands them from `state/secrets.env`) or files bound from `state/secrets/`. Nothing a renderer returns may contain a password, key or token.
- **Gate on features.** `model.features` holds `k8s`, `serving`, `storage_setup`. The Gateways, audiences, populations, models and DNS views are in the model even when `k8s` is off (the firewall rules reference their addresses); a renderer that deploys them checks the feature. `model.k8s` is `None` when `k8s` is off.
- **Use the model, not the spec file.** If a field you need is missing, `node.props` holds the node's raw spec entry and `model.spec` the merged, when-filtered profile tree; use them sparingly and say so in a comment, so the field can be promoted into the model.
- **Prose in generated comments** is plain English, no em or en dashes.

`ctx` is a `sfab.render.Context`:

| Field or method | Meaning |
|---|---|
| `ctx.outdir` | where this render lands (the lab directory, `<labdir>/variants/<key>/` for a variant, or a temporary directory during `sfab check`) |
| `ctx.labdir` | the lab's directory, holding chapter.yaml |
| `ctx.root` | the repo root |
| `ctx.spec` | the loaded `Spec` (`ctx.spec.versions`, `ctx.spec.known`, `ctx.spec.normalize`) |
| `ctx.profile_file(model)` | `"spec/profile-a.yaml"`, for header comments |
| `ctx.rel(path)` | a path relative to the repo root |
| `ctx.warn(msg)` | a warning printed by `sfab render` |

The KLISH header line the launcher skips (FRAMEWORK 2.3) is built from the model: `f"! {model.lab} {sw.name}: rendered from {ctx.profile_file(model)}; edit the spec and run make render"`.

**KLISH lint hook.** `sfab lint` calls `sfab.render.klish.lint(lines: list[str]) -> list[str]` on each rendered `bootstrap/<sw>/startup-config.cfg` when the klish module defines it; each returned string is one problem.

**Writing and checking.** `render_all(model, ctx)` returns a `RenderResult(outputs, present, skipped, warnings)`; `write_outputs(outdir, outputs)` writes changed files only and removes files the previous `gen/RENDER.json` listed that are no longer produced. `sfab check` renders into a temporary directory and compares byte for byte with the committed files (RENDER.json is compared without its `generator` block). Exit codes: 0 clean, 1 drift or lint problems, 2 spec, selection or validation error, 3 PyYAML missing.

## 3. Conventions

- **Addresses are strings.** A *CIDR* is an interface address with its length (`"10.20.1.21/24"`); a *bare* address has none (`"10.20.1.1"`); a *prefix* is a network (`"10.20.1.0/24"`). Each field's comment says which. `sfab.addr` converts between them.
- **Ports.** Container ports are `"ethN"` strings with an `index` int beside them. Switch native names come from `sfab.ports.native(N)`: eth1 is Ethernet0, eth48 Ethernet47, eth49 Ethernet48, eth50 Ethernet52, eth56 Ethernet76. The PA-VM's ethernet1/N is container ethN.
- **Immutability.** Every dataclass is frozen; sequences are tuples; mappings are plain dicts that you must not change.
- **Order.** `model.nodes` is in spec order: switches, then appliances, then hosts, each as written. Links are sorted by (a node, a port number, b node, b port number). VLANs, PortChannels, access ports and NICs are sorted by number.
- **Metadata.** `decision` is the decision id (always `dec-...`) chapter 2 stamps into PAN-OS rule descriptions, HTTPRoute labels, NAD annotations, zone-file comments and the placement table; `since` is the chapter that teaches an element (metadata only).
- **Names.** Container names are `<lab>-<node>` (`sfab-m1-fe-sw1`); the containerlab directory is `clab-<lab>`.

## 4. `Model`

| Field | Type | Example (sfab-m1 unless noted) |
|---|---|---|
| `lab` | str | `"sfab-m1"`; a variant appends its key (`"sfab-ch12m"`) |
| `profile`, `build` | str | `"a"`, `"A"` |
| `state`, `step` | str, int | `"one"`, `7` |
| `variant` | str or None | the variant key |
| `features` | dict[str, bool] | `{"k8s": False, "serving": False, "storage_setup": False}` |
| `org` | `Org` | Tarnwick |
| `mgmt` | `Mgmt` | the management network |
| `segments` | dict[str, `Segment`] | every prefix of the addressing plan, by id |
| `vlans` | dict[int, `Vlan`] | 100, 200, 300, 90, 101 to 108 |
| `rails` | dict[int, `Rail`] | 1 to 8 |
| `nodes` | dict[str, `Node`] | every node in the slice: `Switch`, `Firewall`, `Storage` or `Host` |
| `pairs` | dict[str, `Pair`] | `"fe"` |
| `links` | tuple[`Link`] | every wire in the slice |
| `dropped` | tuple[`Link`] | links of kept nodes the slice dropped (empty for an unsliced lab) |
| `gateways` | dict[str, `Gateway`] | `gw-internal`, `gw-users` (and `gw-inet` from step 8) |
| `audiences` | dict[str, `Audience`] | `internal`, `enterprise` (and `internet`) |
| `populations` | dict[str, `Population`] | `operator`, `nodes`, `enterprise` (and `internet` from step 9) |
| `models` | dict[str, `ServedModel`] | `chat`, `staff` |
| `placement` | tuple[`PlacementRow`] | one row per pod, all models |
| `dns` | `Dns` or None | |
| `ca` | `Ca` or None | |
| `k8s` | `K8s` or None | None unless `features["k8s"]` |
| `registry` | `Registry` or None | None unless the registry node is in the slice |
| `common` | dict | `kinds`, `switch`, `host`, `guest`, `timeouts`, `harness`, `naming` from common.yaml |
| `warnings` | tuple[str] | for example `"lan-dns: pending: ..."` |
| `spec` | dict | the merged, when-filtered profile tree before slicing (read-only escape hatch) |
| `meta` | `Meta` | lab, profile, variant, variant_file, state, step, chapter (`sfab.spec.Chapter`), features, versions, known, normalize, spec_files, root |

Typed views (properties, each a dict by name in spec order): `switches`, `hosts`, `appliances`, `storage`, `routers` (hosts of kind `frr`), `guests` (hosts of kind `vm-node`); `firewall` is the one `Firewall` or None. `prefix` is `"<lab>-"`, `clabdir` is `"clab-<lab>"`.

Methods:

| Method | Returns |
|---|---|
| `node(name)` | the node; KeyError naming the lab when absent |
| `container(name)` | `"sfab-m1-k8s-gpu1"` |
| `links_of(name)` | links with an end on that node |
| `link_at(node, eth)` | the link on that port, or None (`eth` is `"eth4"` or `4`) |
| `peer(node, eth)` | the far `End`, or None: `m.peer("fe-sw1", 3)` is `End("fw", "eth1")` |
| `pair_members(switch)` | the switch's pair members present in the lab (including itself) |
| `by_role(role)`, `by_group(group)`, `by_kind(kind)` | tuples of nodes |
| `segment_of(address)` | the most specific `Segment` holding an address or prefix |
| `to_json()` | the model as JSON-ready data (what `sfab show` prints) |

## 5. Value types

**`Org`**: `name` (`"Tarnwick"`), `domain` (`"tarnwick.example"`), `short` (`"tw"`), `label_domain` (`"tarnwick.example"`).
- `label_key(name, prefix=None)`: `label_key("control", "node-role")` is `"node-role.tarnwick.example/control"`; `label_key("lb-pool")` is `"tarnwick.example/lb-pool"`.
- `fqdn(label)`: `fqdn("llm")` is `"llm.tarnwick.example"`.
- `route_id(model_name)`: uuid5 (URL namespace) over `https://tarnwick.example/models/<name>`; `route_id("chat")` is `"a48b3df9-3b7f-58f0-9c52-c6f3004f05f7"`.

**`Mgmt`**: `network` (`"sfab-a-mgmt"`, the docker network), `subnet` (`"172.21.40.0/24"`), `gw` (bare, `"172.21.40.1"`, the docker bridge), `bridge`, `prefixlen` (24); `addr(octet)` gives a bare management address.

**`Segment`**: `id`, `prefix`, `scope` (`internal` must be RFC 1918, `external` RFC 5737 or RFC 3849, `mgmt` the management network), `vlan` (int or None), `desc`, `per_port` (the prefix length of per-router-port subnets, 30 on the operator segment), `node_local` (the relay), `reserved` (declared, nothing assigned yet: the IPv6 blocks), `within` (the segment it sits inside), `since`; `host(n)` gives the bare n-th address and `cidr(n)` the CIDR. Profile A's segments: `mgmt`, `data`, `stor-mgmt`, `bastion`, `oob`, `rail1` to `rail8`, `relay`, `pods`, `services`, `enterprise`, `uplink`, `operator`, `v6-org`, and from step 9 `isp`, `internet`, `v6-public`.

**`Vlan`**: `id`, `name`, `segment`, `prefix`, `gw_node` (`"fw"`), `gw_iface` (`"ae1.100"`), `gw` (bare `"10.20.1.1"`; None on rails), `decision`, `since`. VLAN 90 is the out-of-band VLAN with its gateway `10.20.9.254` on `ethernet1/3`. A host's `gateway`, its bond's and its out-of-band NIC's are the VLAN's `gw` only while `gw_node` is in the slice; in a slice without the firewall (chapter 5's) they are None.

**`Rail`**: `r`, `vlan` (`100 + r`), `segment` (`"rail3"`), `prefix` (`"10.21.3.0/24"`), `switch` (the rail switch carrying it: odd rails on rail-sw1, even on rail-sw2), `parity` (`"odd"` or `"even"`).

**`End`**: `node`, `eth` (`"eth4"`), `index` (4); `str(End)` is `"k8s-cp1:eth4"`. Ends sort by node then eth string.

**`Link`**: one wire.

| Field | Meaning |
|---|---|
| `id` | `str(a)`, unique: `"k8s-gpu1:eth1"`, `"fe-sw1:eth1"` |
| `a` | the attaching node's end (the host or appliance; for a peer link the pair's first member) |
| `b` | the switch end, or the declared peer node's end |
| `kind` | `peer-link`, `bundle` (an MCLAG PortChannel member), `access`, `rail`, `oob` (access ports on the rail and out-of-band switches), `p2p` (between two non-switch nodes) |
| `attachment` | `"<owner>.<attach id>"`: `"k8s-gpu1.bond"`, `"fw.ae1"`, `"truenas1.data"`, `"fe.peer-link"`, `"k8s-gpu1.rail3"` |
| `pc` | the switch-side PortChannel id (peer-link and bundle) |
| `mode` | `access` or `trunk`, on the switch side |
| `vlans` | access: one VLAN; trunk: the allowed list |
| `mtu` | the switch-side MTU when set (`9216` on the firewall bundle), else None for the factory 9100 |
| `rail` | rail number on rail links |
| `decision`, `since` | |

Methods: `has(node)`, `has_any(names)`, `end(node)`, `other(node)`.

**`Nic`**: one connected port of a node. `node`, `eth`, `index`, `role`, `attachment`, `peer` (the far `End`), `link` (the link id), and optional `native` (switches), `ifname` (VM guests: `"rail3"`; PA-VM: `"ethernet1/4"`), `desc` (switches: the port description), `mac` (VM guests only), `mtu`, `vlan`, `vlans`, `rail`, `address` (CIDR, when the NIC itself holds one), `gateway`. Roles:

| Role | Where |
|---|---|
| `peer-link` | a pair switch's peer-link member |
| `bundle-member` | a switch port in an MCLAG PortChannel, and the firewall's ae1 members |
| `access`, `rail`, `oob` | a switch access port (the role is the link kind), and the far end on hosts for `rail` and `oob` |
| `bond-member` | a host's or TrueNAS's bond member |
| `p2p` | a routed port between two non-switch nodes |

**`Budget`**: `mem_gib`, `vcpus`, `state_gib`, `layer_gib` (floats), from common.yaml `kinds` or, where the kind's value is null (vm-node), the node's own entry. Planning figures for preflight. The disk budget is expected growth, never a disk's virtual size (FRAMEWORK.md 3.1): `state_gib` under the lab's `state/`, `layer_gib` in the node's container layer under Docker's data root. A VM guest's root disk size is `Host.disk_gib`, not a budget.

**`Route`**: `dest` (prefix), `via` (bare next hop, or a symbol), `dev`, `src` (bare), `id`, `first` (install before anything else), `dest_ref` and `via_ref` (the spec's references when it wrote them as such, else None), `decision`, `since`. The one symbol today is `via: "qemu-user"` on TrueNAS: the vrnetlab VM's user-mode NIC gateway, which only the storage setup script knows. A host's route may write `dest: seg:<segment>` (resolved to the segment's prefix) and `via: public` (the firewall's public address): the uplink router's routes to the inside prefixes, which carry the operator's forbidden requests to the firewall from chapter 4 on, are written that way, `Route(dest="10.20.1.0/24", via="198.51.100.2", id="inside-data", dest_ref="seg:data", via_ref="public", decision="dec-route-inside-via-fw", since=4)`, and `render/frr.py` renders such a route only while the firewall gateways that segment in the lab.

## 6. Nodes

Every node has these `Node` fields:

| Field | Example |
|---|---|
| `name` | `"fe-sw1"` |
| `kind` | spec kind: `dell_sonic`, `paloalto_panos`, `truenas`, `vm-node`, `bastion`, `client`, `resolver`, `frr`, `registry` |
| `clab_kind` | `dell_sonic`, `paloalto_panos`, `generic_vm` (TrueNAS, ONTAP) or `linux` |
| `image` | `"vrnetlab/dell_sonic:4.6.0"` (from versions.yaml) |
| `image_key` | `"dell_sonic"` (the key in versions.yaml `images:`) |
| `section` | `switches`, `appliances` or `hosts` |
| `group` | the slice group: `fe`, `rail`, `oob`, `fw`, `storage`, `ctrl`, `gpu`, `bastion`, `uplink`, `enterprise`, `internet` |
| `role` | switches: `mclag_member`, `rail_vlan`, `oob_access`; vm-node: its group (`ctrl`, `gpu`); otherwise `firewall`, `storage`, `bastion`, `client`, `resolver`, `router`, `registry` |
| `mgmt`, `mgmt_octet` | `"172.21.40.11"`, `11` |
| `container` | `"sfab-m1-fe-sw1"` |
| `budget` | `Budget` |
| `nics` | tuple[`Nic`] sorted by index; `nic(eth)` finds one, `eths` lists their names |
| `requires` | nodes the slice closure pulls in with this one |
| `decision`, `since` | |
| `pending` | free text when the spec has not settled the node yet (lan-dns from step 9) |
| `props` | the node's raw spec entry |

### 6.1 `Switch` (kind `dell_sonic`)

| Field | Meaning |
|---|---|
| `pair`, `partner` | `"fe"`, `"fe-sw2"` for a pair member, else None |
| `vlans` | sorted VLAN ids to create (`interface Vlan N`, no address): a pair member's trunk VLANs plus any VLAN its ports use; a rail switch's four rail VLANs; the out-of-band switch's VLAN 90 |
| `portchannels` | tuple[`PortChannel`] sorted by id |
| `access_ports` | tuple[`AccessPort`] sorted by port |
| `mclag` | `MclagDomain` or None |
| `keepalive` | `Keepalive` (a pair member's two keepalive paths) or None |
| `stp` | `"pvst"` under the spec's `l2:` policy (the pair and the rail switches), else None |
| `rails` | `(1, 3, 5, 7)` on rail-sw1 |
| `oob_vlan` | `90` on oob-sw |
| `num_nics` | NUM_NICS: the highest port in this slice, or 56 with sFlow |
| `passthrough` | CLAB_MGMT_PASSTHROUGH; true on both pair members, the harness's management access (validate refuses its absence only on a member whose keepalive would ride VRF mgmt) |
| `sflow` | false everywhere in build A |
| `mgmt_vrf` | `"mgmt"` |
| `used_ports` | tuple of port numbers in use |

Methods: `port(eth)` (the `Nic`), `portchannel(pc)`.

**`PortChannel`**: `id`, `name` (`"PortChannel10"`), `desc` (`"peer-link"`, `"fw-ae1"`, `"k8s-gpu1-bond"`, `"truenas1-data"`), `kind` (`peer-link` or `mclag`), `mode` (`trunk` or `access`), `vlans` (trunk allowed list or `(vlan,)`), `vlan` (access VLAN or None), `mclag` (true: type `mclag <domain>` under it), `fast_rate` (always true), `mtu` (None means the factory 9100 and no mtu line), `members` (tuple[`Member`]), `peer_node` (`"fw"`; None on the peer link), `attachment`, `decision`, `tagged`, `edge` (host-facing under the l2 policy: `spanning-tree portfast` and `bpduguard port-shutdown`; never the peer link or the firewall's trunk), `storm` (`((type, kbps), ...)` typed on each member). The peer link's `vlans` hold the backup keepalive's VLAN (3966) beside the served VLANs; the switch's `vlans` do not.

**`Member`**: `eth` (int), `ifname` (`"eth3"`), `native` (`"Ethernet2"`), `desc` (`"fw-eth1"`, `"peer-link-1"`), `peer` (`End`), `mtu` (the PortChannel's).

**`AccessPort`**: `eth`, `ifname`, `native`, `vlan`, `desc` (`"truenas1-eth5"`, `"k8s-gpu1-rail3"`, `"k8s-gpu1-eth3"`), `kind` (`access`, `rail`, `oob`), `peer`, `rail`, `decision`, `mtu` (9216 under the l2 policy), `edge`, `storm`.

**`MclagDomain`**: `domain` (1), `source_ip` (this switch's address on the dedicated keepalive link, `"10.20.255.0"` on fe-sw1), `peer_ip` (the partner's), `peer` (partner name), `peer_link` (`"PortChannel1"`), `peer_link_pc` (1), `system_mac` (`"02:5a:00:00:00:01"`), `session_vrf` (`"VrfMclagKa"`), `backup_source_ip` and `backup_peer_ip` (`"10.20.255.4"`, `"10.20.255.5"` on fe-sw1), `backup_vrf`, `backup_interval` (1). It is None when the partner is not in the lab. A pair with no `keepalive:` block keeps the old form: the management addresses in VRF `session_vrf`.

**`Keepalive`**: `vrf`, `eth` (13), `ifname` (`"eth13"`), `native` (`"Ethernet12"`), `address` (`"10.20.255.0/31"`), `peer_address`, `mtu`, `backup_vlan` (3966), `backup_address` (`"10.20.255.4/31"`), `backup_peer`, `backup_interval`, `segment` (`"pair-keepalive"`). From the spec's `pairs.<p>.keepalive: {vrf, segment, link: {eth, prefix}, backup: {vlan, prefix, interval}}`: each prefix a /31 inside the segment, the first member taking the first address; the backup VLAN below 3967 (SONiC 4.6.0 reserves 3967 to 4094); the VRF name starting with Vrf.

Example, sfab-m1 fe-sw1 (`sfab show dev/m1 ports fe-sw1`):

```
eth1  Ethernet0  peer-link      fe-sw2:eth1  100,200,300  PC 1   peer-link-1
eth2  Ethernet1  peer-link      fe-sw2:eth2  100,200,300  PC 1   peer-link-2
eth3  Ethernet2  bundle-member  fw:eth1      100,200,300  PC 10  fw-eth1      (trunk, mtu 9216)
eth7  Ethernet6  bundle-member  k8s-gpu1:eth1    100          PC 21  k8s-gpu1-eth1    (access)
eth8  Ethernet7  bundle-member  k8s-gpu2:eth1    100          PC 22  k8s-gpu2-eth1    (access)
```

The full pair plan (state one, unsliced): eth1 and eth2 peer link (PortChannel1); eth3 firewall ae1 (PortChannel10, trunk 100,200,300, mtu 9216); eth4 to eth6 k8s-cp1 to k8s-cp3 (PortChannel11 to 13); eth7 and eth8 k8s-gpu1 and k8s-gpu2 (PortChannel21, 22); eth9 bastion (PortChannel30, VLAN 300); eth10 and eth11 TrueNAS's data bond (PortChannel31, two members per switch); eth12 TrueNAS management, fe-sw1 only (access VLAN 200). fe-sw1 uses 12 ports, fe-sw2 11. The out-of-band switch: eth1 k8s-gpu1, eth2 k8s-gpu2, eth3 firewall, eth4 to eth6 k8s-cp1 to k8s-cp3, eth7 bastion. The rail switches: k8s-gpu1 on eth1 to eth4 and k8s-gpu2 on eth5 to eth8, in the order of the switch's rails (rail-sw1 eth2 is k8s-gpu1's rail 3).

### 6.2 `Host` (kinds `vm-node`, `bastion`, `client`, `resolver`, `frr`, `registry`)

| Field | Meaning |
|---|---|
| `k8s` | `init`, `join-control`, `join-worker` or None |
| `index` | GPU node number n; its rail address is `.(10+n)` |
| `vlan` | the VLAN its primary address sits in (vm-node, bastion) |
| `address` | primary address, CIDR: the bond's, else the first addressed iface |
| `gateway` | default gateway, bare |
| `primary` | property: `address` without its length |
| `bond` | `Bond` or None |
| `oob` | `OobIf` or None |
| `rails` | tuple[`RailIf`] by rail (GPU nodes) |
| `relay` | `Relay` or None (GPU nodes) |
| `ifaces` | tuple[`Iface`]: addressed ports outside a bond (clients, resolvers, routers, the registry) |
| `routes` | tuple[`Route`]: static routes (isp-rtr's `198.51.100.2/32 via 198.51.100.10`; uplink-rtr's five inside prefixes via `198.51.100.2`) |
| `resolver`, `resolver_address` | the node it resolves through and that node's primary address (bare; None while that node is pending) |
| `dns_role` | `bind-views` (bastion), `bind-auth` (ops-dns, inet-dns), `dnsmasq` (lan-dns) |
| `resolv_options` | a resolv.conf options line when the spec asks for one |
| `mgmt_mac` | VM guests: eth0's guest MAC |
| `disk_gib` | VM guests: the root disk's virtual size in GiB (`VM_DISK_GIB`), not a budget; `None` otherwise |
| `tables` | `{"mgmt": 150, "oob": 100, "rail_base": 300}` |

The NIC convention for vm-node and the bastion (common.yaml `guest.nics`): eth1 and eth2 are the bond members (eth1 to the pair's first member), eth3 is out-of-band, and a GPU node's rails are eth4 to eth11 (rail r on eth(3+r)). VM guest MACs are `02:5a:<management octet in hex>:00:00:<NIC index in hex>`: k8s-gpu1 (management .111) has eth1 `02:5a:6f:00:00:01`, eth0 `02:5a:6f:00:00:00`.

**`Bond`**: `name` (`"bond0"`), `members` (`("eth1", "eth2")`), `pc` (the switch PortChannel, 21), `vlan` (100), `address` (`"10.20.1.21/24"`), `gateway` (`"10.20.1.1"`), `mtu` (9000), `mode` (`"802.3ad"`), `lacp_rate` (`"fast"`), `miimon` (100), `xmit_hash_policy` (`"layer3+4"`), `mac` (the first member's guest MAC; None on the bastion, a container).

**`OobIf`**: `eth` (`"eth3"`), `address` (the BMC address `10.20.9.<octet>/24`: k8s-gpu1 `10.20.9.21/24`, bastion `10.20.9.10/24`), `gateway` (`"10.20.9.254"`), `table` (100), `vlan` (90).

**`RailIf`**: `rail`, `vlan`, `eth` (`"eth6"` for rail 3), `ifname` (`"rail3"`, the guest NIC renamed by MAC), `address` (`"10.21.3.11/24"`, held by namespace gpu3, not by the NIC), `switch` (`"rail-sw1"`), `switch_eth` (`"eth2"`), `switch_native` (`"Ethernet1"`), `mac`.

**`Relay`**: `bridge` (`"relay0"`), `prefix` (`"10.21.250.0/24"`), `mtu` (9000), `rp_filter` (2, loose), `ip_forward` (1), `namespaces` (tuple[`RelayNs`]).

**`RelayNs`** (one per rail): `rail`, `ns` (`"gpu3"`), `rail_if` (`"rail3"`, a macvlan in the namespace) on `rail_master` (`"rail3"`, the guest NIC), `rail_addr` (`"10.21.3.11/24"`), `veth` (`"relay"`, in the namespace) whose peer `bridge_port` (`"rl3"`) is a port of the bridge, `relay_addr` (`"10.21.250.3/24"`), and `routes`: seven `Route`s, one per other rail, `dest` that rail's prefix, `via` the sibling namespace's relay address, `dev` `"relay"`, `src` the namespace's own rail address. No default route; the namespace forwards.

**`Iface`**: `eth`, `address` (CIDR), `gateway` (bare), `segment` (id), `peer` (`End` or None when unwired in this lab), `mtu`.

Build A hosts: k8s-cp1 to k8s-cp3 (data .11 to .13), k8s-gpu1 and k8s-gpu2 (data .21, .22), bastion (VLAN 300 .10), uplink-rtr (198.51.100.1/29 to the firewall, 192.0.2.1/30, .5/30 and .9/30 to its three customers), ops-client (192.0.2.2/30), inet-registry (192.0.2.6/30), ops-dns (192.0.2.10/30), ent-client (10.24.10.10/24); from step 9 isp-rtr (198.51.100.9/30, 203.0.113.1/30 and .5/30), inet-client (203.0.113.2/30), inet-dns (203.0.113.6/30), and lan-dns (pending: chapter 9 settles the enterprise LAN layout, so it has no wire and no address yet).

### 6.3 `Firewall` (kind `paloalto_panos`)

| Field | Meaning |
|---|---|
| `hostname`, `vr` | `"fw"`, `"core"` (the one routing instance) |
| `public`, `public_iface` | `"198.51.100.2"`, `"ethernet1/5"` |
| `interfaces` | tuple[`FwInterface`] in spec order, each aggregate followed by its members |
| `zones` | tuple[`Zone`] |
| `routes` | tuple[`FwRoute`] |
| `services` | tuple[`FwService`] |
| `rules` | tuple[`FwRule`], in rulebase order; `deny-all-log` is always last |
| `nat` | tuple[`FwNat`], in rulebase order |
| `system` | `FwSystem` |
| `admin` | `FwAdmin` or None |
| `addresses`, `groups` | tuple[`FwAddress`], tuple[`FwGroup`]: the named sources rules may reference (`addr:<name>`, `group:<name>`) |
| `profiles` | `FwProfiles`: the profile group every allow rule carries and the zone protection profile |
| `default_rules` | `{"intrazone-default": {"action": "deny", "log_end": True}, "interzone-default": {...}}`: the predefined rules overridden |
| `crypto`, `vpns` | tuple[`FwCrypto`], tuple[`FwVpn`]: the IKE and IPsec crypto profiles and the tunnels the firewall terminates |
| `app_default` | `{App-ID: ("tcp/443", ...)}` from `panos.app_default` (common.yaml): the default ports `application-default` matches on |

Methods: `interface(name)`, `zone(name)`.

**`FwInterface`**: `name` (`"ae1"`, `"ae1.100"`, `"ethernet1/3"`, `"tunnel.1"`), `kind` (`aggregate`, `aggregate-member`, `subinterface`, `layer3`, `tunnel`), `eth` (container port for ethernet1/N, else None), `parent`, `members`, `tag`, `address` (CIDR), `zone`, `mtu`, `lacp`, `vlan`, `connected` (its wire, or a member's, is in this lab; a tunnel interface while the interface its VPN rides on is), `since`.

Build A interfaces: ae1 over ethernet1/1 and 1/2 (MTU 9216) with ae1.100 `10.20.1.1/24` (zone k8s-nodes, MTU 9000), ae1.110 `10.20.11.1/24` (ingress), ae1.200 `10.20.2.1/24` (stor-mgmt), ae1.300 `10.20.3.1/24` (bastion), ae1.130 and ae1.131 (services), each at MTU 1500; ethernet1/3 `10.20.9.254/24` (oob); ethernet1/4 `10.24.10.9/30` and ethernet1/7 `10.24.10.54/30` (enterprise); ethernet1/5 `198.51.100.2/29` (uplink, with zone protection); tunnel.1 (operator-vpn); from step 9 ethernet1/6 `198.51.100.10/30` (isp).

**`Zone`**: `name`, `interfaces` (names), `decision`, `since`, `zone_protection` (the profile name, or None).

**`FwRoute`**: `name`, `dest`, `nexthop` (bare, or None), `interface` (None for a discard route), `metric`, `since`, `kind` (`ip`, `interface` for a route out a tunnel interface, `discard`), `dest_ref` (`"seg:operator-site"` when written as a reference). Build A: `default-uplink` 0.0.0.0/0 via 198.51.100.1 on ethernet1/5; `operator-site` 192.0.2.0/30 out tunnel.1; `discard-10`, `discard-172-16`, `discard-192-168`; from step 10 `isp-customers` 203.0.113.0/26 via 198.51.100.9 on ethernet1/6.

**`FwService`**: `name`, `protocol`, `port` (string): tcp-443 (the step-10 DNAT), tcp-5000 (the registry), tcp-6443 (the API server), tcp-4460 (NTS-KE). A rule may also name `any` (deny-all-log only) or `application-default` (the default for a rule that names App-IDs).

**`FwRule`**: `name`, `from_zones`, `to_zones` (tuples; `any` allowed), `src`, `dst` (the references as written), `src_cidrs`, `dst_cidrs` (resolved prefixes, or `("any",)`), `services` (`("application-default",)` unless a non-default port names one), `applications` (App-IDs; `("any",)` only on a deny rule), `action` (`allow` or `deny`), `log_end` (always true), `decision`, `since`, `desc`, `src_members`, `dst_members` (what the rule prints: an object or group name, else a bare prefix), `profile_group` (`"bp-default"` on every allow rule), `src_parts`, `dst_parts` (per reference: the reference, its prefixes and its members, which the slice prunes by).

**`FwNat`**: `name`, `from_zones`, `to_zones` (pre-NAT zones), `src`, `dst`, `src_cidrs`, `dst_cidrs`, `service` (one name or `any`), `dnat` (translated destination, bare) and `dnat_ref` (as written), `dnat_port`, `snat_type` (`dynamic-ip-and-port`) and `snat_interface` (`ethernet1/5`), `decision`, `since`.

**`FwSystem`**: `dns`, `ntp` (bare addresses: dns-res1 and dns-res2, `10.20.13.21` and `10.20.14.21`), `service_route` (`"ae1.130"`: the firewall's own DNS and NTP leave by the services interface, which has no management profile).

**`FwAdmin`** (chapter 4): `interface` (`"ae1.300"`), `profile` (`"bastion-admin"`), `allow` (`("https", "ssh", "ping")`), `permitted` (`("node:bastion",)`) and `permitted_cidrs` (`("10.20.3.10/32",)`), `since`. The interface takes that management profile; every other layer 3 interface takes `ping-only`.

**`FwAddress`**: `name`, `prefix`, `ref`, `desc` (`ent-client`, `operator-site`, and `collector` 10.20.3.20/32, reserved for chapter 20). **`FwGroup`**: `name`, `members`, `cidrs`, `desc` (`admins`: ent-client and operator-site).

**`FwProfiles`**: `group` (`"bp-default"`), `virus`, `spyware`, `vulnerability` (`"default"`), `file_blocking` (`"basic file blocking"`), `zone_protection` (`"zp-internet"`), `zp_flood` (per flood type its RED or SYN-cookie rates), `zp_discard` (`("ip-spoof", "malformed-option", "strict-ip-check")`).

**`FwCrypto`**: `name`, `kind` (`ike` or `ipsec`), `encryption`, `hash`, `dh`, `lifetime_h`. **`FwVpn`**: `name` (`"ops-gw"`), `interface` (`"ethernet1/5"`), `local` (its CIDR), `peer` (`"192.0.2.22"`) and `peer_node` (`"ops-gw"`), `tunnel_interface` (`"tunnel.1"`), `ike_crypto`, `ipsec_crypto`, `psk` (the key's name under state/secrets/ipsec, never the key), `proxy_ids` (`(("ingress", "10.20.11.0/24", "192.0.2.0/30"), ("bastion", "10.20.3.0/24", "192.0.2.0/30"))`), `zone`, `since`. render/panos.py keeps the IKE gateway and the IPsec tunnel out of the startup file and writes bootstrap/fw/vpn.json, which boot sets through the API with the key.

Address references in rules and NAT resolve as: `any`; `public` (the public address /32); `vip:<gateway>` (that Gateway's VIP /32); `seg:<segment>` (the segment's prefix); `node:<host>` (the host's primary address /32); `mgmt:<storage>` (its management address /32); `fw:<interface>` (one of the firewall's own interface addresses /32, the gateway a segment's hosts ping); `addr:<name>` and `group:<name>` (the objects above); or a literal prefix or address. Example:

```python
FwRule(name="staff-to-users-gateway", from_zones=("enterprise",), to_zones=("ingress",),
       src=("seg:enterprise",), dst=("vip:gw-users",), src_cidrs=("10.24.10.0/24",),
       dst_cidrs=("10.20.11.210/32",), services=("application-default",), applications=("ssl",),
       action="allow", log_end=True, decision="dec-policy-enterprise-users", since=4,
       src_members=("10.24.10.0/24",), dst_members=("10.20.11.210",), profile_group="bp-default", ...)
```

Rules: state one has 21 rules, every allow rule with its App-IDs, `application-default` or one explicit service, and the profile group; no allow-any intrazone rule, no open egress, no public path to the internal Gateway; `deny-all-log` last, and the predefined intrazone and interzone rules set to deny with a log line. Step 10 adds `isp-to-internet-gateway`. NAT: from step 10 `dnat-internet-gateway`, then `no-nat-public` above `internet-snat` (from k8s-nodes and services, the allowlisted egress).

### 6.4 `Storage` (kinds `truenas`, `ontap`)

| Field | Example (truenas1) |
|---|---|
| `product` | `"truenas"` |
| `data` | `StorageIf(address="10.20.12.31/24", nics=("eth1","eth2","eth3","eth4"), vlan=120, mtu=9000, lacp={"rate": "fast", "hash": "layer3+4"})`: the four-leg bond on the storage VLAN, eth1 and eth2 to fe-sw1, eth3 and eth4 to fe-sw2 |
| `mgmt_if` | `StorageIf(address="10.20.2.31/24", nics=("eth5","eth6"), vlan=200, mtu=1500, lacp=...)`: the management bond, one leg on each pair switch |
| `gateway` | `"10.20.2.1"` |
| `routes` | `(Route(dest="172.21.40.0/24", via="qemu-user", id="mgmt-return", first=True),)` |
| `dns`, `ntp` | `("10.20.13.21", "10.20.14.21")` |
| `settings` | `{"pool": "tank", ..., "csi": {"user": "democratic-csi", "api": "mgmt", "classes": ["nvmeof", "nfs"], "default_class": "nvmeof"}}` |
| `address` | property: the data address |

The CSI driver calls the management address over HTTPS (`csi.api: mgmt`), through the firewall; NFS and NVMe/TCP run on the data address. TrueNAS's NIC MACs are the launcher's, so the setup maps bond members by reading them at run time.

## 7. Services above the network

**`Gateway`**: `name`, `audience`, `vip` (bare) and `vip_cidr` (/32), `pool_start`, `pool_end`, `pool_cidrs` (the pool as prefixes), `segment` (`"ingress"`), `hostnames` (listener FQDNs: the users' hostname on every Gateway, plus the admin hostnames on the Gateway whose audience is `admin`), `decision`, `since`.

| Gateway | VIP | Pool | Audience | Hostnames |
|---|---|---|---|---|
| gw-internal | 10.20.11.200 | .200 to .209 | internal | llm, admin, grafana (.ai.tarnwick.example) |
| gw-users | 10.20.11.210 | .210 to .214 | enterprise | llm.ai.tarnwick.example |
| gw-inet (step 8 on) | 10.20.11.220 | .220 to .224 | internet | llm.ai.tarnwick.example |

**`Audience`**: `name`, `gateway`, `models` (the model ids its route set lists: internal has all, enterprise `("chat", "staff")`, internet `("chat",)`), `admin` (its Gateway carries the bare /models/ prefix and the admin hostnames), `populations` (names whose audience this is), `decision`, `since`.

**`Population`**: `name`, `segments`, `prefixes`, `zones` (the firewall zones it arrives in), `audience`, `clients` (client node names), `resolver`, `resolver_address`, `answer` (`"public"` or `"vip:<gateway>"`) and `answer_address` (bare), `translated` (arrives through a DNAT), `decision`, `since`. Build A: `operator` (192.0.2.0/30, the site behind ops-gw, zone operator-vpn through the tunnel, resolver ops-dns, answer the internal VIP, untranslated), `web` (192.0.2.16/30, an internet host that is not the operator, zone uplink, audience none, answer the public address, where nothing is published), `nodes` (nodes and bastion, resolvers dns-res1 and dns-res2, answer the internal VIP), `enterprise` (10.24.10.0/24, resolver ent-dns, answer the users' VIP), `internet` (step 9 on: 203.0.113.0/26, zone isp, resolver inet-dns, answer the public address).

**`ServedModel`**: `name` (`"chat"`), `weights`, `route_id` (`Org.route_id`), `audiences`, `copies` (tuple[`Copy`]), `since`.

**`Copy`**: `model`, `name` (`"a"`), `rail`, `parity`, `server` (node), `workers` (nodes), `pods` (tuple[`PlacementRow`]), `decision`. A model's copies sit on rails of different parity (validate refuses otherwise): chat on rails 3 and 6, staff on rails 4 and 5; copy a's server runs on k8s-gpu1 with workers on k8s-gpu2 then k8s-gpu1, copy b the other way round.

**`PlacementRow`** (`model.placement`): `model`, `copy`, `role` (`server` or `worker`), `index`, `pod` (`"chat-a-server"`, `"chat-a-worker0"`), `node`, `rail`, `nad` (`"rail3"`), `decision`.

**`Dns`**: `zone` (`"tarnwick.example"`), `users` (`("llm.tarnwick.example",)`), `admin` (`("admin.tarnwick.example", "grafana.tarnwick.example")`), `wildcard` (`"*.tarnwick.example"`), `views` (tuple[`DnsView`]), `records` (tuple[`DnsRecord`], sorted by name: every node in the slice whose primary address is internal, `truenas1` and `truenas1-mgmt`, and `k8s` for the API VIP).

**`DnsView`**: `name`, `server` (the node serving it), `kind` (`bind-views`, `bind-auth`, `dnsmasq`), `match` (segment ids) and `match_cidrs`, `answer` and `answer_address` (what the users' and admin hostnames and the wildcard resolve to in this view), `recursion`, `infra` (the view holds the infrastructure records), `decision`, `since`. Build A: `internal` (bastion; data, bastion, stor-mgmt, oob; the internal VIP; recursion on), `enterprise` (bastion, through step 8; the users' VIP), `lan` (lan-dns, from step 9; the users' VIP), `public-operator` (ops-dns; the public address), `public-internet` (inet-dns, from step 9; the public address). The two public views serve identical zones.

**`DnsRecord`**: `name` (FQDN), `address` (bare), `kind` (`infra` or `api`).

**`Ca`**: `root_cn` (`"Tarnwick Lab Root CA"`), `intermediates` (tuple[`CaIntermediate`]), `proof_inside` (`("llm.tarnwick.example",)`), `proof_outside` (`("llm.corvane.example",)`).

**`CaIntermediate`**: `name` (`platform`, `kubernetes`), `cn`, `key` (`ec-p256`, `rsa-2048`), `dns` and `ip` (the name constraints: platform `tarnwick.example` with `10.20.0.0/14` and `10.24.10.0/24`).

**`K8s`** (None unless k8s is on): `version` (`"v1.35.8"`), `api_vip` (`"10.20.1.10"`), `api_fqdn` (`"k8s.tarnwick.example"`), `pod_cidr` (`"10.22.0.0/16"`), `service_cidr` (`"10.23.0.0/16"`), `init` (`"k8s-cp1"`), `control` and `workers` (node names in the slice), `gateway_class` (`"cilium"`), `labels` (`{"control": "node-role.tarnwick.example/control", "gpu": "node-role.tarnwick.example/gpu", "pool": "tarnwick.example/lb-pool", "audience": "tarnwick.example/audience", "decision": "decision.tarnwick.example/id"}`), `l2_announce` (`{"interfaces": ["^bond0$"], "nodes": "control"}`), `nads` (tuple[`Nad`]), `registry`.

**`Nad`**: `name` (`"rail3"`), `rail`, `master` (the guest NIC `"rail3"`), `prefix`, `range_start` and `range_end` (whereabouts, `.100` to `.199`, clear of the nodes' addresses), `decision`.

**`Registry`**: `node`, `address` (`"192.0.2.6"`), `port` (5000), `name`, `fqdn` (`"registry.tarnwick.example"`), `mirror` (`"192.0.2.6:5000"`).

**`Pair`** (`model.pairs`): `name`, `members`, `domain`, `system_mac`, `peer_link_pc`, `peer_link_eths`, `trunk_vlans`, `session_vrf`, `passthrough`, `decision`, `since`, `keepalive_eth` (`"eth13"`), `backup_vlan` (3966).

## 8. Helpers

`sfab.ports`:

| Function | Example |
|---|---|
| `native(n)` | `native(4) == "Ethernet3"`, `native("eth50") == "Ethernet52"` |
| `eth(n)`, `eth_index(x)` | `eth(4) == "eth4"`, `eth_index("eth4") == 4` |
| `from_native(name)` | `from_native("Ethernet52") == 50` |
| `standard(n)` | `standard(4) == "Eth1/4"` (reference only; configurations use native names) |
| `native_range(ns)` | `native_range([1, 2]) == "Ethernet0-1"` (contiguous, eth48 or below) |
| `num_nics(sw_or_ports, sflow=None)` | the highest port, or 56 with sFlow |
| `MAX_NICS` | 56 |

`sfab.addr`:

| Function | Example |
|---|---|
| `host(prefix, n)`, `host_cidr(prefix, n)` | `host("10.20.1.0/24", 21) == "10.20.1.21"`, `host_cidr(...) == "10.20.1.21/24"` |
| `host32(a)` | `"10.20.1.210/32"` |
| `prefix_of(cidr)` | `prefix_of("10.20.1.21/24") == "10.20.1.0/24"` |
| `ip(a)`, `iface(cidr)`, `net(prefix)` | parsed `ipaddress` objects (`ip` accepts a CIDR and drops the length) |
| `subnet(prefix, len, k)` | `subnet("192.0.2.0/26", 30, 1) == "192.0.2.4/30"` |
| `contains(prefix, x)` | address, CIDR or prefix inside prefix |
| `is_rfc1918`, `is_rfc5737`, `is_rfc3849`, `classify(x)`, `scope_ok(scope, x)` | the address-block checks |
| `in_slirp(x)` | touches 10.0.0.0/24 |
| `overlaps([(id, prefix), ...])` | overlapping id pairs |
| `mac(prefix, octet, index)` | `mac("02:5a", 111, 1) == "02:5a:6f:00:00:01"` |

`sfab.validate`: `validate(model)` raises `ValidationError`; `problems(model)` returns the list; each `check_*` function returns its own list (`check_segments`, `check_addresses`, `check_ports`, `check_num_nics`, `check_pairs`, `check_firewall`, `check_audiences`, `check_placement`, `check_labels`, `check_domains`, `check_mtu`).

What validate rejects: an internal address outside RFC 1918 or an outside one outside RFC 5737 or RFC 3849; an address in no declared segment; overlapping segments (a segment with `within:` must sit inside its parent); anything in 10.0.0.0/24; a port used twice; NUM_NICS above 56 (and sFlow without eth56); a pair member without passthrough or an MCLAG domain; a firewall rule, NAT rule or interface naming an unknown zone, service or interface; deny-all-log anywhere but last; an audience with no Gateway, a Gateway with no audience, overlapping pools, a VIP outside its pool; a model whose copies share a rail parity; a name, label value or DNS label over 63 characters; a domain not under `.example`, or a name not under the org domain; a PortChannel facing the firewall with an MTU below the firewall's units.

## 9. `gen/inventory.json` (for scripts)

Scripts read it with `common/bin/inv.py`, standard library only:

```
inv.py nodes --role mclag_member          # fe-sw1, fe-sw2 (one per line, inventory order)
inv.py nodes --kind vm-node               # also --group, --clab-kind, --section
inv.py containers --group gpu             # sfab-m1-k8s-gpu1 ...
inv.py get nodes.fe-sw1.mgmt              # 172.21.40.11
inv.py get watchdog.order                 # k8s-gpu2, k8s-gpu1 (one per line)
inv.py json budget                        # always JSON
```

It reads `--inv FILE`, else `$SFAB_INV`, else `./gen/inventory.json`; exit 1 means the path does not exist. Top-level keys (all sorted on disk):

| Key | Content |
|---|---|
| `schema` | 1 |
| `lab`, `prefix`, `clabdir`, `build`, `profile`, `state`, `step`, `variant`, `chapter`, `extends`, `prints` | identity |
| `org`, `mgmt` | as in the model |
| `features` | k8s, serving, storage_setup |
| `stages` | `switches`, `pairs`, `guests`, `fw`, `storage`, `bastion`, `fw_bootstrap`, `wait_fabric` (`mclag` or `none`), `guest_hold`, `ca_init`, `cluster`, `serving`, `storage_setup`, `modules` (common.yaml `host.modules`, then the `kinds.<kind>.modules` of every kind in the lab: `[bonding]` for M1, `[bonding, vrf]` once an FRR router is in the lab) |
| `nodes` | per node: `container`, `kind`, `clab_kind`, `section`, `role`, `group`, `mgmt`, `image`, `budget`, `eths`, `nics` (per eth: peer, role, link, and native, ifname, desc, mac, mtu, vlan, vlans, rail, address, gateway when set), `requires`, `pending`; switches add `num_nics`, `pair`, `partner`, `passthrough`, `sflow`, `vlans`, `rails`, `portchannels` (by name: id, kind, mode, vlans, mclag, mtu, peer_node, members (native), member_eths), `access` (by native name: eth, vlan, kind, peer, mtu, edge), `mclag` (with `backup`: source_ip, peer_ip, vrf, interval), `keepalive` (vrf, port, eth, address, peer_address, mtu, backup_vlan, backup_interface, backup_address, backup_peer), `stp`, `edge` (the edge PortChannels and ports), `storm` (`kbps` by type, `ports`); hosts add `address`, `gateway`, `vlan`, `k8s`, `resolver`, `resolver_address`, `dns_role`, `bond`, `oob`, `rails` (by rail number), `relay`, `ifaces`, and `guest_user` and `disk_gib` (the root disk's virtual size, `VM_DISK_GIB`) on VM guests; the firewall adds `public`, `public_iface`, `interfaces`, and as the lab renders it (`render/panos.py`'s view) `rules` and `nat` (rule names in order), `system` (`dns`, `ntp`, `service_routes` by service: `interface`, `address`, and `rule`, the render's rule that admits the service from that source) and `admin` (`interface`, `profile`, `allow`, `permitted`, or null); an FRR router with routes adds `routes` (`id`, `dest`, `via`, `dev`, `decision`, as its frr.conf carries them); storage adds `product`, `data`, `mgmt_if`, and `csi` (`user`, `api`, `classes`, `default_class`) when the spec gives it storage.csi |
| `order` | node names in model order |
| `roles`, `groups`, `kinds` | name lists by role, group and kind |
| `links` | id, a, b, kind, attachment, pc, mode, vlans, mtu, rail |
| `budget` | `mem_gib`, `floor_gib`, `need_gib`, `vcpus`, `vcpu_overcommit`, `state_base_gib` (common.yaml `host.state_base_gib`), `state_gib` (that plus every node's `state_gib`), `layer_gib` (every node's `layer_gib`) |
| `watchdog` | `order` (GPU guests highest-numbered first, then the other VM guests), `floor_gib` |
| `images` | per image reference: key, pulled, digest |
| `host`, `timeouts`, `harness`, `naming`, `switch`, `guest` | constants from common.yaml |
| `trace` | the chapter's `trace:` block as written (chapter 4's and chapter 5's forms are also rendered, resolved, to `gen/trace.json` by `render/trace.py`) |
| `known` | the KNOWN ids (L1 to L11) |
| `warnings` | the model's warnings |
| `gateways` | by name: `vip`, `pool` (first and last), `pool_cidrs`, `audience`, `hostnames`, `segment`, `decision` |
| `populations` | by name: `segments`, `prefixes`, `zones`, `audience`, `gateway` (the audience's), `clients`, `resolver`, `resolver_address`, `answer`, `answer_address`, `translated` |
| `dns` | `zone`, `users`, `admin`, `wildcard`, `records` (FQDN to address), `views` (by name: `server`, `kind`, `match_cidrs`, `answer_address`, `recursion`, `infra`); null without a DNS block |
| `k8s` | null with the cluster off; else `version`, `api_vip`, `api_fqdn`, `pod_cidr`, `service_cidr`, `init`, `control`, `workers`, `gateway_class`, `labels`, `l2_announce`, and from the spec `cilium_devices`, `gateway_namespace`, `test_backend` (`name`, `namespace`, `port`, `path`, `replicas`, `gateways`) |
| `registry` | null without the registry node; else `node`, `address`, `port`, `mirror`, `fqdn`, and from the spec `scheme`, `upstreams`, `charts` |
| `ca` | `root_cn`, `intermediates` (by name: `cn`, `key`, `dns`, `ip`), `proof_inside`, `proof_outside`, and from the spec `issuer`, `certificates` |
| `ntp` | `server`, its `address` when it is in the lab, `allow`, `local_stratum` |

`gen/RENDER.json` holds `files` (sha256 of every other output), `spec` (`files` with each spec file's sha256, and a combined `sha256`), `chapter` (path and sha256), `versions` (the images this lab uses, tools, kubernetes) and `generator` (`version`, the sha256 of the generator's own source, and `renderers` with `present` and `skipped`). `sfab check` compares everything except `generator`, so a generator change, or a renderer landing that writes nothing for a lab, is no drift.

## 10. What the spec does not settle yet

Renderers must not invent these; they come from the milestone or chapter that owns them.

- **The enterprise LAN from step 9.** lan-dns has `pending` set, no wire and no address. The ch09 lab chooses a SONiC access switch or a router port per host (FRAMEWORK 1.5).
- **The firewall's management port on the out-of-band network** (chapter 4, settled as built). The PA-VM's own management interface stays on the containerlab network (`fw.mgmt`), where vrnetlab and the harness reach it; the chapter's administrative access is `Firewall.admin`, a profile on ethernet1/3 permitted from the out-of-band segment, with the service routes on the same interface.
- **Image digests and several Kubernetes pins** are null or `status: open` in versions.yaml; M1 and M2 record them.
- **Profile b** is a placeholder: org, management network and addressing only. `select()` refuses it.
- **Variants** render into `<labdir>/variants/<key>/`; no variant file exists yet.
