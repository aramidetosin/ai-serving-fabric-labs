# Framework


## 0. Constraints the design follows

- **One platform per layer:**
  - Switches: SONiC 4.6.0, kind `dell_sonic`, KLISH only.
  - Hosts: Linux, with FRR wherever a host speaks BGP.
  - Kubernetes: kubeadm with Cilium, the Gateway API and Multus.
  - Edge: PA-VM 12.1.2.
  - Carrier WAN: FRR.
  - Storage: TrueNAS in build A, ONTAP in build B.
  - Drills fail ports with KLISH `shutdown`. They never use `docker pause`, and never take a link down from the container side.
  - Flows are placed by IP address.
  - No Linux bridge stands in for a switch.
- **Labs ship complete:**
  - Each chapter commits its rendered topology and per-node bootstrap files.
  - `make up` works from a clean clone.
  - Every lab ships `audit.sh` and `trace.sh`.
  - Result sets, with `TRACE.md` and the capture decodes, are committed under `chNN/audits/`.
  - Platform quirks live only in lab READMEs.
- **Names and addresses:**
  - Build A is Tarnwick (`tarnwick.example`). Every serving name and every platform host lives in the delegated zone `ai.tarnwick.example` (`org.zone`); the corporate apex `tarnwick.example` holds only the enterprise's own hosts and no wildcard. Build B is Corvane (`corvane.example`).
  - Addresses facing the internet come from RFC 5737 (and RFC 3849 for IPv6). Everything inside a build uses RFC 1918.
  - Switch interfaces keep native names.
  - No private name, host, domain, path, address prefix or credential appears anywhere. `make namecheck` checks this against a scrub list and a file of credential literals, both kept outside the repository (4.4).
- **What this design settles for the labs:**
  - The host tick: preflight reads and records it, wants 10000 and never refuses on it (3.1).
  - The addressing plan: section 1.5.
  - DNS and time live inside the lab on their own hosts: an authoritative pair (dns-auth1 primary, dns-auth2 secondary over TSIG, views keyed by the asking resolver), two recursive resolvers that also serve time (dns-res1, dns-res2, chrony with NTS to an upstream reference, inet-ntp), and the enterprise's corporate resolver stand-in (ent-dns). The CA lives on the lab host, outside every node (`common/ca/sfab-ca`): a root, intermediates for the platform, Kubernetes and the lab's internet, and node leaves for the registry and the time reference. The bastion is a jump host only.
  - The identity guard (3.1, 4.1).
  - Interface naming: native names, as above.

## 1. Repository layout

The tree is the whole design. Built so far: `platform/`, `serving-layer/` (the recipe and its image, unit-tested, and deployed by chapter 6's recorded lab), `spec/` without `variants/` (profile B holds only its organization, management network and addressing plan), the framework core in `common/` (6.1), the `vm-node`, `client`, `bastion`, `frr` and `registry` images, the `resolver` image (chapter 7's recorded lab is the first to run it), the `serving` and `keys` images and Multus in the cluster render, `dev/m1`, `dev/m2`, `ch03` (with `common/trace/`, `common/drill/` and `common/breakheal.py`, which chapter 3 first needs), `ch04` (with the firewall trace, drills and break actions, `common/audit/panos_parse.py` and `render/trace.py`, which chapter 4 first needs), `ch05` (with the rail trace, the dark-switch drill, the relay's break actions and the `rail-backend` audit group, which chapter 5 first needs), `ch06`, recorded (with the API gateway and the router in the cluster render, `render/inference.py`, the pods' fixed rail MACs, the serving trace, the serving drills, the recipe's break actions and the `placement` audit group, which chapter 6 first needs) and `ch07`, recorded (with the Gateways' allowedRoutes and the namespaces labelled for them, the per-pod key probe and the key Jobs, the keyed trace and its capture scrubber, the gateway drills, the key break actions and the `keys` and `gateway-layer` audit groups, which chapter 7 first needs), `ch01`, recorded (with the request walk, its three refusals, the held connect probe and the firewall rule's destination edit, which chapter 1 first needs), and `ch02`, recorded (with the decision table and the matrix in the render, `render/decisions.py`, the decision labels on every object of a decisions lab, `common/matrix/`, the walk's row tags, the resolver view's break action and the matrix's break probe and check, which chapter 2 first needs). Every build A lab now renders build A revision 2 (the repository README's "Build A, revision 2"), every chapter's committed recording is revision 2's, and the chapters' revision 1 sets have left the repository; each lab's `RESULTS.md` says what changed set by set. Every other entry lands with the milestone or chapter that first needs it (6.3), and the tree below marks each file still to come `planned:`.

```
ai-serving-fabric-labs/
  README.md  FRAMEWORK.md  Makefile  .gitignore  .gitattributes  .shellcheckrc
  platform/dell-sonic-4.6.0/        switch image build
  platform/paloalto-pa-vm-12.1.2/   firewall image build (the PA-VM launcher)
  serving-layer/                    Makefile serving.py load.py client.py serving.env.example: make serve / make load / make client; image/ holds the serving image
  spec/
    common.yaml                     platform constants, host budget, timeouts, harness defaults
    profile-a.yaml                  Tarnwick, build A
    profile-b.yaml                  Corvane, build B
    variants/b-mclag-evpn.yaml      planned: overlays (ch12 comparison, ch16 second plane / second site)
    versions.yaml                   every pin, with digest or sha256
    known.yaml                      platform-limit registry for KNOWN lines
    klish-normalize.yaml            parity normalization table (filled by M1, each row cites its evidence)
  common/
    sfab/                           the generator (python package; PyYAML at render time only)
      spec.py model.py addr.py ports.py cli.py validate.py klish_lint.py
      render/{clab,klish,panos,host,frr,storage,dns,ca,k8s,inference,expect,trace,drills,decisions,inventory}.py
      tests/                        golden renders + lint tests
    bin/  sfab  inv.py  secrets.py  tick.py  repostate.py
    lib.sh
    stages/  run.sh preflight.sh up.sh boot.sh finish.sh stop.sh down.sh
    klish/   session.sh replay.sh parity.py
    fw/      fw-startup.py fw-api.sh panos.sh
    storage/ truenas-setup.py tnrpc.py; planned: ontap-setup.sh
    audit/   collect.sh judge.py vocab.py panos_parse.py placement.py gwlayer.py gate.sh lib-audit.sh evfile.py redact.py redact_tree.py setsize.py cmds/<role>.list; planned: purpose.py keep-latest.sh
    trace/   lib-trace.sh trace-md.py lib-fwtrace.sh fwtrace.py hold_request.py lib-railtrace.sh railtrace.py lib-railcap.sh
             lib-servecap.sh servekeys.py lib-servetrace.sh servetrace.py keyscrub.py keyprobe.py
             lib-walktrace.sh walktrace.py syn_connect.py
    drill/   lib-drill.sh drill.py analyze_ping.py probe_tcp.py summarize.py compare_passes.py lib-fwdrill.sh fwdrill.py
             lib-raildrill.sh raildrill.py lib-servedrill.sh servedrill.py probe_gateway.py lib-gwdrill.sh gwdrill.py
    breakheal.py  break/breakheal.sh break/lib-servebreak.sh break/lib-keybreak.sh
    matrix/  matrix.sh matrix.py label.sh label.py
    host/    mem-watchdog.sh node-sync.sh; planned: node-restart.sh relink.sh
    tools/   namecheck.py typescript.py testrun.py
    tests/   the harness tests (test_*.py), their stand-ins (shims*/) and helpers (runscope.py codefiles.py ch04_world.py m2_world.py services_block.py)
    mk/      chapter.mk
  images/
    Makefile  VENDOR-IMAGES.md  fetch.py  vm-node/ bastion/ resolver/ client/ frr/ registry/ keys/
  vendor/                           (gitignored, VENDOR_DIR) charts/: the pinned chart tarballs make -C images registry-seed downloads; serving/ and keys/: the serving image's and the key tool's pinned files
  dev/m1/                           framework milestone lab, sfab-m1 (not a chapter)
  chNN/
    README.md  RESULTS.md  chapter.yaml  Makefile  audit.sh  trace.sh  [drills.sh]  [label.sh matrix.sh]; planned: configure.sh
    breaks/<id>.yaml
    topo.clab.yml  bootstrap/  gen/      rendered and committed
    audits/                             committed result sets
    state/                              gitignored runtime state: disks, secrets, logs, markers, shared/
```

**A lab's own pages.** Every lab directory, milestone or chapter, carries two pages for its reader. `README.md` says what the lab builds, what it needs and how to run it, with the platform notes its checks rest on. `RESULTS.md` says what the recorded run proved: each claim with the verdict lines that prove it, the RESULT line of every committed set, the problems the deploys met and their fixes, how to reproduce the run, and what the recordings do not show; a chapter's `audits/INDEX.md` maps the book's exhibits to the same sets. The deploy diary, the running log kept while a lab is built, deployed and recorded, is not part of this repository. A fact a reader needs from it goes into the lab's README or `RESULTS.md` with its evidence file, and no file here cites the diary (4.4).

**`.gitignore`.** The image build contexts are tracked; their large inputs and outputs, the vendored files and every lab's runtime state are not:

```
images/*/base/
images/registry/data
vendor/
**/state/
images/**/*.qcow2
```

It also ignores `*.qcow2` and `clab-sfab-*/`, the other disk, archive and model file types a vendor image or a model comes in (`*.img`, `*.iso`, `*.ova`, `*.vmdk`, `*.zip`, `*.tar`, `*.tar.gz`, `*.tgz`, `*.gguf`), and a copy of a lab's credentials, keys or kubeconfig made outside `state/` (`secrets.env`, `lab_ed25519*`, `redact.key`, `*.key`, `*.pem`, `*.p12`, `kubeconfig`).

**`.gitattributes`.** `* -text`: git converts no line ends on checkout or commit, whatever `core.autocrlf` says, so a recorded file keeps its CR LF lines as recorded and every rendered file the sha256 in its lab's `gen/RENDER.json`.

### 1.1 The one spec

`spec/` loads as one tree with `sfab.spec.load(root)`. A profile is `deep_merge(common.yaml, profile-<x>.yaml)`, and a variant overlays a profile. Each element (a node, link, VLAN, zone, rule, NAT entry, Gateway, audience, route, zone record or model copy) has an `id` and may carry:

- `when:` the states and steps it exists in (1.3).
- `decision:` the decision id that chapter 2 stamps into PAN-OS rule descriptions, HTTPRoute labels, NAD annotations, zone-file comments and the placement table.
- `since:` the chapter that teaches it. This is metadata only and does not select anything.

The spec never holds secrets. Profile A, excerpt:

```yaml
profile: a
org: {name: Tarnwick, domain: tarnwick.example, zone: ai.tarnwick.example, short: tw, label_domain: tarnwick.example}
mgmt: {network: sfab-a-mgmt, subnet: 172.21.40.0/24, bridge: sfab-a-mgmt}
states:
  one:  {steps: [1, 2, 3, 4, 5, 6, 7], step_mode: fixed}   # one state, every A/one chapter sees all of it
  many: {steps: [8, 9, 10, 11]}                             # cumulative steps
vlans:
  - {id: 100, name: data,      prefix: 10.20.1.0/24, gw: fw/ae1.100}
  - {id: 200, name: stor-mgmt, prefix: 10.20.2.0/24, gw: fw/ae1.200}
  - {id: 300, name: bastion,   prefix: 10.20.3.0/24, gw: fw/ae1.300}
  - {id: 130, name: services-a, prefix: 10.20.13.0/24, gw: fw/ae1.130}
  - {id: 131, name: services-b, prefix: 10.20.14.0/24, gw: fw/ae1.131}
switches:
  fe-sw1:   {role: mclag_member, pair: fe, mgmt: 11}
  fe-sw2:   {role: mclag_member, pair: fe, mgmt: 12}
  rail-sw1: {role: rail_vlan, rails: [1, 3, 5, 7], mgmt: 21}
  rail-sw2: {role: rail_vlan, rails: [2, 4, 6, 8], mgmt: 22}
  oob-sw:   {role: oob_access, vlan: 90, mgmt: 31}
pairs:
  fe: {domain: 1, system_mac: "02:5a:00:00:00:01", peer_link: {pc: 1, eth: [1, 2]},
       trunk_vlans: [100, 130, 131, 200, 300], session_vrf: mgmt}
hosts:
  k8s-gpu1: {kind: vm-node, group: gpu, mgmt: 111, octet: 21, mem_gib: 16, vcpus: 8,
         bond: {pc: 21, eth: 7}, oob_eth: 1, rails: {switch_eth: 1}, relay: true, k8s: join-worker}
  k8s-cp1: {kind: vm-node, group: ctrl, mgmt: 101, octet: 11, mem_gib: 8, vcpus: 4,
          bond: {pc: 11, eth: 4}, oob_eth: 4, k8s: init}
  bastion: {kind: bastion, mgmt: 50, vlan: 300, octet: 10, bond: {pc: 30, eth: 9}, resolver: [dns-res1, dns-res2]}
  dns-auth1:   {kind: resolver, role: dns-auth, mgmt: 56, vlan: 130, octet: 11, bond: {pc: 41, eth: 16}, dns_role: bind-auth}
  dns-res1:    {kind: resolver, role: dns-res, mgmt: 57, vlan: 130, octet: 21, bond: {pc: 42, eth: 17}, dns_role: bind-recursive}
  isp-rtr: {kind: frr, mgmt: 62, when: "many>=9"}
gateways:
  - {id: gw-internal, vip: .200, pool: [.200, .209]}
  - {id: gw-users,    vip: .210, pool: [.210, .214], audience: enterprise}
  - {id: gw-inet,     vip: .220, pool: [.220, .224], audience: internet, when: many}
```

### 1.2 Profiles

There are two profiles, `a` (Tarnwick) and `b` (Corvane). Each holds:

- the organization (name, domain, label domain);
- the management network;
- the VLAN and VRF plan;
- the switch roles and port plan;
- hosts and appliances;
- the firewall (interfaces, zones, routing instances, rules, NAT);
- the routers (uplink, ISP, carrier);
- Kubernetes (pins, pools, announcement policies, Gateways, audiences, HTTPRoutes, NADs);
- the placement table;
- DNS views and zones;
- the CA (subjects and name constraints);
- storage (TrueNAS or ONTAP);
- the populations and the matrix seed.

Label keys use the profile's label domain, for example `node-role.tarnwick.example/control`, `tarnwick.example/lb-pool`, `tarnwick.example/audience` and `decision.tarnwick.example/id`. Model route ids are uuid5 over `https://<org domain>/models/<name>`. API keys are `sk-<short>-<slug>-<hex>`.

### 1.3 The four states and the `when` grammar

| State | Profile | Chapters | Steps |
|---|---|---|---|
| A/one | a | 1 to 7 | fixed: all seven chapters see the whole state (ch01 prints the whole build) |
| A/many | a | 8 to 11 | cumulative: 8, 9, 10, 11 |
| B/one | b | 12 to 16 | cumulative where a chapter adds hardware (13 adds the rail Clos, 15 adds ONTAP, 16 adds plane 2 by variant) |
| B/many | b | 17, 18 | cumulative: 17, 18 |
| ops | a or b | 19 to 21 | the last step of the chosen build's many state |

`when:` is a disjunction of `state` or `state<cmp>step` terms, for example:

- `when: one`
- `when: "many>=9"`
- `when: "one | many<=8"`

This is how a later state adds or moves an element (a server, a view, a resolver) at a step. An element with no `when` exists in every state of its profile. `sfab.spec.when(expr, state, step) -> bool` is about 30 lines with no `eval`.

### 1.4 How a chapter selects its slice

```yaml
# ch05/chapter.yaml
lab: sfab-ch05
profile: a
state: one
slice:
  nodes: [rail, k8s-gpu1, k8s-gpu2]        # groups or node ids; except: [...] also allowed
features: {k8s: false, serving: false, storage_setup: false}
prints: [rail-sw1, rail-sw2]       # devices whose configuration the chapter prints
extends: null                      # or the chapter whose lab this extends (each lab still ships complete: section 0)
variants: {}                       # e.g. ch12: {m: b-mclag-evpn} gives lab sfab-ch12m
trace:  {points: [...], flows: [...]}
drills: {probes: {...}, timing: {...}, list: [...]}   # rendered to gen/drills.json (4.6)
```

`sfab.spec.select(spec, chapter) -> Model`:

1. Merge the profile, apply the variant overlay, and pick the state.
2. Set the step: the chapter number if it is in the state's steps, else the state's last step (or the fixed state).
3. Keep the elements whose `when` holds.
4. Apply the slice with dependency closure:
   - a host pulls in the switches its links land on, and the pair partner;
   - `k8s: true` pulls in k8s-cp1 to k8s-cp3, the bastion, the registry and the uplink router;
   - links to removed nodes are dropped;
   - switch roles render only the attachments that remain;
   - a VLAN's gateway is given to its hosts only while the node that holds it is in the slice (chapter 5's rail slice holds no firewall, so its guests get no `BOND_GW` and no `OOB_GW`).
5. Apply `features`. Each state sets defaults; a slice may only switch features off.
6. Validate (2.5).
7. Refuse if a device listed in `prints:` lost any attachment to the slice. A chapter that prints a switch's configuration therefore always deploys that switch whole.

Port numbers never move under a slice. k8s-cp1 is `eth4` (Ethernet3) on both pair switches in every lab.

### 1.5 Addressing plan

The plan keeps every lab address out of 10.0.0.0/24, the slirp network behind each vrnetlab VM's management port; validate refuses any address there (2.5). Only the management subnet has an address on the host, its Docker bridge's .1, and preflight refuses it when another Docker network or a host interface already holds it (3.1).

**Build A, Tarnwick:**

| Segment | Prefix | Assignments |
|---|---|---|
| Management `sfab-a-mgmt` | 172.21.40.0/24 | gw .1 (docker bridge); fe-sw1 .11, fe-sw2 .12, rail-sw1 .21, rail-sw2 .22, oob-sw .31; fw .40; bastion .50; resolvers .53 to .55 (ent-dns .55); dns-auth1 .56, dns-res1 .57, dns-auth2 .58, dns-res2 .59; uplink-rtr .61, isp-rtr .62, inet-ntp .63, ops-gw .64; inet-registry .70; clients .81 to .84 (web-client .84); k8s-cp1-3 .101-.103; k8s-ingress1-2 .104-.105; k8s-gpu1-2 .111-.112; truenas1 .121 |
| Nodes VLAN 100 (IP MTU 9000) | 10.20.1.0/24 | gw .1 (fw ae1.100, zone k8s-nodes); API VIP .10; ctrl .11-.13; gpu .21-.22; ing .31-.32 |
| Ingress VLAN 110 (IP MTU 1500) | 10.20.11.0/24 | gw .1 (fw ae1.110, zone ingress); k8s-ingress1 .11, k8s-ingress2 .12 (bond0.110, its own routing table 110); pools .200-.209 (internal Gateway .200), .210-.214 (users .210), .220-.224 (internet .220, many) |
| Storage data VLAN 120 (IP MTU 9000) | 10.20.12.0/24 | no gateway, Layer 2 only; gpu .21-.22 (bond0.120); TrueNAS data .31 |
| Storage management VLAN 200 (IP MTU 1500) | 10.20.2.0/24 | gw .1; TrueNAS management .31 (a bond, one leg per pair switch; the API answers here only) |
| Bastion VLAN 300 | 10.20.3.0/24 | gw .1 (fw ae1.300, also the firewall's management, from the bastion only); bastion .10 |
| Services VLAN 130 | 10.20.13.0/24 | gw .1 (fw ae1.130, the firewall's DNS and NTP service route); dns-auth1 .11, dns-res1 .21 |
| Services VLAN 131 | 10.20.14.0/24 | gw .1 (fw ae1.131); dns-auth2 .11, dns-res2 .21 |
| Out-of-band, BMC VLAN 90 | 10.20.9.0/24 | gw .254 (fw ethernet1/3); BMC = .<node octet>, in network namespace `bmc` inside each VM guest |
| Rails, VLAN 10r | 10.21.r.0/24, r 1 to 8 | no gateway; gpu n = .(10+n) |
| In-node relay | 10.21.250.0/24 | node-local; namespace gpuR = .R |
| Pods / services | 10.22.0.0/16 / 10.23.0.0/16 | |
| Enterprise LAN | 10.24.10.0/24, one /30 per firewall port | ent-client .10/30 gw .9 (fw ethernet1/4); ent-dns .53/30 gw .54 (fw ethernet1/7) |
| Uplink (public address) | 198.51.100.0/29 | uplink-rtr .1; fw ethernet1/5 .2 is the public address |
| Operator segment | 192.0.2.0/26 | one /30 per router port: the operator's site LAN 192.0.2.0/30 behind ops-gw (ops-gw .1, operator client .2), inet-registry .6, operator resolver .10, time reference inet-ntp .14, web-client .18 (an internet host that is not the operator), ops-gw's uplink .22 |
| ISP link (many, from step 9) | 198.51.100.8/30 | isp-rtr .9; fw ethernet1/6 .10 |
| Internet users (many) | 203.0.113.0/26 | one /30 per router port: client .2, public resolver .6 |

**Build B, Corvane:**

| Segment | Prefix | Assignments |
|---|---|---|
| Management `sfab-b-mgmt` | 172.21.41.0/24 | spines .11-.12; leaf pairs .13-.18; borders .19-.20; rail spines .21-.24; rail leaves .31-.38; oob .41-.42; fw .50; bastion .60; uplink-rtr .61, isp-rtr .62; registry .70; carrier .71-.75; resolvers .53-.56; clients .81-.86; ctrl .101-.103; gpu .111-.118; ontap .121-.122 |
| Data VRF, VLAN 100 | 10.30.1.0/24 | anycast gw .1; API VIP .10; ctrl .11-.13; gpu .21-.28; ONTAP data LIFs .31-.32; pools .200-.209, .210-.214 (private), .220-.224 (internet) |
| Storage management VRF, VLAN 200 | 10.30.2.0/24 | ONTAP cluster management .30, node LIFs .31-.32 |
| Bastion VRF, VLAN 300 | 10.30.3.0/24 | bastion .10 |
| Out-of-band | 10.30.9.0/24 | gw .254 (fw) |
| Frontend loopbacks / VTEPs | 10.31.0.0/24 | spines .1-.2; leaves .11-.16; borders .21-.22; MCLAG-variant anycast VTEPs .101-.103 |
| Border to firewall | 10.31.254.0/24 | one /30 per VRF per border |
| Firewall to CE (many) | 10.31.253.0/30 | |
| Rail Clos loopbacks | 10.32.0.0/24 | spines .1-.4; leaves .11-.18 (underlay unnumbered over IPv6 link-local) |
| Rails, plane 1 | 10.33.L.0/24 | gw .1 on rail leaf L; gpu n = .(10+n) |
| Plane 2 (ch16 variant) | rails 10.36.L.0/24, loopbacks 10.37.0.0/24 | |
| Pods / services | 10.34.0.0/16 / 10.35.0.0/16 | |
| Carrier (many) | 10.38.0.0/16 | loopbacks .255.x, core /31s .254.x, PE-CE /30s .10.x |
| Customer sites (many) | 10.39.0.0/16 | site LANs 10.39.10.0/24, 10.39.20.0/24; site resolver 10.39.70.53 |
| Uplink / operator / ISP / internet | 198.51.100.128/29, 192.0.2.64/26, 198.51.100.136/30, 203.0.113.64/26 | same pattern as build A |

**IPv6** (only where a chapter answers AAAA; RFC 3849 documentation prefix): Tarnwick 2001:db8:a::/48, Corvane 2001:db8:b::/48, the ISP and the internet users 2001:db8:f::/48.

**ASNs:**

- Build B frontend: spines 64600; leaf pairs 64601 to 64603; borders 64604.
- Firewall: 64610.
- Rail Clos: spines 64700; rail leaf L is 64700+L. Plane 2 uses 64800 the same way.
- Carrier: 64900. CEs: 64911 and 64912.

**MACs (locally administered):**

- Guests: `02:5a:<octet>:...` in build A, `02:5b:<octet>:...` in build B.
- build A MCLAG system MAC: `02:5a:00:00:00:01`.
- Build B anycast gateway MAC: `02:5b:00:00:00:01`.
- Build B ES system MACs: `02:5b:00:e5:<pair>:<bond>`.

**Segments with more than one host.** Each such segment is either a SONiC access switch or a router with one port per host, chosen per segment in the spec. The enterprise LAN's layout is settled when the ch09 lab adds its resolver.

## 2. The generator

### 2.1 Inputs and commands

**Inputs:** `spec/`, `chNN/chapter.yaml`, and `spec/versions.yaml`.

**Commands** (all through `common/bin/sfab`, which runs `python3 -m sfab` with `PYTHONDONTWRITEBYTECODE=1`):

- `sfab render chNN`: writes every output below.
- `sfab check chNN`: re-renders into a temporary directory and diffs against the committed render. Exits non-zero on drift.
- `sfab lint chNN`: KLISH lint, address validation and label lengths.
- `sfab show chNN <path>`: queries the model.

**Runtime needs no PyYAML.** Stage scripts read only `gen/inventory.json`, through `common/bin/inv.py` (stdlib json), for example `inv nodes --role mclag_member` or `inv get nodes.fe-sw1.mgmt`.

### 2.2 Outputs per node kind

| Node kind | Output (under `chNN/`) | Renderer | Consumed by |
|---|---|---|---|
| Topology | `topo.clab.yml` | `render/clab.py: topology()` | containerlab |
| SONiC switch | `bootstrap/<sw>/startup-config.cfg` (KLISH, native names) | `render/klish.py: role_*()` | bound to `/config/startup-config.cfg:ro`; typed by the patched launcher; replayed by `configure.sh` (planned, 6.3) |
| SONiC switch | `gen/expect/<sw>.json` (VLANs, PortChannels and members, MCLAG domain, addresses none, routes none; later BGP, EVPN and ES) | `render/expect.py` | audit judges, boot parity, wait-fabric |
| Linux VM guest (ctrl, gpu) | `bootstrap/<n>/node.env`; `bootstrap/<n>/containerd/<registry>/hosts.toml` | `render/host.py: node_env(), containerd_hosts()` | `vm-init.sh` seeds them through cloud-init; node-sync keeps them current |
| Bastion | `bootstrap/bastion/init.env` | `render/host.py` | bastion-init |
| DNS and time servers | `bootstrap/<n>/init.env`; `named.conf` plus `zones/` (bind-auth, bind-recursive) or `dnsmasq.conf`; `chrony.conf` | `render/host.py`, `render/dns.py` | the resolver image's `sfab-init.sh` (sfab-dns, sfab-ntp) |
| The lab CA | `bootstrap/ca/` (the root's, each intermediate's and each node leaf's openssl configuration, `proof.json`) | `render/ca.py` | `common/ca/sfab-ca` on the lab host |
| Clients | `bootstrap/<n>/init.env` | `render/host.py` | the image's `init.sh`, run as the single topology `exec` |
| PA-VM | `bootstrap/fw/startup-config.xml`; `bootstrap/fw/enforced.txt` (set-format lines that must survive) | `render/panos.py: fw_xml(), rule(), dnat(), snat(), enforced()` | the containerlab `startup-config`; `fw-startup.py`; the parity check |
| FRR (uplink, ISP, carrier) | `bootstrap/<r>/frr.conf`, `daemons`, `vtysh.conf`, `init.env` | `render/frr.py` | bound read-only into `sfab/frr` |
| TrueNAS | `bootstrap/truenas1/setup.json` (bond members by MAC, data and management addresses, the management return route first, services, datasets, CSI user names) | `render/storage.py: truenas_setup()` | `common/storage/truenas-setup.py` |
| ONTAP (planned: build B, 6.3) | `bootstrap/ontapN/ontap.env` (ports, ifgroup, broadcast domains, LIFs, aggregates, SVM, export network, gateways) | `render/storage.py: ontap_env()` | `common/storage/ontap-setup.sh` |
| DNS and time | per view on the authoritative pair: `match-clients` keyed by the asking resolver's address, a TSIG key per view for NOTIFY and AXFR from the primary to the secondary, zone files under the platform zone, reverse zones in the infrastructure view only; on the recursive resolvers static-stub zones to the pair and an empty root (a name outside the zone is NXDOMAIN at once); dnsmasq `local=/tarnwick.example/`, one `host-record` per corporate name and `server=/ai.tarnwick.example/` to the pair; identical public zones for the ISP-side and operator-side servers; chrony on the resolvers (NTS to the reference) and the reference | `render/dns.py: bind_auth(), bind_recursive(), dnsmasq_conf(), chrony_server(), chrony_reference()` | resolver image |
| CA | `bootstrap/ca/{root,platform,kubernetes}.cnf` (name constraints = the org domain plus the build's prefixes), `proof.json` (leaf names inside and outside the constraints) | `render/ca.py` | `sfab-ca` in the bastion |
| Kubernetes | `bootstrap/k8s/NN-*.yaml`, fully rendered with no runtime envsubst: kubeadm init and join, kube-vip, Cilium values, LB pools, L2 policies, Gateways, HTTPRoutes per audience, PKI, CSI values or Trident backend; with serving on, Multus v4.3.0's thick plugin (`12-multus-daemonset-thick.yaml`: the upstream manifest kept in `render/upstream/`, its image pinned by digest and its daemon's memory limit raised) and `serving.env` (the serving recipe's settings, rail attachments and placement table, each pod's rail address fixed from `k8s.rail_pod_range` for the CNI static IPAM plugin and its rail MAC from that address; `serving-layer/` renders the attachments and pods from it); with serving on and the spec's `inference:` block, `60-inference-base.yaml` (the namespace and the key Job's roles, and from chapter 7 the per-pod key probe's account), `61-inference-keys.yaml` (the key Job) and `62-inference.yaml` (the API gateway, the router and one HTTPRoute of model routes per Gateway), which finish applies after the recipe, outside `apply.list` (`render/inference.py`); with serving on and the spec's `k8s.allowed_routes`, each Gateway's listener admits HTTPRoutes only from the namespaces labelled `<label_prefix>.<label domain>/<gateway>: "true"`, and the render labels exactly the namespaces it attaches routes from (the test backend's in `05-namespaces.yaml`, the API gateway's in `60-inference-base.yaml`, the recipe's through `serving.env`'s `SERVING_NAMESPACE_LABELS`); a lab without serving keeps `from: All`. Build A revision 2 adds: Secrets encrypted at rest (`k8s.secrets_encryption`: the API server's `--encryption-provider-config` and its hostPath volume in the ClusterConfiguration; cluster-bootstrap.sh makes the secretbox key on the init node and shares it with the other control nodes), Cilium's WireGuard (`k8s.pod_encryption`), one listener certificate and key per Gateway (`k8s.listener.certificate: gateway`), the API gateway, the router and the identity provider on the ingress nodes (`k8s.edge`), network policy (`k8s.network_policy`: `58-network-policy.yaml` in `apply.list` for the test backend and the identity provider, `63-inference-policy.yaml` after the inference layer, each namespace a default deny and then the request path's allows, `render/netpol.py`), and with serving on and the spec's `identity:` block the identity provider (`57-identity.yaml`: Dex, its configuration naming no secret, one HTTPRoute per Gateway for its name, `render/identity.py`); the API gateway's routes then authenticate with multi-auth, key-auth and the lab's oidc-consumer plugin (`render/apisix/oidc-consumer.lua`), and admit the consumer groups of the callers that may call each model (`inference.callers`) | `render/k8s.py`, `render/inference.py`, `render/identity.py`, `render/netpol.py` | the init node (kubeadm, kube-vip, Cilium); everything else is applied from the bastion in `finish` |
| Inventory | `gen/inventory.json` (nodes, kinds, mgmt addresses, roles, budgets, capture points, watchdog order, stage features); `gen/RENDER.json` (sha256 of every output, spec sha256, versions, generator version and the sha256 of its source); | `render/inventory.py` | every script |
| Decision table and matrix (a lab whose chapter.yaml says `decisions: true`, from chapter 2) | `gen/decisions.yaml` (the spec's `decisions.rows`, Table 2-1, each row with the lab's objects that implement it, each object's decision id and where it is stamped; the switches as forwarding only; the ids of no row with why) and `gen/decisions.json` (the same, with label.sh's plan of reads); `gen/matrix.yaml` (the spec's `matrix:` rows and columns, Table 2-2, every cell's mode computed as the request meets the layers: the view's answer, the router's and the firewall's routes, the NAT rule on the pre-NAT zones, the first security rule on the original addresses and the post-NAT zone, the Gateway's HTTPRoutes, the key; each cell's requests, source ports and the evidence its mode leaves) and `gen/matrix.json` (the same); and in such a lab a decision label on every object of every row (each security and NAT rule's description, each zone file entry a view answers, each consumer group's desc, each rail attachment's annotation and the serving recipe's route label through `serving.env`) and on every switch (a comment under its startup file's header) | `render/decisions.py` | `common/matrix/`, `common/breakheal.py` |
| Drills and breaks | `gen/drills.json` (chapter.yaml's `drills:` resolved: the probes' addresses and captured ports with the switch each lands on, each shut's members and its KLISH, the bonded hosts, the timing; from chapter 4 a firewall drill's rendered entries, xpaths and counter; from chapter 5 the rails probe's rows and captured ports, a dark drill's ports, KLISH and dead rails, and each row's expectation; from chapter 6 the gateway probe's client, URLs and key Secret, the endpoints probe's Services and their servers, a serving drill's KLISH, the copies it takes out and each Service's servers while it holds, and a rail-move drill's row as rendered and as moved; from chapter 7 the gateway layer the drills share (the API gateway's selector and sidecar, the key Secret, the key tool's image and accounts, each model's route path), a key-lifecycle drill's models and id base, a rejected-code drill's routes ConfigMap as rendered and without the route's rejected code, and an idle-timeout drill's client, URL, silence, Cilium's values as rendered and corrected (`render/k8s.py` `cilium_values_doc`) and the test backend's route as rendered and with timeouts); `gen/breaks.json` (each `breaks/<id>.yaml` resolved and checked); neither when the lab has none | `render/drills.py` | `common/drill/`, `common/breakheal.py` |
| Firewall and rail traces | `gen/trace.json` (chapter 4's form of chapter.yaml's `trace:`: each session's client, the address it connects to and the address the destination NAT translates it to, the rule and NAT rule it must name; the pull's node, image by digest, registry and source NAT address, and capture points; chapter 5's `rails:` form: every rail both nodes hold, each flow's request and reply rails and switches, the reply's TTL and traceroute's hops, each capture point's expected requests and replies, and the DF matrix; chapter 6's `serving:` form: the client and whether its name is pinned, the Gateway's VIP and lease, the model's URL and the answer the router must name, the API gateway's and the router's selectors, and every copy of the model with its rail, server, workers (which one sits on another node than its server) and the rail switch ports facing its nodes; chapter 7 adds to it `keys: true`, the router's master key and the backend key named by Secret and field and the router's per-model path, and `refuse:`, a hostname the Gateway does not carry, with its URL and source port; chapter 1's `walk:` form: chapter 7's keyed plan with its in-cluster points numbered after the frontend's, the frontend's capture points from the client's port to the pair's ports facing the bundle's legs, the firewall's ingress zone, connected route, egress interface and first matching security rule as the render resolves them (a walk the render would translate is refused), chapter 4's session form for the walked request with its POST, body and key file, the resolver's view that answers the client and the one that answers the resolver itself, the rail switches whose counters the walk reads, and the three refusals, each with the device and layer that must refuse it); none when the trace block is chapter 3's (flows and points, read from the inventory) | `render/trace.py` | `common/trace/lib-fwtrace.sh`, `common/trace/lib-railtrace.sh` |

**Rendered files contain no secrets.** Credentials are `${SFAB_*}` references, which containerlab expands at deploy from `state/secrets.env`, or 0600 files bound from `state/secrets/`. `common/bin/secrets.py` creates them on the first `make up`:

- the TrueNAS and ONTAP passwords;
- the kubeadm token in `[a-z0-9]{6}.[a-z0-9]{16}` form, and the cert key;
- a lab SSH key pair, and at every preflight `state/secrets/authorized_keys`: the lab key's public half and each public key in `~/.ssh/*.pub` of the user who runs `make up` (and of `SUDO_USER` under `sudo`), each once. The topology binds it at `/sfab/authorized_keys` in every VM guest, the bastion, every FRR router and the VPN router, the authorized keys of their one login, `guest.user` (`admin`), so `ssh admin@<lab>-<node>` from the lab host works with the lab key or the user's own, as the containerlab VS Code extension's Connect (SSH) runs it (`ssh <user>@<container name>`, its user `admin` for a `linux` node unless `containerlab.node.sshUserMapping` names the kind; https://github.com/srl-labs/vscode-containerlab, `src/commands/ssh.ts`). Only the number of keys is printed, never a path or a comment;
- the lab's redaction key, `state/secrets/redact.key`, which no container or device sees (4.3);
- with the identity provider, each OIDC client's secret and each person's password (`SFAB_IDP_*` in `state/secrets.env`); finish writes the identity provider's Secret from them (`common/bin/idp-secret.py`: the client secrets and bcrypt hashes, never the passwords), and the audit hands a person's password to that person's client only, through a pipe.

**The switches and the PA-VM keep their kinds' default logins.** containerlab's `dell_sonic` and `paloalto_panos` kinds pass the image's launcher its login on its command line, and the topology references no credential for either. The harness reads that login from the node's own container (4.1). No firewall password is generated: the PA-VM's launcher never reads one from its environment (M1, `dev/m1/RESULTS.md`, problem 4).

**ONTAP licences** come from a reader-supplied `~/.config/sfab/ontap-licenses.txt` and are never committed.

### 2.3 The KLISH renderer

There is one function per role, so chapter 21 can print the tree as it stands:

- Build A: `role_mclag_member`, `role_rail_vlan`, `role_oob_access`.
- Build B: `role_fe_spine`, `role_es_leaf`, `role_mclag_evpn_leaf`, `role_border`, `role_rail_leaf`, `role_rail_spine`.

Each role is built from helpers:

- `head()`
- `vlans()`
- `portchannel(id, desc, mode, vlans, mclag, mtu, tagged, edge)`
- `member(eth, pc, desc, mtu, storm)`
- `access_port(eth, vlan, desc, mtu, edge, storm)`
- `keepalive_backup(ka)` and `keepalive_link(ka)` (an MCLAG member's two keepalive paths)
- `mclag_domain(pair)`

**Native port names.** `ports.native(n)` returns `Ethernet{n-1}` for n up to 48, then `Ethernet{48+4*(n-49)}` for n 49 to 56. `ports.num_nics(sw)` returns the highest `ethN` connected, or 56 when the switch exports sFlow, in which case eth56 must be cabled.

**Order for an MCLAG member** (the order SONiC 4.6.0's KLISH accepts), with `head()` as its own session block:

```
! sfab-ch03 fe-sw1: rendered from spec/profile-a.yaml; edit the spec and run make render
configure terminal
ip vrf mgmt
end
configure terminal
spanning-tree mode pvst      the l2 policy (spec l2:)
interface Vlan 100
exit
... the served VLANs
ip vrf VrfMclagKa            the keepalive VRF
interface Vlan 3966          the backup keepalive: description, ip vrf forwarding VrfMclagKa,
                             mclag-separate-ip, then ip address 10.20.255.4/31 (fe-sw2 .5)
interface PortChannel 1      peer link: mtu 9216, fast_rate, trunk of the served VLANs and 3966, no
                             shutdown; members Ethernet0-1 (mtu 9216 before channel-group)
interface Ethernet12         the dedicated keepalive link: mtu 9216, ip vrf forwarding VrfMclagKa,
                             ip address 10.20.255.0/31 (fe-sw2 .1), no shutdown
mclag domain 1               source-ip/peer-ip = the keepalive link's addresses, peer-link PortChannel 1,
                             mclag-system-mac, session-vrf VrfMclagKa, backup-keepalive source-ip,
                             peer-ip, session-vrf VrfMclagKa and interval 1 (before any mclag 1)
interface PortChannel 10     firewall: mtu 9216, fast_rate, mclag 1, trunk, no shutdown (not an edge port)
interface PortChannel 11..   hosts: mtu 9216, fast_rate, mclag 1, access Vlan N, spanning-tree portfast
                             and bpduguard port-shutdown, no shutdown; members mtu 9216, channel-group N,
                             storm-control broadcast, unknown-unicast and unknown-multicast 10000 (kbps)
end
```

Every form was accepted on SONiC 4.6.0 by chapter 3's lab, and each behavior below was seen there: VLANs 3967 to 4094 are reserved, so the backup VLAN is 3966; without `mclag-separate-ip` the backup VLAN interface on the standby carries the active's MAC and the two ends never answer each other; storm control is refused on a PortChannel and taken on each member; BPDU guard needs spanning tree on, and PVST runs on both members with the peer link outside it (the pair is one bridge, its ID built from the mclag-system-mac), and a BPDU on one leg of a bond shuts that PortChannel on both members. A rail switch takes the same `spanning-tree mode pvst` and, on each access port, the mtu, edge and storm lines.

The launcher skips `!` lines and blank lines, so decision ids ride as `!` comments. The replay tool strips them the same way.

**`klish.lint(lines)` rejects:**

- a file whose first non-comment lines are not `configure terminal`, `ip vrf mgmt`, `end`;
- `?`;
- `exit` directly after `ip vrf`;
- a description containing a space;
- `grep -E` or a quoted pattern;
- `no mclag domain`;
- `mclag <id>` before `mclag domain`;
- any address in 10.0.0.0/24;
- a used port with no `no shutdown`;
- an `mtu` below its attached sub-interface's MTU.

### 2.4 Containerlab topology rules (`render/clab.py`)

**Lab-wide:**

- `name: sfab-chNN` (variants `sfab-chNNx`, milestone `sfab-m1`) and `prefix: __lab-name`, so containers are `sfab-ch03-fe-sw1` and the lab directory is `clab-sfab-ch03/`.
- `mgmt: {network: sfab-a-mgmt, ipv4-subnet: 172.21.40.0/24}` for build A, `sfab-b-mgmt` with 172.21.41.0/24 for build B. Every node gets a static `mgmt-ipv4` from the spec.
- **Management VRF first:** the KLISH head above on every switch, so Management0's route never sits in the default table.

**Switches:**

- `kind: dell_sonic`, image `vrnetlab/dell_sonic:4.6.0`.
- `env.NUM_NICS` from `ports.num_nics`.
- `CLAB_MGMT_PASSTHROUGH: "true"` on every MCLAG pair member, so the stages reach the pair on its harness management address. Nothing of the pair's own rides it: the MCLAG keepalive runs on a dedicated link (eth13 on both members) in VRF VrfMclagKa, with the backup keepalive on a VLAN interface carried by the peer link, and the generator refuses a member without passthrough only when its keepalive would ride the management VRF. The keepalive link is a containerlab link like any other, in every lab that has the pair.
- Binds `bootstrap/<sw>/startup-config.cfg:/config/startup-config.cfg:ro`.
- Links name container `ethN`. KLISH names `ports.native(N)`.

**Hosts and containers:**

- **TX checksum offload is off on every Linux data NIC:**
  - containers get it in their `init.sh`, run as the topology `exec`, which runs after links attach;
  - VM guests get it on both sides: `vm-init.sh` sets `ethtool -K ethN tx off` on the container's data NICs, and `netsetup.sh` sets it inside the guest. M1 records whether the guest side is needed.
- **VM guests:**
  - `restart-policy: "no"`, so a guest that powers off stays off;
  - `devices: [/dev/kvm, /dev/net/tun]`. M1 recorded that containerlab 0.81.0 accepts it on kind `linux`, and M2's deploy recorded the same on the pinned 0.81.1 (`dev/m2/RESULTS.md`, settle item 5).
- **PA-VM:**
  - `kind: paloalto_panos`, `startup-config: bootstrap/fw/startup-config.xml`;
  - env `QEMU_CPU: host`, `QEMU_SMP: "8"`, `QEMU_MEMORY: "16384"`, and no credentials. The PA-VM keeps the `paloalto_panos` kind's default login: containerlab gives the launcher `--username` and `--password` on its command line, and the launcher never reads `USERNAME` or `PASSWORD` from its environment (M1, `dev/m1/RESULTS.md`, problem 4).
- **TrueNAS and ONTAP:** `kind: generic_vm` with their launcher env, and persistence bound from `state/<node>/persist`.

**Startup:**

- Build A uses no `startup-delay`.
- Build B boots switches in waves (`host.boot_batch`, 8 per wave, `startup-delay` = 180 s times the wave number).
- Deploy always runs with `--max-workers` equal to the node count, so delays never queue inside a shared worker.

### 2.5 Determinism and validation

- **Stable output.** Outputs are byte-stable: sorted keys, fixed ordering, no timestamps. The DNS SOA serial is derived from the zone content hash; there are no secondaries.
- **What `validate()` rejects:**
  - internal addresses outside RFC 1918, or outside addresses outside RFC 5737 / RFC 3849;
  - overlapping prefixes, or anything in 10.0.0.0/24;
  - a port used twice;
  - `NUM_NICS` above 56;
  - a rule naming an unknown zone;
  - an audience with no Gateway;
  - a model whose two copies sit on rails of the same parity (`break-19a` breaks this on purpose, outside the spec);
  - a label longer than 63 characters;
  - a domain not under `.example`.
- `make check` at the repo root runs `sfab check` on every chapter, then every test (`make test-full`, 2.6) and `namecheck`.

### 2.6 Tests

`make test` at the repo root runs the generator's tests (`common/sfab/tests`), the serving recipe's (`serving-layer/tests`), the key tool's (`images/keys/tests`) and the harness's (`common/tests`) through `common/tools/testrun.py`, which needs only the standard library. Each suite lists its tests with unittest's own discovery, so a run holds exactly the tests `unittest discover` finds. The tests are cut into units: a class, a few tests of a long class (one with a class fixture only after a run has timed the fixture as short, since each unit runs it again), or the short classes of one module together. Each unit runs in a fresh interpreter started at the repo root with the environment its suite always had, `JOBS` units at once (the CPU count by default), the longest first by the times the last run kept. Those times live in `sfab-test-durations.json` in the git directory every worktree of the checkout shares, never in the tree. A failing test prints its traceback and its unit's output, and `DURATIONS=N` prints the N slowest tests and units. The run fails when a test fails or errors, or when a listed test was neither run nor skipped by its class or module.

- **`make test-quick`** runs the tests for the areas a change touches, then the public-tree guard's scan and `namecheck --mask` on the changed files. The paths are those `CHANGED='path ...'` names; without it, or with `SINCE=<commit>` beside it, they are also the work tree's changes against HEAD (untracked files included) and, with `SINCE`, every path the commits since that one changed. `QUICK` in `testrun.py` maps each path to its tests, the first matching rule winning, and prints the mapping; a path no rule names runs the whole of `make test`, so a change the table does not know is never left untested. A path outside the recorded sets also runs the two quick checks that read every file of the code (the product name and the kernel-log rule), and a path inside a set runs the size policy and the namecheck of the whole tree; the whole-tree public-tree test runs when a rule names its module.
- **`make test`** runs every test but the tree tier: it is complete for the code.
- **`make test-full`** runs every test, the tree tier too. The tree tier (`TREE` in `testrun.py`) is the tests that read every recorded set: `test_harness.NamecheckTest.test_repo_is_clean`, the namecheck of every file of the tree, and the four tests of `test_setsize.CommittedSetsTest`, the recording size policy over every committed set. They take seconds today and grow with every recording. `make check` runs `make test-full`.
- **`make test-serial`** runs every test as the repository did before `testrun.py`, one suite after another with `unittest discover`, to compare against.

Every change follows one policy:

1. `make test-quick` while iterating, as often as the work needs.
2. `make test` once before a review or merge, with the author's list variables exported (4.4).
3. `make test-full` once per stage, after the stage's last change to a recorded set and before the stage reports done.

A test that fails is fixed and its `make test-quick` run again; a full run is not repeated to see whether a failure goes away. A lab test that passes alone and fails beside the others has a timing margin too tight for a busy machine: widen the bound in the test (a wait that stops at the first success costs nothing when it is long) and keep every assertion.

Two runs at once are safe: a lab test's check that no stand-in is left running reads only the process groups its own commands started (`common/tests/runscope.py`), never another test's or another checkout's. Each run takes every CPU by default, so two at once share them; `JOBS=` splits them.

When a test lands: a test that reads every recorded set goes in `TREE`, and a new test module, shared test helper or stand-in directory gets its `QUICK` rule (a lab added with a later chapter adds its `chNN/` rule). Every whole run checks that each test `TREE` names exists and that each selector `QUICK` writes out in full names a test.

## 3. Stages

`common/stages/run.sh <stage...>` runs stages in order. It holds `flock chNN/state/lock` plus a host-wide `/run/lock/sfab.lock` while deploying, and tees to `state/logs/<stage>-<UTC>.log`.

`make up` runs `preflight up boot finish audit`. `make up BG=1` runs the same through `systemd-run --unit=sfab-<lab>-up --collect --working-directory=$PWD` (follow it with `journalctl -fu sfab-<lab>-up`).

Each step writes `state/stage/<stage>.<step>.ok`, holding the render hash and every container's `StartedAt`. A step whose marker matches is skipped, so re-running any stage is safe.

### 3.1 Preflight (`preflight.sh`, PASS/FAIL lines, any FAIL refuses)

| Check | Function | Rule |
|---|---|---|
| Identity | `pf_identity` | the lab name matches `^sfab-(ch[0-9]{2}[a-z]?|m[0-9]+)$` and the directory it runs in |
| Tools | `pf_tools` | docker, containerlab at the pinned 0.82.0 (`spec/versions.yaml`; always the latest release: 0.81.0, 0.81.1 from 2026-10-20, 0.82.0 from 2026-10-27), python3 ≥ 3.10, sshpass, tcpdump, nsenter, ethtool, openssl |
| KVM | `pf_kvm` | `/dev/kvm` read-write |
| **Host tick** | `pf_tick` | `common/bin/tick.py` (ctypes `adjtimex(2)`, modes 0, reads `struct timex.tick`; falls back to `adjtimex --print`) is read and recorded, never refused (any container holding CAP_SYS_TIME can move it, since every container shares the host's one clock); a reading other than **10000** prints a SKIP line and stamps the result set `host-tick: N`; as root, `tick.py --set` sets it to 10000 (`adjtimex(2)` with ADJ_TICK, or `adjtimex --tick`) |
| **No other sfab lab** | `pf_other_labs` | no running container `^sfab-` outside `$LAB-`; no other `sfab-*` in `containerlab inspect --all --format json`; no `containerlab deploy` process |
| Subnet | `pf_subnet` | no docker network other than `sfab-a-mgmt` / `sfab-b-mgmt` holds the subnet; if that network exists, its subnet matches and it has no foreign endpoints |
| Images | `pf_images` | every image in the inventory is present locally, with its digest recorded; vrnetlab images are never pulled |
| Registry data | `pf_registry` | a lab with the in-lab registry finds its seeded data at `images/registry/data` (`SEED.json`), which the registry binds read-only |
| **Free memory** | `pf_mem` | `MemAvailable` ≥ Σ budget + floor. Budgets per kind from `spec/common.yaml`: `dell_sonic` 4.6 GiB, PA-VM 16.5, vm-node `mem_gib`, TrueNAS 16, ONTAP 8.5, container 0.25; floor 16 GiB |
| CPU, disk | `pf_cpu`, `pf_disk` | Σ vCPU ≤ 2 × `nproc`; free space covers the disk budget below: the growth under `state/` and the container layers of the nodes not yet running, both at once where they share a filesystem |
| Modules | `pf_modules` | loads `bonding`, `vrf` when an FRR router is in the lab (its management port sits in VRF `mgmt`), and in build B many also `mpls_router mpls_iptunnel`; idempotent, not persistent |
| Secrets, guest user, render | `pf_secrets`, `pf_guest_user`, `pf_render` | creates `state/secrets.env` (0600) if missing and writes `state/secrets/authorized_keys` again (2.2); refuses guest disks made for another login user than `guest.user`, since cloud-init makes the user once per disk (`state/guest-user` records it when no disk exists; a disk with no record was made for `sfab`, the user before 2026-10-27), with `make wipe` as the way out; runs `sfab check` (a warning only if PyYAML is absent; the committed render still deploys) |

**The disk budget is what a deploy writes, where it writes it, never a disk's virtual size.** The guests' disks are thin qcow2 overlays: a VM guest's `disk_gib` in the profile is the virtual size of its root disk (the guest's `VM_DISK_GIB`: 40 GiB on a control node, 80 on a GPU node), and the overlay grows only as the guest writes. So every node carries two disk budgets, from `spec/common.yaml` `kinds` or, for a vm-node, its own entry:

- `state_gib`, the expected growth of what the node writes under the lab's `state/`: a VM guest's overlay and seed in `state/nodes/<n>/`, TrueNAS's boot overlay and data disks in `state/nodes/<n>/persist` (its launcher keeps both there when `/persist` exists). `host.state_base_gib`, 1 GiB, adds the lab's own files: logs, markers, run directories, secrets, `shared/` and `ca/`.
- `layer_gib`, the expected growth of the node's container layer under Docker's data root (`DockerRootDir` in `docker info`): vrnetlab's launcher writes a switch's or the PA-VM's overlay next to its image disk inside the container, since nothing is bound for it.

The registry's data is budgeted nowhere. It lives under `images/registry/data`, not `state/`; the registry binds it read-only, and it is seeded before any lab (`make -C images registry-seed`, which `pf_registry` checks), so a deploy writes nothing there.

`pf_disk` counts, under `state/`, the lab's own files plus each node's `state_gib` less what its `state/nodes/<n>/` already holds (allocated blocks, so a thin disk counts what it uses; never below 0 for a node), and under the data root the `layer_gib` of each node not yet running. Where the two share a filesystem, as on the lab host, its free space must cover both at once; otherwise each is judged on its own.

The basis, read on the lab host on 2026-10-20. Each lab records what its deploy used.

| Node | `state_gib` | `layer_gib` | Basis |
|---|---|---|---|
| Control node | 6 | 0 | M1's two guests held 148 MiB and 175 MiB under `state/nodes/<n>/` after all of M1's runs (`du -sh`), with no image pulled. The 22 images the registry holds for the cluster are 0.97 GiB as pulled and 2.75 GiB unpacked (linux/amd64, summed from the seeded blobs), 3.7 GiB for a node that holds every one in both forms. With M1's 0.2 GiB that is 3.9 GiB; the other 2.1 GiB is headroom for etcd's data and the journal, which M2's deploy measures |
| GPU node | 12 | 0 | the same 3.9 GiB, plus 8 GiB held for the serving image, which holds no model since revision 2 (the weights come read-only from the models share and never reach the node's disk); the budget stays at 12 until chapter 6's deploy records what a GPU node's disk holds |
| TrueNAS | 40 | 0 | the expected use of its thin boot and data disks (four data disks of 100G virtual); not measured yet |
| ONTAP | 60 | 0 | not measured; no lab runs it yet |
| Switch | 0 | 8 | the overlay of its image disk (64 GiB virtual); a planning allowance: the recorded deploys of M2, chapter 3 and chapter 4 read 1.09 GB to 1.39 GB per switch (`container-layers.txt` in their sets) |
| PA-VM | 0 | 16 | the overlay of its image disk; a planning allowance: the same files read 1.76 GB to 2.96 GB |
| Bastion, clients, resolvers, FRR, registry | 0 | 0 | no disk image; the bastion's files under `state/shared` and `state/ca` are in `state_base_gib` |

M1 budgets 25 GiB under `state/` and 56 GiB of container layers; M2 83 GiB and 56 GiB. Until 2026-10-20 the budget was every node's `disk_gib` summed against `state/`, the guests' virtual sizes, the switches' and the PA-VM's layers and the registry's data included: 420 GiB for M2, on which its preflight refused twice (`dev/m2/RESULTS.md`, the RESULT lines).

Labs change nothing on the host beyond those module loads, the transient `sfab-<lab>-*` units and containerlab's own deploy and destroy writes under `/etc` (the lab's block in `/etc/hosts` and `/etc/ssh/ssh_config.d/clab-<lab>.conf`, which containerlab offers no way to skip and removes again at destroy). They need no egress at run time, so no host NAT rule is added, and `lib.sh` exports `CLAB_VERSION_CHECK=disable`, so containerlab's own check for a newer release, which reaches the internet, never runs (it printed its notice in chapter 1's first recorded deploy).

### 3.2 `up` (deploy)

1. If every inventory container is running and `links_intact()` holds (every expected `ethN` exists and is up in every container), up is a no-op. If some containers exist but not all, it runs `down.sh fast` first.
2. Create `state/shared/hold-guests`, with an EXIT trap.
3. Start the memory watchdog as its own unit, `systemd-run --unit=sfab-<lab>-memwatch common/host/mem-watchdog.sh <lab>`, so it does not die with the caller's cgroup. It uses exact container names, the inventory's victim order (highest-numbered GPU guest first) and the spec's floor.
4. Run `containerlab deploy -t topo.clab.yml --reconfigure --max-workers $NODES`. It is never wrapped in `timeout`, because a SIGTERM tears the lab down.
5. Confirm every container is running.

### 3.3 `boot` (bring every node to its rendered state)

1. **Links.** If `links_intact()` is false, which is the host-reboot case, run `down fast` then `up` (always redeploy, never adopt broken links).
2. **`wait_switches`** (parallel, 20 min cap per switch):
   - vrnetlab health reads `healthy`;
   - the launcher log shows `KLISH startup config applied`;
   - SSH and `terminal length 0`, then `show version`.
3. **`switch_parity`.** `common/klish/parity.py` compares the rendered lines with `show running-configuration`, matching each line within its context and applying `spec/klish-normalize.yaml`.
   - The launcher does not stop on `% Error`, so parity is the only proof the file took.
   - Missing lines are replayed with `replay.sh <sw>`. Replay never touches an MCLAG domain that `show mclag brief` already shows, and stops on any `% Error`. Parity then runs again; a remaining miss is a FAIL.
4. **`gro_check`.** On every switch, `ethtool -k ethN` shows GRO, rx-gro-hw and LRO off on every data NIC (`/usr/sbin/ethtool`: the `admin` login's PATH has no sbin). Then **`iccp_listen`** on every pair member: iccpd's listener on TCP 8888 in the domain's session VRF (`sudo ss -tanp`). iccpd binds that socket to the VRF once, when it reads the domain, and when the bind fails then (`Set socket SO_BINDTODEVICE option for server fd failed for vrf mgmt` in `/var/log/iccp/iccpd.log`) the listener stays in the default VRF while the session still comes up; chapter 1's first deployment met it on both members (`ch01/RESULTS.md`). A listener outside the VRF is put right by one `sudo systemctl restart iccpd` on that switch, then read again; a listener still outside it, or none, is a FAIL.
5. **`fw_bootstrap`.**
   - Wait for `healthy` (30 min cap).
   - Check the delivered `/config/startup-config.cfg` is byte-identical to the render.
   - Look for a commit marker (`XML startup config commit finished: result=OK`, the log line of the patched launcher in `platform/paloalto-pa-vm-12.1.2/`, or `/tmp/lab-startup-committed`). If there is none, run `common/fw/fw-startup.py` inside the container: keygen with the login the launcher was started with (its `--username` and `--password`, the kind's default), wait for jobs, import plus partial merge, validate, commit with BUSY retries, a poll that survives the web server restarting, then write the marker.
   - Confirm `bootstrap/fw/enforced.txt` lines in the set-format running config, 3 tries 20 s apart.
   - Redact `key=` and send API keys in the `X-PAN-KEY` header.
6. **`ca_init`** (when the lab runs its CA: k8s on, or a node leaf's node in the lab): run `common/ca/sfab-ca -C <lab> init` on the lab host, before deploy, which is a no-op when the root exists. The keys stay in `state/ca/` on the lab host and no node mounts it. It publishes `root.crt` and the intermediates' certificates in `state/shared/ca/`, places the kubernetes intermediate (0600) in `state/shared/cluster/ca/` for the init node (finish's `sfab-ca retract` removes it once every control node has joined), signs each node leaf into `state/tls/<node>/` (bound read-only at `/sfab/tls`), and refuses its own proof leaves outside each intermediate's name constraints. The lab's kubeadm token goes from `state/secrets.env` to `state/shared/cluster/kubeadm.env` (0600) for the guests.
7. **`wait_fabric`.** Hold conditions are read from `gen/expect`, and must hold in two consecutive polls 15 s apart (120 polls at most):
   - build A: `show mclag brief` shows the session up and the roles set; `show PortChannel summary` shows every expected PortChannel up with every member, except the PortChannels that face a held guest (their bonds cannot come up before the release; M1 found this) and those that face a storage node, whose data bond its setup in `finish` makes;
   - build B: `show bgp ipv4 unicast summary`, `show bgp l2vpn evpn summary`, `show evpn es`.
8. **Release the guests.**
   - Remove `hold-guests`. The guests' `vm-init.sh` polls it every 5 s for up to 3600 s, before the link wait.
   - `wait_guests`: SSH answers and `sfab-netsetup.service` ran in this boot.
   - `wait_bonds` (build A): the pair again with every PortChannel, the guests' included, in two consecutive polls (the storage nodes' still set aside).
9. **`node_sync`.**
   - Compare the guests' boot-time files with the repo by sha256 (`node.env` sorted), and apply them live.
   - Exit 3 means the bootstrap files changed, so restart `sfab-cluster.service`.
10. **`dns_zones`.** Every `type secondary` zone of every rendered `bootstrap/<node>/named.conf`, per view, read with `rndc zonestatus` until it holds a serial, every 5 s for 300 s at most. A zone not loaded is told to transfer at once (`rndc retransfer`, again each minute it stays unloaded): BIND backs off the retries of a zone that has never loaded while its primary is out of reach, and the primary sits behind the firewall, which boots last, so chapter 4's second revision 2 attempt met dns-auth2's internal forward zone still unloaded when the audit read it, 12 minutes after boot had found the firewall committed and the pair up (it loaded a minute later). A zone still unloaded is a FAIL.

### 3.4 `finish` (cluster and workloads, gated by the inventory's features)

1. Wait for the cluster bootstrap. "Done" means `sfab-cluster.service` is inactive, `ExecMainStatus=0`, and its exit timestamp falls in this boot (cap 240 × 30 s).
2. Wait for every node to be Ready. Every control node has then joined, so `sfab-ca retract` in the bastion removes the private keys kubeadm's control nodes take from `state/shared` (the kubernetes intermediate's key and the init node's shared control-plane keys); boot and the init node publish them again at the next boot.
3. Cilium device drift check: set comparison plus agent age against the ConfigMap; fix with `helm upgrade --reuse-values`, then roll the DaemonSet.
4. Apply `bootstrap/k8s/*` from the bastion with `kubectl apply --server-side`.
5. Install pinned charts with `helm upgrade --install` from the registry's OCI charts.
6. Storage:
   - build A: `truenas-setup.py all`, then the pair with every PortChannel, the storage bonds included, then democratic-csi;
   - build B (planned, 6.3): `ontap-setup.sh`, then the Trident install and backend. Delete Trident node pods that are not 2/2 after 12 × 15 s.
7. With serving on: `make -C serving-layer serve SERVING_ENV=bootstrap/k8s/serving.env` (`serving-layer/README.md`): the rail attachments, the key generated in the cluster, the workers, the servers, their Services and the recipe's HTTPRoute, read back. Then the API gateway and the router (`render/inference.py`): `60-inference-base.yaml` applied, the key Job (`61-inference-keys.yaml`: the router's master key, the first key a model, the recipe's key copied for the router) run once and removed with its log of fingerprints printed, `62-inference.yaml` applied, the router restarted when its backend key changed, and both Deployments rolled out; then, with `k8s.network_policy`, `63-inference-policy.yaml`. Chapter 6's and chapter 7's recorded labs run it. With the identity provider, the `idp-secret` step after the CA secrets writes its Secret from the lab host and rolls Dex out.
8. Settle sweeps:
   - frontend: each node pings 6 peers at offsets 1, 5, 11, 17, 23, 29 plus the round number; VIPs are tested by TCP 443; 3 clean rounds, 40 at most; after 2 bad rounds, bounce the bond legs (guest side) of the node named most often, 4 nodes at most;
   - rails: 2 clean rounds, 10 at most, stopping early when the same loss repeats.
9. Warning events archived and held at 0 for 90 s.
10. `audit.sh --quick`.

### 3.5 `stop`, `down`, `wipe`, `recover`

- **`stop.sh`.** Clean power-off in order. `docker update --restart=no` runs first (belt and braces).
  1. GPU guests, 300 s.
  2. Storage: TrueNAS with `docker stop -t 120` (ACPI); ONTAP halted from its CLI.
  3. Control plane, 180 s.
- **`down.sh`**, modes default, `fast` and `wipe`:
  - default mode runs `stop.sh` first;
  - `containerlab destroy -t topo.clab.yml`, **never `--cleanup`**;
  - `rm -rf ./clab-$LAB`, only when its basename equals `clab-$LAB`;
  - `docker rm -f` for each inventory name, then a sweep of the exact `^$LAB-` prefix;
  - stop `sfab-<lab>-memwatch`;
  - `wipe` also removes `state/nodes/*`, `state/shared/`, `state/ca/` and `state/secrets.env`.
- **`make recover`** runs `boot` then `finish`. There is no autostart unit.

### 3.6 Make targets (`common/mk/chapter.mk`)

`render check up deploy boot finish audit trace label matrix drills accept load serve client break-% heal-% heal-all record status stop down wipe recover namecheck lint`

The variable `VARIANT=` selects `sfab-chNN<variant>`.

## 4. Harness conventions

### 4.1 `lib.sh`

`sfab_init <category>` does the following:

- reads `gen/inventory.json`;
- sets `LAB`, `BUILD`, `STATE`, `STEP`, `PREFIX="$LAB-"`, `CLABDIR`, `MGMT_NET`, `INV`;
- refuses unless the identity check of 3.1 passes;
- opens the result set when the category records one.

Every docker call goes through `dk()`, which refuses any container name not starting with `$PREFIX`. Device runners all append to the transcript (4.3):

| Runner | Target | Mechanics |
|---|---|---|
| `SW <sw> <line>...` | KLISH | `printf 'terminal length 0\n...'` piped to `ssh -tt admin@<mgmt> sonic-cli`; no `?`; output filtered in the shell, never with KLISH `grep -E` |
| `VT <sw> <cmd>` | FRR on a switch | `ssh admin@<mgmt> sudo vtysh -c` |
| `SH <sw> <cmd>` | switch Linux | GRO, kernel addresses, `sonic-cfggen -d --print-data` |
| `FW <cli>` / `FWX <xml-op>` | PAN-OS | CLI over `ssh -tt` with `sshpass -e` (exit 5 means a wrong password); XML API with the key in the `X-PAN-KEY` header; `show log` only with a time filter |
| `H <node> <cmd>` | VM guest | ssh with the lab key, user `admin` (`guest.user`), sudo; background jobs with `setsid` and stdin from `/dev/null` |
| `X <node> <cmd>` | container | `docker exec`, scoped |
| `K <args>` / `KSH '<script>'` | kubectl on the init node | `ssh` with the lab key to the init node (`stages.kubectl`), `sudo env KUBECONFIG=/etc/kubernetes/admin.conf kubectl` with each argument `%q`-quoted; `KI`/`KSHI` pass standard input; `KSH` only where a pipeline is needed. The admin kubeconfig never leaves that node; `common/bin/sfab-kubectl <lab>` is the same for programs outside `lib.sh` |
| `FR <rtr> <cmd>` | FRR container | `vtysh -c` |

**Terminal.** Every interactive session (`SW`, `FW`, `panos.sh`, `klish/session.sh`) runs its `ssh -tt` with no `TERM`, as under a systemd unit, whatever terminal started the run: under a terminal type (tmux's `screen`, `xterm`, `vt100`) the PAN-OS CLI redraws its echo of each word on one line with `ESC [K`, and the splitter then finds no command (chapter 4's revision 1 results, problem 4, not published, 4.4). A recorded run is `script -q -c '<make target>' state/rec-<target>.typescript` inside a tmux session, so the command the book prints is the one that ran; `common/tools/typescript.py` turns the typescript into the plain journal the book quotes (control sequences removed, carriage-return rewrites resolved as the terminal showed them, then `redact.py`'s rules applied, 4.3).

**Logins.** `_creds` gives the password runners (`SW`, `VT`, `SH`, `FW`, `FWX`) the login containerlab gave the node's own container, read with `docker inspect`: the launcher's `--username` and `--password`, else `USERNAME` and `PASSWORD` in the container's environment. For the switches and the PA-VM that is the kind's default login. The firewall tools in `common/fw/` (`panos.sh`, `fw-api.sh`, `fw-startup.py`) read the firewall's login the same way, as `common/klish/session.sh` reads a switch's, and take an exported `SFAB_FW_PASSWORD` only as an explicit operator override. None of the three prints or logs a password.

A batch runner retries each probe once, because the first packets of a new flow are lost to ARP.

### 4.2 Vocabulary

```
== section name
  PASS  [U][X] label
  FAIL  [U][X] label -> detail
  SKIP  [U] label (reason)
  KNOWN [R] label: L9
== RESULT: 41 passed, 0 failed, 1 known platform limitation(s), 0 skipped
```

**Helpers:** `ok`, `bad`, `skip`, `known <id> <label>`, `sec`, `chk <label> <want> <got>`, `ge <label> <min> <got>` and `summary`. `summary` returns non-zero on any FAIL.

**KNOWN lines** must name an id from `spec/known.yaml`. Its entries L1 to L11 mirror the platform limits (peer-link isolation, delay-restore, PFC and ECN, WRED, BMP, sFlow, LLDP after a swss restart, ECMP on addresses, no carrier loss at the far end, `docker pause`, host clock). KNOWN is never counted as a pass and never printed in a chapter.

**Tags.** Labels start with pillar tags. A planned `common/audit/purpose.py` (6.3) will roll them up: a purpose will pass only when each required tag has at least one PASS and no FAIL.

**Output.** `common/audit/vocab.py` writes the same format, so Python judges and shell checks print identical lines.

### 4.3 Evidence transcripts and redaction

- **Transcript.** With `EVID=<set>/commands.txt`, every runner appends one block. The block starts with a `### <UTC> <node> <surface>` header line, then the device's own prompt and command line as printed (extracted from the session, never synthesized), then the raw output. It is the one record of each command as it was sent; over the text cap it is stored as `commands.txt.gz` (4.4, recording size).
- **Raw sessions.** `raw/` keeps the verbatim `ssh -tt` sessions.
- **Keyed requests.** Transcripts are switched off around keyed requests with `EVID_OFF=1`. Keys travel in 0600 header files, never on a command line.
- **`redact <set>`.** Replaces `Authorization:` values, `key=`, `X-PAN-KEY`, set-format secret lines, PEM private-key blocks and every value from `state/secrets.env` (exact-string replacement). Key evidence is recorded as presence plus a keyed hash: a replaced value becomes `<redacted hmac:XXXXXXXXXXXX>`, the first 12 hex digits of its HMAC-SHA256 under the lab's redaction key, `state/secrets/redact.key` (64 hex digits, mode 0600, made by preflight's secrets step and gitignored with the rest of `state/`). The same value reads the same in every set of the lab, and nobody without the key can test a guess against a mark. The checks that record a launcher's login by presence (`host_launcher_login` in `collect.sh`, M1's `settle.sh`) print the same keyed mark, never a plain hash. A run that finds no key uses a random one of its own and says so. The sets recorded before this rule (M1 and M2) hold `<redacted sha256:XXXXXXXXXXXX>`, the first 12 hex digits of the value's plain sha256, as recorded, and their presence checks (`host_launcher_login`'s `02_launcher_login.txt`, and the settle checks of M1 and M2) print the first 12 hex digits of each checked value's plain sha256 as `sha256 XXXXXXXXXXXX`, user names and the kinds' default logins among them, so most of those prefixes match no mark. The switches' and the PA-VM's logins are their kinds' defaults and are not in `state/secrets.env`, so this pass does not know them; no runner writes them, because they travel only in `SSHPASS` or a 0600 request body (4.1).
- **The lab host's kernel release.** A container has no kernel of its own, so what it prints as its kernel release is the lab host's: the bonding driver's header in `/proc/net/bonding` (`Ethernet Channel Bonding Driver: v<release>`), FRR's `show version` (`on Linux(<release>)`), `uname -r` and `uname -a`. `redact.py` replaces the lab host's release, as a whole token, with `[redacted: host-kernel]` in every text file of the set and in containerlab's output, and a set that holds the marker gets `REDACTIONS.md` (below). The release is `uname -r` on the host where the set is recorded, or `$SFAB_HOST_KERNEL` when set; an empty value switches the rule off. A VM boots its own kernel and prints that release, which is kept (Chapter 3's nodes print `6.8.0-138-generic`); on a host that runs the very release its VMs boot, their lines read the marker too. The release is replaced after a hyphen, an underscore or a slash too (`vmlinuz-<release>`). Only the release is replaced, never the rest of the host's `/proc/version` (its builder's `user@host`, compiler and build date), so no audit reads a container's `/proc/version`, `dmesg` or kernel log, and a test checks the command lists for them.
- **The PA-VM's CPU signature.** `show system info` on the PA-VM prints `vm-cpuid`, the CPU signature the VM passes through from the lab host's processor. `redact.py` replaces its value with `[redacted: host-cpuid]` in every text file of the set and in containerlab's output, in the text form and in the XML API's, and the set gets `REDACTIONS.md`. The sets recorded before this rule (M1, M2, chapters 3 and 4) had it replaced in place on 2026-10-21 with `redact_tree.py` (below).
- **Throughput figures.** The repository publishes no measured throughput figure: a lab proves that traffic completes on a path, not how fast. `redact.py` replaces iperf3's transfer and bitrate columns, as one span, and any other rate in bits or bytes per second in the forms tools print it (`bits/sec`, `bit/s`, `kbit/s`, `Bytes/sec`, `bytes/sec`, `B/s`, `kB/s`, `MB/s`, `MiB/s` and the like) with `[redacted: throughput]` in every text file of the set and in containerlab's output, and the set gets `REDACTIONS.md`. Retransmits, the congestion window, a packet rate and a link's configured speed (`Mbps`, `Mb/s`) are kept. The timings llama-server adds to an answer's JSON (`prompt_ms`, `prompt_per_token_ms`, `prompt_per_second` and the `predicted_` ones, a token rate) are the one JSON form caught: each value becomes the marker, and the token counts beside them are kept (`redact_tree.TIMINGS`); a keyed capture has them blanked in place by `keyscrub.py` (4.5). A rate written another way, in words or in another JSON field (iperf3 `--json`), is not caught, so a check must not save such output. A check that runs iperf3 reads its result before the set is closed and says whether the run completed, never how fast (`dev/m1/settle.sh`, item 4).
- **containerlab's own output.** `clab()` in `lib.sh` passes every `containerlab deploy` and `destroy` through `redact.py --stream`: containerlab prints the output of any lab container that exited, and the TrueNAS launcher's output lists its environment, `PASSWORD` among it (M2, `dev/m2/RESULTS.md`, problem 5).
- **After recording: `redact_tree.py`.** Text found in a committed set that the repository must not carry is replaced with `common/audit/redact_tree.py --class CLASS` and a pattern source: a literals file, matched without regard to case and never printed (a binary file, a capture, is searched for each literal as text and as a DNS name on the wire), a regular expression, or a file of them. Each match becomes `[redacted: CLASS]` on the line that held it, so every line keeps its number and file:line citations hold; a second run changes nothing. A file stored compressed is read decompressed and written back compressed, and its lines are those of the decompressed text. The set gets `REDACTIONS.md`, rebuilt from its markers (file, line and class, never the text), and its row in the lab's `audits/INDEX.md`, or the lab's README where it has no index, says so; the ledger's first sentence says whether its markers were written while the set was recorded (`redact.py`), after it (`redact_tree.py`), or both. The classes are `host-search-domain` (the lab host's search domain in a container's resolv.conf), `host-kernel` (the lab host's kernel release, in the sets recorded before `redact.py` replaced it), `host-cpuid` (the PA-VM's `vm-cpuid`, in the sets recorded before `redact.py` replaced it), `throughput` (a measured throughput figure: in M1's two settle sets, recorded before `redact.py` replaced it; and the request count chapter 7's `make load` printed over its fixed 60 s in that lab's record-run journal and its typescript, which with the duration reads as a request rate and which no rule of `redact.py` catches), `private-path` (a path into the author's own private files, in one check written by hand into M2's record-refused folder, which was later removed from it; no recording writes one), `host-note` (a line written by hand into a set's host readings about the lab host outside the lab, in M2's record-refused folder; no recording writes one), `work-note` (words written by hand into a set about a step of the author's own workflow, in a header comment in M2's set G (`dev/m2/RESULTS.md`); no recording writes them) and `upgrade-notice` (containerlab's notice of a release newer than the pin, which its own version check can print in a deploy output; no committed set holds one). One class works on whole files and takes no pattern: `--class namecheck-summary` cuts a set's `repo/namecheck.txt` to the lines `audit_clean` saves today (the summary, and any fail line without its text), so that file's lines are renumbered; its row in `REDACTIONS.md` gives its length as recorded and the recorded numbers of the lines it kept, and a later marker run keeps that row.

### 4.4 `audit.sh` and the `audits/` layout

`chNN/audit.sh` is thin:

```bash
. "$(dirname "$0")/../common/lib.sh"; sfab_init audit "$@"
audit_collect                       # per role, from common/audit/cmds/<role>.list, switches in parallel
audit_judge                         # common/audit/judge.py, from the saved files only
audit_forwarding_only fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw    # the chapter 2 function chapter 3 reuses
audit_mclag_pair fe-sw1 fe-sw2
summary
```

**What collection saves.** Both forms of each command:

- text, as the book will quote it: KLISH, PAN-OS CLI;
- machine form: `sonic-cfggen -d --print-data` JSON, `vtysh ... json`, PAN-OS XML API responses, `ip -j`, `kubectl -o json`.

**Shared checks every lab gets:**

- GRO off on every switch after every boot;
- `ip vrf mgmt` present;
- parity;
- the MAC-table check, ignoring the containers' own veth MACs, the VLAN 1 entries learned on trunks, and on a pair member the partner's backup keepalive interface learned on the peer link in the backup VLAN;
- the forwarding-only reads (build A revision 2: an MCLAG member's only addresses are its two keepalive /31s, in the keepalive VRF):
  - KLISH `show ip interfaces` lists only Management0 (and on a pair member the keepalive link and the backup VLAN interface, each at its rendered address in `VrfMclagKa`), `show ip route` (in KLISH, never `ip route` on the Linux side) prints nothing, and `show ip route vrf VrfMclagKa` holds only the two connected /31s;
  - no `router` line, no address on any served VLAN's `interface Vlan` block, PortChannel or host port;
  - the kernel holds no address on any Vlan, PortChannel or Ethernet netdev but those two (lo-m, docker-mgmt, redirect and docker0 are whitelisted).
- chapter 3 on (`l2-hygiene`, the pair and the rail switches): the spanning-tree mode, every used port at its rendered MTU, BPDU guard on every edge port and on no other, none tripped, and storm control on every member and access port the spec's `l2:` policy names.

**Result set layout:**

```
chNN/audits/
  INDEX.md                                   Example number -> result set file:line (feeds Appendix G)
  sfab-ch03_audit_20261020T101500Z/
    RUN.json        lab, labs-repo commit with its dirty flag and source, spec and render sha256,
                    image digests, containerlab version, host tick, UTC start and end, stage durations
    RESULT.txt  verdict.txt  commands.txt
    fe-sw1/01_show_mclag_brief.txt  fe-sw1/01_show_mclag_brief.json ...  bastion/18_pods.json.gz
  sfab-ch03_trace_<ts>/   TRACE.md verdict.txt captures/<point>.pcap + .txt raw/
  sfab-ch03_drills_<ts>/  DRILLS.md pass1/ pass2/ pass3/ compare.txt
  sfab-ch03_break-3a_<ts>/
```

**The labs commit in `RUN.json`.** `labs_repo` gives the commit of this repository the run used, read once when the set opens by `common/bin/repostate.py`, from the first of these sources that applies; `source` names it:

- `git`: the lab's checkout is a git work tree of its own. `commit` is its HEAD, and `dirty` is true when a file outside the recorded sets (every `audits/` directory) differs from HEAD, or is untracked and not ignored. The set being recorded, or any other set, never makes a run dirty.
- `environment`: `SFAB_REPO_COMMIT` is exported. `commit` is its value, and `dirty` is `SFAB_REPO_DIRTY` (`1` or `0`), or `null` without it. `make up BG=1` passes both to its unit.
- `stamp`: the checkout is a copy made without `.git` (with `rsync --exclude .git/`, say). Run `common/bin/repostate.py stamp` in the git checkout before every copy: it writes `.repo-stamp.json` (ignored by git) with the commit, the dirty flag by the rule above and the sha256 of every file that rule covers, and the copy carries it. The run hashes those files again, and one that is missing or changed makes `dirty` true; so does a file outside the recorded sets that the repository's `.gitignore` does not ignore and the stamp does not list, added since the stamp (looking for one needs git, run on an empty repository of its own; without git, `dirty` is `null` unless a listed file differs). A git checkout never reads a stamp.

With none of them, `commit` is `none` and `dirty` is `null`: not known. The trace and drill pages `common/` writes print the commit in their header, followed by "(with uncommitted changes)" when `dirty` is true. Every set recorded before this rule, in M1, M2 and chapters 3, 4 and 5, says `commit: none` and `dirty: false`: the lab host's copy of the tree had no `.git`, nothing passed the commit on, and the false was never checked.

**As built for chapter 4.** `audit_fw_edge` in `lib-audit.sh` makes the edge's active reads into the set's `fw-edge/` (`show ntp` read every 30 s until the firewall's own NTP is synched, up to 20 minutes: on the first deploy PAN-OS's ntpd synched 15 minutes after its restart at boot; `show counter global filter value all` before and after a node pings the public address; the administrative interface (ae1.300) reached from the bastion's own address and not from another inside host; the public address from the operator's side, HTTPS asked for the internal Gateway's first hostname, since an address alone names no listener; the operator's connects to each of its forbidden cells in chapter 2's matrix, the client's view saved, with their log lines read per destination port and the drop counters' delta view read around them; a node's connect to an internet host the allowlist does not name (the client of a population with no audience, the web client, on 443), with its log line; a name resolved through the firewall's DNS service route and its own DNS and NTP in the log), then `judge.py fw-edge` judges them with the plan's files: zone bindings, rule order, the LAND counter (its name first looked for in the firewall's own counter table), the egress refusal (a timeout, and `deny-all-log` from the node's zone to the uplink's), administrative access, the service routes, and the uplink router's routes to the inside prefixes, which carry the operator's forbidden requests to the firewall. Under build A revision 2 an operator cell inside the tunnel's proxy IDs leaves its `deny-all-log` line in zone `operator-vpn`, and one outside them, sent in the clear to the uplink, is dropped by zone protection's strict IP check before any rule: the judge wants `flow_dos_pf_strictip` risen and no log line. `common/audit/panos_parse.py` reads every PAN-OS text and XML form the chapter 4 harness uses. The uplink router's plan also saves `show ip route` as text, for the book to quote.

**As built for chapter 5.** `audit_rail_backend` in `lib-audit.sh` reads, in each GPU node the full audit collected, every GPU namespace's links (`ip -n <ns> -j link show`) into the set's `rail-backend/`, then `judge.py rail-backend` judges the rail switches from the plan's files (no VLAN interface address, no gateway, no `router bgp` in KLISH or FRR's view, only the rendered GPU access ports up with every other port admin down, every MAC learned where the render cables it, only Management0 in the mgmt VRF, every rail port `no shutdown` at the factory MTU 9100 with no `mtu` line typed) and each GPU node collected (every namespace's connected rail and relay routes as `node.env` renders them, each source-pinned; no default route; `rp_filter` 2 everywhere; the rail NICs, the relay bridge, and in each namespace the macvlan and the relay veth at 9000). A quick audit judges the switches only; `show ip vrf` and `show interface status` are quick reads in `dell_sonic.list` from chapter 5's deploy on, since the group reads both (the full plan's order, and so every full set's file numbers, did not move).

**As built for chapter 6.** `audit_placement` in `lib-audit.sh` reads, with serving on and in a quick audit too, into the set's `placement/`: the serving namespace's pods, EndpointSlices, Services and rail attachments (JSON, and the pods, EndpointSlices and Services as kubectl prints them); inside each pod's own network namespace on its node (its sandbox found with `crictl`, then `nsenter`), its routes and addresses (JSON, and as `ip route` and `ip addr` print them); and for each model route a client of the lab reaches, one chat completion a model with the model's key, handed to the client through pipes into a 0600 file (`common/trace/lib-servecap.sh`), its status and response headers saved and never the request's. The table it judges against, `bootstrap/k8s/serving.env` or the one `audit.sh --table` names, is copied in beside them, with the recipe's render of it (`serving.py render`, no cluster read) in `placement/rendered/`, so a set holds the pod manifests and Services as rendered beside what the cluster runs. `judge.py placement` (`common/audit/placement.py`) judges the table by the recipe's own rules (`serving-layer/serving.py`) and each model's copies on rails of different parity, then each row's pod on its node with the row's attachment, address and MAC in its network-status annotation, each server's `--rpc` list and RPC-aware readiness probe with the table's timers, each worker's bind address, one macvlan attachment per rail used and no other, each Service's ready endpoints its servers, the default route on `eth0` and only the connected prefix on the rail attachment in every pod, no pod the table does not name, and the Gateways' answers. Each placement row's rail MAC is fixed by the render from its rail address (`render/k8s.py` `pod_mac`), so the rail switches' expected MAC tables (`gen/expect/<switch>.json`) hold every pod's MAC at its port, and the shared MAC-table check and `rail-backend` accept them.

**As built for chapter 7.** `audit_gateway_layer` in `lib-audit.sh` reads, with serving on, into the set's `keys/` (a quick audit too): for each model route a client of the lab reaches, that client's requests with no key, with a key no Secret holds (made in the client from its own random bytes), and with each other model's key (handed through pipes as `audit_placement` hands a key), each answer's status and body saved, never a request header; then the per-pod key probe (`common/trace/keyprobe.py pod`: a pod of the key tool on the probe's own account, the model keys' Secret mounted read-only, `sfab-keys probe` sending each model's first key to every API gateway pod by its address, on the key's own route and on every other), its log saved. `judge.py keys` (`common/audit/gwlayer.py`) wants 401 for no key and for the unknown key, 401 with the unknown key's own message for another model's key (the cross-key check), and from every API gateway pod 200 on the key's own route and 401 on the others (the per-pod key check). A full audit also reads into `gateway-layer/` the GatewayClasses, Gateways, HTTPRoutes, namespaces and leases, the Gateways' CiliumEnvoyConfigs, cilium-config and the inference ConfigMaps (JSON, and the Gateways, routes, leases and namespaces as kubectl prints them), each VIP from a GPU node (ping, a TCP connect to 443 and the neighbor entry), each VIP's chain from the bastion (`openssl s_client` against the lab root, with the users' hostname as SNI) and `sfab-ca proof` on the lab host with the outside leaves' verify output, and `judge.py gateway-layer` judges the GatewayClass, each listener's `allowedRoutes` and the namespaces carrying its label against the render, each Gateway's accepted routes and its hostname and path pairs against the render's, no admin hostname on a Gateway that carries none, each lease held by a control node, each VIP answering ARP and TCP and no ICMP echo, each chain verifying, the proof's outside leaves refused on a name constraint, and the timeout chain as the cluster runs it (the model routes' timeouts, the API gateway's upstream read and the router's attempts nesting) with the stream idle timeout each Gateway's listener runs.

**As built for revision 2 (build 4).** `audit_gateway_layer` gains, in a full audit with the identity provider, `audit_identity` (`identity/`, `judge.py identity` in `common/audit/clustersec.py`): from each person's client, the IdP's discovery document through the person's Gateway, a token with the API gateway's audience and one without (the person's password and the client's secret handed through pipes into a 0600 curl configuration, the tokens kept in 0600 files and never saved; only their claims are), each answered on every model route the client reaches (200 where the person's caller may call the model, 401 otherwise), the token without the audience and an altered one refused 401 with a Bearer challenge, and the API gateway's access log (file-logger JSON, no header in it) naming the person's consumer. `audit_build_a_cluster` gains `audit_cluster_security` (`cluster-security/`, `judge.py cluster-security`): each control node's API server flag and its EncryptionConfiguration's mode, etcd's stored prefix of the issuer's CA Secret (its first 26 bytes, `k8s:enc:secretbox:v1:key1:`), every Cilium agent's WireGuard status and peer count, each Gateway's certificate issuer and public-key fingerprint (no two equal), the network policies present and a probe pod in a namespace no policy selects refused by every policed Service while the cluster's DNS answers it, the edge pods on the ingress nodes, each ingress node's table 110, and the users' Gateway's SYN-ACK to a population's client captured leaving its lease holder tagged in VLAN 110.

The audit's own namecheck and the gate's run `namecheck.py --mask`, which prints each hit without the text it matched, so no saved file quotes a scrubbed entry (`ch03/RESULTS.md`, problem 1). namecheck reads its lists from outside the repository, and each is optional, though a list named by its option or variable that is not there is an error (exit 2): the scrub list from `$SFAB_SCRUB_LIST`, the allow list from `$SFAB_NAMECHECK_ALLOW` (a salted digest of each exact chunk a list entry catches by accident in what a device prints, never the plaintext) and the credential literals from `$SFAB_SCRUB_SECRETS` or `~/.config/sfab/scrub-secrets.txt`. Without a scrub list it prints `namecheck: skipped, no scrub list` and exits 3, and the audit and the gate record `SKIP` for it, not `FAIL`, so a reader's audit passes without the author's list; the literals, when that file is there, are still checked. A check with the author's lists runs over every committed set with `SFAB_REQUIRE_NAMECHECK=1` exported in that shell beside the lists' variables and `$SFAB_PUBLIC_TREE_PATTERNS` (no file of the repository sets it, since a reader's run has none of the lists): it makes the gate and the audit record `FAIL` where they would record that `SKIP`, `make namecheck` fail where it would skip, and the public-tree test below error without its list, so a run without the author's lists cannot pass. Every namecheck run recorded through chapter 5 used a digests file that the tool no longer reads, so the summaries the audits saved (`repo/namecheck.txt`) and the namecheck lines their gates and audits printed end in `(digests)`; they give counts only. A fail name entry of 6 or more letters and digits, a dotted domain or host included, also fails as a variant: its letters and digits joined by hyphens, underscores, spaces or nothing, with digits after it, or split by terminal escape codes; a path, a MAC prefix and a user at a host have no variant (the docstring of `common/tools/namecheck.py` has the rules). A file is ruled out from its words before any line of it is matched, and `--jobs` scans files in parallel. A second check needs no list for its general part: `common/tests/test_public_tree.py`, in `make test`, fails when a file outside the recorded sets (every file under an `audits/` directory but its `INDEX.md`) points at what a reader cannot open: a `../` path whose first name after the climb is no file or directory of this repository (a lab directory still to come, `chNN`, counts as one), a path into a `notes/` directory, or a decision cited by its number, whatever joins the word and the number (a space, an underscore, a hyphen or nothing), except as the head of a file name a recorded set carries, and only in the three files that must write such a name (chapter 4's `audits/INDEX.md`, which cites the recorded files, `common/audit/judge.py`, which reads them, and `common/tests/test_ch04.py`), since a recording keeps the names it was recorded under. Such a file states the fact where it is used, or cites the book's chapter or appendix by title. The rest of the check is the author's own: patterns for the names and wording of the author's private files and working notes, a deploy diary cited from a lab directory among them (1, a lab's own pages), read from a list kept outside the repository with the others, `$SFAB_PUBLIC_TREE_PATTERNS`. Beside each pattern the list holds made-up lines it must catch, and lines no pattern may catch, and the test proves both, so the repository never spells that vocabulary out (the test's docstring has the list's format). Without the variable those checks are skipped, as namecheck skips names without a scrub list; a list the variable names that is not there is an error, and so is no variable while `SFAB_REQUIRE_NAMECHECK` is set. Each line is also read joined with the next, so a phrase split across a line break is caught.

**`make record`** runs audit and trace, then `common/audit/gate.sh`, which checks:

- namecheck is clean, or `SKIP` when there is no scrub list;
- the secret scan is clean, a compressed file read decompressed, and no file holds the lab host's kernel release as a token (`$SFAB_HOST_KERNEL`, else `uname -r` on Linux);
- the literal scan is clean: no literal from namecheck's credential literals file is in any file of the set, captures included, in the forms `redact_tree.py --check` counts (any case, and in a binary file also the DNS wire form: the whole name, a leading run of its labels followed by a compression pointer, which is how a compressed name spells it, or a first label of 4 or more characters alone), each hit printed as its path and line without the literal, or `SKIP` when that file is not there or holds no literal;
- with `SFAB_REQUIRE_NAMECHECK=1`, a namecheck or literal scan that would be a `SKIP` is a `FAIL`;
- each pcap is under 5 MiB (larger ones are ignored, with their sha256 recorded);
- the recording size policy below: no plain text file over the text cap, no XML or JSON of 256 KiB or more stored plain, and the set within the set cap;
- RESULT shows 0 FAIL, except in break sets, which judge the designed failure as PASS.

`make record` gates only the sets it makes. A drill, break or heal set is gated with `common/audit/gate.sh SET...` before it is committed. A set of plain files (a launch's journals and the host readings written beside them) has no RESULT line for the gate: its journals are made with `common/tools/typescript.py`, which applies `redact.py`'s rules, and the set goes through `common/audit/redact.py SET` on the lab host before it is committed.

**Recording size.** A result set is committed, and a public repository keeps every commit, so a set carries each output once, stores its large machine-readable evidence compressed, and fits two caps. `common/audit/setsize.py` holds the policy: `pack` applies it when a set closes (`rs_close`, after `redact`), `check` is the gate's, and `report` measures a lab's sets by file class. The numbers come from the sets recorded through chapter 4, measured on 2026-10-21:

- **Each output once.** The transcript, `commands.txt`, is kept: it alone records each command as it was sent, with its time, and the book quotes it by line. The per-node `00_ALL_OUTPUT.txt` and the set's `ALL_DEVICES_OUTPUT.txt` only joined the per-command files beside them; no chapter, Appendix G or index cited them and nothing read them, and they were 128 MiB of the 1,063 MiB of recordings. They are no longer written. A drill's placement windows, `captures/place/`, are partial decodes of the captures committed beside them, which the drill reads while it places its probes; they are still written, and `.gitignore` keeps them out of commits.
- **Machine-readable evidence compressed.** An XML or JSON file of 256 KiB or more is stored as `NAME.gz`, which holds exactly the bytes of `NAME`. In the sets so far only two outputs reach it: the firewall's whole counter table, `show counter global filter value all`, 1.9 MiB as XML (0.8 MiB as text), read before and after each probe of chapter 4's audit, drills, break and heal; and `kubectl get pods -o json`, 1.1 MiB. The judge, the drills, the break and the heal read these files before the set closes, and every reader opens `NAME` or `NAME.gz` (`common/audit/evfile.py`); `namecheck.py`, the gate's secret scan, `redact.py` and `redact_tree.py` read a compressed file decompressed. Lines are counted in the decompressed text (`gzip -dc NAME.gz | sed -n 'A,Bp'`; macOS's `zcat` looks for `NAME.gz.Z`, so `gzip -dc` is the form that reads it everywhere), and a file the book quotes by line is committed plain. The compressed stream restarts after lines the content picks (a line whose CRC-32 is a multiple of 128, at least 4 KiB after the last restart), because git stores a plain file that differs from another in a few lines as a small delta of it, but finds little to share between two compressed files: the 18 counter tables of chapter 4's third drill run pack into 0.15 MiB as plain XML, 2.3 MiB as plain gzip and 0.5 MiB in this form, whose files are 23% larger than plain gzip's.
- **The text cap, 10 MiB a file.** No plain text file over it is committed. The largest plain file the book quotes by line is the transcript of chapter 4's `make audit` (8.1 MiB), and the largest capture decode is 3.7 MiB (chapter 3's drills). A transcript over the cap is stored as `commands.txt.gz`: chapter 4's drill transcripts are 49 MiB and its break's 16 MiB, nearly all of it the counter tables and CLI sessions saved beside them. Any other text over the cap fails the gate: a capture's decode is committed whole and as plain text, so a drill or trace whose decode passes the cap captures less. The decodes of the pcaps over 1 MiB so far are 1.4 to 1.7 times their pcap's size, so a pcap at the 5 MiB cap decodes to about 7 to 9 MiB.
- **The set cap, 64 MiB.** A set's committed bytes, as stored, without the placement windows and the pcaps the gate set aside. Under the policy the largest sets are chapter 4's drill runs (37.5 MiB) and audits (13.8 MiB). Chapter 3's revision 1 drills set, 126.7 MiB (72.0 MiB of capture decodes and 43.4 MiB of pcaps from three passes of four drills), predated the cap; it left the repository with chapter 3's revision 2 recording, whose six drills are recorded as three sets of three passes, the largest 57.2 MiB, so no committed set is over the cap. `common/tests/test_setsize.py` checks every committed set against the policy.
- **Sets not published.** A set that a lab's index marks as superseded, or that belongs to a deployment no Example quotes, is not committed, unless a chapter, Appendix G or an index row quotes it. The lab's `audits/INDEX.md` lists each with its RESULT line and the reason, under "Superseded sets" when the index marks it superseded and under "Result sets not published" otherwise.

`$SFAB_TEXT_MAX_MIB` and `$SFAB_SET_MAX_MIB` change the two caps for one run. The sets recorded before the policy were brought to it on 2026-10-21, and each lab's index or README says what changed in them.

A planned `keep-latest.sh` will prune only result sets that git does not track. It will never delete a committed or SUMMARY-referenced set.

### 4.5 `trace.sh` and `TRACE.md`

`chNN/trace.sh` reads capture points and flows from `chapter.yaml`, using `common/trace/lib-trace.sh` and `common/trace/trace-md.py` (promoted from M2's trace, which keeps its own copy as recorded). A flow with `same_frame: true` is also judged as one frame at every point that saw it: the same MACs, addresses, IP id and TTL, and the lease holder's bond MAC as its destination (chapter 3's four-point trace).

**Capture points.** Each point is `<depth>-<name>`, for example `3-fw-ae1-leg1` or `5-fe-sw1-Ethernet3`.

- On switch, firewall and router links: `nsenter -t <pid> -n tcpdump -i ethN -nn -s 256 -w`.
- In guests: tcpdump over ssh, decoded inside the guest, because `-i any` decoded on the host shows the host's interface names.

**Filters:**

- 802.1Q-aware: `(f) or (vlan and (f))`;
- tag checks by raw EtherType: `ether[12:2]=0x8100`;
- MPLS by `ether proto 0x8847`, never the `mpls` keyword before `vlan`.

**Procedure:**

1. `trace_start`: wait until every pcap exists, then 3 s more.
2. A warm-up attempt, labelled as such.
3. The recorded attempt, with the client source port pinned (`curl --local-port`).
4. `trace_stop` with `kill -INT`, waiting on PIDs, never a bare `wait`.
5. Decode with `-e -tttt`.

**Judgment** comes from the evidence:

- the SYN present or absent at each point;
- the same sequence number at every point, including across NAT;
- the tag present at each point;
- forbidden-column tallies, from ch11;
- the firewall traffic log as a second witness. Its entries are written at session end, and rule names are cut to 19 characters.

**As built for chapter 4.** A trace block with `sessions:` and `pull:` is rendered to `gen/trace.json` and run by `common/trace/lib-fwtrace.sh`: each session is one HTTPS request from a client (`common/trace/hold_request.py`, fed through `docker exec`) whose connection is held open after the reply while `show session all` and `show session id` are read, and whose traffic log line is read after it closes; the pull is a node's `crictl pull` through the registry mirror, captured inside and on the uplink, where the same sequence number carries the rewritten source. `common/trace/fwtrace.py` judges and writes `TRACE.md`.

**As built for chapter 5.** A trace block with `rails:` is rendered to `gen/trace.json` and run by `common/trace/lib-railtrace.sh`, its captures through `common/trace/lib-railcap.sh` (a guest's relay bridge captured and decoded inside the guest, a switch port on the lab host in the switch container): a same-rail health ping on every rail, then each flow's ping under its own ICMP id (`ping -e`) with every point capturing, traceroute from the same namespace, and the DF matrix (each flow forward and reversed at each size, `ping -M do`) with its own captures. `common/trace/railtrace.py` judges each point's requests and replies against the plan, the IP id of one request at every point that saw it, the hops and the DF rows (where a refused size was refused; the DF bit judged on the requests, since the far kernel's echo replies carry none, which the trace records), and writes `TRACE.md`.

**As built for chapter 6.** A trace block with `serving:` is rendered to `gen/trace.json` and run by `common/trace/lib-servetrace.sh`: both namespaces' pods and the lease of the Gateway's VIP read first, the model's key handed to the client as a 0600 header file, a warm-up request, then the captures servetrace.py lists from what was read (the lease holder's `bond0`; every API gateway, router, server and worker pod inside its own network namespace in its node's guest, `lib-railcap.sh` `railcap_pod_start`, a pod's cluster interface at 66 bytes a frame so no capture holds an HTTP header; the rail switch ports facing each copy's nodes), and the request with curl, its source port pinned, the key read from the header file. `common/trace/servetrace.py` follows the request by the addresses each hop sends to and the segments that carry data, and writes `TRACE.md` with the path hop by hop. A router reads each model's list from its Service on its own now and then (`GET /v1/models`); where the router pods are captured whole (a keyed trace), a connection that carried one is set aside, and named, when the other copies are judged to have carried none of the request.

**As built for chapter 7.** A `serving:` trace with `keys: true` captures every API gateway pod and every router pod on its cluster interface whole (2048 bytes a frame); `lib-railcap.sh` (`RAILCAP_SCRUB=1`) takes each of those pcaps out of its guest only on a pipe through `common/trace/keyscrub.py`, which overwrites every `Authorization` value and every token shaped like a key in place with its keyed mark (redact.py's, padded to the value's length so every frame keeps its length) and blanks with `_` each timing value llama-server writes into an answer (a token rate, 4.3), writes the scrubbed pcap, and decodes it on the lab host as `<point>.txt` and with `-A` as `<point>-payload.txt`; `captures/scrub.log` counts the values each pcap had replaced and blanked. The caller's key, the router's master key and the backend key are named in `request/` by field, fingerprint and mark (`servekeys.py --mark-key`, `mark`), read through pipes from their Secrets. `servetrace.py` then judges the HTTP requests each in-cluster hop carried, from the payload decodes: the caller's key's mark from the Gateway's proxy to the API gateway pod, the master key's from the API gateway to the router with the caller's nowhere on that hop, the backend key's from the router to the server, and every `Authorization` value a mark. With `refuse:`, one more request from the client, with no key, to a hostname the Gateway does not carry: the Gateway's 404, the SYN at the lease holder, and no request for that name at any API gateway pod, which must have received the keyed request alone.

**As built for chapter 1.** A trace block with `walk:` is rendered to `gen/trace.json` and run by `common/trace/lib-walktrace.sh`, which reuses chapter 4's held session (`lib-fwtrace.sh`, `hold_request.py` with a POST, its body and the key's header file read inside the client), chapter 6's and 7's serving captures and key marks, and adds the frontend: one chat completion from the enterprise client through the users' Gateway, after a warm-up, walked inward with every device's table. The client's own lookup and the resolver's lookup from its own address (`dns/`); the firewall's routing table, security and NAT rulebases in one CLI session, then the session table while the connection is held and its traffic log line after it closes (`fw/`, `sessions/walk/`); the rail switches' counters cleared (`clear counters interface all`, answered `y`, the session typed a line every 5 s, since KLISH never reads an `exit` typed ahead of the answer) and read before and after the request, each read stamped on the lab host's clock, with their MAC tables and the pair's (`rail/`, `pair/`); the HTTPRoutes, the lease, the API gateway's routes and the router's model list (`cluster/`); captures on the client's port, the firewall's interface facing it, both legs of the bundle, the pair ports those legs land on and the pair ports facing the lease holder, all on the lab host, then the serving trace's points. Three refused requests follow from their own pinned source ports: the admin hostname with no key, the walked model's route with another model's key, and a connect to a node's SSH port (`common/trace/syn_connect.py`, the client's view recorded). `common/trace/walktrace.py` judges each hop from the saved files (the view's answer; the connected route, no NAT rule from the client's zone and the first matching rule; the same SYN by sequence number on the client's port, on the firewall's interface, on exactly one leg tagged with the Gateway's VLAN with its TTL one lower, on the pair port that leg lands on and that switch's port facing the lease holder, untagged on the holder's bond with its MACs, TTL and IP id as the leg carried them; the holder's bond MAC in the pair's MAC tables; the matched HTTPRoute, the model's route and consumer group, the router's model list and the server among its Service's ready endpoints; the rail port's counters at least the frames its capture counted between the reads, and the worker's rail MAC in that switch's table), judges each refusal where it died and that nothing of it passed that device, and writes `TRACE.md` with the table of hops, devices, tables and decisions.

**As built for chapter 2.** In a lab whose chapter.yaml says `decisions: true`, the walk's plan carries `rows:` (`render/trace.py`): each hop's row of the decision table (the resolver view at the resolver, routing, NAT and security policy at the firewall, forwarding only at the bundle's leg, the pair and the rail switch, the route set at the Gateway, the key at the API gateway, placement at the Service and the copy, none at the client, the lease holder and the router) and each refusal's (the route set, the key, security policy), with each row's layer; `walktrace.py` then prints a Row column in `TRACE.md`'s two tables. Chapter 1's plan carries none, so its page is as recorded.

**`TRACE.md`** holds:

- a header: lab, commit, UTC;
- the client and path table;
- the verdict block;
- a per-point table of frame counts and SYN counts;
- the first SYN per point with link headers;
- `file:line` pointers;
- the `== RESULT` line.

The count of capture points is computed and printed, never fixed in prose.

### 4.6 Drills (`common/drill/lib-drill.sh`)

**Lifecycle:** `drill_init <id>`, then `restore_add "<cmd>"`. The restore commands run last-in first-out from an EXIT/INT/TERM trap.

**Probes:**

- `probe_icmp <src> <dst> --id <n>` uses `ping -e <id>`, placed on a bond leg by ICMP id;
- `probe_tcp` connects every `interval_s` (chapter 3: 0.1 s), a new source port each time, logging each attempt's local port so the captures on the firewall's legs locate it;
- `probe_http` sends a request every second, with the key in a 0600 file;
- `probe_load` runs serving-layer `make load` aimed at a population address;
- `probe_storage` writes 1 MiB with O_DIRECT and fsync every second.

**Locating the flow.** `locate_by_counters` (`clear counters interface all`, then `show interface counters`) or `locate_by_capture` (2 s per candidate). Every pass locates its flow before its cut.

**Faults:** `fault_shut <sw> <EthernetN...>` and `fault_range`, both in KLISH. The restore is `no shutdown`.

**Measurement:** `drill_wait`, then `drill_measure`. Late replies (RTT over 1 s) count as lost. Durations are quoted from the host clock; a set whose host tick read other than 10000 carries the `host-tick` stamp and its RESULTS page says so. `drill_verdict` records the result.

**Passes.** `make drills DRILLS="3a 3b" PASSES=3` writes `pass{1,2,3}/`. `compare_passes.py` prints disagreements between passes, and `summarize.py` writes `DRILLS.md`. After each drill, `audit --quick` runs on the devices it touched.

**As built for chapter 3.** The plan is chapter.yaml's `drills:` block, rendered to `gen/drills.json`; drill ids are names (`make drills DRILLS="fw-leg server-member" PASSES=3`). `lib-drill.sh` holds the bash half (the lab-whole check, captures, probes, faults, the reboot monitor) and `drill.py` the Python half (placement, the whole-bond check, the reboot's events, the analysis). Per drill and pass: the lab whole first (the pair as `judge.py mclag-pair` reads it, and every bond on its legs under the system MAC, two polls in a row); host-side tcpdump on the probes' own container ports; the ping as one `ping -D -O -i 0.1 -W 1 -e <id>` per ICMP id in the source guest, the connect loop (`probe_tcp.py`) in the client; placement read from the captures after `lead_s` (decoded so far into `captures/place/`, which is not committed: 4.4, recording size), the pings restarted with new ids up to `place_tries` until placed (a drill never placed still runs, and a FAIL line says it measured no worst case); the fault, its restore pushed first; the hold with counter and KLISH snapshots, or for a reboot the monitor until every bond is back on two legs; the lab whole again, `audit.sh --quick`, then `drill.py analyze`. Every time is the lab host's clock: a guest's ping is timed from the host-side captures of its container ports, and the guest's own ping log is the second witness of each round trip, a disagreement printed and never resolved. Loss counts round trips, split at the cut, at the restore and elsewhere; a reboot's return is an event (every bond back on two legs), never a span from its departure. KNOWN lines name L9 on every shut, L2 on every reboot and L1 on any duplicate reply.

**Revision 2's keepalive drills (chapter 3).** A shut may name the pair's dedicated keepalive link (`shut: {switch, keepalive: true}`), with or without a PortChannel (`portchannel: 1` beside it cuts both keepalive paths), its own `hold_s` (a keepalive cut must outlast the 30 s session timeout) and `await_return: true`. Such a drill runs the reboot's monitor from before the cut to the return, reads the roles first (`ACTIVE` and `STANDBY` in the timeline), and after the restore waits, up to `return_max_s`, for the pair as rendered and every bond on its legs in two polls in a row, no sooner than 10 s after the restore: the standby that shut its own MCLAG PortChannels while the keepalive was gone holds them down for delay-restore once it is back. `drill.py analyze` reads the standby's events from the monitor (the session lost, its PortChannels down, every bond on one leg, the session back, its PortChannels up) beside the drill's own `RETURN` line, and counts the probes lost around the standby's shut and its return in windows of their own.

**As built for chapter 4.** A drill that names `nat_removed` or `service_route` is a firewall drill (`common/drill/lib-fwdrill.sh`, `common/drill/fwdrill.py`), changed live through `common/fw/fw-api.sh` with its restore pushed first: `land` removes `no-nat-public` and reads `show counter global` around a node's requests to the public address (the drop counters' delta view right before and right after them, since every `show counter global` read starts the firewall's next delta sampling), with packet-diag's receive and drop stages captured (exported through the API, `fw-api.sh export-pcap`) and the rule put back where the render places it; `ntp-uplink` moves the firewall's NTP service route to the uplink, with every service route whose server is the same address (DNS: moved alone, the NTP route left the firewall's NTP on the DNS route's source on the PA-VM, chapter 4's revision 1 results, problem 5, not published, 4.4), looks a name up through the firewall so its DNS query leaves at once, and reads the traffic log for `deny-all-log`'s lines for both, then moves them back and sees both allowed again. The counter's name is relied on only once the firewall's own counter table has printed it. `fwdrill.py summarize` writes `DRILLS.md`.

**As built for chapter 5.** A drill that names `dark:` is a rail drill (`common/drill/lib-raildrill.sh`, `common/drill/raildrill.py`): every port the switch uses is shut in one KLISH session (`interface range`, from `_shut_session`), its restore pushed first, held `hold_s`, then given `no shutdown`. The rails probe runs one `ping -D -O -e <id> -c <count>` per row in the source guest (a count that outlasts the drill, never `-w`: with a deadline iputils ping exits at the first error the network reports, and on a dark rail the source's neighbor entry fails and its kernel reports Destination Host Unreachable) (the same rail on every rail, and the cross-rail pairs the block lists), and tcpdump on the lab host records both nodes' container ports on every rail. Before and after, the rails whole (every same-rail row answered and every rail switch's rendered ports up, in two consecutive polls); during, `show interface status` on every rail switch and the nodes' rail NICs as their kernels see them. `raildrill.py analyze` follows each row's request out of the source and into the far node on the rail it rides and the reply back on the rail it rides, groups them by when they were sent (before, at the cut, dark, at the restore, after), judges each row dark or answered as the plan marks it and where a dark row went silent, and times the first answered request after the restore as an event, and counts for each dark row the ARP requests sent for the far address on the dead rail while dark and the guest log's Destination Host Unreachable lines; `raildrill.py summarize` writes `DRILLS.md`. KNOWN L9 is printed on every pass.

**As built for chapter 6.** A drill that names `worker_port` or `rail_move`, or `dark:` with the `gateway` probe, is a serving drill (`common/drill/lib-servedrill.sh`, `common/drill/servedrill.py`). The endpoints probe reads the serving namespace's EndpointSlices from the bastion every interval on the lab host, each read stamped when it began and ended; the gateway probe (`common/drill/probe_gateway.py`, run in the client, whose clock is the host's) sends one chat completion a model every interval through the Gateway's model route, each request on its own, recording its times, status, outcome and the router's headers (the deployment that answered and the retries it made). The fault is one KLISH session on the rail switch (every port it uses, or the one port facing the worker's node on the copy's rail), its restore pushed first; after the restore the drill waits until every Service holds all its servers again. The serving and inference namespaces' Warning events are saved and cleared after each drill, since the readiness failures are its evidence and the audit after it expects none. `servedrill.py analyze` times each server's removal from and return to each Service, bracketed by the reads around it, against the readiness bound, checks no server the fault leaves alone left, and counts the probe's requests by when they were sent and how they ended; `summarize` writes `DRILLS.md`. A `rail_move` drill changes only a copy of the table: the recipe refuses to render it, `audit.sh --quick --table` against it fails, and the audit against the table as rendered is green. KNOWN L9 is printed on every fault pass.

**As built for chapter 7.** A drill that names `key_lifecycle`, `rejected_code` or `idle_timeout` is a gateway drill (`common/drill/lib-gwdrill.sh`, `common/drill/gwdrill.py`); a drill may name `max_passes`, the passes that run it. Every gateway drill checks the gateway layer whole before and after (every API gateway and router pod Ready, both Gateways Programmed, the test backend ready, two polls in a row), pushes each restore before its change, archives the inference and test backend namespaces' Warning events (the idle drill also Cilium's namespace, where its pods' readiness probes fail while the drill rolls them, which the next full audit would otherwise read) and runs `audit.sh --quick`. `key-lifecycle`, under the gateway probe with each model's first key (which must lose nothing; a model the probe names under `every` is sent on every K-th interval only, as in the serving drills): a key Job (`keyprobe.py job`, the key Job's account) mints a key whose id is the drill's id base plus the pass; the new key goes to the client, whose own probe sends it through the VIP every interval, while the per-pod probe sends it to every API gateway pod in rounds until each accepts it; one round on the other model's route; a second probe pod started before the revoke (it reads its key file once), the revoke, and its rounds until every pod refuses the key. `rejected-code`, under the same probe: the API gateway's routes ConfigMap applied server-side as the render makes it without one route's `rejected_code` and `rejected_msg` (`render/inference.py apisix_routes(default_code=...)`), the per-pod probe in rounds until every pod answers another model's key with the plugin's own default, the rendered ConfigMap back and the rounds until every pod answers 401 again. `idle-timeout`: one request from a client through a Gateway to the test backend while its processes are stopped with SIGSTOP from their nodes' guests (found with `crictl`) for `silent_s`, then continued, with the lease holder's `bond0` and the backend pods' cluster interfaces captured; then Cilium upgraded with helm from the bastion with the rendered values plus both stream idle keys (`render/k8s.py cilium_values_doc`), its operator, agents and Envoy rolled, the backend's route applied with timeouts, until the listener reads the corrected timeout and the route answers; the same silence; then the rendered values and route back, the listener read again and the release's values compared with the render's. `gwdrill.py analyze` times each change's reach (the Secret's write, the first 200 through the VIP, each pod's acceptance and refusal, the ConfigMap's reach at each pod), counts the probe's requests by how they ended, and for the idle drill names each half's status, time and server, the listener's timeout, whether the backend sent a byte before it was continued and when the Gateway's proxy closed its connection, and the time of each helm upgrade and rollout with each Gateway's lease holder and transitions read before and after them; `summarize` writes `DRILLS.md`.

### 4.7 Break and heal

`chNN/breaks/<id>.yaml` holds:

- `title`;
- `break:` typed actions: `klish {node, context, lines}`, `panos_api {set|del, xpath, element}` plus commit, `kubectl {apply|delete|patch}`, `dns {node, file}`, `frr {node, lines}`, `host {node, cmd}`;
- `record:` evidence commands;
- `expect_broken` / `expect_healed` checks;
- `heal:`, either explicit actions or `restore: <node>`.

The exact KLISH lines of each break are fixed when the break is first run and its acceptance is recorded.

`common/breakheal.py {break|heal} <id>` marks `state/breaks/<id>` so the same break never applies twice. It records `audits/<lab>_break-<id>_<ts>/` and runs the chapter audit after heal.

`restore` is generic:

- switches: replay plus parity;
- firewall: a partial load of the render plus commit;
- Kubernetes: re-apply;
- DNS: re-render and reload.

`make heal-all` restores every device this way.

**As built for chapter 3.** A break file is rendered to `gen/breaks.json` (`render/drills.py`), so the lab host needs no PyYAML, and a changed break is drift to `sfab check`. `breakheal.py` validates and hands over to `common/break/breakheal.sh`, which holds the lab's lock and owns the result set (`audits/<lab>_break-<id>_<UTC>/`, `audits/<lab>_heal-<id>_<UTC>/`). Built so far: `klish {node, context, lines, fallback}` (the fallback is typed only when the switch answers the lines with "% Error", and the set records which form it took), `show {node, lines}` and `probe_tcp {from, to, address, port, count, interval_s, timeout_s, passes}` in `record:`, `restore: <switch>` (replay plus parity) in `heal:`, and the checks `vlan_member`, `parity`, `probe_share {failing: some|none}` and, from build A revision 2's break-3b, `mclag_iface {node, portchannel, local, remote}` (an MCLAG interface's Local/Remote status as `show mclag brief` prints it on that member, read with the pair audit's parser, `breakheal.py mclag`). The firewall, Kubernetes and DNS actions land with the chapters that first break those.

**As built for chapter 4.** The firewall's actions: `panos_api {del|set: nat|security, rule}` (a delete, or the rendered rule set back and moved where the render places it; one commit after a part's firewall actions, and a break whose commit fails is put back at once), `fw_show {lines}` in `record:`, `probe_ping {id, from, to, count, interval_s, timeout_s, passes, counters}` (the counters read in `show counter global` before and after each pass; break-4a brackets one uncounted ping run with two delta views, since a full counter read would restart the delta sampling) and `probe_http {id, from, hostname, path, count, interval_s, timeout_s, passes}`, and the checks `counter {name, probe, rise}`, `rule_order` and `probe_share {failing: all}`.

**As built for chapter 5.** The relay's actions: `relay_route {node, rail, to_rail, src: none|rendered}` in `break:` and `heal:` (the rendered relay route from namespace `gpu<rail>` to rail `to_rail` replaced with `ip -n <ns> route replace`, without its source pin or with it, and read back), `ns_show {node, rail, to, get}` and `probe_rail {id, from, to, rail, to_rail, count, interval_s, timeout_s, passes, capture}` in `record:` (pings from a GPU namespace to the far node's rail address, or with `rail: all` the same rail on every rail; with `capture: true` the far node's rail NIC and relay bridge are captured in the guest around each pass), and the checks `route_src {node, rail, to_rail, pinned}` and `far_capture {probe, src: relay|rail}` (`breakheal.py farcap`: where the far node saw the requests come from and where its replies went).

**As built for chapter 6.** The serving recipe's actions (`common/break/lib-servebreak.sh`): `pod_rail {pod, to_rail}` in `break:` (the pod made again by `serving.py move` on another rail, at the first free address of that rail's pod range and that address's MAC, with an attachment for the rail when the table uses none; its labels still the table's), `serve {replace}` in `heal:` (the named pods removed, then `serving.py serve`, which replaces a pod whose rendered stamp differs and removes an attachment the table does not use), `k8s_show {}` and `probe_gateway {id, from, gateway, models, count, interval_s, timeout_s, passes}` in `record:`, and the checks `endpoints {service, ready}`, `placement {pod, rail}` and `mac_gone {pod, wait_s}` (the rail switch's MAC table read until it no longer holds the MAC the moved pod had on its wrong rail). After a heal in a serving lab the serving and inference namespaces' Warning events are saved and cleared before the chapter audit.

**As built for chapter 7.** The API gateway's key actions (`common/break/lib-keybreak.sh`): `key_hold {pod}` and `key_mint {model, id}` in `break:` (an API gateway pod, by its place among them by name, held: a hold file in its sidecar's shared directory, while which `sfab-keys compose` keeps the `apisix.yaml` it has; a key minted by a key Job), `key_probe {id, model, key, route, expect, wait_s}` and `key_show {}` in `record:` (the per-pod probe in rounds; the Secret's fields and fingerprints and each API gateway pod's sidecar log), `gateway_restart {pod: held}` in `heal:` (the held pod deleted, its Deployment rolled out), the check `key_pods {probe, refusing: held|none}`, and `probe_gateway` with `key:` (a named key, not the model's first). A break file may carry `cleanup:`, actions run after `expect_healed:` is judged and before the chapter audit: `key_revoke {model, id}` puts the key Secret back to the lab's first key a model.

**As built for chapter 1.** `panos_api {edit: security, rule, destination}` in `break:` and `heal:` replaces one security rule's destination node through the XML API's edit (a set would add members beside the rendered ones), with the break's addresses or, with `destination: rendered`, the render's, then commits; `probe_syn {id, from, to, port, count, sport, timeout_s, passes, capture}` in `record:` makes `count` connects from a client, each from its own pinned source port (`common/trace/syn_connect.py`; a heal's ports follow the break's), while the container ports `capture` names (`node:eth`) are captured on the lab host around each pass, its shares judged by `probe_share`; the checks `syn_at {probe, seen, seen_any, unseen}` (where the probe's SYNs were captured, and where not) and `tlog_rule {probe, rule, action}` (the traffic log read until it holds every connect of the probe, each logged under that rule with that action).

**As built for chapter 2.** `dns_answer {node, view, names, answer}` in `break:` gives the named hostnames of one view another answer (`vip:<gateway>` or `public`): the render writes the view's forward zone with those names moved (`render/dns.py` `answered_zone`, its other entries as rendered, a comment line saying so), the break copies the server's render to `/tmp/sfab-break-dns` in its container, writes the zone there and reloads the server on the copy (`sfab-dns reload`, which checks every file first); `restore: <DNS server>` in `heal:` installs the server's render again and reloads it (the render refuses a dns_answer whose server no restore names). `matrix_cells {id, cells}` in `record:` tries cells of the lab's matrix as `matrix.sh` does (4.8), into the set's `probes/<id>-<mode>/`, with each cell's mode as its evidence shows it in `observed.jsonl`; the check `cell_mode {probe, cell, mode, rule}` (`breakheal.py cellmode`) wants that mode, and for a log line that rule.

### 4.8 The decision table and the matrix (`common/matrix/`)

A lab whose chapter.yaml says `decisions: true` (chapter 2 on) renders `gen/decisions.json` and `gen/matrix.json` (2.2) and ships `label.sh` and `matrix.sh`, run by `make label` and `make matrix` (`run.sh` stages `label` and `matrix`, recorded sets of those categories) and by `make record` after the audit and the trace. Both read only the committed JSON, so the lab host needs no PyYAML.

**`label.sh`** (`common/matrix/label.sh`, judged by `common/matrix/label.py`) reads the live object behind every row of the decision table and changes nothing on any device: each population's lookup of the users' hostname from its own client (`dig` in a container, `getent ahostsv4` in a VM guest) and each BIND server's installed zone file; the firewall's routing table and both rulebases in one CLI session, and the running rulebase through the XML API (`fw-api.sh show`), whose rules carry their descriptions; each router's `show ip route` and the configuration bound into it; every HTTPRoute with its labels; the API gateway's routes ConfigMap and one pod's key logs, its compose init container's and its sidecar's (consumers by fingerprint); the placement table, the serving pods and the rail attachments; and each switch's delivered startup file and `show ip route`. The judge wants every object live and labelled with its decision id, both rulebases in the rendered order with `deny-all-log` last (PAN-OS's two predefined rules after it set aside, as the audit's judge sets them aside), and every switch labelled forwarding only with an empty `show ip route`, and writes `LABELS.md`, one line per object with its row, decision and evidence by file and line.

**`matrix.sh`** (`common/matrix/matrix.sh`, judged by `common/matrix/matrix.py`) tries every cell from its population's own client, never by ping: a connect cell by one TCP connect from a pinned source port (`syn_connect.py`), a name or model cell by an HTTP request by name through the client's own resolver, its source port pinned with curl's `--local-port`, a model cell twice (its own key, then another model's). First each client looks up every name its cells ask for; then both models' keys go to each client a model cell runs from, through pipes from their Secret into a 0600 header file (over ssh's standard input for a VM guest), never on a command line, in the transcript or on the lab host; then every request, each attempt in `requests.tsv`, an attempt that was to be answered and was not tried once more from the next source port after a pause (the first packets of a new flow are lost to ARP); then the traffic log for every destination port an unanswered attempt crossed, read until it holds each of them, the firewall's and the routers' routing tables and the API gateway pods' access log over the run; where a cell of the run is dropped by zone protection's strict IP check, the firewall's drop counters' delta view is read before and after the requests; last the keys' files are removed. A mode is observed from that evidence alone (an answer is allowed or its HTTP status; an unanswered attempt is a log line when the traffic log holds a deny for its source port, silence when no log line names it), and the judge asserts each cell's mode with its evidence: a log line's rule and zones and the client's view, the router's route to the firewall for a cell the firewall refuses behind it, a silent cell's device with its own evidence (a router's table without the route, the firewall's discard route, or for the strict IP check the firewall's route back to the source out another interface and `flow_dos_pf_strictip` risen over the run), a 404 with no line for the request's marker in an API gateway log that holds the run's model requests, a 401 with the API gateway's own message. A cell in another mode than the plan's fails whatever its outcome, and `MATRIX.md` prints the matrix turned on its side with every cell's verdict and evidence. No measured duration is printed: the client's view is named (a timeout at its connect timeout, an error, a reset), never timed.

## 5. Images

| Image | Tag | Base and contents | What the image's scripts do |
|---|---|---|---|
| Linux VM node | `sfab/vm-node:6-k8s1.35.8` | **Runtime:** `ubuntu:24.04` plus qemu-system-x86, qemu-utils, cloud-image-utils, genisoimage, iproute2, ethtool, gettext-base. **Base disk baked into the image** at `/base/node.qcow2`, so it lives once, in Docker. `make -C images vm-node-base` boots the pinned Ubuntu 24.04 cloud image (serial and sha256 in `versions.yaml`) with `user-data-bake.tmpl`, installs the pinned packages (containerd, kubelet/kubeadm/kubectl v1.35.8, CNI plugins, open-iscsi, multipath-tools, nfs-common, nvme-cli, lldpd, linux-modules-extra for the baked kernel), holds the kernel, disables unattended upgrades and the apt timers, powers off and flattens the disk | **`vm-init.sh`:** bridge plus tap per NIC; `group_fwd_mask 0x4004`; MAC-named NICs through `.link` files; NoCloud seed; qcow2 overlay that grows, never shrinks; link keeper; guest hold before the link wait; container-side TX off; on a GPU node that runs a model server, the bound models directory exported to the guest read-only over virtio-9p (mount tag `models`), with a mount unit at `/srv/models` that kubelet requires. **`node-files/`:** `sfab-netsetup.service` (after network-online), `sfab-cluster.service` (`Restart=on-failure`), `networkd-foreign.conf`, lldpd exclusions, `cluster-bootstrap.sh` (idempotent init and join; kube-vip with `super-admin.conf`, then a localhost kubeconfig; the intermediate CA chain, checked against the lab root before anything else runs; the admin kubeconfig stays on the init node; absolute eviction thresholds). **`netsetup.sh`:** 802.3ad `lacp_rate fast`, layer3+4, speed and duplex set; management table 150, out-of-band table 100, routed rails table 300+r; the relay; `src_valid_mark=0`; sshd on `ssh.service` with `ssh.socket` disabled; per-node IQN `iqn.2026-10.example.<org>:<host>` |
| Bastion | `sfab/bastion:4` | `ubuntu:24.04` plus openssh-server, lldpd, jq, openssl; kubectl, helm and cilium-cli at pinned versions with sha256 | `bastion-init.sh` (PID 1 with traps, `resolv.conf` naming dns-res1 and dns-res2 and searching the platform zone only, one leg in the bastion VLAN, table 150, the lab root trusted from `/shared/ca`, each operator's short-lived kubeconfig picked up from `/sfab/operators`); `operator-shell.sh` (guard variable `_SFAB_OPERATOR_SHELL`); key-only login. A jump host only: no DNS, time, CA, BMC leg or admin kubeconfig |
| Resolvers | `sfab/resolver:3` | pinned Alpine plus bind9, dnsmasq and chrony; `ROLE=bind-auth|bind-recursive|dnsmasq`, and chrony when the render holds `chrony.conf` | BIND views keyed by the asking resolver's address, per-view TSIG keys (bound from `state/secrets/tsig`) for NOTIFY and AXFR from dns-auth1 to dns-auth2; static-stub zones and an empty root on dns-res1 and dns-res2; dnsmasq `host-record` per corporate name and `server=/ai.tarnwick.example/` to the pair; chrony `-x` (never adjusts the host clock), NTS from inet-ntp with a leaf of the internet intermediate; management table 150; BIND transactional reload (`named-checkconf`/`checkzone`, then `rndc reload`) |
| Clients | `sfab/client:2` | pinned Alpine plus curl, openssl, bind-tools, tcpdump, iperf3, python3, iproute2, ethtool, jq, bash, openssh-client | `init.sh`: wait for links; address and gateway; management default to table 150; `resolv.conf` searching the lab's domain only, never the lab host's (Docker's nameserver and options kept when the lab has no resolver for the node), with options (`timeout:10 attempts:4` where the spec asks); lab root CA appended to the bundle explicitly; TX off |
| FRR | `sfab/frr:10.5.4-3` | `quay.io/frrouting/frr:10.5.4` by digest, plus openssh, tcpdump, iproute2, ethtool, pre-baked | `frr-init.sh`: wait 180 s for links; **eth0 enslaved to VRF `mgmt`**, so the main table holds no management default and sshd runs in that VRF; `ip_forward`, `rp_filter 0`, `platform_labels` and `conf.<if>.input=1` on core interfaces only; customer VRFs from `init.env`; TX off; `resolv.conf` searching the lab's domain only; `vtysh.conf` present; configuration bound read-only. Healthcheck `vtysh -c 'show version'`. Used for the uplink router, ISP router and carrier |
| Serving | `sfab/serving:b11382-2` (in `serving-layer/image/`) | `debian:12-slim` by digest plus libgomp1 and libssl3 from their pinned `.deb` files, llama.cpp `b11382`'s x64 Ubuntu build (`llama-server`, `ggml-rpc-server` and the libraries beside them, sha256) and `sfab-ready`, the readiness probes; no model: the two models (LFM2.5-24B-A2B and Qwen3.8-27B as GGUF, Hugging Face revisions and sha256 under `serving.models`) live in `images/models` and reach the servers read-only through the GPU nodes' models share; user 65532; no training stack, no iperf layers | fetch rule (`images/fetch.py`): a copy whose sha256 matches is used, else the pinned URL is downloaded and refused unless its sha256 and size match; publisher metadata (size, ETag or listed digest) agreed with each pin when it was set. Delivered through the in-lab registry: the seed pushes it from the host's Docker (`mirror: local`) and a pod names it `<mirror>/sfab/serving:<tag>` |
| Keys | `sfab/keys:3` (in `images/keys/`) | `sfab/client:2` plus `sfab-keys` and PyYAML 6.0.3 unpacked from its pinned wheel (no pip, no index); user 65532 | the key tool: keys made inside the cluster and never printed (`ensure`, `mint`, with `--if-none` for a lab's first key a caller, `revoke`, and `copy` from one Secret to another), the API gateway's consumer sidecar, the per-pod key probe (from chapter 7 a POST of a JSON body, JSON lines, and rounds until every pod answers a status); delivered like the serving image |
| Registry | `sfab/registry:3` | `registry:2` by digest, data under `images/registry/data/`, TLS with a leaf of the internet intermediate bound from `state/tls/inet-registry` | `make -C images registry-seed` pulls every pinned image by digest and pushes it as `<mirror>/<upstream host>/<repo>:<tag>`; charts are pushed as OCI. containerd `hosts.toml` uses `override_path = true` and one `config_path` directory. Placed on the operator side so a node's pull crosses the firewall's source NAT |

**Image rules:**

- An image rebuilds when any file in its build context is newer than the image.
- Images carry only `org.opencontainers.image.*` labels.
- Images contain no passwords, no personal keys, no lab or organization names and no label domains. All of those arrive through `init.env` or `node.env`.
- `make -C images check` runs namecheck over every build context.

**Vendor images** (the switch, the PA-VM, TrueNAS and ONTAP) are built with vrnetlab from the reader's own copies, at the vrnetlab commits `spec/versions.yaml` pins, with the switch's and the PA-VM's launcher changes in `platform/`: `images/VENDOR-IMAGES.md`.

**One-time setup needs internet:** `make -C images all` (build, bake, seed, vendor). After that, a lab runs offline.

## 6. Build order

### 6.1 Step 0: framework core (no lab)

- `spec/common.yaml`, profile A's one-tenant state, `versions.yaml`, `known.yaml`.
- `sfab` for `clab`, `klish` (pair, rail, oob roles), `panos` (interfaces, zones, intrazone allows, deny-all-log), `host`, `expect` and `inventory`.
- `validate`, `lint`, golden tests.
- `lib.sh`, `preflight`, `up`, `boot`, `finish`, `down`.
- Audit collect and judge, `namecheck` and `gate`.
- Images: `vm-node` (runtime plus bake) and `client`.

### 6.2 Milestone M1: the framework proven (`dev/m1`, lab `sfab-m1`)

**Selection:** profile `a`, state `one`, slice `[fe, rail, oob, fw, k8s-gpu1, k8s-gpu2]`, features `{k8s: false, serving: false, storage_setup: false}`.

**What it builds:** build A's five switches, the PA-VM (ae1 with its three units, ethernet1/3 to the out-of-band network, zones, intrazone allows, deny-all-log), and two VM guests (bonds to the pair, out-of-band NICs, eight rail NICs each). It needs 23 + 16.5 + 32 = 71.5 GiB of budget (five switches at 4.6 GiB, the PA-VM, two guests at 16 GiB) plus the 16 GiB floor, 87.5 GiB in all.

```
cd dev/m1 && make render && make up && make audit
make up                # second run: every stage reports its marker and acts on nothing
docker rm -f sfab-m1-k8s-gpu1 && make recover    # links lost: boot redeploys, the audit returns green
make down && make up && make down
```

**Exit criteria.** All of these are lines in the audit's `verdict.txt`:

1. **Preflight** passes, with the host tick read and recorded (a SKIP, never a refusal, when it is not 10000), no other sfab lab, and the memory budget.
2. **Every switch:**
   - `KLISH startup config applied` in the launcher log;
   - parity shows 0 missing lines;
   - GRO, rx-gro-hw and LRO off;
   - the forwarding-only reads;
   - `ip vrf mgmt` present;
   - NUM_NICS as rendered (fe-sw1 and fe-sw2 per slice, rail switches 8, oob-sw 3).
3. **Pair:**
   - `show mclag brief` shows the session up with active and standby roles, the keepalive in VRF mgmt on the passthrough addresses, and the peer link up;
   - PortChannel 10 and 21 to 22 are up with their member on each switch.
4. **Firewall:**
   - the commit marker is present;
   - the delivered XML matches the render byte for byte;
   - `enforced.txt` is present;
   - ethernet1/1 and 1/2 are in ae1 with the LACP partner equal to the pair's `mclag-system-mac`;
   - ae1.100, .200 and .300 are up.
   - This retires the chapter 1, 3 and 4 risk: the pair facing the PA-VM's ae1.
5. **Guests:**
   - `bond0` has two slaves under one aggregator ID, with the partner MAC equal to the system MAC;
   - TX off on both sides;
   - management in table 150;
   - 10.20.1.1 answers ping with one traceroute hop;
   - 10.20.9.254 answers over the out-of-band network;
   - 8 relay namespaces, no default route in any of them, `rp_filter` as asserted;
   - same-rail 9000-byte DF pings between k8s-gpu1 and k8s-gpu2 on all 8 rails;
   - cross-rail through the relay.
6. **Rail and out-of-band switches:** VLAN membership as rendered, and MAC tables holding host MACs only.
7. **Result:** `== RESULT: N passed, 0 failed, K known, 0 skipped` (1 skipped, namecheck, without a scrub list), where any K names a registry id (L1 duplicates are expected).
8. **Teardown:** after `down`, no `sfab-m1-*` container and no `clab-sfab-m1/` remain; `state/` disks survive until `wipe`.
9. **Clean:** namecheck is clean (`SKIP` without a scrub list) and `sfab check` is clean.

**M1 also settles these items** and records each with its evidence file:

- containerlab `${VAR}` expansion and `devices:` support on 0.81.0 (the pin then; M2's deploy recorded the same on 0.81.1);
- whether `dell_sonic` honors generated credentials, or keeps the kind's defaults;
- the first rows of `klish-normalize.yaml`;
- whether guest-side TX off is required.

### 6.3 Chapter labs in build order

Orders 1 to 5 are built and recorded: order 5's foundation (the serving and key images, Multus and `serving.env` in the render, and the serving recipe) and the labs of chapters 6 and 7, with the API gateway and the router in the render, both recorded. Of order 6, chapter 1's lab is built and recorded, and chapter 2's is built and not yet recorded. Each later order is planned: what it adds is not built yet, although some files, images and targets it extends exist already (`render/klish.py`, `make accept`, the `serving-layer` README).

| Order | Lab | What it adds to the framework |
|---|---|---|
| 1 | M2 (`dev/m2`, A/one with k8s, no serving) | k8s-cp1 to k8s-cp3; the bastion as a jump host; the DNS and time servers (dns-auth1, dns-auth2, dns-res1, dns-res2, ent-dns, inet-ntp); the lab CA on the lab host; inet-registry and uplink router (`sfab/frr`); operator and enterprise clients; TrueNAS attached; `cluster-bootstrap`, Cilium, kube-vip, cert-manager; two Gateways with a test backend; first `trace.sh` from the enterprise client to the users' VIP |
| 2 | ch03 | full pair port plan (12 and 11 ports); the four-point SYN trace; three-pass drills (firewall bundle leg, server member, peer link, standby reboot recorded as an event); break-3a |
| 3 | ch04 | the single-audience rulebase with the operator DNAT, `no-nat-public` above `internet-snat`, and the stor-mgmt and out-of-band rules; firewall management on the out-of-band network with service routes to the bastion; LAND-drop capture and `show counter global`; break-4a; the uplink router's routes to the inside prefixes via the public address, so the operator's forbidden requests reach the firewall, part of build A from here on |
| 4 | ch05 | rail slice; DF matrix; dark-switch drill (`interface range` shutdown); break-5a |
| 5 | ch06, ch07 | `serving-layer` deployed through `serving.env`; placement table; rail readiness; APISIX and LiteLLM keys; CA proof failure recorded; key captures; timeout drill; breaks 6a and 7a |
| 6 | ch01, ch02 | the assembled A/one hop-by-hop trace with the three refusals; `gen/decisions.yaml`, `matrix.yaml`, `common/matrix/matrix.sh`, `label.sh`; break-1a, break-2a |
| 7 | ch08 to ch11 | A/many steps: third Gateway and audience routes; the ISP router, the public servers and the LAN view on dnsmasq (`sfab/resolver`'s other roles); ISP DNAT and the held-connection load; forbidden tallies per point and per population |
| 8 | B0 (`dev/b0`) | build B minimum: 2 spines, 1 leaf pair, 2 borders, firewall, 2 hosts; EVPN MH, per-VRF BFD and eBGP to the PA-VM green (retires the chapter 12 risk) |
| 9 | ch12, ch13 | full frontend (10 switches: two spines, three leaf pairs, a border pair) plus the `m` variant (MCLAG with EVPN); rail Clos (12 switches, wave boot, first 24-switch boot recorded); ECMP-width expectations |
| 10 | ch14, ch15, ch16 | ONTAP and Trident (B), TrueNAS and break-15a (A), two out-of-band switches; plane-2 variant and second site |
| 11 | ch17, ch18 | carrier routers (MPLS modules in preflight), private Gateway, three routing instances; the build B isolation trace |
| 12 | ch19 to ch21 | `make accept`, `make gameday`, purposes and plane table; serving-layer metrics and route pollers; the template tree printed from `render/klish.py`, the replay path, parity's reverse report and `make reboot` |

### 6.4 Platform rules and where each lives

- **Deploy:**
  - one worker per node, no `timeout`, never `--cleanup`, exact prefixes and a fail-closed identity (3.2, 3.5, 4.1);
  - `restart-policy: "no"` on guests plus an ordered stop (2.4, 3.5).
- **Guest and host networking:**
  - veths lost on reboot, so redeploy (3.3); a planned `common/host/node-restart.sh` will recreate one node's veths at MTU 9500, and a planned `relink.sh` will re-bind tc redirects on its vrnetlab peers;
  - LACP and LLDP through the guest bridges (`group_fwd_mask`); `lacp_rate fast`;
  - guest hold before the link wait (3.3);
  - the `pgrep -f` form, since comm is cut to 15 characters;
  - cloud-init writes files once, so node-sync;
  - Cilium flushes table 200, so management uses 150, out-of-band 100 and rails 300+r;
  - networkd's foreign rules setting; `src_valid_mark=0`; the sshd socket fix;
  - lldpd on a bond member sends from the member's own MAC (`bond-slave-src-mac-type real`), never lldpd's one fixed address, which every bonded node would share (M2).
- **Kubernetes:**
  - kube-vip with `super-admin.conf` during init; the intermediate CA chain, checked against the lab root before anything else runs; the admin kubeconfig stays on the init node; absolute eviction thresholds; Multus's memory limit raised in its rendered manifest;
  - Cilium devices drift;
  - Envoy idle timeout raised in both keys;
  - VIPs tested by TCP, never ICMP (M2: Cilium 1.19.7 answers no echo on a Gateway VIP);
  - helm copied out of its pinned image by a short-lived container of that image, never `ctr images mount`, which fails on containerd 2.2.1 (M2).
- **DNS:** dnsmasq host-records.
- **Firewall:**
  - the PA-VM launcher race (3.3);
  - zone matched post-NAT, address pre-NAT;
  - no `set static-route` on the CLI, so live changes go through the XML API (`fw-api.sh`);
  - the traffic log writes at session end, with rule names cut to 19 characters.
- **Storage:**
  - TrueNAS: the return route first, commit with check-in, the session limits; NVMe/TCP listens only while a subsystem exists, so the node path to it is read with a volume in place (M2);
  - ONTAP: port settling, iSCSI last, 8 GiB, its own sysid and serial for node 2, the ssh backoff.
- **FRR:** the management VRF and a read-only `frr.conf` (5).
- **Captures:** the libpcap MPLS filter; guest decode inside the guest; waiting on PIDs (4.5).
- **Harness:** retry once for ARP; `iperf3 -B` on multihomed hosts.
- **SONiC session rules:** `terminal length 0`, `ssh -tt`, no `?`, no `exit` after `ip vrf`, quoted descriptions, MCLAG domain first and never re-created (`sudo systemctl restart iccpd` on a conflict loop, and on a member whose ICCP listener boot finds outside the session VRF, 3.3), `sudo reboot` wrapped in a timeout, GRO checked after every reboot, LLDP read only after a reboot following any swss restart, the route cache flushed after an MTU event, sFlow only with NUM_NICS 56.
- **Host clock:** tick read and recorded by preflight and the result set, never refused on, since any container holding CAP_SYS_TIME can move it; 10000 is wanted, and a set stamped `host-tick` says so in its RESULTS page.
