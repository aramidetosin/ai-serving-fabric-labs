# Chapter 9 results

What lab `sfab-ch09` proved on its one recorded deployment under build A revision 2, the verdict lines that prove each part, the RESULT line of every set, and how to reproduce them. `audits/INDEX.md` maps the book's exhibits to the same sets and lines.

The deployment ran on 2026-10-31 on the first lab host (chapter 8's ran on the same host), from wiped disks, at host tick 10000 on containerlab 0.82.0, with the images `vrnetlab/dell_sonic:4.6.0` (c0214f532277), `vrnetlab/paloalto_pa-vm:12.1.2` (d1ca9a0f1687), `sfab/vm-node:6-k8s1.35.8` (f3c5c06ad669), `sfab/bastion:4`, `sfab/client:2`, `sfab/frr:10.5.4-3`, `sfab/registry:3`, `sfab/resolver:3` and `sfab/vpngw:3` (each id in every `RUN.json`), and in the cluster `sfab/serving:b11382-2`, `sfab/keys:4` (the in-lab registry's manifest `sha256:c6c2bcfc256d...`, `audits/sfab-ch09_audit_20261031T160618Z/k8s-cp1/26_nodes.json`:959), APISIX 3.9.1, LiteLLM v1.104.0, the identity provider and the test backend from the in-lab registry: `make down` and `make wipe` at 15:29:37, `make up` from 15:32:55 to 16:06:15, `make audit`, `make trace`, `make break-9a`, `make heal-9a`, and `make record` from 16:31:25 to 16:43:48, then `make down`. Every command ran in tmux under `script`, so each journal shows the command exactly as typed (`audits/sfab-ch09_record-run_20261031T152937Z/chain.log`). No container restarted between the end of `make up` and the end of `make record` (the start times in `audits/sfab-ch09_record-run_20261031T152937Z/startedat-*.txt` are identical, every one `restarts=0`). Times are the lab host's clock.

The short names are the index's: N is `audits/sfab-ch09_record-run_20261031T152937Z/`, U `audits/sfab-ch09_audit_20261031T155420Z/` (the audit `make up` ran), A `audits/sfab-ch09_audit_20261031T160618Z/`, T `audits/sfab-ch09_trace_20261031T161820Z/`, B `audits/sfab-ch09_break-9a_20261031T161851Z/`, H `audits/sfab-ch09_heal-9a_20261031T161910Z/`, HA `audits/sfab-ch09_audit_20261031T161927Z/` (the chapter audit H ran), RA `audits/sfab-ch09_audit_20261031T163125Z/` and RT `audits/sfab-ch09_trace_20261031T164316Z/` (the audit and trace `make record` ran).

## What the lab proved

| Claim | Verdict lines |
|---|---|
| One name, three answers, each picked by the resolver that asks: llm.ai.tarnwick.example is 10.20.11.210 (the users' Gateway) through ent-dns for the staff, 10.20.11.200 (the internal Gateway) through dns-res1 for the nodes, and 198.51.100.10 (the firewall's published address) through inet-dns-res for the internet users; the operator's resolver publishes no platform name, so its tools name the internal VIP through the tunnel | A/verdict.txt:974 to :997, :1171 to :1179 |
| The internet side is in place with nothing inside it: the ISP router holds its four connected links and no route into 10.0.0.0/8; the firewall's ethernet1/6 is in zone `isp` at 198.51.100.10/30 | A/verdict.txt:917 to :936, :1084, :1180; A/split-horizon/isp-rtr-ip-route.txt:8 to :16 |
| The public authoritative server holds the users' name alone: inet-dns-auth answers llm.ai.tarnwick.example 198.51.100.10 with the authoritative flag, holds none of the 17 admin, internal, identity and infrastructure names, has no wildcard, and refuses a query with recursion desired | A/verdict.txt:1164 to :1167; A/split-horizon/public-llm-ai-tarnwick-example.txt:6, :7, :16, recursion.txt:6 to :8 |
| The provider's resolver recurses for its customers only: inet-dns-res answers inet-client, and refuses the same query from the ISP router's link address 198.51.100.9, outside 203.0.113.0/26 | A/verdict.txt:1168, :1169; A/split-horizon/isp-answer.txt:16, isp-outside.txt:1, :3 |
| Every typed name's AAAA is answered NODATA (NOERROR, no record, the zone's SOA) by every population's own resolver | A/verdict.txt:1171 to :1178; A/split-horizon/aaaa-*.txt |
| The internet users' SYN to the published address is refused at the firewall by `deny-all-log` from `isp` to `isp` (no translation and no rule at this step), and nothing of it reaches the bundle; the staff's SYN crosses one leg of the bundle under `staff-to-users-gateway`; the nodes' connect is answered on k8s-cp2 itself | A/verdict.txt:984, :985, :1181; T/verdict.txt:1 to :24; RT/verdict.txt:1 to :24 |
| Each Gateway has its own certificate and key for the one name `*.ai.tarnwick.example`, and every node's Envoy holds all three: Cilium copies each Gateway Secret into `cilium-secrets` under a hashed name labelled with the Secret it copies, and the Envoy of k8s-ingress1, k8s-ingress2 and k8s-cp1 each lists the three Gateways' serials (recorded, not judged) | A/verdict.txt:690 to :698, :1056 to :1059, :1146, :1182 to :1185; A/split-horizon/gateway-certs.txt:1 to :15, cilium-secrets.txt:1 to :4, envoy-certs-k8s-cp1.txt:8, :25, :42 |
| break-9a: with ent-dns's forwarding of the platform's zone replaced by `address=` pins for llm and id, A is answered 10.20.11.210 and AAAA is answered REFUSED (EDE 14, Not Ready); python3's getaddrinfo, through musl, fails the whole name with EAI_AGAIN after the 10 s resolver timeout, while curl, through its own resolver library, connects on the A answer; the heal puts the rendered configuration back, AAAA is NODATA again, both stubs resolve, and the chapter audit is green | B/verdict.txt:2 to :10; B/probes/staff-break/dig-a.txt:5, :14, dig-aaaa.txt:5, :10, getaddrinfo.txt:1, :2, curl.txt:1, :2; H/verdict.txt:2 to :12 |
| The trace and the audit after the break and the heal, on the same deployment, as before them | RA/verdict.txt:1163 to :1189; RT/verdict.txt:1 to :24 |
| No key value is in any file of the recorded sets: the keys are made inside the cluster and named by fingerprint only, and the certificate reads list serials, names and public-key fingerprints, never a private key | N/rec-make-up.txt:456 to :463; A/split-horizon/gateway-certs.txt:1 to :15, envoy-certs-k8s-cp1.txt:1 to :55 |

## The RESULT lines

| Set | RESULT |
|---|---|
| U, `sfab-ch09_audit_20261031T155420Z` (the audit `make up` ran) | `== RESULT: 1090 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| A, `sfab-ch09_audit_20261031T160618Z` (`make audit`) | `== RESULT: 1090 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| T, `sfab-ch09_trace_20261031T161820Z` (`make trace`) | `== RESULT: 19 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| B, `sfab-ch09_break-9a_20261031T161851Z` (`make break-9a`) | `== RESULT: 6 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| H, `sfab-ch09_heal-9a_20261031T161910Z` (`make heal-9a`) | `== RESULT: 7 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| HA, `sfab-ch09_audit_20261031T161927Z` (the chapter audit heal-9a ran) | `== RESULT: 1090 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RA, `sfab-ch09_audit_20261031T163125Z` (the audit `make record` ran) | `== RESULT: 1090 passed, 0 failed, 0 known platform limitation(s), 3 skipped` |
| RT, `sfab-ch09_trace_20261031T164316Z` (the trace `make record` ran) | `== RESULT: 19 passed, 0 failed, 0 known platform limitation(s), 0 skipped` |
| the gate `make record` ran on RA and RT and the repository | `== RESULT: 12 passed, 0 failed, 0 known platform limitation(s), 5 skipped` (N/rec-make-record.txt:1275) |
| `common/audit/gate.sh` on U, A, T, B, H and HA | `== RESULT: 36 passed, 0 failed, 0 known platform limitation(s), 13 skipped` (N/gate-sets.txt:57) |

The audits' three SKIPs are the LAND counter, which this lab's drills plan does not name, the web population's cell at the internet Gateway, since this lab's slice has no client of that population, and namecheck, which reads `skipped, no scrub list` on a host without the author's list, as on a reader's. The gates' SKIPs are namecheck and the literal scan, which needs the author's literals file.

## The result sets

All under `audits/`, each with its `RUN.json` (lab, labs commit with its dirty flag, spec and render sha256, image ids, containerlab version, host tick 10000, UTC start and end), `verdict.txt`, `RESULT.txt` and `commands.txt`. Every `RUN.json` carries one spec sha256 (`8f314deb6bce...`) and one render sha256 (`5aa0316e4bae...`), so neither changed during the deployment, and one labs commit from the checkout's stamp (FRAMEWORK.md 4.4) with `dirty: false`: a commit of the development history, which is not in this repository; the commit that adds these sets holds the same lab code.

| Directory | What it holds |
|---|---|
| `sfab-ch09_record-run_20261031T152937Z/` | plain files: `chain.log`, the host before and after, the plain journal of every recorded command and the typescripts it was made from, the serving recipe's and the inference step's output from `make up`'s finish stage, container start times, each VM guest's time sync, containerlab's host writes, disk and container-layer readings, the gate on the sets `make record` does not gate, the lab's memory watchdog's log and a second watcher's readings |
| `sfab-ch09_audit_20261031T155420Z/`, `..._160618Z/`, `..._161927Z/`, `..._163125Z/` | the four full audits: every node's reads, both forms, chapter 6's `placement/`, chapter 7's `keys/`, `identity/`, `gateway-layer/` and `cluster-security/`, chapter 8's `audiences/` (each Gateway certificate's issuer, serial and key fingerprint among them), and chapter 9's `split-horizon/` (the public server's answer for each name it must hold and each it must not, the wildcard probe and the recursion probe, the provider's resolver from its customer and from the ISP router's link, every population's A and AAAA through its own resolver, the uplink side's server, the ISP router's routing table, the internet client's connect and the firewall's traffic log, each Gateway's certificate with its serial, Cilium's copies with the Secret each copies, and each recorded node's Envoy certificate list) |
| `sfab-ch09_trace_20261031T161820Z/`, `..._164316Z/` | the two split-horizon traces: `TRACE.md`, `warmup/` (one connect for each population whose connect is answered, before the captures), `lookups/` and `connects/` per population, `fw/traffic-log-443.txt`, and `captures/` (each population's resolver on port 53, k8s-cp2's own ports, the ISP router's link, the firewall's enterprise port and both legs of its bundle; pcaps and their decodes) |
| `sfab-ch09_break-9a_20261031T161851Z/`, `sfab-ch09_heal-9a_20261031T161910Z/` | the break and the heal: ent-dns's configuration as the break installed it and the reload's output, the restore's output, the staff client's lookups by dig (A and AAAA), python3's getaddrinfo and curl, each with its exit status and times, and its resolv.conf; the heal's Warning events saved and cleared before its chapter audit |

Sets made on the five attempts before the recorded deployment, and the trial sets on two of them, are not published; `audits/INDEX.md` lists each with its RESULT line and why.

## What the deploys found

Each was met on an attempt before the recorded deployment and fixed before it (`audits/INDEX.md`, "Sets not published").

1. **`make up` waited on a connect this step refuses.** finish's settle connected every population's client to its answer address on 443 every round, the internet users' among them, and in this chapter the firewall refuses that connect by design (no translation or rule until chapter 10), so no round could be clean. settle now takes each population's connect at this step from `gen/tenancy.json`'s `audiences.reach`, as the audit's gateway targets do, and skips one that is not answered.
2. **The populations group wanted the internet users answered.** It judged every population's request through its own Gateway, 200 on the users' name and 404 on the admin name, so the second attempt's audit failed both of inet-client's requests on a timeout. It now reads the same `audiences.reach` and wants a population the firewall refuses at this step unanswered, naming the device, the rule and the address (A/verdict.txt:984, :985); its log line is the split-horizon group's check.
3. **The certificate lines said the opposite of their files.** Cilium 1.19.7 names its copies of the Gateway Secrets `cilium-sync-secret-<hash>` and labels each with the Secret it copies, and Envoy's certificate list gives serials, so the group's lines read "0 of 3" copies and "0 of the 3 Gateway certificates named" on Envoys that held all three. A line its own file contradicts is not published. The group now lists the copies with their labels, reads each Gateway's certificate with its serial beside the Envoy lists, and names each Envoy's certificates by serial (A/verdict.txt:1182 to :1185); the third attempt was stopped during boot and run again.
4. **dnsmasq's restart found its socket still held.** dnsmasq reads its configuration only at start, so a reload stops it and starts it again, and on the fourth attempt the new process found 10.24.10.53:53 still in use and the reload put the previous configuration back, so break-9a stopped. The same restart worked on the attempt before. The break library now tries such a reload again after 3 s, twice at most, and writes the retry into its record; the recorded heal met it once and its second reload succeeded (H/record/restore-ent-dns.txt:5, :6, :8).
5. **The staff's SYN was seen on both legs of the bundle.** The pair held the lease holder's MAC in VLAN 100 but not in VLAN 110, so the switch flooded the frame, and the virtual bridge sends a flood that crosses the peer link back out the MCLAG bonds (spec/known.yaml L1); the holder answered both copies. The trace now makes one warm-up connect for each population whose connect is answered before its captures start, as chapter 11's ladder trace does, and the SYN crossed one leg (T/verdict.txt:8).

Facts the recordings show and a reader should know:

- **The leases sit on two ingress nodes here.** In every audit of this deployment gw-inet's lease was held by k8s-ingress2 and gw-internal's and gw-users' by k8s-ingress1 (A/verdict.txt:1147 to :1149; A/audiences/leases.txt:7 to :9); chapter 8's recording had all three on one node. No step of this lab places them.
- **A control node's Envoy holds the internet Gateway's key.** k8s-cp1's Envoy lists gw-inet's serial beside the other two, as both ingress nodes' do (A/split-horizon/envoy-certs-k8s-cp1.txt:8, :25, :42).
- **curl and getaddrinfo disagree on the same answers.** With AAAA refused, curl on the staff client connected on the A answer within the same second, while python3's getaddrinfo failed the whole name after 10 s with `[Errno -3] Try again` (B/probes/staff-break/curl.txt:1, getaddrinfo.txt:1, :2). Which tool a user runs decides whether the break is seen at all.
- **The refused AAAA carries an extended error.** dnsmasq 2.90 answered the pinned name's AAAA `REFUSED` with `EDE: 14 (Not Ready)` once its upstream for the zone was gone (B/probes/staff-break/dig-aaaa.txt:5, :10).
- **A refused connect leaves four log lines.** The firewall logs the internet client's SYN and each of its three retransmits under `deny-all-log` (A/split-horizon/traffic-log.txt:6 to :21).

## How to reproduce

On a Linux host with KVM, Docker, containerlab 0.82.0, the host tick at 10000, the images `vrnetlab/dell_sonic:4.6.0`, `vrnetlab/paloalto_pa-vm:12.1.2` and the `sfab/*` images with the in-lab registry seeded (`sfab/keys:4` among them, `make -C images keys`), the two models in `images/models`, 179.75 GiB of MemAvailable (the inventory's 163.75 GiB budget plus the 16 GiB floor) and no other `sfab-` lab running:

```
cd ch09
make up
make audit
make trace
make break-9a
make heal-9a
make record
make down
```

`make up` took 33 min 20 s here from wiped disks: boot 775 s (the switches 302 s, the firewall 327 s, the DNS zones 28 s), finish 497 s (the serving recipe 83 s, the inference step 30 s, settle 170 s), the audit 715 s (N/rec-make-up.txt:341, :368, :415, :417, :454, :467, :471, :865, :2087). The running lab took about 78 GiB of the host's memory: MemAvailable read 335.8 GiB before `make up` and 257.6 GiB after `make record` (N/host-before-up.txt:4, N/host-after-record.txt:4). `state/` held 23639940 kB before the down (N/state-du.txt:2).

## What the recordings do not show

- **A GPU.** The models run on CPU, split over RPC workers; nothing here measures a GPU or publishes a throughput figure.
- **A key in clear.** Every key is made in the cluster and named by fingerprint; the certificate reads hold serials and public-key fingerprints, never a private key.
- **An internet user reaching a Gateway.** No population reaches the internet Gateway through the firewall until chapter 10; here the internet users' connects end at the firewall's `deny-all-log`.
- **A capture of an AAAA query or of a resolver's forward.** The AAAA answers are dig's printed output, and in both recorded traces each resolver answered from its cache, so the captures hold the client's query and the answer only.
- **A sub-second stub timing.** The break's probes record whole seconds, so getaddrinfo's failure reads 10 s and curl's success 0 s.
- **A public CA or a second public server.** inet-client trusts the lab root, and the platform has one public authoritative server, on a customer port of the ISP router; both are lab simplifications, labelled in `README.md`.
- **A `git clone` line.** No recording ran `git clone`: the clone line is the repository README's (`../README.md`, "Clone, build, deploy"); Example 9-1 opens at `cd ch09`.
