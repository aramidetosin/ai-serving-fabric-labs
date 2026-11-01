# shellcheck shell=bash
# common/audit/lib-audit.sh: the audit helpers a build A lab with the cluster shares (FRAMEWORK.md
# 4.4), promoted from milestone M2's audit.sh (dev/m2/audit.sh keeps its own copy as recorded).
# Sourced after lib.sh's sfab_init audit:
#
#   judge_present GROUP NODE...   judge GROUP on the named nodes this set collected
#   of_kind KIND                  the lab's nodes of one kind
#   k8s_nodes                     the guests with a Kubernetes role
#   bonded_nodes                  the hosts with a bond toward the pair, the bastion included
#   switch_containers             the container hosts cabled to a switch (the quick audit reads
#                                 their container links: the switches learn those MACs)
#   storage_volumes               a volume on each storage class, written and read back (M2 exit
#                                 criterion 9), in the namespace sfab-audit, deleted again
#   audit_build_a_cluster         every judge of a build A lab with the cluster after the pair
#                                 (M2's criteria 3 to 9 and 16), in M2's order
#   audit_rail_backend SW...      chapter 5: each GPU node's namespace links read into the set's
#                                 rail-backend/ (not in a quick audit), then judge.py rail-backend
#                                 on the rail switches and every GPU node the set collected
#   audit_placement               chapter 6: the serving pods, their Services and rail attachments,
#                                 each pod's routes on its node, and a request a model through each
#                                 model route a client of the lab reaches, read into placement/ (a
#                                 quick audit too), then judge.py placement against the table
#                                 (bootstrap/k8s/serving.env, or the one audit.sh --table names)
#   audit_gateway_layer           chapter 7: each model route's refusals from its client and the
#                                 per-pod key probe, read into keys/ (a quick audit too), then
#                                 judge.py keys; in a full audit also the Gateways, routes,
#                                 namespaces, leases, the Gateways' CiliumEnvoyConfigs and the
#                                 inference ConfigMaps, the VIPs from a GPU node, each VIP's chain
#                                 from the bastion and the CA's proof (on the lab host), read into gateway-layer/,
#                                 then judge.py gateway-layer

# judge_present GROUP NODE...: judge GROUP on the named nodes this set collected; nothing when
# none of them was collected (a quick audit collects only the switches and the firewall).
judge_present() {
  local group="$1" n have=()
  shift
  for n in "$@"; do [ -d "$RS/$n" ] && have+=("$n"); done
  [ ${#have[@]} -eq 0 ] || _judge "$group" "${have[@]}"
}
of_kind() { local n; for n in "${NODES[@]}"; do [ "${NODE_KIND[$n]}" != "$1" ] || printf '%s\n' "$n"; done; }
k8s_nodes() { local g; for g in "${GUESTS[@]+"${GUESTS[@]}"}"; do [ -z "${NODE_K8S[$g]:-}" ] || printf '%s\n' "$g"; done; }

# storage_volumes: for each storage class the render names, a PersistentVolumeClaim; a pod on a GPU
# node writes 1 MiB to it with fsync and prints its sha256; then a second pod mounts the same claim
# and prints the sha256 of what it reads (the first pod's unmount flushed the node's cache of it).
# Applied and read with the harness's kubectl (the init node); everything it made is deleted again.
volume_pod() {  # volume_pod NS NAME CLAIM NODE IMAGE SCRIPT
  KSH "kubectl -n $1 apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata: {name: $2}
spec:
  restartPolicy: Never
  nodeSelector: {kubernetes.io/hostname: $4}
  tolerations: [{operator: Exists}]
  containers:
    - name: probe
      image: $5
      command: [sh, -c, '$6']
      volumeMounts: [{name: v, mountPath: /data}]
  volumes: [{name: v, persistentVolumeClaim: {claimName: $3}}]
EOF"
}

pod_done() {  # pod_done NS NAME: wait for the pod to finish; prints its phase
  local _ phase=""
  for _ in $(seq 1 "${SFAB_VOLUME_POLLS:-50}"); do
    phase="$(EVID_OFF=1 K -n "$1" get pod "$2" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$phase" in Succeeded|Failed) break ;; esac
    sleep "${SFAB_VOLUME_POLL_S:-6}"
  done
  printf '%s\n' "${phase:-unknown}"
}

storage_volumes() {
  local s classes img node ns=sfab-audit dir="$RS/storage-volumes" c sc want got pw pr bound
  local transports tsc taddr tport g reached total shut
  [ "$STAGE_STORAGE_SETUP" = 1 ] && [ ${#STORAGE[@]} -gt 0 ] || return 0
  sec "storage: a volume on each class"
  if [ "${SFAB_AUDIT_VOLUMES:-1}" = 0 ]; then skip "a volume on each class" "SFAB_AUDIT_VOLUMES=0"; return 0; fi
  mkdir -p "$dir"
  s="${STORAGE[0]}"
  classes="$(py - "$RENDERDIR/bootstrap/$s/setup.json" <<'PY'
import json, sys
try:
    csi = json.load(open(sys.argv[1])).get("csi") or {}
except (OSError, ValueError):
    csi = {}
for c in csi.get("classes") or []:
    print(c["storage_class"])
PY
)"
  # each class's NVMe/TCP transports, "<class> <address> <port>" per line (none for NFS)
  transports="$(py - "$RENDERDIR/bootstrap/$s/setup.json" <<'PY'
import json, re, sys
try:
    csi = json.load(open(sys.argv[1])).get("csi") or {}
except (OSError, ValueError):
    csi = {}
for c in csi.get("classes") or []:
    for t in ((c.get("driver_config") or {}).get("nvmeof") or {}).get("transports") or []:
        m = re.match(r"^tcp://([^:/]+):(\d+)$", t)
        if m:
            print(c["storage_class"], m.group(1), m.group(2))
PY
)"
  [ -n "$classes" ] || { bad "a volume on each class" "bootstrap/$s/setup.json names no CSI class"; return 0; }
  # the image: the CSI driver's own, pinned by digest (spec/versions.yaml), so the in-lab registry
  # holds it and the node has it already; its Debian base has sh, dd and sha256sum
  img="$(py - "$RENDERDIR/gen/RENDER.json" <<'PY'
import json, sys
try:
    k = (json.load(open(sys.argv[1])).get("versions") or {}).get("kubernetes") or {}
except (OSError, ValueError):
    k = {}
pin = ((k.get("democratic_csi") or {}).get("images") or {}).get("driver") or {}
print(pin["ref"] + "@" + pin["digest"] if pin.get("ref") and pin.get("digest") else "")
PY
)"
  [ -n "$img" ] || { bad "a volume on each class" "spec/versions.yaml pins no CSI driver image (kubernetes.democratic_csi.images.driver)"; return 0; }
  node="${GPU_GUESTS[0]:-}"
  [ -n "$node" ] || node="$(k8s_nodes | head -n 1)"
  EVID_OFF=1 K delete namespace "$ns" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  K create namespace "$ns" >"$dir/namespace.txt" 2>&1 || true
  for sc in $classes; do
    c="vol-$sc"
    KSH "kubectl -n $ns apply -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: $c}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: $sc
  resources: {requests: {storage: 1Gi}}
EOF" >"$dir/$sc-claim.txt" 2>&1 || true
    # shellcheck disable=SC2016 # the pod's shell expands these, not this one
    volume_pod "$ns" "$c-write" "$c" "$node" "$img" \
      'dd if=/dev/urandom of=/data/blob bs=1048576 count=1 conv=fsync 2>/dev/null && sync && echo written $(sha256sum /data/blob)' \
      >"$dir/$sc-write-apply.txt" 2>&1 || true
    pw="$(pod_done "$ns" "$c-write")"
    K -n "$ns" logs "$c-write" >"$dir/$sc-write.txt" 2>&1 || true
    EVID_OFF=1 K -n "$ns" delete pod "$c-write" --wait=true >/dev/null 2>&1 || true
    # shellcheck disable=SC2016
    volume_pod "$ns" "$c-read" "$c" "$node" "$img" 'echo read $(sha256sum /data/blob)' >"$dir/$sc-read-apply.txt" 2>&1 || true
    pr="$(pod_done "$ns" "$c-read")"
    K -n "$ns" logs "$c-read" >"$dir/$sc-read.txt" 2>&1 || true
    K -n "$ns" get pvc "$c" -o wide >"$dir/$sc-pvc.txt" 2>&1 || true
    # TrueNAS listens on NVMe/TCP only while a subsystem exists, so the node path to it is read now,
    # with this claim's volume in place: from every node with a unit in the storage data VLAN (the
    # data path), and from no other node (the VLAN is Layer 2 only, behind no gateway)
    while read -r tsc taddr tport; do
      [ "$tsc" = "$sc" ] || continue
      reached=0 total=0 shut=() leaked=() others=0
      for g in $(k8s_nodes); do
        if py - "$INV" "$g" "$taddr" <<'PY'
import ipaddress, json, sys
n = (json.load(open(sys.argv[1])).get("nodes") or {}).get(sys.argv[2]) or {}
a = ipaddress.ip_address(sys.argv[3])
units = ((n.get("bond") or {}).get("vlan_ifs")) or []
sys.exit(0 if any(a in ipaddress.ip_interface(u["address"]).network for u in units) else 1)
PY
        then
          total=$((total + 1))
          if H "$g" "timeout 5 bash -c '</dev/tcp/$taddr/$tport'" >>"$dir/$sc-nvme-tcp.txt" 2>&1; then
            reached=$((reached + 1))
          else
            shut+=("$g")
          fi
        else
          others=$((others + 1))
          if H "$g" "timeout 5 bash -c '</dev/tcp/$taddr/$tport'" >>"$dir/$sc-nvme-tcp.txt" 2>&1; then leaked+=("$g"); fi
        fi
      done
      if [ "$total" -gt 0 ] && [ "$reached" -eq "$total" ]; then
        ok "$sc: with the claim bound, TrueNAS's data address $taddr answers on NVMe/TCP $tport from every node in its VLAN ($reached of $total)"
      else
        bad "$sc: with the claim bound, TrueNAS's data address $taddr answers on NVMe/TCP $tport from every node in its VLAN" \
          "refused from ${shut[*]:-every node} ($reached of $total)"
      fi
      if [ "${#leaked[@]}" -eq 0 ]; then
        ok "$sc: no node outside the storage data VLAN reaches $taddr:$tport ($others tried)"
      else
        bad "$sc: no node outside the storage data VLAN reaches $taddr:$tport" "reached from ${leaked[*]}"
      fi
    done <<<"$transports"
    want="$(sed -n 's/^written \([0-9a-f]\{64\}\).*/\1/p' "$dir/$sc-write.txt" | head -n 1)"
    got="$(sed -n 's/^read \([0-9a-f]\{64\}\).*/\1/p' "$dir/$sc-read.txt" | head -n 1)"
    bound="$(awk 'NR == 2 {print $2}' "$dir/$sc-pvc.txt")"
    if [ "$bound" = Bound ] && [ "$pw" = Succeeded ] && [ "$pr" = Succeeded ] && [ -n "$want" ] && [ "$want" = "$got" ]; then
      ok "$sc: the claim binds; a pod on $node writes 1 MiB and a second pod reads back the same sha256"
    else
      bad "$sc: the claim binds; a pod on $node writes 1 MiB and a second pod reads back the same sha256" \
        "claim ${bound:-absent}, writer $pw, reader $pr, written ${want:-none}, read ${got:-none}"
    fi
  done
  if K delete namespace "$ns" --wait=true --timeout=300s >"$dir/cleanup.txt" 2>&1; then
    ok "the claims, pods and namespace $ns deleted again"
  else
    bad "the claims, pods and namespace $ns deleted again" "$(tail -n 1 "$dir/cleanup.txt")"
  fi
}

# switch_containers: the container hosts cabled to a switch (the bastion). The quick audit reads
# their container links too, because the switches learn those MACs and the MAC-table check sets
# every collected container veth MAC aside.
switch_containers() {
  py - "$INV" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
nodes = d["nodes"]
for n in d["order"]:
    v = nodes[n]
    if v.get("section") == "hosts" and v.get("kind") != "vm-node" and any(
            str(x.get("peer") or "").split(":")[0] in (d.get("stages") or {}).get("switches", []) for x in (v.get("nics") or {}).values()):
        print(n)
PY
}

bonded_nodes() {
  py - "$INV" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for n in d["order"]:
    v = d["nodes"][n]
    if v.get("bond") and v.get("kind") in ("vm-node", "bastion", "resolver"):
        print(n)
PY
}

# services_nodes: the platform's DNS and time servers (judge.py services): the authoritative pair,
# the resolvers, the corporate resolver and the time reference.
services_nodes() {
  py - "$INV" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
for n in d["order"]:
    v = d["nodes"][n]
    if v.get("kind") == "resolver" and v.get("role") in ("dns-auth", "dns-res", "dns-corporate", "inet-ntp"):
        print(n)
PY
}

audit_build_a_cluster() {
  local _k8s _rtr _reg _cli
  mapfile -t _k8s < <(k8s_nodes)
  judge_present cluster-nodes "${_k8s[@]}"
  judge_present bastion ${BASTION:+"$BASTION"}
  local _svc
  mapfile -t _svc < <(services_nodes)
  judge_present services "${_svc[@]}"
  mapfile -t _rtr < <(of_kind frr)
  mapfile -t _reg < <(of_kind registry)
  judge_present routers "${_rtr[@]}"
  judge_present registry "${_reg[@]}"
  mapfile -t _cli < <(of_kind client)
  judge_present clients "${_cli[@]}"
  judge_present storage "${STORAGE[@]+"${STORAGE[@]}"}"
  [ "$STAGE_CLUSTER" != 1 ] || _judge populations
  [ "$STAGE_CLUSTER" != 1 ] || _judge cluster
  [ "$STAGE_CLUSTER" != 1 ] || storage_volumes
  [ "$STAGE_CLUSTER" != 1 ] || audit_cluster_security
}

# ---------------------------------------------------------------------------------------------
# chapter 4: the firewall edge (judge.py fw-edge)
#
# audit_fw_edge [NODE]: the active reads the fw-edge group judges, saved under fw-edge/ with
# plan.json naming what was used, then the group itself. NODE is the node whose requests to the
# public address are read around show counter global (default: the source of the lab's drills
# public probe, else its first Kubernetes node). In order, every read on the lab host's clock:
#   ntp         show ntp, read until the firewall's own NTP is synched (up to 20 minutes after boot)
#   counters    show counter global filter value all (CLI and XML) before and after NODE pings the
#               public address (no-nat-public in place: answered, and the LAND counter unmoved)
#   egress      NODE connects to an internet host no rule admits the inside to (the client of a
#               population with no audience, the web client, on 443): it must time out
#               (egress-connect.txt), and the traffic log, read until it appears
#               (egress-tlog-<port>.txt), must hold its deny-all-log line from NODE's zone to the uplink
#   admin       from the bastion (the jump host, the one address the administrative profile
#               permits): HTTPS and SSH on the firewall's administrative interface (SSH read as its
#               banner over telnet://); from NODE, an inside host the profile does not permit: HTTPS
#               on the same address (not answered); from the operator's client: SSH on the public
#               address (not answered) and HTTPS there (not answered where nothing is published, the
#               internal Gateway's server header where a destination NAT publishes it)
#   refusals    the operator's client connects to each of its forbidden cells in chapter 2's matrix
#               that the lab holds (the users' VIP, the API server, a node's SSH, its BMC, the
#               storage management address; the storage data address has no gateway); each must
#               fail, the client's view saved (operator-cells-<cell>.txt); a cell inside the tunnel's
#               proxy IDs must leave its deny-all-log line in the traffic log, read per port until
#               each appears (operator-cells-tlog-<port>.txt), and one outside them, sent in the clear
#               to the uplink, a rise of zone protection's strict IP check drop counter around the
#               connects (operator-drops.txt) and no log line
#   services    ping source <service route address> host <the bastion's name>, so the firewall
#               resolves a name through its DNS service route (the lab's resolvers), then the
#               traffic log for its own DNS and NTP (port 53 in the last 15 minutes, 123 in the last
#               hour: NTP polls slowly)
# Each probe is retried once where the first packets of a new flow are lost to ARP (pchk's rule).
audit_fw_edge() {
  local node="${1:-}" d="$RS/fw-edge" i a p cell
  [ -n "${FW_NODE:-}" ] || return 0
  mkdir -p "$d"
  py - "$INV" "$RENDERDIR/gen/drills.json" "$node" >"$d/plan.env" <<'PY' || { bad "fw-edge: plan" "the inventory could not be read"; return 0; }
import ipaddress, json, shlex, sys
inv = json.load(open(sys.argv[1]))
try:
    dr = json.load(open(sys.argv[2]))
except (OSError, ValueError):
    dr = {}
nodes, st = inv["nodes"], inv.get("stages") or {}
fw = nodes[st["fw"]]
bare = lambda a: str(a).split("/")[0] if a else ""
pub = fw.get("public") or ""
probe = (dr.get("probes") or {}).get("public") or {}
node = sys.argv[3] or probe.get("src") or next((g for g in st.get("guests") or [] if nodes[g].get("k8s")), "")
counter = next((x.get("counter") for x in dr.get("list") or [] if x.get("kind") == "fw_nat_removed"), None)
adm = fw.get("admin") or {}
admin_addr = bare((fw.get("interfaces") or {}).get(adm.get("interface") or "", {}).get("address"))
b = st.get("bastion")
bn = nodes.get(b) or {}
# the operator: the population that arrives through the firewall's tunnel (its zone), else from the
# uplink (a build that publishes the internal Gateway); an internet host with no audience is not it
vpn_zones = {x.get("zone") for x in fw.get("vpns") or []}
pops = inv.get("populations") or {}
op = next((c for p in pops.values() if vpn_zones & set(p.get("zones") or []) for c in p.get("clients") or [] if c in nodes), "") or \
    next((c for p in pops.values() if p.get("gateway") and "uplink" in (p.get("zones") or []) for c in p.get("clients") or [] if c in nodes), "")
# where nothing is published (no destination NAT on the public address), the public address answers
# HTTPS to nobody; otherwise the internal Gateway answers there
published = bool(fw.get("published"))
# the name the operator asks the public address for: the internal Gateway's first hostname, whose
# listener (the wildcard name) answers it; an address alone names no listener in TLS
igw = next((g for g in (inv.get("gateways") or {}).values() if g.get("audience") == "internal"), {})
op_fqdn = (igw.get("hostnames") or [""])[0]
# The operator's forbidden cells of chapter 2's matrix (Table 2-2), in its order, each tried at
# its own address and port: the users' Gateway, the API server, a node's SSH, that node's BMC (its
# out-of-band address), the storage data address on NFS and the storage management address.
cells = []
gws = inv.get("gateways") or {}
users = next((g for g in gws.values() if g.get("audience") == "enterprise"), None)
if users:
    cells.append({"id": "users-vip", "addr": users["vip"], "port": 443})
k8s = inv.get("k8s") or {}
if k8s.get("api_vip") and st.get("cluster"):
    cells.append({"id": "api-server", "addr": bare(k8s["api_vip"]), "port": 6443})
wk = next((w for w in k8s.get("workers") or [] if w in nodes and nodes[w].get("address")), None)
if wk:
    cells.append({"id": "node-ssh", "addr": bare(nodes[wk]["address"]), "port": 22})
    if (nodes[wk].get("oob") or {}).get("address"):
        cells.append({"id": "bmc", "addr": bare(nodes[wk]["oob"]["address"]), "port": 443})
sto = next((s for s in st.get("storage") or [] if s in nodes), None)
# the storage data address sits on a VLAN with no gateway: no router beyond it holds a route, so it
# leaves no log line (chapter 2's matrix holds it as silence); the cell is left out here
def gatewayed(a):
    ip = ipaddress.ip_address(bare(a))
    return any(i.get("address") and ip in ipaddress.ip_interface(i["address"]).network for i in (fw.get("interfaces") or {}).values())
if sto and (nodes[sto].get("data") or {}).get("address") and gatewayed(nodes[sto]["data"]["address"]):
    cells.append({"id": "stor-data", "addr": bare(nodes[sto]["data"]["address"]), "port": 2049})
if sto and (nodes[sto].get("mgmt_if") or {}).get("address"):
    cells.append({"id": "stor-mgmt", "addr": bare(nodes[sto]["mgmt_if"]["address"]), "port": 443})
sr = (fw.get("system") or {}).get("service_routes") or {}
svc_src = bare((sr.get("dns") or sr.get("ntp") or {}).get("address"))
# an egress the allowlist does not name: the node's connect to an internet host of a population with
# no audience (the web client), which no rule admits the inside to (only the registry and the time
# source are allowlisted outward), so deny-all-log refuses it from the node's zone to the uplink's
def zone_of(a):
    if not a:
        return ""
    ip = ipaddress.ip_address(bare(a))
    return next((i.get("zone") or "" for i in (fw.get("interfaces") or {}).values()
                 if i.get("address") and i.get("zone") and ip in ipaddress.ip_interface(i["address"]).network), "")
web = next((c for p in pops.values() if (p.get("audience") in (None, "none")) and not p.get("gateway")
            for c in p.get("clients") or [] if c in nodes and nodes[c].get("address")), "")
egress = {}
if web and node and pub and (nodes.get(node) or {}).get("address"):
    egress = {"client": web, "addr": bare(nodes[web]["address"]), "port": 443, "rule": "deny-all-log",
              "from_zone": zone_of(nodes[node]["address"]), "to_zone": zone_of(pub)}
# a cell the tunnel's proxy IDs protect goes through the tunnel and meets the firewall's policy in
# zone operator-vpn; any other leaves the operator's site in the clear and arrives on the uplink from
# an address the firewall routes through the tunnel, which zone protection's strict IP check drops
# before any rule (counter flow_dos_pf_strictip, no traffic log line)
def through_tunnel(a):
    ip = ipaddress.ip_address(bare(a))
    return any(ip in ipaddress.ip_network(local) for v in fw.get("vpns") or [] for _, local, _ in v.get("proxy_ids") or [])
for c in cells:
    c["via"] = "tunnel" if (fw.get("vpns") and through_tunnel(c["addr"])) else ("uplink-spoof" if fw.get("vpns") else "uplink")
plan = {"node": node, "node_addr": bare((nodes.get(node) or {}).get("address")), "node_kind": (nodes.get(node) or {}).get("kind"),
        "public": pub, "counter": counter, "admin_addr": admin_addr if adm else "", "bastion": b or "",
        "bastion_addr": bare(bn.get("address")), "bastion_oob": bare((bn.get("oob") or {}).get("address")),
        "bastion_fqdn": f"{b}.{inv['org'].get('zone') or inv['org']['domain']}" if b else "", "operator": op,
        "operator_addr": bare((nodes.get(op) or {}).get("address")), "operator_fqdn": op_fqdn, "cells": cells if op and pub else [],
        "svc_src": svc_src, "dns_rule": (sr.get("dns") or {}).get("rule"), "ntp_rule": (sr.get("ntp") or {}).get("rule"),
        "published": published, "egress": egress}
print("FWE_PLAN=" + shlex.quote(json.dumps(plan, sort_keys=True)))
for k in ("node", "node_addr", "node_kind", "public", "counter", "admin_addr", "bastion", "bastion_addr", "bastion_oob",
          "bastion_fqdn", "operator", "operator_addr", "operator_fqdn", "svc_src"):
    print(f"FWE_{k.upper()}={shlex.quote(str(plan[k] or ''))}")
print("FWE_CELLS=(" + " ".join(shlex.quote(f"{c['id']}:{c['addr']}:{c['port']}") for c in plan["cells"]) + ")")
print(f"FWE_EGRESS_ADDR={shlex.quote(egress.get('addr') or '')}")
print(f"FWE_EGRESS_PORT={shlex.quote(str(egress.get('port') or ''))}")
PY
  # shellcheck disable=SC1091
  . "$d/plan.env"
  printf '%s\n' "$FWE_PLAN" >"$d/plan.json"
  rm -f "$d/plan.env"

  # the firewall's own NTP: show ntp read until it names the server synched, every 30 s for up to
  # SFAB_FWE_NTP_WAIT_S (1200 s: PAN-OS's ntpd took 15 min from its restart at boot to its first
  # sync on the first deploy), each read saved with the lab host's clock
  if [ -n "$FWE_SVC_SRC" ]; then
    local t0=$SECONDS n=0
    : >"$d/ntp-reads.txt"
    while :; do
      n=$((n + 1))
      FW "show ntp" | judge_body_panos "show ntp" >"$d/ntp.txt" 2>/dev/null || true
      { printf '### %s read %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$n"; cat "$d/ntp.txt"; } >>"$d/ntp-reads.txt"
      grep -q 'NTP synched to' "$d/ntp.txt" && break
      [ $((SECONDS - t0)) -lt "${SFAB_FWE_NTP_WAIT_S:-1200}" ] || break
      sleep 30
    done
  fi

  # the LAND counter around a node's requests to the public address
  if [ -n "$FWE_COUNTER" ] && [ -n "$FWE_NODE" ] && [ -n "$FWE_PUBLIC" ]; then
    FW "show counter global filter value all" | judge_body_panos "show counter global filter value all" >"$d/counters-before.txt" 2>/dev/null || true
    FWX "<show><counter><global><filter><value>all</value></filter></global></counter></show>" >"$d/counters-before.xml" 2>/dev/null || true
    fw_edge_ping "$FWE_NODE" "$FWE_PUBLIC" >"$d/node-public-ping.txt" 2>&1 || true
    FW "show counter global filter value all" | judge_body_panos "show counter global filter value all" >"$d/counters-after.txt" 2>/dev/null || true
    FWX "<show><counter><global><filter><value>all</value></filter></global></counter></show>" >"$d/counters-after.xml" 2>/dev/null || true
  fi

  # an egress the allowlist does not name: the node's connect to an internet host, refused and logged
  if [ -n "$FWE_EGRESS_ADDR" ] && [ -n "$FWE_NODE" ]; then
    fw_edge_connect_from "$FWE_NODE" "$FWE_EGRESS_ADDR" "$FWE_EGRESS_PORT" >"$d/egress-connect.txt"
    fw_edge_tlog "$d/egress-tlog" "show log traffic direction equal backward receive_time in last-15-minutes" \
      "$FWE_NODE_ADDR" "egress:$FWE_EGRESS_ADDR:$FWE_EGRESS_PORT"
  fi

  # administrative access: answered for the jump host, not for another inside host
  if [ -n "$FWE_ADMIN_ADDR" ] && [ -n "$FWE_BASTION" ]; then
    fw_edge_try "$d/bastion-admin-https.txt" X "$FWE_BASTION" curl -sk -o /dev/null -w '%{http_code}\n' --max-time 10 "https://$FWE_ADMIN_ADDR/"
    X "$FWE_BASTION" sh -c "curl -s --max-time 5 telnet://$FWE_ADMIN_ADDR:22 </dev/null | head -c 200; echo" >"$d/bastion-admin-ssh.txt" 2>&1 || true
    if [ -n "$FWE_NODE" ]; then
      if [ "$FWE_NODE_KIND" = vm-node ]; then
        H "$FWE_NODE" "curl -sk -o /dev/null -w '%{http_code}\n' --max-time 10 https://$FWE_ADMIN_ADDR/" >"$d/other-admin-https.txt" 2>&1 || true
      else
        X "$FWE_NODE" curl -sk -o /dev/null -w '%{http_code}\n' --max-time 10 "https://$FWE_ADMIN_ADDR/" >"$d/other-admin-https.txt" 2>&1 || true
      fi
    fi
  fi
  if [ -n "$FWE_OPERATOR" ] && [ -n "$FWE_PUBLIC" ]; then
    X "$FWE_OPERATOR" sh -c "curl -s --max-time 5 telnet://$FWE_PUBLIC:22 </dev/null | head -c 200; echo" >"$d/operator-public-ssh.txt" 2>&1 || true
    if [ -n "$FWE_OPERATOR_FQDN" ]; then
      fw_edge_try "$d/operator-public-https.txt" X "$FWE_OPERATOR" curl -sk -o /dev/null -D - --max-time 10 \
        --resolve "$FWE_OPERATOR_FQDN:443:$FWE_PUBLIC" "https://$FWE_OPERATOR_FQDN/"
    else
      fw_edge_try "$d/operator-public-https.txt" X "$FWE_OPERATOR" curl -sk -o /dev/null -D - --max-time 10 "https://$FWE_PUBLIC/"
    fi
  fi

  # the operator's requests to inside cells, refused at the firewall and logged
  if [ ${#FWE_CELLS[@]} -gt 0 ]; then
    # the drop counters read around the connects (a cell outside the tunnel is dropped by zone
    # protection before any rule, and only a counter says so)
    FW "show counter global filter delta yes severity drop" >/dev/null 2>&1 || true
    for cell in "${FWE_CELLS[@]}"; do
      IFS=: read -r i a p <<<"$cell"
      fw_edge_connect "$FWE_OPERATOR" "$a" "$p" >"$d/operator-cells-$i.txt"
    done
    FW "show counter global filter delta yes severity drop" >"$d/operator-drops.txt" 2>&1 || true
    fw_edge_tlog "$d/operator-cells-tlog" "show log traffic direction equal backward receive_time in last-15-minutes" \
      "$FWE_OPERATOR_ADDR" "${FWE_CELLS[@]}"
  fi

  # the service routes: a name resolved through the DNS one, then the firewall's own DNS and NTP in the log
  if [ -n "$FWE_SVC_SRC" ]; then
    [ -z "$FWE_BASTION_FQDN" ] || FW "ping source $FWE_SVC_SRC count 1 host $FWE_BASTION_FQDN" |
      judge_body_panos "ping source $FWE_SVC_SRC count 1 host $FWE_BASTION_FQDN" >"$d/fw-dns.txt" 2>/dev/null || true
    sleep "${SFAB_FWE_LOG_PAUSE_S:-10}"
    {
      FW "show log traffic direction equal backward receive_time in last-15-minutes dport equal 53" |
        judge_body_panos "show log traffic direction equal backward receive_time in last-15-minutes dport equal 53"
      FW "show log traffic direction equal backward receive_time in last-hour dport equal 123" |
        judge_body_panos "show log traffic direction equal backward receive_time in last-hour dport equal 123"
    } >"$d/svc-tlog.txt" 2>/dev/null || true
  fi
  _judge fw-edge "$FW_NODE"
}

# judge_body_panos CMD: one PAN-OS command's output from a session on stdin, without its prompt line
# (the whole session when the CLI wrapped the echo and it cannot be found).
judge_body_panos() {
  local s
  s="$(cat)"
  printf '%s\n' "$s" | py "$SFAB_COMMON/audit/judge.py" body --style panos --command "$1" 2>/dev/null || printf '%s\n' "$s"
}

# fw_edge_try OUT ARGV...: run into OUT, and once more after a pause when it fails (the first
# packets of a new flow are lost to ARP); OUT keeps the last attempt only
fw_edge_try() {
  local out="$1"
  shift
  "$@" >"$out" 2>&1 && return 0
  sleep "${SFAB_RETRY_PAUSE:-2}"
  "$@" >"$out" 2>&1 || true
}

# fw_edge_ping NODE ADDRESS: five pings from a VM guest (over SSH) or a container (docker exec)
fw_edge_ping() {
  if [ "${NODE_KIND[$1]}" = vm-node ]; then
    H "$1" "ping -c 5 -i 0.5 -W 1 $2"
  else
    X "$1" ping -c 5 -i 0.5 -W 1 "$2"
  fi
}

# fw_edge_connect CLIENT ADDRESS PORT: one TCP connect from a container, printed as the client saw
# it: "connected", or "failed" and how (timed out after 4 s, or the error the client printed). The
# clients are Alpine: busybox timeout ends a command that ran out of time with status 143 (SIGTERM)
# and prints "Terminated", where coreutils' exits 124.
fw_edge_connect() {
  local rc=0 err
  err="$(X "$1" bash -c "timeout 4 bash -c 'exec 3<>/dev/tcp/$2/$3' 2>&1" 2>&1)" || rc=$?
  if [ "$rc" = 0 ]; then
    echo connected
  elif [ "$rc" = 124 ] || [ "$rc" = 143 ]; then
    echo "failed: timed out after 4 s"
  else
    echo "failed: exit $rc${err:+, $(printf '%s' "$err" | tr '\n' ' ' | sed 's/ *$//')}"
  fi
}

# fw_edge_connect_from NODE ADDRESS PORT: fw_edge_connect from a container, or the same connect from a
# VM guest over SSH (coreutils' timeout exits 124 when the connect ran out of time)
fw_edge_connect_from() {
  local out rc
  if [ "${NODE_KIND[$1]:-}" != vm-node ]; then
    fw_edge_connect "$@"
    return
  fi
  out="$(H "$1" "timeout 4 bash -c 'exec 3<>/dev/tcp/$2/$3' 2>&1; echo rc=\$?" 2>&1)" || true
  rc="$(printf '%s\n' "$out" | sed -n 's/^rc=//p' | tail -n 1)"
  out="$(printf '%s\n' "$out" | { grep -v '^rc=' || true; } | tr '\n' ' ' | sed 's/ *$//')"
  case "$rc" in
    0) echo connected ;;
    124 | 143) echo "failed: timed out after 4 s" ;;
    *) echo "failed: exit ${rc:-unknown}${out:+, $out}" ;;
  esac
}

# fw_edge_tlog PREFIX CMD SRC ID:ADDR:PORT...: the traffic log, one read per destination port into
# PREFIX-<port>.txt (CMD and "dport equal <port>"), read again until it holds an entry from SRC to
# every ADDR:PORT (deny entries are written when the session is denied, a few seconds later)
fw_edge_tlog() {
  local pre="$1" cmd="$2" src="$3" i c miss p ports=()
  shift 3
  for c in "$@"; do
    IFS=: read -r _ _ p <<<"$c"
    case " ${ports[*]-} " in *" $p "*) ;; *) ports+=("$p") ;; esac
  done
  for i in $(seq 1 "${SFAB_FWE_TLOG_TRIES:-9}"); do
    for p in "${ports[@]}"; do
      FW "$cmd dport equal $p" | judge_body_panos "$cmd dport equal $p" >"$pre-$p.txt" 2>/dev/null || true
    done
    miss=0
    for c in "$@"; do
      IFS=: read -r _ a p <<<"$c"
      [ "$(py "$SFAB_COMMON/audit/panos_parse.py" tlog "$pre-$p.txt" --src "$src" --dst "$a" --dport "$p")" != "[]" ] || miss=1
    done
    [ "$miss" = 1 ] || return 0
    sleep "${SFAB_FWE_LOG_PAUSE_S:-10}"
  done
}

# audit_rail_backend SWITCH...: chapter 5's group. A full audit first reads, in every GPU node it
# collected, each GPU namespace's links (ip -n <ns> -j link show: the rail macvlan's and the relay
# veth's MTU, which the guest's own ip -j addr does not show) into rail-backend/<node>-<ns>-links.json.
# Then judge.py rail-backend judges the switches' absences and ports and, for each GPU node the set
# holds, its namespaces; a quick audit, which collects the switches only, judges the switches.
audit_rail_backend() {
  local g ns dir="$RS/rail-backend"
  if [ "$SFAB_QUICK" != 1 ]; then
    mkdir -p "$dir"
    for g in "${RELAY_GUESTS[@]+"${RELAY_GUESTS[@]}"}"; do
      [ -d "$RS/$g" ] || continue
      for ns in $(inv get "nodes.$g.relay.namespaces" 2>/dev/null); do
        H "$g" "ip -n $ns -j link show" >"$dir/$g-$ns-links.json" 2>/dev/null || true
      done
    done
  fi
  judge_present rail-backend "$@"
}

# ---------------------------------------------------------------------------------------------
# chapter 6: the serving pods against the placement table (judge.py placement)
#
# audit_placement: with serving on, reads into the set's placement/, every read on the lab host's
# clock: the serving namespace's pods, EndpointSlices, Services and rail attachments (JSON, and the
# pods, EndpointSlices and Services as kubectl prints them); inside each pod's own network namespace
# on its node, its routes and addresses (pod-<pod>-routes.json and -addr.json, and -route.txt and
# -addr.txt as ip route and ip addr print them); and for each model route a client of the lab
# reaches (gen/k8s.json inference.routes, the client of the population that Gateway answers), one
# chat completion a model with the model's key, handed to the client as a 0600 header file
# (lib-servecap.sh: the transcript off), its status and the response headers saved
# (gateway-<route>-<model>-*); the request's headers are never saved. The table judged is copied in
# as placement/serving.env, with the recipe's render of it beside it (placement/rendered/, its
# output in placement/render.txt). A quick audit reads all of it too.
audit_placement() {
  local dir table="" i sns pod node ppid model rt client url pin gw
  [ "${STAGE_SERVING:-0}" = 1 ] || return 0
  dir="$RS/placement"
  for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
    [ "${SFAB_ARGS[$i]}" != --table ] || table="${SFAB_ARGS[$((i + 1))]:-}"
  done
  [ -n "$table" ] || table="$RENDERDIR/bootstrap/k8s/serving.env"
  # shellcheck source=common/trace/lib-servecap.sh
  . "$SFAB_COMMON/trace/lib-servecap.sh"
  mkdir -p "$dir"
  if [ ! -f "$table" ]; then
    sec "placement"
    bad "the placement table" "no $table"
    return 0
  fi
  cp "$table" "$dir/serving.env"
  sns="$(k8s_get serving.namespace)"
  EVID_OFF=1 K -n "$sns" get pods -o json >"$dir/pods.json" 2>/dev/null || true
  K -n "$sns" get pods -o wide >"$dir/pods.txt" 2>&1 || true
  EVID_OFF=1 K -n "$sns" get endpointslices -o json >"$dir/endpointslices.json" 2>/dev/null || true
  K -n "$sns" get endpointslices -o wide >"$dir/endpointslices.txt" 2>&1 || true
  EVID_OFF=1 K -n "$sns" get services -o json >"$dir/services.json" 2>/dev/null || true
  K -n "$sns" get services -o wide >"$dir/services.txt" 2>&1 || true
  EVID_OFF=1 K -n "$sns" get network-attachment-definitions -o json >"$dir/nads.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$sns" get statefulsets -o json >"$dir/statefulsets.json" 2>/dev/null || true
  K -n "$sns" get statefulsets -o wide >"$dir/statefulsets.txt" 2>&1 || true
  EVID_OFF=1 K -n "$sns" get persistentvolumeclaims -o json >"$dir/pvcs.json" 2>/dev/null || true
  EVID_OFF=1 K get persistentvolumes -l "app.kubernetes.io/name=serving" -o json >"$dir/pvs.json" 2>/dev/null || true
  K get persistentvolumes -l "app.kubernetes.io/name=serving" -o wide >"$dir/pvs.txt" 2>&1 || true
  # the manifests the recipe renders from the table judged (no cluster read: serving.py render), so
  # a set holds the pod manifests and Services as rendered beside what the cluster runs
  (cd "$dir" && py "$SFAB_ROOT/serving-layer/serving.py" render --env serving.env --out rendered >render.txt 2>&1) || true
  while read -r pod node; do
    [ -n "$pod" ] || continue
    ppid="$(pod_pid "$node" "$sns" "$pod")"
    [ -n "$ppid" ] || continue
    EVID_OFF=1 pod_ns_run "$node" "$ppid" ip -j route show >"$dir/pod-$pod-routes.json" 2>/dev/null || true
    EVID_OFF=1 pod_ns_run "$node" "$ppid" ip -j addr show >"$dir/pod-$pod-addr.json" 2>/dev/null || true
    pod_ns_run "$node" "$ppid" ip route show >"$dir/pod-$pod-route.txt" 2>&1 || true
    pod_ns_run "$node" "$ppid" ip addr show >"$dir/pod-$pod-addr.txt" 2>&1 || true
    # the pod's listening TCP sockets: llama-server on its cluster address, ggml-rpc-server on its rail address
    pod_ns_run "$node" "$ppid" ss -Hltn >"$dir/pod-$pod-listen.txt" 2>&1 || true
  done < <(py -c 'import json, sys
try:
    d = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    d = {}
for i in d.get("items") or []:
    if (i.get("spec") or {}).get("nodeName"):
        print(i["metadata"]["name"], i["spec"]["nodeName"])' "$dir/pods.json")
  while IFS=$'\t' read -r rt gw client url model pin; do
    [ -n "$rt" ] || continue
    local tag="$rt-$model" kdir=/tmp/sfab-audit-key pinarg=()
    [ "$pin" = - ] || pinarg=(--resolve "$pin")
    printf '{"client": "%s", "gateway": "%s", "model": "%s", "route": "%s", "url": "%s"}\n' "$client" "$gw" "$model" "$rt" "$url" >"$dir/gateway-$tag.json"
    if key_to_client "$(k8s_get inference.namespace)" "$(k8s_get inference.keys.models.secret)" "$model" "$client" "$kdir" >"$dir/gateway-$tag-key.txt" 2>&1; then
      X "$client" curl -sS --max-time 120 "${pinarg[@]+"${pinarg[@]}"}" -o /dev/null -D "$kdir/headers.txt" -w '%{http_code}\n' \
        -H "@$kdir/hdr-$model" -H 'Content-Type: application/json' \
        --data "{\"model\": \"$model\", \"max_tokens\": 8, \"messages\": [{\"role\": \"user\", \"content\": \"Say hello.\"}]}" "$url" \
        >"$dir/gateway-$tag-result.txt" 2>&1 || true
      dk exec "$(ctr "$client")" cat "$kdir/headers.txt" 2>/dev/null | tr -d '\r' >"$dir/gateway-$tag-headers.txt" || true
    else
      echo "none" >"$dir/gateway-$tag-result.txt"
    fi
    key_clear "$client" "$kdir"
  done < <(audit_gateway_targets)
  _judge placement
}

# audit_gateway_targets: one line a model route and model a client of the lab reaches, tab-separated:
# route, Gateway, client, URL, model, and the --resolve pin (- when the client's resolver is in the lab).
# From chapter 8 gen/tenancy.json's audiences.reach gives each population's connect to its own
# Gateway at this step: a population the firewall does not yet let through (the internet users in
# chapter 9, before the translation) is no target
audit_gateway_targets() {
  py - "$RENDERDIR/gen/k8s.json" "$INV" "$RENDERDIR/gen/tenancy.json" <<'PY'
import json, sys
k8s, inv = (json.load(open(p, encoding="utf-8")) for p in sys.argv[1:3])
try:
    reach = {r["population"]: r for r in (json.load(open(sys.argv[3], encoding="utf-8")).get("audiences") or {}).get("reach") or []}
except (OSError, ValueError):
    reach = {}
inf = k8s.get("inference") or {}
nodes, gws = inv.get("nodes") or {}, inv.get("gateways") or {}
for rt in inf.get("routes") or []:
    g = gws.get(rt["gateway"]) or {}
    vip = (g.get("vip") or "").split("/")[0]
    pop = next((p for pid, p in sorted((inv.get("populations") or {}).items()) if p.get("gateway") == rt["gateway"]
                and any(c in nodes for c in p.get("clients") or [])
                and (pid not in reach or reach[pid]["outcome"] == "reached")), None)
    if pop is None:
        continue
    client = next(c for c in pop["clients"] if c in nodes)
    host = rt["hostnames"][0]
    resolver = (nodes.get(client) or {}).get("resolver")
    addr = pop.get("answer_address") or vip
    # pinned unless the client's resolver is in the lab and answers the name: an authoritative view
    # of that server lists it, or the server is a resolver that reaches the platform's pair (the
    # operator's public server publishes no platform name in state one)
    dns = inv.get("dns") or {}
    served = any(resolver in (v.get("servers") or [v.get("server")]) and host in (v.get("names") or [])
                 for v in (dns.get("views") or {}).values())
    recursive = any(resolver in (r.get("servers") or []) for r in (dns.get("resolvers") or {}).values())
    pin = "-" if resolver and resolver in nodes and (served or recursive) else f"{host}:443:{addr}"
    for m in inf.get("models") or []:
        if any(r.get("model") in (None, m["name"]) for r in rt["rules"]):
            print("\t".join((rt["name"], rt["gateway"], client, f"https://{host}{m['path']}/v1/chat/completions", m["name"], pin)))
PY
}

# audit_gateway_layer: with serving on (chapter 7). The keys are handed to each route's client
# through pipes (lib-servecap.sh: the transcript off) and removed after; no request header is saved,
# only each answer's status and body (an API gateway refusal holds no key). The per-pod probe is a
# pod of the key tool in the cluster, which reads the keys from its own mounted Secret.
audit_gateway_layer() {
  local d g dir kdir=/tmp/sfab-audit-keys rt gw client url model pin tag o fields checks ns from vip host
  [ "${STAGE_SERVING:-0}" = 1 ] || return 0
  # shellcheck source=common/trace/lib-servecap.sh
  . "$SFAB_COMMON/trace/lib-servecap.sh"
  d="$RS/keys"
  mkdir -p "$d"
  : >"$d/targets.jsonl"
  mapfile -t _models < <(k8s_get inference.models | py -c 'import json, sys; [print(json.loads(l)["name"]) for l in sys.stdin if l.strip()]')
  while IFS=$'\t' read -r rt gw client url model pin; do
    [ -n "$rt" ] || continue
    tag="$rt-$model"
    local pinarg=() req=() cross=()
    [ "$pin" = - ] || pinarg=(--resolve "$pin")
    req=(-sS --max-time 60 "${pinarg[@]+"${pinarg[@]}"}" -o "$kdir/body.txt" -w '%{http_code}\n' -H 'Content-Type: application/json'
      --data "{\"model\": \"$model\", \"max_tokens\": 1, \"messages\": [{\"role\": \"user\", \"content\": \"Say yes.\"}]}")
    key_clear "$client" "$kdir"
    dk exec "$(ctr "$client")" sh -c "umask 077; mkdir -p $kdir" >/dev/null 2>&1 || true
    X "$client" curl "${req[@]}" "$url" >"$d/$tag-nokey-result.txt" 2>&1 || true
    dk exec "$(ctr "$client")" cat "$kdir/body.txt" >"$d/$tag-nokey-body.txt" 2>/dev/null || true
    if key_unknown "$client" "$kdir" unknown; then
      X "$client" curl "${req[@]}" -H "@$kdir/hdr-unknown" "$url" >"$d/$tag-unknown-result.txt" 2>&1 || true
      dk exec "$(ctr "$client")" cat "$kdir/body.txt" >"$d/$tag-unknown-body.txt" 2>/dev/null || true
    fi
    for o in "${_models[@]}"; do
      [ "$o" != "$model" ] || continue
      if key_to_client "$(k8s_get inference.namespace)" "$(k8s_get inference.keys.models.secret)" "$o" "$client" "$kdir" >>"$d/keys.txt" 2>&1; then
        X "$client" curl "${req[@]}" -H "@$kdir/hdr-$o" "$url" >"$d/$tag-cross-$o-result.txt" 2>&1 || true
        dk exec "$(ctr "$client")" cat "$kdir/body.txt" >"$d/$tag-cross-$o-body.txt" 2>/dev/null || true
        cross+=("\"$o\"")
      fi
    done
    key_clear "$client" "$kdir"
    printf '{"tag": "%s", "route": "%s", "gateway": "%s", "client": "%s", "model": "%s", "url": "%s", "cross": [%s]}\n' \
      "$tag" "$rt" "$gw" "$client" "$model" "$url" "$(IFS=,; echo "${cross[*]-}")" >>"$d/targets.jsonl"
  done < <(audit_gateway_targets)
  # the per-pod probe: every model's first key on its own route (200) and on every other model's route (401)
  : >"$d/checks.jsonl"
  checks=()
  ns="$(k8s_get inference.namespace)"
  for model in "${_models[@]}"; do
    fields="$(EVID_OFF=1 K -n "$ns" get secret "$(k8s_get inference.keys.models.secret)" -o json 2>/dev/null |
      py "$SFAB_COMMON/trace/servekeys.py" which --model "$model" 2>/dev/null | cut -d' ' -f1 || true)"
    [ -n "$fields" ] || continue
    printf '%s %s\n' "$model" "$fields" >>"$d/fields.txt"
    for o in "${_models[@]}"; do
      if [ "$o" = "$model" ]; then
        checks+=("own-$model $model $fields 200")
        printf '{"label": "own-%s", "kind": "own", "route": "%s", "key_model": "%s", "expect": 200}\n' "$model" "$model" "$model" >>"$d/checks.jsonl"
      else
        checks+=("cross-$o-$model $o $fields $(k8s_get inference.rejected.code)")
        printf '{"label": "cross-%s-%s", "kind": "cross", "route": "%s", "key_model": "%s", "expect": %s}\n' "$o" "$model" "$o" "$model" \
          "$(k8s_get inference.rejected.code)" >>"$d/checks.jsonl"
      fi
    done
  done
  if [ ${#checks[@]} -gt 0 ]; then
    keyprobe_run "$(k8s_get inference.probe.name)-audit" "$d/probe.log" 30 "${checks[@]}" || true
  fi
  _judge keys
  [ "$SFAB_QUICK" != 1 ] || return 0
  audit_identity
  dir="$RS/gateway-layer"
  mkdir -p "$dir"
  EVID_OFF=1 K get gatewayclasses -o json >"$dir/gatewayclasses.json" 2>/dev/null || true
  EVID_OFF=1 K get gateways -A -o json >"$dir/gateways.json" 2>/dev/null || true
  EVID_OFF=1 K get httproutes -A -o json >"$dir/httproutes.json" 2>/dev/null || true
  EVID_OFF=1 K get namespaces -o json >"$dir/namespaces.json" 2>/dev/null || true
  EVID_OFF=1 K -n kube-system get leases -o json >"$dir/leases.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$(k8s_get gateway_namespace)" get ciliumenvoyconfigs -o json >"$dir/cec.json" 2>/dev/null || true
  EVID_OFF=1 K -n kube-system get configmap cilium-config -o json >"$dir/cilium-config.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$ns" get configmaps -o json >"$dir/configmaps.json" 2>/dev/null || true
  K get gateways -A -o wide >"$dir/gateways.txt" 2>&1 || true
  K get httproutes -A >"$dir/httproutes.txt" 2>&1 || true
  K -n kube-system get leases >"$dir/leases.txt" 2>&1 || true
  local labels=()
  for g in $(k8s_get gateways | py -c 'import json, sys; print(" ".join(sorted(json.loads(sys.stdin.read()))))'); do
    labels+=(-L "$(k8s_get "gateways.$g.allowed_routes.label")")
  done
  K get namespaces "${labels[@]+"${labels[@]}"}" >"$dir/namespaces.txt" 2>&1 || true
  from="$(py -c 'import json, sys; inv = json.load(open(sys.argv[1])); g = [n for n in (inv.get("groups") or {}).get("gpu", []) if n in inv["nodes"]]; print(g[0] if g else "")' "$INV")"
  printf '%s\n' "$from" >"$dir/vip-from.txt"
  host="$(k8s_get inference.hostname)"
  local gfrom
  for g in $(k8s_get gateways | py -c 'import json, sys; print(" ".join(sorted(json.loads(sys.stdin.read()))))'); do
    vip="$(k8s_get "gateways.$g.vip")"
    # ARP answers only inside the VIP's own VLAN: ask from a node with a unit in it (the ingress VLAN
    # in revision 2) that does not hold the VIP's lease, else from the first GPU node
    gfrom="$(py - "$INV" "$vip" "$dir/leases.json" "$(k8s_get "gateways.$g.l2_lease" 2>/dev/null)" <<'PY'
import ipaddress, json, sys
inv = json.load(open(sys.argv[1]))
vip = ipaddress.ip_address(sys.argv[2])
try:
    ln = sys.argv[4].split("/", 1)[-1]
    holder = next((i["spec"].get("holderIdentity") for i in json.load(open(sys.argv[3])).get("items") or []
                   if i["metadata"]["name"] == ln), None)
except (OSError, ValueError, KeyError):
    holder = None
inside = [n for n, x in sorted(inv["nodes"].items()) if x.get("kind") == "vm-node" and n != holder and
          any(u.get("address") and vip in ipaddress.ip_interface(u["address"]).network for u in (x.get("bond") or {}).get("vlan_ifs") or [])]
print(inside[0] if inside else "")
PY
)"
    gfrom="${gfrom:-$from}"
    printf '%s\n' "$gfrom" >"$dir/vip-from-$g.txt"
    [ -z "$gfrom" ] || H "$gfrom" "ping -c 3 -W 1 $vip; if timeout 5 bash -c '</dev/tcp/$vip/443' 2>/dev/null; then echo tcp-open; else echo tcp-failed; fi; ip neigh show $vip" \
      >"$dir/vip-$g.txt" 2>&1 || true
    # the chain read from a client the firewall lets reach this Gateway: a population's client of
    # it, else the bastion (whose rules reach the internal Gateway only). From chapter 8
    # gen/tenancy.json's audiences.tls_from names the node and the address: a client of a
    # population that reaches the Gateway, at its answer address (the published one for a
    # translated population), else the nodes' client at the VIP, which its own datapath answers
    local tfrom tkind taddr
    read -r tfrom tkind taddr < <(py -c 'import json, sys
inv = json.load(open(sys.argv[1]))
try:
    t = ((json.load(open(sys.argv[4])).get("audiences") or {}).get("tls_from") or {}).get(sys.argv[2])
except (OSError, ValueError):
    t = None
if t:
    print(t["node"], t["kind"], t["address"])
    sys.exit(0)
nodes = inv.get("nodes") or {}
for p in (inv.get("populations") or {}).values():
    if p.get("gateway") == sys.argv[2]:
        c = next((x for x in p.get("clients") or [] if (nodes.get(x) or {}).get("kind") == "client"), None)
        if c:
            print(c, "client", sys.argv[3])
            sys.exit(0)
print("-", "client", sys.argv[3])' "$INV" "$g" "$vip" "$RENDERDIR/gen/tenancy.json" 2>/dev/null || echo "- client $vip")
    [ "$tfrom" != - ] || tfrom="$BASTION"
    printf '%s\n' "$tfrom" >"$dir/tls-from-$g.txt"
    local tcmd="openssl s_client -connect $taddr:443 -servername $host -CAfile /shared/ca/root.crt -verify_return_error -showcerts </dev/null 2>&1 | grep -E '^(depth=|verify error|Verify return code| *[0-9]+ s:| *i:)'"
    if [ "$tkind" = vm-node ]; then
      H "$tfrom" "$tcmd" >"$dir/tls-$g.txt" 2>&1 || true
    else
      X "$tfrom" sh -c "$tcmd" >"$dir/tls-$g.txt" 2>&1 || true
    fi
  done
  # the CA's proof, on the lab host where the CA lives (common/ca/sfab-ca), and its refused leaves
  "$SFAB_COMMON/ca/sfab-ca" -C "$RENDERDIR" proof >"$dir/ca-proof.txt" 2>&1 || true
  for f in "$STATEDIR"/ca/proof/*-outside-*.verify.txt; do
    [ -f "$f" ] || continue
    printf '== state/ca/proof/%s\n' "$(basename "$f")"
    cat "$f"
  done >"$dir/ca-proof-outside.txt" 2>&1 || true
  _judge gateway-layer
}

# ---------------------------------------------------------------------------------------------
# the cluster's protections (build A revision 2): judge.py cluster-security

audit_cluster_security() {
  local dir n init sec c ns pod img vip holder client addr t port name lease
  [ "${STAGE_CLUSTER:-0}" = 1 ] || return 0
  [ "$SFAB_QUICK" != 1 ] || return 0
  # shellcheck source=common/trace/lib-servecap.sh
  . "$SFAB_COMMON/trace/lib-servecap.sh"
  dir="$RS/cluster-security"
  mkdir -p "$dir"
  init="$KNODE"
  # Secrets at rest: the flag and the config's mode on every control node (never its content), and
  # the first bytes etcd stores for one Secret (the provider's prefix when it is encrypted)
  if [ -n "$(k8s_get secrets_encryption.config)" ]; then
    for n in $(k8s_get api.control); do
      H "$n" "grep -c -- '--encryption-provider-config=$(k8s_get secrets_encryption.config)' /etc/kubernetes/manifests/kube-apiserver.yaml; stat -c '%a %U' $(k8s_get secrets_encryption.config) 2>&1; grep -c '^ *- $(k8s_get secrets_encryption.provider):' $(k8s_get secrets_encryption.config) 2>&1" \
        >"$dir/encryption-$n.txt" 2>&1 || true
    done
    sec="$(k8s_get issuer.namespace)/$(k8s_get issuer.secret)"
    printf '%s\n' "$sec" >"$dir/etcd-secret.txt"
    H "$init" "id=\$(crictl ps --name '^etcd\$' -q 2>/dev/null | head -n 1); crictl exec \$id etcdctl --endpoints=https://127.0.0.1:2379 --cacert=/etc/kubernetes/pki/etcd/ca.crt --cert=/etc/kubernetes/pki/etcd/healthcheck-client.crt --key=/etc/kubernetes/pki/etcd/healthcheck-client.key get /registry/secrets/$sec --print-value-only 2>/dev/null | head -c 26; echo" \
      >"$dir/etcd-prefix.txt" 2>&1 || true
    K -n "${sec%%/*}" get secret "${sec#*/}" -o jsonpath='{.type}{"\n"}' >"$dir/api-secret-type.txt" 2>&1 || true
  fi
  # WireGuard: each agent's own view
  EVID_OFF=1 K -n kube-system get configmap cilium-config -o json >"$dir/cilium-config.json" 2>/dev/null || true
  : >"$dir/wireguard.txt"
  while read -r pod node; do
    [ -n "$pod" ] || continue
    { echo "== $pod $node"
      K -n kube-system exec "$pod" -c cilium-agent -- cilium-dbg encrypt status 2>&1; } >>"$dir/wireguard.txt" || true
  done < <(EVID_OFF=1 K -n kube-system get pods -l k8s-app=cilium -o json 2>/dev/null | py -c 'import json, sys
try:
    for i in json.load(sys.stdin).get("items") or []:
        print(i["metadata"]["name"], (i.get("spec") or {}).get("nodeName", "?"))
except ValueError:
    pass')
  # each Gateway's certificate: subject, issuer, names and its public key's fingerprint
  : >"$dir/gateway-certs.txt"
  for c in $(k8s_get certificates | py -c 'import json, sys; [print(json.loads(l)["secret"]) for l in sys.stdin if l.strip()]'); do
    { echo "== $c"
      KSH "kubectl -n $(k8s_get gateway_namespace) get secret $c -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/sfab-gwcert.pem; openssl x509 -in /tmp/sfab-gwcert.pem -noout -subject -issuer -ext subjectAltName -nameopt RFC2253; printf 'spki sha256 '; openssl x509 -in /tmp/sfab-gwcert.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | cut -c1-64; rm -f /tmp/sfab-gwcert.pem" 2>&1; } >>"$dir/gateway-certs.txt" || true
  done
  # the pods and their nodes, and the policies
  EVID_OFF=1 K get pods -A -o json >"$dir/pods.json" 2>/dev/null || true
  EVID_OFF=1 K get ciliumnetworkpolicies -A -o json >"$dir/cnp.json" 2>/dev/null || true
  K get ciliumnetworkpolicies -A >"$dir/cnp.txt" 2>&1 || true
  # a probe pod in a namespace no policy selects connects to every policed Service: each must be
  # refused (Cilium drops it, so the connect times out), and the cluster's DNS, unpoliced, answers
  if [ -n "$(k8s_get network_policy.files.base)" ] && [ -n "$(k8s_get test_backend.namespace)" ]; then
    img="$(EVID_OFF=1 K -n "$(k8s_get test_backend.namespace)" get deployment "$(k8s_get test_backend.deployment)" -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || true)"
    name=sfab-netpol-probe
    py "$SFAB_COMMON/audit/clustersec.py" targets "$RENDERDIR/gen/k8s.json" >"$dir/targets.txt" 2>&1 || true
    t="$(tmpf)"
    py "$SFAB_COMMON/audit/clustersec.py" probe-pod "$name" "$img" >"$t"
    EVID_OFF=1 K -n default delete pod "$name" --ignore-not-found --wait=true >/dev/null 2>&1 || true
    kcreate "$t" >"$dir/probe-create.txt" 2>&1 || true
    rm -f "$t"
    K -n default wait --for=condition=Ready "pod/$name" --timeout=180s >"$dir/probe-ready.txt" 2>&1 || true
    : >"$dir/probe.txt"
    while IFS=$'\t' read -r t ns c port _; do
      [ -n "$t" ] || continue
      addr="$(EVID_OFF=1 K -n "$ns" get service "$c" -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
      { printf '== %s %s/%s %s:%s\n' "$t" "$ns" "$c" "${addr:-none}" "$port"
        K -n default exec "$name" -- /agnhost connect "$addr:$port" --timeout=5s 2>&1; echo "rc=$?"; } >>"$dir/probe.txt" || true
    done <"$dir/targets.txt"
    EVID_OFF=1 K -n default delete pod "$name" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
  # the ingress nodes' policy routing, and a reply of a Gateway leaving its lease holder tagged in
  # the ingress VLAN while a population's client connects to the VIP
  for n in $(k8s_get edge.nodes); do
    H "$n" "ip rule show; echo ==; ip route show table 110" >"$dir/policy-routing-$n.txt" 2>&1 || true
  done
  read -r vip lease client <<<"$(py "$SFAB_COMMON/audit/clustersec.py" reply-plan "$INV" "$RENDERDIR/gen/k8s.json" 2>/dev/null || true)"
  if [ -n "${vip:-}" ] && [ -n "${lease:-}" ] && [ -n "$(k8s_get edge.nodes)" ]; then
    holder="$(EVID_OFF=1 K -n "${lease%%/*}" get lease "${lease#*/}" -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
    printf '%s %s %s\n' "$vip" "${holder:-none}" "$client" >"$dir/reply-plan.txt"
    if [ -n "$holder" ]; then
      H "$holder" "rm -f /tmp/sfab-reply.txt" >/dev/null 2>&1 || true
      HBG "$holder" "timeout 40 tcpdump -i bond0 -nn -e -c 3 'vlan 110 and tcp and src host $vip and tcp[tcpflags] & tcp-syn != 0' > /tmp/sfab-reply.txt 2>/dev/null"
      sleep 4
      for port in 1 2 3; do X "$client" sh -c "nc -z -w 3 $vip 443" >/dev/null 2>&1 || true; sleep 1; done
      sleep 3
      H "$holder" "cat /tmp/sfab-reply.txt; rm -f /tmp/sfab-reply.txt" >"$dir/reply-capture.txt" 2>&1 || true
    fi
  fi
  _judge cluster-security
}

# ---------------------------------------------------------------------------------------------
# the identity provider and the people's tokens at the API gateway (chapter 7): judge.py identity

audit_identity() {
  local dir kdir=/tmp/sfab-audit-idp client person gw host pin ns pod m rt rgw url model rpin
  [ "${STAGE_SERVING:-0}" = 1 ] || return 0
  [ "$SFAB_QUICK" != 1 ] || return 0
  [ -n "$(k8s_get identity.namespace)" ] || return 0
  # shellcheck source=common/trace/lib-servecap.sh
  . "$SFAB_COMMON/trace/lib-servecap.sh"
  dir="$RS/identity"
  mkdir -p "$dir"
  : >"$dir/people.jsonl"
  EVID_OFF=1 K -n "$(k8s_get identity.namespace)" get pods -o json >"$dir/idp-pods.json" 2>/dev/null || true
  K -n "$(k8s_get identity.namespace)" get pods,services,httproutes -o wide >"$dir/idp-objects.txt" 2>&1 || true
  while IFS=$'\t' read -r person client gw host pin; do
    [ -n "$person" ] || continue
    local pinarg=()
    [ "$pin" = - ] || pinarg=(--resolve "$pin")
    key_clear "$client" "$kdir"
    dk exec "$(ctr "$client")" sh -c "umask 077; mkdir -p $kdir" >/dev/null 2>&1 || true
    X "$client" curl -sS --max-time 30 "${pinarg[@]+"${pinarg[@]}"}" -o "$kdir/discovery.json" -w '%{http_code}\n' \
      "https://$host/.well-known/openid-configuration" >"$dir/$person-discovery-status.txt" 2>&1 || true
    dk exec "$(ctr "$client")" cat "$kdir/discovery.json" >"$dir/$person-discovery.json" 2>/dev/null || true
    idp_token "$client" "$kdir" aud >"$dir/$person-token-status.txt" 2>&1 || true
    dk exec "$(ctr "$client")" cat "$kdir/claims-aud.json" >"$dir/$person-claims.json" 2>/dev/null || true
    idp_token "$client" "$kdir" noaud noaud >"$dir/$person-token-noaud-status.txt" 2>&1 || true
    dk exec "$(ctr "$client")" cat "$kdir/claims-noaud.json" >"$dir/$person-claims-noaud.json" 2>/dev/null || true
    # the altered token: one character of its signature changed, in the client, never printed. Not
    # the last: base64url's last character of a 256-byte signature carries padding bits a decoder
    # ignores, so changing it can leave the signature's bytes as they were (a first audit saw the
    # "altered" token answered 200 for that reason); the tenth from the end is all signature.
    # shellcheck disable=SC2016 # expanded by the client's python3
    dk exec "$(ctr "$client")" python3 -c '
import os, sys
os.umask(0o077)
t = open(sys.argv[1]).read().rstrip("\n")
i = len(t) - 10
open(sys.argv[2], "w").write(t[:i] + ("A" if t[i] != "A" else "B") + t[i + 1:] + "\n")
' "$kdir/hdr-aud" "$kdir/hdr-altered" >/dev/null 2>&1 || true
    while IFS=$'\t' read -r rt rgw _ url model rpin; do
      [ "$rgw" = "$gw" ] || continue
      local rpinarg=() req=()
      [ "$rpin" = - ] || rpinarg=(--resolve "$rpin")
      req=(-sS --max-time 120 "${rpinarg[@]+"${rpinarg[@]}"}" -o "$kdir/body.txt" -D "$kdir/headers.txt" -w '%{http_code}\n'
        -H 'Content-Type: application/json'
        --data "{\"model\": \"$model\", \"max_tokens\": 4, \"messages\": [{\"role\": \"user\", \"content\": \"Say yes.\"}]}")
      for m in aud noaud altered; do
        X "$client" curl "${req[@]}" -H "@$kdir/hdr-$m" "$url" >"$dir/$person-$model-$m-result.txt" 2>&1 || true
        dk exec "$(ctr "$client")" cat "$kdir/body.txt" 2>/dev/null | head -c 400 >"$dir/$person-$model-$m-body.txt" || true
        dk exec "$(ctr "$client")" cat "$kdir/headers.txt" 2>/dev/null | tr -d '\r' | grep -i '^www-authenticate' >"$dir/$person-$model-$m-www.txt" || true
      done
    done < <(audit_gateway_targets)
    key_clear "$client" "$kdir"
    printf '{"person": "%s", "client": "%s", "gateway": "%s"}\n' "$person" "$client" "$gw" >>"$dir/people.jsonl"
  done < <(py "$SFAB_COMMON/audit/clustersec.py" people "$RENDERDIR/gen/k8s.json" "$INV")
  # the API gateway's access lines (file-logger: no header, so no credential) of the last minutes
  ns="$(k8s_get inference.namespace)"
  : >"$dir/api-gateway-log.txt"
  for pod in $(EVID_OFF=1 K -n "$ns" get pods -l "app.kubernetes.io/name=$(k8s_get inference.gateway.name)" -o json 2>/dev/null |
                py -c 'import json, sys
try:
    print(" ".join(i["metadata"]["name"] for i in json.load(sys.stdin).get("items") or []))
except ValueError:
    pass'); do
    EVID_OFF=1 K -n "$ns" logs "$pod" -c apisix --since=15m 2>/dev/null | grep '"consumer"' | sed "s/^/$pod /" >>"$dir/api-gateway-log.txt" || true
  done
  _judge identity
}
