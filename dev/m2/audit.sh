#!/usr/bin/env bash
# dev/m2/audit.sh: the M2 exit criteria (dev/m2/RESULTS.md) as checks, recorded as a result set
# under audits/. Criterion 11 (the trace) is recorded by trace.sh, 15 (teardown) by
# `make teardown-check`.
#
#   ./audit.sh            the full audit
#   ./audit.sh --quick    switches and the firewall only (and the storage appliances' and the
#                         bastion's container links, for the MAC tables), not recorded (finish runs it)
#
# The full audit also writes a volume on each storage class and reads it back (criterion 9); it
# creates its claims and pods in the namespace sfab-audit and deletes them, and the namespace,
# before it ends. SFAB_AUDIT_VOLUMES=0 leaves that out (the line then reads SKIP), and
# SFAB_AUDIT_CLEAN=0 the repository checks (the tests, which run on a copy of the render).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../../common/lib.sh"
sfab_init audit "$@"

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
# services_nodes: the platform's DNS and time servers (judge.py services), as common/audit/lib-audit.sh lists them
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

[ "$SFAB_QUICK" = 1 ] || audit_preflight                         # 1: preflight, tick, other labs, budget
if [ "$SFAB_QUICK" = 1 ]; then
  mapfile -t _sc < <(switch_containers)
  # quick: switches, the firewall, the storage appliances' and the bastion's container links
  audit_collect "${SWITCHES[@]}" ${FW_NODE:+"$FW_NODE"} "${STORAGE[@]+"${STORAGE[@]}"}" "${_sc[@]+"${_sc[@]}"}"
else
  audit_collect                                                  # every node's plan
fi
audit_judge                                                      # 2: switches, firewall, guests, rails, VLANs, MAC tables
audit_forwarding_only fe-sw1 fe-sw2 rail-sw1 rail-sw2 oob-sw     # 2: the forwarding-only reads
audit_mclag_pair fe-sw1 fe-sw2                                   # 2: the pair, every PortChannel
if [ "$SFAB_QUICK" = 1 ]; then summary; exit; fi
audit_l2_hygiene fe-sw1 fe-sw2 rail-sw1 rail-sw2                # 2: MTU, BPDU guard, storm control (revision 2)
mapfile -t _k8s < <(k8s_nodes)
judge_present cluster-nodes "${_k8s[@]}"                         # 3: the cluster's nodes
judge_present bastion ${BASTION:+"$BASTION"}                     # 4: the bastion, the jump host
mapfile -t _svc < <(services_nodes)
judge_present services "${_svc[@]}"                              # 4: the DNS and time servers
mapfile -t _rtr < <(of_kind frr)
mapfile -t _reg < <(of_kind registry)
judge_present routers "${_rtr[@]}"                               # 5: the uplink router
judge_present registry "${_reg[@]}"                              # 5: the registry
mapfile -t _cli < <(of_kind client)
judge_present clients "${_cli[@]}"                               # 6: the clients
judge_present storage "${STORAGE[@]+"${STORAGE[@]}"}"            # 9: storage
[ "$STAGE_CLUSTER" != 1 ] || _judge populations                  # 7: the populations reach their Gateways
[ "$STAGE_CLUSTER" != 1 ] || _judge cluster                      # 8: the cluster
[ "$STAGE_CLUSTER" != 1 ] || storage_volumes                     # 9: a volume on each class
[ "${SFAB_AUDIT_CLEAN:-1}" = 0 ] || audit_clean                 # 16: namecheck and sfab check
summary                                                          # 12: the RESULT line
