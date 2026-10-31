#!/usr/bin/env bash
# vm-init.sh: PID 1 of an sfab/vm-node container. It turns the container into a KVM guest that
# containerlab wires like any other node:
#
#   1. reads bootstrap/<node>/node.env (bound at /sfab/bootstrap) and checks it against the
#      topology's env (SFAB_NODE, VM_MEMORY_MB, VM_SMP, VM_DISK_GIB, VM_NICS, VM_TX_OFF);
#   2. waits while /shared/hold-guests exists (the up stage holds the guests until the fabric
#      converges), and only then waits for its links, so every link exists when it is wired;
#   3. bridges each container NIC to a tap (br<i>, tap<i>), with learning off on both ports so the
#      bridge is a wire. Data bridges forward LACP and LLDP
#      (group_fwd_mask 0x4004); on a kernel that refuses that mask, the NIC and its tap are
#      joined by a tc mirred redirect instead. The container's data devices carry no IPv6 and
#      have TX checksum offload off; eth0 (management) loses its address to the guest;
#   4. creates the root disk as a qcow2 overlay of /base/node.qcow2 (grown, never shrunk), and
#      refuses a disk made from another base;
#   5. writes the NoCloud seed (/vm/seed.iso): user-data, meta-data and network-config, plus
#      the node files under sfab/ that seed-sync.sh installs inside the guest at every boot;
#   6. boots the guest and waits for it. SIGTERM (docker stop) presses the guest's power
#      button; when the guest powers off, this script exits and the container stops.
#
# Binds (render/clab.py): /sfab/bootstrap (ro), /vm (state/nodes/<node>), /shared (state/shared),
# /sfab/authorized_keys (ro, the lab key and the deploying user's own public keys), and on a GPU
# node of a lab with serving on /models (ro, the models directory). When node.env sets MODELS_TAG
# and MODELS_MOUNT, /models is exported to the guest read-only over virtio-9p under that tag, and
# the seed carries a mount unit for MODELS_MOUNT with a kubelet drop-in that requires it, so the
# guest mounts the weights read-only before kubelet starts any pod. SFAB_DRY_RUN=1
# writes the seed tree under SFAB_VM_DIR and prints the QEMU command instead of touching devices
# (the tests use it).
set -euo pipefail

BOOT=${SFAB_BOOTSTRAP:-/sfab/bootstrap}
VM=${SFAB_VM_DIR:-/vm}
SHARED=${SFAB_SHARED:-/shared}
KEYS=${SFAB_AUTHORIZED_KEYS:-/sfab/authorized_keys}
BASE=${SFAB_BASE:-/base/node.qcow2}
FILES=${SFAB_NODE_FILES:-/opt/sfab/node-files}
LINK_WAIT_S=${SFAB_LINK_WAIT_S:-240}
DRY=${SFAB_DRY_RUN:-0}
MON=${SFAB_QEMU_MONITOR:-/run/sfab/qemu.mon}
MODELS=${SFAB_MODELS:-/models}
QPID=""
Q=()

log() { printf '[vm-init] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }
b64() { base64 < "$1" | tr -d '\n'; }

# NIC<kk>_<FIELD> from node.env, for container port eth<k>.
nicvar() {
  local v
  v=$(printf 'NIC%02d_%s' "$1" "$2")
  printf '%s' "${!v:-}"
}

# ------------------------------------------------------------------------------------------
load_env() {
  local f="$BOOT/node.env" v t
  [ -r "$f" ] || die "no $f: the topology binds bootstrap/<node>/ at $BOOT (run make render)"
  local -A topo=()
  for v in VM_MEMORY_MB VM_SMP VM_DISK_GIB VM_NICS VM_TX_OFF; do topo[$v]=${!v:-}; done
  t=${SFAB_NODE:-}
  set -a
  # shellcheck source=/dev/null
  . "$f"
  set +a
  for v in LAB NODE_NAME FQDN GUEST_USER MGMT_ADDR MGMT_GW MGMT_MAC MGMT_TABLE \
           VM_MEMORY_MB VM_SMP VM_DISK_GIB VM_NICS VM_UUID; do
    [ -n "${!v:-}" ] || die "node.env sets no $v"
  done
  if [ -n "$t" ] && [ "$t" != "$NODE_NAME" ]; then die "SFAB_NODE is $t but node.env is for $NODE_NAME"; fi
  for v in "${!topo[@]}"; do
    if [ -n "${topo[$v]}" ] && [ "${topo[$v]}" != "${!v:-}" ]; then
      log "warning: the topology sets $v=${topo[$v]}, node.env ${!v:-}; using node.env (re-render the lab)"
    fi
  done
  MGMT_IP=${MGMT_ADDR%/*}
}

# ------------------------------------------------------------------------------------------
hold() {
  local w=0 max=${HOLD_S:-3600} step=${HOLD_POLL_S:-5}
  while [ -f "$SHARED/hold-guests" ] && [ "$w" -lt "$max" ]; do
    if [ $((w % 120)) -eq 0 ]; then log "held by $SHARED/hold-guests for ${w}s"; fi
    sleep "$step"
    w=$((w + step))
  done
  if [ "$w" -ge "$max" ]; then log "hold not released after ${max}s: starting anyway"; fi
}

wait_links() {
  local i n missing=""
  for ((i = 0; i <= LINK_WAIT_S; i++)); do
    missing=""
    for n in eth0 $VM_NICS; do
      ip link show "$n" >/dev/null 2>&1 || missing="$missing $n"
    done
    if [ -z "$missing" ]; then return 0; fi
    sleep 1
  done
  die "links still missing after ${LINK_WAIT_S}s:$missing"
}

# How each data NIC reaches its tap: "bridge" (br<i>, the default) or "tc" (a tc mirred redirect
# both ways, as vrnetlab wires its own VMs). SFAB_NIC_LINK=tc forces tc for every data NIC.
NIC_LINK=${SFAB_NIC_LINK:-bridge}
declare -A LINKMODE=()

data_dev_prep() {  # data_dev_prep <dev> <tap> <mtu or empty>: no IPv6, MTU, TX checksum off
  local dev=$1 tap=$2 mtu=$3 d
  # No IPv6 on the container's own data devices: their link-local frames would put the
  # container's MACs in the switches' MAC tables.
  for d in "$dev" "$tap"; do echo 1 > "/proc/sys/net/ipv6/conf/$d/disable_ipv6" 2>/dev/null || true; done
  if [ -n "$mtu" ]; then
    for d in "$dev" "$tap"; do ip link set "$d" mtu "$mtu"; done
  fi
  if [ "${VM_TX_OFF:-1}" = 1 ]; then
    # TX checksum offload off on the container side (TCP fails silently on a routed path
    # otherwise). netsetup.sh does the same inside the guest.
    for d in "$dev" "$tap"; do ethtool -K "$d" tx off >/dev/null 2>&1 || log "warning: ethtool -K $d tx off failed"; done
  fi
}

# A two-port bridge must never learn: it is a wire. The switch pair floods a guest's own
# broadcasts back to it over its other bond leg (peer-link isolation is not enforced on the VM,
# known limit L1 in spec/known.yaml), so a learning bridge moved the guest's own MAC to the container side and then
# dropped every frame sent back to that MAC (the M1 deploy, dev/m1/RESULTS.md, problem 7).
no_learning() {  # no_learning <port>...: learning off on each bridge port; unknown frames flood
  local d
  for d in "$@"; do ip link set dev "$d" type bridge_slave learning off; done
}

tc_redirect() {  # tc_redirect <from> <to>: every frame arriving on <from> leaves on <to>
  tc qdisc del dev "$1" ingress >/dev/null 2>&1 || true
  tc qdisc add dev "$1" ingress
  tc filter add dev "$1" parent ffff: protocol all u32 match u8 0 0 action mirred egress redirect dev "$2"
}

# link_nic <index> <container dev> <mtu or empty> <data: 1|0>
link_nic() {
  local i=$1 dev=$2 mtu=$3 data=$4 br="br$1" tap="tap$1" d
  ip link show "$tap" >/dev/null 2>&1 || ip tuntap add dev "$tap" mode tap
  if [ "$data" = 1 ]; then data_dev_prep "$dev" "$tap" "$mtu"; fi
  if [ "$data" = 1 ] && [ "$NIC_LINK" = tc ]; then
    LINKMODE[$i]=tc
  else
    LINKMODE[$i]=bridge
    ip link show "$br" >/dev/null 2>&1 || ip link add "$br" type bridge
    echo 0 > "/sys/class/net/$br/bridge/multicast_snooping" 2>/dev/null || true
    if [ "$data" = 1 ]; then
      echo 1 > "/proc/sys/net/ipv6/conf/$br/disable_ipv6" 2>/dev/null || true
      # 0x4 passes 01:80:c2:00:00:02 (LACP), 0x4000 passes 01:80:c2:00:00:0e (LLDP); a Linux
      # bridge drops both by default. A stock kernel refuses bit 2 (it keeps 00 to 02 for
      # itself); a kernel that refuses it gets the tc redirect instead.
      if ! echo 0x4004 > "/sys/class/net/$br/bridge/group_fwd_mask" 2>/dev/null; then
        log "this kernel will not forward LACP through a bridge (group_fwd_mask 0x4004): $dev uses a tc redirect to $tap"
        ip link del "$br"
        LINKMODE[$i]=tc
      fi
    fi
  fi
  if [ "${LINKMODE[$i]}" = tc ]; then
    for d in "$tap" "$dev"; do ip link set "$d" up; done
    tc_redirect "$dev" "$tap"
    tc_redirect "$tap" "$dev"
    return 0
  fi
  ip link set "$tap" master "$br"
  ip link set "$dev" master "$br"
  no_learning "$tap" "$dev"
  if [ -n "$mtu" ]; then ip link set "$br" mtu "$mtu"; fi
  for d in "$tap" "$dev" "$br"; do ip link set "$d" up; done
}

wire() {
  local out cur n k
  out=$(ip -4 -o addr show dev eth0)
  cur=$(awk '{print $4; exit}' <<< "$out")
  if [ -n "$cur" ] && [ "$cur" != "$MGMT_ADDR" ]; then
    log "warning: the container's eth0 holds $cur, node.env says $MGMT_ADDR; the guest takes $MGMT_ADDR"
  fi
  ip addr flush dev eth0
  link_nic 0 eth0 "" 0
  for n in $VM_NICS; do
    k=${n#eth}
    link_nic "$k" "$n" "$(nicvar "$k" MTU)" 1
  done
  local modes=""
  for n in $VM_NICS; do modes="$modes ${n}:${LINKMODE[${n#eth}]}"; done
  log "wired eth0 (bridge) and the data NICs:$modes (tx off ${VM_TX_OFF:-1})"
}

# A container NIC re-created while the guest runs (a peer redeployed, relink.sh) comes back
# unwired, and the guest NIC would stay dark: every 5 s, wire each one again.
keep_links() {
  local n k mtu
  while sleep 5; do
    for n in $VM_NICS; do
      k=${n#eth}
      ip link show "$n" >/dev/null 2>&1 || continue
      if [ "${LINKMODE[$k]}" = tc ]; then
        [[ $(tc filter show dev "$n" parent ffff: 2>/dev/null) == *mirred* ]] && continue
      else
        [[ $(ip -o link show "$n") == *" master br$k "* ]] && continue
      fi
      mtu=$(nicvar "$k" MTU)
      data_dev_prep "$n" "tap$k" "$mtu" || true
      if [ "${LINKMODE[$k]}" = tc ]; then
        ip link set "$n" up || true
        if tc_redirect "$n" "tap$k"; then log "link keeper: $n was re-created, redirected to tap$k again"; fi
      elif ip link set "$n" master "br$k" && no_learning "$n" && ip link set "$n" up; then
        log "link keeper: $n was re-created, back in br$k"
      fi
    done
  done
}

# ------------------------------------------------------------------------------------------
disks() {
  local id have want size info
  [ -r "$BASE" ] || die "no base disk at $BASE: build the image with make -C images vm-node"
  if [ -r "${BASE%.qcow2}.id" ]; then id=$(head -1 "${BASE%.qcow2}.id"); else id=$(sha256 < "$BASE"); fi
  mkdir -p "$VM"
  if [ -f "$VM/root.qcow2" ]; then
    have=$(head -1 "$VM/base.id" 2>/dev/null || true)
    if [ "$have" != "$id" ]; then
      die "$VM/root.qcow2 was made from another base disk (${have:-unknown}, the image has $id): run make wipe, or remove state/nodes/$NODE_NAME"
    fi
  else
    qemu-img create -q -f qcow2 -b "$BASE" -F qcow2 "$VM/root.qcow2" "${VM_DISK_GIB}G"
    printf '%s\n' "$id" > "$VM/base.id"
    log "root disk created: ${VM_DISK_GIB}G overlay of $(basename "$BASE") ($id)"
  fi
  # Grow, never shrink: cloud-init's growpart extends the partition at the next boot. The text
  # form's first "virtual size:" line is the overlay's own; the JSON form also lists the child
  # file node's size, which comes first.
  want=$((VM_DISK_GIB * 1024 * 1024 * 1024))
  info=$(qemu-img info -U "$VM/root.qcow2")
  size=$(sed -n 's/^virtual size: .*(\([0-9]*\) bytes).*/\1/p' <<< "$info" | head -n 1)
  if [ -n "$size" ] && [ "$size" -lt "$want" ]; then
    qemu-img resize -q "$VM/root.qcow2" "${VM_DISK_GIB}G"
    log "root disk grown from $size to $want bytes"
  fi
}

# ------------------------------------------------------------------------------------------
# The seed. Files under sfab/root/ mirror their absolute paths in the guest; sfab/MANIFEST lists
# "sha256 mode owner path" for each, and seed-sync.sh installs any that differ at every boot.
SEED=""
MANIFEST=()

put_data() {  # put_data <content file> <guest path> <mode> <owner>
  local src=$1 path=$2 mode=$3 owner=$4 dst
  dst="$SEED/sfab/root$path"
  mkdir -p "$(dirname "$dst")"
  cp "$src" "$dst"
  MANIFEST+=("$(sha256 < "$dst") $mode $owner $path")
}

put_lines() {  # put_lines <guest path> <mode> <owner> <line>...
  local path=$1 mode=$2 owner=$3 tmp
  shift 3
  tmp=$(mktemp)
  printf '%s\n' "$@" > "$tmp"
  put_data "$tmp" "$path" "$mode" "$owner"
  rm -f "$tmp"
}

# models_unit: the mount unit's name for MODELS_MOUNT (systemd's path escaping, for the plain
# paths the render writes: /srv/models is srv-models.mount).
models_unit() {
  [[ ${MODELS_MOUNT:-} =~ ^(/[a-z0-9]+)+$ ]] || return 1
  local p=${MODELS_MOUNT#/}
  printf '%s.mount' "${p//\//-}"
}

yq() {  # a YAML double-quoted scalar
  local s=${1//\\/\\\\}
  printf '"%s"' "${s//\"/\\\"}"
}

seed() {
  local n k name mac mtu unmanaged="" keys=() line f host user_data
  SEED="$VM/seed"
  rm -rf "$SEED"
  mkdir -p "$SEED/sfab/root"
  MANIFEST=()

  put_data "$BOOT/node.env" /etc/sfab/node.env 0644 root:root
  put_data "$FILES/netsetup.sh" /opt/sfab/bin/netsetup.sh 0755 root:root
  put_data "$FILES/seed-sync.sh" /opt/sfab/bin/seed-sync.sh 0755 root:root
  put_data "$FILES/sfab-netsetup.service" /etc/systemd/system/sfab-netsetup.service 0644 root:root
  put_data "$FILES/networkd-foreign.conf" /etc/systemd/networkd.conf.d/10-sfab-foreign.conf 0644 root:root
  put_data "$FILES/lldpd.conf" /etc/lldpd.d/sfab.conf 0644 root:root

  # Guest NIC names by MAC (eth1, eth3, rail3 ...), with their MTU; networkd leaves them,
  # the bond and the relay alone (netsetup.sh owns them).
  for n in $VM_NICS; do
    k=${n#eth}
    name=$(nicvar "$k" NAME)
    mac=$(nicvar "$k" MAC)
    mtu=$(nicvar "$k" MTU)
    if [ -z "$name" ] || [ -z "$mac" ]; then die "node.env has no name or MAC for $n"; fi
    put_lines "/etc/systemd/network/10-sfab-$name.link" 0644 root:root \
      "[Match]" "MACAddress=$mac" "" "[Link]" "Name=$name" ${mtu:+"MTUBytes=$mtu"}
    unmanaged="$unmanaged $name"
  done
  if [ -n "${BOND_NAME:-}" ]; then
    unmanaged="$unmanaged $BOND_NAME"
    for k in ${BOND_VLANS:-}; do unmanaged="$unmanaged $BOND_NAME.$k"; done
  fi
  if [ -n "${RELAY_BRIDGE:-}" ]; then
    unmanaged="$unmanaged $RELAY_BRIDGE"
    for k in ${RAILS:-}; do f="RELAY${k}_PORT"; unmanaged="$unmanaged ${!f:-}"; done
  fi
  put_lines /etc/systemd/network/05-sfab-unmanaged.network 0644 root:root \
    "[Match]" "Name=${unmanaged# }" "" "[Link]" "Unmanaged=yes"

  if [ -r "$KEYS" ]; then
    while IFS= read -r line; do
      [[ $line =~ ^[[:space:]]*(#|$) ]] && continue
      keys+=("$line")
    done < "$KEYS"
    put_data "$KEYS" "/home/$GUEST_USER/.ssh/authorized_keys" 0600 "$GUEST_USER:$GUEST_USER"
  else
    log "warning: no $KEYS: SSH as $GUEST_USER will be refused (the console still works)"
  fi

  # The models share (MODELS_TAG, MODELS_MOUNT): a mount unit for the guest path, read-only 9p with
  # the page cache on (cache=loose: the files never change, and llama-server maps them), and a
  # kubelet drop-in that requires it, so no pod starts before the weights are there.
  if [ -n "${MODELS_TAG:-}" ]; then
    local unit
    unit=$(models_unit) || die "MODELS_MOUNT=${MODELS_MOUNT:-} is not an absolute path of lower-case words"
    put_lines "/etc/systemd/system/$unit" 0644 root:root \
      "[Unit]" "Description=sfab models share (read-only)" "" \
      "[Mount]" "What=$MODELS_TAG" "Where=$MODELS_MOUNT" "Type=9p" \
      "Options=trans=virtio,version=9p2000.L,ro,cache=loose" "DirectoryMode=0755"
    put_lines /etc/systemd/system/kubelet.service.d/20-sfab-models.conf 0644 root:root \
      "[Unit]" "RequiresMountsFor=$MODELS_MOUNT"
  fi

  # containerd registry mirrors rendered for this node, if any (bootstrap/<node>/containerd/<host>/hosts.toml).
  if [ -d "$BOOT/containerd" ]; then
    for f in "$BOOT"/containerd/*/hosts.toml; do
      [ -f "$f" ] || continue
      host=$(basename "$(dirname "$f")")
      put_data "$f" "/etc/containerd/certs.d/$host/hosts.toml" 0644 root:root
    done
  fi

  # A Kubernetes node's cluster files (render/k8s.py: bootstrap/<node>/k8s/, with cluster.env naming
  # the role), its bootstrap script and the unit that runs it. seed-sync.sh enables the unit the
  # first time it installs it, so every boot runs the bootstrap after sfab-netsetup.service.
  if [ -f "$BOOT/k8s/cluster.env" ]; then
    for f in "$BOOT"/k8s/*; do
      [ -f "$f" ] || continue
      put_data "$f" "/etc/sfab/k8s/$(basename "$f")" 0644 root:root
    done
    put_data "$FILES/cluster-bootstrap.sh" /opt/sfab/bin/cluster-bootstrap.sh 0755 root:root
    put_data "$FILES/sfab-cluster.service" /etc/systemd/system/sfab-cluster.service 0644 root:root
  fi

  printf '%s\n' "${MANIFEST[@]}" | LC_ALL=C sort -k4 > "$SEED/sfab/MANIFEST"

  printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "$LAB" "$NODE_NAME" "$NODE_NAME" > "$SEED/meta-data"

  # Management: networkd keeps eth0's default in table MGMT_TABLE with a rule for the management
  # address, so the main table never holds a management default (Cilium flushes table 200).
  cat > "$SEED/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match: {macaddress: "$MGMT_MAC"}
    set-name: eth0
    addresses: ["$MGMT_ADDR"]
    routes:
      - {to: default, via: "$MGMT_GW", table: $MGMT_TABLE}
    routing-policy:
      - {from: "$MGMT_IP", table: $MGMT_TABLE}
EOF

  user_data="$SEED/user-data"
  {
    printf '#cloud-config\n'
    printf 'hostname: %s\nfqdn: %s\nprefer_fqdn_over_hostname: false\nmanage_etc_hosts: true\n' "$NODE_NAME" "$FQDN"
    printf 'ssh_pwauth: false\ndisable_root: true\npackage_update: false\npackage_upgrade: false\n'
    # The user's own group as its primary group, made when missing: Ubuntu's cloud image already
    # holds a group admin, and useradd refuses to make a group of the user's name that exists.
    printf 'users:\n  - name: %s\n    gecos: lab operator\n    shell: /bin/bash\n    lock_passwd: true\n' "$GUEST_USER"
    printf '    primary_group: %s\n    groups: [%s]\n' "$GUEST_USER" "$GUEST_USER"
    printf '    sudo: "ALL=(ALL) NOPASSWD:ALL"\n'
    printf '    ssh_authorized_keys:'
    if [ "${#keys[@]}" -eq 0 ]; then printf ' []\n'; else
      printf '\n'
      for line in "${keys[@]}"; do printf '      - %s\n' "$(yq "$line")"; done
    fi
    printf 'mounts:\n  - [shared, /shared, 9p, "trans=virtio,version=9p2000.L,rw,nofail", "0", "0"]\n'
    printf 'write_files:\n'
    printf '  - {path: /opt/sfab/bin/seed-sync.sh, permissions: "0755", encoding: b64, content: "%s"}\n' "$(b64 "$FILES/seed-sync.sh")"
    printf '  - {path: /etc/systemd/system/sfab-netsetup.service, permissions: "0644", encoding: b64, content: "%s"}\n' "$(b64 "$FILES/sfab-netsetup.service")"
    printf 'runcmd:\n  - [systemctl, daemon-reload]\n  - [systemctl, enable, --now, sfab-netsetup.service]\n'
  } > "$user_data"

  if command -v genisoimage >/dev/null 2>&1; then
    genisoimage -quiet -output "$VM/seed.iso.tmp" -volid cidata -joliet -rational-rock "$SEED"
    mv "$VM/seed.iso.tmp" "$VM/seed.iso"
  elif [ "$DRY" != 1 ]; then
    die "genisoimage is not installed"
  fi
  log "seed: ${#MANIFEST[@]} node files, $([ "${#keys[@]}" -gt 0 ] && echo "${#keys[@]} key(s)" || echo "no key")"
}

# ------------------------------------------------------------------------------------------
qemu_cmd() {
  local n k mac
  Q=(qemu-system-x86_64 -name "$NODE_NAME" -uuid "$VM_UUID"
     -machine "q35,accel=kvm" -cpu host -smp "$VM_SMP" -m "$VM_MEMORY_MB"
     -nodefaults -no-user-config -display none -rtc "base=utc"
     -serial "file:$VM/console.log" -monitor "unix:$MON,server,nowait"
     -drive "file=$VM/root.qcow2,if=virtio,format=qcow2,cache=writeback,discard=unmap"
     -drive "file=$VM/seed.iso,if=virtio,format=raw,readonly=on"
     -fsdev "local,id=fs0,path=$SHARED,security_model=none" -device "virtio-9p-pci,fsdev=fs0,mount_tag=shared")
  if [ -n "${MODELS_TAG:-}" ]; then
    Q+=(-fsdev "local,id=fs1,path=$MODELS,security_model=none,readonly=on" -device "virtio-9p-pci,fsdev=fs1,mount_tag=$MODELS_TAG")
  fi
  Q+=(
     -object "rng-random,id=rng0,filename=/dev/urandom" -device "virtio-rng-pci,rng=rng0"
     -netdev "tap,id=n0,ifname=tap0,script=no,downscript=no" -device "virtio-net-pci,netdev=n0,mac=$MGMT_MAC,romfile=")
  for n in $VM_NICS; do
    k=${n#eth}
    mac=$(nicvar "$k" MAC)
    # 802.3ad needs a speed and duplex, and virtio reports neither unless told. No option ROM:
    # the guest boots from its disk, never from the network.
    Q+=(-netdev "tap,id=n$k,ifname=tap$k,script=no,downscript=no"
        -device "virtio-net-pci,netdev=n$k,mac=$mac,speed=${NIC_SPEED:-10000},duplex=full,romfile=")
  done
}

on_term() {
  if [ -z "$QPID" ]; then
    log "stopped before the guest started"
    exit 0
  fi
  log "stop requested: pressing the guest's power button"
  printf 'system_powerdown\n' | socat - "UNIX-CONNECT:$MON" >/dev/null 2>&1 || kill -TERM "$QPID" 2>/dev/null || true
}

# ------------------------------------------------------------------------------------------
main() {
  local rc=0
  load_env
  log "guest $NODE_NAME ($LAB): ${VM_SMP} vCPU, ${VM_MEMORY_MB} MiB, ${VM_DISK_GIB}G, NICs eth0 $VM_NICS"
  if [ "$DRY" = 1 ]; then
    mkdir -p "$VM"
    seed
    qemu_cmd
    printf '+'; printf ' %s' "${Q[@]}"; printf '\n'
    return 0
  fi
  [ -c /dev/kvm ] || die "no /dev/kvm in the container (the topology sets devices: [/dev/kvm, /dev/net/tun])"
  [ -c /dev/net/tun ] || die "no /dev/net/tun in the container"
  if [ -n "${MODELS_TAG:-}" ] && [ ! -d "$MODELS" ]; then
    die "node.env exports the models share ($MODELS_TAG) but $MODELS is not a directory (the topology binds the models directory there)"
  fi
  trap on_term TERM INT
  mkdir -p "$SHARED" "$(dirname "$MON")"
  hold
  log "waiting for links (at most ${LINK_WAIT_S}s)"
  wait_links
  wire
  disks
  seed
  qemu_cmd
  if [ -f "$VM/console.log" ]; then mv -f "$VM/console.log" "$VM/console.log.1"; fi
  keep_links &
  log "booting the guest (console in $VM/console.log)"
  "${Q[@]}" &
  QPID=$!
  while :; do
    wait "$QPID" && rc=0 || rc=$?
    kill -0 "$QPID" 2>/dev/null || break
  done
  log "guest exited ($rc)"
  exit "$rc"
}

main "$@"
