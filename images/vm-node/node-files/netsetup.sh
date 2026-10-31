#!/usr/bin/env bash
# netsetup.sh: the network of an sfab VM guest, built from /etc/sfab/node.env (rendered by
# render/host.py). sfab-netsetup.service runs it once per boot, after seed-sync.sh has brought
# node.env and this file up to date; node-sync may run it again live. Idempotent.
#
#   eth0         management (networkd): its default sits in table MGMT_TABLE (150), reached by a
#                rule for the management address, so the main table holds no management default
#   bond0        802.3ad over the bond members to the MCLAG pair, lacp_rate fast, layer3+4 hash,
#                MTU 9000; the node address and the main default route via the VLAN's gateway
#   BOND_VLANS   the bond's tagged units (bond0.120, bond0.110): each holds VLAN<id>_ADDR at
#                VLAN<id>_MTU; a unit with VLAN<id>_TABLE also sends what is sourced from its
#                segment (VLAN<id>_PREFIX) out of itself by that table, via VLAN<id>_GW
#   OOB_IF       the out-of-band (BMC) NIC. With OOB_NETNS (the BMC stand-in) the NIC moves into that
#                namespace with the BMC address and a default route via OOB_GW, and the host OS
#                keeps no address on the BMC VLAN; the namespace answers SSH (its own sshd) and
#                HTTPS (a listener standing in for Redfish) as OOB_SERVICES names. Without it the
#                address answers only from table OOB_TABLE (100), and the main table has no route to
#                the out-of-band subnet, so a data-side packet to it crosses the firewall
#   rails, relay (build A) the rail NICs carry no address; namespace gpuR holds rail R's address
#                on a macvlan, and a veth to the relay bridge; a route to every other rail goes
#                via that rail's namespace with the source pinned to the namespace's own rail
#                address; no default route; ip_forward on and rp_filter loose (RELAY_RP_FILTER)
#   rails, routed (build B) the address on the rail NIC, and traffic sourced from it leaves on
#                that rail through table RAIL<r>_TABLE (300 + r)
#
# TX checksum offload is turned off on every data NIC (VM_TX_OFF=1); vm-init.sh does the same on
# the container side. SFAB_DRY_RUN=1 prints every change instead of making it, as if nothing
# existed yet (the tests read that output); SFAB_NODE_ENV names another env file.
set -euo pipefail

ENV_FILE=${SFAB_NODE_ENV:-/etc/sfab/node.env}
DRY=${SFAB_DRY_RUN:-0}

log() { printf '[netsetup] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }

# Every change goes through run (stops the script on failure) or try (best effort). The queries
# below answer "nothing exists" in a dry run, so a dry run prints the whole build.
run() { if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }
try() {
  if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; return 0; fi
  "$@" >/dev/null 2>&1 || log "warning: failed: $*"
}
link_exists() { [ "$DRY" != 1 ] && ip link show "$1" >/dev/null 2>&1; }
ns_exists() { [ "$DRY" != 1 ] && [ -e "/run/netns/$1" ]; }
ns_link_exists() { [ "$DRY" != 1 ] && ip -n "$1" link show "$2" >/dev/null 2>&1; }
rule_exists() {  # rule_exists <from address> <table>
  [ "$DRY" != 1 ] || return 1
  ip -4 rule show | awk -v f="$1" -v t="$2" '$2 == "from" && $3 == f && $4 == "lookup" && $5 == t {ok = 1} END {exit !ok}'
}
route_exists() {  # route_exists <table> <dest> [dev]
  [ "$DRY" != 1 ] || return 1
  local out
  out=$(ip -4 route show table "$1" "$2" ${3:+dev "$3"} 2>/dev/null) || return 1
  [ -n "$out" ]
}
sysfs() { if [ "$DRY" != 1 ]; then cat "$1" 2>/dev/null || true; fi; }
tx_off() {  # tx_off [ip netns exec <ns>] <dev>
  if [ "${VM_TX_OFF:-1}" = 1 ]; then try "${@:1:$#-1}" ethtool -K "${!#}" tx off; fi
}

nicvar() {
  local v
  v=$(printf 'NIC%02d_%s' "$1" "$2")
  printf '%s' "${!v:-}"
}

net_of() {  # net_of 10.20.9.21/24 -> 10.20.9.0/24
  local ip=${1%/*} len=${1#*/} a b c d n mask
  IFS=. read -r a b c d <<< "$ip"
  n=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  mask=$(( len == 0 ? 0 : (0xffffffff << (32 - len)) & 0xffffffff ))
  n=$(( n & mask ))
  printf '%d.%d.%d.%d/%d' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 )) "$len"
}

perm_mac() {  # the NIC's permanent MAC (a bond member's current MAC is the bond's)
  local o
  o=$(ethtool -P "$1" 2>/dev/null) || return 0
  printf '%s' "${o##* }"
}

dev_by_mac() {  # the PCI NIC whose permanent MAC is $1
  local d m
  for d in /sys/class/net/*; do
    [ -e "$d/device" ] || continue
    m=$(perm_mac "${d##*/}")
    if [ "${m,,}" = "${1,,}" ]; then printf '%s' "${d##*/}"; return 0; fi
  done
}

# ------------------------------------------------------------------------------------------
load() {
  [ -r "$ENV_FILE" ] || die "no $ENV_FILE"
  set -a
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  set +a
  local v
  for v in NODE_NAME MGMT_IF MGMT_ADDR MGMT_GW MGMT_TABLE VM_NICS; do
    [ -n "${!v:-}" ] || die "$ENV_FILE sets no $v"
  done
}

# The guest's .link files name the NICs by MAC from the second boot on; the first boot, and a
# NIC udev left alone, are named here.
name_nics() {
  local n k name mac cur
  for n in $VM_NICS; do
    k=${n#eth}
    name=$(nicvar "$k" NAME)
    mac=$(nicvar "$k" MAC)
    if [ "$DRY" = 1 ]; then printf '+ ip link set <nic %s> name %s\n' "$mac" "$name"; continue; fi
    if [ -n "${OOB_NETNS:-}" ] && [ "$name" = "${OOB_IF:-}" ] && ns_link_exists "$OOB_NETNS" "$name"; then continue; fi
    cur=$(dev_by_mac "$mac")
    if [ "$cur" = "$name" ]; then continue; fi
    if [ -z "$cur" ]; then log "warning: no NIC has MAC $mac (wanted as $name)"; continue; fi
    if link_exists "$name"; then
      run ip link set "$name" down
      run ip link set "$name" name "sfx$k"
    fi
    run ip link set "$cur" down
    run ip link set "$cur" name "$name"
    log "renamed $cur ($mac) to $name"
  done
}

# ------------------------------------------------------------------------------------------
bond() {
  [ -n "${BOND_NAME:-}" ] || return 0
  local b=$BOND_NAME m mode o cur
  for m in $BOND_MEMBERS; do
    try ethtool -s "$m" speed "${NIC_SPEED:-10000}" duplex full autoneg off
  done
  if link_exists "$b"; then
    mode=$(sysfs "/sys/class/net/$b/bonding/mode")
    if [ "${mode%% *}" != "$BOND_MODE" ]; then
      log "$b is in mode ${mode%% *}, want $BOND_MODE: rebuilding it"
      run ip link del "$b"
    fi
  fi
  if ! link_exists "$b"; then
    run ip link add "$b" type bond mode "$BOND_MODE" lacp_rate "$BOND_LACP_RATE" \
      miimon "$BOND_MIIMON" xmit_hash_policy "$BOND_HASH"
    # udev handles the new bond's add event on its own time and, under 99-default.link's
    # MACAddressPolicy=persistent, gives it a MAC of its own: let it finish before the rendered MAC
    # is set, or udev's MAC can land after it (seen once on a first boot: every member and the
    # VLAN unit then carried udev's MAC, not BOND_MAC)
    if [ "$DRY" != 1 ]; then udevadm settle --timeout=10 >/dev/null 2>&1 || log "warning: udevadm settle timed out"; fi
  else
    # Options that change live on an existing bond (sysfs prints "fast 1", "layer3+4 1", "100").
    for o in "lacp_rate $BOND_LACP_RATE" "xmit_hash_policy $BOND_HASH" "miimon $BOND_MIIMON"; do
      cur=$(sysfs "/sys/class/net/$b/bonding/${o%% *}")
      [ "${cur%% *}" = "${o#* }" ] || run ip link set "$b" type bond "${o%% *}" "${o#* }"
    done
  fi
  if [ -n "${BOND_MAC:-}" ] && [ "$(sysfs "/sys/class/net/$b/address")" != "$BOND_MAC" ]; then
    run ip link set "$b" address "$BOND_MAC"
  fi
  for m in $BOND_MEMBERS; do
    if [ "$DRY" = 1 ] || [ "$(basename "$(readlink "/sys/class/net/$m/master" 2>/dev/null || echo none)")" != "$b" ]; then
      run ip link set "$m" down
      run ip link set "$m" master "$b"
    fi
  done
  run ip link set "$b" mtu "${BOND_MTU:-9000}"
  for m in $BOND_MEMBERS; do
    tx_off "$m"
    run ip link set "$m" up
  done
  tx_off "$b"
  run ip link set "$b" up
  run ip addr replace "$BOND_ADDR" dev "$b"
  if [ -n "${BOND_GW:-}" ]; then run ip route replace default via "$BOND_GW" dev "$b"; fi
  # and the MAC read back once the bond is up: anything that changed it after the set above is undone
  if [ -n "${BOND_MAC:-}" ] && [ "$DRY" != 1 ] && [ "$(sysfs "/sys/class/net/$b/address")" != "$BOND_MAC" ]; then
    log "warning: $b carries $(sysfs "/sys/class/net/$b/address"), not $BOND_MAC: setting it again"
    run ip link set "$b" address "$BOND_MAC"
  fi
  log "$b ($BOND_MODE, lacp_rate $BOND_LACP_RATE, $BOND_HASH) over $BOND_MEMBERS: $BOND_ADDR via ${BOND_GW:-none}"
}

vlans() {
  [ -n "${BOND_VLANS:-}" ] || return 0
  local b=$BOND_NAME v d a m t pfx gw ip
  for v in $BOND_VLANS; do
    d="$b.$v"
    a=$(envvar "VLAN${v}_ADDR"); m=$(envvar "VLAN${v}_MTU"); t=$(envvar "VLAN${v}_TABLE")
    pfx=$(envvar "VLAN${v}_PREFIX"); gw=$(envvar "VLAN${v}_GW")
    [ -n "$a" ] || die "VLAN${v}_ADDR is not set"
    ip=${a%/*}
    link_exists "$d" || run ip link add link "$b" name "$d" type vlan id "$v"
    # the unit's name holds a dot: sysctl takes the slash form of the key for it
    run sysctl -qw "net/ipv6/conf/$d/disable_ipv6=1"
    run ip link set "$d" mtu "${m:-1500}"
    tx_off "$d"
    run ip link set "$d" up
    run ip addr replace "$a" dev "$d"
    run sysctl -qw "net/ipv4/conf/$d/rp_filter=0"
    if [ -n "$t" ]; then
      run ip route replace "$pfx" dev "$d" src "$ip" table "$t"
      if [ -n "$gw" ]; then run ip route replace default via "$gw" dev "$d" table "$t"; fi
      rule_exists "$pfx" "$t" || run ip rule add from "$pfx" lookup "$t"
      log "$d: $a (mtu ${m:-1500}); traffic from $pfx leaves by table $t via ${gw:-none}"
    else
      log "$d: $a (mtu ${m:-1500})"
    fi
  done
}

envvar() { local v=$1; printf '%s' "${!v:-}"; }

# ------------------------------------------------------------------------------------------
mgmt() {
  local ip=${MGMT_ADDR%/*} t=$MGMT_TABLE net
  net=$(net_of "$MGMT_ADDR")
  run ip route replace "$net" dev "$MGMT_IF" src "$ip" table "$t"
  run ip route replace default via "$MGMT_GW" dev "$MGMT_IF" table "$t"
  rule_exists "$ip" "$t" || run ip rule add from "$ip" lookup "$t"
  if route_exists main default "$MGMT_IF"; then run ip route del default dev "$MGMT_IF" table main; fi
  log "management $MGMT_ADDR on $MGMT_IF: default via $MGMT_GW in table $t"
}

# The BMC stand-in's HTTPS: a listener that accepts and closes (nothing is served), standing in
# for a Redfish service, so a connect the firewall allows opens.
BMC_HTTPS_PY='import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 443))
s.listen(16)
while True:
    c, _ = s.accept()
    c.close()'

bmc_ns() {
  local ns=$OOB_NETNS ip=${OOB_ADDR%/*} svc pidf
  ns_exists "$ns" || run ip netns add "$ns"
  run ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
  if link_exists "$OOB_IF"; then
    run ip link set "$OOB_IF" down
    run ip link set "$OOB_IF" netns "$ns"
  fi
  run ip -n "$ns" link set lo up
  tx_off ip netns exec "$ns" "$OOB_IF"
  run ip -n "$ns" link set "$OOB_IF" up
  run ip -n "$ns" addr replace "$OOB_ADDR" dev "$OOB_IF"
  if [ -n "${OOB_GW:-}" ]; then run ip -n "$ns" route replace default via "$OOB_GW" dev "$OOB_IF"; fi
  # the host OS's own table and rule for the BMC address, left from a boot before the namespace
  if rule_exists "$ip" "$OOB_TABLE"; then run ip rule del from "$ip" lookup "$OOB_TABLE"; fi
  for svc in ${OOB_SERVICES:-}; do
    case $svc in
      ssh)
        pidf=/run/sfab-bmc-sshd.pid
        if [ "$DRY" = 1 ]; then printf '+ ip netns exec %s sshd on %s:22\n' "$ns" "$ip"; continue; fi
        if [ -s "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then continue; fi
        mkdir -p /run/sshd
        ip netns exec "$ns" /usr/sbin/sshd -o "ListenAddress=$ip" -o "PidFile=$pidf" || log "warning: the BMC namespace's sshd did not start"
        ;;
      https)
        pidf=/run/sfab-bmc-https.pid
        if [ "$DRY" = 1 ]; then printf '+ ip netns exec %s listener on %s:443\n' "$ns" "$ip"; continue; fi
        if [ -s "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then continue; fi
        ip netns exec "$ns" setsid python3 -c "$BMC_HTTPS_PY" >/dev/null 2>&1 < /dev/null &
        echo $! > "$pidf"
        ;;
      *) log "warning: unknown BMC service $svc" ;;
    esac
  done
  log "BMC stand-in: $OOB_IF in namespace $ns, $OOB_ADDR via ${OOB_GW:-none}, answering ${OOB_SERVICES:-nothing}; no BMC address in the host OS"
}

oob() {
  [ -n "${OOB_IF:-}" ] || return 0
  if [ -n "${OOB_NETNS:-}" ]; then bmc_ns; return; fi
  local ip=${OOB_ADDR%/*} t=$OOB_TABLE net
  net=$(net_of "$OOB_ADDR")
  tx_off "$OOB_IF"
  run ip link set "$OOB_IF" up
  run ip addr replace "$OOB_ADDR" dev "$OOB_IF" noprefixroute
  if route_exists main "$net" "$OOB_IF"; then run ip route del "$net" dev "$OOB_IF" table main; fi
  run ip route replace "$net" dev "$OOB_IF" src "$ip" table "$t"
  if [ -n "${OOB_GW:-}" ]; then run ip route replace default via "$OOB_GW" dev "$OOB_IF" table "$t"; fi
  rule_exists "$ip" "$t" || run ip rule add from "$ip" lookup "$t"
  run sysctl -qw "net.ipv4.conf.$OOB_IF.rp_filter=0"
  log "out-of-band $OOB_ADDR on $OOB_IF: table $t via ${OOB_GW:-none}; no route to $net in main"
}

# ------------------------------------------------------------------------------------------
rail_nic() {  # rail_nic <dev>: jumbo, no IPv6, TX off, up
  run sysctl -qw "net.ipv6.conf.$1.disable_ipv6=1"
  run ip link set "$1" mtu "$RAIL_MTU"
  tx_off "$1"
  run ip link set "$1" up
}

relay() {
  local br=$RELAY_BRIDGE mtu=$RELAY_MTU rp=$RELAY_RP_FILTER fwd=$RELAY_IP_FORWARD
  local r v dev ns mv mac veth port raddr laddr rt dest via rdev src want d cur
  for r in $RAILS; do
    v="RAIL${r}_IF"; dev=${!v}
    rail_nic "$dev"
    run ip addr flush dev "$dev" scope global
  done
  link_exists "$br" || run ip link add "$br" type bridge
  run sysctl -qw "net.ipv6.conf.$br.disable_ipv6=1"
  try sh -c "echo 0 > /sys/class/net/$br/bridge/multicast_snooping"
  run ip link set "$br" mtu "$mtu" up
  for r in $RAILS; do
    v="RAIL${r}_IF"; dev=${!v}
    v="RAIL${r}_ADDR"; raddr=${!v}
    v="RELAY${r}_NS"; ns=${!v}
    v="RELAY${r}_MACVLAN"; mv=${!v}
    v="RELAY${r}_MACVLAN_MAC"; mac=${!v}
    v="RELAY${r}_VETH"; veth=${!v}
    v="RELAY${r}_PORT"; port=${!v}
    v="RELAY${r}_ADDR"; laddr=${!v}
    v="RELAY${r}_ROUTES"; rt=${!v:-}
    ns_exists "$ns" || run ip netns add "$ns"
    # IPv6 off before any device enters the namespace, so none sends a link-local frame.
    run ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
    if ! ns_link_exists "$ns" "$mv"; then
      # The macvlan is made under a temporary name (its final name is its lower NIC's).
      link_exists "sfmv$r" && run ip link del "sfmv$r"
      run ip link add link "$dev" name "sfmv$r" address "$mac" type macvlan mode bridge
      run ip link set "sfmv$r" netns "$ns"
      run ip -n "$ns" link set "sfmv$r" name "$mv"
    elif [ "$DRY" != 1 ]; then
      cur=$(ip -n "$ns" -o link show "$mv")
      if [[ $cur != *"link/ether $mac "* ]]; then run ip -n "$ns" link set "$mv" address "$mac"; fi
    fi
    if ! ns_link_exists "$ns" "$veth"; then
      link_exists "$port" && run ip link del "$port"
      run ip link add "$port" type veth peer name "$veth" netns "$ns"
    fi
    run sysctl -qw "net.ipv6.conf.$port.disable_ipv6=1"
    tx_off "$port"
    run ip link set "$port" master "$br" mtu "$mtu" up
    run ip -n "$ns" link set lo up
    run ip -n "$ns" link set "$mv" mtu "$mtu" up
    run ip -n "$ns" addr replace "$raddr" dev "$mv"
    run ip -n "$ns" link set "$veth" mtu "$mtu" up
    run ip -n "$ns" addr replace "$laddr" dev "$veth"
    run ip netns exec "$ns" sysctl -qw "net.ipv4.ip_forward=$fwd" "net.ipv4.conf.all.rp_filter=$rp" \
      "net.ipv4.conf.default.rp_filter=$rp" "net.ipv4.conf.$mv.rp_filter=$rp" "net.ipv4.conf.$veth.rp_filter=$rp"
    tx_off ip netns exec "$ns" "$mv"
    tx_off ip netns exec "$ns" "$veth"
    want=""
    for d in $rt; do
      IFS=, read -r dest via rdev src <<< "$d"
      run ip -n "$ns" route replace "$dest" ${via:+via "$via"} ${rdev:+dev "$rdev"} ${src:+src "$src"}
      want="$want $dest"
    done
    # Nothing else: no default route and no route the render no longer lists.
    if [ "$DRY" != 1 ]; then
      while read -r d; do
        [ -n "$d" ] || continue
        [[ " $want " == *" $d "* ]] || run ip -n "$ns" route del "$d"
      done < <(ip -n "$ns" -4 route show | awk '$1 == "default" || / via / {print $1}')
    fi
  done
  log "relay: $br and namespaces $(for r in $RAILS; do v="RELAY${r}_NS"; printf '%s ' "${!v}"; done)(rp_filter $rp, no default route)"
}

routed() {
  local r v dev addr ip t gw net
  for r in $RAILS; do
    v="RAIL${r}_IF"; dev=${!v}
    v="RAIL${r}_ADDR"; addr=${!v}
    v="RAIL${r}_TABLE"; t=${!v}
    v="RAIL${r}_GW"; gw=${!v:-}
    ip=${addr%/*}
    net=$(net_of "$addr")
    rail_nic "$dev"
    run ip addr replace "$addr" dev "$dev"
    run ip route replace "$net" dev "$dev" src "$ip" table "$t"
    if [ -n "$gw" ]; then run ip route replace default via "$gw" dev "$dev" table "$t"; fi
    rule_exists "$ip" "$t" || run ip rule add from "$ip" lookup "$t"
    # Eight NICs in one host: each answers ARP only for its own address.
    run sysctl -qw "net.ipv4.conf.$dev.arp_ignore=1" "net.ipv4.conf.$dev.arp_announce=2" "net.ipv4.conf.$dev.rp_filter=0"
  done
  log "routed rails: $RAILS (tables ${RAIL1_TABLE:-?} on)"
}

rails() {
  [ -n "${RAILS:-}" ] || return 0
  case "${RAIL_MODE:-}" in
    relay) relay ;;
    routed) routed ;;
    *) die "RAIL_MODE is ${RAIL_MODE:-unset}, want relay or routed" ;;
  esac
}

# ------------------------------------------------------------------------------------------
host_sysctls() {
  # Forwarding for the cluster; rp_filter off for the VIPs that live on the bond; src_valid_mark
  # 0, since a host VPN client that sets it to 1 leaks into new namespaces and makes Cilium drop
  # Gateway clients as martians.
  run sysctl -qw net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 "net.ipv4.conf.$MGMT_IF.rp_filter=0" \
    net.ipv4.conf.all.src_valid_mark=0 net.ipv4.conf.default.src_valid_mark=0
  if [ -n "${BOND_NAME:-}" ]; then
    run sysctl -qw "net.ipv4.conf.$BOND_NAME.rp_filter=0" "net.ipv4.conf.$BOND_NAME.src_valid_mark=0"
  fi
}

storage_clients() {
  try modprobe nvme_tcp
  try modprobe iscsi_tcp
  run mkdir -p /run/lock/iscsi
  if [ -n "${ISCSI_IQN:-}" ]; then
    local want="InitiatorName=$ISCSI_IQN"
    if [ "$DRY" = 1 ] || [ "$(cat /etc/iscsi/initiatorname.iscsi 2>/dev/null || true)" != "$want" ]; then
      run mkdir -p /etc/iscsi
      if [ "$DRY" = 1 ]; then printf '+ write /etc/iscsi/initiatorname.iscsi: %s\n' "$want"
      else printf '%s\n' "$want" > /etc/iscsi/initiatorname.iscsi; try systemctl try-restart iscsid; fi
    fi
  fi
}

write_if_changed() {  # write_if_changed <path> <content>
  if [ "$DRY" = 1 ]; then printf '+ write %s\n' "$1"; return 0; fi
  if [ "$(cat "$1" 2>/dev/null || true)" != "$2" ]; then
    mkdir -p "$(dirname "$1")"
    rm -f "$1"
    printf '%s\n' "$2" > "$1"
    return 0
  fi
  return 1
}

names() {
  local s="" n a h
  if [ -n "${DNS_SERVERS:-}" ]; then
    s="search ${SEARCH:-$DOMAIN}"
    for n in $DNS_SERVERS; do s="$s"$'\n'"nameserver $n"; done
    if [ -n "${RESOLV_OPTIONS:-}" ]; then s="$s"$'\n'"options $RESOLV_OPTIONS"; fi
    write_if_changed /etc/resolv.conf "$s" || true
  fi
  if [ -n "${NTP_SERVERS:-}" ]; then
    if write_if_changed /etc/systemd/timesyncd.conf.d/sfab.conf "$(printf '[Time]\nNTP=%s' "$NTP_SERVERS")"; then
      try systemctl restart systemd-timesyncd
    fi
  fi
  for h in ${HOSTS:-}; do
    a=${h%%,*}
    n=${h#*,}
    if [ "$DRY" = 1 ]; then printf '+ hosts %s %s\n' "$a" "$n"; continue; fi
    grep -qE "^${a//./\\.}[[:space:]]+${n//./\\.}([[:space:]]|$)" /etc/hosts || printf '%s %s\n' "$a" "$n" >> /etc/hosts
  done
}

# Ubuntu 24.04 starts sshd through ssh.socket, which refuses connections during the handover to
# the service, and can leave a listener outside the unit that holds port 22. Every harness reaches
# the guests over SSH, so: the plain service, always listening, repaired when it is not.
ssh_service() {
  if [ "$DRY" = 1 ]; then printf '+ sshd: ssh.service listening, ssh.socket off\n'; return 0; fi
  if [ "$(systemctl is-enabled ssh.socket 2>/dev/null || true)" = enabled ]; then
    try systemctl disable --now ssh.socket
    try systemctl enable ssh.service
  fi
  local main pids p
  main=$(systemctl show -p MainPID --value ssh.service 2>/dev/null || echo 0)
  pids=$(ss -ltnpH 'sport = :22' 2>/dev/null | grep -o 'pid=[0-9]*' | cut -d= -f2 | sort -u | tr '\n' ' ' || true)
  if ! systemctl is-active --quiet ssh.service || [ "${pids%% *}" != "$main" ]; then
    try systemctl stop ssh.service
    for p in $pids; do kill "$p" 2>/dev/null || true; done
    sleep 1
    try systemctl reset-failed ssh.service
    try systemctl start ssh.service
    log "sshd restarted: $(systemctl is-active ssh.service 2>/dev/null || true)"
  fi
}

main() {
  load
  log "node $NODE_NAME ($LAB)"
  name_nics
  bond
  vlans
  mgmt
  oob
  rails
  host_sysctls
  storage_clients
  names
  ssh_service
  log "done"
}

main "$@"
