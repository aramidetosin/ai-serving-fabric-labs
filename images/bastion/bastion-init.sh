#!/usr/bin/env bash
# bastion-init.sh: PID 1 of sfab/bastion, the lab's jump host (it gives access
# and nothing else; it serves no DNS, no time and no CA, has no leg in the BMC VLAN and holds no
# standing cluster-admin credential). It builds the bastion from the bound render (/sfab/bootstrap,
# which is bootstrap/<bastion>/ in the lab) and then stays, keeping sshd and lldpd up, until docker
# stops it.
#
#   network   IPv6 off from the first instant (the switches must never learn a container MAC
#             from a router solicitation); resolv.conf, before it waits for anything, as
#             sfab/client's init.sh writes it (the search line is always SEARCH, the lab's
#             domain, never the one Docker copied from the lab host's file); waits up to
#             LINK_WAIT seconds for its links; the 802.3ad bond to the MCLAG pair (BOND_*) with
#             the bastion's address and the default route via the firewall (GATEWAY on
#             GATEWAY_DEV); an out-of-band NIC (OOB_*) only when the render names one (build A's
#             bastion has none); the management default in table MGMT_TABLE
#             (150) behind a rule for the management address, so main holds no management
#             default; TX checksum offload off on every data NIC (TX_OFF) and the bond. Its
#             resolvers are the lab's (DNS_SERVERS: dns-res1 and dns-res2).
#   ssh       sshd, key-only: the keys bound at /sfab/authorized_keys (the lab key and the
#             deploying user's own), for the operator user (GUEST_USER, else admin), no root
#             login, no password.
#   lldp      lldpd on the data NICs, never the management network; the bond members send from
#             their own MACs.
#   ca        the lab root CA (CA_ROOT: /shared/ca/root.crt, state/shared/ca bound read-only, which
#             sfab-ca publishes on the lab host) trusted once it is there.
#   operators each operator's short-lived kubeconfig, picked up whenever
#             OPERATOR_DIR/<user>/kubeconfig (state/operators, bound read-only) appears or changes:
#             the finish stage issues it on the init node (kubeadm kubeconfig user, a client
#             certificate valid for hours, bound to the operators' ClusterRole) and writes it there.
#             It is installed for that operator user only; root has none.
#
# Every 10 s it restarts a service that died and looks for a new kubeconfig. TERM or INT stops
# the services and exits 0, so docker stop is prompt; nothing else ends PID 1, because a stopped
# container loses the links containerlab wired into it. A setup failure leaves PID 1 idle, so the
# bastion can still be read with docker exec. When setup has finished it writes
# /run/sfab/bastion.ready; `bastion-init.sh --health` (the image's HEALTHCHECK) is healthy while
# that file exists and sshd runs.
#
# SFAB_DRY_RUN=1 prints every change and exits after the build, starting nothing (the tests).
# SFAB_BOOTSTRAP, SFAB_INIT_ENV, SFAB_OPERATOR_DIR, SFAB_CA_ROOT, SFAB_AUTHORIZED_KEYS and
# SFAB_LINK_WAIT_S move what the topology binds; SFAB_RESOLV_CONF names another resolv.conf.
set -uo pipefail

BOOT=${SFAB_BOOTSTRAP:-/sfab/bootstrap}
ENV_FILE=${SFAB_INIT_ENV:-$BOOT/init.env}
KEYS=${SFAB_AUTHORIZED_KEYS:-/sfab/authorized_keys}
READY=${SFAB_READY_FILE:-/run/sfab/bastion.ready}
RESOLV_CONF=${SFAB_RESOLV_CONF:-/etc/resolv.conf}
DRY=${SFAB_DRY_RUN:-0}
POLL=10
KUBE_SUM=""
STOPPING=0

log() { printf '[bastion] %s\n' "$*"; }
run() { if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }
try() {
  if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; return 0; fi
  "$@" >/dev/null 2>&1 || log "warning: failed: $*"
}
link_exists() { [ "$DRY" != 1 ] && ip link show "$1" >/dev/null 2>&1; }
rule_exists() {
  [ "$DRY" != 1 ] || return 1
  ip -4 rule show | awk -v f="$1" -v t="$2" '$2 == "from" && $3 == f && $4 == "lookup" && $5 == t {ok = 1} END {exit !ok}'
}
route_exists() {  # route_exists <table> <dest> [dev]
  [ "$DRY" != 1 ] || return 1
  local out
  out=$(ip -4 route show table "$1" "$2" ${3:+dev "$3"} 2>/dev/null) || return 1
  [ -n "$out" ]
}
net_of() {  # net_of 10.20.9.10/24 -> 10.20.9.0/24
  local ip=${1%/*} len=${1#*/} a b c d n mask
  IFS=. read -r a b c d <<< "$ip"
  n=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  mask=$(( len == 0 ? 0 : (0xffffffff << (32 - len)) & 0xffffffff ))
  n=$(( n & mask ))
  printf '%d.%d.%d.%d/%d' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 )) "$len"
}

# Setup failures leave PID 1 alive and idle, so the bastion can be inspected with docker exec.
fail() {
  log "FATAL: $*"
  [ "$DRY" = 1 ] && exit 1
  idle
}

# ------------------------------------------------------------------------------------------
load() {
  [ -r "$ENV_FILE" ] || fail "no $ENV_FILE: the topology binds bootstrap/<bastion>/ at $BOOT (run make render)"
  set -a
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  set +a
  local v
  for v in NODE_NAME MGMT_IF MGMT_ADDR MGMT_GW MGMT_TABLE BOND_NAME BOND_MEMBERS BOND_ADDR; do
    [ -n "${!v:-}" ] || fail "$ENV_FILE sets no $v"
  done
  OPERATOR=${GUEST_USER:-admin}
  LINK_WAIT=${SFAB_LINK_WAIT_S:-${LINK_WAIT:-600}}
  OPS=${SFAB_OPERATOR_DIR:-${OPERATOR_DIR:-}}
  ROOT_CA=${SFAB_CA_ROOT:-${CA_ROOT:-}}
}

ipv6_off() {  # the namespace default first, so a veth containerlab moves in later takes it
  run sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  run sysctl -qw net.ipv6.conf.all.disable_ipv6=1
}

data_nics() {
  # shellcheck disable=SC2086  # each list splits into its device names
  printf '%s\n' ${BOND_MEMBERS:-} ${OOB_IF:-} ${TX_OFF:-} | sort -u | tr '\n' ' '
}

wait_links() {
  local i d missing want
  want=$(data_nics)
  if [ "$DRY" = 1 ]; then printf '+ wait for links: %s(at most %ss)\n' "$want" "$LINK_WAIT"; return 0; fi
  for ((i = 0; i <= LINK_WAIT; i++)); do
    missing=""
    for d in $want; do ip link show "$d" >/dev/null 2>&1 || missing="$missing $d"; done
    if [ -z "$missing" ]; then log "links present: $want"; return 0; fi
    if [ $((i % 60)) -eq 0 ]; then log "waiting for links:$missing"; fi
    sleep 1
  done
  fail "links still missing after ${LINK_WAIT}s:$missing"
}

nic_ipv6_off() {
  local d
  for d in $(data_nics); do run sysctl -qw "net.ipv6.conf.$d.disable_ipv6=1"; done
}

bond() {
  local b=$BOND_NAME m
  if ! link_exists "$b"; then
    run ip link add "$b" type bond mode "${BOND_MODE:-802.3ad}" lacp_rate "${BOND_LACP_RATE:-fast}" \
      miimon "${BOND_MIIMON:-100}" xmit_hash_policy "${BOND_HASH:-layer3+4}"
  fi
  if [ -n "${BOND_MAC:-}" ]; then run ip link set "$b" address "$BOND_MAC"; fi
  for m in $BOND_MEMBERS; do
    if [ "$DRY" = 1 ] || [ "$(basename "$(readlink "/sys/class/net/$m/master" 2>/dev/null || echo none)")" != "$b" ]; then
      run ip link set "$m" down
      run ip link set "$m" master "$b"
    fi
  done
  run ip link set "$b" mtu "${BOND_MTU:-9000}"
  for m in $BOND_MEMBERS; do run ip link set "$m" up; done
  run ip link set "$b" up
  run sysctl -qw "net.ipv6.conf.$b.disable_ipv6=1"
  run ip addr replace "$BOND_ADDR" dev "$b"
  log "$b (${BOND_MODE:-802.3ad}, lacp_rate ${BOND_LACP_RATE:-fast}, ${BOND_HASH:-layer3+4}) over $BOND_MEMBERS: $BOND_ADDR"
}

oob() {
  [ -n "${OOB_IF:-}" ] || return 0
  local ip=${OOB_ADDR%/*} t=${OOB_TABLE:-100} net
  net=$(net_of "$OOB_ADDR")
  run ip link set "$OOB_IF" up
  run ip addr replace "$OOB_ADDR" dev "$OOB_IF" noprefixroute
  if route_exists main "$net" "$OOB_IF"; then run ip route del "$net" dev "$OOB_IF" table main; fi
  run ip route replace "$net" dev "$OOB_IF" src "$ip" table "$t"
  if [ -n "${OOB_GW:-}" ]; then run ip route replace default via "$OOB_GW" dev "$OOB_IF" table "$t"; fi
  rule_exists "$ip" "$t" || run ip rule add from "$ip" lookup "$t"
  run sysctl -qw "net.ipv4.conf.$OOB_IF.rp_filter=0"
  log "out-of-band $OOB_ADDR on $OOB_IF: table $t via ${OOB_GW:-none}; no route to $net in main"
}

mgmt() {
  local ip=${MGMT_ADDR%/*} t=$MGMT_TABLE net
  net=$(net_of "$MGMT_ADDR")
  run ip route replace "$net" dev "$MGMT_IF" src "$ip" table "$t"
  run ip route replace default via "$MGMT_GW" dev "$MGMT_IF" table "$t"
  rule_exists "$ip" "$t" || run ip rule add from "$ip" lookup "$t"
  if route_exists main default "$MGMT_IF"; then run ip route del default dev "$MGMT_IF" table main; fi
  log "management $MGMT_ADDR on $MGMT_IF: default via $MGMT_GW in table $t"
}

routes() {
  local r dest via dev src
  if [ -n "${GATEWAY:-}" ]; then run ip route replace default via "$GATEWAY" dev "${GATEWAY_DEV:-$BOND_NAME}"; fi
  for r in ${ROUTES:-}; do
    IFS=, read -r dest via dev src <<< "$r"
    run ip route replace "$dest" ${via:+via "$via"} ${dev:+dev "$dev"} ${src:+src "$src"}
  done
}

tx_off() {
  local d
  for d in ${TX_OFF:-} "$BOND_NAME"; do try ethtool -K "$d" tx off; done
}

# Docker writes a container's resolv.conf from the lab host's own file, search line included. The
# search line here is always SEARCH; without DNS_SERVERS, Docker's nameserver and options lines
# stay as they are, and its comments, search and domain lines go.
resolver() {
  local s="" n line search=${SEARCH:-${DOMAIN:-}}
  if [ -n "$search" ]; then s="search $search"; fi
  if [ -n "${DNS_SERVERS:-}" ]; then
    for n in $DNS_SERVERS; do s="$s"$'\n'"nameserver $n"; done
    if [ -n "${RESOLV_OPTIONS:-}" ]; then s="$s"$'\n'"options $RESOLV_OPTIONS"; fi
  elif [ -r "$RESOLV_CONF" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case $line in
        nameserver[[:space:]]*|options[[:space:]]*) s="$s"$'\n'"$line" ;;
      esac
    done < "$RESOLV_CONF"
  fi
  s=${s#$'\n'}
  if [ "$DRY" = 1 ]; then printf '+ write %s: %s\n' "$RESOLV_CONF" "${s//$'\n'/; }"; return 0; fi
  # Docker binds resolv.conf as a file: rewrite it in place, never replace it.
  printf '%s\n' "$s" > "$RESOLV_CONF"
}

# ------------------------------------------------------------------------------------------
# services

operator_user() {
  if [ "$DRY" = 1 ]; then printf '+ operator user %s, key-only, sudo\n' "$OPERATOR"; return 0; fi
  if ! id -u "$OPERATOR" >/dev/null 2>&1; then
    # useradd refuses to make a group that exists already, so an existing one is joined instead
    local g=()
    if getent group "$OPERATOR" >/dev/null 2>&1; then g=(-g "$OPERATOR"); fi
    useradd -m -s /bin/bash "${g[@]}" -G sudo "$OPERATOR" || { log "warning: could not add user $OPERATOR"; return 0; }
  fi
  # No password at all (not a locked one, which sshd would refuse for a key login too).
  usermod -p '*' "$OPERATOR" >/dev/null 2>&1 || true
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$OPERATOR" > /etc/sudoers.d/sfab-operator
  chmod 0440 /etc/sudoers.d/sfab-operator
  mkdir -p /workspace
}

sshd_up() {
  if [ "$DRY" = 1 ]; then printf '+ sshd: key-only, AllowUsers %s, keys from %s\n' "$OPERATOR" "$KEYS"; return 0; fi
  [ -s "$KEYS" ] || log "warning: no authorized keys at $KEYS; nobody can log in over SSH"
  ssh-keygen -A >/dev/null 2>&1 || true
  mkdir -p /run/sshd /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/10-sfab.conf <<EOF
# written by bastion-init.sh: key-only login for the operator user, with the bound keys
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile $KEYS
AllowUsers $OPERATOR
EOF
  pgrep -x sshd >/dev/null 2>&1 || /usr/sbin/sshd || log "warning: sshd did not start"
}

lldp_up() {
  local ifs
  ifs=$(data_nics | tr ' ' '\n' | sed '/^$/d' | paste -sd, -)
  [ -n "$ifs" ] || return 0
  if [ "$DRY" = 1 ]; then printf '+ lldpd -I %s\n' "$ifs"; return 0; fi
  command -v lldpd >/dev/null 2>&1 || return 0
  pgrep -x lldpd >/dev/null 2>&1 && return 0
  mkdir -p /run/lldpd /etc/lldpd.d
  # The bond members send their LLDP frames from their own MACs: lldpd's default falls back to one
  # fixed address (00:60:08:69:97:ef) for a locally administered MAC, which every bonded node of the
  # lab would then share, and the switches would learn it on whichever port spoke last.
  printf 'configure system bond-slave-src-mac-type real\n' >/etc/lldpd.d/sfab.conf
  lldpd -I "$ifs" >/dev/null 2>&1 || log "warning: lldpd did not start"
}

trust_root() {
  local r=$ROOT_CA dst=/usr/local/share/ca-certificates/sfab-lab-root.crt
  [ -n "$r" ] && [ -s "$r" ] || return 0
  if [ "$DRY" = 1 ]; then printf '+ trust %s\n' "$r"; return 0; fi
  cmp -s "$r" "$dst" 2>/dev/null && return 0
  install -m 0644 "$r" "$dst"
  update-ca-certificates >/dev/null 2>&1 || log "warning: update-ca-certificates failed"
  log "lab root CA trusted"
}

# The operator's own short-lived kubeconfig, never the cluster's admin one: the finish stage writes
# it to state/operators/<user>/kubeconfig on the lab host, bound read-only at OPERATOR_DIR.
kube_pickup() {
  local k sum home
  [ -n "$OPS" ] || return 0
  k=$OPS/$OPERATOR/kubeconfig
  [ -s "$k" ] || return 0
  sum=$(sha256sum "$k" | cut -c1-64)
  [ "$sum" = "$KUBE_SUM" ] && return 0
  if [ "$DRY" = 1 ]; then printf '+ kubeconfig from %s for %s only\n' "$k" "$OPERATOR"; KUBE_SUM=$sum; return 0; fi
  home=$(getent passwd "$OPERATOR" | cut -d: -f6)
  [ -n "$home" ] || return 0
  install -D -m 0600 -o "$OPERATOR" -g "$OPERATOR" "$k" "$home/.kube/config"
  KUBE_SUM=$sum
  log "the operator $OPERATOR's kubeconfig picked up from $k (a short-lived client certificate)"
}

ready() {
  [ "$DRY" = 1 ] && return 0
  mkdir -p "$(dirname "$READY")"
  printf '%s %s\n' "$NODE_NAME" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$READY"
}

health() {
  [ -f "$READY" ] || { echo "setup has not finished"; return 1; }
  pgrep -x sshd >/dev/null 2>&1 || { echo "sshd is not running"; return 1; }
  echo healthy
}

# ------------------------------------------------------------------------------------------
stop_all() {
  [ "$STOPPING" = 1 ] && return 0
  STOPPING=1
  log "stopping: lldpd, sshd"
  rm -f "$READY"
  pkill -x lldpd 2>/dev/null || true
  pkill -x sshd 2>/dev/null || true
  # A few seconds for them to finish (neither writes anything that must survive, so no longer).
  local i p left
  for ((i = 0; i < 10; i++)); do
    left=""
    for p in lldpd sshd; do pgrep -x "$p" >/dev/null 2>&1 && left="$left $p"; done
    [ -z "$left" ] && break
    sleep 0.5
  done
  [ -z "$left" ] || log "still running at exit:$left"
  exit 0
}

supervise() {
  pgrep -x sshd >/dev/null 2>&1 || { log "sshd is not running: starting it"; /usr/sbin/sshd || true; }
  pgrep -x lldpd >/dev/null 2>&1 || lldp_up
  trust_root
  kube_pickup
}

idle() {
  while :; do
    sleep "$POLL" &
    wait $! || true
  done
}

main() {
  trap stop_all TERM INT
  ipv6_off
  load
  # resolv.conf first: it needs nothing from the links, and a later step that fails must not
  # leave Docker's file, with the lab host's search line, in place
  resolver
  wait_links
  nic_ipv6_off
  bond
  oob
  mgmt
  routes
  tx_off
  operator_user
  sshd_up
  lldp_up
  trust_root
  kube_pickup
  ready
  log "$NODE_NAME ready: $BOND_NAME $BOND_ADDR via ${GATEWAY:-none}; out-of-band ${OOB_ADDR:-none}; management $MGMT_ADDR in table $MGMT_TABLE"
  [ "$DRY" = 1 ] && exit 0
  while :; do
    supervise
    sleep "$POLL" &
    wait $! || true
  done
}

case ${1:-} in
  --health) health ;;
  "") main ;;
  *) printf 'usage: bastion-init.sh [--health]\n' >&2; exit 2 ;;
esac
