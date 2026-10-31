#!/usr/bin/env bash
# sfab-init.sh: configure a container host from its init.env (render/host.py). The topology runs
# it once as the node's exec, after containerlab has attached the links; running it again is safe.
#
#   - writes resolv.conf first, before it waits for anything: the search line is always SEARCH
#     (the lab's domain), never the one Docker copied from the lab host's file; the nameservers
#     and options are DNS_SERVERS and RESOLV_OPTIONS when the lab has the node's resolver,
#     Docker's own lines otherwise;
#   - waits for every data NIC the env names;
#   - addresses each port in IFACES (ETH<n>_ADDR, ETH<n>_MTU), or builds the 802.3ad bond and
#     the out-of-band port when the env has BOND_* and OOB_* (the bastion's shape);
#   - moves the management default to table MGMT_TABLE (150) behind a rule for the management
#     address, so the main table's default is the data gateway (GATEWAY on GATEWAY_DEV);
#   - adds the static ROUTES (dest,via,dev,src);
#   - turns TX checksum offload off on every data NIC in TX_OFF (TCP fails silently on a routed
#     path otherwise);
#   - when CA_ROOT is set, appends the lab root CA to the system bundle once the bastion has
#     published it (in the background, so the exec returns).
#
# Usage: sfab-init.sh [init.env]   (default /sfab/bootstrap/init.env). SFAB_DRY_RUN=1 prints the
# changes instead of making them. SFAB_RESOLV_CONF names another resolv.conf (tests).
set -euo pipefail

ENV_FILE=${1:-${SFAB_INIT_ENV:-/sfab/bootstrap/init.env}}
DRY=${SFAB_DRY_RUN:-0}
LINK_WAIT_S=${SFAB_LINK_WAIT_S:-180}
CA_WAIT_S=${SFAB_CA_WAIT_S:-3600}
CA_BUNDLE=${SFAB_CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}
RESOLV_CONF=${SFAB_RESOLV_CONF:-/etc/resolv.conf}
LOG=${SFAB_INIT_LOG:-/var/log/sfab-init.log}

log() { printf '[sfab-init] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }
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
net_of() {
  local ip=${1%/*} len=${1#*/} a b c d n mask
  IFS=. read -r a b c d <<< "$ip"
  n=$(( (a << 24) | (b << 16) | (c << 8) | d ))
  mask=$(( len == 0 ? 0 : (0xffffffff << (32 - len)) & 0xffffffff ))
  n=$(( n & mask ))
  printf '%d.%d.%d.%d/%d' $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) $(( (n >> 8) & 255 )) $(( n & 255 )) "$len"
}
envvar() { local v=$1; printf '%s' "${!v:-}"; }

load() {
  [ -r "$ENV_FILE" ] || die "no $ENV_FILE: the topology binds bootstrap/<node>/ at /sfab/bootstrap (run make render)"
  set -a
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  set +a
  local v
  for v in NODE_NAME MGMT_IF MGMT_ADDR MGMT_GW MGMT_TABLE; do
    [ -n "${!v:-}" ] || die "$ENV_FILE sets no $v"
  done
}

wait_links() {
  local i d missing want
  # shellcheck disable=SC2086  # each list splits into its device names
  want=$(printf '%s\n' ${IFACES:-} ${BOND_MEMBERS:-} ${OOB_IF:-} ${TX_OFF:-} | sort -u | tr '\n' ' ')
  [ "$DRY" != 1 ] || { printf '+ wait for links: %s\n' "$want"; return 0; }
  for ((i = 0; i <= LINK_WAIT_S; i++)); do
    missing=""
    for d in $want; do ip link show "$d" >/dev/null 2>&1 || missing="$missing $d"; done
    if [ -z "$missing" ]; then return 0; fi
    sleep 1
  done
  die "links still missing after ${LINK_WAIT_S}s:$missing"
}

ifaces() {
  local d k a m
  for d in ${IFACES:-}; do
    k=${d^^}
    a=$(envvar "${k}_ADDR")
    m=$(envvar "${k}_MTU")
    if [ -n "$m" ]; then run ip link set "$d" mtu "$m"; fi
    run ip link set "$d" up
    if [ -n "$a" ]; then run ip addr replace "$a" dev "$d"; fi
  done
}

bond() {
  [ -n "${BOND_NAME:-}" ] || return 0
  local b=$BOND_NAME m
  if ! link_exists "$b"; then
    run ip link add "$b" type bond mode "$BOND_MODE" lacp_rate "$BOND_LACP_RATE" \
      miimon "$BOND_MIIMON" xmit_hash_policy "$BOND_HASH"
  fi
  for m in $BOND_MEMBERS; do
    if [ "$DRY" = 1 ] || [ "$(basename "$(readlink "/sys/class/net/$m/master" 2>/dev/null || echo none)")" != "$b" ]; then
      run ip link set "$m" down
      run ip link set "$m" master "$b"
    fi
  done
  if [ -n "${BOND_MTU:-}" ]; then run ip link set "$b" mtu "$BOND_MTU"; fi
  for m in $BOND_MEMBERS; do run ip link set "$m" up; done
  run ip link set "$b" up
  run ip addr replace "$BOND_ADDR" dev "$b"
}

oob() {
  [ -n "${OOB_IF:-}" ] || return 0
  local ip=${OOB_ADDR%/*} t=$OOB_TABLE net
  net=$(net_of "$OOB_ADDR")
  run ip link set "$OOB_IF" up
  run ip addr replace "$OOB_ADDR" dev "$OOB_IF" noprefixroute
  if route_exists main "$net" "$OOB_IF"; then run ip route del "$net" dev "$OOB_IF" table main; fi
  run ip route replace "$net" dev "$OOB_IF" src "$ip" table "$t"
  if [ -n "${OOB_GW:-}" ]; then run ip route replace default via "$OOB_GW" dev "$OOB_IF" table "$t"; fi
  rule_exists "$ip" "$t" || run ip rule add from "$ip" lookup "$t"
}

mgmt() {
  local ip=${MGMT_ADDR%/*} t=$MGMT_TABLE net
  net=$(net_of "$MGMT_ADDR")
  run ip route replace "$net" dev "$MGMT_IF" src "$ip" table "$t"
  run ip route replace default via "$MGMT_GW" dev "$MGMT_IF" table "$t"
  rule_exists "$ip" "$t" || run ip rule add from "$ip" lookup "$t"
  if route_exists main default "$MGMT_IF"; then run ip route del default dev "$MGMT_IF" table main; fi
}

routes() {
  local r dest via dev src
  if [ -n "${GATEWAY:-}" ]; then run ip route replace default via "$GATEWAY" dev "$GATEWAY_DEV"; fi
  for r in ${ROUTES:-}; do
    IFS=, read -r dest via dev src <<< "$r"
    run ip route replace "$dest" ${via:+via "$via"} ${dev:+dev "$dev"} ${src:+src "$src"}
  done
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

tx_off() {
  local d
  for d in ${TX_OFF:-}; do try ethtool -K "$d" tx off; done
}

# The lab root CA, appended explicitly: a bundle rebuilt by update-ca-certificates is not
# guaranteed to hold it.
trust_ca() {
  [ -n "${CA_ROOT:-}" ] || return 0
  if [ "$DRY" = 1 ]; then printf '+ trust %s once it exists (at most %ss)\n' "$CA_ROOT" "$CA_WAIT_S"; return 0; fi
  # shellcheck disable=SC2016  # the inner script expands its own positional parameters
  setsid bash -c '
    set -u
    root=$1 bundle=$2 wait=$3 t=0
    while [ ! -s "$root" ] && [ "$t" -lt "$wait" ]; do sleep 10; t=$((t + 10)); done
    [ -s "$root" ] || { echo "[sfab-init] no lab root CA at $root after ${wait}s"; exit 0; }
    mkdir -p /usr/local/share/ca-certificates
    cp "$root" /usr/local/share/ca-certificates/sfab-lab-root.crt
    line=$(sed -n 2p "$root")
    grep -qF "$line" "$bundle" 2>/dev/null || cat "$root" >> "$bundle"
    echo "[sfab-init] lab root CA trusted ($root)"
  ' sfab-ca "$CA_ROOT" "$CA_BUNDLE" "$CA_WAIT_S" < /dev/null >> "$LOG" 2>&1 &
}

main() {
  load
  # resolv.conf first: it needs nothing from the links, and a later step that fails must not
  # leave Docker's file, with the lab host's search line, in place
  resolver
  wait_links
  ifaces
  bond
  oob
  mgmt
  routes
  tx_off
  trust_ca
  local ports=${IFACES:-${BOND_NAME:-none}} address=${ETH1_ADDR:-${BOND_ADDR:-none}}
  log "$NODE_NAME: $ports $address via ${GATEWAY:-none}; management $MGMT_ADDR in table $MGMT_TABLE; dns ${DNS_SERVERS:-from Docker}, search ${SEARCH:-${DOMAIN:-none}}; tx off on ${TX_OFF:-none}"
}

main "$@"
