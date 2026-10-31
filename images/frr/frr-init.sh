#!/usr/bin/env bash
# frr-init.sh: PID 1's first step in sfab/frr (under tini). It reads the router's init.env
# (render/frr.py, bound from bootstrap/<router>/ at /sfab/bootstrap), prepares the namespace, then
# hands over to FRR's own start script, which runs watchfrr on the rendered daemons file.
#
#   - writes resolv.conf first, before it waits for anything: its search line is SEARCH (the
#     lab's domain), never the one Docker copied from the lab host's file, and Docker's
#     nameserver and options lines stay (DNS_SERVERS and RESOLV_OPTIONS replace them when the env
#     sets them), as sfab/client's init.sh does;
#   - waits up to LINK_WAIT_S (180 s) for every data port in IFACES: containerlab attaches the
#     links after the container starts;
#   - puts the management port (MGMT_IF, eth0) in VRF MGMT_VRF (mgmt, table MGMT_TABLE) with its
#     default route there, so the main table holds only the lab's own routes and a packet for an
#     unknown destination never leaves through the management network;
#   - turns on IPv4 forwarding, sets rp_filter (RP_FILTER, 0), and, on a carrier router, the MPLS
#     label space and net.mpls.conf.<port>.input=1 on its core ports only (CORE_IFS);
#   - creates the customer VRFs in VRFS (name,table,port+port ...) and puts their ports in them;
#   - brings the data ports up at their MTU (ETH<n>_MTU) and turns TX checksum offload off on
#     every port in TX_OFF (TCP fails silently on a routed path otherwise);
#   - links /etc/frr/frr.conf, daemons and vtysh.conf to the rendered files, which are bound read
#     only: the render stays the router's configuration. A `write memory` cannot reach it: vtysh
#     moves the frr.conf link aside (frr.conf.sav) and writes a copy in the container, which the
#     next start replaces with the link again (sfab-frr-restore restore does the same live);
#   - caps the open-file limit at FRR_MAX_FDS (100000, the figure FRR itself suggests), since
#     every FRR daemon warns at start about the container's much larger default;
#   - starts sshd in VRF MGMT_VRF for GUEST_USER (admin by default), key only, with the keys the
#     topology binds at /sfab/authorized_keys (the lab key and the deploying user's own). The
#     sessions themselves run in the main table.
#
# Usage: frr-init.sh [command...]   (the image's CMD, /usr/lib/frr/docker-start, by default).
# SFAB_INIT_ENV names another init.env; SFAB_DRY_RUN=1 prints every change instead of making it,
# as if nothing existed yet, and does not start FRR. SFAB_FRR_CONF_DIR, SFAB_FRR_DIR,
# SFAB_AUTHORIZED_KEYS, SFAB_SSHD, SFAB_SSHD_CONFIG and SFAB_RESOLV_CONF move the files it reads
# and writes (tests).
set -euo pipefail

ENV_FILE=${SFAB_INIT_ENV:-/sfab/bootstrap/init.env}
CONF_DIR=${SFAB_FRR_CONF_DIR:-$(dirname "$ENV_FILE")}
FRR_DIR=${SFAB_FRR_DIR:-/etc/frr}
KEYS=${SFAB_AUTHORIZED_KEYS:-/sfab/authorized_keys}
SSHD_CONFIG=${SFAB_SSHD_CONFIG:-/etc/ssh/sshd_config.sfab}
SSHD=${SFAB_SSHD:-/usr/sbin/sshd}
RESOLV_CONF=${SFAB_RESOLV_CONF:-/etc/resolv.conf}
DRY=${SFAB_DRY_RUN:-0}

log() { printf '[frr-init] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }
run() { if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; else "$@"; fi; }
try() {
  if [ "$DRY" = 1 ]; then printf '+ %s\n' "$*"; return 0; fi
  "$@" >/dev/null 2>&1 || log "warning: failed: $*"
}
link_exists() { [ "$DRY" != 1 ] && ip link show "$1" >/dev/null 2>&1; }
master_of() { basename "$(readlink "/sys/class/net/$1/master" 2>/dev/null || echo none)"; }
envvar() { local v=$1; printf '%s' "${!v:-}"; }
write_file() {  # write_file <path> <mode> <content>
  if [ "$DRY" = 1 ]; then printf '+ write %s (%s): %s\n' "$1" "$2" "${3//$'\n'/; }"; return 0; fi
  printf '%s\n' "$3" > "$1.tmp"
  chmod "$2" "$1.tmp"
  mv -f "$1.tmp" "$1"
}

load() {
  [ -r "$ENV_FILE" ] || die "no $ENV_FILE: the topology binds bootstrap/<router>/ at /sfab/bootstrap (run make render)"
  set -a
  # shellcheck source=/dev/null
  . "$ENV_FILE"
  set +a
  local v
  for v in NODE_NAME MGMT_IF MGMT_ADDR MGMT_GW MGMT_TABLE MGMT_VRF; do
    [ -n "${!v:-}" ] || die "$ENV_FILE sets no $v"
  done
  LINK_WAIT_S=${SFAB_LINK_WAIT_S:-${LINK_WAIT_S:-180}}
}

wait_links() {
  local i d missing want
  # shellcheck disable=SC2086  # each list splits into its device names
  want=$(printf '%s\n' ${IFACES:-} ${TX_OFF:-} | sort -u | tr '\n' ' ')
  [ "$DRY" != 1 ] || { printf '+ wait for links: %s\n' "$want"; return 0; }
  for ((i = 0; i <= LINK_WAIT_S; i++)); do
    missing=""
    for d in $want; do ip link show "$d" >/dev/null 2>&1 || missing="$missing $d"; done
    if [ -z "$missing" ]; then return 0; fi
    sleep 1
  done
  die "links still missing after ${LINK_WAIT_S}s:$missing"
}

sysctls() {
  local d
  run sysctl -q -w "net.ipv4.ip_forward=${IP_FORWARD:-1}"
  run sysctl -q -w "net.ipv4.conf.all.rp_filter=${RP_FILTER:-0}" "net.ipv4.conf.default.rp_filter=${RP_FILTER:-0}"
  for d in ${IFACES:-}; do run sysctl -q -w "net.ipv4.conf.$d.rp_filter=${RP_FILTER:-0}"; done
  [ -n "${CORE_IFS:-}" ] || return 0
  run sysctl -q -w "net.mpls.platform_labels=${MPLS_LABELS:-1048575}"
  for d in $CORE_IFS; do run sysctl -q -w "net.mpls.conf.$d.input=1"; done
}

# vrf_dev <name> <table>: the VRF device, created once and up.
vrf_dev() {
  if ! link_exists "$1"; then run ip link add "$1" type vrf table "$2"; fi
  run ip link set "$1" up
}

# enslave <port> <vrf>
enslave() {
  if [ "$DRY" = 1 ] || [ "$(master_of "$1")" != "$2" ]; then run ip link set "$1" master "$2"; fi
}

# The management port in its own VRF. Enslaving it moves its connected route into the VRF's
# table and drops the default route docker gave the main table; the VRF gets that default.
mgmt_vrf() {
  local t=$MGMT_TABLE v=$MGMT_VRF ip=${MGMT_ADDR%/*}
  vrf_dev "$v" "$t"
  enslave "$MGMT_IF" "$v"
  run ip addr replace "$MGMT_ADDR" dev "$MGMT_IF"
  run ip route replace default via "$MGMT_GW" dev "$MGMT_IF" table "$t"
  if [ "$DRY" != 1 ] && [ -n "$(ip -4 route show table main default 2>/dev/null)" ]; then
    run ip route del default table main
  fi
  log "management $ip on $MGMT_IF in VRF $v (table $t), default via $MGMT_GW"
}

# Customer VRFs: VRFS="name,table,port+port ...".
vrfs() {
  local item name table ports p
  for item in ${VRFS:-}; do
    IFS=, read -r name table ports <<< "$item"
    if [ -z "$name" ] || [ -z "$table" ]; then die "VRFS entry '$item' is not name,table,ports"; fi
    vrf_dev "$name" "$table"
    for p in ${ports//+/ }; do enslave "$p" "$name"; done
  done
}

ports_up() {
  local d m
  for d in ${IFACES:-}; do
    m=$(envvar "${d^^}_MTU")
    if [ -n "$m" ]; then run ip link set "$d" mtu "$m"; fi
    run ip link set "$d" up
  done
}

tx_off() {
  local d
  for d in ${TX_OFF:-}; do try ethtool -K "$d" tx off; done
}

# Docker writes a container's resolv.conf from the lab host's own file, search line included. The
# search line here is always SEARCH; without DNS_SERVERS, Docker's nameserver and options lines
# stay as they are, and its comments, search and domain lines go. The same function as
# images/client/init.sh's (common/sfab/tests/test_hosts.py keeps the two equal).
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

# FRR reads /etc/frr; each rendered file is linked there, never copied, so the bound render is
# what FRR loads at every start. A copy an earlier `write memory` left is replaced by the link.
frr_files() {
  local f
  for f in frr.conf daemons vtysh.conf; do
    if [ ! -r "$CONF_DIR/$f" ]; then
      [ "$f" = vtysh.conf ] || die "no $CONF_DIR/$f (run make render)"
      continue
    fi
    run ln -sfn "$CONF_DIR/$f" "$FRR_DIR/$f"
  done
  if [ "$DRY" = 1 ] || [ -L "$FRR_DIR/frr.conf.sav" ]; then run rm -f "$FRR_DIR/frr.conf.sav"; fi
}

fd_limit() {
  local want=${FRR_MAX_FDS:-100000} have
  have=$(ulimit -n)
  if [ "$have" = unlimited ] || [ "$have" -gt "$want" ]; then
    if [ "$DRY" = 1 ]; then printf '+ ulimit -n %s\n' "$want"; else ulimit -n "$want" || log "warning: could not lower the open-file limit to $want"; fi
  fi
}

# sshd listens only in the management VRF (ListenAddress ... rdomain): the data ports never
# answer on port 22. Host keys are made in the container, never shipped in the image.
sshd_up() {
  local u=${GUEST_USER:-admin} home
  [ -x "$SSHD" ] || { log "warning: no sshd in this image"; return 0; }
  try ssh-keygen -A
  if [ "$DRY" = 1 ] || ! id "$u" >/dev/null 2>&1; then
    # busybox adduser refuses to make a group that exists already, so an existing one is joined
    if [ "$DRY" != 1 ] && getent group "$u" >/dev/null 2>&1; then
      run adduser -D -s /bin/bash -G "$u" "$u"
    else
      run adduser -D -s /bin/bash "$u"
    fi
    # An Alpine account made without a password is locked ("!"), and sshd refuses a locked
    # account even with a key; "*" means no password and not locked.
    run sed -i "s/^$u:!/$u:*/" /etc/shadow
  fi
  # vtysh needs the frrvty group; busybox addgroup fails on a member it already has.
  if [ "$DRY" = 1 ] || ! id -nG "$u" 2>/dev/null | tr ' ' '\n' | grep -qx frrvty; then
    run addgroup "$u" frrvty
  fi
  write_file "/etc/sudoers.d/$u" 0440 "$u ALL=(ALL) NOPASSWD: ALL"
  home=$(getent passwd "$u" 2>/dev/null | cut -d: -f6 || true)
  home=${home:-/home/$u}
  if [ -r "$KEYS" ]; then
    run install -d -m 0700 -o "$u" -g "$u" "$home/.ssh"
    run install -m 0600 -o "$u" -g "$u" "$KEYS" "$home/.ssh/authorized_keys"
  else
    log "no $KEYS: sshd runs, but no one can log in (docker exec <container> vtysh still works)"
  fi
  write_file "$SSHD_CONFIG" 0644 "# sfab/frr: written by frr-init.sh at every start
ListenAddress 0.0.0.0 rdomain $MGMT_VRF
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PidFile /run/sshd.pid
Subsystem sftp internal-sftp"
  if [ "$DRY" = 1 ]; then printf '+ %s -f %s\n' "$SSHD" "$SSHD_CONFIG"; return 0; fi
  if [ -s /run/sshd.pid ] && kill -0 "$(cat /run/sshd.pid)" 2>/dev/null; then return 0; fi
  "$SSHD" -f "$SSHD_CONFIG" || log "warning: sshd did not start (docker exec <container> vtysh still works)"
}

main() {
  load
  # resolv.conf first: it needs nothing from the links, and a later step that fails must not
  # leave Docker's file, with the lab host's search line, in place
  resolver
  wait_links
  sysctls
  mgmt_vrf
  vrfs
  ports_up
  tx_off
  frr_files
  fd_limit
  sshd_up
  log "$NODE_NAME: ports ${IFACES:-none} up; vrfs ${VRFS:-none}; mpls on ${CORE_IFS:-none}; tx off on ${TX_OFF:-none}; search ${SEARCH:-${DOMAIN:-none}}; starting FRR"
  if [ "$DRY" = 1 ]; then
    printf '+ exec %s\n' "${*:-/usr/lib/frr/docker-start}"
    return 0
  fi
  if [ $# -eq 0 ]; then set -- /usr/lib/frr/docker-start; fi
  exec "$@"
}

main "$@"
