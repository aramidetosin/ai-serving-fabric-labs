#!/usr/bin/env bash
# sfab-init.sh of sfab/vpngw: the topology runs it once as the node's exec, after containerlab has
# attached the links; running it again is safe.
#
#   1. the network, by the client's init (sfab-net-init.sh, images/client/init.sh): the ports'
#      addresses, the gateway, the management default in table 150, TX checksum offload off;
#   2. IP forwarding on, so the site's hosts behind the router reach the uplink and the tunnel;
#   3. the SSH login, as on the FRR routers: GUEST_USER (admin by default), key only, no root and
#      no password, with the keys the topology binds at /sfab/authorized_keys (the lab key and the
#      deploying user's own), passwordless sudo, the ipsec group so swanctl reaches charon without
#      sudo, and sshd listening on the management address
#      (MGMT_ADDR) only, so the uplink, the site LAN and the tunnel never answer on port 22;
#   4. the tunnel: swanctl.conf from the render beside init.env goes to /etc/swanctl/conf.d/, and
#      the pre-shared key named by IPSEC_PSK (IPSEC_DIR/<IPSEC_PSK>.psk, bound read-only from the lab's
#      state/secrets/ipsec) becomes a secrets section in a 0600 file there; the key is never
#      printed. Then /run/sfab/vpngw.ready, which tells the main process (vpngw-run.sh) to start
#      charon and load the connections.
#
# Usage: sfab-init.sh [init.env]   (default /sfab/bootstrap/init.env). SFAB_DRY_RUN=1 prints the
# changes instead of making them; SFAB_NET_INIT names the network step's script, and
# SFAB_AUTHORIZED_KEYS, SFAB_SSHD and SFAB_SSHD_CONFIG the files the login step reads.
set -euo pipefail

ENV_FILE=${1:-${SFAB_INIT_ENV:-/sfab/bootstrap/init.env}}
BOOT=$(dirname "$ENV_FILE")
DRY=${SFAB_DRY_RUN:-0}
NET_INIT=${SFAB_NET_INIT:-/usr/local/sbin/sfab-net-init.sh}
READY=${SFAB_READY_FILE:-/run/sfab/vpngw.ready}
CONF_D=${SFAB_SWANCTL_DIR:-/etc/swanctl/conf.d}
KEYS=${SFAB_AUTHORIZED_KEYS:-/sfab/authorized_keys}
SSHD=${SFAB_SSHD:-/usr/sbin/sshd}
SSHD_CONFIG=${SFAB_SSHD_CONFIG:-/etc/ssh/sshd_config.sfab}

log() { printf '[sfab-vpngw] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }
envget() { sed -n "s/^$1=//p" "$ENV_FILE" | tr -d "'\""; }

[ -r "$ENV_FILE" ] || die "no $ENV_FILE: the topology binds bootstrap/<node>/ at /sfab/bootstrap (run make render)"
[ -r "$BOOT/swanctl.conf" ] || die "no $BOOT/swanctl.conf (run make render)"
dir=$(envget IPSEC_DIR)
psk=$(envget IPSEC_PSK)
peer=$(envget IPSEC_PEER_ID)
[ -n "$dir" ] && [ -n "$psk" ] && [ -n "$peer" ] || die "$ENV_FILE sets no IPSEC_DIR, IPSEC_PSK or IPSEC_PEER_ID"

SFAB_DRY_RUN=$DRY "$NET_INIT" "$ENV_FILE"

# The login, as frr-init.sh's sshd_up does it, on the management address instead of a VRF: the
# client's network step keeps management in its own routing table (MGMT_TABLE), keyed by source.
sshd_up() {
  local u=${GUEST_USER:-admin} mgmt home
  mgmt=$(envget MGMT_ADDR); mgmt=${mgmt%/*}
  [ -n "$mgmt" ] || { log "warning: $ENV_FILE sets no MGMT_ADDR: no sshd"; return 0; }
  if [ "$DRY" = 1 ]; then
    printf '+ login %s (key only, sudo, group ipsec for swanctl) from %s; sshd on %s:22\n' "$u" "$KEYS" "$mgmt"
    return 0
  fi
  [ -x "$SSHD" ] || { log "warning: no sshd in this image"; return 0; }
  ssh-keygen -A >/dev/null
  if ! id "$u" >/dev/null 2>&1; then
    # busybox adduser refuses to make a group that exists already, so an existing one is joined
    if getent group "$u" >/dev/null 2>&1; then adduser -D -s /bin/bash -G "$u" "$u"; else adduser -D -s /bin/bash "$u"; fi
    # An Alpine account made without a password is locked ("!"), and sshd refuses a locked
    # account even with a key; "*" means no password and not locked.
    sed -i "s/^$u:!/$u:*/" /etc/shadow
  fi
  # swanctl talks to charon over /var/run/charon.vici (ipsec:ipsec, 0770), so the login joins
  # ipsec the way the FRR routers' joins frrvty for vtysh; busybox addgroup fails on a member it
  # already has.
  if ! id -nG "$u" | tr ' ' '\n' | grep -qx ipsec; then addgroup "$u" ipsec; fi
  printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$u" > "/etc/sudoers.d/$u"
  chmod 0440 "/etc/sudoers.d/$u"
  home=$(getent passwd "$u" | cut -d: -f6)
  if [ -r "$KEYS" ]; then
    install -d -m 0700 -o "$u" -g "$u" "$home/.ssh"
    install -m 0600 -o "$u" -g "$u" "$KEYS" "$home/.ssh/authorized_keys"
  else
    log "no $KEYS: sshd runs, but no one can log in (docker exec <container> sh still works)"
  fi
  cat > "$SSHD_CONFIG" <<CONF
# sfab/vpngw: written by sfab-init.sh at every start
ListenAddress $mgmt
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PidFile /run/sshd.pid
Subsystem sftp internal-sftp
CONF
  if [ -s /run/sshd.pid ] && kill -0 "$(cat /run/sshd.pid)" 2>/dev/null; then return 0; fi
  "$SSHD" -f "$SSHD_CONFIG" || log "warning: sshd did not start (docker exec <container> sh still works)"
}
sshd_up

if [ "$DRY" = 1 ]; then
  printf '+ sysctl net.ipv4.ip_forward=1\n'
  printf '+ install %s/swanctl.conf %s/sfab.conf\n' "$BOOT" "$CONF_D"
  printf '+ write %s/sfab-secrets.conf (0600) from %s/%s.psk\n' "$CONF_D" "$dir" "$psk"
  printf '+ write %s\n' "$READY"
  exit 0
fi
sysctl -qw net.ipv4.ip_forward=1
[ -r "$dir/$psk.psk" ] || die "no pre-shared key file $dir/$psk.psk: the topology binds state/secrets/ipsec there (make up makes it)"
mkdir -p "$CONF_D" "$(dirname "$READY")"
install -m 0644 "$BOOT/swanctl.conf" "$CONF_D/sfab.conf"
umask 077
key=$(tr -d '\n' < "$dir/$psk.psk")
[ -n "$key" ] || die "the pre-shared key file is empty"
{
  printf 'secrets {\n  ike-%s {\n    id = %s\n    secret = "%s"\n  }\n}\n' "$psk" "$peer" "$key"
} > "$CONF_D/sfab-secrets.conf"
chmod 0600 "$CONF_D/sfab-secrets.conf"
unset key
: > "$READY"
log "tunnel configuration installed; charon starts under vpngw-run.sh"
