#!/usr/bin/env bash
# sfab-init.sh of sfab/resolver: the topology runs it once as the node's exec, after containerlab
# has attached the links; running it again is safe. The image runs the lab's DNS and time services
# (render/dns.py): the authoritative servers, the resolvers, the corporate resolver, the public
# servers and the time reference.
#
#   1. the network, by the client's init (sfab-net-init.sh, images/client/init.sh): resolv.conf's
#      search line as the host's domain, the port's address and gateway or the 802.3ad bond to the
#      pair, the management default in table 150, TX checksum offload off, the lab root CA when
#      CA_ROOT is set;
#   2. the DNS server from the render beside init.env, when the node has a DNS role, by sfab-dns
#      start: BIND on named.conf and zones/ (ROLE bind-auth or bind-recursive), with the TSIG keys
#      the topology binds at TSIG_DIR, or dnsmasq on dnsmasq.conf (ROLE dnsmasq), each file checked
#      before the server sees it. The role is ROLE, else DNS_ROLE from init.env;
#   3. the time server, when the render holds chrony.conf, by sfab-ntp start: chronyd -x (it never
#      adjusts the clock of the host the container shares) on it, as the chrony user; a
#      reference's NTS key and chain are installed from TLS_DIR (state/tls/<node>, bound
#      read-only) where chronyd reads them;
#   4. /run/sfab/resolver.ready, which tells the image's main process (resolver-run.sh) to keep
#      the servers running from now on.
#
# Usage: sfab-init.sh [init.env]   (default /sfab/bootstrap/init.env). SFAB_DRY_RUN=1 prints the
# changes instead of making them; SFAB_NET_INIT names the network step's script, SFAB_NTP sfab-ntp.
set -euo pipefail

ENV_FILE=${1:-${SFAB_INIT_ENV:-/sfab/bootstrap/init.env}}
BOOT=$(dirname "$ENV_FILE")
DRY=${SFAB_DRY_RUN:-0}
NET_INIT=${SFAB_NET_INIT:-/usr/local/sbin/sfab-net-init.sh}
NTP=${SFAB_NTP:-/usr/local/bin/sfab-ntp}
READY=${SFAB_READY_FILE:-/run/sfab/resolver.ready}

log() { printf '[sfab-resolver] %s\n' "$*"; }
die() { log "FATAL: $*"; exit 1; }
envget() { sed -n "s/^$1=//p" "$ENV_FILE" | tr -d "'\""; }

[ -r "$ENV_FILE" ] || die "no $ENV_FILE: the topology binds bootstrap/<node>/ at /sfab/bootstrap (run make render)"
role=${ROLE:-$(envget DNS_ROLE)}
case $role in
  bind-auth|bind-recursive|dnsmasq|"") ;;
  *) die "unknown DNS role: ROLE, or DNS_ROLE in $ENV_FILE, is bind-auth, bind-recursive or dnsmasq (got '${role}')" ;;
esac
ntp=0
if [ -f "$BOOT/chrony.conf" ]; then ntp=1; fi
[ -n "$role" ] || [ "$ntp" = 1 ] || die "nothing to serve: no DNS role (ROLE, or DNS_ROLE in $ENV_FILE) and no chrony.conf in $BOOT"
tls=$(envget TLS_DIR)
tsig=$(envget TSIG_DIR)

SFAB_DRY_RUN=$DRY "$NET_INIT" "$ENV_FILE"

what=""
if [ -n "$role" ]; then what="$role"; fi
if [ "$ntp" = 1 ]; then what="${what:+$what and }time"; fi
if [ "$DRY" = 1 ]; then
  if [ -n "$role" ]; then printf '+ ROLE=%s TSIG_DIR=%s sfab-dns start %s\n' "$role" "${tsig:-/sfab/tsig}" "$BOOT"; fi
  if [ "$ntp" = 1 ]; then printf '+ TLS_DIR=%s sfab-ntp start %s\n' "${tls:-}" "$BOOT"; fi
  printf '+ write %s\n' "$READY"
  exit 0
fi
if [ -n "$role" ]; then ROLE=$role TSIG_DIR=${tsig:-/sfab/tsig} sfab-dns start "$BOOT"; fi
if [ "$ntp" = 1 ]; then TLS_DIR=$tls "$NTP" start "$BOOT"; fi
mkdir -p "$(dirname "$READY")"
printf '%s %s\n' "${role:-none} ntp=$ntp" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$READY"
log "serving $what from $BOOT"
