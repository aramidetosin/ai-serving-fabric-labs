#!/usr/bin/env bash
# resolver-run.sh: the main process of sfab/resolver, under tini. It holds the container up and,
# once sfab-init.sh (the topology's exec) has started the servers and written
# /run/sfab/resolver.ready, starts a server again whenever it is not running (every 10 s): the DNS
# server when the node has a DNS role, chronyd when the render holds chrony.conf.
#
#   TERM or INT   stop the servers and exit 0, so docker stop is prompt
#   HUP           sfab-dns reload: re-check and re-install the DNS render (after make render)
#   --health      the image's HEALTHCHECK: healthy once ready and while every server it runs runs
set -uo pipefail

READY=${SFAB_READY_FILE:-/run/sfab/resolver.ready}
BOOT=${SFAB_BOOTSTRAP:-/sfab/bootstrap}
NTP=${SFAB_NTP:-/usr/local/bin/sfab-ntp}
POLL=10

log() { printf '[resolver] %s\n' "$*"; }
envget() { sed -n "s/^$1=//p" "$BOOT/init.env" 2>/dev/null | tr -d "'\""; }
has_dns() { [ -n "${ROLE:-$(envget DNS_ROLE)}" ]; }
has_ntp() { [ -f "$BOOT/chrony.conf" ]; }

stop() {
  log "stopping the servers"
  if has_dns; then sfab-dns stop "$BOOT" >/dev/null 2>&1 || true; fi
  "$NTP" stop >/dev/null 2>&1 || true
  exit 0
}

reload() {
  [ -f "$READY" ] || { log "SIGHUP before sfab-init.sh ran: nothing to reload"; return 0; }
  has_dns || { log "SIGHUP: no DNS role, nothing to reload"; return 0; }
  log "SIGHUP: re-installing the render"
  TSIG_DIR=$(envget TSIG_DIR) sfab-dns reload "$BOOT" || log "warning: the reload failed; the previous configuration still serves"
}

health() {
  [ -f "$READY" ] || { echo "sfab-init.sh has not run"; return 1; }
  if has_dns; then sfab-dns running "$BOOT" || { echo "the DNS server is not running"; return 1; }; fi
  if has_ntp; then "$NTP" running || { echo "chronyd is not running"; return 1; }; fi
  echo healthy
}

case ${1:-} in
  --health) health; exit $? ;;
  "") ;;
  *) printf 'usage: resolver-run.sh [--health]\n' >&2; exit 2 ;;
esac

trap stop TERM INT
trap reload HUP
while :; do
  if [ -f "$READY" ]; then
    if has_dns && ! sfab-dns running "$BOOT"; then
      log "the DNS server is not running: starting it"
      TSIG_DIR=$(envget TSIG_DIR) sfab-dns start "$BOOT" || log "warning: sfab-dns start failed"
    fi
    if has_ntp && ! "$NTP" running; then
      log "chronyd is not running: starting it"
      TLS_DIR=$(envget TLS_DIR) "$NTP" start "$BOOT" || log "warning: sfab-ntp start failed"
    fi
  fi
  sleep "$POLL" &
  wait $! || true
done
