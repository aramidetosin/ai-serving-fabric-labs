#!/usr/bin/env bash
# vpngw-run.sh: the main process of sfab/vpngw, under tini. It holds the container up and, once
# sfab-init.sh (the topology's exec) has installed the tunnel's configuration and written
# /run/sfab/vpngw.ready, starts charon, loads every connection and key with swanctl, and starts
# charon again whenever it is not running (every 10 s).
#
#   TERM or INT   stop charon and exit 0, so docker stop is prompt
#   HUP           swanctl --load-all again (after make render and sfab-init.sh)
#   --health      the image's HEALTHCHECK: healthy once ready and while charon runs
set -uo pipefail

READY=${SFAB_READY_FILE:-/run/sfab/vpngw.ready}
POLL=10
CHARON=${SFAB_CHARON:-/usr/lib/strongswan/charon}

log() { printf '[vpngw] %s\n' "$*"; }
# charon is started by its full path, and BusyBox pgrep -x matches the whole argv[0], so
# `pgrep -x charon` never finds it. A charon is running when any process's name is charon: its
# pid file appears only some time after it starts, so reading the pid file alone let the loop
# start a second charon beside a starting one (which refused, "charon already running") and, worse,
# delete the live daemon's vici socket, after which swanctl could reach no charon at all.
running() {
  local d
  for d in /proc/[0-9]*; do
    [ "$(cat "$d/comm" 2>/dev/null)" = charon ] && return 0
  done
  return 1
}

start() {
  if ! running; then
    # A charon that died leaves its pid file and sockets behind: clear them so the wait below
    # sees the new daemon's socket, not the old one. Only when no charon process exists.
    rm -f /var/run/charon.pid /var/run/charon.vici /var/run/charon.ctl
    "$CHARON" >>/var/log/charon.log 2>&1 &
  fi
  local i
  for i in $(seq 1 30); do
    running && [ -S /var/run/charon.vici ] && break
    sleep 1
  done
  swanctl --load-all --noprompt >/var/log/swanctl-load.log 2>&1 || log "warning: swanctl --load-all failed (/var/log/swanctl-load.log)"
}

stop() {
  log "stopping charon"
  pkill -x charon 2>/dev/null || true
  exit 0
}

health() {
  [ -f "$READY" ] || { echo "sfab-init.sh has not run"; return 1; }
  running || { echo "charon is not running"; return 1; }
  echo healthy
}

case ${1:-} in
  --health) health; exit $? ;;
  "") ;;
  *) printf 'usage: vpngw-run.sh [--health]\n' >&2; exit 2 ;;
esac

trap stop TERM INT
trap 'log "SIGHUP: loading the connections again"; swanctl --load-all --noprompt >/var/log/swanctl-load.log 2>&1 || true' HUP
log "waiting for sfab-init.sh"
while :; do
  if [ -f "$READY" ] && ! running; then
    log "starting charon"
    start
  fi
  sleep "$POLL" &
  wait $!
done
