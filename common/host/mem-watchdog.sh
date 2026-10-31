#!/usr/bin/env bash
# common/host/mem-watchdog.sh LAB [--once] [--dry-run]: the lab's memory watchdog (FRAMEWORK.md 3.2).
#
# up.sh starts it as the transient unit <lab>-memwatch (systemd-run), so it outlives the run that
# started it and dies with nothing but its own unit; down.sh stops that unit. It refuses unless LAB
# is the lab the inventory names (SFAB_LABDIR, SFAB_INV and VARIANT come from the unit's env).
#
# Every SFAB_MEMWATCH_POLL_S (default 20) seconds it reads MemAvailable. Below the floor (the
# inventory's watchdog.floor_gib, the spec's 16 GiB) it stops the next running guest in the
# inventory's victim order (watchdog.order: the highest-numbered GPU guest first, then the other VM
# guests, highest-numbered first): restart policy off, then docker stop -t 3, which lets QEMU go
# before the kernel's OOM killer picks something on the shared host. One guest per poll, so the host
# gets a poll to recover before the next one goes. Switches, the firewall, storage and the
# containers are never victims, and only this lab's containers are touched, by exact name (lib.sh's
# dk refuses any other).
#
# It logs to stdout (the unit's journal) and to state/logs/memwatch.log, and exits by itself once the
# lab's containers, seen at least once, have all been gone for three polls in a row, or when none
# has appeared within SFAB_MEMWATCH_GRACE_S (900) of its start (up starts it before the deploy,
# which may first wait for the host-wide lock).
#
#   --once     one poll, then exit (a manual check; the tests)
#   --dry-run  say which guest it would stop, and stop nothing
# SFAB_MEMINFO names another meminfo file (the tests).
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

want_lab=""
once=0
dry=0
rest=()
for a in "$@"; do
  case "$a" in
    --once) once=1 ;;
    --dry-run) dry=1 ;;
    -*) rest+=("$a") ;;
    *) if [ -z "$want_lab" ]; then want_lab="$a"; else rest+=("$a"); fi ;;
  esac
done
sfab_init memwatch "${rest[@]+"${rest[@]}"}"
[ -n "$want_lab" ] || die "usage: mem-watchdog.sh LAB [--once] [--dry-run]"
[ "$want_lab" = "$LAB" ] || die "mem-watchdog: asked to watch $want_lab, but $INV is $LAB: refusing"

MEMINFO="${SFAB_MEMINFO:-/proc/meminfo}"
POLL="${SFAB_MEMWATCH_POLL_S:-20}"
LOG="$STATEDIR/logs/memwatch.log"
FLOOR_GIB="$(inv get watchdog.floor_gib 2>/dev/null || true)"
[ -n "$FLOOR_GIB" ] || FLOOR_GIB="$(inv get budget.floor_gib 2>/dev/null || echo 16)"
FLOOR_KB="$(awk -v g="$FLOOR_GIB" 'BEGIN { printf "%d", g * 1024 * 1024 }')"

wlog() {
  local line
  line="$(utc) $LAB memwatch: $*"
  printf '%s\n' "$line"
  printf '%s\n' "$line" >>"$LOG"
}

avail_kb() { awk '$1 == "MemAvailable:" { print $2; found = 1 } END { if (!found) print -1 }' "$MEMINFO"; }

# the next victim: the first guest in the order whose container is running
next_victim() {
  local n
  for n in "${WATCH_ORDER[@]+"${WATCH_ORDER[@]}"}"; do
    [ -n "${NODE_CTR[$n]:-}" ] || continue
    if running "$n"; then printf '%s\n' "$n"; return 0; fi
  done
  return 1
}

poll() {
  local a v c
  a="$(avail_kb)"
  if [ "$a" -lt 0 ]; then
    wlog "no MemAvailable in $MEMINFO: nothing judged"
    return 0
  fi
  [ "$a" -lt "$FLOOR_KB" ] || return 0
  if ! v="$(next_victim)"; then
    wlog "MemAvailable $((a / 1024)) MiB is below the floor ($FLOOR_GIB GiB), and no guest of $LAB is left running to stop"
    return 0
  fi
  c="$(ctr "$v")"
  if [ "$dry" = 1 ]; then
    wlog "MemAvailable $((a / 1024)) MiB is below the floor ($FLOOR_GIB GiB): would stop $c (dry run)"
    return 0
  fi
  wlog "MemAvailable $((a / 1024)) MiB is below the floor ($FLOOR_GIB GiB): stopping $c"
  dk update --restart=no "$c" >/dev/null 2>&1 || true
  if dk stop -t 3 "$c" >/dev/null 2>&1; then wlog "stopped $c"; else wlog "docker stop $c failed"; fi
}

wlog "watching: floor $FLOOR_GIB GiB, victims in order: ${WATCH_ORDER[*]:-none}, poll ${POLL}s, meminfo $MEMINFO$([ "$dry" = 1 ] && echo ', dry run')"
GRACE="${SFAB_MEMWATCH_GRACE_S:-900}"
gone=0
seen=0
t0=$SECONDS
while :; do
  poll
  [ "$once" = 0 ] || break
  if any_exists; then
    seen=1 gone=0
  elif [ "$seen" = 1 ]; then
    gone=$((gone + 1))
    if [ "$gone" -ge 3 ]; then
      wlog "no container of $LAB for three polls: the lab is down, watchdog off"
      break
    fi
  elif [ $((SECONDS - t0)) -ge "$GRACE" ]; then
    wlog "no container of $LAB appeared within ${GRACE}s of the start: watchdog off"
    break
  fi
  sleep "$POLL"
done
