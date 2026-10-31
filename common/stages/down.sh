#!/usr/bin/env bash
# down.sh [fast|wipe] [--verify]: take the lab down (FRAMEWORK.md 3.5).
#
#   (default)  stop.sh first, then destroy
#   fast       destroy without the ordered power-off
#   wipe       stop.sh, destroy, then remove state/nodes/*, state/shared/, state/ca/ (the lab CA,
#              made on the lab host), state/tls/ (its node leaves), state/operators/ (the operators'
#              kubeconfigs), state/secrets.env, the TSIG keys and the stage markers
#
# Destroy is `containerlab destroy -t topo.clab.yml`, never --cleanup and never --all, under the
# host-wide lock; then rm -rf of ./clab-<lab> only when its basename is exactly clab-<lab>, docker
# rm -f of each inventory container, a sweep of the exact <lab>- prefix, and the lab's memory
# watchdog unit stopped. Nothing outside the lab is touched. --verify records the teardown checks
# (no <lab>- container, no clab-<lab>/, the <lab>-memwatch unit not running, state/ disks kept
# unless wiped) as a result set.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

mode=default
verify=0
rest=()
for a in "$@"; do
  case "$a" in
    fast|wipe|default) mode="$a" ;;
    --verify) verify=1 ;;
    *) rest+=("$a") ;;
  esac
done
if [ "$verify" = 1 ]; then sfab_init teardown "${rest[@]}"; else sfab_init down "${rest[@]}"; fi

if [ "$mode" != fast ] && any_exists; then
  "$SFAB_COMMON/stages/stop.sh"
fi

host_lock
if [ -f "$TOPO" ] && any_exists; then
  echo "down: containerlab destroy $LAB"
  (cd "$RENDERDIR" && clab destroy -t "$TOPO") || echo "down: containerlab destroy exited $?; sweeping by name"
fi
host_unlock

if [ -d "$CLABDIR" ]; then
  if [ "$(basename "$CLABDIR")" = "clab-$LAB" ] && [ "$(dirname "$CLABDIR")" = "$RENDERDIR" ]; then
    rm -rf -- "$CLABDIR"
    echo "down: removed $(basename "$CLABDIR")/"
  else
    die "refusing to remove $CLABDIR: not clab-$LAB under $RENDERDIR"
  fi
fi

for n in "${NODES[@]}"; do
  c="$(ctr "$n")"
  if dk inspect -f '{{.Name}}' "$c" >/dev/null 2>&1; then
    dk rm -f "$c" >/dev/null && echo "down: removed $c"
  fi
done
while read -r c; do
  [ -n "$c" ] || continue
  dk rm -f "$c" >/dev/null && echo "down: swept $c"
done < <(lab_containers)

if have systemctl; then
  u="$LAB-memwatch"
  if systemctl is-active --quiet "$u.service" 2>/dev/null; then
    systemctl stop "$u.service" && echo "down: stopped $u"
  fi
  systemctl reset-failed "$u.service" >/dev/null 2>&1 || true
fi
rm -f "$STATEDIR/shared/hold-guests" "$STATEDIR"/stage/*.ok

if [ "$mode" = wipe ]; then
  rm -rf -- "${STATEDIR:?}/nodes/"* "${STATEDIR:?}/shared" "${STATEDIR:?}/ca" "${STATEDIR:?}/tls" "${STATEDIR:?}/operators" \
    "${STATEDIR:?}/secrets.env" "${STATEDIR:?}/secrets/tsig" "${STATEDIR:?}/stage"
  rm -f "$STATEDIR/secrets/fw-api.hdr" "$STATEDIR/secrets/fw-api.started"
  echo "down: wiped state/nodes, state/shared, state/ca, state/tls, state/operators, state/secrets.env, the TSIG keys and the stage markers"
fi

sec "teardown $LAB ($mode)"
left="$(lab_containers | paste -sd ' ' -)"
if [ -z "$left" ]; then ok "no $PREFIX* container remains"; else bad "no $PREFIX* container remains" "$left"; fi
if [ -e "$CLABDIR" ]; then bad "no clab-$LAB/ remains" "$CLABDIR exists"; else ok "no clab-$LAB/ remains"; fi
if ! have systemctl; then
  skip "the memory watchdog unit $LAB-memwatch is not running" "no systemctl on this host"
elif systemctl is-active --quiet "$LAB-memwatch.service" 2>/dev/null; then
  bad "the memory watchdog unit $LAB-memwatch is not running" "the unit is still active"
else
  ok "the memory watchdog unit $LAB-memwatch is not running"
fi
if [ "$mode" = wipe ]; then
  if [ -z "$(ls -A "$STATEDIR/nodes" 2>/dev/null)" ]; then ok "state/nodes emptied by wipe"; else bad "state/nodes emptied by wipe" "files remain"; fi
elif [ -d "$STATEDIR/nodes" ] && [ -n "$(ls -A "$STATEDIR/nodes" 2>/dev/null)" ]; then
  ok "state/ disks kept until wipe ($(du -sh "$STATEDIR/nodes" 2>/dev/null | cut -f1))"
else
  skip "state/ disks kept until wipe" "this lab has no state/nodes yet"
fi
summary
