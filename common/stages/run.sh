#!/usr/bin/env bash
# run.sh STAGE...: run a lab's stages in order (FRAMEWORK.md section 3).
#
# Stages: preflight up boot finish audit trace label matrix dbs rpf attach stop down down-fast wipe, and
# recover (boot then finish); label, matrix, dbs, rpf and attach run the lab's script of that name. status
# prints the lab's containers and markers and takes no lock. Run from the lab directory (make does),
# or with SFAB_LABDIR set; VARIANT selects a variant lab.
#
# The run holds flock state/lock for its whole length (a second run of the same lab is refused);
# up and down take the host-wide /run/lock/sfab.lock around containerlab themselves. Each stage is
# logged to state/logs/<stage>-<UTC>.log and its duration kept in state/stage/durations.json for
# the next result set's RUN.json. The first stage that fails stops the run. When the run ends, for
# any reason, the guest hold up.sh made is removed, so no guest waits past the run that held it.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
[ $# -gt 0 ] || die "usage: run.sh STAGE... (preflight up boot finish audit trace label matrix dbs rpf attach stop down down-fast wipe recover status)"
sfab_init run

status() {
  local n c st h
  printf '%-12s %-28s %-10s %-10s %s\n' NODE CONTAINER STATE HEALTH STARTED
  for n in "${NODES[@]}"; do
    c="$(ctr "$n")"
    st="$(state_of "$n")"
    h="$(health_of "$n")"
    if [ "$st" = missing ]; then
      printf '%-12s %-28s %-10s %-10s %s\n' "$n" "$c" absent - -
    else
      printf '%-12s %-28s %-10s %-10s %s\n' "$n" "$c" "$( [ "${st##* }" = true ] && echo running || echo stopped)" "$h" "${st% *}"
    fi
  done
  echo
  local markers
  markers="$(find "$STATEDIR/stage" -maxdepth 1 -name '*.ok' 2>/dev/null | sed 's:.*/::; s/\.ok$//' | sort | paste -sd ' ' -)"
  echo "markers: ${markers:-none}"
  [ ! -f "$STATEDIR/shared/hold-guests" ] || echo "guests held: state/shared/hold-guests"
  if [ -d "$RENDERDIR/audits" ]; then
    echo "latest result sets:"
    find "$RENDERDIR/audits" -mindepth 1 -maxdepth 1 -type d -name "${LAB}_*" | sort | tail -n 5 | while read -r d; do
      printf '  %s  %s\n' "$(basename "$d")" "$(grep -h '^== RESULT' "$d/RESULT.txt" 2>/dev/null | tail -n 1)"
    done
  fi
}

stages=()
for s in "$@"; do
  case "$s" in
    recover) stages+=(boot finish) ;;
    status) status; exit 0 ;;
    preflight|up|boot|finish|audit|trace|label|matrix|dbs|rpf|attach|stop|down|down-fast|wipe) stages+=("$s") ;;
    *) die "unknown stage $s" ;;
  esac
done

exec 8>"$STATEDIR/lock"
flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"
export SFAB_IN_RUN=1 SFAB_RUN_STAGES="${stages[*]}"
trap 'rm -f "$STATEDIR/shared/hold-guests"' EXIT

# record_duration STAGE SECONDS: into state/stage/durations.json, the directory made again when
# missing (wipe removes it with the stage markers; ch04/RESULTS.md, problem 6)
record_duration() {
  py - "$STATEDIR/stage/durations.json" "$1" "$2" <<'PY'
import json, os, sys
p, stage, secs = sys.argv[1], sys.argv[2], int(sys.argv[3])
os.makedirs(os.path.dirname(p), exist_ok=True)
try:
    d = json.load(open(p))
except (OSError, ValueError):
    d = {}
d[stage] = secs
json.dump(d, open(p, "w"), indent=2, sort_keys=True)
PY
}

for st in "${stages[@]}"; do
  args=()
  case "$st" in
    preflight|up|boot|finish|stop) cmd=("$SFAB_COMMON/stages/$st.sh") ;;
    down) cmd=("$SFAB_COMMON/stages/down.sh") ;;
    down-fast) cmd=("$SFAB_COMMON/stages/down.sh"); args=(fast) ;;
    wipe) cmd=("$SFAB_COMMON/stages/down.sh"); args=(wipe) ;;
    audit|trace|label|matrix|dbs|rpf|attach)
      [ -x "$LABDIR/$st.sh" ] || die "$LABDIR/$st.sh is not present"
      cmd=("$LABDIR/$st.sh") ;;
  esac
  log="$STATEDIR/logs/$st-$(utc_compact).log"
  printf '== stage %s %s (log %s)\n' "$st" "$(utc)" "${log#"$RENDERDIR"/}"
  t0=$SECONDS
  rc=0
  "${cmd[@]}" "${args[@]}" 2>&1 | tee -a "$log" || rc=${PIPESTATUS[0]}
  record_duration "$st" "$((SECONDS - t0))"
  if [ "$rc" -ne 0 ]; then
    printf '== stage %s failed (exit %s) after %ss\n' "$st" "$rc" "$((SECONDS - t0))"
    exit "$rc"
  fi
  printf '== stage %s done in %ss\n' "$st" "$((SECONDS - t0))"
done
