#!/usr/bin/env bash
# up.sh: deploy the lab (FRAMEWORK.md 3.2).
#
# 1. When every container is running with every expected ethN up, up acts on nothing. When some
#    of the lab's containers exist but not all (or their links are gone), it runs down.sh fast
#    first: links are always redeployed, never adopted.
# 2. state/shared/hold-guests holds the VM guests before their link wait until boot releases them
#    after wait_fabric. The hold lasts while the run that made it lives (run.sh removes it on
#    exit; up.sh run on its own removes it on exit unless boot is to follow).
# 3. The memory watchdog runs as its own transient unit, <lab>-memwatch, so it outlives the caller.
# 4. The state/ directories and files gen/clab-state.json names are made or checked, then
#    containerlab deploy -t topo.clab.yml --reconfigure --max-workers <node count>, under the
#    host-wide lock, never wrapped in timeout (a SIGTERM tears the lab down), with the lab's
#    state/secrets.env in the environment for containerlab's ${SFAB_*} expansion.
# 5. Every container must then be running.
#
# Before the deploy, when the inventory turns ca_init on: the lab CA on the lab host (common/ca/sfab-ca
# init, outside every node): the root once, the intermediates, the node leaves the topology binds
# (state/tls/<node>: the registry's and the time reference's certificates must exist when those
# containers start) and the lab root in state/shared/ca, then the CA's proof.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init up "$@"

[ -f "$TOPO" ] || die "no $TOPO: run make render"

hold_guests() {
  [ "$STAGE_GUEST_HOLD" = 1 ] || return 0
  mkdir -p "$STATEDIR/shared"
  : >"$STATEDIR/shared/hold-guests"
  echo "up: guests held (state/shared/hold-guests) until boot releases them"
  if [ "${SFAB_IN_RUN:-0}" != 1 ]; then
    trap 'rm -f "$STATEDIR/shared/hold-guests"' EXIT
  fi
}

start_memwatch() {
  local unit="$LAB-memwatch" wd="$SFAB_COMMON/host/mem-watchdog.sh"
  if ! have systemd-run; then
    warn "no systemd-run: the memory watchdog is not running"
    return 0
  fi
  if systemctl is-active --quiet "$unit.service" 2>/dev/null; then
    echo "up: $unit already running"
    return 0
  fi
  if [ ! -x "$wd" ]; then
    warn "$wd is not present: the memory watchdog is not running"
    return 0
  fi
  systemctl reset-failed "$unit.service" >/dev/null 2>&1 || true
  systemd-run --quiet --unit="$unit" --collect \
    --setenv=SFAB_INV="$INV" --setenv=SFAB_LABDIR="$LABDIR" --setenv=VARIANT="$VARIANT" \
    "$wd" "$LAB"
  echo "up: started $unit"
}

# prepare: what gen/clab-state.json (render/clab.py) says must exist before containerlab binds it:
# the state/ directories (made here), the state/ files (made by preflight's secrets step) and the
# SFAB_ variables the topology expands (each must have a value in state/secrets.env). Only paths
# under state/ are ever created.
prepare() {
  local cs="$RENDERDIR/gen/clab-state.json" probs
  [ -f "$cs" ] || { warn "no gen/clab-state.json: nothing to prepare"; return 0; }
  probs="$(py - "$cs" "$RENDERDIR" "$STATEDIR/secrets.env" "$LAB" <<'PY2'
import json, os, sys
cs, render, env, lab = sys.argv[1:5]
d = json.load(open(cs))
probs = []
if d.get("lab") != lab:
    probs.append(f"gen/clab-state.json is for {d.get('lab')}, not {lab}")
state = os.path.realpath(os.path.join(render, "state"))
def inside(rel):
    p = os.path.realpath(os.path.join(render, rel))
    return p if (p == state or p.startswith(state + os.sep)) else None
for rel in d.get("dirs") or []:
    p = inside(rel)
    if p is None:
        probs.append(f"refusing to create {rel}: not under state/")
    else:
        os.makedirs(p, exist_ok=True)
for rel in d.get("files") or []:
    p = inside(rel)
    if p is None or not os.path.isfile(p):
        probs.append(f"{rel} is missing (preflight makes it)")
have = {}
try:
    for line in open(env):
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.strip().split("=", 1)
            have[k] = v
except OSError:
    pass
for k in d.get("env") or []:
    if not have.get(k):
        probs.append(f"{k} has no value in state/secrets.env")
print("\n".join(probs))
PY2
)" || die "cannot read $cs"
  [ -z "$probs" ] || die "not ready to deploy: $(printf '%s' "$probs" | paste -sd ';' -)"
  echo "up: state/ prepared from gen/clab-state.json"
}

deploy() {
  if all_running && links_intact 2>/dev/null; then
    echo "up: every container of $LAB is running with its links; nothing to deploy"
    start_memwatch
    return 0
  fi
  if any_exists; then
    echo "up: $LAB is partly present or its links are gone: down fast first"
    "$SFAB_COMMON/stages/down.sh" fast
  fi
  [ -s "$STATEDIR/secrets.env" ] || die "no $STATEDIR/secrets.env: run preflight first"
  prepare
  hold_guests
  start_memwatch
  host_lock
  echo "up: containerlab deploy $LAB, ${#NODES[@]} nodes, ${#NODES[@]} workers ($(utc))"
  local rc=0
  (
    cd "$RENDERDIR"
    set -a
    # shellcheck disable=SC1091 # the lab's own secrets, made by preflight
    . "$STATEDIR/secrets.env"
    set +a
    clab deploy -t "$TOPO" --reconfigure --max-workers "${#NODES[@]}"
  ) || rc=$?
  host_unlock
  [ "$rc" -eq 0 ] || die "containerlab deploy exited $rc"
  local n down=()
  for n in "${NODES[@]}"; do running "$n" || down+=("$n"); done
  [ ${#down[@]} -eq 0 ] || die "not running after deploy: ${down[*]}"
  echo "up: all ${#NODES[@]} containers running ($(utc))"
}

# ca_init: no marker, every run: sfab-ca is idempotent and acts only on what is due, and a lab
# whose state/ca or state/tls was wiped must have them again before containerlab binds them.
ca_init() {
  local log
  mkdir -p "$STATEDIR/logs"
  log="$STATEDIR/logs/ca-init-$(utc_compact).txt"
  if ! "$SFAB_COMMON/ca/sfab-ca" -C "$RENDERDIR" init >"$log" 2>&1; then
    die "sfab-ca init failed on the lab host: $(grep -m 1 -E '^  FAIL |FAIL:' "$log" || tail -n 1 "$log")"
  fi
  echo "up: the lab CA made or checked on the lab host (state/ca), its root and node leaves published ($(grep -c '^  PASS ' "$log") proof lines passed)"
}

if [ "${STAGE_CA_INIT:-0}" = 1 ]; then ca_init; fi
stage_step up deploy deploy
