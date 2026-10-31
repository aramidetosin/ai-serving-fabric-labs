# shellcheck shell=bash
# common/drill/lib-servedrill.sh: chapter 6's serving drills (FRAMEWORK.md section 4.6 as chapter 6
# uses it), sourced by a chapter's drills.sh after lib.sh's sfab_init drills, which opened
# audits/<lab>_drills_<UTC>/. The plan is gen/drills.json (sfab.render.drills: serve-dark,
# worker-port and rail-move drills).
#
#   servedrills_main            --drills "ID ..." --passes N: every pass runs every drill, then
#                               servedrill.py summarize writes DRILLS.md
#   servedrill_fault PASS ID    a dark switch or a worker's port, one pass, into pass<PASS>/<ID>/
#   servedrill_move PASS ID     a worker moved in the table, one pass
#
# A fault drill, in order, every time on the lab host's clock (date +%s.%N here; the gateway probe
# stamps its requests in the client container, whose clock is the host's):
#   1. whole     every pod of the table Ready, every Service holding its servers, every rail switch's
#                rendered ports up, in two consecutive polls 5 s apart; else the drill is not run
#   2. probes    the endpoints probe: the serving namespace's EndpointSlices read from the lab host with the harness's kubectl (on the init node)
#                every interval, each read stamped when it began and ended (endpoints.jsonl); the
#                gateway probe: each model's key handed to the client (lib-servecap.sh), then
#                probe_gateway.py in the client, one chat completion a model every interval through
#                the Gateway's model route, each on its own; both run lead_s before the fault
#   3. the fault the restore pushed first (no shutdown, run from the EXIT trap whatever happens); one
#                KLISH session on the rail switch: every port it uses (dark) or the one port facing
#                the worker's node on the copy's rail (worker-port), shutdown; the session's start and
#                return stamped (INJECT, INJECTED)
#   4. down      at half the hold: show interface status on the switch, the pods and the Services'
#                endpoints as kubectl prints them, and the faced nodes' rail NICs as their kernels see
#                them (a KLISH shutdown drops no carrier there)
#   5. restore   at hold_s: the restore's session, stamped (RESTORE, RESTORED); then until every
#                Service holds all its servers again (RETURNED), return_max_s at most, then tail_s
#   6. stop      the gateway probe stopped (its requests in flight answered or timed out) and its
#                records fetched; the endpoints probe stopped; the keys removed from the client
#   7. after     the serving and inference namespaces' Warning events saved and cleared (the
#                readiness failures are the drill's evidence); the whole check again; parity on the
#                switch; audit.sh --quick; servedrill.py analyze
#
# A rail-move drill changes nothing in the cluster: the table with one worker's row moved
# (servedrill.py moved-env), the recipe rendering the manifests from it (it refuses the table),
# audit.sh --quick against it (its placement group fails), then audit.sh --quick against the table
# as rendered (green).
#
# Nothing here uses docker pause or takes a link down from the container side; the fault is a KLISH
# shutdown inside the switch, and the restore its no shutdown.

SDP="$SFAB_COMMON/drill/servedrill.py"
SD_PLAN="$RENDERDIR/gen/drills.json"
SD_DIR=/tmp/sfab-drill-probe
SD_RESTORES=()
# shellcheck source=common/trace/lib-servecap.sh
. "$SFAB_COMMON/trace/lib-servecap.sh"

sd_get() { py "$SDP" get --plan "$SD_PLAN" "$1"; }
sd_now() { date +%s.%N; }
sd_tl() { printf '%s %s\n' "$(sd_now)" "$*" >>"$D/timeline.txt"; }
sd_sleep_until() { local s; s="$(py -c 'import sys, time; print(max(0.0, float(sys.argv[1]) - time.time()))' "$1")"; sleep "$s"; }
sd_add() { py -c 'import sys; print(float(sys.argv[1]) + float(sys.argv[2]))' "$1" "$2"; }

sd_restore_add() { SD_RESTORES+=("$*"); }
sd_restore_run() {
  local i
  for ((i = ${#SD_RESTORES[@]} - 1; i >= 0; i--)); do
    eval "${SD_RESTORES[$i]}" || warn "drill: restore '${SD_RESTORES[$i]}' failed"
  done
  SD_RESTORES=()
}
sd_cleanup() {
  sd_restore_run
  sd_probes_stop quiet || true
}

# --------------------------------------------------------------------------------------------
# the serving layer whole

# sd_poll DIR: one poll: the serving pods and EndpointSlices, every rail switch's show interface status
sd_poll() {
  local dir="$1" sns sw
  rm -rf "$dir"
  mkdir -p "$dir"
  sns="$(sd_get serving.namespace)"
  EVID_OFF=1 K -n "$sns" get pods -o json >"$dir/pods.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$sns" get endpointslices -o json >"$dir/endpointslices.json" 2>/dev/null || true
  for sw in $(py -c 'import json, sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["rail_switches"])))' "$SD_PLAN"); do
    EVID_OFF=1 SW "$sw" "show interface status" 2>/dev/null | klish_body "show interface status" >"$dir/$sw-status.txt" 2>/dev/null || true
  done
  py "$SDP" whole --plan "$SD_PLAN" --dir "$dir" >"$dir/whole.txt" 2>&1
}

# sd_whole LABEL DIR: two consecutive polls 5 s apart with the serving layer whole
sd_whole() {
  local label="$1" dir="$2" polls good=0 i
  polls="$(sd_get timing.whole_polls)"
  for i in $(seq 1 "$polls"); do
    if sd_poll "$dir"; then
      good=$((good + 1))
      [ "$good" -ge 2 ] && break
    else
      good=0
    fi
    sleep "${SFAB_DRILL_POLL_S:-5}"
  done
  if [ "$good" -ge 2 ]; then
    ok "$label: every pod of the table Ready, every Service holding its servers, every rail switch's rendered ports up (poll $i)"
    return 0
  fi
  bad "$label" "$(cat "$dir/whole.txt" 2>/dev/null || echo 'no poll read')"
  return 1
}

# --------------------------------------------------------------------------------------------
# the probes

sd_endpoints_start() {
  local iv sns b
  iv="$(sd_get probes.endpoints.interval_s)" sns="$(sd_get probes.endpoints.namespace)"
  : >"$D/endpoints.jsonl"
  rm -f "$D/.endpoints-stop"
  (
    while [ ! -e "$D/.endpoints-stop" ]; do
      t0="$(sd_now)"
      out="$(EVID_OFF=1 K -n "$sns" get endpointslices -o json 2>/dev/null || true)"
      t1="$(sd_now)"
      printf '%s' "$out" | py "$SDP" epline --t0 "$t0" --t1 "$t1" >>"$D/endpoints.jsonl" 2>/dev/null || true
      sd_sleep_until "$(sd_add "$t0" "$iv")"
    done
  ) &
  SD_EP_PID=$!
}

sd_endpoints_stop() {
  [ -n "${SD_EP_PID:-}" ] || return 0
  touch "$D/.endpoints-stop"
  wait "$SD_EP_PID" 2>/dev/null || true
  rm -f "$D/.endpoints-stop"
  SD_EP_PID=""
}

# sd_probes_start: the endpoints probe on the lab host, the gateway probe in the client
sd_probes_start() {
  local client models m mn mu targets=() pin=() iv to mt
  client="$(sd_get probes.gateway.client)"
  iv="$(sd_get probes.gateway.interval_s)" to="$(sd_get probes.gateway.timeout_s)" mt="$(sd_get probes.gateway.max_tokens)"
  sd_endpoints_start
  mapfile -t models < <(py -c 'import json, sys; [print(m["model"], m["url"], m.get("every", 1)) for m in json.load(open(sys.argv[1]))["probes"]["gateway"]["models"]]' "$SD_PLAN")
  : >"$D/keys.txt"
  for m in "${models[@]}"; do
    read -r mn mu me <<<"$m"
    if key_to_client "$(sd_get probes.gateway.keys.namespace)" "$(sd_get probes.gateway.keys.secret)" "$mn" "$client" "$SD_DIR" >>"$D/keys.txt" 2>&1; then
      targets+=(--target "$mn" "$mu")
      [ "${me:-1}" = 1 ] || targets+=(--every "$mn" "$me")
    else
      bad "pass $PASS $DRILL_ID: the key for $mn handed to $client" "$(tail -n 1 "$D/keys.txt")"
    fi
  done
  [ -z "$(sd_get probes.gateway.resolve 2>/dev/null || true)" ] || pin=(--resolve "$(sd_get probes.gateway.resolve)")
  dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$SD_DIR/probe_gateway.py" <"$SFAB_COMMON/drill/probe_gateway.py"
  X "$client" sh -c "rm -f $SD_DIR/stop $SD_DIR/records-*.jsonl; nohup python3 $SD_DIR/probe_gateway.py --dir $SD_DIR $(printf '%q ' "${targets[@]}") --interval $iv --timeout $to --max-tokens $mt --until-stop $(qargs "${pin[@]+"${pin[@]}"}") >$SD_DIR/probe.out 2>&1 </dev/null &" >"$D/logs/probe-start.txt" 2>&1 || true
  SD_PROBING=1
  # each model as "MODEL URL EVERY": its URL and on which of the gateway probe's intervals it is sent
  sd_tl PROBES "gateway every ${iv} s: ${models[*]}; endpoints every $(sd_get probes.endpoints.interval_s) s"
}

sd_probes_stop() {
  local client to i m
  if [ "${SD_PROBING:-0}" = 1 ]; then
    client="$(sd_get probes.gateway.client)" to="$(sd_get probes.gateway.timeout_s)"
    dk exec "$(ctr "$client")" touch "$SD_DIR/stop" >/dev/null 2>&1 || true
    for i in $(seq 1 "$(py -c 'import math, sys; print(int(math.ceil(float(sys.argv[1]))) + 15)' "$to")"); do
      dk exec "$(ctr "$client")" sh -c "pgrep -f '[p]robe_gateway.py' >/dev/null" 2>/dev/null || break
      sleep 1
    done
    for m in $(py -c 'import json, sys; print(" ".join(m["model"] for m in json.load(open(sys.argv[1]))["probes"]["gateway"]["models"]))' "$SD_PLAN"); do
      dk exec "$(ctr "$client")" cat "$SD_DIR/records-$m.jsonl" >"$D/records-$m.jsonl" 2>/dev/null || true
    done
    dk exec "$(ctr "$client")" cat "$SD_DIR/probe.out" >"$D/logs/probe.out" 2>/dev/null || true
    key_clear "$client" "$SD_DIR"
    SD_PROBING=0
  fi
  sd_endpoints_stop
  [ "${1:-}" = quiet ] || sd_tl STOP probes
}

# --------------------------------------------------------------------------------------------
# snapshots and the fault

sd_snapshot() {
  local ph="$1" sw sns
  sw="$(sd_get "list.$DRILL_ID.switch")" sns="$(sd_get serving.namespace)"
  mkdir -p "$D/klish" "$D/cluster"
  SW "$sw" "show interface status" >"$D/klish/$ph-$sw.txt" 2>&1 || true
  K -n "$sns" get pods -o wide >"$D/cluster/pods-$ph.txt" 2>&1 || true
  K -n "$sns" get endpointslices -o wide >"$D/cluster/endpointslices-$ph.txt" 2>&1 || true
}

sd_links() {
  local n
  for n in $(py -c 'import json, sys; d = json.load(open(sys.argv[1])); print(" ".join(sorted({p["node"] for c in d["serving"]["copies"] for p in [c["server"]] + c["workers"]})))' "$SD_PLAN"); do
    H "$n" "ip -br link show | grep -E '^rail[0-9]'" >"$D/links-$1-$n.txt" 2>&1 || true
  done
}

sd_klish() {  # sd_klish KEY OUT: the drill's KLISH session (klish or restore); non-zero on % Error
  local key="$1" out="$2" sw
  sw="$(sd_get "list.$DRILL_ID.switch")"
  mapfile -t _lines < <(sd_get "list.$DRILL_ID.$key")
  SW "$sw" "${_lines[@]}" >"$out" 2>&1 || true
  ! grep -qE '%[[:space:]]?Error' "$out"
}

sd_unshut() { sd_klish restore "$D/restore.txt" || bad "pass $PASS $DRILL_ID: restore on $(sd_get "list.$DRILL_ID.switch")" "the switch answered % Error ($(grep -m1 -E '%[[:space:]]?Error' "$D/restore.txt"))"; }

sd_parity() {
  local sw="$1" norm=() prc=0
  [ ! -f "$RENDERDIR/gen/klish-normalize.json" ] || norm=(--normalize "$RENDERDIR/gen/klish-normalize.json")
  SW "$sw" "show running-configuration" | klish_body "show running-configuration" >"$D/running-$sw.txt" 2>/dev/null || true
  py "$SFAB_COMMON/klish/parity.py" "$RENDERDIR/bootstrap/$sw/startup-config.cfg" "$D/running-$sw.txt" --switch "$sw" "${norm[@]+"${norm[@]}"}" \
    --json "$D/parity-$sw.json" >"$D/parity-$sw.txt" 2>&1 || prc=$?
  if [ "$prc" -eq 0 ]; then
    ok "pass $PASS $DRILL_ID: $sw after the restore: parity, 0 missing lines"
  else
    bad "pass $PASS $DRILL_ID: $sw after the restore: parity" "$(grep -E '^ +missing \(' "$D/parity-$sw.txt" | head -n 2 | sed 's/^ *//' | paste -sd ';' -)"
    return 1
  fi
}

sd_quick_audit() {
  local out="$D/audit-quick.txt" res
  if [ "${SFAB_DRILL_AUDIT:-1}" = 0 ]; then
    skip "pass $PASS $DRILL_ID: audit.sh --quick after the drill" "SFAB_DRILL_AUDIT=0"
    return 0
  fi
  "$LABDIR/audit.sh" --quick >"$out" 2>&1 || true
  res="$(grep -E '^== RESULT: ' "$out" | tail -n 1 || true)"
  case "$res" in
    *", 0 failed,"*) ok "pass $PASS $DRILL_ID: audit.sh --quick after the drill: ${res#== }" ;;
    *) bad "pass $PASS $DRILL_ID: audit.sh --quick after the drill" "${res:-no RESULT line}" ;;
  esac
}

# --------------------------------------------------------------------------------------------
# one fault drill

servedrill_fault() {
  PASS="$1" DRILL_ID="$2"
  local title sw kind lead hold tail rmax t0 tr rc=0 ret natives
  D="$RS/pass$PASS/$DRILL_ID"
  mkdir -p "$D/logs"
  : >"$D/timeline.txt"
  title="$(sd_get "list.$DRILL_ID.title")" sw="$(sd_get "list.$DRILL_ID.switch")" kind="$(sd_get "list.$DRILL_ID.kind")"
  lead="$(sd_get timing.lead_s)" hold="$(sd_get timing.hold_s)" tail="$(sd_get timing.tail_s)" rmax="$(sd_get timing.return_max_s)"
  natives="$(sd_get "list.$DRILL_ID.natives" | paste -sd ',' -)"
  sec "pass $PASS, drill $DRILL_ID: $title"
  echo "drill: pass $PASS $DRILL_ID ($title)"
  if ! sd_whole "pass $PASS $DRILL_ID: the serving layer whole before the fault" "$D/whole-before"; then
    sd_tl ABORTED "the serving layer was not whole before the fault"
    return 1
  fi
  cp "$D/whole-before/pods.json" "$D/pods-before.json"
  sd_tl TARGET "$sw $natives; copies out: $(sd_get "list.$DRILL_ID.expect.dead_copies" | paste -sd ' ' -)"
  trap sd_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  sd_probes_start
  sd_sleep_until "$(sd_add "$(sd_now)" "$lead")"
  sd_snapshot before
  sd_restore_add sd_unshut
  t0="$(sd_now)"
  sd_tl INJECT "shutdown on $sw ($natives)"
  if sd_klish klish "$D/fault.txt"; then
    sd_tl INJECTED ok
    ok "pass $PASS $DRILL_ID: KLISH $(sd_get "list.$DRILL_ID.klish" | sed -n 2p), shutdown accepted on $sw ($natives)"
  else
    sd_tl INJECTED error
    bad "pass $PASS $DRILL_ID: KLISH shutdown on $sw" "$(grep -m1 -E '%[[:space:]]?Error' "$D/fault.txt")"
  fi
  sd_sleep_until "$(sd_add "$t0" "$(py -c 'import sys; print(float(sys.argv[1]) / 2)' "$hold")")"
  sd_snapshot during
  sd_links during
  sd_sleep_until "$(sd_add "$t0" "$hold")"
  sd_tl RESTORE "no shutdown on $sw"
  SD_RESTORES=()
  tr="$(sd_now)"
  if sd_klish restore "$D/restore.txt"; then
    sd_tl RESTORED ok
    ok "pass $PASS $DRILL_ID: no shutdown accepted on $sw after ${hold} s"
  else
    sd_tl RESTORED error
    bad "pass $PASS $DRILL_ID: no shutdown on $sw" "$(grep -m1 -E '%[[:space:]]?Error' "$D/restore.txt")"
    rc=2
  fi
  ret=""
  while py -c 'import sys, time; sys.exit(0 if time.time() < float(sys.argv[1]) else 1)' "$(sd_add "$tr" "$rmax")"; do
    if ret="$(py "$SDP" returned --plan "$SD_PLAN" --log "$D/endpoints.jsonl" --pods "$D/pods-before.json" --since "$tr")"; then
      break
    fi
    ret=""
    sleep "${SFAB_DRILL_POLL_S:-2}"
  done
  if [ -n "$ret" ]; then
    printf '%s RETURNED every Service holds all its servers\n' "$ret" >>"$D/timeline.txt"
    ok "pass $PASS $DRILL_ID: every Service held all its servers again $(py -c 'import sys; print(round(float(sys.argv[1]) - float(sys.argv[2]), 1))' "$ret" "$tr") s after the restore's session began"
  else
    bad "pass $PASS $DRILL_ID: every Service holding all its servers again" "not within ${rmax} s of the restore"
    rc=2
  fi
  sleep "$tail"
  sd_probes_stop
  trap - EXIT INT TERM
  sd_snapshot after
  events_archive "$D/events" "$(sd_get serving.namespace)" "$(sd_get serving.inference_namespace)"
  sd_whole "pass $PASS $DRILL_ID: the serving layer whole again after the drill" "$D/whole-after" || rc=2
  sd_parity "$sw" || rc=2
  sd_quick_audit
  py "$SDP" analyze --plan "$SD_PLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analyze.out"
  cat "$D/analysis.txt" 2>/dev/null || true
  known L9 "pass $PASS $DRILL_ID: a KLISH shutdown drops no carrier at the GPU NICs, so the dead rail shows only as silence: readiness over the rail is the only detector ($(cat "$D"/links-during-*.txt 2>/dev/null | awk '{print $1 "=" $2}' | paste -sd ' ' - | cut -c1-160))"
  return "$rc"
}

# --------------------------------------------------------------------------------------------
# one rail-move drill

servedrill_move() {
  PASS="$1" DRILL_ID="$2"
  local title env pod frm to out res rc=0
  D="$RS/pass$PASS/$DRILL_ID"
  mkdir -p "$D"
  title="$(sd_get "list.$DRILL_ID.title")"
  pod="$(sd_get "list.$DRILL_ID.row.pod")" frm="$(sd_get "list.$DRILL_ID.row.rail")" to="$(sd_get "list.$DRILL_ID.moved.rail")"
  env="$RENDERDIR/bootstrap/k8s/serving.env"
  sec "pass $PASS, drill $DRILL_ID: $title"
  echo "drill: pass $PASS $DRILL_ID ($title)"
  if ! py "$SDP" moved-env --plan "$SD_PLAN" --drill "$DRILL_ID" --env "$env" >"$D/serving-moved.env" 2>"$D/moved-env.err"; then
    bad "pass $PASS $DRILL_ID: $pod's row moved in the table" "$(tail -n 1 "$D/moved-env.err")"
    return 1
  fi
  diff "$env" "$D/serving-moved.env" >"$D/table.diff" 2>&1 || true
  ok "pass $PASS $DRILL_ID: $pod's row moved in the table from rail $frm to rail $to ($(grep '^>' "$D/table.diff" | cut -c3- | head -n 1))"
  out="$D/render-moved.txt"
  if py "$SFAB_ROOT/serving-layer/serving.py" render --env "$D/serving-moved.env" --out "$D/rendered-moved" >"$out" 2>&1; then
    bad "pass $PASS $DRILL_ID: the recipe refuses the moved table" "it rendered the manifests"
  else
    ok "pass $PASS $DRILL_ID: the recipe refuses to render the manifests from it: $(tail -n 1 "$out")"
  fi
  "$LABDIR/audit.sh" --quick --table "$D/serving-moved.env" >"$D/audit-moved.txt" 2>&1 || true
  res="$(grep -E '^== RESULT: ' "$D/audit-moved.txt" | tail -n 1 || true)"
  if grep -qE "^  FAIL  .*$pod" "$D/audit-moved.txt" && [[ "$res" != *", 0 failed,"* ]]; then
    ok "pass $PASS $DRILL_ID: audit.sh against the moved table fails first, nothing in the cluster having moved: ${res#== } ($(grep -cE '^  FAIL  ' "$D/audit-moved.txt") FAIL lines, $pod named)"
  else
    bad "pass $PASS $DRILL_ID: audit.sh against the moved table fails, naming $pod" "${res:-no RESULT line}"
    rc=1
  fi
  "$LABDIR/audit.sh" --quick >"$D/audit-restored.txt" 2>&1 || true
  res="$(grep -E '^== RESULT: ' "$D/audit-restored.txt" | tail -n 1 || true)"
  case "$res" in
    *", 0 failed,"*) ok "pass $PASS $DRILL_ID: audit.sh against the table as rendered, restored: ${res#== }" ;;
    *) bad "pass $PASS $DRILL_ID: audit.sh against the table as rendered" "${res:-no RESULT line}"; rc=2 ;;
  esac
  grep -E '^  (PASS|FAIL)  ' "$D/audit-moved.txt" | grep -E "$pod|the table" >"$D/result.txt" || true
  return "$rc"
}

# --------------------------------------------------------------------------------------------
# the run

servedrills_main() {
  local want="" passes=3 i d p ids=() stop=0 kind
  for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
    case "${SFAB_ARGS[$i]}" in
      --drills) want="${SFAB_ARGS[$((i + 1))]:-}" ;;
      --passes) passes="${SFAB_ARGS[$((i + 1))]:-3}" ;;
    esac
  done
  [ -f "$SD_PLAN" ] || die "drills: no $SD_PLAN (chapter.yaml has no drills block, or make render)"
  [[ "$passes" =~ ^[1-9][0-9]*$ ]] || die "drills: --passes wants a positive number, got $passes"
  mapfile -t ids < <(py -c 'import json, sys; [print(d["id"]) for d in json.load(open(sys.argv[1]))["list"] if d.get("kind") in ("serve-dark", "worker-port", "rail-move")]' "$SD_PLAN")
  [ ${#ids[@]} -gt 0 ] || die "drills: $SD_PLAN holds no serving drill"
  if [ -n "$want" ]; then
    for d in $want; do
      case " ${ids[*]} " in *" $d "*) ;; *) die "drills: no drill $d (have ${ids[*]})" ;; esac
    done
    read -r -a ids <<<"$want"
  fi
  exec 8>"$STATEDIR/lock"
  flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"
  cp "$SD_PLAN" "$RS/drills.json"
  {
    printf 'drills: %s\npasses: %s\n' "${ids[*]}" "$passes"
    printf 'host tick: %s\n' "$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null || echo unreadable)"
  } >"$RS/RUNPLAN.txt"
  for p in $(seq 1 "$passes"); do
    for d in "${ids[@]}"; do
      local rc=0
      kind="$(sd_get "list.$d.kind")"
      if [ "$kind" = rail-move ]; then
        servedrill_move "$p" "$d" || rc=$?
      else
        servedrill_fault "$p" "$d" || rc=$?
      fi
      if [ "$rc" -eq 2 ]; then
        warn "drills: pass $p $d left the serving layer not whole; the remaining drills are not run"
        stop=1
        break
      fi
    done
    [ "$stop" = 0 ] || break
  done
  py "$SDP" summarize --set "$RS" ${SFAB_TICK_STAMP:+--stamp "$SFAB_TICK_STAMP"} >/dev/null 2>&1 || warn "drills: servedrill.py summarize failed"
  summary
}
