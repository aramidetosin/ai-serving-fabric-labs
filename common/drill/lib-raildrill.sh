# shellcheck shell=bash
# common/drill/lib-raildrill.sh: chapter 5's dark-switch drill (FRAMEWORK.md section 4.6 as chapter
# 5 uses it), sourced by a chapter's drills.sh after lib.sh's sfab_init drills, which opened
# audits/<lab>_drills_<UTC>/. The plan is gen/drills.json (sfab.render.drills, a drill with dark:).
#
#   raildrills_main                --drills "ID ..." --passes N: every pass runs every drill, then
#                                  raildrill.py summarize writes DRILLS.md
#   raildrill_run PASS ID          one drill, one pass, into pass<PASS>/<ID>/
#
# One drill, in order, every time on the lab host's clock (date +%s.%N here, tcpdump -tt there):
#   1. whole     every same-rail row answered (one ping, retried once) and every rail switch's
#                rendered ports up and oper-up in show interface status, in two consecutive polls
#                5 s apart; else the drill is not run
#   2. captures  tcpdump on the lab host in both nodes' container ports on every rail (ICMP and ARP)
#   3. before    show interface status on every rail switch, saved as the switches printed it
#   4. probes    in the source guest, one ping -D -O -e <id> -c <count> per row from the row's
#                namespace, the rows all at once; they run lead_s before the cut (a count, never
#                -w: with a deadline ping exits at the first Destination Host Unreachable)
#   5. the cut   the restore pushed first (no shutdown on every port, run from the EXIT trap whatever
#                happens); then one KLISH session: interface range over every port the switch uses,
#                shutdown; the session's start and return stamped (INJECT, INJECTED)
#   6. dark      at half the hold: show interface status on every rail switch, and both nodes' rail
#                NICs as their kernels see them (ip -br link: a KLISH shutdown drops no carrier there)
#   7. restore   at hold_s: the restore's session, its start and return stamped (RESTORE, RESTORED)
#   8. tail      the probes run tail_s more, then stop with SIGINT (ping prints its statistics); the
#                guest's logs fetched; the captures stopped and decoded with tcpdump -nn -tt -e
#   9. after     show interface status again; the rails whole again; parity on the switch that went
#                dark (its no shutdown lines back as rendered); audit.sh --quick; raildrill.py analyze
#
# Nothing here uses docker pause or takes a link down from the container side; the fault is a KLISH
# shutdown inside the switch itself, and the restore is its no shutdown. Late replies (RTT over
# late_ms) count as lost.

RDP="$SFAB_COMMON/drill/raildrill.py"
RD_PLAN="$RENDERDIR/gen/drills.json"
RD_GUEST_DIR=/tmp/sfab-drill
RD_RESTORES=()
# shellcheck source=common/trace/lib-railcap.sh
. "$SFAB_COMMON/trace/lib-railcap.sh"

rd_get() { py "$RDP" get --plan "$RD_PLAN" "$1"; }
rd_now() { date +%s.%N; }
rd_tl() { printf '%s %s\n' "$(rd_now)" "$*" >>"$D/timeline.txt"; }
rd_sleep_until() { local s; s="$(py -c 'import sys, time; print(max(0.0, float(sys.argv[1]) - time.time()))' "$1")"; sleep "$s"; }
rd_add() { py -c 'import sys; print(float(sys.argv[1]) + float(sys.argv[2]))' "$1" "$2"; }

rd_restore_add() { RD_RESTORES+=("$*"); }
rd_restore_run() {
  local i
  for ((i = ${#RD_RESTORES[@]} - 1; i >= 0; i--)); do
    eval "${RD_RESTORES[$i]}" || warn "drill: restore '${RD_RESTORES[$i]}' failed"
  done
  RD_RESTORES=()
}
rd_cleanup() {
  rd_restore_run
  rd_probes_stop quiet || true
  railcap_cleanup || true
}

# --------------------------------------------------------------------------------------------
# the rails whole

# rd_poll DIR: one poll: the same-rail rows, and every rail switch's show interface status
rd_poll() {
  local dir="$1" id ns dst icmp src sw kind
  rm -rf "$dir"
  mkdir -p "$dir"
  src="$(rd_get probes.rails.src)"
  while IFS=$'\t' read -r id ns dst icmp; do
    [ -n "$id" ] || continue
    kind="${id%%-*}"
    [ "$kind" = same ] || continue
    EVID_OFF=1 H "$src" "ip netns exec $ns ping -c 1 -W 1 $dst" >"$dir/$id.txt" 2>&1 ||
      { sleep "${SFAB_RETRY_PAUSE:-1}"; EVID_OFF=1 H "$src" "ip netns exec $ns ping -c 1 -W 1 $dst" >"$dir/$id.txt" 2>&1 || true; }
  done < <(py "$RDP" rows --plan "$RD_PLAN")
  for sw in $(py -c 'import json, sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["rail_switches"])))' "$RD_PLAN"); do
    EVID_OFF=1 SW "$sw" "show interface status" 2>/dev/null | klish_body "show interface status" >"$dir/$sw-status.txt" 2>/dev/null || true
  done
  py "$RDP" whole --plan "$RD_PLAN" --dir "$dir" >"$dir/whole.txt" 2>&1
}

# rd_whole LABEL DIR: two consecutive polls 5 s apart with the rails whole
rd_whole() {
  local label="$1" dir="$2" polls good=0 i
  polls="$(rd_get timing.whole_polls)"
  for i in $(seq 1 "$polls"); do
    if rd_poll "$dir"; then
      good=$((good + 1))
      [ "$good" -ge 2 ] && break
    else
      good=0
    fi
    sleep "${SFAB_DRILL_POLL_S:-5}"
  done
  if [ "$good" -ge 2 ]; then
    ok "$label: every rail answers its same-rail ping and every rail switch's rendered ports are up (poll $i)"
    return 0
  fi
  bad "$label" "$(cat "$dir/whole.txt" 2>/dev/null || echo 'no poll read')"
  return 1
}

# --------------------------------------------------------------------------------------------
# probes, snapshots and the fault

# rd_probes_start SECS: one ping per row, bounded by a count that outlasts SECS. Never -w: with a
# deadline, iputils ping also exits at the first error the network reports, and on a dark rail the
# source's neighbor entry fails and the kernel reports Destination Host Unreachable.
rd_probes_start() {
  local secs="$1" src iv to script="" id ns dst icmp count
  src="$(rd_get probes.rails.src)" iv="$(rd_get probes.rails.interval_s)" to="$(rd_get probes.rails.timeout_s)"
  count="$(py -c 'import math, sys; print(math.ceil(float(sys.argv[1]) / float(sys.argv[2])))' "$secs" "$iv")"
  while IFS=$'\t' read -r id ns dst icmp; do
    [ -n "$id" ] || continue
    script="$script rm -f $RD_GUEST_DIR/ping-$id.log; ip netns exec $ns setsid ping -D -O -i $iv -W $to -e $icmp -c $count $dst >$RD_GUEST_DIR/ping-$id.log 2>&1 </dev/null &"
  done < <(py "$RDP" rows --plan "$RD_PLAN")
  H "$src" "mkdir -p $RD_GUEST_DIR;$script sleep 0.2; pgrep -fc '[p]ing -D -O -i'" >"$D/logs/ping-start.txt" 2>&1 || true
  RD_PROBING=1
  rd_tl PROBES "$(py "$RDP" rows --plan "$RD_PLAN" | cut -f1 | paste -sd ' ' -)"
}

rd_probes_stop() {
  local src i
  [ "${RD_PROBING:-0}" = 1 ] || return 0
  src="$(rd_get probes.rails.src)"
  EVID_OFF=1 H "$src" "pkill -INT -f '[p]ing -D -O -i' || true" >/dev/null 2>&1 || true
  for i in $(seq 1 10); do
    EVID_OFF=1 H "$src" "pgrep -f '[p]ing -D -O -i' >/dev/null" >/dev/null 2>&1 || break
    sleep 1
  done
  { EVID_OFF=1 H "$src" "for f in $RD_GUEST_DIR/ping-*.log; do echo \"==> \$f\"; cat \"\$f\"; done; rm -rf $RD_GUEST_DIR" 2>/dev/null || true; } |
    py "$RDP" split --dir "$D" || true
  RD_PROBING=0
  [ "${1:-}" = quiet ] || rd_tl STOP probes
}

# rd_snapshot PHASE: show interface status on every rail switch, as each printed it
rd_snapshot() {
  local ph="$1" sw
  mkdir -p "$D/klish"
  for sw in $(py -c 'import json, sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["rail_switches"])))' "$RD_PLAN"); do
    SW "$sw" "show interface status" >"$D/klish/$ph-$sw.txt" 2>&1 || true
  done
}

# rd_links PHASE: each node's rail NICs as its kernel sees them
rd_links() {
  local ph="$1" n
  for n in $(rd_get probes.rails.src) $(rd_get probes.rails.dst); do
    H "$n" "ip -br link show | grep -E '^rail[0-9]'" >"$D/links-$ph-$n.txt" 2>&1 || true
  done
}

rd_klish() {  # rd_klish KEY OUT: the drill's KLISH session (klish or restore); non-zero on % Error
  local key="$1" out="$2" sw
  sw="$(rd_get "list.$DRILL_ID.switch")"
  mapfile -t _lines < <(rd_get "list.$DRILL_ID.$key")
  SW "$sw" "${_lines[@]}" >"$out" 2>&1 || true
  ! grep -qE '%[[:space:]]?Error' "$out"
}

rd_unshut() { rd_klish restore "$D/restore.txt" || bad "pass $PASS $DRILL_ID: restore on $(rd_get "list.$DRILL_ID.switch")" "the switch answered % Error ($(grep -m1 -E '%[[:space:]]?Error' "$D/restore.txt"))"; }

# rd_parity SW: every rendered KLISH line in the running configuration again
rd_parity() {
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

rd_quick_audit() {
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
# one drill

raildrill_run() {
  PASS="$1" DRILL_ID="$2"
  local title sw lead hold tail secs t0 rc=0 node eth
  D="$RS/pass$PASS/$DRILL_ID"
  mkdir -p "$D/logs" "$D/captures"
  : >"$D/timeline.txt"
  title="$(rd_get "list.$DRILL_ID.title")"
  sw="$(rd_get "list.$DRILL_ID.switch")"
  lead="$(rd_get timing.lead_s)" hold="$(rd_get timing.hold_s)" tail="$(rd_get timing.tail_s)"
  sec "pass $PASS, drill $DRILL_ID: $title"
  echo "drill: pass $PASS $DRILL_ID ($title)"
  if ! rd_whole "pass $PASS $DRILL_ID: the rails whole before the fault" "$D/whole-before"; then
    rd_tl ABORTED "the rails were not whole before the fault"
    return 1
  fi
  rd_tl TARGET "$sw"
  trap rd_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  secs="$(py -c 'import sys; print(int(float(sys.argv[1]) + float(sys.argv[2]) + float(sys.argv[3]) + 30))' "$lead" "$hold" "$tail")"
  while IFS=$'\t' read -r node eth _; do
    [ -n "$node" ] || continue
    railcap_host_start "$node" "$eth" "$D/captures/$node-$eth.pcap" "icmp or arp" "$((secs + 120))"
  done < <(py "$RDP" caps --plan "$RD_PLAN")
  railcap_wait
  rd_snapshot before
  rd_probes_start "$secs"
  rd_sleep_until "$(rd_add "$(rd_now)" "$lead")"

  rd_restore_add rd_unshut
  t0="$(rd_now)"
  rd_tl INJECT "interface range shutdown on $sw ($(rd_get "list.$DRILL_ID.natives" | paste -sd ' ' -))"
  if rd_klish klish "$D/fault.txt"; then
    rd_tl INJECTED ok
    ok "pass $PASS $DRILL_ID: KLISH $(rd_get "list.$DRILL_ID.klish" | sed -n 2p), shutdown accepted on $sw: every port it uses ($(rd_get "list.$DRILL_ID.natives" | paste -sd ',' -))"
  else
    rd_tl INJECTED error
    bad "pass $PASS $DRILL_ID: KLISH shutdown on $sw" "$(grep -m1 -E '%[[:space:]]?Error' "$D/fault.txt")"
  fi
  rd_sleep_until "$(rd_add "$t0" "$(py -c 'import sys; print(float(sys.argv[1]) / 2)' "$hold")")"
  rd_snapshot during
  rd_links during
  rd_sleep_until "$(rd_add "$t0" "$hold")"
  rd_tl RESTORE "no shutdown on $sw"
  RD_RESTORES=()
  if rd_klish restore "$D/restore.txt"; then
    rd_tl RESTORED ok
    ok "pass $PASS $DRILL_ID: no shutdown accepted on $sw after ${hold} s"
  else
    rd_tl RESTORED error
    bad "pass $PASS $DRILL_ID: no shutdown on $sw" "$(grep -m1 -E '%[[:space:]]?Error' "$D/restore.txt")"
    rc=2
  fi
  sleep "$tail"
  rd_probes_stop
  RAILCAP_DECODE="-nn -tt -e" railcap_stop
  trap - EXIT INT TERM
  rd_snapshot after
  rd_whole "pass $PASS $DRILL_ID: the rails whole again after the drill" "$D/whole-after" || rc=2
  rd_parity "$sw" || rc=2
  rd_quick_audit
  py "$RDP" analyze --plan "$RD_PLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analysis.txt" 2>/dev/null || cat "$D/analyze.out"
  known L9 "pass $PASS $DRILL_ID: a KLISH shutdown drops no carrier at the GPU NICs, so the dark rail shows only as silence ($(cat "$D"/links-during-*.txt 2>/dev/null | awk '{print $1 "=" $2}' | paste -sd ' ' - | cut -c1-160))"
  return "$rc"
}

# --------------------------------------------------------------------------------------------
# the run

raildrills_main() {
  local want="" passes=3 i d p ids=() stop=0
  for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
    case "${SFAB_ARGS[$i]}" in
      --drills) want="${SFAB_ARGS[$((i + 1))]:-}" ;;
      --passes) passes="${SFAB_ARGS[$((i + 1))]:-3}" ;;
    esac
  done
  [ -f "$RD_PLAN" ] || die "drills: no $RD_PLAN (chapter.yaml has no drills block, or make render)"
  [[ "$passes" =~ ^[1-9][0-9]*$ ]] || die "drills: --passes wants a positive number, got $passes"
  mapfile -t ids < <(py -c 'import json, sys; [print(d["id"]) for d in json.load(open(sys.argv[1]))["list"] if d.get("kind") == "dark"]' "$RD_PLAN")
  [ ${#ids[@]} -gt 0 ] || die "drills: $RD_PLAN holds no dark drill"
  if [ -n "$want" ]; then
    for d in $want; do
      case " ${ids[*]} " in *" $d "*) ;; *) die "drills: no drill $d (have ${ids[*]})" ;; esac
    done
    read -r -a ids <<<"$want"
  fi
  exec 8>"$STATEDIR/lock"
  flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"
  cp "$RD_PLAN" "$RS/drills.json"
  {
    printf 'drills: %s\npasses: %s\n' "${ids[*]}" "$passes"
    printf 'host tick: %s\n' "$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null || echo unreadable)"
  } >"$RS/RUNPLAN.txt"
  for p in $(seq 1 "$passes"); do
    for d in "${ids[@]}"; do
      local rc=0
      raildrill_run "$p" "$d" || rc=$?
      if [ "$rc" -eq 2 ]; then
        warn "drills: pass $p $d left the rails not whole; the remaining drills are not run"
        stop=1
        break
      fi
    done
    [ "$stop" = 0 ] || break
  done
  py "$RDP" summarize --set "$RS" ${SFAB_TICK_STAMP:+--stamp "$SFAB_TICK_STAMP"} >/dev/null 2>&1 || warn "drills: raildrill.py summarize failed"
  summary
}
