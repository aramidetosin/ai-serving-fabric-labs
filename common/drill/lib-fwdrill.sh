# shellcheck shell=bash
# common/drill/lib-fwdrill.sh: chapter 4's firewall drills (FRAMEWORK.md section 4.6 as chapter 4
# uses it), sourced by a chapter's drills.sh after lib.sh's sfab_init drills, which opened
# audits/<lab>_drills_<UTC>/. The plan is gen/drills.json (sfab.render.drills): each drill changes
# the firewall live through common/fw/fw-api.sh and puts the render back after, its restore pushed
# onto the EXIT trap before the change is made, so an interrupted drill still restores.
#
#   fwdrills_main                  --drills "ID ..." --passes N: every pass runs every drill, then
#                                  fwdrill.py summarize writes DRILLS.md
#   fwdrill_run PASS ID            one drill, one pass, into pass<PASS>/<ID>/
#
# land (kind fw_nat_removed), every time on the lab host's clock:
#   1. the rule order as rendered (fw-api.sh order); else the drill is not run
#   2. show counter global filter value all (CLI and XML), the probe (the node pings the public
#      address) with the rule in place, the counters again
#   3. the restore pushed; the rule deleted and committed; show running nat-policy saved
#   4. packet-diag cleared, its filter set to the probe's source and destination, a capture file
#      per stage, filter and capture on; host-side tcpdump on the plan's container ports
#   5. the counters, the drop counters' delta view (its baseline), the probe, the delta view (what
#      moved during the probe), the counters again
#   6. packet-diag off; view-pcap of each stage file saved, and each file exported through the API
#      and decoded with tcpdump; packet-diag cleared and its files deleted; host captures stopped
#   7. the restore: the rendered rule set back, moved where the render puts it, committed; the order
#      checked again; the counters, the probe, the counters
# ntp-uplink (kind fw_service_route):
#   1. the service routes as they run (fw-api.sh show: NTP's and each one that moves with it, the
#      services whose server is the same address), and the traffic log on each one's port
#   2. the restore pushed; host-side tcpdump; the routes edited to the new interface and committed
#      in one commit; a name looked up through the firewall (ping host), whose DNS query the log
#      must show from the new source
#   3. the traffic log read every log_pause_s, up to ntp_wait_s, until an NTP entry new since step
#      1 comes from the new source to the server
#   4. captures stopped; the routes edited back and committed; a name looked up again, its query
#      allowed from the rendered source; the NTP log read until an entry from the rendered source
#      is new since the restore; the routes read again
# Then fwdrill.py analyze prints the drill's verdict lines.

FWD_PY="$SFAB_COMMON/drill/fwdrill.py"
FWD_PLAN="$RENDERDIR/gen/drills.json"
FWAPI="$SFAB_COMMON/fw/fw-api.sh"
FWD_RESTORES=()
FWD_CAP_PIDS=()

fwapi() { "$FWAPI" --lab "$RENDERDIR" "$@"; }
fwd_now() { date +%s.%N; }
fwd_tl() { printf '%s %s\n' "$(fwd_now)" "$*" >>"$D/timeline.txt"; }
fwd_body() {
  local s
  s="$(cat)"
  printf '%s\n' "$s" | py "$SFAB_COMMON/audit/judge.py" body --style panos --command "$1" 2>/dev/null || printf '%s\n' "$s"
}

fwd_restore_add() { FWD_RESTORES+=("$*"); }
fwd_restore_run() {
  local i
  for ((i = ${#FWD_RESTORES[@]} - 1; i >= 0; i--)); do
    eval "${FWD_RESTORES[$i]}" || warn "drill: restore '${FWD_RESTORES[$i]}' failed"
  done
  FWD_RESTORES=()
}
fwd_cleanup() {
  fwd_restore_run
  fwd_captures_stop || true
}

# fwd_commit TAG DESCRIPTION: commit and record it; a PASS or FAIL line
fwd_commit() {
  if fwapi commit "$2" >"$D/commit-$1.txt" 2>&1; then
    ok "pass $PASS $DRILL_ID: committed: $2 ($(tail -n 1 "$D/commit-$1.txt"))"
    return 0
  fi
  bad "pass $PASS $DRILL_ID: committed: $2" "$(tail -n 1 "$D/commit-$1.txt")"
  return 1
}

# fwd_counters TAG: show counter global, all values, as the CLI prints it and as XML
fwd_counters() {
  FW "show counter global filter value all" | fwd_body "show counter global filter value all" >"$D/counters-$1.txt" 2>/dev/null || true
  FWX "<show><counter><global><filter><value>all</value></filter></global></counter></show>" >"$D/counters-$1.xml" 2>/dev/null || true
}

# fwd_probe TAG: the public probe from its node (a VM guest over SSH, else docker exec)
fwd_probe() {
  local cmd="ping -c $D_PCOUNT -i $D_PIV -W $D_PTO $D_PDST"
  fwd_tl "PROBE $1 $D_PSRC $cmd"
  if [ "$D_PSRC_KIND" = vm-node ]; then
    H "$D_PSRC" "$cmd" >"$D/ping-$1.txt" 2>&1 || true
  else
    # shellcheck disable=SC2086 # the command's words
    X "$D_PSRC" $cmd >"$D/ping-$1.txt" 2>&1 || true
  fi
  fwd_tl "PROBED $1 $(grep -E 'packets transmitted' "$D/ping-$1.txt" | head -n 1)"
}

# fwd_captures_start: host-side tcpdump on the plan's container ports of the firewall
fwd_captures_start() {
  local pid eth f i missing
  pid="$(pid_of "$D_FWN")"
  [ "$pid" != 0 ] || { warn "drill: $D_FWN is not running"; return 0; }
  mkdir -p "$D/captures"
  f="($D_CAP_FILTER) or (vlan and ($D_CAP_FILTER))"
  for eth in $D_CAP_ETHS; do
    _evid "$D_FWN" capture "+ nsenter -t $pid -n timeout 900 tcpdump -i $eth -nn -s 256 -U -w captures/$eth.pcap '$f'"
    nsenter -t "$pid" -n timeout 900 tcpdump -i "$eth" -nn -s 256 -U -w "$D/captures/$eth.pcap" "$f" >"$D/captures/$eth.log" 2>&1 </dev/null &
    FWD_CAP_PIDS+=("$!")
  done
  for i in $(seq 1 30); do
    missing=0
    for eth in $D_CAP_ETHS; do [ -f "$D/captures/$eth.pcap" ] || missing=$((missing + 1)); done
    [ "$missing" -gt 0 ] || break
    sleep 1
  done
  sleep "${SFAB_DRILL_CAP_SETTLE_S:-2}"
}

fwd_captures_stop() {
  local p f
  [ ${#FWD_CAP_PIDS[@]} -gt 0 ] || return 0
  sleep "${SFAB_DRILL_CAP_TAIL_S:-1}"
  for p in "${FWD_CAP_PIDS[@]}"; do kill -INT "$p" 2>/dev/null || true; done
  for p in "${FWD_CAP_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  FWD_CAP_PIDS=()
  for f in "$D"/captures/*.pcap; do
    [ -f "$f" ] || continue
    tcpdump -nn -e -tttt -v -r "$f" >"${f%.pcap}.txt" 2>&1 || true
  done
}

# fwd_order TAG: the running rulebase against the render (fw-api.sh order)
fwd_order() { fwapi order >"$D/order-$1.txt" 2>&1; }

# fwd_nat_restore: the rendered rule set back, moved where the render puts it, committed
fwd_nat_restore() {
  fwd_tl "RESTORE $D_RULE"
  fwapi set "$D_RULES_XPATH" "$D_ELEMENT" >"$D/restore-set.txt" 2>&1 || true
  if [ "$D_WHERE" = bottom ]; then
    fwapi move "$D_XPATH" bottom >"$D/restore-move.txt" 2>&1 || true
  else
    fwapi move "$D_XPATH" "$D_WHERE" "$D_DST" >"$D/restore-move.txt" 2>&1 || true
  fi
  fwd_commit restore "sfab drill $DRILL_ID: $D_RULE back where the render puts it" || true
  fwd_tl "RESTORED $D_RULE"
}

# fwd_diag: packet-diag commands in one CLI session, saved
fwd_diag() {
  local tag="$1"
  shift
  FW "$@" >"$D/diag/$tag.txt" 2>&1 || true
}

fwdrill_land() {
  local st files=()
  for st in $D_STAGES; do files+=("sfab-$DRILL_ID-$st.pcap"); done
  mkdir -p "$D/diag"
  if ! fwd_order before; then
    bad "pass $PASS $DRILL_ID: the rulebase in the render's order before the drill" "$(tail -n 1 "$D/order-before.txt")"
    return 2
  fi
  ok "pass $PASS $DRILL_ID: the rulebase in the render's order before the drill ($(paste -sd ';' "$D/order-before.txt"))"
  fwd_counters base0
  fwd_probe baseline
  fwd_counters base1
  fwd_restore_add fwd_nat_restore
  fwd_tl "INJECT delete $D_RULE"
  if fwapi del "$D_XPATH" >"$D/delete.txt" 2>&1; then
    ok "pass $PASS $DRILL_ID: $D_RULE deleted through the XML API ($(tail -n 1 "$D/delete.txt"))"
  else
    bad "pass $PASS $DRILL_ID: $D_RULE deleted" "$(tail -n 1 "$D/delete.txt")"
    return 2
  fi
  fwd_commit remove "sfab drill $DRILL_ID: $D_RULE removed" || return 2
  fwd_tl "INJECTED"
  FW "show running nat-policy" | fwd_body "show running nat-policy" >"$D/running-nat-broken.txt" 2>/dev/null || true
  sleep "$D_SETTLE_S"
  local diag_on=("debug dataplane packet-diag clear all"
    "debug dataplane packet-diag set filter match source $D_DIAG_SRC destination $D_DIAG_DST"
    "debug dataplane packet-diag set filter on")
  for st in $D_STAGES; do diag_on+=("debug dataplane packet-diag set capture stage $st file sfab-$DRILL_ID-$st.pcap"); done
  # the settings as the firewall holds them (PAN-OS answers "show debug dataplane packet-diag" with
  # "Invalid syntax.": ch04/RESULTS.md, problem 8)
  diag_on+=("debug dataplane packet-diag set capture on" "debug dataplane packet-diag show setting")
  fwd_diag on "${diag_on[@]}"
  fwd_captures_start
  fwd_counters before
  # Every show counter global read starts the firewall's next delta sampling ("Elapsed time since
  # last sampling"), so the delta view's baseline is read last before the probe and the delta view
  # first after it, before the full table is read again (ch04/RESULTS.md, problem 7)
  FW "show counter global filter delta yes severity drop" | fwd_body "show counter global filter delta yes severity drop" \
    >"$D/drop-delta-before.txt" 2>/dev/null || true
  fwd_probe broken
  sleep "${SFAB_DRILL_SETTLE_S:-2}"
  FW "show counter global filter delta yes severity drop" | fwd_body "show counter global filter delta yes severity drop" \
    >"$D/drop-delta-after.txt" 2>/dev/null || true
  fwd_counters after
  fwd_diag off "debug dataplane packet-diag set capture off" "debug dataplane packet-diag set filter off"
  for st in $D_STAGES; do
    FW "view-pcap filter-pcap sfab-$DRILL_ID-$st.pcap" | fwd_body "view-pcap filter-pcap sfab-$DRILL_ID-$st.pcap" >"$D/diag/$st.view.txt" 2>/dev/null || true
    fwapi export-pcap "sfab-$DRILL_ID-$st.pcap" "$D/diag/$st.pcap" >"$D/diag/$st.export.txt" 2>&1 || true
    if [ -s "$D/diag/$st.pcap" ] && grep -q 'saved' "$D/diag/$st.export.txt"; then
      tcpdump -nn -e -tttt -v -r "$D/diag/$st.pcap" >"$D/diag/$st.decode.txt" 2>&1 || true
    else
      : >"$D/diag/$st.decode.txt"
    fi
  done
  local cleanup=("debug dataplane packet-diag clear all")
  for st in "${files[@]}"; do cleanup+=("delete debug-filter file $st"); done
  fwd_diag cleanup "${cleanup[@]}"
  fwd_captures_stop
  trap - EXIT INT TERM
  fwd_restore_run
  trap fwd_cleanup EXIT INT TERM
  fwd_order after || true
  sleep "$D_SETTLE_S"
  fwd_counters restored0
  fwd_probe restored
  fwd_counters restored1
}

# fwd_with_restore: every service route that moved with the drill's own put back (no commit)
fwd_with_restore() {
  local i v
  for ((i = 1; i <= D_WITH_N; i++)); do
    v="D_WITH_${i}_XPATH"
    local x="${!v}"
    v="D_WITH_${i}_RESTORE"
    fwapi edit "$x" "${!v}" >"$D/restore-edit-$i.txt" 2>&1 || true
  done
}

# fwd_lookup TAG SVC PORT SRC: a name looked up through the firewall's DNS service route (ping
# host, no source: only the lookup matters, the name does not exist), then the traffic log on PORT
# read every log_pause_s, up to 60 s, until an entry new since TAG's baseline comes from SRC
fwd_lookup() {
  local tag="$1" svc="$2" port="$3" src="$4" name i
  name="sfab-$DRILL_ID-p$PASS-$tag-$(date +%s).$D_DOMAIN"
  fwd_tl "LOOKUP $tag $name"
  FW "ping count 1 host $name" | fwd_body "ping count 1 host $name" >"$D/lookup-$tag.txt" 2>/dev/null || true
  for i in $(seq 1 6); do
    sleep "$D_LOG_PAUSE_S"
    FW "show log traffic direction equal backward receive_time in last-15-minutes dport equal $port" |
      fwd_body "show log traffic direction equal backward receive_time in last-15-minutes dport equal $port" >"$D/$svc-tlog-$tag.txt" 2>/dev/null || true
    if py "$FWD_PY" newlog --before "$D/$svc-tlog-$tag-before.txt" --after "$D/$svc-tlog-$tag.txt" --src "$src" --dst "$D_SERVER" \
      --dport "$port" >"$D/$svc-$tag-entries.json"; then
      fwd_tl "LOGGED $svc $tag read $i"
      return 0
    fi
  done
  fwd_tl "NOT LOGGED $svc $tag after $i reads"
}

fwdrill_service_route() {
  local i t0 new=0 v svc port
  fwapi show "$D_XPATH" >"$D/route-before.xml" 2>&1 || true
  for ((i = 1; i <= D_WITH_N; i++)); do
    v="D_WITH_${i}_XPATH"; local wx="${!v}"
    v="D_WITH_${i}_SVC"; svc="${!v}"
    fwapi show "$wx" >"$D/route-before-$svc.xml" 2>&1 || true
  done
  FW "show log traffic direction equal backward receive_time in last-hour dport equal $D_PORT" |
    fwd_body "show log traffic direction equal backward receive_time in last-hour dport equal $D_PORT" >"$D/tlog-before.txt" 2>/dev/null || true
  fwd_restore_add "fwapi edit \"\$D_XPATH\" \"\$D_RESTORE_ELEMENT\" >\"\$D/restore-edit.txt\" 2>&1; fwd_with_restore; fwd_commit restore \"sfab drill \$DRILL_ID: the service routes back to \$D_OLD_IF\""
  fwd_captures_start
  fwd_tl "INJECT $D_SVC service route to $D_NEW_IF"
  if fwapi edit "$D_XPATH" "$D_ELEMENT" >"$D/edit.txt" 2>&1; then
    ok "pass $PASS $DRILL_ID: the $D_SVC service route set to $D_NEW_IF ($D_NEW_SRC) through the XML API"
  else
    bad "pass $PASS $DRILL_ID: the $D_SVC service route set to $D_NEW_IF" "$(tail -n 1 "$D/edit.txt")"
    return 2
  fi
  for ((i = 1; i <= D_WITH_N; i++)); do
    v="D_WITH_${i}_SVC"; svc="${!v}"
    v="D_WITH_${i}_XPATH"; local wx="${!v}"
    v="D_WITH_${i}_ELEMENT"
    if fwapi edit "$wx" "${!v}" >"$D/edit-$svc.txt" 2>&1; then
      ok "pass $PASS $DRILL_ID: the $svc service route set to $D_NEW_IF ($D_NEW_SRC) with it: its server is the same address"
    else
      bad "pass $PASS $DRILL_ID: the $svc service route set to $D_NEW_IF" "$(tail -n 1 "$D/edit-$svc.txt")"
      return 2
    fi
  done
  for ((i = 1; i <= D_WITH_N; i++)); do
    v="D_WITH_${i}_SVC"; svc="${!v}"
    v="D_WITH_${i}_PORT"; port="${!v}"
    FW "show log traffic direction equal backward receive_time in last-15-minutes dport equal $port" |
      fwd_body "show log traffic direction equal backward receive_time in last-15-minutes dport equal $port" >"$D/$svc-tlog-new-before.txt" 2>/dev/null || true
  done
  fwd_commit move "sfab drill $DRILL_ID: the service routes to $D_NEW_IF" || return 2
  fwd_tl "INJECTED"
  t0=$SECONDS
  for ((i = 1; i <= D_WITH_N; i++)); do
    v="D_WITH_${i}_SVC"; svc="${!v}"
    v="D_WITH_${i}_PORT"; port="${!v}"
    [ "$svc" = dns ] || continue
    fwd_lookup new "$svc" "$port" "$D_NEW_SRC"
  done
  i=0
  while [ $((SECONDS - t0)) -lt "${D_NTP_WAIT_S%.*}" ]; do
    i=$((i + 1))
    sleep "$D_LOG_PAUSE_S"
    FW "show log traffic direction equal backward receive_time in last-hour dport equal $D_PORT" |
      fwd_body "show log traffic direction equal backward receive_time in last-hour dport equal $D_PORT" >"$D/tlog-after.txt" 2>/dev/null || true
    if py "$FWD_PY" newlog --before "$D/tlog-before.txt" --after "$D/tlog-after.txt" --src "$D_NEW_SRC" --dst "$D_SERVER" \
      --dport "$D_PORT" >"$D/new-entries.json"; then
      new=1
      fwd_tl "LOGGED read $i, $((SECONDS - t0)) s after the commit"
      break
    fi
  done
  [ "$new" = 1 ] || fwd_tl "NOT LOGGED after $i reads"
  fwd_captures_stop
  cp "$D/tlog-after.txt" "$D/tlog-restore-before.txt" 2>/dev/null || cp "$D/tlog-before.txt" "$D/tlog-restore-before.txt"
  for ((i = 1; i <= D_WITH_N; i++)); do
    v="D_WITH_${i}_SVC"; svc="${!v}"
    v="D_WITH_${i}_PORT"; port="${!v}"
    FW "show log traffic direction equal backward receive_time in last-15-minutes dport equal $port" |
      fwd_body "show log traffic direction equal backward receive_time in last-15-minutes dport equal $port" >"$D/$svc-tlog-restored-before.txt" 2>/dev/null || true
  done
  trap - EXIT INT TERM
  fwd_restore_run
  trap fwd_cleanup EXIT INT TERM
  t0=$SECONDS
  fwapi show "$D_XPATH" >"$D/route-after.xml" 2>&1 || true
  for ((i = 1; i <= D_WITH_N; i++)); do
    v="D_WITH_${i}_SVC"; svc="${!v}"
    v="D_WITH_${i}_XPATH"; local wx="${!v}"
    v="D_WITH_${i}_PORT"; port="${!v}"
    fwapi show "$wx" >"$D/route-after-$svc.xml" 2>&1 || true
    [ "$svc" = dns ] || continue
    fwd_lookup restored "$svc" "$port" "$D_OLD_SRC"
  done
  : >"$D/restored-entries.json"
  while [ $((SECONDS - t0)) -lt "${D_NTP_WAIT_S%.*}" ]; do
    sleep "$D_LOG_PAUSE_S"
    FW "show log traffic direction equal backward receive_time in last-hour dport equal $D_PORT" |
      fwd_body "show log traffic direction equal backward receive_time in last-hour dport equal $D_PORT" >"$D/tlog-restored.txt" 2>/dev/null || true
    if py "$FWD_PY" newlog --before "$D/tlog-restore-before.txt" --after "$D/tlog-restored.txt" --src "$D_OLD_SRC" --dst "$D_SERVER" \
      --dport "$D_PORT" >"$D/restored-entries.json"; then
      fwd_tl "RESTORED-LOGGED $((SECONDS - t0)) s after the restore"
      break
    fi
  done
}

# fwdrill_run PASS ID
fwdrill_run() {
  PASS="$1" DRILL_ID="$2"
  local rc=0
  D="$RS/pass$PASS/$DRILL_ID"
  mkdir -p "$D"
  eval "$(py "$FWD_PY" env --plan "$FWD_PLAN" --id "$DRILL_ID")"
  sec "pass $PASS $DRILL_ID: $D_TITLE"
  fwd_tl "START pass $PASS $DRILL_ID"
  trap fwd_cleanup EXIT INT TERM
  case "$D_KIND" in
    fw_nat_removed) fwdrill_land || rc=$? ;;
    fw_service_route) fwdrill_service_route || rc=$? ;;
    *) bad "pass $PASS $DRILL_ID" "unknown kind $D_KIND"; rc=2 ;;
  esac
  trap - EXIT INT TERM
  fwd_restore_run
  fwd_captures_stop || true
  fwd_tl "END"
  py "$FWD_PY" analyze --plan "$FWD_PLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analyze.out"
  return "$rc"
}

fwdrills_main() {
  local want="" passes=3 i d p ids=() stop=0
  for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
    case "${SFAB_ARGS[$i]}" in
      --drills) want="${SFAB_ARGS[$((i + 1))]:-}" ;;
      --passes) passes="${SFAB_ARGS[$((i + 1))]:-3}" ;;
    esac
  done
  [ -f "$FWD_PLAN" ] || die "drills: no $FWD_PLAN (chapter.yaml has no drills block, or make render)"
  [[ "$passes" =~ ^[1-9][0-9]*$ ]] || die "drills: --passes wants a positive number, got $passes"
  [ -n "${FW_NODE:-}" ] || die "drills: the lab has no firewall"
  mapfile -t ids < <(py -c 'import json, sys; [print(d["id"]) for d in json.load(open(sys.argv[1]))["list"]]' "$FWD_PLAN")
  if [ -n "$want" ]; then
    for d in $want; do
      case " ${ids[*]} " in *" $d "*) ;; *) die "drills: no drill $d (have ${ids[*]})" ;; esac
    done
    read -r -a ids <<<"$want"
  fi
  exec 8>"$STATEDIR/lock"
  flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"
  cp "$FWD_PLAN" "$RS/drills.json"
  {
    printf 'drills: %s\npasses: %s\n' "${ids[*]}" "$passes"
    printf 'host tick: %s\n' "$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null || echo unreadable)"
  } >"$RS/RUNPLAN.txt"
  for p in $(seq 1 "$passes"); do
    for d in "${ids[@]}"; do
      local rc=0
      fwdrill_run "$p" "$d" || rc=$?
      if [ "$rc" -eq 2 ]; then
        warn "drills: pass $p $d could not run or restore as planned; the remaining drills are not run"
        stop=1
        break
      fi
    done
    [ "$stop" = 0 ] || break
  done
  sec "after the drills"
  if fwapi order >"$RS/order-final.txt" 2>&1; then
    ok "the running rulebase in the render's order after every drill ($(paste -sd ';' "$RS/order-final.txt"))"
  else
    bad "the running rulebase in the render's order after every drill" "$(tail -n 1 "$RS/order-final.txt")"
  fi
  if [ "${SFAB_DRILL_AUDIT:-1}" != 0 ]; then
    "$LABDIR/audit.sh" --quick >"$RS/audit-quick.txt" 2>&1 || true
    local res
    res="$(grep -E '^== RESULT: ' "$RS/audit-quick.txt" | tail -n 1 || true)"
    case "$res" in
      *", 0 failed,"*) ok "audit.sh --quick after the drills: ${res#== }" ;;
      *) bad "audit.sh --quick after the drills" "${res:-no RESULT line}" ;;
    esac
  else
    skip "audit.sh --quick after the drills" "SFAB_DRILL_AUDIT=0"
  fi
  py "$FWD_PY" summarize --set "$RS" ${SFAB_TICK_STAMP:+--stamp "$SFAB_TICK_STAMP"} >/dev/null 2>&1 || warn "drills: fwdrill.py summarize failed"
  summary
}
