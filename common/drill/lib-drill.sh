# shellcheck shell=bash
# common/drill/lib-drill.sh: the drill harness (FRAMEWORK.md section 4.6), sourced by a chapter's
# drills.sh after lib.sh's sfab_init drills, which opened audits/<lab>_drills_<UTC>/. The plan is
# gen/drills.json (rendered from chapter.yaml's drills block by sfab.render.drills).
#
#   drills_main                    --drills "ID ..." --passes N: every pass runs every drill, in the
#                                  plan's order; then compare_passes.py and summarize.py
#   drill_run PASS ID              one drill, one pass, into pass<PASS>/<ID>/
#
# One drill, in order, every time on the lab host's clock (date +%s.%N here, tcpdump -tt there):
#   1. whole     the pair's session, roles and every PortChannel as rendered (judge.py mclag-pair on
#                show mclag brief and show PortChannel summary), and every bond toward the pair on
#                its legs under the system MAC, in two consecutive polls 5 s apart; else the drill
#                is not run (a drill that starts from a broken lab measures nothing)
#   2. target    a shut's switch is the plan's; a reboot's is read now from show mclag brief
#   3. captures  tcpdump on the lab host in the probes' own container ports: the source and the far
#                guest's for the ping, the firewall's two bundle legs for the TCP connects
#   4. probes    ping -D -O -i 0.1 -W 1 -e ID in the source guest, one process per ICMP id; the
#                connect loop (probe_tcp.py) in the client; the orphan loop (bash) in the bastion
#   5. placement after lead_s, the captures so far are decoded and drill.py place says whether the
#                probes sit where the drill needs them; not placed, the pings restart with new ids
#                (place_tries in all) and the lead runs again; never placed, the drill still runs
#                and its analysis says it measured no worst case
#   6. fault     T0, then the KLISH shutdown (a restore is pushed first: no shutdown, run from the
#                EXIT trap whatever happens), or sudo reboot under a timeout with the monitor running
#   7. hold      counters and KLISH snapshots during the fault; then the restore at T0 + hold_s, or
#                for a reboot the wait for its return (every bond on two legs), up to return_max_s
#   8. tail      the probes run tail_s more (return_tail_s after a return); then everything this
#                drill started stops: pings with SIGINT (so ping prints its statistics), the loops,
#                the monitor, the captures (kill -INT, waiting on their PIDs)
#   9. after     the lab whole again (as in 1, the verdict line says so), GRO and parity on a
#                rebooted switch, then audit.sh --quick; drill.py analyze writes analysis.json
#
# Nothing here uses docker pause or takes a link down from the container side; a fault is a KLISH
# shutdown or a reboot of the switch itself. Late replies (RTT over late_ms) count as lost.

DRILL_PY="$SFAB_COMMON/drill/drill.py"
DPLAN="$RENDERDIR/gen/drills.json"
DRILL_GUEST_DIR=/tmp/sfab-drill
DRILL_RESTORES=()
DRILL_CAP_PIDS=()
DRILL_BG_PIDS=()

dget() { py "$DRILL_PY" get --plan "$DPLAN" "$1"; }
now() { date +%s.%N; }
# sleep_until EPOCH: sleep until the host clock reads EPOCH (never a negative sleep)
sleep_until() { local s; s="$(py -c 'import sys, time; print(max(0.0, float(sys.argv[1]) - time.time()))' "$1")"; sleep "$s"; }
tl() { printf '%s %s\n' "$(now)" "$*" >>"$D/timeline.txt"; }

# --------------------------------------------------------------------------------------------
# restores and cleanup

restore_add() { DRILL_RESTORES+=("$*"); }
restore_run() {
  local i
  for ((i = ${#DRILL_RESTORES[@]} - 1; i >= 0; i--)); do
    eval "${DRILL_RESTORES[$i]}" || warn "drill: restore '${DRILL_RESTORES[$i]}' failed"
  done
  DRILL_RESTORES=()
}

drill_cleanup() {
  restore_run
  probes_stop quiet || true
  captures_stop || true
}

# --------------------------------------------------------------------------------------------
# the lab whole

# pair_poll DIR: the pair's session, roles and every PortChannel as rendered (judge.py mclag-pair).
# As in drill_shut, the session's echo must reach the closing `exit`: on the lab host a read of
# fe-sw1 just after keepalive-link's restore echoed `show PortChannel summary` and printed nothing
# more, which judged every PortChannel absent and took the drill's whole return wait. A read cut
# short, or still running after $SFAB_DRILL_SESSION_S (90 s; a read takes about 4 s), is typed
# again, up to three times, each short try named on a RETYPED timeline line and kept as
# <sw>.session.tryN until the next poll empties DIR.
pair_poll() {
  local dir="$1" a b sw try
  read -r a b <<<"${PAIR_MEMBERS[$(dget pair.name)]}"
  rm -rf "$dir"
  mkdir -p "$dir"
  for sw in "$a" "$b"; do
    mkdir -p "$dir/$sw"
    for try in 1 2 3; do
      EVID_OFF=1 SFAB_SESSION_TIMEOUT="${SFAB_DRILL_SESSION_S:-90}" SW "$sw" "show mclag brief" "show PortChannel summary" >"$dir/$sw.session" 2>/dev/null || true
      grep -qE "^${sw}# exit[[:space:]]*\$" "$dir/$sw.session" && break
      [ "$try" = 3 ] && break
      cp "$dir/$sw.session" "$dir/$sw.session.try$try"
      tl RETYPED "pair read on $sw cut short before its exit (try $try, $(basename "$dir")/$sw.session.try$try)"
    done
    printf '01\tmclag_brief\tklish\t.txt\tshow mclag brief\n02\tportchannel_summary\tklish\t.txt\tshow PortChannel summary\n' >"$dir/$sw.plan"
    py "$SFAB_COMMON/audit/judge.py" split --style klish --plan "$dir/$sw.plan" --session "$dir/$sw.session" --out "$dir/$sw" >/dev/null || true
  done
  SFAB_VERDICT="$dir/verdict.txt" py "$SFAB_COMMON/audit/judge.py" run --set "$dir" --inv "$INV" --render "$RENDERDIR" \
    mclag-pair "$a" "$b" >"$dir/judge.txt" 2>&1
}

# bond_read NODE: the node's bonding file (a VM guest over SSH, the bastion by docker exec)
bond_read() {
  local n="$1" bond
  bond="$(py -c 'import json, sys; d = json.load(open(sys.argv[1])); print(next(b["bond"] for b in d["bonded"] if b["node"] == sys.argv[2]))' "$DPLAN" "$n")"
  if [ "${NODE_KIND[$n]}" = vm-node ]; then
    EVID_OFF=1 H "$n" "cat /proc/net/bonding/$bond" 2>/dev/null
  else
    EVID_OFF=1 X "$n" cat "/proc/net/bonding/$bond" 2>/dev/null
  fi
}

bonded_list() { py -c 'import json, sys; [print(b["node"]) for b in json.load(open(sys.argv[1]))["bonded"]]' "$DPLAN"; }

bonds_poll() {
  local dir="$1" n
  mkdir -p "$dir"
  for n in $(bonded_list); do bond_read "$n" >"$dir/$n.bonding.txt" & done
  wait_pids_children
  py "$DRILL_PY" bonds --plan "$DPLAN" --dir "$dir" >"$dir/bonds.txt" 2>&1
}

# wait_pids_children: wait for this shell's background jobs started since the last call, except
# the long-running ones it keeps (captures, the monitor), which are never waited on here.
wait_pids_children() {
  local j keep=" ${DRILL_CAP_PIDS[*]:-} ${DRILL_BG_PIDS[*]:-} "
  for j in $(jobs -p); do
    case "$keep" in *" $j "*) continue ;; esac
    wait "$j" 2>/dev/null || true
  done
}

# lab_whole LABEL DIR: two consecutive polls 5 s apart with the pair and every bond as rendered.
lab_whole() {
  local label="$1" dir="$2" polls good=0 i
  polls="$(dget timing.whole_polls)"
  for i in $(seq 1 "$polls"); do
    if pair_poll "$dir/pair" && bonds_poll "$dir/bonds"; then
      good=$((good + 1))
      [ "$good" -ge 2 ] && break
    else
      good=0
    fi
    sleep "${SFAB_DRILL_POLL_S:-5}"
  done
  if [ "$good" -ge 2 ]; then
    ok "$label: the pair's session, roles and PortChannels as rendered, and every bond on its legs under the system MAC (poll $i)"
    return 0
  fi
  bad "$label" "$( { grep -h '^  FAIL  ' "$dir/pair/judge.txt" 2>/dev/null | head -n 2 | sed 's/^  FAIL  //'; head -n 2 "$dir/bonds/bonds.txt" 2>/dev/null; } | paste -sd ';' -)"
  return 1
}

# --------------------------------------------------------------------------------------------
# captures on the lab host

capture_filter() {
  local f
  case "$1" in
    ping) f="icmp and host $(dget probes.ping.src_addr) and host $(dget probes.ping.dst_addr)" ;;
    tcp) f="tcp port $(dget probes.tcp.port) and host $(dget probes.tcp.client_addr) and host $(dget probes.tcp.dst_addr)" ;;
  esac
  printf '(%s) or (vlan and (%s))' "$f" "$f"
}

captures_start() {
  local probe line node eth pid name filt cap_s
  cap_s=$(( $(py -c 'import json, sys; t = json.load(open(sys.argv[1]))["timing"]; print(int(t["return_max_s"] + t["return_tail_s"] + t["lead_s"] * (t["place_tries"] + 1) + 600))' "$DPLAN") ))
  mkdir -p "$D/captures"
  for probe in "$@"; do
    [ "$probe" = ping ] || [ "$probe" = tcp ] || continue
    filt="$(capture_filter "$probe")"
    while IFS= read -r line; do
      node="$(py -c 'import json, sys; print(json.loads(sys.argv[1])["node"])' "$line")"
      eth="$(py -c 'import json, sys; print(json.loads(sys.argv[1])["eth"])' "$line")"
      name="$probe-$node-$eth"
      pid="$(pid_of "$node")"
      [ "$pid" != 0 ] || { warn "drill: $node is not running"; continue; }
      _evid "$node" capture "+ nsenter -t $pid -n timeout $cap_s tcpdump -i $eth -nn -s 128 -U -w captures/$name.pcap '$filt'"
      nsenter -t "$pid" -n timeout "$cap_s" tcpdump -i "$eth" -nn -s 128 -U -w "$D/captures/$name.pcap" "$filt" >"$D/captures/$name.log" 2>&1 </dev/null &
      DRILL_CAP_PIDS+=("$!")
    done < <(dget "probes.$probe.capture")
  done
  local i
  for i in $(seq 1 "${SFAB_DRILL_CAP_WAIT_S:-20}"); do
    [ -n "$(find "$D/captures" -name '*.pcap' 2>/dev/null)" ] && [ "$(find "$D/captures" -name '*.pcap' | wc -l)" -ge "${#DRILL_CAP_PIDS[@]}" ] && break
    sleep "${SFAB_DRILL_CAP_POLL_S:-1}"
  done
  sleep "${SFAB_DRILL_CAP_SETTLE_S:-1}"
}

# captures_decode SUBDIR: decode every pcap so far into captures/SUBDIR/ (or captures/ itself)
captures_decode() {
  local out="$D/captures${1:+/$1}" f
  mkdir -p "$out"
  for f in "$D"/captures/*.pcap; do
    [ -f "$f" ] || continue
    tcpdump -nn -tt -e -r "$f" >"$out/$(basename "$f" .pcap).txt" 2>/dev/null || true
  done
}

captures_stop() {
  local p
  [ ${#DRILL_CAP_PIDS[@]} -gt 0 ] || return 0
  sleep "${SFAB_DRILL_CAP_TAIL_S:-1}"
  for p in "${DRILL_CAP_PIDS[@]}"; do kill -INT "$p" 2>/dev/null || true; done
  for p in "${DRILL_CAP_PIDS[@]}"; do wait "$p" 2>/dev/null || true; done
  DRILL_CAP_PIDS=()
}

# --------------------------------------------------------------------------------------------
# probes

# probe_seconds KIND [HOLD]: how long the probes run: a reboot waits for its return; a shut holds
# HOLD (default timing.hold_s) and, kind "return" (a shut with await_return), waits for its return too
probe_seconds() {
  py -c 'import json, sys
t = json.load(open(sys.argv[1]))["timing"]
k = sys.argv[2]
hold = float(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else t["hold_s"]
ret = t["return_max_s"] + t["return_tail_s"]
print(int(t["lead_s"] * (t["place_tries"] + 1) + (ret if k == "reboot" else hold + ret if k == "return" else hold + t["tail_s"]) + 60))' "$DPLAN" "$1" "${2:-}"
}

# ping_start ATTEMPT SECONDS: one ping -e per id of placement try ATTEMPT, in the source guest
ping_start() {
  local attempt="$1" secs="$2" src dst ids iv script
  src="$(dget probes.ping.src)"
  dst="$(dget probes.ping.dst_addr)"
  iv="$(dget probes.ping.interval_s)"
  ids="$(py "$DRILL_PY" ids --plan "$DPLAN" --attempt "$attempt")"
  script="mkdir -p $DRILL_GUEST_DIR; for id in $ids; do rm -f $DRILL_GUEST_DIR/ping-\$id.log; setsid ping -D -O -i $iv -W 1 -e \$id -w $secs $dst >$DRILL_GUEST_DIR/ping-\$id.log 2>&1 </dev/null & done; sleep 0.2; pgrep -fc '[p]ing -D -O -i'"
  H "$src" "$script" >"$D/logs/ping-start-$attempt.txt" 2>&1 || true
  tl PING_IDS "$ids"
}

ping_stop() {
  local src i
  src="$(dget probes.ping.src)"
  EVID_OFF=1 H "$src" "pkill -INT -f '[p]ing -D -O -i' || true" >/dev/null 2>&1 || true
  for i in $(seq 1 10); do
    EVID_OFF=1 H "$src" "pgrep -f '[p]ing -D -O -i' >/dev/null" >/dev/null 2>&1 || break
    sleep 1
  done
}

ping_fetch() {
  local src
  src="$(dget probes.ping.src)"
  { EVID_OFF=1 H "$src" "for f in $DRILL_GUEST_DIR/ping-*.log; do echo \"==> \$f\"; cat \"\$f\"; done; rm -rf $DRILL_GUEST_DIR" 2>/dev/null || true; } |
    py "$DRILL_PY" split --dir "$D" || true
}

tcp_start() {
  local secs="$1" c ctr
  c="$(dget probes.tcp.client)"
  ctr="$(ctr "$c")"
  dk cp "$SFAB_COMMON/drill/probe_tcp.py" "$ctr:/tmp/sfab-probe-tcp.py" >/dev/null
  _evid "$c" container "+ python3 /tmp/sfab-probe-tcp.py $(dget probes.tcp.dst_addr) $(dget probes.tcp.port) $secs $(dget probes.tcp.interval_s) $(dget probes.tcp.timeout_s) /tmp/sfab-drill-tcp.log &"
  dk exec -d "$ctr" python3 /tmp/sfab-probe-tcp.py "$(dget probes.tcp.dst_addr)" "$(dget probes.tcp.port)" "$secs" \
    "$(dget probes.tcp.interval_s)" "$(dget probes.tcp.timeout_s)" /tmp/sfab-drill-tcp.log >/dev/null
}

tcp_stop() {
  local c ctr
  c="$(dget probes.tcp.client)"
  ctr="$(ctr "$c")"
  dk exec "$ctr" sh -c "pkill -f '[s]fab-probe-tcp' || true" >/dev/null 2>&1 || true
  sleep "${SFAB_DRILL_PROBE_STOP_S:-1}"
  dk exec "$ctr" cat /tmp/sfab-drill-tcp.log >"$D/logs/tcp.log" 2>/dev/null || true
  dk exec "$ctr" rm -f /tmp/sfab-drill-tcp.log /tmp/sfab-probe-tcp.py >/dev/null 2>&1 || true
}

orphan_start() {
  local secs="$1" c ctr addr port iv to loop
  c="$(dget probes.orphan.client)"
  ctr="$(ctr "$c")"
  addr="$(dget probes.orphan.dst_addr)" port="$(dget probes.orphan.port)" iv="$(dget probes.orphan.interval_s)" to="$(dget probes.orphan.timeout_s)"
  loop="end=\$(( \$(date +%s) + $secs )); i=0; : > /tmp/sfab-drill-orphan.log; while [ \"\$(date +%s)\" -lt \"\$end\" ]; do t=\$(date +%s.%N); if timeout $to bash -c 'exec 3<>/dev/tcp/$addr/$port' 2>/dev/null; then ok=1; else ok=0; fi; echo \"\$t \$i \$ok\" >> /tmp/sfab-drill-orphan.log; i=\$((i + 1)); sleep $iv; done"
  _evid "$c" container "+ bash -c '<connect loop to $addr:$port every ${iv}s, ${to}s timeout, ${secs}s>' &"
  dk exec -d "$ctr" bash -c "$loop" >/dev/null
}

orphan_stop() {
  local c ctr
  c="$(dget probes.orphan.client)"
  ctr="$(ctr "$c")"
  dk exec "$ctr" sh -c "pkill -f '[s]fab-drill-orphan' || true" >/dev/null 2>&1 || true
  sleep "${SFAB_DRILL_PROBE_STOP_S:-1}"
  dk exec "$ctr" cat /tmp/sfab-drill-orphan.log >"$D/logs/orphan.log" 2>/dev/null || true
  dk exec "$ctr" rm -f /tmp/sfab-drill-orphan.log >/dev/null 2>&1 || true
}

DRILL_PROBES=()
probes_start() {
  local secs="$1" p
  shift
  DRILL_PROBES=("$@")
  mkdir -p "$D/logs"
  for p in "$@"; do
    case "$p" in
      ping) ping_start 1 "$secs" ;;
      tcp) tcp_start "$secs" ;;
      orphan) orphan_start "$secs" ;;
    esac
  done
  tl PROBES "$*"
}

probes_stop() {
  local p
  for p in "${DRILL_PROBES[@]+"${DRILL_PROBES[@]}"}"; do
    case "$p" in
      ping) ping_stop; ping_fetch ;;
      tcp) tcp_stop ;;
      orphan) orphan_stop ;;
    esac
  done
  [ "${1:-}" = quiet ] || tl STOP "${DRILL_PROBES[*]:-}"
  DRILL_PROBES=()
}

# --------------------------------------------------------------------------------------------
# counters and snapshots

# counters_sample PHASE N: the peer-link members' host-side counters on both pair members
counters_sample() {
  local ph="$1" k="$2" sw pid
  mkdir -p "$D/counters"
  for sw in $(dget pair.members); do
    pid="$(pid_of "$sw")"
    printf '{"t": %s, "links": %s}\n' "$(now)" "$(nsenter -t "$pid" -n ip -s -j link show 2>/dev/null | py "$DRILL_PY" ipstats)" \
      >"$D/counters/$ph-$k-$sw.json"
  done
}

# snapshot PHASE [counters]: show mclag brief and show PortChannel summary (and show interface
# counters) on both pair members, saved as the switches printed them
snapshot() {
  local ph="$1" sw extra=()
  [ "${2:-}" = counters ] && extra=("show interface counters")
  mkdir -p "$D/klish"
  for sw in $(dget pair.members); do
    SW "$sw" "show mclag brief" "show PortChannel summary" "${extra[@]+"${extra[@]}"}" >"$D/klish/$ph-$sw.txt" 2>&1 || true
    if [ ${#extra[@]} -gt 0 ]; then
      klish_body "show interface counters" <"$D/klish/$ph-$sw.txt" >"$D/klish/$ph-$sw-counters.txt" 2>/dev/null || true
    fi
  done
}

# --------------------------------------------------------------------------------------------
# the reboot monitor

monitor_switch_cmd() {
  local sw="$1" pcs domain
  pcs="$(py -c 'import json, sys
d = json.load(open(sys.argv[1]))
print(" ".join(sorted(d["nodes"][sys.argv[2]]["portchannels"], key=lambda s: int(s[11:]))))' "$INV" "$sw")"
  domain="$(dget pair.domain)"
  # the reboot monitor's reads, in the forms SONiC 4.6.0 answers them
  # shellcheck disable=SC2016 # expanded by the switch's shell
  printf 'echo sys=$(systemctl is-system-running 2>/dev/null); docker exec iccpd mclagdctl -i %s dump state 2>/dev/null | grep -E "keepalive is|^Role" | tr "\\n" " "; for p in %s; do echo -n "$p=$(sonic-db-cli APPL_DB hget LAG_TABLE:$p oper_status)/td=$(sonic-db-cli APPL_DB hget LAG_TABLE:$p traffic_disable) "; done' "$domain" "$pcs"
}

# monitor_fw_loop END: the firewall's selected ae1 members every few seconds, into monitor-fw.log
# (its own loop: a PA-VM session takes seconds, and the monitor's interval must not wait for it)
monitor_fw_loop() {
  local end="$1" tmp sel
  tmp="$(mktemp "$STATEDIR/run/monitor-fw.XXXXXX")"
  while [ "$(date +%s)" -lt "$end" ]; do
    EVID_OFF=1 FW "show lacp aggregate-ethernet all" >"$tmp" 2>/dev/null || true
    sel="$(py -c 'import sys
sys.path.insert(0, sys.argv[1])
import judge
g = judge.p_panos_lacp(open(sys.argv[2]).read())
print(",".join(",".join(m for m, x in sorted(v["members"].items()) if x.get("selected")) for v in g.values()) or "none")' "$SFAB_COMMON/audit" "$tmp" 2>/dev/null || echo '?')"
    printf '%s %s\n' "$(now)" "$sel" >>"$D/monitor-fw.log"
    sleep "${SFAB_DRILL_FW_S:-3}"
  done
  rm -f "$tmp"
}

# monitor_loop END: one line every few seconds until END (epoch seconds): every bond's legs in its
# active aggregator, each pair member's management reachability and, while it answers, its iccpd
# keepalive and role and every PortChannel's state, and the firewall's latest LACP read
monitor_loop() {
  local end="$1" out="$D/monitor.log" n sw t line tmp fwr fwl fwt fwpid="" pids
  tmp="$(mktemp -d "$STATEDIR/run/monitor.XXXXXX")"
  declare -A cmd
  for sw in $(dget pair.members); do cmd[$sw]="$(monitor_switch_cmd "$sw")"; done
  if [ -n "${FW_NODE:-}" ]; then
    monitor_fw_loop "$end" &
    fwpid=$!
  fi
  # stopped by the drill (kill): stop the firewall's loop with it
  trap '[ -z "$fwpid" ] || kill "$fwpid" 2>/dev/null; rm -rf "$tmp"; exit 0' TERM
  while [ "$(date +%s)" -lt "$end" ]; do
    t="$(now)"
    pids=()
    for n in $(bonded_list); do
      (bond_read "$n" | py "$DRILL_PY" legs >"$tmp/$n" 2>/dev/null || echo "?" >"$tmp/$n") &
      pids+=("$!")
    done
    for sw in $(dget pair.members); do
      (if ping -c 1 -W 1 "$(node_mgmt "$sw")" >/dev/null 2>&1; then
         printf 'mgmt=up ' >"$tmp/sw-$sw"
         EVID_OFF=1 SFAB_CMD_TIMEOUT=8 SH "$sw" "${cmd[$sw]}" 2>&1 | tr '\n' ' ' >>"$tmp/sw-$sw" || true
       else
         printf 'mgmt=down' >"$tmp/sw-$sw"
       fi) &
      pids+=("$!")
    done
    wait "${pids[@]}" 2>/dev/null || true
    line="$t | bonds"
    for n in $(bonded_list); do line="$line $n=$(cat "$tmp/$n" 2>/dev/null || echo '?')"; done
    for sw in $(dget pair.members); do line="$line | $sw $(cat "$tmp/sw-$sw" 2>/dev/null)"; done
    # the firewall's last read, when it is less than 10 s old
    fwr="?"
    fwl="$(tail -n 1 "$D/monitor-fw.log" 2>/dev/null || true)"
    if [ -n "$fwl" ]; then
      fwt="${fwl%% *}"
      if py -c 'import sys; sys.exit(0 if float(sys.argv[2]) - float(sys.argv[1]) < 10 else 1)' "$fwt" "$t" 2>/dev/null; then fwr="${fwl#* }"; fi
    fi
    printf '%s | fw ae1=%s\n' "$line" "$fwr" >>"$out"
    sleep "${SFAB_DRILL_MONITOR_S:-1}"
  done
  [ -z "$fwpid" ] || kill "$fwpid" 2>/dev/null || true
  rm -rf "$tmp"
}

# --------------------------------------------------------------------------------------------
# one drill

drill_shut() {
  # The session's echo must reach the closing `exit` at the operational prompt: sonic-cli can drop
  # typed-ahead lines while it handles one (a restore's transcript once stopped at `interface
  # Ethernet12` and left the port shut), so a session cut short is typed again, up to three times,
  # each short try kept as <out>.tryN and named on a RETYPED timeline line. A session still running
  # after $SFAB_DRILL_SESSION_S (90 s; one takes about 3 s) counts as cut short, so a hung session
  # cannot use up the drill's return wait.
  local key="$1" out="$2" sw try
  sw="$(dget "list.$DRILL_ID.switch")"
  mapfile -t _lines < <(dget "list.$DRILL_ID.$key")
  for try in 1 2 3; do
    SFAB_SESSION_TIMEOUT="${SFAB_DRILL_SESSION_S:-90}" SW "$sw" "${_lines[@]}" >"$out" 2>&1 || true
    grep -qE '%[[:space:]]?Error' "$out" && return 1
    grep -qE "^${sw}# exit[[:space:]]*\$" "$out" && return 0
    cp "$out" "$out.try$try"
    tl RETYPED "$key session on $sw cut short before its exit (try $try, $(basename "$out").try$try)"
  done
  return 1
}

drill_unshut() { drill_shut restore "$D/restore.txt" || bad "pass $PASS $DRILL_ID: restore on $(dget "list.$DRILL_ID.switch")" "the switch answered % Error ($(grep -m1 -E '%[[:space:]]?Error' "$D/restore.txt"))"; }

# role_of ROLE: the pair member show mclag brief names ROLE (standby or active), read now
role_of() {
  local want="$1" sw r
  for sw in $(dget pair.members); do
    r="$( { SW "$sw" "show mclag brief" 2>/dev/null || true; } | klish_body "show mclag brief" 2>/dev/null | sed -n 's/^Role[[:space:]]*:[[:space:]]*//p' | head -n 1 | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]' || true)"
    [ "$r" = "$want" ] && { printf '%s\n' "$sw"; return 0; }
  done
  return 1
}

drill_run() {
  PASS="$1" DRILL_ID="$2"
  local kind title target probes secs attempt tries placed=1 t0 lead hold tail end rc=0 other a b why pc="" awaitr standby mon_pid=""
  D="$RS/pass$PASS/$DRILL_ID"
  mkdir -p "$D/logs"
  : >"$D/timeline.txt"
  kind="$(dget "list.$DRILL_ID.kind")"
  title="$(dget "list.$DRILL_ID.title")"
  mapfile -t probes < <(dget "list.$DRILL_ID.probes")
  lead="$(dget timing.lead_s)" tail="$(dget timing.tail_s)" tries="$(dget timing.place_tries)"
  # a shut may hold its own hold_s (a keepalive cut outlasts the session timeout)
  hold="$(dget "list.$DRILL_ID.hold_s" 2>/dev/null || true)"
  [ -n "$hold" ] || hold="$(dget timing.hold_s)"
  awaitr="$(dget "list.$DRILL_ID.await_return" 2>/dev/null || echo 0)"
  sec "pass $PASS, drill $DRILL_ID: $title"
  echo "drill: pass $PASS $DRILL_ID ($title)"
  if ! lab_whole "pass $PASS $DRILL_ID: the lab whole before the fault" "$D/whole-before"; then
    tl ABORTED "the lab was not whole before the fault"
    return 1
  fi
  read -r a b <<<"$(dget pair.members | paste -sd ' ' -)"
  if [ "$kind" = reboot ]; then
    target="$(role_of "$(dget "list.$DRILL_ID.role")")" || { bad "pass $PASS $DRILL_ID: the $(dget "list.$DRILL_ID.role") read from show mclag brief" "neither switch names that role"; return 1; }
    other="$a"; [ "$target" = "$a" ] && other="$b"
    tl ACTIVE "$other"
  else
    target="$(dget "list.$DRILL_ID.switch")"
    if [ "$awaitr" = 1 ]; then
      # the monitor's events need the roles as the drill starts
      standby="$(role_of standby)" || { bad "pass $PASS $DRILL_ID: the standby read from show mclag brief" "neither switch names that role"; return 1; }
      other="$a"; [ "$standby" = "$a" ] && other="$b"
      tl ACTIVE "$other"
      tl STANDBY "$standby"
    fi
  fi
  tl TARGET "$target"
  trap drill_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  [ "$(dget "list.$DRILL_ID.peer_link_counters")" != 1 ] || pc=counters
  if [ "$kind" = shut ] && [ "$awaitr" = 1 ]; then secs="$(probe_seconds return "$hold")"; else secs="$(probe_seconds "$kind" "$hold")"; fi
  captures_start "${probes[@]}"
  snapshot before "$pc"
  probes_start "$secs" "${probes[@]}"
  attempt=1
  while :; do
    end="$(py -c 'import sys; print(float(sys.argv[1]) + float(sys.argv[2]))' "$(now)" "$lead")"
    sleep_until "$end"
    captures_decode place
    if py "$DRILL_PY" place --plan "$DPLAN" --drill "$DRILL_ID" --dir "$D" --end "$(now)" --target "$target" --attempt "$attempt" \
      --ids "$(sed -n 's/^[0-9.]* PING_IDS //p' "$D/timeline.txt" | tail -n 1)" >"$D/logs/place-$attempt.txt" 2>&1; then
      placed=0
      tl PLACED "try $attempt yes"
      break
    fi
    tl PLACED "try $attempt no"
    [ "$attempt" -lt "$tries" ] || break
    attempt=$((attempt + 1))
    case " ${probes[*]} " in
      *" ping "*) ping_stop; ping_start "$attempt" "$secs" ;;
    esac
  done
  why="$(py -c 'import json, sys; print("; ".join(json.load(open(sys.argv[1]))["why"]))' "$D/placement-$attempt.json" 2>/dev/null || echo "no placement read")"
  if [ "$placed" = 0 ]; then
    ok "pass $PASS $DRILL_ID: probes located before the fault as the drill needs them (try $attempt): $why"
  else
    bad "pass $PASS $DRILL_ID: probes located before the fault" "not placed in $attempt tries, so the drill measures no worst case: $why"
  fi
  if [ -n "$pc" ]; then counters_sample before 1; sleep "${SFAB_DRILL_SAMPLE_S:-3}"; counters_sample before 2; fi

  if [ "$kind" = shut ]; then
    restore_add drill_unshut
    if [ "$awaitr" = 1 ]; then
      monitor_loop "$(py -c 'import sys, time; print(int(time.time() + float(sys.argv[1]) + float(sys.argv[2]) + float(sys.argv[3]) + 60))' "$hold" "$(dget timing.return_max_s)" "$(dget timing.return_tail_s)")" &
      mon_pid=$!
      DRILL_BG_PIDS+=("$mon_pid")
      sleep "${SFAB_DRILL_STEP_S:-5}"
    fi
    t0="$(now)"
    tl INJECT "shutdown $(dget "list.$DRILL_ID.members" | paste -sd ' ' -) on $target"
    if drill_shut klish "$D/fault.txt"; then
      tl INJECTED ok
      ok "pass $PASS $DRILL_ID: KLISH shutdown of $(dget "list.$DRILL_ID.members" | paste -sd ',' -) ($(dget "list.$DRILL_ID.portchannel")) on $target accepted"
    else
      tl INJECTED error
      bad "pass $PASS $DRILL_ID: KLISH shutdown on $target" "$(grep -m1 -E '%[[:space:]]?Error' "$D/fault.txt")"
    fi
    if [ -n "$pc" ]; then
      # the during window: from 5 s after the cut to 5 s before the restore (a quarter of the hold
      # each way when the hold is shorter than 20 s)
      sleep_until "$(py -c 'import sys; t, h = float(sys.argv[1]), float(sys.argv[2]); print(t + min(5.0, h / 4))' "$t0" "$hold")"; counters_sample during 1
      sleep_until "$(py -c 'import sys; t, h = float(sys.argv[1]), float(sys.argv[2]); print(t + h - min(5.0, h / 4))' "$t0" "$hold")"; counters_sample during 2
    fi
    sleep_until "$(py -c 'import sys; print(float(sys.argv[1]) + float(sys.argv[2]) / 2)' "$t0" "$hold")"
    snapshot during "$pc"
    sleep_until "$(py -c 'import sys; print(float(sys.argv[1]) + float(sys.argv[2]))' "$t0" "$hold")"
    tl RESTORE "no shutdown on $target"
    DRILL_RESTORES=()
    if drill_shut restore "$D/restore.txt"; then
      tl RESTORED ok
      ok "pass $PASS $DRILL_ID: no shutdown accepted on $target after ${hold} s"
    else
      tl RESTORED error
      bad "pass $PASS $DRILL_ID: no shutdown on $target" "$(grep -m1 -E '%[[:space:]]?Error' "$D/restore.txt")"
      rc=2
    fi
    if [ "$awaitr" = 1 ]; then
      drill_await_return "$(now)" || rc=2
      kill "$mon_pid" 2>/dev/null || true
      wait "$mon_pid" 2>/dev/null || true
      DRILL_BG_PIDS=()
    elif [ -n "$pc" ]; then
      sleep "$(py -c 'import sys; print(min(5.0, float(sys.argv[1]) / 4))' "$tail")"; counters_sample after 1
      sleep "$(py -c 'import sys; print(max(0.5, float(sys.argv[1]) / 2))' "$tail")"; counters_sample after 2
    else
      sleep "$tail"
    fi
    snapshot after "$pc"
  else
    local rmax rtail mon_pid ret
    rmax="$(dget timing.return_max_s)" rtail="$(dget timing.return_tail_s)"
    monitor_loop "$(( $(date +%s) + rmax + rtail + 60 ))" &
    mon_pid=$!
    DRILL_BG_PIDS+=("$mon_pid")
    sleep "${SFAB_DRILL_STEP_S:-5}"
    t0="$(now)"
    tl INJECT "sudo reboot on $target (the $(dget "list.$DRILL_ID.role"))"
    SFAB_CMD_TIMEOUT="$(dget "list.$DRILL_ID.command_timeout_s")" SH "$target" "$(dget "list.$DRILL_ID.command")" >"$D/fault.txt" 2>&1 || true
    tl INJECTED "the reboot command returned"
    ok "pass $PASS $DRILL_ID: sudo reboot sent to $target, the $(dget "list.$DRILL_ID.role") (the session is cut by the reboot, under a $(dget "list.$DRILL_ID.command_timeout_s") s timeout)"
    ret=""
    while [ "$(py -c 'import sys, time; print(int(time.time() - float(sys.argv[1])))' "$t0")" -lt "$rmax" ]; do
      sleep "${SFAB_DRILL_STEP_S:-5}"
      if py "$DRILL_PY" events --plan "$DPLAN" --monitor "$D/monitor.log" --t0 "$t0" --standby "$target" --active "$other" >"$D/events.json" 2>/dev/null; then
        ret="$(py -c 'import json, sys; print(json.load(open(sys.argv[1]))["return"])' "$D/events.json")"
        break
      fi
    done
    if [ -n "$ret" ]; then
      tl RETURN "every bond back on two legs (monitor read at $ret)"
      ok "pass $PASS $DRILL_ID: $target returned: every bond toward the pair back on two legs (an event; drill.py analyze times it)"
      sleep "$rtail"
    else
      bad "pass $PASS $DRILL_ID: $target returned within ${rmax} s" "not every bond back on two legs"
      rc=2
    fi
    kill "$mon_pid" 2>/dev/null || true
    wait "$mon_pid" 2>/dev/null || true
    DRILL_BG_PIDS=()
    snapshot after
  fi

  probes_stop
  captures_stop
  captures_decode
  trap - EXIT INT TERM
  restore_run
  lab_whole "pass $PASS $DRILL_ID: the lab whole again after the drill" "$D/whole-after" || rc=2
  if [ "$kind" = reboot ]; then
    drill_reboot_checks "$target" || rc=2
  fi
  drill_events_archive "$D/events"
  drill_quick_audit
  py "$DRILL_PY" analyze --plan "$DPLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analysis.txt" 2>/dev/null || cat "$D/analyze.out"
  drill_known "$kind"
  return "$rc"
}

# drill_await_return RESTORED: after a shut's restore, wait (up to return_max_s) for the pair as
# rendered and every bond back on its legs, in two consecutive polls, the first no sooner than 10 s
# after the restore; then the probes run return_tail_s more. The standby that shut its MCLAG ports
# while the keepalive was gone holds them down for delay-restore once it is back (the keepalive
# probe), so this is a wait for an event, recorded with the time it was seen.
drill_await_return() {
  local t1="$1" rmax rtail good=0 el
  rmax="$(dget timing.return_max_s)" rtail="$(dget timing.return_tail_s)"
  sleep_until "$(py -c 'import sys; print(float(sys.argv[1]) + 10)' "$t1")"
  while :; do
    el="$(py -c 'import sys, time; print(int(time.time() - float(sys.argv[1])))' "$t1")"
    [ "$el" -lt "$rmax" ] || break
    # each poll's outcome goes to return/polls.txt, since the next poll replaces the reads
    if pair_poll "$D/return/pair" && bonds_poll "$D/return/bonds"; then
      good=$((good + 1))
      printf '+%s s pair ok, bonds ok\n' "$el" >>"$D/return/polls.txt"
      [ "$good" -lt 2 ] || break
    else
      good=0
      if grep -q '^  FAIL  ' "$D/return/pair/judge.txt" 2>/dev/null; then
        printf '+%s s pair: %s\n' "$el" "$(grep -h -m1 '^  FAIL  ' "$D/return/pair/judge.txt" | sed 's/^  FAIL  //')" >>"$D/return/polls.txt"
      else
        printf '+%s s pair ok, bonds: %s\n' "$el" "$(head -n 1 "$D/return/bonds/bonds.txt" 2>/dev/null)" >>"$D/return/polls.txt"
      fi
    fi
    sleep "${SFAB_DRILL_POLL_S:-5}"
  done
  if [ "$good" -ge 2 ]; then
    tl RETURN "the pair as rendered and every bond on its legs, $el s after the restore"
    ok "pass $PASS $DRILL_ID: the pair whole and every bond back on its legs $el s after the restore (polls 5 s apart; an event, drill.py analyze times it from the monitor)"
    sleep "$rtail"
    return 0
  fi
  bad "pass $PASS $DRILL_ID: the pair whole again within ${rmax} s of the restore" "$( { grep -h '^  FAIL  ' "$D/return/pair/judge.txt" 2>/dev/null | head -n 2 | sed 's/^  FAIL  //'; head -n 2 "$D/return/bonds/bonds.txt" 2>/dev/null; } | paste -sd ';' -)"
  return 1
}

# drill_known KIND: the platform limits that bear on what this drill's figures mean (spec/known.yaml)
drill_known() {
  local dups
  if [ "$1" = shut ]; then
    known L9 "pass $PASS $DRILL_ID: a KLISH shutdown drops no carrier at the far end, so every member figure here is an LACP-timeout figure"
  else
    known L2 "pass $PASS $DRILL_ID: delay-restore holds nothing down, so the return is boot plus LACP, recorded as an event and never as a span"
  fi
  dups="$(py -c 'import json, sys; print(json.load(open(sys.argv[1])).get("ping", {}).get("dup", 0))' "$D/analysis.json" 2>/dev/null || echo 0)"
  if [ "${dups:-0}" != 0 ]; then
    known L1 "pass $PASS $DRILL_ID: $dups duplicate ping replies (peer-link isolation is not enforced)"
  fi
}

# drill_reboot_checks SW: after a reboot, GRO, rx-gro-hw and LRO off on every data NIC, and every
# rendered KLISH line still in the running configuration (FRAMEWORK.md 6.4: GRO after every reboot)
drill_reboot_checks() {
  local sw="$1" rc=0 probs norm=() prc=0
  # shellcheck disable=SC2016 # expanded by the switch's shell
  SH "$sw" 'for i in $(ls /sys/class/net | grep "^eth[1-9][0-9]*$" | sort -V); do echo "== $i"; /usr/sbin/ethtool -k "$i" | grep -E "^(generic-receive-offload|rx-gro-hw|large-receive-offload):"; done' >"$D/gro-$sw.txt" 2>&1 || true
  if probs="$(py "$SFAB_COMMON/audit/judge.py" offloads --nics "${NODE_NUM_NICS[$sw]}" "$D/gro-$sw.txt")"; then
    ok "pass $PASS $DRILL_ID: $sw after its reboot: GRO, rx-gro-hw and LRO off on all ${NODE_NUM_NICS[$sw]} data NICs"
  else
    bad "pass $PASS $DRILL_ID: $sw after its reboot: GRO, rx-gro-hw and LRO off" "$(printf '%s' "$probs" | head -n 2 | paste -sd ';' -)"
    rc=1
  fi
  [ ! -f "$RENDERDIR/gen/klish-normalize.json" ] || norm=(--normalize "$RENDERDIR/gen/klish-normalize.json")
  SW "$sw" "show running-configuration" | klish_body "show running-configuration" >"$D/running-$sw.txt" 2>/dev/null || true
  py "$SFAB_COMMON/klish/parity.py" "$RENDERDIR/bootstrap/$sw/startup-config.cfg" "$D/running-$sw.txt" --switch "$sw" "${norm[@]+"${norm[@]}"}" \
    --json "$D/parity-$sw.json" >"$D/parity-$sw.txt" 2>&1 || prc=$?
  if [ "$prc" -eq 0 ]; then
    ok "pass $PASS $DRILL_ID: $sw after its reboot: parity, 0 missing lines"
  else
    bad "pass $PASS $DRILL_ID: $sw after its reboot: parity" "$(grep -E '^ +missing \(' "$D/parity-$sw.txt" | head -n 2 | sed 's/^ *//' | paste -sd ';' -)"
    rc=1
  fi
  return "$rc"
}

# drill_events_archive DIR: in a lab with the cluster, every namespace's Warning events saved as
# DIR/events-<ns>.json and .txt, then deleted. A pair fault leaves readiness and liveness failures on
# the nodes it cut off for a few seconds (the bonds on one leg, the standby's ports held down), which
# are the drill's evidence; the full audit after the drills expects no Warning event since finish
# archived them, as the serving and gateway drills archive theirs.
drill_events_archive() {
  local dir="$1" ns n=0 c
  [ -n "${KNODE:-}" ] || return 0
  mkdir -p "$dir"
  for ns in $(EVID_OFF=1 K get events -A --field-selector type=Warning \
      -o jsonpath='{range .items[*]}{.metadata.namespace}{"\n"}{end}' 2>/dev/null | sort -u); do
    EVID_OFF=1 K -n "$ns" get events --field-selector type=Warning -o json >"$dir/events-$ns.json" 2>/dev/null || true
    EVID_OFF=1 K -n "$ns" get events --field-selector type=Warning --sort-by=.lastTimestamp >"$dir/events-$ns.txt" 2>&1 || true
    c="$(py -c 'import json, sys; print(len(json.load(open(sys.argv[1])).get("items", [])))' "$dir/events-$ns.json" 2>/dev/null || echo 0)"
    n=$((n + c))
    EVID_OFF=1 K -n "$ns" delete events --field-selector type=Warning >/dev/null 2>&1 || true
  done
  echo "drills: $n Warning event(s) archived in ${dir#"$RS"/} and cleared"
}

# drill_quick_audit: audit.sh --quick on the devices the drill touched (the switches and the
# firewall), its verdict kept in the drill's directory
drill_quick_audit() {
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
# the run

drills_main() {
  local want="" passes=3 i d p ids=() stop=0
  for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
    case "${SFAB_ARGS[$i]}" in
      --drills) want="${SFAB_ARGS[$((i + 1))]:-}" ;;
      --passes) passes="${SFAB_ARGS[$((i + 1))]:-3}" ;;
    esac
  done
  [ -f "$DPLAN" ] || die "drills: no $DPLAN (chapter.yaml has no drills block, or make render)"
  [[ "$passes" =~ ^[1-9][0-9]*$ ]] || die "drills: --passes wants a positive number, got $passes"
  mapfile -t ids < <(py -c 'import json, sys; [print(d["id"]) for d in json.load(open(sys.argv[1]))["list"]]' "$DPLAN")
  if [ -n "$want" ]; then
    for d in $want; do
      case " ${ids[*]} " in *" $d "*) ;; *) die "drills: no drill $d (have ${ids[*]})" ;; esac
    done
    read -r -a ids <<<"$want"
  fi
  exec 8>"$STATEDIR/lock"
  flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"
  cp "$DPLAN" "$RS/drills.json"
  {
    printf 'drills: %s\npasses: %s\n' "${ids[*]}" "$passes"
    printf 'host tick: %s\n' "$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null || echo unreadable)"
  } >"$RS/RUNPLAN.txt"
  for p in $(seq 1 "$passes"); do
    for d in "${ids[@]}"; do
      local rc=0
      drill_run "$p" "$d" || rc=$?
      if [ "$rc" -eq 2 ]; then
        warn "drills: pass $p $d left the lab not whole; the remaining drills are not run"
        stop=1
        break
      fi
    done
    [ "$stop" = 0 ] || break
  done
  drill_events_archive "$RS/events-after"
  sec "the passes compared"
  py "$SFAB_COMMON/drill/compare_passes.py" --set "$RS" >"$RS/compare.txt" 2>&1 || true
  cat "$RS/compare.txt"
  if grep -q '^DISAGREE' "$RS/compare.txt"; then
    ok "compare_passes.py: the passes disagree on $(grep -c '^DISAGREE' "$RS/compare.txt") row(s); compare.txt prints each"
  else
    ok "compare_passes.py: no disagreement between the passes"
  fi
  py "$SFAB_COMMON/drill/summarize.py" --set "$RS" ${SFAB_TICK_STAMP:+--stamp "$SFAB_TICK_STAMP"} >/dev/null 2>&1 || warn "drills: summarize.py failed"
  summary
}
