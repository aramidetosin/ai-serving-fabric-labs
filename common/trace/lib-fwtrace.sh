# shellcheck shell=bash
# common/trace/lib-fwtrace.sh: chapter 4's firewall trace (FRAMEWORK.md section 4.5 as the chapter
# uses it), recorded as audits/<lab>_trace_<UTC>/ with TRACE.md, verdict.txt, sessions/ and pull/.
# A chapter's trace.sh is
#
#   . "$(dirname "$0")/../common/lib.sh"; sfab_init trace "$@"
#   . "$SFAB_COMMON/trace/lib-fwtrace.sh"; fwtrace_run
#
# The plan is gen/trace.json (sfab.render.trace, from chapter.yaml's trace block). In order:
#   1. each session: the client runs common/trace/hold_request.py (fed through docker exec), one
#      HTTPS request from its pinned source port whose connection it then holds open; once it
#      prints HELD, the firewall's session table is read while the connection still stands (show
#      session all filtered on the client's address and source port, CLI and XML, then show session
#      id for the row's id); then the client closes it, and the traffic log is read until the
#      session's line appears (PAN-OS writes it when the session ends)
#   2. the pull: captures start on the plan's container ports (nsenter and tcpdump on the lab host,
#      the registry's port, 802.1Q-aware); the trace waits until every pcap exists, then 3 s more;
#      the node pulls the image with crictl through its CRI (the registry mirror its containerd
#      names); the captures stop with kill -INT, waited on by PID; the traffic log is read for the
#      pull; the image is removed from the node again, so the next trace pulls it whole
#   3. fwtrace.py judges the saved files and writes TRACE.md
#
# Every process this starts it stops; the only change it makes on any device is the image pulled
# and removed again on the pull's node.

FWT="$SFAB_COMMON/trace/fwtrace.py"
FWT_PLAN="$RENDERDIR/gen/trace.json"
FWT_PIDS=()

fwtrace_cleanup() {
  local p
  for p in "${FWT_PIDS[@]+"${FWT_PIDS[@]}"}"; do kill -INT "$p" 2>/dev/null || true; done
}

# fwt_body CMD: a PAN-OS command's output from the session on stdin
fwt_body() {
  local s
  s="$(cat)"
  printf '%s\n' "$s" | py "$SFAB_COMMON/audit/judge.py" body --style panos --command "$1" 2>/dev/null || printf '%s\n' "$s"
}

# fwt_tlog OUT CMD ARGS...: the traffic log, read until panos_parse.py tlog ARGS finds an entry
fwt_tlog() {
  local out="$1" cmd="$2" i
  shift 2
  for i in $(seq 1 "${SFAB_TRACE_TLOG_TRIES:-9}"); do
    FW "$cmd" | fwt_body "$cmd" >"$out" 2>/dev/null || true
    if [ "$(py "$SFAB_COMMON/audit/panos_parse.py" tlog "$out" "$@")" != "[]" ]; then
      echo "trace: the firewall logged it (read $i)"
      return 0
    fi
    sleep "${SFAB_TRACE_TLOG_PAUSE_S:-10}"
  done
  echo "trace: no traffic log entry after $i reads"
}

# fwtrace_session ID: one held request and its session, read on the firewall. A session with a
# method (chapter 1's walk) sends that request with its body and header files, which sit in the
# client; FWT_HELD_HOOK, when set, names a function run with the session's id while the connection
# is still held, after the session table's reads.
fwtrace_session() {
  local id="$1" d pid i held=0 sid cmd post=()
  eval "$(py "$FWT" session-env --plan "$FWT_PLAN" --id "$id")"
  d="$RS/sessions/$id"
  mkdir -p "$d"
  [ -z "${S_METHOD:-}" ] || post=("$S_METHOD" "$S_BODY" "$S_HEADER")
  echo "trace: session $id, $S_CLIENT ($S_CLIENT_ADDR) to $S_DST_ADDR:443 from source port $S_SPORT"
  _evid "$S_CLIENT" container "+ python3 - $S_DST_ADDR $S_FQDN $S_PATH $S_SPORT $S_HOLD_S $S_CA_ROOT${post[*]:+ ${post[*]}} < common/trace/hold_request.py (started)"
  dk exec -i "$(ctr "$S_CLIENT")" python3 - "$S_DST_ADDR" "$S_FQDN" "$S_PATH" "$S_SPORT" "$S_HOLD_S" "$S_CA_ROOT" "${post[@]+"${post[@]}"}" \
    <"$SFAB_COMMON/trace/hold_request.py" >"$d/request.txt" 2>&1 &
  pid=$!
  FWT_PIDS+=("$pid")
  # the reply is waited for FWT_WAIT_POLLS half-seconds (a model's answer takes longer than a GET's)
  for i in $(seq 1 "${FWT_WAIT_POLLS:-60}"); do
    if grep -q '^HELD ' "$d/request.txt" 2>/dev/null; then held=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if [ "$held" = 1 ]; then
    cmd="show session all filter source $S_CLIENT_ADDR source-port $S_SPORT"
    FW "$cmd" | fwt_body "$cmd" >"$d/session-all.txt" 2>/dev/null || true
    FWX "<show><session><all><filter><source>$S_CLIENT_ADDR</source><source-port>$S_SPORT</source-port></filter></all></session></show>" \
      >"$d/session-all.xml" 2>/dev/null || true
    sid="$(py "$FWT" session-id --file "$d/session-all.txt" --src "$S_CLIENT_ADDR" --sport "$S_SPORT" || true)"
    if [ -n "$sid" ]; then
      FW "show session id $sid" | fwt_body "show session id $sid" >"$d/session-detail.txt" 2>/dev/null || true
      FWX "<show><session><id>$sid</id></session></show>" >"$d/session-detail.xml" 2>/dev/null || true
    else
      echo "trace: session $id not found in show session all" >"$d/session-detail.txt"
    fi
    [ -z "${FWT_HELD_HOOK:-}" ] || "$FWT_HELD_HOOK" "$id"
  else
    echo "trace: session $id: the client never held its connection (see request.txt)"
  fi
  wait "$pid" 2>/dev/null || true
  FWT_PIDS=()
  _evid "$S_CLIENT" container "+ hold_request.py $S_DST_ADDR $S_FQDN (finished)"$'\n'"$(cat "$d/request.txt")"
  fwt_tlog "$d/traffic-log.txt" "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" \
    --src "$S_CLIENT_ADDR" --sport "$S_SPORT"
}

# fwtrace_pull: the node's image pull, captured inside and on the uplink
fwtrace_pull() {
  local d="$RS/pull" id node eth pid i missing f filt cap_s cap_n sport
  py "$FWT" pull-env --plan "$FWT_PLAN" >"$RS/pull.env" || return 0
  # shellcheck disable=SC1091
  . "$RS/pull.env"
  mkdir -p "$d/captures"
  py "$FWT" points --plan "$FWT_PLAN" >"$d/points.tsv"
  filt="tcp port $P_REGISTRY_PORT"
  filt="($filt) or (vlan and ($filt))"
  cap_s="${SFAB_TRACE_CAP_S:-300}"
  # each point keeps the pull's first cap_n frames: the decode is committed whole and must stay under
  # the text cap (a whole pull of the node helm image decoded to about 11 MiB at a point on
  # chapter 4's revision 2 deploy); the first SYN and its translation are among the first frames
  cap_n="${SFAB_TRACE_CAP_FRAMES:-5000}"
  while IFS=$'\t' read -r id node eth _; do
    [ -n "$id" ] || continue
    pid="$(pid_of "$node")"
    [ "$pid" != 0 ] || { warn "trace: $node is not running"; continue; }
    _evid "$node" capture "+ nsenter -t $pid -n timeout $cap_s tcpdump -i $eth -nn -s 256 -c $cap_n -U -w pull/captures/$id.pcap '$filt'"
    nsenter -t "$pid" -n timeout "$cap_s" tcpdump -i "$eth" -nn -s 256 -c "$cap_n" -U -w "$d/captures/$id.pcap" "$filt" >"$d/captures/$id.log" 2>&1 </dev/null &
    FWT_PIDS+=("$!")
  done <"$d/points.tsv"
  for i in $(seq 1 "${SFAB_TRACE_START_S:-30}"); do
    missing=0
    while IFS=$'\t' read -r id _; do [ -z "$id" ] || [ -f "$d/captures/$id.pcap" ] || missing=$((missing + 1)); done <"$d/points.tsv"
    [ "$missing" -gt 0 ] || break
    sleep 1
  done
  sleep "${SFAB_TRACE_SETTLE_S:-3}"
  echo "trace: pull: $(grep -c . "$d/points.tsv") capture points started ($missing without a pcap)"
  H "$P_NODE" "crictl --runtime-endpoint $P_CRI pull $P_IMAGE" >"$d/pull.txt" 2>&1 || true
  sleep "${SFAB_TRACE_TAIL_S:-2}"
  for pid in "${FWT_PIDS[@]+"${FWT_PIDS[@]}"}"; do kill -INT "$pid" 2>/dev/null || true; done
  for pid in "${FWT_PIDS[@]+"${FWT_PIDS[@]}"}"; do wait "$pid" 2>/dev/null || true; done
  FWT_PIDS=()
  for f in "$d"/captures/*.pcap; do
    [ -f "$f" ] || continue
    tcpdump -nn -e -tttt -v -S -r "$f" >"${f%.pcap}.txt" 2>&1 || true
  done
  # the pull's own session, by its first SYN's source port: PAN-OS writes the line at session end, and
  # containerd keeps its idle connection to the registry open for a while after the pull, so the
  # log is read for up to SFAB_TRACE_PULL_TLOG_TRIES x 10 s (an earlier pull's line is not this one's)
  sport="$(py "$FWT" pull-sport --set "$RS" --plan "$FWT_PLAN" 2>/dev/null || true)"
  echo "trace: pull: the node's first SYN left from source port ${sport:-unknown}"
  SFAB_TRACE_TLOG_TRIES="${SFAB_TRACE_PULL_TLOG_TRIES:-30}" fwt_tlog "$d/traffic-log.txt" \
    "show log traffic direction equal backward receive_time in last-15-minutes dport equal $P_REGISTRY_PORT" \
    --src "$P_NODE_ADDR" --dst "$P_REGISTRY_ADDR" ${sport:+--sport "$sport"}
  H "$P_NODE" "crictl --runtime-endpoint $P_CRI rmi $P_IMAGE" >"$d/rmi.txt" 2>&1 || true
}

# fwtrace_run: the whole trace, then summary
fwtrace_run() {
  local id stamp_args=()
  [ -f "$FWT_PLAN" ] || die "trace: no $FWT_PLAN (chapter.yaml's trace block has no sessions or pull, or make render)"
  [ -n "${FW_NODE:-}" ] || die "trace: the lab has no firewall"
  cp "$FWT_PLAN" "$RS/trace.json"
  trap fwtrace_cleanup EXIT
  while read -r id; do
    [ -n "$id" ] || continue
    fwtrace_session "$id"
  done < <(py -c 'import json, sys; [print(s["id"]) for s in json.load(open(sys.argv[1])).get("sessions") or []]' "$FWT_PLAN")
  fwtrace_pull
  trap - EXIT
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$FWT" judge --set "$RS" --plan "$FWT_PLAN" --inv "$INV" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  summary
}
