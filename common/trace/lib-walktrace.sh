# shellcheck shell=bash
# common/trace/lib-walktrace.sh: chapter 1's walk (FRAMEWORK.md section 4.5 as chapter 1 uses it),
# recorded as audits/<lab>_trace_<UTC>/ with TRACE.md, verdict.txt, dns/, fw/, pair/, rail/,
# cluster/, sessions/, request/, refuse/ and captures/. A chapter's trace.sh is
#
#   . "$(dirname "$0")/../common/lib.sh"; sfab_init trace "$@"
#   . "$SFAB_COMMON/trace/lib-walktrace.sh"; walktrace_run
#
# The plan is gen/trace.json (sfab.render.trace, walk form): chapter 7's keyed serving plan, chapter
# 4's session form for the walked request, and the frontend, the tables and the three refusals. In
# order:
#   1. cluster   chapter 6's reads (both namespaces' pods, the Gateway's lease, the serving
#                EndpointSlices), then every HTTPRoute, the lease as kubectl prints it, the API
#                gateway's routes and the router's model list (each ConfigMap's file saved as is: no
#                key is in either, the master key is an environment reference)
#   2. names     the client's own lookup of the users' hostname, through its resolver, and another
#                of the lab's resolvers asking itself, which the platform's servers answer from
#                another view
#   3. keys      the model's first key and the refused model's key handed to the client as 0600
#                header files (lib-servecap.sh key_to_client, the transcript off), the router's master
#                key and the backend key named by mark; the request's body written in the client
#   4. warm-up   one request, not captured (the first packets of a new flow are lost to ARP)
#   5. tables    the firewall's routing table, security and NAT rulebases (one CLI session)
#   6. counters  every rail switch of the model's copies: clear counters interface all (KLISH asks
#                to confirm; the answer is typed), then show interface counters
#   7. captures  every point walktrace.py points lists: the frontend's container ports on the lab
#                host (the client's port, the firewall's interface facing it, both legs of the bundle,
#                the pair's ports facing the legs, and the pair's ports facing the lease holder, found
#                from the lease), then the serving trace's (the lease holder's bond0, the API gateway's
#                and the router's pods whole and scrubbed of their keys, the servers and workers, the
#                rail switch ports); the trace waits until every pcap exists
#   8. request   the model's request from the client's pinned source port with chapter 4's held
#                session (lib-fwtrace.sh fwtrace_session, hold_request.py with the POST): while it is
#                held, show session all and show session id, then the rail switches' counters and MAC
#                tables and the pair's MAC tables; after the client closes it, its traffic log line
#   9. refusals  the admin hostname to the Gateway with no key, the other model's key on the walked
#                model's route, and a connect to a node's port the rulebase does not allow, each from
#                its own pinned source port while the captures run
#  10. captures stopped (SIGINT) and decoded with tcpdump -nn -tt -e -v -S; the traffic log read for
#                the refused port and the refused requests; the keys' files removed from the client
#  11. walktrace.py judges the evidence and writes TRACE.md
#
# The only change it makes on any device is the rail switches' interface counters, cleared before the
# request; every process it starts it stops, and no file it writes holds a key.

WTP="$SFAB_COMMON/trace/walktrace.py"
# shellcheck source=common/trace/lib-servetrace.sh
. "$SFAB_COMMON/trace/lib-servetrace.sh"
# shellcheck source=common/trace/lib-fwtrace.sh
. "$SFAB_COMMON/trace/lib-fwtrace.sh"

wt_get() { py "$WTP" get --plan "$ST_PLAN" "$1"; }
wt_now() { date +%s.%N; }

# walktrace_cluster: chapter 6's reads, then the routes and the two ConfigMaps the walk's hops consult
walktrace_cluster() {
  local ins lease cm
  servetrace_cluster
  ins="$(wt_get api_gateway.namespace)" lease="$(wt_get gateway.lease)"
  EVID_OFF=1 K get httproutes -A -o json >"$RS/cluster/httproutes.json" 2>/dev/null || true
  K get httproutes -A >"$RS/cluster/httproutes.txt" 2>&1 || true
  K -n "${lease%%/*}" get lease "${lease#*/}" >"$RS/cluster/lease.txt" 2>&1 || true
  cm="$(wt_get tables.routes.configmap)"
  EVID_OFF=1 K -n "$ins" get configmap "$cm" -o json 2>/dev/null |
    py "$WTP" cmdata --key "$(wt_get tables.routes.key)" >"$RS/cluster/api-gateway-routes.yaml" 2>/dev/null || true
  cm="$(wt_get tables.router.configmap)"
  EVID_OFF=1 K -n "$ins" get configmap "$cm" -o json 2>/dev/null |
    py "$WTP" cmdata --key "$(wt_get tables.router.key)" >"$RS/cluster/router-config.yaml" 2>/dev/null || true
}

# walktrace_names: the client's lookup through its resolver, and the resolver's own from its address
walktrace_names() {
  local client host
  client="$(wt_get client.node)" host="$(wt_get dns.hostname)"
  mkdir -p "$RS/dns"
  X "$client" dig "$host" >"$RS/dns/client-dig.txt" 2>&1 || true
  if [ -n "$(wt_get dns.contrast.node 2>/dev/null || true)" ]; then
    X "$(wt_get dns.contrast.node)" dig -b "$(wt_get dns.contrast.source)" "@$(wt_get dns.contrast.server)" "$host" >"$RS/dns/resolver-dig.txt" 2>&1 || true
  fi
}

# walktrace_fw_tables: the firewall's routing table and rulebases, as one CLI session reads them
walktrace_fw_tables() {
  local l
  mkdir -p "$RS/fw"
  FW "show routing route" "show running security-policy" "show running nat-policy" >"$RS/fw/tables-session.txt" 2>&1 || true
  for l in "show routing route" "show running security-policy" "show running nat-policy"; do
    fwt_body "$l" <"$RS/fw/tables-session.txt" >"$RS/fw/$(printf '%s' "${l#show }" | tr -cs 'A-Za-z0-9' '-' | sed 's/-$//').txt" 2>/dev/null || true
  done
}

# walktrace_counters PHASE: on every rail switch of the model's copies, PHASE before: clear counters
# interface all, answered y, in a session of its own typed a line every WT_CLEAR_PACE_S seconds (5;
# lib.sh _paced: an exit typed ahead of the answer is never read), then show interface counters; PHASE after:
# show interface counters and show mac address-table. Each read is stamped on the lab host's clock
# (rail/stamps.tsv: switch, phase, start, end), so the judge counts only the frames captured between
# the before read and the after read.
walktrace_counters() {
  local ph="$1" sw t0 t1
  mkdir -p "$RS/rail"
  for sw in $(wt_get rail_counters.switches); do
    if [ "$ph" = before ]; then
      _SESSION_PACE="${WT_CLEAR_PACE_S:-5}" SW "$sw" "clear counters interface all" "y" >"$RS/rail/$sw-clear-session.txt" 2>&1 || true
      t0="$(wt_now)"
      SW "$sw" "show interface counters" >"$RS/rail/$sw-before-session.txt" 2>&1 || true
      t1="$(wt_now)"
      klish_body "show interface counters" <"$RS/rail/$sw-before-session.txt" >"$RS/rail/$sw-counters-before.txt" 2>/dev/null || true
    else
      t0="$(wt_now)"
      SW "$sw" "show interface counters" "show mac address-table" >"$RS/rail/$sw-after-session.txt" 2>&1 || true
      t1="$(wt_now)"
      klish_body "show interface counters" <"$RS/rail/$sw-after-session.txt" >"$RS/rail/$sw-counters-after.txt" 2>/dev/null || true
      klish_body "show mac address-table" <"$RS/rail/$sw-after-session.txt" >"$RS/rail/$sw-mac-table.txt" 2>/dev/null || true
    fi
    printf '%s\t%s\t%s\t%s\n' "$sw" "$ph" "$t0" "$t1" >>"$RS/rail/stamps.tsv"
  done
}

# walktrace_pair_macs: the pair's MAC tables, which the bridged hop consults
walktrace_pair_macs() {
  local sw
  mkdir -p "$RS/pair"
  for sw in $(wt_get frontend.pair); do
    SW "$sw" "show mac address-table" >"$RS/pair/$sw-session.txt" 2>&1 || true
    klish_body "show mac address-table" <"$RS/pair/$sw-session.txt" >"$RS/pair/$sw-mac-table.txt" 2>/dev/null || true
  done
}

# walk_held SESSION: while the walked request's connection is held (lib-fwtrace.sh FWT_HELD_HOOK)
walk_held() {
  walktrace_counters after
  walktrace_pair_macs
}

walktrace_captures() {
  local id kind node ns pod iface filt snap keyed ppid
  mkdir -p "$RS/captures"
  py "$WTP" points --plan "$ST_PLAN" --set "$RS" --inv "$INV" >"$RS/points.tsv" 2>"$RS/points.err" || true
  while IFS=$'\t' read -r id kind node ns pod iface filt snap keyed; do
    [ -n "$id" ] || continue
    case "$kind" in
      host) RAILCAP_SNAPLEN="$snap" railcap_host_start "$node" "$iface" "$RS/captures/$id.pcap" "$filt" "$CAP_S" ;;
      guest) RAILCAP_SNAPLEN="$snap" railcap_guest_start "$node" "$iface" "trace-$id" "$filt" "$CAP_S" "$RS/captures/$id.txt" "$RS/captures/$id.pcap" ;;
      pod)
        ppid="$(pod_pid "$node" "$ns" "$pod")"
        if [ -z "$ppid" ]; then
          warn "trace: $ns/$pod has no ready sandbox on $node; $id is not captured"
          continue
        fi
        printf '%s\t%s\n' "$id" "$ppid" >>"$RS/points-pids.tsv"
        RAILCAP_SCRUB="${keyed:-0}" RAILCAP_SNAPLEN="$snap" railcap_pod_start "$node" "$ppid" "$iface" "trace-$id" "$filt" "$CAP_S" \
          "$RS/captures/$id.txt" "$RS/captures/$id.pcap" ;;
    esac
  done <"$RS/points.tsv"
  railcap_wait
  echo "trace: $(grep -c . "$RS/points.tsv") capture points started"
}

# walk_refuse_key: the walked model's request with the other model's key
walk_refuse_key() {
  local client url sport km res pin=()
  client="$(wt_get client.node)" url="$(wt_get refusals.key.url)" sport="$(wt_get refusals.key.sport)" km="$(wt_get refusals.key.model)"
  [ -z "$(st_get client.resolve 2>/dev/null || true)" ] || pin=(--resolve "$(st_get client.resolve)")
  res="$(X "$client" curl -sS --max-time 60 --local-port "$sport" "${pin[@]+"${pin[@]}"}" -o "$ST_DIR/refuse-key-body.txt" \
    -D "$ST_DIR/refuse-key-headers.txt" -w '%{http_code} %{local_port}\n' -H "@$ST_DIR/hdr-$km" -H 'Content-Type: application/json' \
    --data "@$ST_DIR/request.json" "$url" 2>&1 || true)"
  printf '%s\n' "$res" | tail -n 1 >"$RS/request/refuse-key-result.txt"
  dk exec "$(ctr "$client")" cat "$ST_DIR/refuse-key-headers.txt" 2>/dev/null | tr -d '\r' >"$RS/request/refuse-key-headers.txt" || true
  dk exec "$(ctr "$client")" cat "$ST_DIR/refuse-key-body.txt" 2>/dev/null >"$RS/request/refuse-key-body.txt" || true
}

# walk_refuse_port: one connect to a node's port, from a pinned source port (common/trace/syn_connect.py)
walk_refuse_port() {
  local client a p sp to
  client="$(wt_get client.node)" a="$(wt_get refusals.port.address)" p="$(wt_get refusals.port.port)"
  sp="$(wt_get refusals.port.sport)" to="$(wt_get refusals.port.timeout_s)"
  mkdir -p "$RS/refuse"
  _evid "$client" container "+ python3 - $a $p $sp 1 $to 0 < common/trace/syn_connect.py"
  dk exec -i "$(ctr "$client")" python3 - "$a" "$p" "$sp" 1 "$to" 0 <"$SFAB_COMMON/trace/syn_connect.py" >"$RS/refuse/port-result.txt" 2>&1 || true
  _evid "$client" container "$(cat "$RS/refuse/port-result.txt")"
}

# walk_tlog OUT DPORT SPORT...: the traffic log for DPORT, read until it holds a line from the client
# for every SPORT (PAN-OS writes an allowed session's line when the session ends, a denied one's at once)
walk_tlog() {
  local out="$1" dport="$2" i cmd
  shift 2
  cmd="show log traffic direction equal backward receive_time in last-15-minutes dport equal $dport"
  for i in $(seq 1 "${SFAB_TRACE_TLOG_TRIES:-9}"); do
    FW "$cmd" | fwt_body "$cmd" >"$out" 2>/dev/null || true
    if py "$WTP" tlog-has --file "$out" --src "$(wt_get client.address)" "$@"; then
      echo "trace: the firewall logged them, port $dport (read $i)"
      return 0
    fi
    sleep "${SFAB_TRACE_TLOG_PAUSE_S:-10}"
  done
  echo "trace: the traffic log for port $dport lacks a line after $i reads"
}

walktrace_cleanup() {
  fwtrace_cleanup || true
  railcap_cleanup || true
  key_clear "$(wt_get client.node)" "$ST_DIR"
}

walktrace_run() {
  local client model body stamp_args=() km
  [ -f "$ST_PLAN" ] || die "trace: no $ST_PLAN (chapter.yaml has no trace block, or make render)"
  [ "$(wt_get kind)" = walk ] || die "trace: $ST_PLAN is not a walk"
  [ -n "${FW_NODE:-}" ] || die "trace: the lab has no firewall"
  cp "$ST_PLAN" "$RS/trace.json"
  # the captures outlive the held session, its traffic log and the refusals
  CAP_S="${SFAB_TRACE_CAP_S:-900}"
  client="$(wt_get client.node)" model="$(wt_get model)" km="$(wt_get refusals.key.model)"
  mkdir -p "$RS/request"
  trap walktrace_cleanup EXIT
  sec "the walk: $model through $(wt_get gateway.name), from $client"
  walktrace_cluster
  walktrace_names
  if KEY_MARK=1 key_to_client "$(wt_get keys.namespace)" "$(wt_get keys.secret)" "$model" "$client" "$ST_DIR" >"$RS/request/key.txt" 2>&1; then
    ok "the key for $model handed to $client as a 0600 header file, read from its Secret in the cluster ($(tail -n 1 "$RS/request/key.txt"))"
  else
    bad "the key for $model handed to $client" "$(tail -n 1 "$RS/request/key.txt")"
  fi
  if KEY_MARK=1 key_to_client "$(wt_get keys.namespace)" "$(wt_get keys.secret)" "$km" "$client" "$ST_DIR" >"$RS/request/key-$km.txt" 2>&1; then
    ok "the key for $km handed to $client the same way, for the refused request ($(tail -n 1 "$RS/request/key-$km.txt"))"
  else
    bad "the key for $km handed to $client" "$(tail -n 1 "$RS/request/key-$km.txt")"
  fi
  secret_mark "$(wt_get keys.namespace)" "$(wt_get keys.master.secret)" "$(wt_get keys.master.field)" >"$RS/request/master-key.txt" 2>&1 || true
  secret_mark "$(wt_get keys.namespace)" "$(wt_get keys.backend.secret)" "$(wt_get keys.backend.field)" >"$RS/request/backend-key.txt" 2>&1 || true
  body="$(py -c 'import json, sys; print(json.dumps({"model": sys.argv[1], "max_tokens": int(sys.argv[2]), "messages": [{"role": "user", "content": "In one sentence, what is a network rail?"}]}))' "$model" "$(wt_get max_tokens)")"
  printf '%s\n' "$body" | dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$ST_DIR/request.json"
  printf '%s\n' "$body" >"$RS/request/request.json"
  servetrace_request warmup
  echo "trace: warm-up answered $(cut -d' ' -f1 "$RS/request/warmup-result.txt")"
  walktrace_fw_tables
  walktrace_counters before
  walktrace_captures
  FWT_HELD_HOOK=walk_held FWT_WAIT_POLLS="${SFAB_TRACE_REPLY_POLLS:-240}" fwtrace_session walk
  py "$WTP" split-reply --set "$RS" || true
  echo "trace: the walked request answered $(cut -d' ' -f1 "$RS/request/result.txt" 2>/dev/null)"
  sleep "${SFAB_TRACE_GAP_S:-1}"
  servetrace_refuse
  echo "trace: $(wt_get refusals.hostname.hostname) answered $(cut -d' ' -f1 "$RS/request/refuse-result.txt")"
  walk_refuse_key
  echo "trace: $model's route with $km's key answered $(cut -d' ' -f1 "$RS/request/refuse-key-result.txt")"
  walk_refuse_port
  echo "trace: $(wt_get refusals.port.to) port $(wt_get refusals.port.port): $(cut -d' ' -f5 "$RS/refuse/port-result.txt")"
  RAILCAP_DECODE="-nn -tt -e -v -S" railcap_stop
  walk_tlog "$RS/fw/traffic-log-$(wt_get refusals.port.port).txt" "$(wt_get refusals.port.port)" "$(wt_get refusals.port.sport)"
  walk_tlog "$RS/fw/traffic-log-443.txt" 443 "$(wt_get refusals.hostname.sport)" "$(wt_get refusals.key.sport)"
  trap - EXIT
  key_clear "$client" "$ST_DIR"
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$WTP" judge --set "$RS" --plan "$ST_PLAN" --inv "$INV" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  # the judge writes TRACE.md last: a judge that stopped before it (a traceback above) left the
  # set without the table the chapter prints, so the set fails
  [ -s "$RS/TRACE.md" ] || bad "TRACE.md written by the judge" "missing: walktrace.py judge stopped before it (see above)"
  summary
}
