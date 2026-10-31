# shellcheck shell=bash
# common/trace/lib-servetrace.sh: chapter 6's serving trace (FRAMEWORK.md section 4.5 as chapter 6
# uses it), recorded as audits/<lab>_trace_<UTC>/ with TRACE.md, verdict.txt, cluster/, request/ and
# captures/. A chapter's trace.sh is
#
#   . "$(dirname "$0")/../common/lib.sh"; sfab_init trace "$@"
#   . "$SFAB_COMMON/trace/lib-servetrace.sh"; servetrace_run
#
# The plan is gen/trace.json (sfab.render.trace, serving form). In order:
#   1. cluster   both namespaces' pods, the users' VIP's lease and the serving EndpointSlices, read
#                from the bastion into cluster/ (the capture points are found from them)
#   2. the key   the model's first key from its Secret into the client, as a 0600 header file
#                (lib-servecap.sh key_to_client, the transcript off); request/key.txt names its
#                field and fingerprint
#   3. warm-up   one request, not captured, saved as request/warmup-*
#   4. captures  every point servetrace.py points lists: the lease holder's bond0 in its guest; each
#                API gateway, router, server and worker pod inside its own network namespace in its
#                node's guest (a pod's cluster interface at 66 bytes a frame, headers only); the rail
#                switch ports on the lab host in the switch container. The trace waits until every
#                pcap exists, then a few seconds more
#   5. request   one chat completion with curl from the client, its source port pinned, the key read
#                from the header file (so no command line holds it), its status, response headers
#                and body saved in request/; the request's own headers are never saved. With the
#                plan's pin (a copy the request must land on), steps 4 and 5 run again, the source
#                port one higher each time, until the pinned copy's server took the request (its
#                llama-server log holds one more launched slot than before it), at most pin.tries
#                times: a miss's captures are stopped and discarded, and request/attempts.txt
#                names each try and the copy that did not take it
#   6. captures stopped (SIGINT), decoded with tcpdump -nn -tt -e -v; the key's file removed
#   7. servetrace.py judges the evidence and writes TRACE.md
#
# Chapter 7's keyed form (the plan's keys.capture): the API gateway's and the router's cluster
# interfaces are captured whole, each pcap taken out of its guest on a pipe through keyscrub.py
# (lib-railcap.sh RAILCAP_SCRUB), so only the keys' marks reach the set; request/key.txt names the
# caller's key by field, fingerprint and mark, and request/master-key.txt and backend-key.txt the
# router's master key and the backend key the same way, each read through a pipe from its Secret.
# With the plan's refuse, one more request after the keyed one, from the same client to a hostname
# the Gateway does not carry, with no key, its status and response headers saved as
# request/refuse-*.
#
# Changes nothing on any device; every process it starts it stops.

STP="$SFAB_COMMON/trace/servetrace.py"
ST_PLAN="$RENDERDIR/gen/trace.json"
ST_DIR=/tmp/sfab-trace
# shellcheck source=common/trace/lib-servecap.sh
. "$SFAB_COMMON/trace/lib-servecap.sh"

st_get() { py "$STP" get --plan "$ST_PLAN" "$1"; }

servetrace_cluster() {
  local ins sns lease
  ins="$(st_get api_gateway.namespace)" sns="$(st_get serving.namespace)" lease="$(st_get gateway.lease)"
  mkdir -p "$RS/cluster"
  EVID_OFF=1 K -n "$ins" get pods -o json >"$RS/cluster/pods-$ins.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$sns" get pods -o json >"$RS/cluster/pods-$sns.json" 2>/dev/null || true
  EVID_OFF=1 K -n "${lease%%/*}" get lease "${lease#*/}" -o json >"$RS/cluster/lease.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$sns" get endpointslices -o json >"$RS/cluster/endpointslices-$sns.json" 2>/dev/null || true
  K -n "$ins" get pods -o wide >"$RS/cluster/pods-$ins.txt" 2>&1 || true
  K -n "$sns" get pods -o wide >"$RS/cluster/pods-$sns.txt" 2>&1 || true
}

# servetrace_request TAG [SPORT]: one chat completion from the client; TAG.txt holds its status
servetrace_request() {
  local tag="$1" sport="${2:-}" client url model res pin=() lp=()
  client="$(st_get client.node)" url="$(st_get url)" model="$(st_get model)"
  [ -z "$(st_get client.resolve 2>/dev/null || true)" ] || pin=(--resolve "$(st_get client.resolve)")
  [ -z "$sport" ] || lp=(--local-port "$sport")
  res="$(X "$client" curl -sS --max-time 120 "${lp[@]+"${lp[@]}"}" "${pin[@]+"${pin[@]}"}" -o "$ST_DIR/$tag-body.json" -D "$ST_DIR/$tag-headers.txt" \
    -w '%{http_code} %{local_port}\n' -H "@$ST_DIR/hdr-$model" -H 'Content-Type: application/json' --data "@$ST_DIR/request.json" "$url" 2>&1 || true)"
  printf '%s\n' "$res" | tail -n 1 >"$RS/request/$tag-result.txt"
  dk exec "$(ctr "$client")" cat "$ST_DIR/$tag-headers.txt" 2>/dev/null | tr -d '\r' >"$RS/request/$tag-headers.txt" || true
  dk exec "$(ctr "$client")" cat "$ST_DIR/$tag-body.json" 2>/dev/null >"$RS/request/$tag-body.json" || true
}

servetrace_captures() {
  local id kind node ns pod iface filt snap ppid
  mkdir -p "$RS/captures"
  py "$STP" points --plan "$ST_PLAN" --set "$RS" >"$RS/points.tsv"
  while IFS=$'\t' read -r id kind node ns pod iface filt snap keyed; do
    [ -n "$id" ] || continue
    case "$kind" in
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
      host) RAILCAP_SNAPLEN="$snap" railcap_host_start "$node" "$iface" "$RS/captures/$id.pcap" "$filt" "$CAP_S" ;;
    esac
  done <"$RS/points.tsv"
  railcap_wait
  echo "trace: $(grep -c . "$RS/points.tsv") capture points started"
}

# st_launches POD: how many requests the server pod's llama-server has taken (launched slots in its log)
st_launches() {
  EVID_OFF=1 K -n "$(st_get serving.namespace)" logs "$1" -c "$(st_get pin.container)" 2>/dev/null | grep -c 'launch_slot_' || true
}

# servetrace_pinned: steps 4 and 5 until the pinned copy's server took the request
servetrace_pinned() {
  local pod tries base k sport before after
  pod="$(st_get pin.server)" tries="$(st_get pin.tries)" base="$(st_get sport)"
  : >"$RS/request/attempts.txt"
  for ((k = 0; k < tries; k++)); do
    sport=$((base + k))
    before="$(st_launches "$pod")"
    servetrace_captures
    servetrace_request request "$sport"
    after="$(st_launches "$pod")"
    if [ "${after:-0}" -gt "${before:-0}" ]; then
      printf 'try %d source port %d: %s took it\n' "$((k + 1))" "$sport" "$pod" >>"$RS/request/attempts.txt"
      echo "trace: try $((k + 1)), source port $sport: $pod took the request"
      printf '%s\n' "$sport" >"$RS/request/sport.txt"
      return 0
    fi
    printf 'try %d source port %d: another copy took it (%s took none); its captures discarded\n' "$((k + 1))" "$sport" "$pod" >>"$RS/request/attempts.txt"
    echo "trace: try $((k + 1)), source port $sport: another copy took the request; trying again"
    railcap_stop >/dev/null 2>&1 || true
    railcap_cleanup || true
    rm -rf "$RS/captures" "$RS/points.tsv" "$RS/points-pids.tsv"
    # the router and the API gateway keep idle connections to a Service for a few seconds, and a
    # kept connection goes back to the same server: the next try waits until they have closed
    sleep "${SFAB_TRACE_PIN_GAP_S:-20}"
  done
  printf '%s\n' "$sport" >"$RS/request/sport.txt"
  warn "trace: $pod took none of $tries tries; the last one is judged"
}

servetrace_cleanup() {
  railcap_cleanup || true
  key_clear "$(st_get client.node)" "$ST_DIR"
}

# servetrace_refuse: one request, with no key, to the hostname the Gateway does not carry
servetrace_refuse() {
  local client url sport res pin=()
  client="$(st_get client.node)" url="$(st_get refuse.url)" sport="$(st_get refuse.sport)"
  [ -z "$(st_get refuse.resolve 2>/dev/null || true)" ] || pin=(--resolve "$(st_get refuse.resolve)")
  res="$(X "$client" curl -sS --max-time 30 --local-port "$sport" "${pin[@]+"${pin[@]}"}" -o "$ST_DIR/refuse-body.txt" \
    -D "$ST_DIR/refuse-headers.txt" -w '%{http_code} %{local_port}\n' "$url" 2>&1 || true)"
  printf '%s\n' "$res" | tail -n 1 >"$RS/request/refuse-result.txt"
  dk exec "$(ctr "$client")" cat "$ST_DIR/refuse-headers.txt" 2>/dev/null | tr -d '\r' >"$RS/request/refuse-headers.txt" || true
  dk exec "$(ctr "$client")" cat "$ST_DIR/refuse-body.txt" 2>/dev/null >"$RS/request/refuse-body.txt" || true
}

servetrace_run() {
  local client model stamp_args=() body keyed
  [ -f "$ST_PLAN" ] || die "trace: no $ST_PLAN (chapter.yaml has no trace block, or make render)"
  [ "$(st_get kind)" = serving ] || die "trace: $ST_PLAN is not a serving trace"
  cp "$ST_PLAN" "$RS/trace.json"
  CAP_S="${SFAB_TRACE_CAP_S:-300}"
  client="$(st_get client.node)" model="$(st_get model)"
  mkdir -p "$RS/request"
  trap servetrace_cleanup EXIT
  sec "the serving trace: $(st_get model) through $(st_get gateway.name)"
  servetrace_cluster
  keyed="$(st_get keys.capture)"
  if KEY_MARK="$keyed" key_to_client "$(st_get keys.namespace)" "$(st_get keys.secret)" "$model" "$client" "$ST_DIR" >"$RS/request/key.txt" 2>&1; then
    ok "the key for $model handed to $client as a 0600 header file, read from its Secret in the cluster ($(tail -n 1 "$RS/request/key.txt"))"
  else
    bad "the key for $model handed to $client" "$(tail -n 1 "$RS/request/key.txt")"
  fi
  if [ "$keyed" = 1 ]; then
    secret_mark "$(st_get keys.namespace)" "$(st_get keys.master.secret)" "$(st_get keys.master.field)" >"$RS/request/master-key.txt" 2>&1 || true
    secret_mark "$(st_get keys.namespace)" "$(st_get keys.backend.secret)" "$(st_get keys.backend.field)" >"$RS/request/backend-key.txt" 2>&1 || true
    echo "trace: the router's master key $(tail -n 1 "$RS/request/master-key.txt" | cut -d' ' -f2-), the backend key $(tail -n 1 "$RS/request/backend-key.txt" | cut -d' ' -f2-)"
  fi
  body="$(py -c 'import json, sys; print(json.dumps({"model": sys.argv[1], "max_tokens": int(sys.argv[2]), "messages": [{"role": "user", "content": "In one sentence, what is a network rail?"}]}))' "$model" "$(st_get max_tokens)")"
  printf '%s\n' "$body" | dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$ST_DIR/request.json"
  printf '%s\n' "$body" >"$RS/request/request.json"
  servetrace_request warmup
  echo "trace: warm-up answered $(cut -d' ' -f1 "$RS/request/warmup-result.txt")"
  if [ -n "$(st_get pin.copy 2>/dev/null || true)" ]; then
    servetrace_pinned
  else
    servetrace_captures
    servetrace_request request "$(st_get sport)"
  fi
  cp "$RS/request/request-result.txt" "$RS/request/result.txt"
  cp "$RS/request/request-headers.txt" "$RS/request/headers.txt"
  if [ -n "$(st_get refuse.url 2>/dev/null || true)" ]; then
    sleep 1
    servetrace_refuse
    echo "trace: $(st_get refuse.hostname) answered $(cut -d' ' -f1 "$RS/request/refuse-result.txt")"
  fi
  RAILCAP_DECODE="-nn -tt -e -v" railcap_stop
  trap - EXIT
  key_clear "$client" "$ST_DIR"
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$STP" judge --set "$RS" --plan "$ST_PLAN" --inv "$INV" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  summary
}
