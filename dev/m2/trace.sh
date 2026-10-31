#!/usr/bin/env bash
# dev/m2/trace.sh [--flow ID]: the first trace (dev/m2/RESULTS.md, criterion 11; FRAMEWORK.md
# section 4.5), recorded as audits/sfab-m2_trace_<UTC>/ with TRACE.md, verdict.txt and captures/.
#
# The flow and the capture points come from chapter.yaml's trace block (the inventory's "trace"). In
# order:
#   1. the lease holder: the ingress node holding the Gateway Service's Cilium L2 announcement
#      lease, read with the harness's kubectl (the init node); the points at it are expanded (trace-md.py points)
#   2. captures start at every point: on a container port with nsenter and tcpdump on the lab host,
#      in a VM guest with tcpdump over SSH (decoded in the guest, so the decode names the guest's
#      own interfaces); the trace waits until every pcap exists, then 3 s more
#   3. the client resolves the name through its own resolver, then makes a warm-up attempt, labelled
#      as such, then the recorded attempt with its source port pinned (curl --local-port)
#   4. captures stop with kill -INT, waiting on their PIDs (never a bare wait); each runs under
#      timeout as well, as M1's settle captures did; host-side pcaps are decoded with
#      tcpdump -nn -e -tttt -v -S
#   5. the firewall's traffic log is read (a time filter and the destination port), until the
#      connection's entry appears: PAN-OS writes an entry when the session ends
#   6. trace-md.py judges the evidence and writes TRACE.md
#
# Capture filter: TCP port 443, 802.1Q-aware ((f) or (vlan and (f))), snaplen 256. Every process this
# script starts it stops; it changes nothing on any device.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(dirname "$0")/../../common/lib.sh"
sfab_init trace "$@"

TMD="$LABDIR/trace-md.py"
CAP="$RS/captures"
mkdir -p "$CAP"
flow_id=""
for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
  case "${SFAB_ARGS[$i]}" in --flow) flow_id="${SFAB_ARGS[$((i + 1))]:-}" ;; esac
done

# --- the flow ----------------------------------------------------------------------------------------
py "$TMD" flow --inv "$INV" --k8s "$RENDERDIR/gen/k8s.json" ${flow_id:+--flow "$flow_id"} >"$RS/flow.env" || die "trace: no flow to trace"
# shellcheck disable=SC1091
. "$RS/flow.env"
FILTER_F="tcp port $PORT"
FILTER="($FILTER_F) or (vlan and ($FILTER_F))"
GUEST_PCAP=/tmp/sfab-trace
# Every capture also ends by itself after CAP_S seconds (timeout), so a tcpdump that missed its
# SIGINT can never hold the trace up for longer than that.
CAP_S="${SFAB_TRACE_CAP_S:-300}"

HOLDER=""
K get leases -A -o json >"$RS/leases.json" 2>/dev/null || true
HOLDER="$(py "$TMD" holder --leases "$RS/leases.json" --namespace "$GW_NS" --gateway "$GATEWAY" --lease "$L2_LEASE" 2>/dev/null || true)"
printf 'HOLDER=%q\n' "$HOLDER" >>"$RS/flow.env"
if ! py "$TMD" points --inv "$INV" --holder "$HOLDER" >"$RS/points.tsv" 2>"$RS/points.err"; then
  sec "trace $FLOW"
  bad "capture points resolved" "$(tail -n 1 "$RS/points.err")"
  summary || true
  exit 1
fi
# A guest-side process is found by its pcap's name with the first letter bracketed, so the pattern
# never matches the shell that runs pkill or pgrep.
gpat() { printf '[s]%s' "${GUEST_PCAP#/tmp/s}-$1.pcap"; }

# --- captures ---------------------------------------------------------------------------------------
PIDS=()
GUEST_POINTS=()
cleanup() {
  local p g id
  for p in "${PIDS[@]+"${PIDS[@]}"}"; do kill -INT "$p" 2>/dev/null || true; done
  for g in "${GUEST_POINTS[@]+"${GUEST_POINTS[@]}"}"; do
    id="${g#*:}"
    EVID_OFF=1 H "${g%%:*}" "pkill -INT -f '$(gpat "$id")' || true" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

trace_start() {
  local id where node iface pid n=0 i missing
  while IFS=$'\t' read -r id where node iface _; do
    [ -n "$id" ] || continue
    n=$((n + 1))
    if [ "$where" = guest ]; then
      HBG "$node" "rm -f $GUEST_PCAP-$id.pcap $GUEST_PCAP-$id.txt; exec timeout $CAP_S tcpdump -i $iface -nn -s 256 -U -w $GUEST_PCAP-$id.pcap '$FILTER'" >/dev/null
      GUEST_POINTS+=("$node:$id")
    else
      pid="$(pid_of "$node")"
      [ "$pid" != 0 ] || { warn "trace: $node is not running"; continue; }
      _evid "$node" capture "+ nsenter -t $pid -n timeout $CAP_S tcpdump -i $iface -nn -s 256 -U -w captures/$id.pcap '$FILTER'"
      nsenter -t "$pid" -n timeout "$CAP_S" tcpdump -i "$iface" -nn -s 256 -U -w "$CAP/$id.pcap" "$FILTER" >"$CAP/$id.log" 2>&1 </dev/null &
      PIDS+=("$!")
    fi
  done <"$RS/points.tsv"
  for i in $(seq 1 "${SFAB_TRACE_START_S:-30}"); do
    missing=0
    while IFS=$'\t' read -r id where node _; do
      [ -n "$id" ] || continue
      if [ "$where" = guest ]; then
        EVID_OFF=1 H "$node" "test -f $GUEST_PCAP-$id.pcap" >/dev/null 2>&1 || missing=$((missing + 1))
      else
        [ -f "$CAP/$id.pcap" ] || missing=$((missing + 1))
      fi
    done <"$RS/points.tsv"
    [ "$missing" -gt 0 ] || break
    sleep 1
  done
  sleep "${SFAB_TRACE_SETTLE_S:-3}"
  echo "trace: $n capture points started ($missing without a pcap)"
}

trace_stop() {
  local p g node id i
  sleep "${SFAB_TRACE_TAIL_S:-2}"
  for p in "${PIDS[@]+"${PIDS[@]}"}"; do kill -INT "$p" 2>/dev/null || true; done
  for p in "${PIDS[@]+"${PIDS[@]}"}"; do wait "$p" 2>/dev/null || true; done
  PIDS=()
  for g in "${GUEST_POINTS[@]+"${GUEST_POINTS[@]}"}"; do
    node="${g%%:*}" id="${g#*:}"
    H "$node" "pkill -INT -f '$(gpat "$id")' || true" >/dev/null 2>&1 || true
    for i in $(seq 1 20); do
      EVID_OFF=1 H "$node" "pgrep -f '$(gpat "$id")' >/dev/null" >/dev/null 2>&1 || break
      sleep 1
    done
    H "$node" "tcpdump -nn -e -tttt -v -S -r $GUEST_PCAP-$id.pcap > $GUEST_PCAP-$id.txt 2>&1; wc -l < $GUEST_PCAP-$id.txt" >/dev/null 2>&1 || true
    EVID_OFF=1 H "$node" "cat $GUEST_PCAP-$id.txt" >"$CAP/$id.txt" 2>/dev/null || true
    EVID_OFF=1 H "$node" "base64 -w0 $GUEST_PCAP-$id.pcap" 2>/dev/null | base64 -d >"$CAP/$id.pcap" 2>/dev/null || true
    EVID_OFF=1 H "$node" "rm -f $GUEST_PCAP-$id.pcap $GUEST_PCAP-$id.txt" >/dev/null 2>&1 || true
  done
  GUEST_POINTS=()
  local f
  for f in "$CAP"/*.pcap; do
    [ -f "$f" ] || continue
    id="$(basename "$f" .pcap)"
    [ -s "$CAP/$id.txt" ] || tcpdump -nn -e -tttt -v -S -r "$f" >"$CAP/$id.txt" 2>&1 || true
  done
}

# fw_traffic_log: the connection's entries from the firewall's traffic log, read until one appears.
fw_traffic_log() {
  local i cmd="show log traffic direction equal backward receive_time in last-15-minutes dport equal $PORT"
  [ -n "${FW_NODE:-}" ] && [ -n "${RULE:-}" ] || return 0
  for i in $(seq 1 "${SFAB_TRACE_TLOG_TRIES:-9}"); do
    FW "$cmd" >"$RS/fw-session.txt" 2>&1 || true
    py "$SFAB_COMMON/audit/judge.py" body --style panos --command "$cmd" <"$RS/fw-session.txt" >"$RS/fw-traffic-log.txt" 2>/dev/null || true
    # a command echo the CLI wrapped is not found by its prompt line: keep the whole session then
    [ -s "$RS/fw-traffic-log.txt" ] || cp "$RS/fw-session.txt" "$RS/fw-traffic-log.txt"
    if grep -q -- "$SPORT" "$RS/fw-traffic-log.txt" 2>/dev/null && grep -q -- "$CLIENT_ADDR" "$RS/fw-traffic-log.txt"; then
      echo "trace: the firewall logged the session (read $i)"
      return 0
    fi
    sleep "${SFAB_TRACE_TLOG_PAUSE_S:-10}"
  done
  echo "trace: no traffic log entry for source port $SPORT after $i reads"
}

curl_args() { printf '%s\n' -sS -i --max-time 20 --local-port "$1" "https://$FQDN$URLPATH"; }

trace_start
X "$CLIENT" dig +time=5 +tries=2 +short "$FQDN" >"$RS/dns.txt" 2>&1 || true
mapfile -t _a < <(curl_args "$WARM_SPORT")
X "$CLIENT" curl "${_a[@]}" >"$RS/warmup.txt" 2>&1 || true
sleep "${SFAB_TRACE_GAP_S:-3}"
mapfile -t _a < <(curl_args "$SPORT")
X "$CLIENT" curl "${_a[@]}" >"$RS/request.txt" 2>&1 || true
trace_stop
trap - EXIT
fw_traffic_log

stamp_args=()
[ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
py "$TMD" judge --set "$RS" --inv "$INV" --points "$RS/points.tsv" --env "$RS/flow.env" "${stamp_args[@]+"${stamp_args[@]}"}" || true
summary
