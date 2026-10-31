# shellcheck shell=bash
# common/trace/lib-railtrace.sh: chapter 5's rail trace (FRAMEWORK.md section 4.5 as chapter 5 uses
# it), recorded as audits/<lab>_trace_<UTC>/ with TRACE.md, verdict.txt, health/, flows/, df/,
# captures/ and captures-df/. A chapter's trace.sh is
#
#   . "$(dirname "$0")/../common/lib.sh"; sfab_init trace "$@"
#   . "$SFAB_COMMON/trace/lib-railtrace.sh"; railtrace_run
#
# The plan is gen/trace.json (sfab.render.trace, rails form). In order:
#   1. health    one ping from each of the source's GPU namespaces to the far node's address on the
#                same rail, every rail, each retried once (the first packet of a new flow can be
#                lost to ARP); saved as health/rail<r>.txt
#   2. captures  at every point of the plan, ICMP only: a guest's relay bridge captured in the guest,
#                a switch port on the lab host in the switch container; the trace waits until every
#                pcap exists, then a few seconds more
#   3. flows     each flow's ping from its source namespace, count requests at interval_s under the
#                flow's own ICMP id (ping -e), so every frame at every point is the flow's
#   4. captures stopped (SIGINT, waiting on PIDs), decoded with tcpdump -nn -e -tttt -v
#   5. traceroute for each flow from the same namespace (traceroute -n, three probes a hop)
#   6. the DF matrix with its own captures (captures-df/): each row's ping, three requests with the
#      don't-fragment bit set (ping -M do) at the row's payload, under the row's own ICMP id
#   7. railtrace.py judges the evidence and writes TRACE.md
#
# Changes nothing on any device; every process it starts it stops.

RTP="$SFAB_COMMON/trace/railtrace.py"
RT_PLAN="$RENDERDIR/gen/trace.json"
# shellcheck source=common/trace/lib-railcap.sh
. "$SFAB_COMMON/trace/lib-railcap.sh"

rt_get() { py "$RTP" get --plan "$RT_PLAN" "$1"; }

# rt_ping NODE NS ARGS... : a ping inside one of the node's GPU namespaces
rt_ping() {
  local node="$1" ns="$2"
  shift 2
  H "$node" "ip netns exec $ns ping $*"
}

railtrace_health() {
  local r ns da src out
  src="$(rt_get src.node)"
  mkdir -p "$RS/health"
  while IFS=$'\t' read -r r _ ns _ da; do
    [ -n "$r" ] || continue
    out="$RS/health/rail$r.txt"
    rt_ping "$src" "$ns" -c 2 -i 0.5 -W 2 "$da" >"$out" 2>&1 || {
      sleep "${SFAB_RETRY_PAUSE:-2}"
      rt_ping "$src" "$ns" -c 2 -i 0.5 -W 2 "$da" >"$out" 2>&1 || true
    }
  done < <(py "$RTP" rails --plan "$RT_PLAN")
}

# railtrace_captures DIR: start a capture at every point of the plan into DIR
railtrace_captures() {
  local dir="$1" id where node what tag
  mkdir -p "$dir"
  py "$RTP" points --plan "$RT_PLAN" >"$RS/points.tsv"
  while IFS=$'\t' read -r id where node what; do
    [ -n "$id" ] || continue
    if [ "$where" = guest ]; then
      tag="$(basename "$dir")-$id"
      railcap_guest_start "$node" "$what" "$tag" "$(rt_get filter)" "$CAP_S" "$dir/$id.txt" "$dir/$id.pcap"
    else
      railcap_host_start "$node" "$what" "$dir/$id.pcap" "$(rt_get filter)" "$CAP_S"
    fi
  done <"$RS/points.tsv"
  railcap_wait
  echo "trace: $(grep -c . "$RS/points.tsv") capture points started in $(basename "$dir")/"
}

railtrace_run() {
  local id node ns dst icmp payload stamp_args=() count iv
  [ -f "$RT_PLAN" ] || die "trace: no $RT_PLAN (chapter.yaml has no trace block, or make render)"
  [ "$(rt_get kind)" = rails ] || die "trace: $RT_PLAN is not a rails trace"
  cp "$RT_PLAN" "$RS/trace.json"
  CAP_S="${SFAB_TRACE_CAP_S:-300}"
  count="$(rt_get count)" iv="$(rt_get interval_s)"
  trap railcap_cleanup EXIT
  railtrace_health
  railtrace_captures "$RS/captures"
  mkdir -p "$RS/flows"
  while IFS=$'\t' read -r id node ns dst icmp; do
    [ -n "$id" ] || continue
    mkdir -p "$RS/flows/$id"
    rt_ping "$node" "$ns" -c "$count" -i "$iv" -W 2 -e "$icmp" "$dst" >"$RS/flows/$id/ping.txt" 2>&1 || true
  done < <(py "$RTP" flows --plan "$RT_PLAN")
  railcap_stop
  while IFS=$'\t' read -r id node ns dst icmp; do
    [ -n "$id" ] || continue
    H "$node" "ip netns exec $ns traceroute -n -w 2 -q 3 -m 4 $dst" >"$RS/flows/$id/traceroute.txt" 2>&1 || true
  done < <(py "$RTP" flows --plan "$RT_PLAN")
  railtrace_captures "$RS/captures-df"
  mkdir -p "$RS/df"
  while IFS=$'\t' read -r id node ns dst payload icmp; do
    [ -n "$id" ] || continue
    rt_ping "$node" "$ns" -c 3 -i 0.5 -W 2 -M "do" -s "$payload" -e "$icmp" "$dst" >"$RS/df/$id.txt" 2>&1 || true
  done < <(py "$RTP" df --plan "$RT_PLAN")
  railcap_stop
  trap - EXIT
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$RTP" judge --set "$RS" --plan "$RT_PLAN" --inv "$INV" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  summary
}
