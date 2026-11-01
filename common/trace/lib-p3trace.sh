# shellcheck shell=bash
# common/trace/lib-p3trace.sh: Part III's traces (FRAMEWORK.md 4.5), recorded as
# audits/<lab>_trace_<UTC>/ with TRACE.md, verdict.txt and captures/. A chapter's trace.sh is
#
#   . "$(dirname "$0")/../common/lib.sh"; sfab_init trace "$@"
#   . "$SFAB_COMMON/trace/lib-p3trace.sh"; p3trace_run
#
# The plan is gen/trace.json (sfab.render.trace), one of three forms:
#
#   dns     chapter 9. Every point captures at once (each population's resolver on its port, port
#           53; the rungs the connects cross, tcp 443), on the lab host in the node's own namespace
#           (nsenter and tcpdump); then each population's client looks the name up through its own
#           resolver (dig, the container's or the guest's) and connects toward the answer from its
#           pinned source port (common/trace/syn_connect.py); the captures stop, and the traffic log
#           is read until it holds every connect that crossed the firewall
#   nat     chapter 10. For each population in turn: its capture points start (the point outside the
#           firewall and both legs), then chapter 4's held session (lib-fwtrace.sh fwtrace_session:
#           the request held after the reply while show session all and show session id are read,
#           the traffic log after it closes), then its captures stop, into captures/<population>/
#   ladder  chapter 11. The Gateways' leases read; one warm-up connect per population to its own
#           Gateway (warmup/), so the pair's MAC tables hold every lease holder's MAC; the pair's MAC
#           tables read (pair/); every rung captures (the ISP router's link, the staff's firewall
#           port, both legs, the pair's ports facing the ingress nodes on the lab host, each ingress
#           node's VLAN 110 unit in its guest); every flow's connects, a forbidden one from tries
#           source ports (connects/); the captures stop
#
# p3trace.py judges the saved files and writes TRACE.md. Changes nothing on any device; every process
# it starts it stops.

P3P="$SFAB_COMMON/trace/p3trace.py"
P3_PLAN="$RENDERDIR/gen/trace.json"
# shellcheck source=common/audit/lib-tenancy.sh
. "$SFAB_COMMON/audit/lib-tenancy.sh"

p3_get() { py "$P3P" get --plan "$P3_PLAN" "$1"; }

# p3_captures DIR [SESSION]: start the plan's capture points (a session's only, for the NAT trace)
p3_captures() {
  local dir="$1" sess="${2:-}" id kind node port filt args=()
  mkdir -p "$dir"
  [ -z "$sess" ] || args=(--session "$sess")
  py "$P3P" points --plan "$P3_PLAN" "${args[@]+"${args[@]}"}" >"$dir/points.tsv"
  while IFS=$'\t' read -r id kind node port filt; do
    [ -n "$id" ] || continue
    if [ "$kind" = guest ]; then
      RAILCAP_SNAPLEN="$(p3_get snaplen)" railcap_guest_start "$node" "$port" "p3-$id" "$filt" "$CAP_S" "$dir/$id.txt" "$dir/$id.pcap"
    else
      RAILCAP_SNAPLEN="$(p3_get snaplen)" railcap_host_start "$node" "$port" "$dir/$id.pcap" "$filt" "$CAP_S"
    fi
  done <"$dir/points.tsv"
  railcap_wait
  echo "trace: $(grep -c . "$dir/points.tsv") capture points started"
}

p3_stop() { RAILCAP_DECODE="-nn -tt -e -v -S" railcap_stop; }

p3_lookup() {  # p3_lookup OUT NODE KIND NAME: the client's own lookup through its resolver
  local out="$1" n="$2" kind="$3" name="$4"
  t_in "$n" "$kind" "dig +tries=1 +time=4 $name A" >"$out" 2>&1 || true
}

p3trace_dns() {
  local n i row pop client kind name addr sport
  p3_captures "$RS/captures"
  mkdir -p "$RS/lookups" "$RS/connects" "$RS/fw"
  n="$(p3_get rows | grep -c .)"
  for ((i = 0; i < n; i++)); do
    row="$(p3_get "rows.$i")"
    read -r pop client kind name addr sport <<<"$(py -c 'import json, sys; r = json.loads(sys.argv[1]); print(r["population"], r["client"], r["kind"], r["name"], r["syn"]["address"], r["syn"]["sport"])' "$row")"
    p3_lookup "$RS/lookups/$pop.txt" "$client" "$kind" "$name"
    t_connect "$RS/connects/$pop.txt" "$client" "$kind" "$addr" 443 "$sport"
    echo "trace: $pop looked up $name and connected toward $addr: $(awk 'NF >= 6 { print $5; exit }' "$RS/connects/$pop.txt")"
  done
  p3_stop
  if [ -n "${FW_NODE:-}" ]; then
    for i in $(seq 1 "${SFAB_TRACE_TLOG_TRIES:-9}"); do
      FW "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" |
        fwt_body "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" >"$RS/fw/traffic-log-443.txt" 2>/dev/null || true
      [ "$(py "$P3P" tlog-missing --set "$RS" --plan "$P3_PLAN")" != 0 ] || break
      sleep "${SFAB_TRACE_TLOG_PAUSE_S:-10}"
    done
  fi
}

p3trace_nat() {
  local id
  [ -n "${FW_NODE:-}" ] || die "trace: the lab has no firewall"
  FWT_PLAN="$P3_PLAN"
  while read -r id; do
    [ -n "$id" ] || continue
    p3_captures "$RS/captures/$id" "$id"
    fwtrace_session "$id"
    p3_stop
  done < <(py -c 'import json, sys; [print(s["id"]) for s in json.load(open(sys.argv[1]))["sessions"]]' "$P3_PLAN")
}

p3trace_ladder() {
  local f client kind addr port sport tries allowed sw lease
  mkdir -p "$RS/cluster" "$RS/warmup" "$RS/connects" "$RS/pair"
  EVID_OFF=1 K -n kube-system get leases -o json >"$RS/cluster/leases.json" 2>/dev/null || true
  K -n kube-system get leases >"$RS/cluster/leases.txt" 2>&1 || true
  # the warm-up: every population's allowed connect to each Gateway it may reach, from a source port
  # the ladder's own flows do not use, so the pair learns every lease holder's MAC
  while IFS=$'\t' read -r f client kind addr port sport tries allowed; do
    [ "$allowed" = 1 ] || continue
    t_connect "$RS/warmup/$(tn_slug "$f").txt" "$client" "$kind" "$addr" "$port" "$((sport + 2))"
  done < <(py "$P3P" flows --plan "$P3_PLAN")
  for sw in $(p3_get pair); do
    SW "$sw" "show mac address-table" | klish_body "show mac address-table" >"$RS/pair/$sw-mac.txt" 2>/dev/null || true
  done
  p3_captures "$RS/captures"
  while IFS=$'\t' read -r f client kind addr port sport tries allowed; do
    [ -n "$f" ] || continue
    _evid "$client" "$([ "$kind" = vm-node ] && echo guest || echo container)" "+ python3 - $addr $port $sport $tries ${SFAB_TN_CONNECT_S:-4} 0 < common/trace/syn_connect.py"
    t_py "$client" "$kind" "$SFAB_COMMON/trace/syn_connect.py" "$addr" "$port" "$sport" "$tries" "${SFAB_TN_CONNECT_S:-4}" 0 \
      >"$RS/connects/$(tn_slug "$f").txt" 2>&1 || true
  done < <(py "$P3P" flows --plan "$P3_PLAN")
  p3_stop
}

p3trace_run() {
  local kind stamp_args=()
  [ -f "$P3_PLAN" ] || die "trace: no $P3_PLAN (chapter.yaml has no trace block, or make render)"
  kind="$(p3_get kind)"
  case "$kind" in dns|nat|ladder) ;; *) die "trace: $P3_PLAN is a $kind trace, not one of Part III's" ;; esac
  cp "$P3_PLAN" "$RS/trace.json"
  CAP_S="${SFAB_TRACE_CAP_S:-600}"
  trap 'railcap_cleanup || true; fwtrace_cleanup || true' EXIT
  sec "the $kind trace"
  "p3trace_$kind"
  trap - EXIT
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$P3P" judge --set "$RS" --plan "$P3_PLAN" --inv "$INV" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  summary
}
