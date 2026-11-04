# shellcheck shell=bash
# common/trace/lib-railcap.sh: the captures chapter 5's trace, drill and break share. Sourced after
# lib.sh's sfab_init. Two kinds of capture point:
#
#   railcap_host_start NODE ETH PCAP FILTER SECONDS
#       tcpdump on the lab host in NODE's own container namespace (nsenter -t <pid> -n), on its
#       container port ETH: a switch port, or a VM guest's container port, as the wire carries it
#   railcap_guest_start NODE IFACE TAG FILTER SECONDS TXT [PCAP]
#       tcpdump inside VM guest NODE on IFACE (its relay bridge, a rail NIC), started in the
#       background over SSH; railcap_stop decodes it inside the guest, so the decode names the
#       guest's own interfaces, and fetches the decode into TXT and the pcap into PCAP
#
#   railcap_pod_start NODE PID IFACE TAG FILTER SECONDS TXT [PCAP]
#       the same inside the network namespace of process PID in guest NODE (a pod's sandbox, found
#       with crictl: chapter 6), so IFACE is the pod's own (eth0, a rail attachment)
#
#   RAILCAP_SNAPLEN               the capture length of the captures started after it is set (256 by
#                                 default; chapter 6 captures headers only on a pod's cluster interface)
#   RAILCAP_SCRUB=1               a guest or pod capture started with it set is never decoded in the
#                                 guest: railcap_stop takes its pcap out of the guest on a pipe through
#                                 common/trace/keyscrub.py (every Authorization value and key-shaped
#                                 token replaced by its mark under the lab's redaction key), writes the
#                                 scrubbed pcap, and decodes that one on the lab host, as TXT and with
#                                 -A as TXT's -payload.txt twin, which shows the payload's lines and no
#                                 key (chapter 7's keyed trace)
#   railcap_wait                  until every capture started has its pcap, then SFAB_RAILCAP_SETTLE_S
#   railcap_stop                  every capture stopped with SIGINT (host ones waited on by PID, never
#                                 a bare wait; guest ones until pgrep no longer finds them), host
#                                 pcaps decoded beside themselves as .txt with $RAILCAP_DECODE (default
#                                 -nn -e -tttt -v), guest ones decoded in the guest the same way
#
# Every capture also ends by itself after SECONDS (timeout), so one that missed its SIGINT can
# never outlive the run by more than that. Nothing here changes a device.

RAILCAP_GUEST_DIR=/tmp/sfab-rail
RAILCAP_HOST_PIDS=()
RAILCAP_HOST_PCAPS=()
RAILCAP_GUEST=()   # node|tag|txt|pcap|scrub

# A guest-side process is found by its pcap's name with the first letter bracketed, so the
# pattern never matches the shell that runs pkill or pgrep.
railcap_gpat() { printf '[s]fab-rail-%s.pcap' "$1"; }

railcap_host_start() {
  local node="$1" eth="$2" pcap="$3" filt="$4" secs="$5" pid
  pid="$(pid_of "$node")"
  [ "$pid" != 0 ] || { warn "capture: $node is not running"; return 0; }
  mkdir -p "$(dirname "$pcap")"
  local snap="${RAILCAP_SNAPLEN:-256}"
  _evid "$node" capture "+ nsenter -t $pid -n timeout $secs tcpdump -i $eth -nn -s $snap -U -w ${pcap#"$RS"/} '$filt'"
  nsenter -t "$pid" -n timeout "$secs" tcpdump -i "$eth" -nn -s "$snap" -U -w "$pcap" "$filt" >"${pcap%.pcap}.log" 2>&1 </dev/null &
  RAILCAP_HOST_PIDS+=("$!")
  RAILCAP_HOST_PCAPS+=("$pcap")
}

railcap_guest_start() {
  local node="$1" iface="$2" tag="$3" filt="$4" secs="$5" txt="$6" pcap="${7:-}" snap="${RAILCAP_SNAPLEN:-256}"
  HBG "$node" "mkdir -p $RAILCAP_GUEST_DIR; rm -f $RAILCAP_GUEST_DIR-$tag.pcap $RAILCAP_GUEST_DIR-$tag.txt; exec timeout $secs tcpdump -i $iface -nn -s $snap -U -w $RAILCAP_GUEST_DIR-$tag.pcap '$filt'" >/dev/null
  RAILCAP_GUEST+=("$node|$tag|$txt|$pcap|${RAILCAP_SCRUB:-0}")
}

railcap_pod_start() {
  local node="$1" ppid="$2" iface="$3" tag="$4" filt="$5" secs="$6" txt="$7" pcap="${8:-}" snap="${RAILCAP_SNAPLEN:-256}"
  HBG "$node" "mkdir -p $RAILCAP_GUEST_DIR; rm -f $RAILCAP_GUEST_DIR-$tag.pcap $RAILCAP_GUEST_DIR-$tag.txt; exec nsenter -t $ppid -n timeout $secs tcpdump -i $iface -nn -s $snap -U -w $RAILCAP_GUEST_DIR-$tag.pcap '$filt'" >/dev/null
  RAILCAP_GUEST+=("$node|$tag|$txt|$pcap|${RAILCAP_SCRUB:-0}")
}

railcap_wait() {
  local missing p g node tag
  for _ in $(seq 1 "${SFAB_RAILCAP_START_S:-30}"); do
    missing=0
    for p in "${RAILCAP_HOST_PCAPS[@]+"${RAILCAP_HOST_PCAPS[@]}"}"; do [ -f "$p" ] || missing=$((missing + 1)); done
    for g in "${RAILCAP_GUEST[@]+"${RAILCAP_GUEST[@]}"}"; do
      IFS='|' read -r node tag _ _ <<<"$g"
      EVID_OFF=1 H "$node" "test -f $RAILCAP_GUEST_DIR-$tag.pcap" >/dev/null 2>&1 || missing=$((missing + 1))
    done
    [ "$missing" -gt 0 ] || break
    sleep 1
  done
  sleep "${SFAB_RAILCAP_SETTLE_S:-3}"
  [ "$missing" -eq 0 ] || warn "capture: $missing capture point(s) without a pcap"
  return 0
}

railcap_stop() {
  local dec="${RAILCAP_DECODE:--nn -e -tttt -v}" p g node tag txt pcap scrub
  sleep "${SFAB_RAILCAP_TAIL_S:-2}"
  for p in "${RAILCAP_HOST_PIDS[@]+"${RAILCAP_HOST_PIDS[@]}"}"; do kill -INT "$p" 2>/dev/null || true; done
  for p in "${RAILCAP_HOST_PIDS[@]+"${RAILCAP_HOST_PIDS[@]}"}"; do wait "$p" 2>/dev/null || true; done
  for p in "${RAILCAP_HOST_PCAPS[@]+"${RAILCAP_HOST_PCAPS[@]}"}"; do
    if [ -f "$p" ]; then
      # shellcheck disable=SC2086 # the decode's own arguments
      tcpdump $dec -r "$p" >"${p%.pcap}.txt" 2>&1 || true
    fi
  done
  for g in "${RAILCAP_GUEST[@]+"${RAILCAP_GUEST[@]}"}"; do
    IFS='|' read -r node tag txt pcap scrub <<<"$g"
    EVID_OFF=1 H "$node" "pkill -INT -f '$(railcap_gpat "$tag")' || true" >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do
      EVID_OFF=1 H "$node" "pgrep -f '$(railcap_gpat "$tag")' >/dev/null" >/dev/null 2>&1 || break
      sleep 1
    done
    if [ "${scrub:-0}" = 1 ]; then
      railcap_scrubbed "$node" "$tag" "$txt" "$pcap" "$dec"
      continue
    fi
    H "$node" "tcpdump $dec -r $RAILCAP_GUEST_DIR-$tag.pcap > $RAILCAP_GUEST_DIR-$tag.txt 2>&1; wc -l < $RAILCAP_GUEST_DIR-$tag.txt" >/dev/null 2>&1 || true
    mkdir -p "$(dirname "$txt")"
    EVID_OFF=1 H "$node" "cat $RAILCAP_GUEST_DIR-$tag.txt" >"$txt" 2>/dev/null || true
    if [ -n "$pcap" ]; then
      EVID_OFF=1 H "$node" "base64 -w0 $RAILCAP_GUEST_DIR-$tag.pcap" 2>/dev/null | base64 -d >"$pcap" 2>/dev/null || true
    fi
    EVID_OFF=1 H "$node" "rm -f $RAILCAP_GUEST_DIR-$tag.pcap $RAILCAP_GUEST_DIR-$tag.txt" >/dev/null 2>&1 || true
  done
  RAILCAP_HOST_PIDS=() RAILCAP_HOST_PCAPS=() RAILCAP_GUEST=()
}

# railcap_scrubbed NODE TAG TXT PCAP DECODE: a keyed capture out of the guest. The raw pcap travels
# only on a pipe, from the guest through keyscrub.py into PCAP; it is removed in the guest after, and
# the scrubbed PCAP is decoded on the lab host into TXT, and with -A (the payload's lines, through
# keyscrub.py text once more) into TXT's -payload.txt twin. A capture whose pcap cannot be fetched
# leaves an empty TXT.
railcap_scrubbed() {
  local node="$1" tag="$2" txt="$3" pcap="$4" dec="$5" err
  [ -n "$pcap" ] || pcap="${txt%.txt}.pcap"
  mkdir -p "$(dirname "$pcap")" "$(dirname "$txt")"
  err="$(tmpf)"
  EVID_OFF=1 H "$node" "base64 -w0 $RAILCAP_GUEST_DIR-$tag.pcap" 2>/dev/null | base64 -d 2>/dev/null |
    py "$SFAB_COMMON/trace/keyscrub.py" pcap --key "$STATEDIR/secrets/redact.key" >"$pcap" 2>"$err" || true
  EVID_OFF=1 H "$node" "rm -f $RAILCAP_GUEST_DIR-$tag.pcap $RAILCAP_GUEST_DIR-$tag.txt" >/dev/null 2>&1 || true
  if [ -s "$pcap" ]; then
    # shellcheck disable=SC2086 # the decode's own arguments
    tcpdump $dec -r "$pcap" >"$txt" 2>&1 || true
    # shellcheck disable=SC2086
    tcpdump $dec -A -r "$pcap" 2>&1 | py "$SFAB_COMMON/trace/keyscrub.py" text --key "$STATEDIR/secrets/redact.key" >"${txt%.txt}-payload.txt" 2>/dev/null || true
  else
    rm -f "$pcap"
    : >"$txt"
  fi
  printf '%s %s\n' "$(basename "$pcap")" "$(tail -n 1 "$err")" >>"$(dirname "$pcap")/scrub.log"
  rm -f "$err"
}

# railcap_cleanup: stop whatever is still running (an EXIT trap), decoding nothing
railcap_cleanup() {
  local p g node tag
  for p in "${RAILCAP_HOST_PIDS[@]+"${RAILCAP_HOST_PIDS[@]}"}"; do kill -INT "$p" 2>/dev/null || true; done
  for g in "${RAILCAP_GUEST[@]+"${RAILCAP_GUEST[@]}"}"; do
    IFS='|' read -r node tag _ _ scrub <<<"$g"
    EVID_OFF=1 H "$node" "pkill -INT -f '$(railcap_gpat "$tag")' || true" >/dev/null 2>&1 || true
    # a keyed capture's raw pcap holds keys: it never stays in the guest
    [ "${scrub:-0}" != 1 ] || EVID_OFF=1 H "$node" "sleep 1; rm -f $RAILCAP_GUEST_DIR-$tag.pcap" >/dev/null 2>&1 || true
  done
  RAILCAP_HOST_PIDS=() RAILCAP_HOST_PCAPS=() RAILCAP_GUEST=()
}
