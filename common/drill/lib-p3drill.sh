# shellcheck shell=bash
# common/drill/lib-p3drill.sh: Part III's drills (FRAMEWORK.md section 4.6), sourced by a chapter's
# drills.sh after lib.sh's sfab_init drills, which opened audits/<lab>_drills_<UTC>/. The plan is
# gen/drills.json (sfab.render.drills, kind part3; render/tenancy.py renders each drill):
#
#   p3drills_main                --drills "ID ..." --passes N: every pass runs every drill (a drill's
#                                max_passes caps how many passes run it), then p3drill.py summarize
#                                writes DRILLS.md
#   leasedrill PASS ID           chapter 8's lease-holder loss: the probes started (probe_echo.py and
#                                probe_tcp.py in each client, probe_gateway.py for the model beside
#                                them), the leases read every 0.5 s on the lab host, the pods' places
#                                and the EndpointSlices read every 2 s, the firewall's ARP table read;
#                                after lead_s the node holding the most leases is cut from the pair
#                                (KLISH shutdown on its two pair ports, the restore pushed first),
#                                held hold_s, given no shutdown; after tail_s the probes stop, the lab
#                                is waited on until whole, and p3drill.py analyze-lease judges
#   leakdrill PASS ID            chapter 11's leaked key: a new key of an application caller of
#                                another audience (batch's) minted by a key Job, handed to the
#                                internet client, sent through the internet Gateway until answered
#                                200, then revoked and sent until refused 401; the API gateway's
#                                access log read, the key Secret's fields read before and after
#   isodrill PASS ID             chapter 11's isolation under load: for each load factor, every
#                                population's held connections (lib-tenancy.sh hold_start), then
#                                probe_isolation.py in each client (its own Gateway's /echo and the
#                                matrix's cells it must not reach, rounds times), the session counts
#                                read while held, the load stopped; p3drill.py analyze-isolation
#                                prints one line a population with its allowed count and its zeros
#
# Every restore is pushed before its change and runs last-in first-out from the EXIT trap whatever
# happens. Every stamp is the lab host's clock (date +%s.%N here; a container's clock is the host's).

P3D="$SFAB_COMMON/drill/p3drill.py"
P3D_PLAN="$RENDERDIR/gen/drills.json"
P3D_DIR=/tmp/sfab-p3drill
P3D_RESTORES=()
P3D_BG=()
# shellcheck source=common/audit/lib-tenancy.sh
. "$SFAB_COMMON/audit/lib-tenancy.sh"

p3d_get() { py "$P3D" get --plan "$P3D_PLAN" "$1"; }
# p3d_warning_namespaces NS...: the namespaces given, then every other namespace holding a Warning event
# now, each once
p3d_warning_namespaces() {
  { printf '%s\n' "$@"
    EVID_OFF=1 K get events -A --field-selector type=Warning -o jsonpath='{range .items[*]}{.metadata.namespace}{"\n"}{end}' 2>/dev/null || true
  } | awk 'NF && !seen[$0]++'
}
p3d_now() { date +%s.%N; }
p3d_tl() { printf '%s %s\n' "$(p3d_now)" "$*" >>"$D/timeline.txt"; }
p3d_restore_add() { P3D_RESTORES+=("$*"); }
p3d_restore_run() {
  local i
  for ((i = ${#P3D_RESTORES[@]} - 1; i >= 0; i--)); do eval "${P3D_RESTORES[$i]}" || true; done
  P3D_RESTORES=()
}
p3d_cleanup() {
  local p
  p3d_restore_run
  for p in "${P3D_BG[@]+"${P3D_BG[@]}"}"; do kill "$p" 2>/dev/null || true; done
  hold_cleanup
}

p3d_begin() {
  PASS="$1" DRILL_ID="$2"
  D="$RS/pass$PASS/$DRILL_ID"
  mkdir -p "$D/logs" "$D/probes"
  : >"$D/timeline.txt"
  sec "pass $PASS, drill $DRILL_ID: $(p3d_get "list.$DRILL_ID.title")"
  echo "drill: pass $PASS $DRILL_ID ($(p3d_get "list.$DRILL_ID.title"))"
}

p3d_quick_audit() {
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

# p3d_whole TAG: both ingress nodes' bonds up on both legs and every Gateway's lease on an ingress
# node, in whole_polls consecutive polls 5 s apart, within settle_max_s; the reads into D/TAG/
p3d_whole() {
  local tag="$1" dir t0 good=0 n polls max ok_now
  dir="$D/$tag"
  mkdir -p "$dir"
  polls="$(p3d_get timing.whole_polls)" max="$(p3d_get timing.settle_max_s)"
  t0="$(date +%s)"
  while :; do
    for n in $(p3d_get "list.$DRILL_ID.ingress" 2>/dev/null || tn_get audiences.ingress_nodes); do
      EVID_OFF=1 H "$n" "cat /proc/net/bonding/bond0" >"$dir/bond-$n.txt" 2>&1 || true
    done
    EVID_OFF=1 K -n kube-system get leases -o json >"$dir/leases.json" 2>/dev/null || true
    ok_now="$(py "$P3D" whole --plan "$P3D_PLAN" --tenancy "$TN_PLAN" --dir "$dir" 2>/dev/null || echo no)"
    if [ "$ok_now" = yes ]; then good=$((good + 1)); else good=0; fi
    [ "$good" -lt "$polls" ] || break
    [ $(($(date +%s) - t0)) -lt "$max" ] || break
    sleep "${SFAB_DRILL_POLL_S:-5}"
  done
  py "$P3D" whole --plan "$P3D_PLAN" --tenancy "$TN_PLAN" --dir "$dir" --explain >"$dir/whole.txt" 2>&1 || true
  if [ "$good" -ge "$polls" ]; then
    ok "pass $PASS $DRILL_ID: the lab whole $tag ($(cat "$dir/whole.txt"))"
    return 0
  fi
  bad "pass $PASS $DRILL_ID: the lab whole $tag" "$(cat "$dir/whole.txt")"
  return 1
}

# --------------------------------------------------------------------------------------------
# chapter 8: the lease-holder loss

p3d_bg_loop() {  # p3d_bg_loop OUT SECONDS-BETWEEN CMD...: CMD every interval, each output a JSON line with its stamps
  local out="$1" iv="$2"
  shift 2
  (
    while [ ! -f "$D/stop-loops" ]; do
      local a b
      a="$(p3d_now)"
      b="$(EVID_OFF=1 "$@" 2>/dev/null | py -c 'import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    d = None
print(json.dumps(d, separators=(",", ":"), sort_keys=True))' 2>/dev/null || echo null)"
      printf '{"t0": %s, "t1": %s, "doc": %s}\n' "$a" "$(p3d_now)" "$b" >>"$out"
      sleep "$iv"
    done
  ) &
  P3D_BG+=("$!")
}

leasedrill() {
  p3d_begin "$1" "$2"
  local n i client url resolve iv civ addr cut sw rc=0 ca ns p
  iv="$(p3d_get "list.$DRILL_ID.interval_s")" civ="$(p3d_get "list.$DRILL_ID.connect_interval_s")"
  p3d_whole whole-before || { p3d_tl ABORT "the lab not whole"; return 2; }
  rm -f "$D/stop-loops"
  EVID_OFF=1 K get pods -A -o wide >"$D/pods-wide.txt" 2>&1 || true
  p3d_bg_loop "$D/leases.jsonl" 0.5 K -n kube-system get leases -o json
  for ns in $(p3d_get "list.$DRILL_ID.endpoints"); do
    p3d_bg_loop "$D/endpointslices-$ns.jsonl" 2 K -n "$ns" get endpointslices -o json
  done
  FW "show arp all" | fwt_body "show arp all" >"$D/arp-before.txt" 2>/dev/null || true
  # the probes, in each client: the echo probe and the connect loop, then the model probe
  n="$(p3d_get "list.$DRILL_ID.echo" | grep -c .)"
  for ((i = 0; i < n; i++)); do
    client="$(p3d_get "list.$DRILL_ID.echo.$i.client")" url="$(p3d_get "list.$DRILL_ID.echo.$i.url")"
    resolve="$(p3d_get "list.$DRILL_ID.echo.$i.resolve")" addr="$(p3d_get "list.$DRILL_ID.connect.$i.address")"
    dk exec "$(ctr "$client")" sh -c "umask 077; rm -rf $P3D_DIR; mkdir -p $P3D_DIR" >/dev/null 2>&1 || true
    dk exec -i "$(ctr "$client")" sh -c "cat >$P3D_DIR/probe_echo.py" <"$SFAB_COMMON/drill/probe_echo.py"
    dk exec -i "$(ctr "$client")" sh -c "cat >$P3D_DIR/probe_tcp.py" <"$SFAB_COMMON/drill/probe_tcp.py"
    X "$client" sh -c "nohup python3 $P3D_DIR/probe_echo.py --url $url --log $P3D_DIR/echo.jsonl --interval $iv --stop $P3D_DIR/stop${resolve:+ --resolve $resolve} >$P3D_DIR/echo.out 2>&1 </dev/null &" \
      >"$D/logs/echo-start-$client.txt" 2>&1 || true
    X "$client" sh -c "nohup python3 $P3D_DIR/probe_tcp.py $addr 443 3600 $civ 1 $P3D_DIR/tcp.log >$P3D_DIR/tcp.out 2>&1 </dev/null &" \
      >"$D/logs/tcp-start-$client.txt" 2>&1 || true
  done
  if [ -n "$(p3d_get "list.$DRILL_ID.model.client" 2>/dev/null || true)" ]; then
    client="$(p3d_get "list.$DRILL_ID.model.client")"
    if key_to_client "$(p3d_get "list.$DRILL_ID.model.keys.namespace")" "$(p3d_get "list.$DRILL_ID.model.keys.secret")" \
      "$(p3d_get "list.$DRILL_ID.model.model")" "$client" "$P3D_DIR/model" >"$D/model-key.txt" 2>&1; then
      dk exec -i "$(ctr "$client")" sh -c "cat >$P3D_DIR/probe_gateway.py" <"$SFAB_COMMON/drill/probe_gateway.py"
      ca=/shared/ca/root.crt
      X "$client" sh -c "nohup python3 $P3D_DIR/probe_gateway.py --dir $P3D_DIR/model --target $(p3d_get "list.$DRILL_ID.model.model") $(p3d_get "list.$DRILL_ID.model.url") --interval $iv --timeout 100 --max-tokens 4 --until-stop --cafile $ca >$P3D_DIR/model.out 2>&1 </dev/null &" \
        >"$D/logs/model-start.txt" 2>&1 || true
    else
      bad "pass $PASS $DRILL_ID: the key for the model probe handed to $client" "$(tail -n 1 "$D/model-key.txt")"
    fi
  fi
  p3d_tl PROBES "echo and connects from $(p3d_get "list.$DRILL_ID.echo" | py -c 'import json, sys; print(" ".join(json.loads(l)["client"] for l in sys.stdin if l.strip()))')"
  sleep "$(p3d_get timing.lead_s)"
  # the cut: the ingress node holding the most leases, read now
  EVID_OFF=1 K -n kube-system get leases -o json >"$D/leases-at-cut.json" 2>/dev/null || true
  cut="$(py "$P3D" holder --plan "$P3D_PLAN" --drill "$DRILL_ID" --leases "$D/leases-at-cut.json")"
  [ -n "$cut" ] || { bad "pass $PASS $DRILL_ID: the node holding the most leases" "no lease held by an ingress node"; cut=""; }
  if [ -n "$cut" ]; then
    printf '%s\n' "$cut" >"$D/cut-node.txt"
    for sw in $(p3d_get "list.$DRILL_ID.candidates.$cut.shut" | py -c 'import json, sys; print(" ".join(sorted(json.loads(sys.stdin.read()))))'); do
      p3d_restore_add "p3d_klish $sw restore $cut"
    done
    p3d_tl CUT "$cut"
    for sw in $(p3d_get "list.$DRILL_ID.candidates.$cut.shut" | py -c 'import json, sys; print(" ".join(sorted(json.loads(sys.stdin.read()))))'); do
      p3d_klish "$sw" shut "$cut" || rc=1
    done
    p3d_tl SHUT "$cut"
    known L9 "pass $PASS $DRILL_ID: the cut node sees no loss of carrier on the virtual switch's ports; it loses its leases because it cannot renew them"
    sleep "$(p3d_get timing.hold_s)"
    FW "show arp all" | fwt_body "show arp all" >"$D/arp-during.txt" 2>/dev/null || true
    p3d_tl RESTORE "$cut"
    p3d_restore_run
    p3d_tl RESTORED "$cut"
  fi
  sleep "$(p3d_get timing.tail_s)"
  # the probes stopped and fetched
  for ((i = 0; i < n; i++)); do
    client="$(p3d_get "list.$DRILL_ID.echo.$i.client")"
    dk exec "$(ctr "$client")" sh -c "touch $P3D_DIR/stop; sleep 4; pkill -f '[p]robe_tcp.py' || true" >/dev/null 2>&1 || true
    dk exec "$(ctr "$client")" cat "$P3D_DIR/echo.jsonl" >"$D/probes/echo-$client.jsonl" 2>/dev/null || true
    dk exec "$(ctr "$client")" cat "$P3D_DIR/tcp.log" >"$D/probes/tcp-$client.log" 2>/dev/null || true
  done
  if [ -n "$(p3d_get "list.$DRILL_ID.model.client" 2>/dev/null || true)" ]; then
    client="$(p3d_get "list.$DRILL_ID.model.client")"
    dk exec "$(ctr "$client")" sh -c "touch $P3D_DIR/model/stop; sleep 3" >/dev/null 2>&1 || true
    dk exec "$(ctr "$client")" sh -c "cat $P3D_DIR/model/records-*.jsonl" >"$D/probes/model.jsonl" 2>/dev/null || true
  fi
  for ((i = 0; i < n; i++)); do
    client="$(p3d_get "list.$DRILL_ID.echo.$i.client")"
    key_clear "$client" "$P3D_DIR"
  done
  touch "$D/stop-loops"
  for p in "${P3D_BG[@]+"${P3D_BG[@]}"}"; do wait "$p" 2>/dev/null || true; done
  P3D_BG=()
  p3d_whole whole-after || rc=2
  FW "show arp all" | fwt_body "show arp all" >"$D/arp-after.txt" 2>/dev/null || true
  # The cut node's pods draw Warning events (NodeNotReady among them) in every namespace with a pod on
  # it, the identity provider's included; each such namespace's are saved here and cleared, as the
  # gateway drills do, since the next full audit wants none since finish.
  events_archive "$D/events" $(p3d_warning_namespaces "$(p3d_get "list.$DRILL_ID.endpoints" | head -n 1)" kube-system) >/dev/null 2>&1 || true
  p3d_quick_audit
  py "$P3D" analyze-lease --plan "$P3D_PLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analyze.out"
  return "$rc"
}

# p3d_klish SWITCH shut|restore NODE: the plan's KLISH session for that node's port on that switch
p3d_klish() {
  local sw="$1" what="$2" node="$3" lines=()
  mapfile -t lines < <(p3d_get "list.$DRILL_ID.candidates.$node.$what.$sw")
  SFAB_SESSION_TIMEOUT="${SFAB_DRILL_SESSION_S:-90}" SW "$sw" "${lines[@]}" >"$D/klish-$what-$sw.txt" 2>&1 || true
  if grep -qE '%[[:space:]]?Error' "$D/klish-$what-$sw.txt"; then
    bad "pass $PASS $DRILL_ID: $what on $sw for $node" "the switch answered % Error"
    return 1
  fi
}

# --------------------------------------------------------------------------------------------
# chapter 11: isolation under load

isodrill() {
  p3d_begin "$1" "$2"
  local f n i client rows rc=0 factor dir
  TN_PLAN="$P3D_PLAN.hold.json"
  py -c 'import json, sys; d = json.load(open(sys.argv[1])); x = next(i for i in d["list"] if i["id"] == sys.argv[2]); json.dump({"hold": x["hold"]}, open(sys.argv[3], "w"))' \
    "$P3D_PLAN" "$DRILL_ID" "$TN_PLAN"
  rows="$(p3d_get "list.$DRILL_ID.rows" | grep -c .)"
  for factor in $(p3d_get "list.$DRILL_ID.factors"); do
    dir="$D/x$factor"
    mkdir -p "$dir"
    n=$(($(tn_get hold.n) * factor))
    sec "pass $PASS $DRILL_ID: $n held connection(s) a population"
    for ((i = 0; i < rows; i++)); do hold_start "$dir" "$i" "$n" 900; done
    for ((i = 0; i < rows; i++)); do hold_wait "$dir" "$i" 120 || true; done
    p3d_tl HELD "x$factor"
    sleep "$(p3d_get timing.lead_s)"
    for ((i = 0; i < rows; i++)); do
      client="$(p3d_get "list.$DRILL_ID.rows.$i.client")"
      py "$P3D" iso-plan --plan "$P3D_PLAN" --drill "$DRILL_ID" --row "$i" | dk exec -i "$(ctr "$client")" sh -c "umask 077; mkdir -p $P3D_DIR; cat >$P3D_DIR/iso-plan.json"
      dk exec -i "$(ctr "$client")" sh -c "cat >$P3D_DIR/probe_isolation.py" <"$SFAB_COMMON/drill/probe_isolation.py"
      X "$client" sh -c "nohup python3 $P3D_DIR/probe_isolation.py --plan $P3D_DIR/iso-plan.json --log $P3D_DIR/iso.jsonl >$P3D_DIR/iso.out 2>&1 </dev/null &" \
        >"$dir/iso-start-$client.txt" 2>&1 || true
    done
    p3d_tl TRIES "x$factor"
    py -c 'import sys, time; time.sleep(float(sys.argv[1]) * float(sys.argv[2]) + 15)' "$(p3d_get "list.$DRILL_ID.rounds")" "$(p3d_get "list.$DRILL_ID.interval_s")"
    hold_counts "$dir" held
    for ((i = 0; i < rows; i++)); do
      client="$(p3d_get "list.$DRILL_ID.rows.$i.client")"
      for _ in $(seq 1 60); do
        dk exec "$(ctr "$client")" sh -c "grep -q '\"done\"' $P3D_DIR/iso.jsonl" >/dev/null 2>&1 && break
        sleep 2
      done
      dk exec "$(ctr "$client")" cat "$P3D_DIR/iso.jsonl" >"$dir/iso-$(p3d_get "list.$DRILL_ID.rows.$i.population").jsonl" 2>/dev/null || true
      dk exec "$(ctr "$client")" rm -rf "$P3D_DIR" >/dev/null 2>&1 || true
    done
    for ((i = 0; i < rows; i++)); do hold_stop "$dir" "$i"; done
    p3d_tl STOPPED "x$factor"
    sleep "$(p3d_get timing.tail_s)"
  done
  p3d_quick_audit
  py "$P3D" analyze-isolation --plan "$P3D_PLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analyze.out"
  TN_PLAN="$RENDERDIR/gen/tenancy.json"
  return "$rc"
}

# --------------------------------------------------------------------------------------------
# chapter 11: the leaked key

# p3d_ask OUT CLIENT URL HDR WANT MAX_S IV [RESOLVE]: one chat completion every IV seconds with the
# key in HDR (a 0600 file in the client) until the answer is WANT or MAX_S passes; each "<t> <status>"
p3d_ask() {
  local out="$1" client="$2" url="$3" hdr="$4" want="$5" max="$6" iv="$7" resolve="${8:-}" t0 st pin=()
  [ -z "$resolve" ] || pin=(--resolve "$resolve")
  t0="$(date +%s)"
  : >"$out"
  while :; do
    st="$(X "$client" curl -sS --max-time 60 "${pin[@]+"${pin[@]}"}" --cacert "$(p3d_get "list.$DRILL_ID.ca_root")" -o "$P3D_DIR/answer.json" \
      -w '%{http_code}\n' -H 'Content-Type: application/json' -H "@$hdr" --data "@$P3D_DIR/body.json" "$url" 2>/dev/null | tail -n 1 || true)"
    printf '%s %s\n' "$(p3d_now)" "${st:-000}" >>"$out"
    [ "${st:-}" != "$want" ] || return 0
    [ $(($(date +%s) - t0)) -lt "$max" ] || return 1
    sleep "$iv"
  done
}

leakdrill() {
  p3d_begin "$1" "$2"
  local client model caller id field ns sec url resolve iv max rc=0 kid
  client="$(p3d_get "list.$DRILL_ID.client")" model="$(p3d_get "list.$DRILL_ID.model")" caller="$(p3d_get "list.$DRILL_ID.caller")"
  ns="$(p3d_get "list.$DRILL_ID.keys.namespace")" sec="$(p3d_get "list.$DRILL_ID.keys.secret")"
  url="$(p3d_get "list.$DRILL_ID.url")" resolve="$(p3d_get "list.$DRILL_ID.resolve")"
  iv="$(p3d_get "list.$DRILL_ID.interval_s")" max="$(p3d_get "list.$DRILL_ID.accept_max_s")"
  kid="$(py -c 'import sys; print(format(int(sys.argv[1], 16) + int(sys.argv[2]), "08x"))' "$(p3d_get "list.$DRILL_ID.id_base")" "$PASS")"
  field="$caller.$kid"
  printf '%s\n' "$field" >"$D/field.txt"
  EVID_OFF=1 K -n "$ns" get secret "$sec" -o json 2>/dev/null | py "$SFAB_COMMON/trace/servekeys.py" list >"$D/keys-before.txt" 2>&1 || true
  p3d_restore_add "keyjob_run $(p3d_get "list.$DRILL_ID.probe")-leak-restore $D/revoke-restore.log revoke $model $kid $caller >/dev/null 2>&1 || true"
  p3d_tl MINT "$field"
  if keyjob_run "$(p3d_get "list.$DRILL_ID.probe")-leak-mint" "$D/mint.log" mint "$model" "$kid" "$caller"; then
    p3d_tl MINTED "$field"
  else
    bad "pass $PASS $DRILL_ID: the key Job minted $field" "$(tail -n 1 "$D/mint.log")"
    p3d_restore_run
    return 1
  fi
  dk exec "$(ctr "$client")" sh -c "umask 077; rm -rf $P3D_DIR; mkdir -p $P3D_DIR" >/dev/null 2>&1 || true
  printf '%s\n' "{\"model\": \"$model\", \"max_tokens\": 1, \"messages\": [{\"role\": \"user\", \"content\": \"Say yes.\"}]}" |
    dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$P3D_DIR/body.json"
  KEY_CALLER="$caller" key_to_client "$ns" "$sec" "$model" "$client" "$P3D_DIR" "$field" leaked >"$D/key.txt" 2>&1 || \
    bad "pass $PASS $DRILL_ID: the new key handed to $client" "$(tail -n 1 "$D/key.txt")"
  p3d_ask "$D/requests-minted.txt" "$client" "$url" "$P3D_DIR/hdr-leaked" 200 "$max" "$iv" "$resolve" || true
  p3d_tl ANSWERED "$(tail -n 1 "$D/requests-minted.txt")"
  p3d_tl REVOKE "$field"
  if keyjob_run "$(p3d_get "list.$DRILL_ID.probe")-leak-revoke" "$D/revoke.log" revoke "$model" "$kid" "$caller"; then
    p3d_tl REVOKED "$field"
    P3D_RESTORES=()
  else
    bad "pass $PASS $DRILL_ID: the key Job revoked $field" "$(tail -n 1 "$D/revoke.log")"
    rc=1
  fi
  p3d_ask "$D/requests-revoked.txt" "$client" "$url" "$P3D_DIR/hdr-leaked" "$(p3d_get "list.$DRILL_ID.rejected.code")" "$max" "$iv" "$resolve" || true
  p3d_tl REFUSED "$(tail -n 1 "$D/requests-revoked.txt")"
  key_clear "$client" "$P3D_DIR"
  K -n "$(p3d_get "list.$DRILL_ID.api_gateway.namespace")" logs -l "$(p3d_get "list.$DRILL_ID.api_gateway.selector")" -c apisix --prefix --tail=-1 \
    --since=15m >"$D/api-gateway-access.txt" 2>&1 || true
  EVID_OFF=1 K -n "$ns" get secret "$sec" -o json 2>/dev/null | py "$SFAB_COMMON/trace/servekeys.py" list >"$D/keys-after.txt" 2>&1 || true
  p3d_quick_audit
  py "$P3D" analyze-leak --plan "$P3D_PLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analyze.out"
  return "$rc"
}

# --------------------------------------------------------------------------------------------

p3drills_main() {
  local want="" passes=3 i d p ids=() stop=0 kind maxp
  for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
    case "${SFAB_ARGS[$i]}" in
      --drills) want="${SFAB_ARGS[$((i + 1))]:-}" ;;
      --passes) passes="${SFAB_ARGS[$((i + 1))]:-3}" ;;
    esac
  done
  [ -f "$P3D_PLAN" ] || die "drills: no $P3D_PLAN (chapter.yaml has no drills block, or make render)"
  [[ "$passes" =~ ^[1-9][0-9]*$ ]] || die "drills: --passes wants a positive number, got $passes"
  mapfile -t ids < <(py -c 'import json, sys; [print(d["id"]) for d in json.load(open(sys.argv[1]))["list"] if d.get("kind") in ("lease-loss", "isolation", "leaked-key")]' "$P3D_PLAN")
  [ ${#ids[@]} -gt 0 ] || die "drills: $P3D_PLAN holds no Part III drill"
  if [ -n "$want" ]; then
    for d in $want; do
      case " ${ids[*]} " in *" $d "*) ;; *) die "drills: no drill $d (have ${ids[*]})" ;; esac
    done
    read -r -a ids <<<"$want"
  fi
  exec 8>"$STATEDIR/lock"
  flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"
  cp "$P3D_PLAN" "$RS/drills.json"
  {
    printf 'drills: %s\npasses: %s\n' "${ids[*]}" "$passes"
    printf 'host tick: %s\n' "$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null || echo unreadable)"
  } >"$RS/RUNPLAN.txt"
  trap p3d_cleanup EXIT
  for p in $(seq 1 "$passes"); do
    for d in "${ids[@]}"; do
      local rc=0
      kind="$(p3d_get "list.$d.kind")" maxp="$(p3d_get "list.$d.max_passes" 2>/dev/null || true)"
      if [ -n "$maxp" ] && [ "$p" -gt "$maxp" ]; then
        echo "drill: pass $p $d skipped (it runs in the first $maxp pass(es))"
        continue
      fi
      case "$kind" in
        lease-loss) leasedrill "$p" "$d" || rc=$? ;;
        isolation) isodrill "$p" "$d" || rc=$? ;;
        leaked-key) leakdrill "$p" "$d" || rc=$? ;;
      esac
      if [ "$rc" -eq 2 ]; then
        warn "drills: pass $p $d left the lab not whole; the remaining drills are not run"
        stop=1
        break
      fi
    done
    [ "$stop" = 0 ] || break
  done
  trap - EXIT
  p3d_cleanup
  py "$P3D" summarize --set "$RS" ${SFAB_TICK_STAMP:+--stamp "$SFAB_TICK_STAMP"} >/dev/null 2>&1 || warn "drills: p3drill.py summarize failed"
  summary
}
