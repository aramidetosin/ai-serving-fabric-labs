# shellcheck shell=bash
# common/drill/lib-gwdrill.sh: chapter 7's gateway drills (FRAMEWORK.md section 4.6 as chapter 7
# uses it), sourced by a chapter's drills.sh after lib.sh's sfab_init drills, which opened
# audits/<lab>_drills_<UTC>/. The plan is gen/drills.json (sfab.render.drills: key-lifecycle,
# rejected-code and idle-timeout drills, and the gateway_layer block they share).
#
#   gwdrills_main               --drills "ID ..." --passes N: every pass runs every drill (a drill's
#                               max_passes caps how many passes run it), then gwdrill.py summarize
#                               writes DRILLS.md
#   gwdrill_keys PASS ID        one key from mint to revoke, under the gateway probe
#   gwdrill_code PASS ID        a route's consumer restriction without its rejected code, then back
#   gwdrill_idle PASS ID        the test backend silent past the stream idle timeout, then the
#                               corrected chain, then the rendered chain back
#
# Every drill checks the gateway layer whole first and after (every API gateway and router pod
# Ready, both Gateways Programmed, the test backend ready, in two consecutive polls 5 s apart),
# pushes each restore before its change (run last-in first-out from the EXIT trap whatever
# happens), archives the inference and test backend namespaces' Warning events, runs audit.sh
# --quick, then gwdrill.py analyze. Every stamp is the lab host's clock (date +%s.%N here).
#
# The gateway probe (common/drill/probe_gateway.py in the client): one chat completion a model every
# interval through the Gateway's model route with each model's first key, each request on its own;
# under the key drills none may fail. A key drill's new key travels like every key: from its Secret
# through pipes into the client's 0600 files, and into the per-pod probe's pod from its own mounted
# Secret (lib-servecap.sh). The idle-timeout drill stops the test backend's processes with SIGSTOP
# from their nodes' guests (its pods stay Running and keep accepting TCP, so the backend is silent,
# not gone) and continues them with SIGCONT; it changes Cilium only with helm and the rendered values
# (render/k8s.py cilium_values_doc), and puts those back.

GDP="$SFAB_COMMON/drill/gwdrill.py"
GD_PLAN="$RENDERDIR/gen/drills.json"
GD_DIR=/tmp/sfab-drill-probe
GD_NEW=/tmp/sfab-drill-newkey
GD_KNODE_DIR=/tmp/sfab-drill
GD_RESTORES=()
# shellcheck source=common/trace/lib-servecap.sh
. "$SFAB_COMMON/trace/lib-servecap.sh"

gd_get() { py "$GDP" get --plan "$GD_PLAN" "$1"; }
gd_now() { date +%s.%N; }
gd_tl() { printf '%s %s\n' "$(gd_now)" "$*" >>"$D/timeline.txt"; }
gd_tlx() { local dir="$1"; shift; printf '%s %s\n' "$(gd_now)" "$*" >>"$dir/timeline.txt"; }
gd_sleep_until() { local s; s="$(py -c 'import sys, time; print(max(0.0, float(sys.argv[1]) - time.time()))' "$1")"; sleep "$s"; }
gd_add() { py -c 'import sys; print(float(sys.argv[1]) + float(sys.argv[2]))' "$1" "$2"; }

gd_restore_add() { GD_RESTORES+=("$*"); }
gd_restore_run() {
  local i
  for ((i = ${#GD_RESTORES[@]} - 1; i >= 0; i--)); do
    eval "${GD_RESTORES[$i]}" || warn "drill: restore '${GD_RESTORES[$i]}' failed"
  done
  GD_RESTORES=()
}
gd_cleanup() {
  gd_restore_run
  gd_probes_stop quiet || true
  gd_newkey_stop || true
  key_clear "$(gd_get probes.gateway.client)" "$GD_NEW"
}

# --------------------------------------------------------------------------------------------
# the gateway layer whole

gd_poll() {
  local dir="$1" ns tbns
  rm -rf "$dir"
  mkdir -p "$dir"
  ns="$(gd_get gateway_layer.namespace)" tbns="$(k8s_get test_backend.namespace)"
  EVID_OFF=1 K -n "$ns" get pods -o json >"$dir/pods.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$tbns" get deployments -o json >"$dir/deployments.json" 2>/dev/null || true
  EVID_OFF=1 K -n "$(k8s_get gateway_namespace)" get gateways -o json >"$dir/gateways.json" 2>/dev/null || true
  py "$GDP" whole --plan "$GD_PLAN" --dir "$dir" >"$dir/whole.txt" 2>&1
}

gd_whole() {
  local label="$1" dir="$2" polls good=0 i
  polls="$(gd_get timing.whole_polls)"
  for i in $(seq 1 "$polls"); do
    if gd_poll "$dir"; then
      good=$((good + 1))
      [ "$good" -ge 2 ] && break
    else
      good=0
    fi
    sleep "${SFAB_DRILL_POLL_S:-5}"
  done
  if [ "$good" -ge 2 ]; then
    ok "$label: $(cat "$dir/whole.txt") (poll $i)"
    return 0
  fi
  bad "$label" "$(cat "$dir/whole.txt" 2>/dev/null || echo 'no poll read')"
  return 1
}

# --------------------------------------------------------------------------------------------
# the gateway probe (each model's first key), and a probe of one new key through the VIP

# each model as "MODEL URL EVERY": EVERY is on which of the probe's intervals it is sent (1, each)
gd_targets() { py -c 'import json, sys; [print(m["model"], m["url"], m.get("every", 1)) for m in json.load(open(sys.argv[1]))["probes"]["gateway"]["models"]]' "$GD_PLAN"; }

gd_probes_start() {
  local client m mn mu me targets=() pin=() iv to mt
  client="$(gd_get probes.gateway.client)"
  iv="$(gd_get probes.gateway.interval_s)" to="$(gd_get probes.gateway.timeout_s)" mt="$(gd_get probes.gateway.max_tokens)"
  : >"$D/keys.txt"
  while read -r mn mu me; do
    [ -n "$mn" ] || continue
    if key_to_client "$(gd_get probes.gateway.keys.namespace)" "$(gd_get probes.gateway.keys.secret)" "$mn" "$client" "$GD_DIR" >>"$D/keys.txt" 2>&1; then
      targets+=(--target "$mn" "$mu")
      [ "${me:-1}" = 1 ] || targets+=(--every "$mn" "$me")
    else
      bad "pass $PASS $DRILL_ID: the key for $mn handed to $client" "$(tail -n 1 "$D/keys.txt")"
    fi
  done < <(gd_targets)
  [ -z "$(gd_get probes.gateway.resolve 2>/dev/null || true)" ] || pin=(--resolve "$(gd_get probes.gateway.resolve)")
  dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$GD_DIR/probe_gateway.py" <"$SFAB_COMMON/drill/probe_gateway.py"
  X "$client" sh -c "rm -f $GD_DIR/stop $GD_DIR/records-*.jsonl; nohup python3 $GD_DIR/probe_gateway.py --dir $GD_DIR $(printf '%q ' "${targets[@]}") --interval $iv --timeout $to --max-tokens $mt --until-stop $(qargs "${pin[@]+"${pin[@]}"}") >$GD_DIR/probe.out 2>&1 </dev/null &" >"$D/logs/probe-start.txt" 2>&1 || true
  GD_PROBING=1
  gd_tl PROBES "gateway: $(gd_targets | cut -d' ' -f1 | paste -sd ' ' -)"
}

gd_probe_wait() {  # gd_probe_wait CLIENT DIR TIMEOUT: until the probe in DIR has ended
  local i
  for i in $(seq 1 "$(py -c 'import math, sys; print(int(math.ceil(float(sys.argv[1]))) + 15)' "$3")"); do
    dk exec "$(ctr "$1")" sh -c "pgrep -f '[p]robe_gateway.py --dir $2' >/dev/null" 2>/dev/null || break
    sleep 1
  done
}

gd_probes_stop() {
  local client m
  [ "${GD_PROBING:-0}" = 1 ] || return 0
  client="$(gd_get probes.gateway.client)"
  dk exec "$(ctr "$client")" touch "$GD_DIR/stop" >/dev/null 2>&1 || true
  gd_probe_wait "$client" "$GD_DIR" "$(gd_get probes.gateway.timeout_s)"
  for m in $(gd_targets | cut -d' ' -f1); do
    dk exec "$(ctr "$client")" cat "$GD_DIR/records-$m.jsonl" >"$D/records-$m.jsonl" 2>/dev/null || true
  done
  dk exec "$(ctr "$client")" cat "$GD_DIR/probe.out" >"$D/logs/probe.out" 2>/dev/null || true
  key_clear "$client" "$GD_DIR"
  GD_PROBING=0
  [ "${1:-}" = quiet ] || gd_tl STOP probes
}

# gd_newkey_start MODEL FIELD URL: the new key into the client's own directory, and a probe of it
# through the VIP, one request every interval (the records keep each status)
gd_newkey_start() {
  local model="$1" field="$2" url="$3" client pin=()
  client="$(gd_get probes.gateway.client)"
  if ! key_to_client "$(gd_get gateway_layer.namespace)" "$(gd_get gateway_layer.keys.secret)" "$model" "$client" "$GD_NEW" "$field" >"$D/newkey.txt" 2>&1; then
    bad "pass $PASS $DRILL_ID: the new key $field handed to $client" "$(tail -n 1 "$D/newkey.txt")"
    return 1
  fi
  [ -z "$(gd_get probes.gateway.resolve 2>/dev/null || true)" ] || pin=(--resolve "$(gd_get probes.gateway.resolve)")
  dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$GD_NEW/probe_gateway.py" <"$SFAB_COMMON/drill/probe_gateway.py"
  X "$client" sh -c "rm -f $GD_NEW/stop $GD_NEW/records-*.jsonl; nohup python3 $GD_NEW/probe_gateway.py --dir $GD_NEW --target $model $(printf '%q' "$url") --interval $(gd_get probes.gateway.interval_s) --timeout 30 --max-tokens 1 --until-stop $(qargs "${pin[@]+"${pin[@]}"}") >$GD_NEW/probe.out 2>&1 </dev/null &" >"$D/logs/newkey-start.txt" 2>&1 || true
  GD_NEWKEY="$model"
}

gd_newkey_stop() {
  local client
  [ -n "${GD_NEWKEY:-}" ] || return 0
  client="$(gd_get probes.gateway.client)"
  dk exec "$(ctr "$client")" touch "$GD_NEW/stop" >/dev/null 2>&1 || true
  gd_probe_wait "$client" "$GD_NEW" 30
  dk exec "$(ctr "$client")" cat "$GD_NEW/records-$GD_NEWKEY.jsonl" >"$D/records-new.jsonl" 2>/dev/null || true
  GD_NEWKEY=""
}

# gd_vip NAME URL HEADER_NAME: one chat completion from the client through the VIP with the key in
# the client's file hdr-HEADER_NAME (in GD_NEW or GD_DIR), its status and body saved as D/NAME-*
gd_vip() {
  local name="$1" url="$2" hname="$3" dir="${4:-$GD_NEW}" client model pin=()
  client="$(gd_get probes.gateway.client)" model="${5:-chat}"
  [ -z "$(gd_get probes.gateway.resolve 2>/dev/null || true)" ] || pin=(--resolve "$(gd_get probes.gateway.resolve)")
  X "$client" curl -sS --max-time 60 "${pin[@]+"${pin[@]}"}" -o "$dir/vip-body.txt" -w '%{http_code}\n' -H "@$dir/hdr-$hname" \
    -H 'Content-Type: application/json' --data "{\"model\": \"$model\", \"max_tokens\": 1, \"messages\": [{\"role\": \"user\", \"content\": \"Say yes.\"}]}" \
    "$url" >"$D/$name-result.txt" 2>&1 || true
  dk exec "$(ctr "$client")" cat "$dir/vip-body.txt" >"$D/$name-body.txt" 2>/dev/null || true
}

gd_secret_list() {
  EVID_OFF=1 K -n "$(gd_get gateway_layer.namespace)" get secret "$(gd_get gateway_layer.keys.secret)" -o json 2>/dev/null |
    py "$SFAB_COMMON/trace/servekeys.py" list >"$1" 2>/dev/null || true
}

# gd_after [NS...]: the drill's Warning events archived (the inference and test backend namespaces,
# and any NS the drill changed: the idle drill's Cilium rolls leave its pods' readiness failures in
# kube-system, which the next full audit would read), the gateway layer whole, the quick audit, the
# analysis
gd_after() {
  local rc=0
  events_archive "$D/events" "$(gd_get gateway_layer.namespace)" "$(k8s_get test_backend.namespace)" "$@"
  gd_whole "pass $PASS $DRILL_ID: the gateway layer whole again after the drill" "$D/whole-after" || rc=2
  gd_quick_audit
  py "$GDP" analyze --plan "$GD_PLAN" --dir "$D" --drill "$DRILL_ID" --pass "$PASS" >"$D/analyze.out" 2>&1 || true
  cat "$D/analyze.out"
  return "$rc"
}

gd_quick_audit() {
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

gd_begin() {
  PASS="$1" DRILL_ID="$2"
  D="$RS/pass$PASS/$DRILL_ID"
  mkdir -p "$D/logs"
  : >"$D/timeline.txt"
  sec "pass $PASS, drill $DRILL_ID: $(gd_get "list.$DRILL_ID.title")"
  echo "drill: pass $PASS $DRILL_ID ($(gd_get "list.$DRILL_ID.title"))"
  gd_whole "pass $PASS $DRILL_ID: the gateway layer whole before the drill" "$D/whole-before"
}

# --------------------------------------------------------------------------------------------
# key-lifecycle

gd_revoke_now() { keyjob_run "$(gd_get gateway_layer.probe.name)-revoke" "$D/revoke-restore.log" revoke "$1" "$2" >/dev/null 2>&1 || true; }

gwdrill_keys() {
  local model cross kid field max probe tr
  gd_begin "$1" "$2" || { gd_tl ABORTED "the gateway layer was not whole"; return 1; }
  model="$(gd_get "list.$DRILL_ID.model")" cross="$(gd_get "list.$DRILL_ID.cross")"
  kid="$(py "$GDP" kid --plan "$GD_PLAN" --drill "$DRILL_ID" --pass "$PASS")"
  # the key belongs to the application caller that stands for the model (gen/drills.json key_caller)
  field="$(gd_get "list.$DRILL_ID.key_caller" 2>/dev/null || true)"
  field="${field:-$model}.$kid"
  max="$(gd_get timing.accept_max_s)" probe="$(gd_get gateway_layer.probe.name)"
  printf '%s\n' "$field" >"$D/field.txt"
  gd_secret_list "$D/secret-before.txt"
  trap gd_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  gd_probes_start
  gd_sleep_until "$(gd_add "$(gd_now)" "$(gd_get timing.lead_s)")"
  gd_restore_add "gd_revoke_now $model $kid"
  gd_tl MINT "$field"
  if keyjob_run "$probe-mint" "$D/mint.log" mint "$model" "$kid"; then
    gd_tl MINTED "$(grep -m1 'minted ' "$D/mint.log" | grep -oE 'sha256:[0-9a-f]{12}' || true)"
  else
    gd_tl MINTED error
    bad "pass $PASS $DRILL_ID: the key Job minted $field" "$(tail -n 1 "$D/mint.log")"
  fi
  K -n "$(gd_get gateway_layer.namespace)" get secret "$(gd_get gateway_layer.keys.secret)" -o jsonpath='{.metadata.managedFields[*].time}' \
    >"$D/secret-times.txt" 2>&1 || true
  gd_newkey_start "$model" "$field" "$(gd_get "list.$DRILL_ID.url")" || true
  KEYPROBE_REPEAT=1 keyprobe_run "$probe-accept" "$D/accept.log" "$max" "accept-$model $model $field 200" || true
  gd_tl ACCEPTED "the per-pod probe ended"
  keyprobe_run "$probe-cross" "$D/cross.log" 30 "cross-$cross $cross $field 401" || true
  gd_vip cross-vip "$(gd_get "list.$DRILL_ID.cross_url")" "$model" "$GD_NEW" "$cross"
  # the refusal probe holds the key before it is revoked: it reads its key file once, as it starts
  KEYPROBE_REPEAT=1 keyprobe_start "$probe-refuse" "$max" "refuse-$model $model $field 401" || true
  keyprobe_running "$probe-refuse" 120 || warn "drill: the refusal probe printed no round before the revoke"
  GD_RESTORES=()
  gd_tl REVOKE "$field"
  tr="$(gd_now)"
  if keyjob_run "$probe-revoke" "$D/revoke.log" revoke "$model" "$kid"; then
    gd_tl REVOKED "$(grep -m1 'revoked ' "$D/revoke.log" | grep -oE 'sha256:[0-9a-f]{12}' || true)"
  else
    gd_tl REVOKED error
    bad "pass $PASS $DRILL_ID: the key Job revoked $field" "$(tail -n 1 "$D/revoke.log")"
  fi
  keyprobe_finish "$probe-refuse" "$D/refuse.log" "$KEYPROBE_WAIT" || true
  sleep "$(gd_get timing.tail_s)"
  gd_newkey_stop
  gd_probes_stop
  trap - EXIT INT TERM
  key_clear "$(gd_get probes.gateway.client)" "$GD_NEW"
  gd_secret_list "$D/secret-after.txt"
  : "$tr"
  gd_after
}

# --------------------------------------------------------------------------------------------
# rejected-code

gd_cm() {  # gd_cm rendered|default: the routes ConfigMap as the plan holds it, applied
  local f
  f="$(tmpf)"
  gd_get "list.$DRILL_ID.configmap_$1" >"$f"
  kapply "$f" >"$D/apply-$1.txt" 2>&1
  local rc=$?
  rm -f "$f"
  return "$rc"
}

gwdrill_code() {
  local model kmod field max probe ns cm
  gd_begin "$1" "$2" || { gd_tl ABORTED "the gateway layer was not whole"; return 1; }
  model="$(gd_get "list.$DRILL_ID.model")" kmod="$(gd_get "list.$DRILL_ID.key_model")"
  max="$(gd_get timing.accept_max_s)" probe="$(gd_get gateway_layer.probe.name)" ns="$(gd_get gateway_layer.namespace)"
  field="$(EVID_OFF=1 K -n "$ns" get secret "$(gd_get gateway_layer.keys.secret)" -o json 2>/dev/null |
    py "$SFAB_COMMON/trace/servekeys.py" which --model "$kmod" 2>/dev/null | cut -d' ' -f1 || true)"
  trap gd_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  gd_probes_start
  key_to_client "$ns" "$(gd_get gateway_layer.keys.secret)" "$kmod" "$(gd_get probes.gateway.client)" "$GD_NEW" >"$D/crosskey.txt" 2>&1 || true
  key_to_client "$ns" "$(gd_get gateway_layer.keys.secret)" "$model" "$(gd_get probes.gateway.client)" "$GD_NEW" >>"$D/crosskey.txt" 2>&1 || true
  gd_sleep_until "$(gd_add "$(gd_now)" "$(gd_get timing.lead_s)")"
  gd_restore_add "gd_cm rendered"
  gd_tl APPLY "$model's route without rejected_code"
  if gd_cm default; then gd_tl APPLIED ok; else gd_tl APPLIED error; bad "pass $PASS $DRILL_ID: the routes without rejected_code applied" "$(tail -n 1 "$D/apply-default.txt")"; fi
  KEYPROBE_REPEAT=1 keyprobe_run "$probe-default" "$D/default.log" "$max" "default-$model $model $field $(gd_get "list.$DRILL_ID.expect.default")" || true
  gd_vip default-vip "$(gd_get "list.$DRILL_ID.url")" "$kmod" "$GD_NEW" "$model"
  GD_RESTORES=()
  gd_tl RESTORE "the rendered routes"
  if gd_cm rendered; then gd_tl RESTORED ok; else gd_tl RESTORED error; bad "pass $PASS $DRILL_ID: the rendered routes applied" "$(tail -n 1 "$D/apply-rendered.txt")"; fi
  KEYPROBE_REPEAT=1 keyprobe_run "$probe-rendered" "$D/rendered.log" "$max" "rendered-$model $model $field $(gd_get "list.$DRILL_ID.expect.rendered")" || true
  gd_vip rendered-vip "$(gd_get "list.$DRILL_ID.url")" "$kmod" "$GD_NEW" "$model"
  gd_vip own-vip "$(gd_get "list.$DRILL_ID.url")" "$model" "$GD_NEW" "$model"
  sleep "$(gd_get timing.tail_s)"
  gd_probes_stop
  trap - EXIT INT TERM
  key_clear "$(gd_get probes.gateway.client)" "$GD_NEW"
  cm="$(gd_get "list.$DRILL_ID.configmap.name")"
  EVID_OFF=1 K -n "$ns" get configmap "$cm" -o json >"$D/configmap-after.json" 2>/dev/null || true
  py - "$D/configmap-after.json" "$GD_PLAN" "$DRILL_ID" >"$D/configmap-after.txt" <<'PY'
import json, sys
try:
    live = (json.load(open(sys.argv[1])).get("data") or {})
except (OSError, ValueError):
    print("unreadable"); sys.exit(0)
d = next(x for x in json.load(open(sys.argv[2]))["list"] if x["id"] == sys.argv[3])
print("same" if live == d["configmap_rendered"]["data"] else "differs from the render")
PY
  gd_after
}

# --------------------------------------------------------------------------------------------
# idle-timeout

# gd_echo_pids: "node pid pod" for every test backend container, its process as its node sees it
gd_echo_pids() {
  local ns sel c
  ns="$(gd_get "list.$DRILL_ID.test_backend.namespace")" sel="$(gd_get "list.$DRILL_ID.test_backend.selector")"
  c="$(gd_get "list.$DRILL_ID.test_backend.container")"
  EVID_OFF=1 K -n "$ns" get pods -l "$sel" -o json 2>/dev/null | py -c '
import json, sys
for p in json.load(sys.stdin).get("items") or []:
    print(p["spec"].get("nodeName") or "-", p["metadata"]["name"])' | while read -r node pod; do
    [ "$node" != - ] || continue
    printf '%s %s %s\n' "$node" "$(EVID_OFF=1 H "$node" "id=\$(crictl ps --label io.kubernetes.pod.name=$pod --label io.kubernetes.container.name=$c -q | head -n 1); [ -n \"\$id\" ] && crictl inspect \"\$id\" | python3 -c 'import json, sys; print(json.load(sys.stdin)[\"info\"][\"pid\"])'" 2>/dev/null | tail -n 1 | tr -cd '0-9')" "$pod"
  done
}

gd_signal() {  # gd_signal STOP|CONT FILE: the signal to every process FILE lists, logged beside FILE
  local node pid pod log
  log="$(dirname "$2")/signals.txt"
  while read -r node pid pod; do
    [ -n "$pid" ] || continue
    H "$node" "kill -$1 $pid" >>"$log" 2>&1 || true
    printf '%s %s %s %s\n' "$(gd_now)" "$1" "$node" "$pod" >>"$log"
  done <"$2"
}

gd_idle_read() {  # the listener's stream idle timeout and the route as the cluster runs them, into DIR
  local dir="$1" cec
  cec="$(gd_get "list.$DRILL_ID.cec")"
  mkdir -p "$dir"
  EVID_OFF=1 K -n "${cec%%/*}" get ciliumenvoyconfig "${cec#*/}" -o json >"$dir/cec.json" 2>/dev/null || true
  py "$GDP" idle --cec "$dir/cec.json" --name "${cec#*/}" >"$dir/idle.txt" 2>&1 || true
  EVID_OFF=1 K -n kube-system get configmap cilium-config -o json 2>/dev/null |
    py -c 'import json, sys; d = (json.load(sys.stdin).get("data") or {}); [print(k, d.get(k, "unset")) for k in sys.argv[1:]]' \
    http-stream-idle-timeout proxy-stream-idle-timeout-seconds >"$dir/cilium-config.txt" 2>&1 || true
  EVID_OFF=1 K -n "$(gd_get "list.$DRILL_ID.test_backend.namespace")" get httproute "$(gd_get "list.$DRILL_ID.test_backend.route")" -o json \
    >"$dir/route.json" 2>/dev/null || true
}

# gd_silent HALF: one request through the Gateway while the test backend is stopped for silent_s.
# The client stamps the request's start with python3: its BusyBox date prints no fraction for %N.
gd_silent() {
  local h="$D/$1" client url silent t0 lease holder pid node pod ppid i pin=()
  mkdir -p "$h/captures"
  : >"$h/timeline.txt"
  client="$(gd_get "list.$DRILL_ID.client")" url="$(gd_get "list.$DRILL_ID.url")" silent="$(gd_get "list.$DRILL_ID.silent_s")"
  [ -z "$(gd_get "list.$DRILL_ID.resolve" 2>/dev/null || true)" ] || pin=(--resolve "$(gd_get "list.$DRILL_ID.resolve")")
  gd_idle_read "$h"
  gd_echo_pids >"$h/pids.txt"
  lease="$(gd_get "list.$DRILL_ID.lease")"
  holder="$(EVID_OFF=1 K -n "${lease%%/*}" get lease "${lease#*/}" -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
  printf '%s\n' "$holder" >"$h/lease-holder.txt"
  [ -z "$holder" ] || RAILCAP_SNAPLEN=96 railcap_guest_start "$holder" bond0 "idle-$1-vip" "tcp port 443 and host $(gd_get "list.$DRILL_ID.vip")" \
    "$((silent + 300))" "$h/captures/vip-$holder.txt" "$h/captures/vip-$holder.pcap"
  while read -r node pid pod; do
    ppid="$(pod_pid "$node" "$(gd_get "list.$DRILL_ID.test_backend.namespace")" "$pod")"
    [ -n "$ppid" ] || continue
    RAILCAP_SNAPLEN=200 railcap_pod_start "$node" "$ppid" eth0 "idle-$1-$pod" "tcp port $(gd_get "list.$DRILL_ID.test_backend.port")" \
      "$((silent + 300))" "$h/captures/echo-$pod.txt" "$h/captures/echo-$pod.pcap"
  done <"$h/pids.txt"
  railcap_wait
  gd_restore_add "gd_signal CONT $h/pids.txt"
  gd_tlx "$h" STOP "the test backend's processes"
  gd_signal STOP "$h/pids.txt"
  gd_tlx "$h" STOPPED "$(wc -l <"$h/pids.txt" | tr -d ' ') processes"
  X "$client" sh -c "rm -f $GD_DIR/idle-*; mkdir -p $GD_DIR; python3 -c 'import time; print(time.time())' >$GD_DIR/idle-sent; nohup curl -sS --max-time $((silent + 240)) $(qargs "${pin[@]+"${pin[@]}"}") -o $GD_DIR/idle-body -D $GD_DIR/idle-headers -w '%{http_code} %{time_starttransfer} %{time_total}\\n' '$url-$PASS-$1' >$GD_DIR/idle-result 2>&1 </dev/null &" >/dev/null 2>&1 || true
  t0="$(dk exec "$(ctr "$client")" cat "$GD_DIR/idle-sent" 2>/dev/null | head -n 1)"
  [ -n "$t0" ] || t0="$(gd_now)"
  printf '%s SENT %s\n' "$t0" "$url-$PASS-$1" >>"$h/timeline.txt"
  gd_sleep_until "$(gd_add "$t0" "$silent")"
  gd_tlx "$h" CONT "the test backend's processes"
  gd_signal CONT "$h/pids.txt"
  gd_tlx "$h" CONTINUED ok
  GD_RESTORES=("${GD_RESTORES[@]:0:${#GD_RESTORES[@]}-1}")
  for i in $(seq 1 300); do
    dk exec "$(ctr "$client")" sh -c "pgrep -f '[c]url -sS --max-time $((silent + 240))' >/dev/null" 2>/dev/null || break
    sleep 1
  done
  dk exec "$(ctr "$client")" cat "$GD_DIR/idle-result" >"$h/result.txt" 2>/dev/null || true
  dk exec "$(ctr "$client")" cat "$GD_DIR/idle-headers" 2>/dev/null | tr -d '\r' >"$h/headers.txt" || true
  dk exec "$(ctr "$client")" cat "$GD_DIR/idle-body" >"$h/body.txt" 2>/dev/null || true
  gd_tlx "$h" ENDED "$(tail -n 1 "$h/result.txt" 2>/dev/null)"
  RAILCAP_DECODE="-nn -tt -e -v" railcap_stop
  : "$i"
}

# gd_leases TAG: the L2 announcement leases as the cluster holds them (holder, transitions, times)
gd_leases() { EVID_OFF=1 K -n kube-system get leases -o json >"$D/leases-$1.json" 2>/dev/null || true; }

# gd_helm rendered|corrected: Cilium's values as the plan holds them, applied with helm on the init
# node (the harness's kubectl and helm), then the operator, the agents and Envoy rolled (each reads its configuration at start);
# the upgrade and each rollout stamped on the timeline, and the leases saved before and after
gd_helm() {
  local which="$1" f rel ns ch ver flags="" r
  rel="$(gd_get "list.$DRILL_ID.cilium.release")" ns="$(gd_get "list.$DRILL_ID.cilium.namespace")"
  ch="$(gd_get "list.$DRILL_ID.cilium.chart")" ver="$(gd_get "list.$DRILL_ID.cilium.version")"
  [ "$(gd_get "list.$DRILL_ID.cilium.plain_http")" != 1 ] || flags="--plain-http"
  [ "$(gd_get "list.$DRILL_ID.cilium.plain_http")" = 1 ] || flags="--ca-file /shared/ca/root.crt"
  f="$(tmpf)"
  gd_get "list.$DRILL_ID.cilium.values_$which" >"$f"
  EVID_OFF=1 KSHI "umask 077; mkdir -p $GD_KNODE_DIR; cat >$GD_KNODE_DIR/cilium-$which.json" <"$f" >/dev/null
  rm -f "$f"
  gd_leases "before-$which"
  gd_tl HELM "$which"
  KSH "helm -n $ns upgrade $rel $(printf '%q' "$ch") --version $(printf '%q' "$ver") -f $GD_KNODE_DIR/cilium-$which.json --wait --timeout 15m $flags" \
    >"$D/helm-$which.txt" 2>&1 || { gd_tl HELMED error; bad "pass $PASS $DRILL_ID: helm upgrade $rel with the $which values" "$(tail -n 1 "$D/helm-$which.txt")"; return 1; }
  gd_tl HELMED "$which"
  for r in "$(gd_get "list.$DRILL_ID.cilium.operator")" "$(gd_get "list.$DRILL_ID.cilium.agents")" "$(gd_get "list.$DRILL_ID.cilium.envoy")"; do
    gd_tl ROLL "$which $r"
    K -n "$ns" rollout restart "$r" >>"$D/rollout-$which.txt" 2>&1 || true
    K -n "$ns" rollout status "$r" --timeout=900s >>"$D/rollout-$which.txt" 2>&1 ||
      { gd_tl ROLLED "$which $r error"; bad "pass $PASS $DRILL_ID: $r rolled out with the $which values" "$(tail -n 1 "$D/rollout-$which.txt")"; return 1; }
    gd_tl ROLLED "$which $r"
  done
  gd_leases "after-$which"
  ok "pass $PASS $DRILL_ID: Cilium upgraded with the $which values from the in-lab registry, its operator, agents and Envoy rolled out"
}

# gd_route rendered|corrected: the test backend's route on the drill's Gateway as the plan holds it
gd_route() {
  local f rc=0
  f="$(tmpf)"
  gd_get "list.$DRILL_ID.test_backend.route_$1" >"$f"
  kapply "$f" >"$D/route-$1.txt" 2>&1 || rc=1
  rm -f "$f"
  return "$rc"
}

# gd_settle WANT: until the listener's stream idle timeout reads WANT, both Gateways are Programmed
# and the client's request through the route answers, settle_max_s at most
gd_settle() {
  local want="$1" t0 dir="$D/settle-$2" client url pin=() code
  client="$(gd_get "list.$DRILL_ID.client")" url="$(gd_get "list.$DRILL_ID.url")"
  [ -z "$(gd_get "list.$DRILL_ID.resolve" 2>/dev/null || true)" ] || pin=(--resolve "$(gd_get "list.$DRILL_ID.resolve")")
  t0="$(date +%s)"
  while [ $(($(date +%s) - t0)) -lt "$(gd_get timing.settle_max_s)" ]; do
    gd_idle_read "$dir"
    code="$(X "$client" curl -sS -o /dev/null --max-time 10 "${pin[@]+"${pin[@]}"}" -w '%{http_code}' "$url-settle" 2>/dev/null || true)"
    if { [ "$want" = any ] || [ "$(cat "$dir/idle.txt")" = "$want" ]; } && [ "$code" = 200 ] && gd_poll "$dir/poll"; then
      ok "pass $PASS $DRILL_ID: the listener's stream idle timeout $(cat "$dir/idle.txt"), both Gateways Programmed, the route answering ($2, $(($(date +%s) - t0)) s)"
      return 0
    fi
    sleep "${SFAB_DRILL_POLL_S:-5}"
  done
  bad "pass $PASS $DRILL_ID: the listener at $want and the route answering ($2)" "idle $(cat "$dir/idle.txt" 2>/dev/null), HTTP ${code:-none}"
  return 1
}

gd_idle_restore() {
  gd_helm rendered || true
  gd_route rendered || true
  gd_settle "$(cat "$D/rendered/idle.txt" 2>/dev/null || echo any)" restored || true
}

gwdrill_idle() {
  local rc=0 idle_before
  gd_begin "$1" "$2" || { gd_tl ABORTED "the gateway layer was not whole"; return 1; }
  trap gd_cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  gd_tl HALF rendered
  gd_silent rendered
  idle_before="$(cat "$D/rendered/idle.txt" 2>/dev/null || echo absent)"
  gd_restore_add gd_idle_restore
  gd_tl CORRECT "Cilium's stream idle timeouts $(gd_get "list.$DRILL_ID.corrected.stream_idle_s") s, the route's timeouts"
  if gd_helm corrected && gd_route corrected && gd_settle "$(gd_get "list.$DRILL_ID.corrected.stream_idle_s")s" corrected; then
    gd_tl CORRECTED ok
    gd_tl HALF corrected
    gd_silent corrected
  else
    gd_tl CORRECTED error
    rc=2
  fi
  GD_RESTORES=()
  gd_tl RESTORE "the rendered chain"
  gd_idle_restore
  gd_tl RESTORED
  gd_idle_read "$D/after"
  EVID_OFF=1 KSH "helm -n $(gd_get "list.$DRILL_ID.cilium.namespace") get values $(gd_get "list.$DRILL_ID.cilium.release") -o json" >"$D/helm-values-after.json" 2>/dev/null || true
  py - "$D" "$idle_before" "$GD_PLAN" "$DRILL_ID" >"$D/restored.txt" <<'PY'
import json, sys
from pathlib import Path
d, before = Path(sys.argv[1]), sys.argv[2]
plan = next(x for x in json.load(open(sys.argv[3]))["list"] if x["id"] == sys.argv[4])
idle = (d / "after" / "idle.txt").read_text().strip() if (d / "after" / "idle.txt").is_file() else "unread"
try:
    rules = json.load(open(d / "after" / "route.json"))["spec"]["rules"]
    tos = [r.get("timeouts") for r in rules if r.get("timeouts")]
except (OSError, ValueError, KeyError):
    tos = ["unread"]
try:
    vals = json.load(open(d / "helm-values-after.json"))
except (OSError, ValueError):
    vals = None
same = vals == plan["cilium"]["values_rendered"]
print(f"idle {idle} (before the drill {before})" + (", the same" if idle == before else ", NOT the same")
      + f"; route timeouts {'none' if not tos else tos}; helm values {'rendered' if same else 'not the rendered ones'}")
PY
  trap - EXIT INT TERM
  gd_after "$(gd_get "list.$DRILL_ID.cilium.namespace")" || rc=2
  return "$rc"
}

# --------------------------------------------------------------------------------------------
# the run

gwdrills_main() {
  local want="" passes=3 i d p ids=() stop=0 kind maxp
  for ((i = 0; i < ${#SFAB_ARGS[@]}; i++)); do
    case "${SFAB_ARGS[$i]}" in
      --drills) want="${SFAB_ARGS[$((i + 1))]:-}" ;;
      --passes) passes="${SFAB_ARGS[$((i + 1))]:-3}" ;;
    esac
  done
  [ -f "$GD_PLAN" ] || die "drills: no $GD_PLAN (chapter.yaml has no drills block, or make render)"
  [[ "$passes" =~ ^[1-9][0-9]*$ ]] || die "drills: --passes wants a positive number, got $passes"
  mapfile -t ids < <(py -c 'import json, sys; [print(d["id"]) for d in json.load(open(sys.argv[1]))["list"] if d.get("kind") in ("key-lifecycle", "rejected-code", "idle-timeout")]' "$GD_PLAN")
  [ ${#ids[@]} -gt 0 ] || die "drills: $GD_PLAN holds no gateway drill"
  if [ -n "$want" ]; then
    for d in $want; do
      case " ${ids[*]} " in *" $d "*) ;; *) die "drills: no drill $d (have ${ids[*]})" ;; esac
    done
    read -r -a ids <<<"$want"
  fi
  exec 8>"$STATEDIR/lock"
  flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"
  cp "$GD_PLAN" "$RS/drills.json"
  {
    printf 'drills: %s\npasses: %s\n' "${ids[*]}" "$passes"
    printf 'host tick: %s\n' "$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null || echo unreadable)"
  } >"$RS/RUNPLAN.txt"
  for p in $(seq 1 "$passes"); do
    for d in "${ids[@]}"; do
      local rc=0
      kind="$(gd_get "list.$d.kind")" maxp="$(gd_get "list.$d.max_passes" 2>/dev/null || true)"
      if [ -n "$maxp" ] && [ "$maxp" != None ] && [ "$p" -gt "$maxp" ]; then
        echo "drill: pass $p $d skipped (it runs in the first $maxp pass(es))"
        continue
      fi
      case "$kind" in
        key-lifecycle) gwdrill_keys "$p" "$d" || rc=$? ;;
        rejected-code) gwdrill_code "$p" "$d" || rc=$? ;;
        idle-timeout) gwdrill_idle "$p" "$d" || rc=$? ;;
      esac
      if [ "$rc" -eq 2 ]; then
        warn "drills: pass $p $d left the gateway layer not whole; the remaining drills are not run"
        stop=1
        break
      fi
    done
    [ "$stop" = 0 ] || break
  done
  py "$GDP" summarize --set "$RS" ${SFAB_TICK_STAMP:+--stamp "$SFAB_TICK_STAMP"} >/dev/null 2>&1 || warn "drills: gwdrill.py summarize failed"
  summary
}
