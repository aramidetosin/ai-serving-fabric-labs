# shellcheck shell=bash
# common/break/lib-keybreak.sh: the API gateway's key break actions and checks (chapter 7), sourced
# by breakheal.sh after lib.sh's sfab_init. Each takes its action as JSON (gen/breaks.json):
#
#   key_hold_action JSON TAG       the API gateway pod at the action's place among them by name held:
#                                  a hold file in its sidecar's shared directory, while which its
#                                  sidecar (sfab-keys compose) keeps the apisix.yaml it has; the pod
#                                  is recorded as "held <pod>" in the break's mark
#   key_mint_action JSON TAG       one key minted into the model keys' Secret by a Job of the key tool
#   key_revoke_action JSON TAG     that key revoked the same way (a cleanup: the Secret holds the
#                                  lab's first key a model again)
#   key_probe_action JSON PASSES   the per-pod key probe (a pod of the key tool in the cluster): the
#                                  key on the route at every API gateway pod by its address, in
#                                  rounds until every pod answers the status wanted or wait_s
#                                  passes; its rows saved for key_pods
#   key_show_action JSON TAG       the key Secret's fields and fingerprints, the API gateway's pods,
#                                  and each pod's sidecar log, which names each key it composed by
#                                  its fingerprint and says when it is held
#   gateway_restart_action JSON TAG
#                                  the held pod deleted, so its Deployment makes a new one, whose
#                                  sidecar composes from the Secret as it starts; then the rollout
#   key_check JSON                 key_pods: from the probe's rows, which pods accepted the key; with
#                                  refusing: held only the held pod refuses it, with none no pod does
#
# No key is printed: the per-pod probe reads its key from its own mounted Secret, and every line
# names a key by its field and fingerprint.

kb_ns() { jf "$1" namespace; }

kb_pods() {  # the Running API gateway pods, by name
  EVID_OFF=1 K -n "$(kb_ns "$1")" get pods -l "$(jf "$1" api_gateway.selector)" -o json 2>/dev/null | py -c '
import json, sys
for p in sorted(json.load(sys.stdin).get("items") or [], key=lambda x: x["metadata"]["name"]):
    if (p.get("status") or {}).get("phase") == "Running" and not (p.get("metadata") or {}).get("deletionTimestamp"):
        print(p["metadata"]["name"])'
}

kb_held() {  # the pod a key_hold of this break held, from the run's taken lines or the break's mark
  { cat "$RS/taken.txt" 2>/dev/null; cat "$MARKS/$BID" 2>/dev/null; } | sed -n 's/^held[[:space:]]\{1,\}//p' | head -n 1
}

key_hold_action() {
  local js="$1" tag="$2" i pods pod out
  i="$(jf "$js" index)"
  mapfile -t pods < <(kb_pods "$js")
  pod="${pods[$i]:-}"
  [ -n "$pod" ] || { bad "the API gateway pod at place $i held" "only ${#pods[@]} Running API gateway pod(s)"; return 1; }
  out="$RS/record/$tag-hold-$pod.txt"
  if K -n "$(kb_ns "$js")" exec "$pod" -c "$(jf "$js" api_gateway.sidecar)" -- touch "$(jf "$js" api_gateway.hold)" >"$out" 2>&1; then
    ok "$pod, the API gateway pod at place $i of ${#pods[@]} by name, held: its sidecar keeps the apisix.yaml it has (hold file $(jf "$js" api_gateway.hold))"
    printf 'held %s\n' "$pod" >>"$RS/taken.txt"
  else
    bad "$pod held" "$(tail -n 1 "$out")"
    return 1
  fi
}

key_job_action() {  # key_job_action JSON TAG mint|revoke
  local js="$1" tag="$2" op="$3" out did
  out="$RS/record/$tag-$op-$(jf "$js" field).log"
  did=minted
  [ "$op" = mint ] || did=revoked
  if keyjob_run "$(k8s_get inference.probe.name)-$tag-$op" "$out" "$op" "$(jf "$js" model)" "$(jf "$js" id)"; then
    ok "the key Job $did $(jf "$js" field) in Secret $(kb_ns "$js")/$(jf "$js" keys.secret) ($(grep -oE 'sha256:[0-9a-f]{12}' "$out" | head -n 1 || echo 'no fingerprint'))"
    [ "$op" != mint ] || printf 'minted %s\n' "$(jf "$js" field)" >>"$RS/taken.txt"
  else
    bad "the key Job $did $(jf "$js" field)" "$(tail -n 1 "$out")"
    return 1
  fi
}

key_mint_action() { key_job_action "$1" "$2" mint; }
key_revoke_action() { key_job_action "$1" "$2" revoke; }

key_probe_action() {
  local js="$1" pid field ns
  pid="$(jf "$js" id)" field="$(jf "$js" field)" ns="$(kb_ns "$js")"
  if [ -z "$field" ]; then
    field="$(EVID_OFF=1 K -n "$ns" get secret "$(jf "$js" keys.secret)" -o json 2>/dev/null |
      py "$SFAB_COMMON/trace/servekeys.py" which --model "$(jf "$js" model)" 2>/dev/null | cut -d' ' -f1 || true)"
  fi
  KEYPROBE_REPEAT=1 keyprobe_run "$(k8s_get inference.probe.name)-break-$pid" "$RS/probes/$pid-$MODE.log" "$(jf "$js" wait_s)" \
    "$pid $(jf "$js" route) $field $(jf "$js" expect)" || true
  py "$SFAB_COMMON/trace/keyprobe.py" summary --log "$RS/probes/$pid-$MODE.log" --label "$pid" --expect "$(jf "$js" expect)" \
    >"$RS/probes/$pid-$MODE.pods" 2>&1 || true
  printf '%s\n' "$(jf "$js" expect)" >"$RS/probes/$pid-$MODE.expect"
  ok "$pid, $MODE: the per-pod probe of $field on $(jf "$js" route)'s route: $(awk -F'\t' '{printf "%s%s %s", (NR > 1 ? "; " : ""), $1, $5}' "$RS/probes/$pid-$MODE.pods") (recorded)"
}

key_show_action() {
  local js="$1" tag="$2" ns p
  ns="$(kb_ns "$js")"
  EVID_OFF=1 K -n "$ns" get secret "$(jf "$js" keys.secret)" -o json 2>/dev/null |
    py "$SFAB_COMMON/trace/servekeys.py" list >"$RS/record/$tag-secret-fields.txt" 2>&1 || true
  K -n "$ns" get pods -l "$(jf "$js" api_gateway.selector)" -o wide >"$RS/record/$tag-api-gateway-pods.txt" 2>&1 || true
  for p in $(kb_pods "$js"); do
    K -n "$ns" logs "$p" -c "$(jf "$js" api_gateway.sidecar)" --tail=20 >"$RS/record/$tag-sidecar-$p.txt" 2>&1 || true
  done
}

gateway_restart_action() {
  local js="$1" tag="$2" pod ns out
  pod="$(kb_held)" ns="$(kb_ns "$js")"
  [ -n "$pod" ] || { bad "the held API gateway pod restarted" "the break's mark names no held pod"; return 1; }
  out="$RS/record/$tag-restart-$pod.txt"
  if K -n "$ns" delete pod "$pod" --wait=true >"$out" 2>&1 &&
    K -n "$ns" rollout status "deployment/$(jf "$js" deployment)" --timeout=300s >>"$out" 2>&1; then
    ok "$pod deleted, and its Deployment $(jf "$js" deployment) rolled out with a new pod in its place ($(kb_pods "$js" | paste -sd ',' -))"
  else
    bad "$pod restarted by its Deployment" "$(tail -n 1 "$out")"
    return 1
  fi
}

key_check() {
  local js="$1" pid want held rows refusing accepting
  pid="$(jf "$js" probe)" want="$(jf "$js" refusing)"
  rows="$RS/probes/$pid-$MODE.pods"
  [ -s "$rows" ] || { bad "$pid: the per-pod probe's rows" "none saved"; return 0; }
  # a pod refusing the key never answered the status the probe wanted (its first column: "-")
  refusing="$(awk -F'\t' '$3 == "-" {print $1}' "$rows" | paste -sd ',' -)"
  accepting="$(awk -F'\t' '$3 != "-" {print $1}' "$rows" | paste -sd ',' -)"
  if [ "$want" = held ]; then
    held="$(kb_held)"
    if [ -n "$held" ] && [ "$refusing" = "$held" ] && [ -n "$accepting" ]; then
      ok "$pid: only $held, the held pod, never accepted the key ($(awk -F'\t' -v p="$held" '$1 == p {print $5}' "$rows")); $accepting accepted it"
    else
      bad "$pid: only the held pod ${held:-?} refuses the key" "refusing ${refusing:-none}, accepting ${accepting:-none}"
    fi
  else
    if [ -z "$refusing" ] && [ -n "$accepting" ]; then
      ok "$pid: every API gateway pod accepted the key ($accepting)"
    else
      bad "$pid: every API gateway pod accepts the key" "refusing ${refusing:-none}"
    fi
  fi
}
