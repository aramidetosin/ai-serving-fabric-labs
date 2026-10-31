# shellcheck shell=bash
# common/trace/lib-servecap.sh: what chapter 6's audit, trace, drills and break share. Sourced after
# lib.sh's sfab_init; it sources lib-railcap.sh, whose captures it adds pods to.
#
#   k8s_get KEY                 a value of gen/k8s.json, by dotted path (serving.namespace,
#                               inference.keys.models.secret); a list prints one item a line
#   pod_pid NODE NS POD         the PID of the pod's sandbox in guest NODE (crictl inspectp), whose
#                               network namespace is the pod's; empty when NODE holds no ready
#                               sandbox of that pod
#   pod_ns_run NODE PID CMD     CMD in that network namespace, in the guest (nsenter -t PID -n)
#   key_to_client NS SECRET MODEL CLIENT DIR [FIELD [NAME]]
#                               the model's first key (or the key in FIELD, <model>.<id>) from its
#                               Secret into the client container: DIR/key-<NAME> (the key alone) and
#                               DIR/hdr-<NAME> (its Authorization header line), both 0600 under a
#                               0700 DIR; NAME is the model's name unless given. The value travels
#                               through pipes only, from the harness's kubectl (on the init node) to the client's own
#                               file: no transcript block, no file on the lab host, no command line
#                               holds it. Prints the key's field and fingerprint, and with
#                               KEY_MARK=1 its mark under the lab's redaction key (chapter 7)
#   key_clear CLIENT DIR        DIR removed in the client
#   idp_token CLIENT DIR NAME [noaud]
#                               a person's ID token from the identity provider (gen/k8s.json
#                               identity), signed in from CLIENT, the person's node: the person's
#                               password and the client's secret go from state/secrets.env through
#                               a pipe into a 0600 curl config in DIR, the client asks the IdP's
#                               token endpoint through its Gateway (the resource owner password
#                               grant, with the scope that asks for the API gateway's audience,
#                               or with noaud without it), and keeps DIR/hdr-NAME (the token's
#                               Authorization header line, 0600) and DIR/claims-NAME.json (the
#                               claims a judge reads: iss, aud, azp, email, email_verified and the
#                               token's lifetime; never the token). The config and the response
#                               are removed. Prints the token endpoint's HTTP status
#   key_unknown CLIENT DIR NAME a key no Secret holds, made in the client from its own random bytes in
#                               the shape of the lab's keys, as DIR/key-NAME and DIR/hdr-NAME (0600):
#                               the probe of an unknown key (chapter 7)
#   secret_mark NS SECRET FIELD the field's fingerprint and mark ("FIELD sha256:... <redacted hmac:...>"),
#                               read through a pipe from the harness's kubectl
#   kapply FILE                 kubectl apply --server-side --force-conflicts of FILE, a manifest
#                               (no secret), fed to the harness's kubectl on its standard input
#   kcreate FILE                kubectl create of FILE the same way
#   pod_phase NS POD MAX_S      the pod's phase once Succeeded or Failed, polled every 2 s for MAX_S
#                               at most (unknown otherwise)
#   keyprobe_run NAME OUT MAX_S CHECK...   the per-pod key probe (common/trace/keyprobe.py pod):
#                               the pod made, waited for, its log saved as OUT, the pod removed;
#                               each CHECK is "LABEL ROUTE FIELD EXPECT", and KEYPROBE_REPEAT=1
#                               runs each in rounds until every API gateway pod answers EXPECT;
#                               keyprobe_start and keyprobe_finish are its two halves, and
#                               keyprobe_running waits until the started pod holds its key
#   keyjob_run NAME OUT mint|revoke MODEL ID   a key Job (keyprobe.py job) run once, its log
#                               (fingerprints only) saved as OUT, the Job removed
#   qargs ARG...                the arguments shell-quoted for a command string; nothing for none
#   events_archive DIR NS...    each namespace's Warning events saved as DIR/events-<ns>.json and
#                               .txt, then deleted: the readiness failures a drill or a break
#                               causes are its evidence, and the audit after it expects none
#
# Nothing here prints a key.

# shellcheck source=common/trace/lib-railcap.sh
. "$SFAB_COMMON/trace/lib-railcap.sh"

# qargs ARG...: the arguments shell-quoted for a command line built as a string, and nothing at all
# for none (printf '%q ' with no argument prints '' , an empty argument the command refuses)
qargs() { [ $# -eq 0 ] || printf '%q ' "$@"; return 0; }

k8s_get() {
  py - "$RENDERDIR/gen/k8s.json" "$1" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
if isinstance(cur, list):
    print("\n".join(json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x) for x in cur))
elif isinstance(cur, dict):
    print(json.dumps(cur, sort_keys=True))
elif cur is not None:
    print(cur)
PY
}

pod_pid() {
  local node="$1" ns="$2" pod="$3" cmd
  cmd="id=\$(crictl pods --namespace '^$ns\$' --name '^$pod\$' --state ready -q 2>/dev/null | head -n 1); [ -n \"\$id\" ] || exit 1; "
  cmd+="crictl inspectp \"\$id\" | python3 -c 'import json, sys; print(json.load(sys.stdin)[\"info\"][\"pid\"])'"
  EVID_OFF=1 H "$node" "$cmd" 2>/dev/null | tail -n 1 | tr -cd '0-9'
}

pod_ns_run() {
  local node="$1" ppid="$2"
  shift 2
  H "$node" "nsenter -t $ppid -n $*"
}

key_to_client() {
  local ns="$1" sec="$2" model="$3" client="$4" dir="$5" field="${6:-}" name="${7:-$3}" c b err rc=0 extra=()
  c="$(ctr "$client")"
  err="$(tmpf)"
  [ -z "$field" ] || extra+=(--field "$field")
  [ "${KEY_MARK:-0}" != 1 ] || extra+=(--mark-key "$STATEDIR/secrets/redact.key")
  dk exec "$c" sh -c "umask 077; mkdir -p $dir" >/dev/null 2>&1 || true
  EVID_OFF=1 K -n "$ns" get secret "$sec" -o json 2>/dev/null |
    py "$SFAB_COMMON/trace/servekeys.py" pick --model "$model" "${extra[@]+"${extra[@]}"}" 2>"$err" |
    dk exec -i "$c" sh -c "umask 077; read -r k; read -r h; printf '%s\n' \"\$k\" >$dir/key-$name; printf '%s\n' \"\$h\" >$dir/hdr-$name" ||
    rc=1
  cat "$err"
  rm -f "$err"
  [ "$rc" -eq 0 ] && dk exec "$c" test -s "$dir/hdr-$name"
}

key_unknown() {
  local client="$1" dir="$2" name="$3" c pfx
  c="$(ctr "$client")" pfx="$(k8s_get inference.keys.models.prefix)"
  dk exec "$c" sh -c "umask 077; mkdir -p $dir; k=\$(python3 -c 'import secrets, sys; print(sys.argv[1] + \"-unknown-\" + secrets.token_hex(16))' $pfx); printf '%s\n' \"\$k\" >$dir/key-$name; printf 'Authorization: Bearer %s\n' \"\$k\" >$dir/hdr-$name" >/dev/null 2>&1 &&
    dk exec "$c" test -s "$dir/hdr-$name"
}

secret_mark() {
  EVID_OFF=1 K -n "$1" get secret "$2" -o json 2>/dev/null |
    py "$SFAB_COMMON/trace/servekeys.py" mark --field "$3" --mark-key "$STATEDIR/secrets/redact.key"
}

kapply() {
  local shown="kubectl apply --server-side --force-conflicts -f - (a manifest, no secret)"
  _knode || return 2
  _cap "$KNODE" kubectl "$shown" _ssh_guest_in "$GUEST_USER@$(node_mgmt "$KNODE")" \
    "sudo env KUBECONFIG=$KADMIN kubectl apply --server-side --force-conflicts -f -" <"$1"
}
kcreate() {
  local shown="kubectl create -f - (a manifest, no secret)"
  _knode || return 2
  _cap "$KNODE" kubectl "$shown" _ssh_guest_in "$GUEST_USER@$(node_mgmt "$KNODE")" \
    "sudo env KUBECONFIG=$KADMIN kubectl create -f -" <"$1"
}

pod_phase() {
  local ns="$1" pod="$2" max="$3" t0 phase=""
  t0="$(date +%s)"
  while :; do
    phase="$(EVID_OFF=1 K -n "$ns" get pod "$pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    case "$phase" in Succeeded|Failed) break ;; esac
    [ $(($(date +%s) - t0)) -lt "$max" ] || break
    sleep "${SFAB_POD_POLL_S:-2}"
  done
  printf '%s\n' "${phase:-unknown}"
}

# keyprobe_start NAME MAX_S CHECK...: the probe pod made; KEYPROBE_WAIT holds how long its rounds may take
keyprobe_start() {
  local name="$1" max="$2" ns m args=() c
  shift 2
  ns="$(k8s_get inference.namespace)"
  for c in "$@"; do
    read -r -a _c <<<"$c"
    args+=(--check "${_c[@]}")
  done
  # the pod's start and image pull, then each check: its rounds when repeating, else one round
  if [ "${KEYPROBE_REPEAT:-0}" = 1 ]; then
    args+=(--repeat --max-s "$max" --interval "${KEYPROBE_INTERVAL_S:-1}")
    KEYPROBE_WAIT=$(( (${max%.*} + 30) * $# + 120 ))
  else
    KEYPROBE_WAIT=$(( 30 * $# + 120 ))
  fi
  m="$(tmpf)"
  py "$SFAB_COMMON/trace/keyprobe.py" pod --k8s "$RENDERDIR/gen/k8s.json" --name "$name" "${args[@]}" >"$m" || { rm -f "$m"; return 1; }
  EVID_OFF=1 K -n "$ns" delete pod "$name" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kcreate "$m" >/dev/null 2>&1 || true
  rm -f "$m"
}

# keyprobe_finish NAME OUT [WAIT_S]: until the probe pod ends, its log saved as OUT (and its phase as
# OUT's .phase twin), the pod removed; non-zero when it did not succeed
keyprobe_finish() {
  local name="$1" out="$2" wait_s="${3:-${KEYPROBE_WAIT:-300}}" ns phase
  ns="$(k8s_get inference.namespace)"
  phase="$(pod_phase "$ns" "$name" "$wait_s")"
  K -n "$ns" logs "$name" >"$out" 2>&1 || true
  printf '%s\n' "$phase" >"${out%.*}.phase"
  EVID_OFF=1 K -n "$ns" delete pod "$name" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  [ "$phase" = Succeeded ] || { warn "key probe $name: the pod ended $phase (see $(basename "$out"))"; return 1; }
}

# keyprobe_running NAME MAX_S: until the probe pod has printed its first line (so it holds its key)
keyprobe_running() {
  local name="$1" max="$2" ns t0
  ns="$(k8s_get inference.namespace)"
  t0="$(date +%s)"
  while [ $(($(date +%s) - t0)) -lt "$max" ]; do
    EVID_OFF=1 K -n "$ns" logs "$name" 2>/dev/null | grep -q '"pod"' && return 0
    sleep "${SFAB_POD_POLL_S:-2}"
  done
  return 1
}

keyprobe_run() {
  local name="$1" out="$2" max="$3"
  shift 3
  keyprobe_start "$name" "$max" "$@" || return 1
  keyprobe_finish "$name" "$out" "$KEYPROBE_WAIT"
}

keyjob_run() {
  local name="$1" out="$2" op="$3" model="$4" id="$5" ns m phase
  ns="$(k8s_get inference.namespace)"
  m="$(tmpf)"
  py "$SFAB_COMMON/trace/keyprobe.py" job --k8s "$RENDERDIR/gen/k8s.json" --name "$name" "--$op" --model "$model" --id "$id" >"$m" || { rm -f "$m"; return 1; }
  EVID_OFF=1 K -n "$ns" delete job "$name" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kcreate "$m" >/dev/null 2>&1 || true
  rm -f "$m"
  phase=unknown
  if K -n "$ns" wait --for=condition=complete "job/$name" --timeout="${SFAB_KEYJOB_WAIT_S:-180}s" >/dev/null 2>&1; then phase=Complete; fi
  K -n "$ns" logs "job/$name" >"$out" 2>&1 || true
  EVID_OFF=1 K -n "$ns" delete job "$name" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  [ "$phase" = Complete ] || { warn "key Job $name did not complete (see $(basename "$out"))"; return 1; }
}

key_clear() { dk exec "$(ctr "$1")" rm -rf "$2" >/dev/null 2>&1 || true; }

idp_token() {
  local client="$1" dir="$2" name="$3" noaud="${4:-}" c plan
  c="$(ctr "$client")"
  plan="$(py - "$RENDERDIR/gen/k8s.json" "$client" "$noaud" <<'PY'
import json, shlex, sys
idp = (json.load(open(sys.argv[1], encoding="utf-8")) or {}).get("identity") or {}
p = next((x for x in idp.get("people") or [] if x.get("node") == sys.argv[2]), None)
if not idp or p is None:
    sys.exit(1)
scope = idp["scope"] if sys.argv[3] != "noaud" else idp["scope"].rsplit(" audience:", 1)[0]
cl = idp["clients"][0]
print(" ".join(shlex.quote(x) for x in (p["password_env"], cl["secret_env"], cl["id"], p["email"], scope,
                                        f"https://{idp['hostname']}{idp['token_path']}")))
PY
)" || { echo "no person signs in from $client"; return 1; }
  local pwenv secenv cid email scope url
  eval "set -- $plan"
  pwenv="$1" secenv="$2" cid="$3" email="$4" scope="$5" url="$6"
  dk exec "$c" sh -c "umask 077; mkdir -p $dir" >/dev/null 2>&1 || true
  # the curl config holds the client's secret and the person's password: from secrets.env to the
  # client's 0600 file through a pipe, never a command line or a file on the lab host
  py - "$STATEDIR/secrets.env" "$pwenv" "$secenv" "$cid" <<'PY' | dk exec -i "$c" sh -c "umask 077; cat > $dir/idp-$name.cfg" || return 1
import sys
env = dict(l.rstrip("\n").split("=", 1) for l in open(sys.argv[1], encoding="utf-8") if "=" in l and not l.startswith("#"))
pw, sec = env.get(sys.argv[2]), env.get(sys.argv[3])
if not pw or not sec:
    sys.exit(1)
print(f'user = "{sys.argv[4]}:{sec}"')
print(f'data-urlencode = "password={pw}"')
PY
  X "$client" curl -sS --max-time 30 -K "$dir/idp-$name.cfg" -o "$dir/tok-$name.json" -w '%{http_code}\n' \
    -d grant_type=password --data-urlencode "username=$email" --data-urlencode "scope=$scope" "$url" || true
  dk exec "$c" sh -c "rm -f $dir/idp-$name.cfg" >/dev/null 2>&1 || true
  # shellcheck disable=SC2016 # expanded by the client's python3
  dk exec "$c" python3 -c '
import base64, json, os, sys
d, n = sys.argv[1], sys.argv[2]
try:
    t = json.load(open(f"{d}/tok-{n}.json"))["id_token"]
except (OSError, ValueError, KeyError):
    sys.exit(1)
finally:
    if os.path.exists(f"{d}/tok-{n}.json"):
        os.remove(f"{d}/tok-{n}.json")
p = t.split(".")[1]
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
os.umask(0o077)
open(f"{d}/hdr-{n}", "w").write(f"Authorization: Bearer {t}\n")
keep = {k: c.get(k) for k in ("iss", "aud", "azp", "email", "email_verified")}
keep["lifetime_s"] = (c.get("exp") or 0) - (c.get("iat") or 0)
open(f"{d}/claims-{n}.json", "w").write(json.dumps(keep, sort_keys=True) + "\n")
' "$dir" "$name" >/dev/null 2>&1
}

events_archive() {
  local dir="$1" ns
  shift
  mkdir -p "$dir"
  for ns in "$@"; do
    [ -n "$ns" ] || continue
    EVID_OFF=1 K -n "$ns" get events --field-selector type=Warning -o json >"$dir/events-$ns.json" 2>/dev/null || true
    EVID_OFF=1 K -n "$ns" get events --field-selector type=Warning --sort-by=.lastTimestamp >"$dir/events-$ns.txt" 2>&1 || true
    EVID_OFF=1 K -n "$ns" delete events --field-selector type=Warning >/dev/null 2>&1 || true
  done
}
