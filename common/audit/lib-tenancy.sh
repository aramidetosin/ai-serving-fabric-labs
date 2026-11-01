# shellcheck shell=bash
# common/audit/lib-tenancy.sh: Part III's audit groups (chapters 8 to 11) and the held connections
# they, chapter 10's measurement and chapter 11's drill share. Sourced after lib.sh's sfab_init and
# common/audit/lib-audit.sh. The plan is gen/tenancy.json (sfab.render.tenancy); each group reads
# into its own directory of the result set and is judged by common/audit/tenancy.py:
#
#   audit_audiences       chapter 8: a Gateway per audience. Into audiences/: the Gateways, the
#                         HTTPRoutes, the namespaces, the leases, the L2 announcement policies,
#                         cilium-config and the API gateway's routes ConfigMap (JSON, and the
#                         Gateways, routes, leases and policies as kubectl prints them); each
#                         Gateway certificate's public key fingerprint (never the key); the key
#                         Secret's fields and fingerprints before and after the refused mint, and the
#                         refused mint's Job log and phase (a key for a model outside its caller's
#                         audience, which the key tool refuses before it reads the Secret); the
#                         internet Gateway's column (every other population's connect to its VIP,
#                         with the firewall's traffic log line for each it refuses)
#   audit_split_horizon   chapter 9: the public server asked for each name it must answer and each
#                         it must not, a name under no record (no wildcard) and a name outside its
#                         zone with recursion asked (refused); the ISP resolver from its customer
#                         and from the ISP router's link address (outside its clients, with
#                         common/trace/dnsq.py, the router holding no dig); every population's typed
#                         names, A and AAAA, through its own resolver; the uplink side's public
#                         server for the platform's names; the ISP router's routing table; the
#                         internet client's connect to the published address and its traffic log
#                         line; Cilium's copies of the Gateway certificates and the certificates
#                         each recorded node's Envoy has loaded (recorded, not judged)
#   audit_zone_nat        chapter 10: the running NAT and security rulebases; each inside
#                         population's connect to the published address and its traffic log line
#                         (or, for a silent one, the routing tables in front of the firewall); and,
#                         with a hold plan, the held connections (hold_conns.py in each client) with
#                         each zone's session count read while they are held, then show session info
#   audit_isolation       chapter 11: the negative checks, from the files the three groups above
#                         saved (run after them)
#
#   hold_start DIR ROW N HOLD_S   the held connections of the plan's hold row ROW (its index) from
#                         its client, N of them, in the background; their events go to
#                         DIR/hold-<population>.jsonl
#   hold_wait DIR ROW MAX_S       until that row's client reports every connection held
#   hold_stop DIR ROW             the row's stop file touched in its client, the generator waited on
#   hold_counts DIR TAG           each row's session count on the firewall (its filter, count yes)
#                         into DIR/counts-<TAG>-<population>.txt, and show session info into
#                         DIR/session-info-<TAG>.txt
#   hold_chat DIR ROW             one chat completion from the row's client with its own caller's key
#                         (lib-servecap.sh key_to_client, KEY_CALLER), its status saved
#
# Nothing here prints a key; the only changes are files under /tmp in the clients, removed again.

TN_PLAN="${TN_PLAN:-$RENDERDIR/gen/tenancy.json}"
TN_DIR=/tmp/sfab-tenancy
HOLD_PIDS=()
# shellcheck source=common/trace/lib-servecap.sh
. "$SFAB_COMMON/trace/lib-servecap.sh"
# shellcheck source=common/trace/lib-fwtrace.sh
. "$SFAB_COMMON/trace/lib-fwtrace.sh"

tn_has() { [ -f "$TN_PLAN" ] && py -c 'import json, sys
cur = json.load(open(sys.argv[1]))
for p in sys.argv[2].split("."):
    cur = cur.get(p) if isinstance(cur, dict) else None
sys.exit(0 if cur else 1)' "$TN_PLAN" "$1"; }

tn_get() {
  py - "$TN_PLAN" "$1" <<'PY'
import json, sys
cur = json.load(open(sys.argv[1], encoding="utf-8"))
for part in sys.argv[2].split("."):
    if isinstance(cur, list) and part.isdigit():
        cur = cur[int(part)] if int(part) < len(cur) else None
    else:
        cur = cur.get(part) if isinstance(cur, dict) else None
if isinstance(cur, list):
    print("\n".join(json.dumps(x, sort_keys=True) if isinstance(x, (dict, list)) else str(x) for x in cur))
elif isinstance(cur, dict):
    print(json.dumps(cur, sort_keys=True))
elif cur is not None:
    print(cur)
PY
}

tn_slug() { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//'; }

# t_in NODE KIND CMD: CMD in a client container (sh -c) or a VM guest (H), in the transcript
t_in() {
  local n="$1" kind="$2"
  shift 2
  if [ "$kind" = vm-node ]; then H "$n" "$*"; else X "$n" sh -c "$*"; fi
}

# t_py NODE KIND SCRIPT ARGS...: a python3 script from the repository run in the node with ARGS, fed
# on its standard input (a container through docker exec -i, a VM guest over ssh)
t_py() {
  local n="$1" kind="$2" script="$3" key
  shift 3
  _evid "$n" "$([ "$kind" = vm-node ] && echo guest || echo container)" "+ python3 - $* < ${script#"$SFAB_ROOT"/}"
  if [ "$kind" = vm-node ]; then
    key="$(lab_key)"
    timeout "${SFAB_CMD_TIMEOUT:-300}" ssh "${_SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$key" \
      "$GUEST_USER@$(node_mgmt "$n")" "sudo python3 - $(qargs "$@")" <"$script"
  else
    dk exec -i "$(ctr "$n")" python3 - "$@" <"$script"
  fi
}

# t_connect OUT NODE KIND ADDRESS PORT SPORT: one connect from a pinned source port (syn_connect.py)
t_connect() {
  local out="$1" n="$2" kind="$3" a="$4" p="$5" sp="$6"
  t_py "$n" "$kind" "$SFAB_COMMON/trace/syn_connect.py" "$a" "$p" "$sp" 1 "${SFAB_TN_CONNECT_S:-4}" 0 >"$out" 2>&1 || true
  _evid "$n" "$([ "$kind" = vm-node ] && echo guest || echo container)" "$(cat "$out")"
}

# t_dig OUT NODE KIND ARGS...: dig in the node, its output saved
t_dig() {
  local out="$1" n="$2" kind="$3"
  shift 3
  t_in "$n" "$kind" "dig +tries=1 +time=4 $*" >"$out" 2>&1 || true
}

# ---------------------------------------------------------------------------------------------
# chapter 8: a Gateway per audience

# tn_refused_events DIR JOB NS: the Warning events of the refused mint's Job and its pods saved as
# DIR/refused-mint-events.json, then deleted by name (no other event is touched)
tn_refused_events() {
  local d="$1" job="$2" ns="$3" e
  EVID_OFF=1 K -n "$ns" get events --field-selector type=Warning -o json 2>/dev/null |
    py -c 'import json, sys
job = sys.argv[1]
try:
    items = json.load(sys.stdin).get("items") or []
except ValueError:
    items = []
mine = [e for e in items if ((e.get("involvedObject") or {}).get("name") or "").startswith(job)]
json.dump({"items": mine}, open(sys.argv[2], "w"), indent=1, sort_keys=True)
print("\n".join(e["metadata"]["name"] for e in mine))' "$job" "$d/refused-mint-events.json" |
    while read -r e; do
      [ -z "$e" ] || EVID_OFF=1 K -n "$ns" delete event "$e" --ignore-not-found >/dev/null 2>&1 || true
    done
}

audit_audiences() {
  local d ns sec g s cm rm phase
  [ "${STAGE_SERVING:-0}" = 1 ] || return 0
  [ "$SFAB_QUICK" != 1 ] || return 0
  tn_has audiences || return 0
  d="$RS/audiences"
  mkdir -p "$d"
  EVID_OFF=1 K get gateways -A -o json >"$d/gateways.json" 2>/dev/null || true
  EVID_OFF=1 K get httproutes -A -o json >"$d/httproutes.json" 2>/dev/null || true
  EVID_OFF=1 K get namespaces -o json >"$d/namespaces.json" 2>/dev/null || true
  EVID_OFF=1 K -n kube-system get leases -o json >"$d/leases.json" 2>/dev/null || true
  EVID_OFF=1 K get ciliuml2announcementpolicies -o json >"$d/l2-policies.json" 2>/dev/null || true
  EVID_OFF=1 K -n kube-system get configmap cilium-config -o json >"$d/cilium-config.json" 2>/dev/null || true
  cm="$(k8s_get inference.configmaps.routes)"
  EVID_OFF=1 K -n "$(k8s_get inference.namespace)" get configmap "$cm" -o json >"$d/routes-cm.json" 2>/dev/null || true
  K get gateways -A -o wide >"$d/gateways.txt" 2>&1 || true
  K get httproutes -A >"$d/httproutes.txt" 2>&1 || true
  K -n kube-system get leases >"$d/leases.txt" 2>&1 || true
  K get ciliuml2announcementpolicies >"$d/l2-policies.txt" 2>&1 || true
  # each Gateway's certificate: its Secret's public key fingerprint, read in the init node
  : >"$d/certs.txt"
  ns="$(tn_get audiences.gateway_namespace)"
  for g in $(tn_get audiences.gateways | py -c 'import json, sys; print(" ".join(sorted(json.loads(sys.stdin.read()))))'); do
    s="$(tn_get "audiences.gateways.$g.secret")"
    { echo "== $g $s"
      KSH "kubectl -n $ns get secret $s -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/sfab-tn-cert.pem; openssl x509 -in /tmp/sfab-tn-cert.pem -noout -subject -issuer -nameopt RFC2253; printf 'spki sha256 '; openssl x509 -in /tmp/sfab-tn-cert.pem -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | cut -c1-64; rm -f /tmp/sfab-tn-cert.pem" 2>&1; } >>"$d/certs.txt" || true
  done
  # the refused mint: the key Secret's fields before and after it (fingerprints only)
  sec="$(tn_get audiences.keys.secret)" ns="$(tn_get audiences.keys.namespace)"
  EVID_OFF=1 K -n "$ns" get secret "$sec" -o json 2>/dev/null | py "$SFAB_COMMON/trace/servekeys.py" list >"$d/keys-before.txt" 2>&1 || true
  if tn_has audiences.refused_mint; then
    rm="$(tn_get audiences.refused_mint)"
    printf '%s\n' "$rm" >"$d/refused-mint.json"
    phase=Complete
    keyjob_run "$(k8s_get inference.probe.name)-refused" "$d/refused-mint.log" mint \
      "$(tn_get audiences.refused_mint.model)" "$(tn_get audiences.refused_mint.id)" "$(tn_get audiences.refused_mint.caller)" \
      >/dev/null 2>&1 || phase=Failed
    printf '%s\n' "$phase" >"$d/refused-mint.phase"
    # the refused Job leaves a Warning event (BackoffLimitExceeded) that the next audit's cluster
    # group would read as a fault (the lab's first ch10 deploy, its second audit): it is this
    # check's own evidence, so it is saved here and deleted, as the drills archive theirs
    tn_refused_events "$d" "$(k8s_get inference.probe.name)-refused" "$(k8s_get inference.namespace)"
    EVID_OFF=1 K -n "$ns" get secret "$sec" -o json 2>/dev/null | py "$SFAB_COMMON/trace/servekeys.py" list >"$d/keys-after.txt" 2>&1 || true
  fi
  # the internet Gateway's column: every other population's connect to its VIP, and the firewall's
  # line for each one it refuses
  if tn_has audiences.column; then
    local row pop client kind addr i=0 sp k
    : >"$d/column.tsv"
    while read -r row; do
      [ -n "$row" ] || continue
      read -r pop client kind addr <<<"$(py -c 'import json, sys; r = json.loads(sys.argv[1]); print(r["population"], r["client"], r["kind"], r["address"])' "$row")"
      sp=$((42370 + 2 * i))
      t_connect "$d/column-$pop.txt" "$client" "$kind" "$addr" 443 "$sp"
      printf '%s\t%s\t%s\t%s\n' "$pop" "$client" "$(inv get nodes."$client".address | cut -d/ -f1)" "$sp" >>"$d/column.tsv"
      i=$((i + 1))
    done < <(tn_get audiences.column.rows)
    if [ -n "${FW_NODE:-}" ]; then
      for k in 1 2 3 4 5 6 7 8 9; do
        FW "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" |
          fwt_body "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" >"$d/traffic-log-443.txt" 2>/dev/null || true
        [ "$(py "$SFAB_COMMON/audit/tenancy.py" tlog-missing --plan "$TN_PLAN" --dir "$d" --rows audiences.column.rows --tsv column.tsv)" != 0 ] || break
        sleep "${SFAB_TRACE_TLOG_PAUSE_S:-10}"
      done
    fi
  fi
  _judge audiences
}

# ---------------------------------------------------------------------------------------------
# chapter 9: split-horizon DNS

audit_split_horizon() {
  local d c srv name row pop client kind server n rtr src addr sp
  [ "$SFAB_QUICK" != 1 ] || return 0
  tn_has dns || return 0
  d="$RS/split-horizon"
  mkdir -p "$d"
  # the public server: every public name, every name it must not hold, no wildcard, no recursion
  c="$(tn_get dns.public.from)" srv="$(tn_get dns.public.address)"
  while read -r name; do
    [ -n "$name" ] || continue
    t_dig "$d/public-$(tn_slug "$name").txt" "$c" client "+norecurse @$srv $name A"
  done < <(tn_get dns.public.names | py -c 'import json, sys; [print(n) for n in sorted(json.loads(sys.stdin.read()))]')
  while read -r name; do
    [ -n "$name" ] || continue
    t_dig "$d/absent-$(tn_slug "$name").txt" "$c" client "+norecurse @$srv $name A"
  done < <(tn_get dns.public.absent)
  t_dig "$d/wildcard.txt" "$c" client "+norecurse @$srv $(tn_get dns.public.wildcard) A"
  t_dig "$d/recursion.txt" "$c" client "+recurse @$srv $(tn_get dns.public.recursion_name) A"
  # the ISP's resolver: for its customer, and from a source outside its clients
  c="$(tn_get dns.isp.from)" srv="$(tn_get dns.isp.address)" name="$(tn_get dns.isp.name)"
  t_dig "$d/isp-answer.txt" "$c" client "@$srv $name A"
  rtr="$(tn_get dns.isp.outside.node)" src="$(tn_get dns.isp.outside.source)"
  _evid "$rtr" container "+ python3 - $srv $name A $src 1 4 < common/trace/dnsq.py"
  dk exec -i "$(ctr "$rtr")" sh -c 'if command -v python3 >/dev/null 2>&1; then exec python3 - "$@"; else echo "dnsq: no python3 on this node"; exit 3; fi' \
    sh "$srv" "$name" A "$src" 1 4 <"$SFAB_COMMON/trace/dnsq.py" >"$d/isp-outside.txt" 2>&1 || true
  _evid "$rtr" container "$(cat "$d/isp-outside.txt")"
  # every population's typed names, A and AAAA, through its own resolver
  while read -r row; do
    [ -n "$row" ] || continue
    read -r pop client kind server <<<"$(py -c 'import json, sys; r = json.loads(sys.argv[1]); print(r["population"], r["client"], r["kind"], r["server"])' "$row")"
    while read -r n; do
      [ -n "$n" ] || continue
      t_dig "$d/a-$pop-$(tn_slug "$n").txt" "$client" "$kind" "@$server $n A"
      t_dig "$d/aaaa-$pop-$(tn_slug "$n").txt" "$client" "$kind" "@$server $n AAAA"
    done < <(py -c 'import json, sys; [print(n) for n in json.loads(sys.argv[1])["names"]]' "$row")
  done < <(tn_get dns.aaaa)
  # the uplink side's public server holds no platform name
  if tn_has dns.ops; then
    srv="$(tn_get dns.ops.address)"
    c="$(py -c 'import json, sys; t = json.load(open(sys.argv[1])); print(next(r["client"] for r in t["dns"]["aaaa"] if r["resolver"] == t["dns"]["ops"]["server"]))' "$TN_PLAN" 2>/dev/null || true)"
    while read -r name; do
      [ -n "$name" ] && [ -n "$c" ] || continue
      t_dig "$d/ops-$(tn_slug "$name").txt" "$c" client "@$srv $name A"
    done < <(tn_get dns.ops.names)
  fi
  rtr="$(tn_get dns.isp_router.node)"
  FR "$rtr" "show ip route" >"$d/$rtr-ip-route.txt" 2>&1 || true
  # the internet client's connect to the published address, and the firewall's line for it
  c="$(tn_get dns.internet_syn.client)" addr="$(tn_get dns.internet_syn.address)" sp="$(tn_get dns.internet_syn.sport)"
  t_connect "$d/syn.txt" "$c" client "$addr" 443 "$sp"
  if [ -n "${FW_NODE:-}" ]; then
    fwt_tlog "$d/traffic-log.txt" "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" \
      --src "$(inv get nodes."$c".address | cut -d/ -f1)" --sport "$sp" >/dev/null 2>&1 || true
  fi
  # Cilium's copies of the Gateway certificates, which every node's Envoy loads (recorded), and
  # the certificates each recorded node's Envoy has loaded, listed from its Cilium agent pod
  K -n "$(tn_get dns.envoy_certs.namespace)" get secrets >"$d/cilium-secrets.txt" 2>&1 || true
  local pod node ecmd
  ecmd="$(tn_get dns.envoy_certs.command | paste -sd ' ' -)"
  while read -r pod node; do
    [ -n "$pod" ] || continue
    tn_get dns.envoy_certs.nodes | grep -qx "$node" || continue
    # shellcheck disable=SC2086
    K -n kube-system exec "$pod" -c cilium-agent -- $ecmd >"$d/envoy-certs-$node.txt" 2>&1 || true
  done < <(EVID_OFF=1 K -n kube-system get pods -l k8s-app=cilium -o json 2>/dev/null | py -c 'import json, sys
try:
    for i in json.load(sys.stdin).get("items") or []:
        print(i["metadata"]["name"], (i.get("spec") or {}).get("nodeName", ""))
except ValueError:
    pass')
  _judge split-horizon
}

# ---------------------------------------------------------------------------------------------
# chapter 10: zone-keyed translation

audit_zone_nat() {
  local d row pop client kind addr i sp n rows
  [ "$SFAB_QUICK" != 1 ] || return 0
  tn_has firewall || return 0
  [ -n "${FW_NODE:-}" ] || return 0
  d="$RS/zone-nat"
  mkdir -p "$d/routers"
  FW "show running nat-policy" | fwt_body "show running nat-policy" >"$d/running-nat.txt" 2>/dev/null || true
  FW "show running security-policy" | fwt_body "show running security-policy" >"$d/running-security.txt" 2>/dev/null || true
  # each inside population's connect to the published address: the arrival zone keys the
  # translation, so none of them is translated
  i=0
  : >"$d/inside.tsv"
  while read -r row; do
    [ -n "$row" ] || continue
    read -r pop client kind addr <<<"$(py -c 'import json, sys; r = json.loads(sys.argv[1]); print(r["population"], r["client"], r["kind"], r["address"])' "$row")"
    sp=$((42392 + 2 * i))
    t_connect "$d/inside-$pop.txt" "$client" "$kind" "$addr" 443 "$sp"
    printf '%s\t%s\t%s\t%s\n' "$pop" "$client" "$(inv get nodes."$client".address | cut -d/ -f1)" "$sp" >>"$d/inside.tsv"
    i=$((i + 1))
  done < <(tn_get firewall.inside)
  for i in 1 2 3 4 5 6 7 8 9; do
    FW "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" |
      fwt_body "show log traffic direction equal backward receive_time in last-15-minutes dport equal 443" >"$d/traffic-log-443.txt" 2>/dev/null || true
    [ "$(py "$SFAB_COMMON/audit/tenancy.py" tlog-missing --plan "$TN_PLAN" --dir "$d")" != 0 ] || break
    sleep "${SFAB_TRACE_TLOG_PAUSE_S:-10}"
  done
  for n in $(py -c 'import json, sys; t = json.load(open(sys.argv[1])); print(" ".join(sorted({r["device"] for r in t["firewall"]["inside"] if r["outcome"] == "silence"})))' "$TN_PLAN"); do
    FR "$n" "show ip route" >"$d/routers/$n-ip-route.txt" 2>&1 || true
  done
  # the held connections and each zone's session count while they are held
  if tn_has hold; then
    rows="$(tn_get hold.rows | grep -c .)"
    for ((i = 0; i < rows; i++)); do hold_start "$d" "$i" "$(tn_get hold.n)" "${SFAB_TN_AUDIT_HOLD_S:-90}"; done
    for ((i = 0; i < rows; i++)); do hold_wait "$d" "$i" 60; done
    hold_counts "$d" held
    for ((i = 0; i < rows; i++)); do hold_stop "$d" "$i"; done
  fi
  _judge zone-nat
}

# chapter 11: the negative checks, from the three groups' files
audit_isolation() {
  [ "$SFAB_QUICK" != 1 ] || return 0
  tn_has isolation || return 0
  _judge isolation
}

# ---------------------------------------------------------------------------------------------
# the held connections

hold_row() { tn_get "hold.rows.$1"; }
hold_field() { py -c 'import json, sys; r = json.loads(sys.argv[1]); v = r
for p in sys.argv[2].split("."):
    v = v.get(p) if isinstance(v, dict) else None
print("" if v is None else v)' "$(hold_row "$1")" "$2"; }

hold_start() {
  local d="$1" i="$2" n="$3" secs="$4" pop client addr host path sport tag
  pop="$(hold_field "$i" population)" client="$(hold_field "$i" client)" addr="$(hold_field "$i" address)"
  host="$(hold_field "$i" hostname)" path="$(hold_field "$i" path)" sport="$(hold_field "$i" sport)"
  tag="$(tn_slug "$pop")"
  dk exec "$(ctr "$client")" sh -c "umask 077; mkdir -p $TN_DIR; rm -f $TN_DIR/stop-$tag" >/dev/null 2>&1 || true
  _evid "$client" container "+ python3 - $addr $host $path $n $secs $(tn_get hold.every_s) $sport $(tn_get hold.ca_root) $tag $TN_DIR/stop-$tag < common/trace/hold_conns.py (started)"
  dk exec -i "$(ctr "$client")" python3 - "$addr" "$host" "$path" "$n" "$secs" "$(tn_get hold.every_s)" "$sport" "$(tn_get hold.ca_root)" \
    "$tag" "$TN_DIR/stop-$tag" <"$SFAB_COMMON/trace/hold_conns.py" >"$d/hold-$pop.jsonl" 2>&1 &
  HOLD_PIDS[$i]=$!
  echo "hold: $pop, $n connection(s) from $client to $addr ($host)"
}

hold_wait() {
  local d="$1" i="$2" max="$3" pop k
  pop="$(hold_field "$i" population)"
  for ((k = 0; k < max * 2; k++)); do
    grep -q '"event": "held"' "$d/hold-$pop.jsonl" 2>/dev/null && return 0
    kill -0 "${HOLD_PIDS[$i]:-0}" 2>/dev/null || return 1
    sleep 0.5
  done
  warn "hold: $pop did not report its connections held within $max s"
  return 1
}

hold_stop() {
  local d="$1" i="$2" pop client tag
  pop="$(hold_field "$i" population)" client="$(hold_field "$i" client)" tag="$(tn_slug "$(hold_field "$i" population)")"
  dk exec "$(ctr "$client")" touch "$TN_DIR/stop-$tag" >/dev/null 2>&1 || true
  wait "${HOLD_PIDS[$i]:-0}" 2>/dev/null || true
  _evid "$client" container "+ hold_conns.py $pop (finished)"$'\n'"$(tail -n 1 "$d/hold-$pop.jsonl" 2>/dev/null)"
  dk exec "$(ctr "$client")" rm -rf "$TN_DIR" >/dev/null 2>&1 || true
}

hold_counts() {
  local d="$1" tag="$2" i rows pop flt cmd
  rows="$(tn_get hold.rows | grep -c .)"
  for ((i = 0; i < rows; i++)); do
    pop="$(hold_field "$i" population)" flt="$(hold_field "$i" filter)"
    cmd="show session all filter $flt count yes"
    FW "$cmd" | fwt_body "$cmd" >"$d/counts-$tag-$pop.txt" 2>/dev/null || true
  done
  FW "show session info" | fwt_body "show session info" >"$d/session-info-$tag.txt" 2>/dev/null || true
}

hold_chat() {
  local d="$1" i="$2" pop client model url caller resolve kdir=/tmp/sfab-tenancy-key pin=()
  pop="$(hold_field "$i" population)" client="$(hold_field "$i" client)"
  model="$(hold_field "$i" chat.model)" url="$(hold_field "$i" chat.url)" caller="$(hold_field "$i" chat.caller)"
  resolve="$(hold_field "$i" resolve)"
  [ -n "$model" ] || return 0
  [ -z "$resolve" ] || pin=(--resolve "$resolve")
  if KEY_CALLER="$caller" key_to_client "$(k8s_get inference.namespace)" "$(k8s_get inference.keys.models.secret)" "$model" "$client" "$kdir" \
    >"$d/chat-$pop-key.txt" 2>&1; then
    printf '%s\n' "{\"model\": \"$model\", \"max_tokens\": 1, \"messages\": [{\"role\": \"user\", \"content\": \"Say yes.\"}]}" |
      dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$kdir/body.json"
    X "$client" curl -sS --max-time 120 "${pin[@]+"${pin[@]}"}" --cacert "$(tn_get hold.ca_root)" -o "$kdir/answer.json" -w '%{http_code}\n' \
      -H 'Content-Type: application/json' -H "@$kdir/hdr-$model" --data "@$kdir/body.json" "$url" >"$d/chat-$pop-result.txt" 2>&1 || true
  else
    echo "no key" >"$d/chat-$pop-result.txt"
  fi
  key_clear "$client" "$kdir"
}

hold_cleanup() {
  local p
  for p in "${HOLD_PIDS[@]+"${HOLD_PIDS[@]}"}"; do kill "$p" 2>/dev/null || true; done
}
