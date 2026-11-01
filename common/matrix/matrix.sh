# shellcheck shell=bash
# common/matrix/matrix.sh: chapter 2's matrix run (FRAMEWORK.md 4.8), sourced after lib.sh's sfab_init
# by a lab's matrix.sh, and by common/break/breakheal.sh for break-2a's matrix_cells record.
#
#   matrix_run                  every cell of gen/matrix.json into the result set ($RS), judged by
#                               common/matrix/matrix.py, which writes MATRIX.md
#   matrix_cells DIR [CELL...]  the named cells (every cell without one) into DIR: the evidence only,
#                               which matrix.py observe and judge read
#
# Each population's cells are tried from its own client, by TCP connect (common/trace/syn_connect.py,
# from a pinned source port) and HTTP request (curl, its source port pinned with --local-port), never
# by ping: a Gateway's VIP answers TCP and not ICMP on the pinned Cilium (chapter 7). In order:
#   1. lookups   each client looks up every name its cells ask for through its own resolver (dig in a
#                container, getent ahostsv4 in a VM guest): the resolver view's row, and the warm-up
#   2. keys      both models' keys (and a cell's own caller's, key_caller, Part III) handed to each
#                client a model cell runs from, through pipes from
#                their Secret in the cluster into a 0600 header file there (lib-servecap.sh for a
#                container; the same pipe over ssh for a VM guest): no key is on a command line, in
#                the transcript or on the lab host, and each is named by its fingerprint only
#   3. requests  every request of every cell, in the plan's order, each attempt logged in
#                requests.tsv; an attempt that was to be answered and was not is tried once more from
#                the next source port after a pause (the first packets of a new flow are lost to ARP)
#   4. evidence  the firewall's traffic log for every destination port an unanswered attempt crossed,
#                read until it holds each of them; its drop counters over the requests, when zone
#                protection's strict IP check drops a cell (no log line records that drop); its
#                routing table and the routers'; the API gateway pods' access log over the run
#   5. cleanup   the keys' files removed from every client
#
# The only changes it makes are files under /tmp/sfab-matrix in the clients, removed at the end.

MXP="$SFAB_COMMON/matrix/matrix.py"
MX_PLAN="${MX_PLAN:-$RENDERDIR/gen/matrix.json}"
MX_DIR=/tmp/sfab-matrix
# shellcheck source=common/trace/lib-servecap.sh
. "$SFAB_COMMON/trace/lib-servecap.sh"
# shellcheck source=common/trace/lib-fwtrace.sh
. "$SFAB_COMMON/trace/lib-fwtrace.sh"

mx_get() { py "$MXP" get --plan "$MX_PLAN" "$1"; }
mx_now() { date +%s; }

# mx_guest_in NODE CMD: CMD as root in the VM guest with this shell's standard input (H runs ssh -n)
mx_guest_in() {
  local n="$1" key
  shift
  key="$(lab_key)"
  [ -f "$key" ] || { warn "no lab key at $key (preflight creates it)"; return 2; }
  timeout "${SFAB_CMD_TIMEOUT:-300}" ssh "${_SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$key" \
    "$GUEST_USER@$(node_mgmt "$n")" "sudo bash -c $(printf '%q' "$*")"
}

# mx_in NODE KIND CMD: CMD in a client container (sh -c) or a VM guest (H), recorded in the transcript
mx_in() {
  local n="$1" kind="$2"
  shift 2
  if [ "$kind" = vm-node ]; then H "$n" "$*"; else X "$n" sh -c "$*"; fi
}

# mx_put NODE KIND FILE: standard input into FILE in the client, mode 0600 under a 0700 directory
mx_put() {
  local n="$1" kind="$2" f="$3"
  if [ "$kind" = vm-node ]; then
    mx_guest_in "$n" "umask 077; mkdir -p $MX_DIR; cat >$f"
  else
    dk exec -i "$(ctr "$n")" sh -c "umask 077; mkdir -p $MX_DIR; cat >$f"
  fi
}

# mx_key NODE KIND MODEL [CALLER]: the model's first key, or with CALLER that caller's first key
# (Part III: a cell's own key_caller), into MX_DIR/hdr-MODEL (hdr-CALLER) in the client, through pipes
mx_key() {
  local n="$1" kind="$2" model="$3" caller="${4:--}" ns sec err rc=0 name extra=()
  ns="$(mx_get api_gateway.namespace)" sec="$(mx_get api_gateway.secret)"
  name="$model"
  if [ "$caller" != - ]; then name="$caller"; extra=(--caller "$caller"); fi
  if [ "$kind" != vm-node ]; then
    KEY_CALLER="${extra[1]:-}" key_to_client "$ns" "$sec" "$model" "$n" "$MX_DIR" "" "$name"
    return
  fi
  err="$(tmpf)"
  EVID_OFF=1 K -n "$ns" get secret "$sec" -o json 2>/dev/null |
    py "$SFAB_COMMON/trace/servekeys.py" pick --model "$model" "${extra[@]+"${extra[@]}"}" 2>"$err" |
    mx_guest_in "$n" "umask 077; mkdir -p $MX_DIR; read -r k; read -r h; printf '%s\n' \"\$k\" >$MX_DIR/key-$name; printf '%s\n' \"\$h\" >$MX_DIR/hdr-$name" ||
    rc=1
  cat "$err"
  rm -f "$err"
  [ "$rc" -eq 0 ] && EVID_OFF=1 H "$n" "test -s $MX_DIR/hdr-$name" >/dev/null 2>&1
}

mx_clear() {
  local n="$1" kind="$2"
  if [ "$kind" = vm-node ]; then EVID_OFF=1 H "$n" "rm -rf $MX_DIR" >/dev/null 2>&1 || true; else key_clear "$n" "$MX_DIR"; fi
}

# mx_lookup DIR ROW CLIENT KIND NAME: the client's own lookup of NAME, through its resolver
mx_lookup() {
  local d="$1" row="$2" n="$3" kind="$4" name="$5" f
  f="$d/lookups/$(mx_slug "$row")-$(mx_slug "$name").txt"
  if [ "$kind" = vm-node ]; then
    H "$n" "getent ahostsv4 $name" >"$f" 2>&1 || true
  else
    X "$n" dig "$name" >"$f" 2>&1 || true
  fi
}

mx_slug() { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//'; }

# mx_connect DIR TAG CLIENT KIND ADDRESS PORT SPORT: one connect from a pinned source port
mx_connect() {
  local d="$1" t="$2" n="$3" kind="$4" a="$5" p="$6" sp="$7" to
  to="$(mx_get timeout_s)"
  _evid "$n" "$([ "$kind" = vm-node ] && echo guest || echo container)" "+ python3 - $a $p $sp 1 $to 0 < common/trace/syn_connect.py"
  if [ "$kind" = vm-node ]; then
    mx_guest_in "$n" "python3 - $a $p $sp 1 $to 0" <"$SFAB_COMMON/trace/syn_connect.py" >"$d/requests/$t.txt" 2>&1 || true
  else
    dk exec -i "$(ctr "$n")" python3 - "$a" "$p" "$sp" 1 "$to" 0 <"$SFAB_COMMON/trace/syn_connect.py" >"$d/requests/$t.txt" 2>&1 || true
  fi
  _evid "$n" "$([ "$kind" = vm-node ] && echo guest || echo container)" "$(cat "$d/requests/$t.txt")"
}

# mx_http DIR TAG CLIENT KIND METHOD URL SPORT KEY BODY [PIN]: one request, by name through the
# client's resolver (or, with PIN host:port:address, at that address when the client's resolver has
# no answer for the name: a cell whose view holds no record for it; a name that resolves, as under a
# break that publishes it, is asked where it resolves), from a pinned source port, with the model
# KEY's key and a body naming the model BODY (a POST); the answer's headers and body copied out,
# never a request header
mx_http() {
  local d="$1" t="$2" n="$3" kind="$4" m="$5" url="$6" sp="$7" k="$8" bm="$9" pin="${10:--}" to cmd
  to="$(mx_get timeout_s)"
  cmd="curl -sS --connect-timeout $to --max-time 120 --local-port $sp --cacert $(mx_get ca_root) -o $MX_DIR/$t-body -D $MX_DIR/$t-headers"
  [ "$pin" = - ] || cmd="if getent hosts ${pin%%:*} >/dev/null 2>&1; then p=; else p='--resolve $pin'; fi; $cmd \$p"
  cmd+=" -w '%{http_code} %{remote_ip}\\n'"
  if [ "$m" = POST ]; then
    cmd+=" -H 'Content-Type: application/json' --data @$MX_DIR/body-$bm.json"
    [ "$k" = - ] || cmd+=" -H @$MX_DIR/hdr-$k"
  fi
  cmd+=" '$url'; echo \"exit \$?\""
  mx_in "$n" "$kind" "$cmd" >"$d/requests/$t.txt" 2>&1 || true
  EVID_OFF=1 mx_in "$n" "$kind" "cat $MX_DIR/$t-headers 2>/dev/null" 2>/dev/null | tr -d '\r' >"$d/requests/$t-headers.txt" || true
  EVID_OFF=1 mx_in "$n" "$kind" "cat $MX_DIR/$t-body 2>/dev/null" >"$d/requests/$t-body.txt" 2>/dev/null || true
}

# mx_answered FILE KIND: the attempt got an answer (a connect that opened, any HTTP status)
mx_answered() {
  if [ "$2" = connect ]; then
    awk 'NF >= 6 && $5 == "CONNECTED" { found = 1 } END { exit !found }' "$1"
  else
    grep -Eq '^[1-5][0-9][0-9] ' "$1"
  fi
}

# matrix_cells DIR [CELL...]: the cells' evidence into DIR
matrix_cells() {
  local d="$1" row n kind name cell req rk c ck ca a p sp m url key mk want bm t att only=() t0 models bodies clients=() x port rtr i
  shift
  [ $# -eq 0 ] || only=(--only "$@")
  [ -f "$MX_PLAN" ] || die "matrix: no $MX_PLAN (chapter.yaml has no decisions: true, or make render)"
  mkdir -p "$d/lookups" "$d/requests" "$d/keys" "$d/fw" "$d/routers" "$d/api-gateway"
  : >"$d/requests.tsv"
  t0="$(mx_now)"
  # 1. lookups, which warm each client's path to its resolver
  while IFS=$'\t' read -r -u 3 row n kind name; do
    [ -n "$row" ] || continue
    mx_lookup "$d" "$row" "$n" "$kind" "$name"
  done 3< <(py "$MXP" lookups --plan "$MX_PLAN" "${only[@]+"${only[@]}"}")
  # 2. keys and request bodies, for every client a model cell runs from
  mapfile -t models < <(py "$MXP" requests --plan "$MX_PLAN" "${only[@]+"${only[@]}"}" | awk -F'\t' '$12 != "-" { print $4 "\t" $5 "\t" $12 "\t" ($17 == "" ? "-" : $17) }' | sort -u)
  for x in "${models[@]+"${models[@]}"}"; do
    IFS=$'\t' read -r n kind key kc <<<"$x"
    case " ${clients[*]-} " in *" $n:$kind "*) ;; *) clients+=("$n:$kind") ;; esac
    if mx_key "$n" "$kind" "$key" "${kc:--}" >>"$d/keys/$n.txt" 2>&1; then
      echo "matrix: $([ "${kc:--}" = - ] && echo "$key" || echo "$kc")'s key handed to $n ($(tail -n 1 "$d/keys/$n.txt"))"
    else
      warn "matrix: $key's key could not be handed to $n: its cells will fail"
    fi
  done
  mapfile -t bodies < <(py "$MXP" requests --plan "$MX_PLAN" "${only[@]+"${only[@]}"}" | awk -F'\t' '$15 != "-" { print $4 "\t" $5 "\t" $15 }' | sort -u)
  for x in "${bodies[@]+"${bodies[@]}"}"; do
    IFS=$'\t' read -r n kind bm <<<"$x"
    py -c 'import json, sys; print(json.dumps({"model": sys.argv[1], "max_tokens": 1, "messages": [{"role": "user", "content": "Say yes."}]}))' \
      "$bm" | mx_put "$n" "$kind" "$MX_DIR/body-$bm.json"
  done
  # 3. requests; where a cell of them is dropped by zone protection's strict IP check, which no log
  # line records, the firewall's drop counters are read around them: every counter's value
  # (show counter global filter value all) before and after, which the judge compares, and between
  # those two reads the delta view (its first read starts the sampling, the second holds what was
  # dropped since), recorded beside them. The values decide: the firewall can start a new delta
  # sampling between the two delta reads, and the view then misses what came before it.
  local sip=""
  [ -z "${FW_NODE:-}" ] || sip="$(py "$MXP" strict-ip --plan "$MX_PLAN" "${only[@]+"${only[@]}"}")"
  [ -z "$sip" ] || FW "show counter global filter value all" | fwt_body "show counter global filter value all" \
    >"$d/fw/counters-before.txt" 2>/dev/null || true
  [ -z "$sip" ] || FW "show counter global filter delta yes severity drop" >"$d/fw/drops-before.txt" 2>&1 || true
  while IFS=$'\t' read -r -u 3 cell req rk c ck ca a p sp m url key mk want bm pin kc; do
    [ -n "$cell" ] || continue
    [ "${kc:--}" = - ] || key="$kc"
    case " ${clients[*]-} " in *" $c:$ck "*) ;; *) clients+=("$c:$ck") ;; esac
    for att in 1 2; do
      t="$(mx_slug "$cell")-$req-a$att"
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$t" "$cell" "$req" "$att" "$((sp + att - 1))" "$([ "$req" = connect ] && echo connect || echo http)" >>"$d/requests.tsv"
      if [ "$req" = connect ]; then
        mx_connect "$d" "$t" "$c" "$ck" "$a" "$p" "$((sp + att - 1))"
        mx_answered "$d/requests/$t.txt" connect && break
      else
        mx_http "$d" "$t" "$c" "$ck" "$m" "$url" "$((sp + att - 1))" "$key" "$bm" "$pin"
        mx_answered "$d/requests/$t.txt" http && break
      fi
      [ "$want" = 1 ] || break
      sleep "${SFAB_RETRY_PAUSE:-2}"
    done
  done 3< <(py "$MXP" requests --plan "$MX_PLAN" "${only[@]+"${only[@]}"}")
  [ -z "$sip" ] || FW "show counter global filter delta yes severity drop" | fwt_body "show counter global filter delta yes severity drop" \
    >"$d/fw/drops.txt" 2>/dev/null || true
  [ -z "$sip" ] || FW "show counter global filter value all" | fwt_body "show counter global filter value all" \
    >"$d/fw/counters-after.txt" 2>/dev/null || true
  # 4. the evidence: the traffic log until it holds every unanswered attempt that crossed the firewall
  if [ -n "${FW_NODE:-}" ]; then
    for i in $(seq 1 "${SFAB_MATRIX_TLOG_TRIES:-9}"); do
      for port in $(py "$MXP" tlog-ports --plan "$MX_PLAN" --dir "$d" "${only[@]+"${only[@]}"}"); do
        x="show log traffic direction equal backward receive_time in last-15-minutes dport equal $port"
        FW "$x" | fwt_body "$x" >"$d/fw/traffic-log-$port.txt" 2>/dev/null || true
      done
      [ "$(py "$MXP" tlog-missing --plan "$MX_PLAN" --dir "$d" "${only[@]+"${only[@]}"}")" != 0 ] || break
      sleep "${SFAB_MATRIX_TLOG_PAUSE_S:-10}"
    done
  fi
  for rtr in $(mx_get routers); do
    FR "$rtr" "show ip route" >"$d/routers/$rtr-ip-route.txt" 2>&1 || true
  done
  # the firewall's routing table, where a cell of the plan is discarded by a route (silence)
  if [ -n "${FW_NODE:-}" ]; then
    FW "show routing route" | fwt_body "show routing route" >"$d/fw/routing-route.txt" 2>/dev/null || true
  fi
  if [ -n "${KNODE:-}" ] && [ -n "$(mx_get api_gateway.namespace)" ]; then
    K -n "$(mx_get api_gateway.namespace)" logs -l "$(mx_get api_gateway.selector)" -c apisix --prefix --tail=-1 \
      --since="$(($(mx_now) - t0 + 60))s" >"$d/api-gateway/access.txt" 2>&1 || true
  fi
  # 5. cleanup
  for x in "${clients[@]+"${clients[@]}"}"; do
    mx_clear "${x%%:*}" "${x##*:}"
  done
}

matrix_run() {
  local stamp_args=()
  [ -f "$MX_PLAN" ] || die "matrix: no $MX_PLAN (chapter.yaml has no decisions: true, or make render)"
  cp "$MX_PLAN" "$RS/matrix.json"
  sec "the matrix: $(mx_get counts.cells) cells, $(mx_get counts.allowed) allowed and $(mx_get counts.forbidden) forbidden"
  matrix_cells "$RS"
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$MXP" judge --plan "$MX_PLAN" --dir "$RS" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  summary
}
