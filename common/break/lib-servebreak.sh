# shellcheck shell=bash
# common/break/lib-servebreak.sh: the serving recipe's break actions and checks (chapter 6), sourced
# by breakheal.sh after lib.sh's sfab_init. Each takes its action as JSON (gen/breaks.json):
#
#   pod_rail_action JSON TAG   one pod of the table deleted and made again by the recipe on another
#                              rail (serving.py move: its networks annotation, bind address and probe
#                              on the new rail, at the address the plan names, with a rail attachment
#                              for it when the table uses none; its labels still the table's)
#   pod_route_action JSON TAG  one pod of the table deleted and made again at its own address and
#                              MAC through a copy of its rail attachment whose static IPAM adds a
#                              route to the pod network via an on-link rail address (serving.py
#                              reroute); serve puts it back and removes the copy
#   serve_action JSON TAG      the named pods removed, then serving.py serve: every pod where the
#                              table places it (a pod whose rendered stamp differs replaced, an
#                              attachment the table does not use removed), read back
#   k8s_show_action JSON TAG   the namespace's pods (wide and JSON), the Services' EndpointSlices, every
#                              pod's network-status annotation and the Warning events, saved
#   pod_net_action JSON TAG    the pod's addresses and route table, read on its node in the network
#                              namespace whose eth0 holds the pod's IP, and the node's rail NIC
#                              captured while a router pod opens a connection to the pod's HTTP
#                              port (python3 in the router's image; the network policy admits the
#                              router alone to a server)
#   gateway_probe_action JSON PASSES
#                              the gateway probe from a client (probe_gateway.py), count requests a
#                              model through a Gateway's model route with each model's key (its
#                              first, or the key the action names: chapter 7), PASSES times; each
#                              pass's failing share recorded for probe_share
#   serve_check JSON           the checks: endpoints (a Service's ready endpoints counted),
#                              placement (the rail a pod's network-status annotation names) and
#                              mac_gone (the rail switch no longer holds the MAC the moved pod had on
#                              its wrong rail: show mac address-table read every 30 s until it ages
#                              out, wait_s at most) and reply_path (what pod_net saved: the route
#                              and the pod's replies on the rail, or neither and the copy gone)
#
# The keys reach the client through lib-servecap.sh key_to_client and leave it after each probe.

SB_DIR=/tmp/sfab-break-probe
# shellcheck source=common/trace/lib-servecap.sh
. "$SFAB_COMMON/trace/lib-servecap.sh"

sb_env() { printf '%s\n' "$RENDERDIR/bootstrap/k8s/serving.env"; }
sb_recipe() { py "$SFAB_ROOT/serving-layer/serving.py" "$@"; }

pod_rail_action() {
  local js="$1" tag="$2" pod rail addr master out
  pod="$(jf "$js" pod)" rail="$(jf "$js" moved.rail)" addr="$(jf "$js" moved.address)" master="$(jf "$js" moved.master)"
  out="$RS/record/$tag-move-$pod.txt"
  if sb_recipe move --env "$(sb_env)" --pod "$pod" --rail "$rail" --address "$addr" --master "$master" --mac "$(jf "$js" moved.mac)" >"$out" 2>&1; then
    ok "$pod deleted and made again on rail $rail at $addr ($(jf "$js" row.nad) $(jf "$js" row.address) in the table)$( [ "$(jf "$js" new_nad)" = True ] && echo ", with a rail$rail attachment the table does not use")"
    printf '%s\t%s\n' "$pod" "moved to rail $rail at $addr" >>"$RS/taken.txt"
  else
    bad "$pod made again on rail $rail at $addr" "$(grep -E '^  FAIL  |serving.py:' "$out" | tail -n 1)"
    return 1
  fi
}

pod_route_action() {
  local js="$1" tag="$2" pod nad out
  pod="$(jf "$js" pod)" nad="$(jf "$js" nad)"
  out="$RS/record/$tag-reroute-$pod.txt"
  if sb_recipe reroute --env "$(sb_env)" --pod "$pod" --nad "$nad" --dst "$(jf "$js" dst)" --via "$(jf "$js" via)" >"$out" 2>&1; then
    ok "$pod deleted and made again at $(jf "$js" row.address) through $nad, a copy of $(jf "$js" row.nad) with a route to $(jf "$js" dst) via $(jf "$js" via) ($(grep -E '^  PASS  .*Ready' "$out" | tail -n 1 | sed 's/^  PASS  //'))"
    printf '%s\t%s\n' "$pod" "rerouted through $nad" >>"$RS/taken.txt"
  else
    bad "$pod made again through $nad" "$(grep -E '^  FAIL  |serving.py:' "$out" | tail -n 1)"
    return 1
  fi
}

# sb_pod_netns NODE IP: the network namespace on NODE whose eth0 holds IP
sb_pod_netns() {
  H "$1" "for n in \$(ip netns list | awk '{print \$1}'); do ip -n \$n -4 -o addr show dev eth0 2>/dev/null | grep -q ' $2/' && echo \$n; done" 2>/dev/null | head -n 1 || true
}

pod_net_action() {
  local js="$1" tag="$2" ns pod peer pns node iface ip pip nsn cap t pfx port
  ns="$(jf "$js" namespace)" pod="$(jf "$js" pod)" node="$(jf "$js" node)" iface="$(jf "$js" iface)" t="$(jf "$js" capture_s)"
  pns="$(jf "$js" peer.namespace)" port="$(jf "$js" port)"
  pfx="$RS/record/$tag-$pod"
  ip="$(EVID_OFF=1 K -n "$ns" get pod "$pod" -o 'jsonpath={.status.podIP}' 2>/dev/null || true)"
  peer="$(EVID_OFF=1 K -n "$pns" get pods -l "$(jf "$js" peer.selector)" --field-selector=status.phase=Running -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true)"
  pip="$(EVID_OFF=1 K -n "$pns" get pod "$peer" -o 'jsonpath={.status.podIP}' 2>/dev/null || true)"
  printf '%s\n' "$ip" >"$pfx-ip.txt"
  nsn="$(sb_pod_netns "$node" "$ip")"
  if [ -n "$ip" ] && [ -n "$nsn" ]; then
    { printf '%s@%s:~$ sudo ip -n %s -br address\n' "$GUEST_USER" "$node" "$nsn"; H "$node" "ip -n $nsn -br address" 2>&1 || true; } >"$pfx-addresses.txt"
    { printf '%s@%s:~$ sudo ip -n %s route\n' "$GUEST_USER" "$node" "$nsn"; H "$node" "ip -n $nsn route" 2>&1 || true; } >"$pfx-routes.txt"
  else
    printf 'no network namespace on %s holds %s on eth0\n' "$node" "${ip:-the pod IP}" >"$pfx-routes.txt"
  fi
  cap="/tmp/sfab-break-$pod.pcap"
  H "$node" "rm -f $cap" >/dev/null 2>&1 || true
  HBG "$node" "timeout $t tcpdump -ni $iface -U -c 50 -w $cap 'ip and src host $ip and dst host ${pip:-0.0.0.0}'" >/dev/null 2>&1 || true
  sleep 2
  local py_conn="import socket,sys; socket.create_connection((sys.argv[1], int(sys.argv[2])), 5); print('connected')"
  { printf 'root@%s:~# kubectl -n %s exec %s -- python3 -c "%s" %s %s\n' "$KNODE" "$pns" "$peer" "$py_conn" "$ip" "$port"
    K -n "$pns" exec "$peer" -- python3 -c "$py_conn" "$ip" "$port" 2>&1 | tail -n 1 || echo "exit $?"; } >"$pfx-connect.txt"
  sleep "$t"
  { printf '%s@%s:~$ sudo tcpdump -nr %s\n' "$GUEST_USER" "$node" "$cap"; H "$node" "tcpdump -nr $cap 2>/dev/null; rm -f $cap" 2>&1 || true; } >"$pfx-$iface.txt"
  ok "$pod ($ip, on $node): route table read, and $iface captured while the router pod $peer ($pip) connected to port $port: $(tail -n +2 "$pfx-connect.txt" | tail -n 1), $(tail -n +2 "$pfx-$iface.txt" | grep -c " IP $ip\." || true) packet(s) from $ip on $iface (recorded)"
}

serve_action() {
  local js="$1" tag="$2" rep=() p out
  for p in $(jf "$js" replace); do rep+=(--replace "$p"); done
  out="$RS/record/$tag-serve.txt"
  if sb_recipe serve --env "$(sb_env)" "${rep[@]+"${rep[@]}"}" >"$out" 2>&1; then
    ok "make serve: every pod where the table places it$( [ ${#rep[@]} -eq 0 ] || echo ", $(jf "$js" replace | paste -sd ',' -) removed first and made again") ($(grep -E '^== RESULT: ' "$out" | tail -n 1 | sed 's/^== //'))"
  else
    bad "make serve: every pod where the table places it" "$(grep -E '^  FAIL  |^== RESULT: |serving.py:' "$out" | tail -n 1)"
    return 1
  fi
}

k8s_show_action() {
  local js="$1" tag="$2" ns
  ns="$(jf "$js" namespace)"
  K -n "$ns" get pods -o wide >"$RS/record/$tag-pods.txt" 2>&1 || true
  EVID_OFF=1 K -n "$ns" get pods -o json >"$RS/record/$tag-pods.json" 2>/dev/null || true
  K -n "$ns" get endpointslices -o wide >"$RS/record/$tag-endpointslices.txt" 2>&1 || true
  EVID_OFF=1 K -n "$ns" get endpointslices -o json >"$RS/record/$tag-endpointslices.json" 2>/dev/null || true
  py "$BH" netstatus --file "$RS/record/$tag-pods.json" >"$RS/record/$tag-network-status.txt" 2>&1 || true
  K -n "$ns" get events --field-selector type=Warning --sort-by=.lastTimestamp >"$RS/record/$tag-events.txt" 2>&1 || true
}

# gateway_probe_action JSON PASSES: count requests a model through the Gateway's model route
gateway_probe_action() {
  local js="$1" passes="${2:-}" client pid iv to mt count p n f m mu me targets=() pin=()
  client="$(jf "$js" client)" pid="$(jf "$js" id)" iv="$(jf "$js" interval_s)" to="$(jf "$js" timeout_s)"
  mt="$(jf "$js" max_tokens)" count="$(jf "$js" count)"
  [ -n "$passes" ] || passes="$(jf "$js" passes)"
  [ -z "$(jf "$js" resolve)" ] || pin=(--resolve "$(jf "$js" resolve)")
  : >"$RS/probes/$pid-$MODE-keys.txt"
  while read -r m mu me; do
    [ -n "$m" ] || continue
    key_to_client "$(jf "$js" keys.namespace)" "$(jf "$js" keys.secret)" "$m" "$client" "$SB_DIR" "$(jf "$js" key)" \
      >>"$RS/probes/$pid-$MODE-keys.txt" 2>&1 && { targets+=(--target "$m" "$mu"); [ "${me:-1}" = 1 ] || targets+=(--every "$m" "$me"); }
  done < <(py -c 'import json, sys; [print(m["model"], m["url"], m.get("every", 1)) for m in json.loads(sys.argv[1])["models"]]' "$js")
  dk exec -i "$(ctr "$client")" sh -c "umask 077; cat >$SB_DIR/probe_gateway.py" <"$SFAB_COMMON/drill/probe_gateway.py"
  for p in $(seq 1 "$passes"); do
    X "$client" sh -c "rm -f $SB_DIR/records-*.jsonl; python3 $SB_DIR/probe_gateway.py --dir $SB_DIR $(printf '%q ' "${targets[@]}") --interval $iv --timeout $to --max-tokens $mt --count $count $(qargs "${pin[@]+"${pin[@]}"}")" \
      >"$RS/probes/$pid-$MODE-pass$p.txt" 2>&1 || true
    n=0 f=0
    for m in $(py -c 'import json, sys; print(" ".join(m["model"] for m in json.loads(sys.argv[1])["models"]))' "$js"); do
      dk exec "$(ctr "$client")" cat "$SB_DIR/records-$m.jsonl" >"$RS/probes/$pid-$MODE-pass$p-$m.jsonl" 2>/dev/null || true
      read -r a b <<<"$(py "$BH" gwshare --file "$RS/probes/$pid-$MODE-pass$p-$m.jsonl" 2>/dev/null || echo "0 0")"
      n=$((n + a)) f=$((f + b))
    done
    ok "$pid, $MODE, pass $p: $f of $n requests through $(jf "$js" gateway) to $(py -c 'import json, sys; print(", ".join(m["model"] for m in json.loads(sys.argv[1])["models"]))' "$js") failed (recorded)"
    printf '%s %s %s\n' "$p" "$n" "$f" >>"$RS/probes/$pid-$MODE.shares"
  done
  echo request >"$RS/probes/$pid-$MODE.kind"
  key_clear "$client" "$SB_DIR"
}

serve_check() {
  local js="$1" kind ns out
  kind="$(jf "$js" kind)"
  case "$kind" in
    endpoints)
      local svc want got ips
      ns="$(jf "$js" namespace)" svc="$(jf "$js" service)" want="$(jf "$js" ready)"
      out="$RS/record/check-$MODE-endpoints-$svc.json"
      EVID_OFF=1 K -n "$ns" get endpointslices -l "kubernetes.io/service-name=$svc" -o json >"$out" 2>/dev/null || true
      ips="$(py "$BH" epready --file "$out")"
      got=0
      [ -z "$ips" ] || [ "$ips" = unreadable ] || got="$(wc -w <<<"$ips" | tr -d ' ')"
      if [ "$ips" != unreadable ] && [ "$got" = "$want" ]; then
        ok "Service $svc holds $want ready endpoint(s)${ips:+ ($ips)} of its servers $(jf "$js" servers | paste -sd ',' -)"
      else
        bad "Service $svc holds $want ready endpoint(s)" "${ips:-none} ($got)"
      fi ;;
    placement)
      local pod rail got
      ns="$(jf "$js" namespace)" pod="$(jf "$js" pod)" rail="$(jf "$js" rail)"
      out="$RS/record/check-$MODE-placement-$pod.json"
      EVID_OFF=1 K -n "$ns" get pod "$pod" -o json >"$out" 2>/dev/null || true
      got="$(py "$BH" netstatus --file "$out")"
      if py "$BH" netstatus --file "$out" --rail "$rail" >/dev/null; then
        if [ "$(jf "$js" matches_table)" = True ]; then
          ok "$pod's network-status names rail $rail, as the table places it ($got)"
        else
          ok "$pod's network-status names rail $rail, while the table places it on rail $(jf "$js" table_rail) ($got)"
        fi
      else
        bad "$pod's network-status names rail $rail" "$got"
      fi ;;
    reply_path)
      local pod node iface nad dst via ip r n on
      ns="$(jf "$js" namespace)" pod="$(jf "$js" pod)" iface="$(jf "$js" iface)" nad="$(jf "$js" nad)" dst="$(jf "$js" dst)" via="$(jf "$js" via)"
      local t=healed
      [ "$MODE" != break ] || t=broken
      on="$(jf "$js" leaves)" ip="$(cat "$RS/record/$t-$pod-ip.txt" 2>/dev/null || true)"
      r="$(tail -n +2 "$RS/record/$t-$pod-routes.txt" 2>/dev/null | grep -E "^$dst via $via dev $iface( |$)" || true)"
      n="$(tail -n +2 "$RS/record/$t-$pod-$iface.txt" 2>/dev/null | grep -c " IP ${ip:-none}\." || true)"
      if [ "$on" = rail ]; then
        if [ -n "$r" ]; then ok "$pod's route table holds $(tr -s ' ' <<<"$r")"; else bad "$pod's route table holds $dst via $via dev $iface" "no such route"; fi
        if [ "${n:-0}" -gt 0 ]; then
          ok "$pod's replies to the cluster network leave on the rail: $n packet(s) from its eth0 address $ip captured on $iface"
        else
          bad "$pod's replies leave on the rail" "no packet from ${ip:-its eth0 address} on $iface"
        fi
      else
        if [ -z "$r" ] && grep -q ' dev eth0' "$RS/record/$t-$pod-routes.txt" 2>/dev/null; then
          ok "$pod's route table holds no route to $dst via $via: the cluster network is on eth0 again"
        else
          bad "$pod's route table holds no route to $dst via $via" "${r:-route table unread}"
        fi
        if [ -f "$RS/record/$t-$pod-$iface.txt" ] && [ "${n:-0}" = 0 ]; then
          ok "no packet from $pod's eth0 address $ip on $iface while its peer connected"
        else
          bad "no packet from $pod's eth0 address on $iface" "${n:-capture unread}"
        fi
        if EVID_OFF=1 K -n "$ns" get network-attachment-definitions "$nad" >/dev/null 2>&1; then
          bad "the attachment $nad is gone" "it is still there"
        else
          ok "the attachment $nad is gone"
        fi
      fi ;;
    mac_gone)
      local sw mac native vlan waited=0 t0 seen
      sw="$(jf "$js" switch)" mac="$(jf "$js" mac)" native="$(jf "$js" native)" vlan="$(jf "$js" vlan)"
      t0="$SECONDS"
      while :; do
        SW "$sw" "show mac address-table" | klish_body "show mac address-table" >"$RS/record/check-$MODE-mac-$sw.txt" 2>/dev/null || true
        seen="$(grep -ciE "^[[:space:]]*${vlan}[[:space:]]+${mac}[[:space:]]" "$RS/record/check-$MODE-mac-$sw.txt" || true)"
        waited=$((SECONDS - t0))
        [ "$seen" != 0 ] || break
        [ "$waited" -lt "$(jf "$js" wait_s)" ] || break
        sleep "${SFAB_MAC_POLL_S:-30}"
      done
      if [ "$seen" = 0 ]; then
        ok "$sw no longer holds $mac (the moved $(jf "$js" pod)'s MAC on Vlan$vlan, $native): gone ${waited} s into the check, the MAC table's own aging"
      else
        bad "$sw no longer holds $mac on Vlan$vlan" "still there after ${waited} s"
      fi ;;
  esac
}
