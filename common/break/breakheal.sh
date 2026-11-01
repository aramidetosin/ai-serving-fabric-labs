#!/usr/bin/env bash
# common/break/breakheal.sh break|heal ID: the driver behind common/breakheal.py (FRAMEWORK.md 4.7).
#
# break ID   refuses when state/breaks/ID exists (a break is never applied twice); types each
#            klish action of break: in its own session (configure terminal, the context, the lines,
#            end), and when the switch answers "% Error" types the action's fallback instead,
#            recording which form the switch took; marks state/breaks/ID; runs record: (the show
#            reads, saved as the switches printed them, and each connect probe passes times, the
#            failing share of every pass printed); then judges expect_broken:.
# heal ID    types heal: (a restore replays the switch's render, the lines its running configuration
#            misses, then checks parity); clears the mark; reads record:'s show lines again and runs
#            the connect probes that expect_healed: names, once each; judges expect_healed:; then
#            runs the chapter audit (audit.sh, its own recorded set; SFAB_HEAL_AUDIT=quick for
#            audit.sh --quick, 0 for none).
# heal all   heals every break marked as applied, then restores every switch (replay plus parity).
#
# The firewall (chapter 4): a panos_api action deletes a rule, or sets the rendered rule back and
# moves it where the render places it, through common/fw/fw-api.sh; after a part's firewall
# actions one commit follows. fw_show reads the CLI and saves each line's output. probe_ping pings
# from a VM guest or a container, passes times, and when it names counters reads show counter
# global (all values, CLI and XML) before and after each pass; probe_http runs curl from a client
# through its own resolver. The checks: counter (the name first looked for in the firewall's own
# counter table, then its rise across the probe's passes), rule_order (fw-api.sh order) and
# probe_share failing all.
#
# The firewall's rule destination (chapter 1): a panos_api edit replaces one security rule's
# destination node through the XML API (the break's addresses, or the render's in the heal). probe_syn
# makes count connects from a client, each from its own pinned source port (common/trace/syn_connect.py),
# while the container ports it names are captured on the lab host, passes times; its shares are
# probe_share's. The checks: syn_at (where the probe's SYNs were seen, and where not) and tlog_rule
# (the traffic log read until it holds every connect of the probe, each under that rule with that
# action).
#
# The relay (chapter 5): a relay_route action replaces one rendered relay route inside a VM
# guest's GPU namespace (ip -n <ns> route replace), without its source pin or with it, and reads the
# route back. ns_show reads a namespace's routes and route get for the far node's addresses.
# probe_rail pings from a GPU namespace to the far node's rail address (rail: all, the same rail on
# every rail), passes times; with capture, the far node's rail NIC and relay bridge are captured in
# the guest around each pass and decoded there. The checks: route_src (the route as it runs, with
# or without the rendered source pin) and far_capture (where the far node saw the requests come
# from, and where its replies went).
#
# The serving recipe (chapter 6, common/break/lib-servebreak.sh): a pod_rail action deletes one pod of
# the placement table and makes it again on another rail (serving.py move), a pod_route action makes
# one again through a copy of its rail attachment that adds a route (serving.py reroute); a serve action runs
# serving.py serve after removing the pods it names, so every pod is where the table places it.
# k8s_show reads the serving namespace's pods, EndpointSlices, network-status annotations and Warning
# events; pod_net reads a pod's route table on its node and captures the node's rail NIC while a peer
# pod connects to it; probe_gateway sends requests through a Gateway's model route from a client, each model's key
# handed to the client from its Secret and removed after. The checks: endpoints (a Service's ready
# endpoints counted), placement (the rail a pod's network-status annotation names) and reply_path
# (where a pod's replies to the cluster network leave, from what pod_net saved). After a heal
# the serving and inference namespaces' Warning events are saved in the set and cleared, before the
# chapter audit, which expects none.
#
# The API gateway's keys (chapter 7, common/break/lib-keybreak.sh): key_hold holds one API gateway
# pod (its sidecar keeps the apisix.yaml it has), key_mint mints a key into the model keys' Secret;
# key_probe runs the per-pod probe (a pod of the key tool in the cluster) in rounds, and key_show
# reads the Secret's fields and fingerprints and every API gateway pod's sidecar log; the heal's
# gateway_restart deletes the held pod so its Deployment makes it again; the check key_pods reads
# which pods accepted the key. A break may carry cleanup: actions, run after expect_healed: is
# judged (key_revoke: the break's key revoked, so the Secret is the lab's again before the audit).
#
# A resolver view (chapter 2): a dns_answer action installs, in a copy of the view's primary's render
# inside its container, the view's forward zone rendered with some names answering another address,
# and reloads the server on that copy (sfab-dns reload, which checks every file before the server
# sees it); restore of a DNS server installs its render again and reloads it. After either, each
# secondary of the server's views is waited for until it holds the primary's serial (it takes the
# zone by transfer at the NOTIFY), and every resolver of the lab drops its cache (rndc flush on BIND,
# SIGHUP to dnsmasq), so the next lookup reads the zone as it now is. matrix_cells tries
# cells of the lab's matrix as matrix.sh tries them (common/matrix/matrix.sh), from their own source
# ports, into probes/<id>-<mode>/; the check cell_mode reads the mode a cell's evidence shows
# (common/matrix/matrix.py observe), and for a log line the rule that logged it.
#
# The result set is audits/<lab>_break-ID_<UTC>/ or audits/<lab>_heal-ID_<UTC>/; a break set judges
# the designed failure as PASS. A break is never saved on a switch (no write memory follows it), so a
# switch rebooted while broken comes back without it; a restore saves the replayed render, as
# replay.sh always does.
set -euo pipefail
MODE="${1:?break or heal}"
BID="${2:?a break id, or all}"
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init "$MODE-$BID"

BH="$SFAB_COMMON/breakheal.py"
BFILE="$RENDERDIR/gen/breaks.json"
# shellcheck source=common/trace/lib-railcap.sh
. "$SFAB_COMMON/trace/lib-railcap.sh"
# shellcheck source=common/break/lib-servebreak.sh
. "$SFAB_COMMON/break/lib-servebreak.sh"
# shellcheck source=common/break/lib-keybreak.sh
. "$SFAB_COMMON/break/lib-keybreak.sh"
# Part III (common/break/lib-k8sbreak.sh): k8s_patch changes one cluster object in place (an
# audience's announcement policy, a model route), its heal the rendered fields; k8s_read reads the
# objects behind a Gateway whole; dnsmasq_pin replaces the corporate resolver's forwarding with
# address= pins, which restore of that node puts back; probe_lookup and the check lookup_answer
# record what each stub of a client makes of one name.
# shellcheck source=common/break/lib-k8sbreak.sh
. "$SFAB_COMMON/break/lib-k8sbreak.sh"
# shellcheck source=common/matrix/matrix.sh
. "$SFAB_COMMON/matrix/matrix.sh"
MARKS="$STATEDIR/breaks"
mkdir -p "$MARKS" "$RS/record" "$RS/probes"
exec 8>"$STATEDIR/lock"
flock -n 8 || die "another run holds $STATEDIR/lock for $LAB"

jf() { py -c 'import json, sys; v = json.loads(sys.argv[1]); [v := v[k] for k in sys.argv[2].split(".")]; print("\n".join(map(str, v)) if isinstance(v, list) else ("" if v is None else v))' "$1" "$2"; }
# jg JSON KEY: one top-level value, empty when the action has no such key
jg() { py -c 'import json, sys; v = json.loads(sys.argv[1]).get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"; }
steps() { py "$BH" steps --breaks "$BFILE" --id "$1" --part "$2"; }
title_of() { py -c 'import json, sys; print(json.load(open(sys.argv[1]))["breaks"][sys.argv[2]]["title"])' "$BFILE" "$1"; }
has_error() { grep -qE '%[[:space:]]?Error' "$1"; }

# klish_action JSON TAG: the session, else its fallback
klish_action() {
  local js="$1" tag="$2" node out
  node="$(jf "$js" node)"
  out="$RS/record/$tag-$node.txt"
  mapfile -t _sess < <(jf "$js" session)
  SW "$node" "${_sess[@]}" >"$out" 2>&1 || true
  if ! has_error "$out"; then
    ok "$node: $(jf "$js" context): $(jf "$js" lines | paste -sd ';' -) accepted"
    printf '%s\t%s\n' "$node" "$(jf "$js" lines | paste -sd ';' -)" >>"$RS/taken.txt"
    return 0
  fi
  mapfile -t _fb < <(jf "$js" fallback)
  if [ ${#_fb[@]} -eq 0 ]; then
    bad "$node: $(jf "$js" lines | paste -sd ';' -)" "$(grep -m1 -E '%[[:space:]]?Error' "$out")"
    return 1
  fi
  echo "breakheal: $node answered $(grep -m1 -E '%[[:space:]]?Error' "$out"); typing the fallback"
  SW "$node" "${_fb[@]}" >"$RS/record/$tag-$node-fallback.txt" 2>&1 || true
  if has_error "$RS/record/$tag-$node-fallback.txt"; then
    bad "$node: the break's lines and its fallback" "both answered % Error (see record/$tag-$node.txt and $tag-$node-fallback.txt)"
    return 1
  fi
  ok "$node: the first form was refused ($(grep -m1 -E '%[[:space:]]?Error' "$out" | tr -s ' ')); the fallback $(jf "$js" fallback_lines | paste -sd ';' -) accepted: fix the break file to it"
  printf '%s\t%s\n' "$node" "fallback: $(jf "$js" fallback_lines | paste -sd ';' -)" >>"$RS/taken.txt"
}

show_action() {
  local js="$1" tag="$2" node l
  node="$(jf "$js" node)"
  mapfile -t _lines < <(jf "$js" lines)
  SW "$node" "${_lines[@]}" >"$RS/record/$tag-$node-session.txt" 2>&1 || true
  for l in "${_lines[@]}"; do
    klish_body "$l" <"$RS/record/$tag-$node-session.txt" >"$RS/record/$tag-$node-$(printf '%s' "$l" | tr -cs 'A-Za-z0-9' '_' | sed 's/_$//').txt" 2>/dev/null || true
  done
}

# probe_action JSON PASSES: the connect loop from a container, PASSES times; prints each pass's share
probe_action() {
  local js="$1" passes="${2:-}" node pid dst port count iv to p n f loop
  node="$(jf "$js" node)" pid="$(jf "$js" id)" dst="$(jf "$js" dst_addr)" port="$(jf "$js" port)"
  count="$(jf "$js" count)" iv="$(jf "$js" interval_s)" to="$(jf "$js" timeout_s)"
  [ -n "$passes" ] || passes="$(jf "$js" passes)"
  loop="for i in \$(seq 0 $((count - 1))); do t=\$(date +%s.%N); if timeout $to bash -c 'exec 3<>/dev/tcp/$dst/$port' 2>/dev/null; then ok=1; else ok=0; fi; echo \"\$t \$i \$ok\"; sleep $iv; done"
  for p in $(seq 1 "$passes"); do
    X "$node" bash -c "$loop" >"$RS/probes/$pid-$MODE-pass$p.log" 2>&1 || true
    read -r n f <<<"$(py "$BH" share --log "$RS/probes/$pid-$MODE-pass$p.log")"
    ok "$pid, $MODE, pass $p: $f of $n connects from $node to $dst:$port failed (recorded; the exercise names no share)"
    printf '%s %s %s\n' "$p" "$n" "$f" >>"$RS/probes/$pid-$MODE.shares"
  done
}

# fwapi ARGS: common/fw/fw-api.sh on this lab
fwapi() { "$SFAB_COMMON/fw/fw-api.sh" --lab "$RENDERDIR" "$@"; }

# panos_action JSON TAG: one firewall change through the XML API (the commit follows the part)
panos_action() {
  local js="$1" tag="$2" op rule out
  op="$(jf "$js" op)" rule="$(jf "$js" rule)"
  out="$RS/record/$tag-panos-$op-$rule.txt"
  if [ "$op" = edit ]; then
    if fwapi edit "$(jf "$js" xpath)" "$(jf "$js" element)" >"$out" 2>&1; then
      ok "fw: security rule $rule's $(jf "$js" field) set to $(jf "$js" members | paste -sd ',' -) through the XML API (the render's: $(jf "$js" rendered | paste -sd ',' -); $(tail -n 1 "$out"))"
      printf '%s\t%s\n' "$(jf "$js" node)" "edit $rule $(jf "$js" field) $(jf "$js" members | paste -sd ',' -)" >>"$RS/taken.txt"
      return 0
    fi
    bad "fw: security rule $rule's $(jf "$js" field) set to $(jf "$js" members | paste -sd ',' -)" "$(tail -n 1 "$out")"
    return 1
  fi
  if [ "$op" = del ]; then
    if fwapi del "$(jf "$js" xpath)" >"$out" 2>&1; then
      ok "fw: $(jf "$js" table) rule $rule deleted through the XML API ($(tail -n 1 "$out"))"
      return 0
    fi
    bad "fw: $(jf "$js" table) rule $rule deleted" "$(tail -n 1 "$out")"
    return 1
  fi
  fwapi set "$(jf "$js" rules_xpath)" "$(jf "$js" element)" >"$out" 2>&1 || { bad "fw: $rule set from the render" "$(tail -n 1 "$out")"; return 1; }
  if [ "$(jf "$js" place.where)" = bottom ]; then
    fwapi move "$(jf "$js" xpath)" bottom >>"$out" 2>&1 || true
  else
    fwapi move "$(jf "$js" xpath)" "$(jf "$js" place.where)" "$(jf "$js" place.dst)" >>"$out" 2>&1 || true
  fi
  ok "fw: $(jf "$js" table) rule $rule set from the render and moved $(jf "$js" place.where) $(jf "$js" place.dst) ($(tail -n 1 "$out"))"
}

# panos_commit TAG: one commit after a part's firewall actions
panos_commit() {
  if fwapi commit "sfab $MODE-$BID" >"$RS/record/$1-commit.txt" 2>&1; then
    ok "fw: committed ($(tail -n 1 "$RS/record/$1-commit.txt"))"
  else
    bad "fw: committed" "$(tail -n 1 "$RS/record/$1-commit.txt")"
    return 1
  fi
}

# fw_show_action JSON TAG: CLI reads on the firewall, each saved as <tag>-fw<N>-<line>.txt, N the
# read's place among this part's firewall reads (a part may read the same line twice: a delta view
# before and after a probe)
FWSHOW_N=0
fw_show_action() {
  local js="$1" tag="$2" l
  FWSHOW_N=$((FWSHOW_N + 1))
  mapfile -t _lines < <(jf "$js" lines)
  FW "${_lines[@]}" >"$RS/record/$tag-fw$FWSHOW_N-session.txt" 2>&1 || true
  for l in "${_lines[@]}"; do
    py "$SFAB_COMMON/audit/judge.py" body --style panos --command "$l" <"$RS/record/$tag-fw$FWSHOW_N-session.txt" \
      >"$RS/record/$tag-fw$FWSHOW_N-$(printf '%s' "$l" | tr -cs 'A-Za-z0-9' '_' | sed 's/_$//').txt" 2>/dev/null || true
  done
}

# fw_counters OUT: show counter global, all values, CLI (OUT.txt) and XML (OUT.xml)
fw_counters() {
  FW "show counter global filter value all" >"$1.session" 2>&1 || true
  py "$SFAB_COMMON/audit/judge.py" body --style panos --command "show counter global filter value all" <"$1.session" >"$1.txt" 2>/dev/null ||
    cp "$1.session" "$1.txt"
  rm -f "$1.session"
  FWX "<show><counter><global><filter><value>all</value></filter></global></counter></show>" >"$1.xml" 2>/dev/null || true
}

# ping_action JSON PASSES: pings from a guest or a container, PASSES times, the counters around each
ping_action() {
  local js="$1" passes="${2:-}" node pid kind cmd p n f c
  node="$(jf "$js" node)" pid="$(jf "$js" id)" kind="$(jf "$js" node_kind)"
  cmd="ping -c $(jf "$js" count) -i $(jf "$js" interval_s) -W $(jf "$js" timeout_s) $(jf "$js" dst_addr)"
  c="$(jf "$js" counters)"
  [ -n "$passes" ] || passes="$(jf "$js" passes)"
  for p in $(seq 1 "$passes"); do
    [ -z "$c" ] || fw_counters "$RS/probes/$pid-$MODE-pass$p-counters-before"
    if [ "$kind" = vm-node ]; then
      H "$node" "$cmd" >"$RS/probes/$pid-$MODE-pass$p.log" 2>&1 || true
    else
      # shellcheck disable=SC2086 # the command's words
      X "$node" $cmd >"$RS/probes/$pid-$MODE-pass$p.log" 2>&1 || true
    fi
    [ -z "$c" ] || fw_counters "$RS/probes/$pid-$MODE-pass$p-counters-after"
    read -r n f <<<"$(py "$BH" pingshare --log "$RS/probes/$pid-$MODE-pass$p.log")"
    ok "$pid, $MODE, pass $p: $f of $n pings from $node to $(jf "$js" dst_addr) unanswered (recorded)"
    printf '%s %s %s\n' "$p" "$n" "$f" >>"$RS/probes/$pid-$MODE.shares"
  done
  echo ping >"$RS/probes/$pid-$MODE.kind"
}

# http_action JSON PASSES: requests from a client through its own resolver, PASSES times
http_action() {
  local js="$1" passes="${2:-}" node pid url count iv to p n f loop
  node="$(jf "$js" node)" pid="$(jf "$js" id)" url="$(jf "$js" url)" count="$(jf "$js" count)"
  iv="$(jf "$js" interval_s)" to="$(jf "$js" timeout_s)"
  [ -n "$passes" ] || passes="$(jf "$js" passes)"
  loop="for i in \$(seq 0 $((count - 1))); do t=\$(date +%s.%N); c=\$(curl -s -o /dev/null -w '%{http_code}' --max-time $to '$url'); if [ \"\$c\" = 200 ]; then ok=1; else ok=0; fi; echo \"\$t \$i \$ok \$c\"; sleep $iv; done"
  for p in $(seq 1 "$passes"); do
    X "$node" bash -c "$loop" >"$RS/probes/$pid-$MODE-pass$p.log" 2>&1 || true
    read -r n f <<<"$(py "$BH" share --log "$RS/probes/$pid-$MODE-pass$p.log")"
    ok "$pid, $MODE, pass $p: $f of $n requests from $node to $url answered other than 200 (recorded)"
    printf '%s %s %s\n' "$p" "$n" "$f" >>"$RS/probes/$pid-$MODE.shares"
  done
  echo request >"$RS/probes/$pid-$MODE.kind"
}

# syn_ports JSON PASS: the first source port of a probe_syn's pass in this mode (a heal's after the
# break's, so no connect reuses a port the other mode's connects held)
syn_ports() {
  local js="$1" p="$2" n sp ps
  n="$(jf "$js" count)" sp="$(jf "$js" sport)" ps="$(jf "$js" passes)"
  [ "$MODE" = break ] || sp=$((sp + n * ps))
  printf '%s\n' "$((sp + (p - 1) * n))"
}

# syn_probe_action JSON PASSES: count connects from a client from pinned source ports, PASSES times,
# with the probe's container ports captured on the lab host around each pass
syn_probe_action() {
  local js="$1" passes="${2:-}" node pid dst port count to p sp n f cid cnode ceth caps
  node="$(jf "$js" node)" pid="$(jf "$js" id)" dst="$(jf "$js" dst_addr)" port="$(jf "$js" port)"
  count="$(jf "$js" count)" to="$(jf "$js" timeout_s)"
  [ -n "$passes" ] || passes="$(jf "$js" passes)"
  caps="$(py -c 'import json, sys; [print(c["id"], c["node"], c["eth"]) for c in json.loads(sys.argv[1])["capture"]]' "$js")"
  for p in $(seq 1 "$passes"); do
    sp="$(syn_ports "$js" "$p")"
    while read -r cid cnode ceth; do
      [ -n "$cid" ] || continue
      RAILCAP_SNAPLEN="$(jf "$js" snaplen)" railcap_host_start "$cnode" "$ceth" "$RS/probes/$pid-$MODE-pass$p-$cid.pcap" "$(jf "$js" filter)" 300
    done <<<"$caps"
    railcap_wait
    _evid "$node" container "+ python3 - $dst $port $sp $count $to 0.5 < common/trace/syn_connect.py"
    dk exec -i "$(ctr "$node")" python3 - "$dst" "$port" "$sp" "$count" "$to" 0.5 <"$SFAB_COMMON/trace/syn_connect.py" \
      >"$RS/probes/$pid-$MODE-pass$p.log" 2>&1 || true
    _evid "$node" container "$(cat "$RS/probes/$pid-$MODE-pass$p.log")"
    RAILCAP_DECODE="-nn -tt -e -v -S" railcap_stop
    read -r n f <<<"$(py "$BH" share --log "$RS/probes/$pid-$MODE-pass$p.log")"
    ok "$pid, $MODE, pass $p: $f of $n connects from $node (source ports $sp to $((sp + count - 1))) to $dst:$port failed (recorded)"
    printf '%s %s %s\n' "$p" "$n" "$f" >>"$RS/probes/$pid-$MODE.shares"
  done
  echo connect >"$RS/probes/$pid-$MODE.kind"
}

# relay_action JSON TAG: one relay route replaced in a guest's GPU namespace, then read back
relay_action() {
  local js="$1" tag="$2" node ns out
  node="$(jf "$js" node)" ns="$(jf "$js" ns)"
  out="$RS/record/$tag-$node-$ns-route-rail$(jf "$js" to_rail).txt"
  if H "$node" "$(jf "$js" command) && $(jf "$js" show)" >"$out" 2>&1; then
    ok "$node, namespace $ns: $(jf "$js" command) (reads back: $(tail -n 1 "$out" | tr -s ' '))"
    printf '%s\t%s\n' "$node" "$(jf "$js" command)" >>"$RS/taken.txt"
  else
    bad "$node, namespace $ns: $(jf "$js" command)" "$(tail -n 1 "$out")"
    return 1
  fi
}

# ns_show_action JSON TAG: a GPU namespace's reads, each saved as <tag>-<node>-<line>.txt
ns_show_action() {
  local js="$1" tag="$2" node l
  node="$(jf "$js" node)"
  mapfile -t _lines < <(jf "$js" lines)
  for l in "${_lines[@]}"; do
    H "$node" "$l" >"$RS/record/$tag-$node-$(printf '%s' "$l" | tr -cs 'A-Za-z0-9' '_' | sed 's/_$//').txt" 2>&1 || true
  done
}

# rail_rows JSON: a probe_rail's rows, one per line: id, namespace, destination address
rail_rows() { py -c 'import json, sys; [print("\t".join(str(r[k]) for k in ("id", "ns", "dst_addr"))) for r in json.loads(sys.argv[1])["rows"]]' "$1"; }

# rail_probe_action JSON PASSES: pings from a GPU namespace, PASSES times, the far node captured
# around each pass when the probe asks
rail_probe_action() {
  local js="$1" passes="${2:-}" node pid count iv to p n f id ns dst far iface cap
  node="$(jf "$js" node)" pid="$(jf "$js" id)" count="$(jf "$js" count)" iv="$(jf "$js" interval_s)" to="$(jf "$js" timeout_s)"
  [ -n "$passes" ] || passes="$(jf "$js" passes)"
  cap="$(py -c 'import json, sys; print(1 if json.loads(sys.argv[1]).get("capture") else 0)' "$js")"
  for p in $(seq 1 "$passes"); do
    if [ "$cap" = 1 ]; then
      far="$(jf "$js" capture.node)"
      for iface in $(jf "$js" capture.ifaces); do
        railcap_guest_start "$far" "$iface" "break-$pid-p$p-$iface" icmp 300 "$RS/probes/$pid-$MODE-pass$p-$iface.txt"
      done
      railcap_wait
    fi
    while IFS=$'\t' read -r id ns dst; do
      [ -n "$id" ] || continue
      H "$node" "ip netns exec $ns ping -c $count -i $iv -W $to $dst" >"$RS/probes/$pid-$MODE-pass$p-$id.log" 2>&1 || true
      read -r n f <<<"$(py "$BH" pingshare --log "$RS/probes/$pid-$MODE-pass$p-$id.log")"
      ok "$pid, $MODE, pass $p: $f of $n pings from $node (namespace $ns) to $dst unanswered (recorded)"
      printf '%s %s %s\n' "$p" "$n" "$f" >>"$RS/probes/$pid-$MODE.shares"
    done < <(rail_rows "$js")
    [ "$cap" = 0 ] || railcap_stop
  done
  echo ping >"$RS/probes/$pid-$MODE.kind"
}

# dns_answer_action JSON TAG: the view's zone as the break renders it, installed in a copy of the
# server's render in its container, and the server reloaded on that copy
dns_answer_action() {
  local js="$1" tag="$2" node dir f c
  node="$(jf "$js" node)" dir="$(jf "$js" dir)" f="$(jf "$js" file)"
  c="$(ctr "$node")"
  py -c 'import json, sys; sys.stdout.write(json.loads(sys.argv[1])["content"])' "$js" >"$RS/record/$tag-$node-$(basename "$f").txt"
  X "$node" sh -c "rm -rf $dir && mkdir -p $dir && cp -R /sfab/bootstrap/. $dir/" >"$RS/record/$tag-$node-copy.txt" 2>&1 || true
  _evid "$node" container "+ cat >$dir/$f (record/$tag-$node-$(basename "$f").txt)"
  dk exec -i "$c" sh -c "cat >$dir/$f" <"$RS/record/$tag-$node-$(basename "$f").txt" || { bad "$node: the zone written" "docker exec failed"; return 1; }
  if dns_reload "$node" "$dir" "$RS/record/$tag-$node-reload.txt"; then
    ok "$node: view $(jf "$js" view) answers $(jf "$js" names | paste -sd ' ' -) with $(jf "$js" address) ($(jf "$js" answer)), rendered $(jf "$js" rendered); BIND reloaded on the copy ($(tail -n 1 "$RS/record/$tag-$node-reload.txt"))"
  else
    bad "$node: BIND reloaded with the moved answer" "$(tail -n 2 "$RS/record/$tag-$node-reload.txt" | paste -sd ';' -)"
    return 1
  fi
  dns_converge "$node" "$tag"
}

# dns_converge NODE TAG: each secondary of NODE's views waited for until it holds NODE's serial
# (rndc zonestatus, every 2 s, 60 s at most), then every resolver's cache dropped. A zone's serial
# follows its data, so a heal can go back to a serial lower, in RFC 1982 serial arithmetic, than the
# break's: the secondary then keeps the newer serial it holds and ignores the NOTIFY, as RFC 1996
# has it. When the primary's serial is behind the secondary's after 10 s, the secondary is told to
# transfer the zone again whatever its serial (rndc retransfer), which is BIND's tool for it.
dns_converge() {
  local node="$1" tag="$2" plan v sec zone want got i r kind how
  plan="$(py - "$INV" "$node" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
dns = d.get("dns") or {}
for v, x in sorted((dns.get("views") or {}).items()):
    if x.get("server") == sys.argv[2]:
        for s in x.get("servers") or []:
            if s != sys.argv[2] and s in d["nodes"]:
                print("sec", v, s, dns.get("zone"))
for r in (dns.get("resolvers") or {}).values():
    for s in r.get("servers") or []:
        if s in d["nodes"]:
            print("res", r.get("kind"), s, "-")
PY
)"
  while read -r kind v sec zone; do
    [ -n "$kind" ] || continue
    if [ "$kind" = sec ]; then
      want="$(X "$node" rndc -k /run/named/rndc.key zonestatus "$zone" IN "$v" 2>/dev/null | sed -n 's/^serial: //p')"
      got=""
      how="taken by transfer"
      for i in $(seq 1 30); do
        got="$(EVID_OFF=1 X "$sec" rndc -k /run/named/rndc.key zonestatus "$zone" IN "$v" 2>/dev/null | sed -n 's/^serial: //p')"
        [ -z "$want" ] || [ "$got" != "$want" ] || break
        if [ "$i" = 5 ] && [ -n "$want" ] && [ -n "$got" ] && serial_behind "$want" "$got"; then
          X "$sec" rndc -k /run/named/rndc.key retransfer "$zone" IN "$v" >"$RS/record/$tag-$sec-$v-retransfer.txt" 2>&1 || true
          how="the primary's serial behind the $got it held, so taken by rndc retransfer"
        fi
        sleep 2
      done
      X "$sec" rndc -k /run/named/rndc.key zonestatus "$zone" IN "$v" >"$RS/record/$tag-$sec-$v-zonestatus.txt" 2>&1 || true
      if [ -n "$want" ] && [ "$got" = "$want" ]; then
        ok "$sec, the secondary: view $v's $zone at the primary's serial $want ($how)"
      else
        bad "$sec: view $v's $zone at $node's serial" "want ${want:-unknown}, got ${got:-none}"
      fi
    else
      case "$v" in
        bind-recursive) X "$sec" rndc -k /run/named/rndc.key flush >/dev/null 2>&1 || true ;;
        dnsmasq) X "$sec" sh -c 'kill -HUP "$(cat /run/dnsmasq.pid)"' >/dev/null 2>&1 || true ;;
      esac
    fi
  done <<<"$plan"
  echo "breakheal: the resolvers' caches dropped" >&2
}

# serial_behind A B: A is behind B in RFC 1982 serial arithmetic (32 bits)
serial_behind() {
  local d=$(( ($2 - $1) & 0xffffffff ))
  [ "$d" -gt 0 ] && [ "$d" -lt 2147483648 ]
}

# dns_reload NODE DIR OUT: sfab-dns reload of DIR on NODE, its output in OUT. dnsmasq reads its
# configuration only at start, so sfab-dns stops it and starts it again, and the new process can
# find the listening address still held ("Address in use": the resolver image's own supervisor can
# start the server again in the second between the two, met on chapter 9's lab); sfab-dns then puts
# the previous configuration back. Such a reload is tried again after 3 s, twice at most, each retry
# written into OUT with its reason; any other failure is returned at once.
dns_reload() {
  local node="$1" dir="$2" out="$3" n=1
  : >"$out"
  while :; do
    if X "$node" sfab-dns reload "$dir" >>"$out" 2>&1; then return 0; fi
    { [ "$n" -lt 3 ] && grep -q 'Address in use' "$out"; } || return 1
    n=$((n + 1))
    sleep 3
    printf '[breakheal] the reload met a listening socket still in use; reload attempt %s\n' "$n" >>"$out"
  done
}

# restore_dns NODE: the DNS server's render installed again and reloaded, the break's copy removed
restore_dns() {
  local node="$1"
  if dns_reload "$node" /sfab/bootstrap "$RS/record/restore-$node.txt"; then
    ok "$node: the rendered zones installed again and reloaded ($(tail -n 1 "$RS/record/restore-$node.txt"))"
  else
    bad "$node: the rendered zones reloaded" "$(tail -n 2 "$RS/record/restore-$node.txt" | paste -sd ';' -)"
    return 1
  fi
  X "$node" rm -rf "$DNS_BREAK_DIR" >/dev/null 2>&1 || true
  dns_converge "$node" restore
}
DNS_BREAK_DIR=/tmp/sfab-break-dns

# matrix_cells_action JSON: the cells of the lab's matrix tried as matrix.sh tries them, into
# probes/<id>-<mode>/, with each cell's mode as its evidence shows it beside them
matrix_cells_action() {
  local js="$1" pid d cells=()
  pid="$(jf "$js" id)" d="$RS/probes/$(jf "$js" id)-$MODE"
  mapfile -t cells < <(jf "$js" cells)
  mkdir -p "$d"
  matrix_cells "$d" "${cells[@]}" </dev/null
  py "$MXP" observe --plan "$MX_PLAN" --dir "$d" --only "${cells[@]}" >"$d/observed.jsonl" 2>&1 || true
  ok "$pid, $MODE: ${#cells[@]} cells of the matrix tried from their own source ports (recorded in probes/$pid-$MODE/)"
  echo cells >"$RS/probes/$pid-$MODE.kind"
}

# cell_check JSON: the mode a cell's evidence shows, against the check's
cell_check() {
  local js="$1" out
  if out="$(py "$BH" cellmode --dir "$RS/probes/$(jf "$js" probe)-$MODE" --plan "$MX_PLAN" --check "$js")"; then
    ok "$(jf "$js" cell): $out"
  else
    bad "$(jf "$js" cell): mode $(jf "$js" mode)$( [ -z "$(jg "$js" rule)" ] || echo ", $(jg "$js" rule)")" "$out"
  fi
}

# restore_switch SW: the render replayed where the running configuration misses it, then parity
restore_switch() {
  local sw="$1" rc=0 norm=()
  [ ! -f "$RENDERDIR/gen/klish-normalize.json" ] || norm=(--normalize "$RENDERDIR/gen/klish-normalize.json")
  _creds "$sw" || { bad "$sw: restored" "no login in its container"; return 1; }
  SFAB_LABDIR="$RENDERDIR" SFAB_SW_PASSWORD="$CRED_PASS" "$SFAB_COMMON/klish/replay.sh" "$sw" >"$RS/record/restore-$sw.txt" 2>&1 || rc=$?
  case "$rc" in
    0) ;;
    3) echo "breakheal: replay.sh $sw left a live MCLAG domain block alone (as it always does)" ;;
    *) bad "$sw: the render replayed" "replay.sh exited $rc ($(tail -n 2 "$RS/record/restore-$sw.txt" | paste -sd ';' -))"; return 1 ;;
  esac
  ok "$sw: the render replayed where the running configuration missed it ($(tail -n 1 "$RS/record/restore-$sw.txt"))"
  parity_check "$sw"
}

parity_check() {
  local sw="$1" rc=0 norm=()
  [ ! -f "$RENDERDIR/gen/klish-normalize.json" ] || norm=(--normalize "$RENDERDIR/gen/klish-normalize.json")
  SW "$sw" "show running-configuration" | klish_body "show running-configuration" >"$RS/record/running-$sw.txt" 2>/dev/null || true
  py "$SFAB_COMMON/klish/parity.py" "$RENDERDIR/bootstrap/$sw/startup-config.cfg" "$RS/record/running-$sw.txt" --switch "$sw" \
    "${norm[@]+"${norm[@]}"}" --json "$RS/record/parity-$sw.json" >"$RS/record/parity-$sw.txt" 2>&1 || rc=$?
  if [ "$rc" -eq 0 ]; then
    ok "$sw: parity, 0 missing lines"
  else
    bad "$sw: parity" "$(grep -E '^ +missing \(' "$RS/record/parity-$sw.txt" | head -n 2 | sed 's/^ *//' | paste -sd ';' -)"
    return 1
  fi
}

check_action() {
  local js="$1" kind node vlan port present mode out n f tot_n=0 tot_f=0 pid
  kind="$(jf "$js" kind)"
  case "$kind" in
    vlan_member)
      node="$(jf "$js" node)" vlan="$(jf "$js" vlan)" port="$(jf "$js" port)" present="$(jf "$js" present)" mode="$(jf "$js" mode)"
      SW "$node" "show vlan" | klish_body "show vlan" >"$RS/record/check-$node-show_vlan.txt" 2>/dev/null || true
      local pres=0 want
      [ "$present" = True ] && pres=1
      want="$port $( [ "$pres" = 1 ] && echo "in" || echo "not in") Vlan$vlan${mode:+ ($mode)}"
      if out="$(py "$BH" vlan --file "$RS/record/check-$node-show_vlan.txt" --vlan "$vlan" --port "$port" --present "$pres" ${mode:+--mode "$mode"})"; then
        ok "$node: show vlan has $want: $out"
      else
        bad "$node: show vlan has $want" "$out"
      fi ;;
    parity) parity_check "$(jf "$js" node)" || true ;;
    mclag_iface)
      local mpc mst mout
      node="$(jf "$js" node)" mpc="$(jf "$js" portchannel)" mst="$(jf "$js" status)"
      SW "$node" "show mclag brief" | klish_body "show mclag brief" >"$RS/record/check-$MODE-$node-show_mclag_brief.txt" 2>/dev/null || true
      if mout="$(py "$BH" mclag --file "$RS/record/check-$MODE-$node-show_mclag_brief.txt" --portchannel "$mpc" --status "$mst")"; then
        ok "$node: show mclag brief has $mpc $mst (Local/Remote): $mout"
      else
        bad "$node: show mclag brief has $mpc $mst (Local/Remote)" "$mout"
      fi ;;
    counter)
      local cname="" cout
      cname="$(jf "$js" name)" pid="$(jf "$js" probe)"
      if cout="$(py "$BH" counter --dir "$RS/probes" --probe "$pid" --mode "$MODE" --name "$cname")"; then :; fi
      case "$cout" in
        "absent "*) bad "fw: $cname in this firewall's own show counter global table" "${cout#absent }" ;;
        "rise "*)
          local rise="${cout#rise }"
          if [ "$(jf "$js" rise)" = True ]; then
            if [ "$rise" -gt 0 ]; then ok "fw: $cname rose by $rise across $pid's passes"; else bad "fw: $cname rose across $pid's passes" "it rose by $rise"; fi
          else
            if [ "$rise" -eq 0 ]; then ok "fw: $cname did not rise across $pid's passes"; else bad "fw: $cname did not rise across $pid's passes" "it rose by $rise"; fi
          fi ;;
        *) bad "fw: $cname read around $pid" "${cout:-no counters saved}" ;;
      esac ;;
    route_src)
      local rnode rns rout
      rnode="$(jf "$js" node)" rns="$(jf "$js" ns)"
      rout="$RS/record/check-$MODE-$rnode-$rns-route-rail$(jf "$js" to_rail).txt"
      H "$rnode" "$(jf "$js" command)" >"$rout" 2>&1 || true
      if [ "$(jf "$js" pinned)" = True ]; then
        if grep -qE " src $(jf "$js" src)( |$)" "$rout"; then
          ok "$rnode, namespace $rns: the route to rail $(jf "$js" to_rail) carries its rendered source pin, src $(jf "$js" src) ($(head -n 1 "$rout" | tr -s ' '))"
        else
          bad "$rnode, namespace $rns: the route to rail $(jf "$js" to_rail) carries src $(jf "$js" src)" "$(head -n 1 "$rout" | tr -s ' ')"
        fi
      elif [ -s "$rout" ] && ! grep -q " src " "$rout"; then
        ok "$rnode, namespace $rns: the route to rail $(jf "$js" to_rail) carries no source pin ($(head -n 1 "$rout" | tr -s ' '))"
      else
        bad "$rnode, namespace $rns: the route to rail $(jf "$js" to_rail) carries no source pin" "$(head -n 1 "$rout" | tr -s ' ')"
      fi ;;
    far_capture)
      local fout
      pid="$(jf "$js" probe)"
      if fout="$(py "$BH" farcap --breaks "$BFILE" --id "$BID" --dir "$RS/probes" --probe "$pid" --mode "$MODE" --src "$(jf "$js" src)")"; then
        ok "$pid: $fout"
      else
        bad "$pid: the far node's capture shows the requests from $( [ "$(jf "$js" src)" = relay ] && echo 'an address of the relay segment' || echo "the source's own rail address")" "$fout"
      fi ;;
    syn_at)
      local sout
      if sout="$(py "$BH" synat --breaks "$BFILE" --id "$BID" --dir "$RS/probes" --mode "$MODE" --check "$js")"; then
        ok "$(jf "$js" probe): $sout"
      else
        bad "$(jf "$js" probe): its SYNs where the break puts them" "$sout"
      fi ;;
    tlog_rule)
      local tout tcmd i
      pid="$(jf "$js" probe)"
      tcmd="$(py "$BH" tlogcmd --breaks "$BFILE" --id "$BID" --probe "$pid")"
      for i in $(seq 1 "${SFAB_BREAK_TLOG_TRIES:-9}"); do
        FW "$tcmd" >"$RS/record/check-$MODE-tlog-$pid-session.txt" 2>&1 || true
        py "$SFAB_COMMON/audit/judge.py" body --style panos --command "$tcmd" <"$RS/record/check-$MODE-tlog-$pid-session.txt" \
          >"$RS/record/check-$MODE-tlog-$pid.txt" 2>/dev/null || true
        if tout="$(py "$BH" tlogrule --breaks "$BFILE" --id "$BID" --dir "$RS/probes" --mode "$MODE" --file "$RS/record/check-$MODE-tlog-$pid.txt" --check "$js")"; then
          break
        fi
        case "$tout" in "missing "*) sleep "${SFAB_BREAK_TLOG_PAUSE_S:-10}" ;; *) break ;; esac
      done
      if [ "${tout%% *}" = logged ]; then
        ok "fw: the traffic log: ${tout#logged }"
      else
        bad "fw: the traffic log holds $pid's connects under $(jf "$js" rule), $(jf "$js" action)" "$tout"
      fi ;;
    endpoints|placement|mac_gone|reply_path) serve_check "$js" ;;
    key_pods) key_check "$js" ;;
    cell_mode) cell_check "$js" ;;
    lookup_answer) lookup_check "$js" ;;
    vip_arp) vip_arp_check "$js" ;;
    route_set) route_set_check "$js" ;;
    rule_order)
      if fwapi order >"$RS/record/check-order-$MODE.txt" 2>&1; then
        ok "fw: the running rulebase in the render's order ($(paste -sd ';' "$RS/record/check-order-$MODE.txt"))"
      else
        bad "fw: the running rulebase in the render's order" "$(grep -m1 differs "$RS/record/check-order-$MODE.txt" || tail -n 1 "$RS/record/check-order-$MODE.txt")"
      fi ;;
    probe_share)
      pid="$(jf "$js" probe)"
      local what=connect
      [ ! -f "$RS/probes/$pid-$MODE.kind" ] || what="$(cat "$RS/probes/$pid-$MODE.kind")"
      while read -r _ n f; do tot_n=$((tot_n + n)); tot_f=$((tot_f + f)); done <"$RS/probes/$pid-$MODE.shares"
      if [ "$(jf "$js" failing)" = all ]; then
        if [ "$tot_n" -gt 0 ] && [ "$tot_f" -eq "$tot_n" ]; then
          ok "$pid: every $what fails ($tot_f of $tot_n across the passes)"
        else
          bad "$pid: every $what fails" "$tot_f of $tot_n failed"
        fi
      elif [ "$(jf "$js" failing)" = some ]; then
        # a connect lands by the bundle's hash; a request through a Gateway by the pod its proxy picks
        local how="connects fail and some succeed, by hash"
        [ "$what" = connect ] || how="${what}s fail and some succeed"
        if [ "$tot_f" -gt 0 ] && [ "$tot_f" -lt "$tot_n" ]; then
          ok "$pid: some $how ($tot_f of $tot_n across the passes)"
        else
          bad "$pid: some $how" "$tot_f of $tot_n failed"
        fi
      else
        if [ "$tot_n" -gt 0 ] && [ "$tot_f" -eq 0 ]; then
          ok "$pid: every $what succeeds ($tot_n of $tot_n)"
        else
          bad "$pid: every $what succeeds" "$tot_f of $tot_n failed"
        fi
      fi ;;
  esac
}

# heal_fw_now ID: a firewall break whose commit failed: the heal's firewall actions, committed
heal_fw_now() {
  local kind node js
  warn "breakheal: the commit of break-$1 failed; putting the firewall back at once"
  while IFS=$'\t' read -r kind node js; do
    [ "$kind" != panos_api ] || panos_action "$js" heal || true
  done < <(steps "$1" heal)
  panos_commit heal-now || true
}

do_break() {
  local id="$1" kind node js
  [ ! -e "$MARKS/$id" ] || die "break-$id is already applied ($(head -n 1 "$MARKS/$id")); make heal-$id first"
  sec "break-$id: $(title_of "$id")"
  local fwc=0
  while IFS=$'\t' read -r kind node js; do
    case "$kind" in
      klish) klish_action "$js" break || { summary || true; exit 1; } ;;
      panos_api) panos_action "$js" break || { summary || true; exit 1; }; fwc=1 ;;
      relay_route) relay_action "$js" break || { summary || true; exit 1; } ;;
      pod_rail) pod_rail_action "$js" break || { summary || true; exit 1; } ;;
      pod_route) pod_route_action "$js" break || { summary || true; exit 1; } ;;
      key_hold) key_hold_action "$js" break || { summary || true; exit 1; } ;;
      key_mint) key_mint_action "$js" break || { summary || true; exit 1; } ;;
      dns_answer) dns_answer_action "$js" break || { summary || true; exit 1; } ;;
      dnsmasq_pin) dnsmasq_pin_action "$js" break || { summary || true; exit 1; } ;;
      k8s_patch) k8s_patch_action "$js" break || { summary || true; exit 1; } ;;
    esac
  done < <(steps "$id" break)
  if [ "$fwc" = 1 ]; then panos_commit break || { heal_fw_now "$id"; summary || true; exit 1; }; fi
  printf 'applied %s\n' "$(utc)" >"$MARKS/$id"
  cat "$RS/taken.txt" >>"$MARKS/$id" 2>/dev/null || true
  sleep "${SFAB_BREAK_SETTLE_S:-5}"
  sec "break-$id: recorded"
  while IFS=$'\t' read -r kind node js; do
    case "$kind" in
      show) show_action "$js" broken ;;
      fw_show) fw_show_action "$js" broken ;;
      probe_tcp) probe_action "$js" ;;
      probe_ping) ping_action "$js" ;;
      probe_http) http_action "$js" ;;
      probe_syn) syn_probe_action "$js" ;;
      ns_show) ns_show_action "$js" broken ;;
      probe_rail) rail_probe_action "$js" ;;
      k8s_show) k8s_show_action "$js" broken ;;
      pod_net) pod_net_action "$js" broken ;;
      probe_gateway) gateway_probe_action "$js" ;;
      key_probe) key_probe_action "$js" ;;
      key_show) key_show_action "$js" broken ;;
      matrix_cells) matrix_cells_action "$js" ;;
      k8s_read) k8s_read_action "$js" broken ;;
      probe_lookup) lookup_probe_action "$js" ;;
    esac
  done < <(steps "$id" record)
  sec "break-$id: broken as designed"
  while IFS=$'\t' read -r kind node js; do check_action "$js"; done < <(steps "$id" expect_broken)
}

do_heal() {
  local id="$1" kind node js probes
  [ -e "$MARKS/$id" ] || warn "break-$id is not marked as applied; healing anyway"
  sec "heal-$id: $(title_of "$id")"
  local fwc=0
  while IFS=$'\t' read -r kind node js; do
    case "$kind" in
      restore)
        if [ "$(jg "$js" what)" = dns ]; then restore_dns "$(jf "$js" node)" || true; else restore_switch "$(jf "$js" node)" || true; fi ;;
      klish) klish_action "$js" heal || true ;;
      panos_api) panos_action "$js" heal || true; fwc=1 ;;
      relay_route) relay_action "$js" heal || true ;;
      serve) serve_action "$js" heal || true ;;
      gateway_restart) gateway_restart_action "$js" heal || true ;;
      k8s_patch) k8s_patch_action "$js" heal || true ;;
    esac
  done < <(steps "$id" heal)
  [ "$fwc" = 0 ] || panos_commit heal || true
  rm -f "$MARKS/$id"
  sleep "${SFAB_BREAK_SETTLE_S:-5}"
  sec "heal-$id: recorded"
  probes="$(steps "$id" expect_healed | awk -F'\t' '$1 == "probe_share" || $1 == "counter" || $1 == "far_capture" || $1 == "key_pods" || $1 == "syn_at" || $1 == "tlog_rule" || $1 == "cell_mode" || $1 == "lookup_answer"' | while IFS=$'\t' read -r _ _ j; do jf "$j" probe; done | tr '\n' ' ')"
  while IFS=$'\t' read -r kind node js; do
    case "$kind" in
      show) show_action "$js" healed ;;
      fw_show) fw_show_action "$js" healed ;;
      probe_tcp) case " $probes " in *" $(jf "$js" id) "*) probe_action "$js" 1 ;; esac ;;
      probe_ping) case " $probes " in *" $(jf "$js" id) "*) ping_action "$js" 1 ;; esac ;;
      probe_http) case " $probes " in *" $(jf "$js" id) "*) http_action "$js" 1 ;; esac ;;
      probe_syn) case " $probes " in *" $(jf "$js" id) "*) syn_probe_action "$js" 1 ;; esac ;;
      ns_show) ns_show_action "$js" healed ;;
      probe_rail) case " $probes " in *" $(jf "$js" id) "*) rail_probe_action "$js" 1 ;; esac ;;
      k8s_show) k8s_show_action "$js" healed ;;
      pod_net) pod_net_action "$js" healed ;;
      probe_gateway) case " $probes " in *" $(jf "$js" id) "*) gateway_probe_action "$js" 1 ;; esac ;;
      key_probe) case " $probes " in *" $(jf "$js" id) "*) key_probe_action "$js" ;; esac ;;
      key_show) key_show_action "$js" healed ;;
      matrix_cells) case " $probes " in *" $(jf "$js" id) "*) matrix_cells_action "$js" ;; esac ;;
      k8s_read) k8s_read_action "$js" healed ;;
      probe_lookup) case " $probes " in *" $(jf "$js" id) "*) lookup_probe_action "$js" ;; esac ;;
    esac
  done < <(steps "$id" record)
  sec "heal-$id: healed"
  while IFS=$'\t' read -r kind node js; do check_action "$js"; done < <(steps "$id" expect_healed)
  if [ -n "$(steps "$id" cleanup)" ]; then
    sec "heal-$id: cleanup"
    while IFS=$'\t' read -r kind node js; do
      case "$kind" in
        key_revoke) key_revoke_action "$js" cleanup || true ;;
      esac
    done < <(steps "$id" cleanup)
  fi
  if [ "${STAGE_SERVING:-0}" = 1 ]; then
    events_archive "$RS/record/events" "$(k8s_get serving.namespace)" "$(k8s_get inference.namespace)"
  fi
}

heal_audit() {
  local out res
  case "${SFAB_HEAL_AUDIT:-full}" in
    0) return 0 ;;
    quick) out="$RS/audit-quick.txt"; "$LABDIR/audit.sh" --quick >"$out" 2>&1 || true ;;
    *) out="$RS/audit.txt"; "$LABDIR/audit.sh" >"$out" 2>&1 || true ;;
  esac
  sec "the chapter audit after the heal"
  res="$(grep -E '^== RESULT: ' "$out" | tail -n 1 || true)"
  case "$res" in
    *", 0 failed,"*) ok "audit.sh after the heal: ${res#== } ($(grep -E '^== result set: ' "$out" | tail -n 1 | sed 's/^== result set: //' || true))" ;;
    *) bad "audit.sh after the heal" "${res:-no RESULT line}" ;;
  esac
}

case "$MODE" in
  break) do_break "$BID" ;;
  heal)
    if [ "$BID" = all ]; then
      for m in "$MARKS"/*; do [ -e "$m" ] || continue; do_heal "$(basename "$m")"; done
      sec "heal-all: every switch to its render"
      for sw in "${SWITCHES[@]}"; do restore_switch "$sw" || true; done
    else
      do_heal "$BID"
    fi
    heal_audit ;;
  *) die "breakheal: mode $MODE" ;;
esac
summary
