# shellcheck shell=bash
# common/reads/attach.sh: one server pod's two networks (book Chapter 6, "Rail-Aware Model
# Placement"), sourced by a lab's attach.sh after sfab_init. Read-only.
#
# The pod (ATTACH_POD, default chat-c-server-0, the server of the copy that spans both GPU nodes, so
# its worker on the other node is learned across the rail switch) is a row of the placement table (the lab's
# bootstrap/k8s/serving.env): its node, rail, rail attachment, rail address and MAC. The stage reads
#   k8s/      the pod, and its network-status annotation: eth0 on the cluster network (the default)
#             and the rail attachment at the table's address and MAC
#   node/     the pod's route table, read on its node in the pod's network namespace: the default
#             route on eth0, and on the rail interface only the rail's own prefix
#   services/ the EndpointSlices of the Services that select the pod: each holds the eth0 address,
#             and no slice of the namespace holds the rail address
#   dns/      a Service's cluster DNS answer, asked by the Service's own client, a router pod (the
#             serving namespace's network policy gives a server no egress, cluster DNS included;
#             the router's image resolves with python3's resolver, its libc's), for the fully
#             qualified name with its final dot: without the dot, ndots:5 sends the name through
#             the search list first, and the lab's own domain there answered
#             kubernetes.default.svc.cluster.local.tarnwick.example with another address; the
#             answer is the Service's ClusterIP
#   switch/   the MAC table of the rail switch that carries the pod's rail: each pod of that rail
#             whose copy has a peer on the other node learned in the rail's VLAN on the port facing
#             its node, as the table places it; a pod whose peers all share its node may be absent
#             (the switch has not learned it, or has aged it out), never on another port
# Each read is saved as <dir>/<n>-<what>.txt in the shell form a reader types (the prompt line,
# then the output).

ATTACH_POD="${ATTACH_POD:-chat-c-server-0}"

# attach_pick: the pod's row, the rail switch, its port toward each GPU node and the rail's VLAN
attach_pick() {
  local out
  out="$(py - "$RENDERDIR/bootstrap/k8s/serving.env" "$INV" "$ATTACH_POD" <<'PY'
import json, shlex, sys
env = {}
for line in open(sys.argv[1]):
    if "=" in line and not line.startswith("#"):
        k, v = line.rstrip("\n").split("=", 1)
        env[k] = (shlex.split(v) or [""])[0]
inv, pod = json.load(open(sys.argv[2])), sys.argv[3]
cols = env["SERVING_POD_COLUMNS"].split()
rows = [dict(zip(cols, env[f"SERVING_POD_{i:02d}"].split())) for i in range(1, int(env["SERVING_PODS"]) + 1)]
row = next(r for r in rows if r["pod"] == pod)
rail = row["rail"]
ri = inv["nodes"][row["node"]]["rails"][rail]
sw = inv["nodes"][ri["switch"]]
vlan = sw["vlans"][sw["rails"].index(int(rail))]
print(env["SERVING_NAMESPACE"], row["node"], rail, row["nad"], row["address"].split("/")[0], row["mac"], ri["switch"], vlan)
# a pod crosses the switch when a peer of its copy (its server, or one of its workers) sits on the
# other node; a pod whose peers all share its node talks to them inside the node (macvlan bridge mode)
for r in rows:
    if r["rail"] == rail:
        peers = [x for x in rows if (x["model"], x["copy"]) == (r["model"], r["copy"]) and x["role"] != r["role"]]
        crosses = any(x["node"] != r["node"] for x in peers)
        print(r["pod"], r["node"], r["mac"], inv["nodes"][r["node"]]["rails"][rail]["switch_native"], 1 if crosses else 0)
PY
)" || return 1
  read -r ATT_NS ATT_NODE ATT_RAIL ATT_NAD ATT_ADDR ATT_MAC ATT_SW ATT_VLAN <<<"$(head -n 1 <<<"$out")"
  ATT_RAIL_PODS="$(tail -n +2 <<<"$out")"
}

# attach_save DIR NAME PROMPT CMD...: run CMD, save PROMPT then its output as DIR/NAME.txt
attach_save() {
  local dir="$1" name="$2" prompt="$3" f
  shift 3
  mkdir -p "$RS/$dir"
  f="$RS/$dir/$name.txt"
  { printf '%s\n' "$prompt"; "$@" 2>&1 || true; } >"$f"
}

attach_body() { tail -n +2 "$RS/$1.txt"; }

# attach_words ARGS...: the arguments as a reader types them, single-quoted where the shell needs it
attach_words() {
  local a out=""
  for a in "$@"; do
    if [[ "$a" =~ ^[A-Za-z0-9_./:=,@-]+$ ]]; then out+=" $a"; else out+=" '$a'"; fi
  done
  printf '%s' "${out# }"
}

# attach_k DIR NAME ARGS...: the harness's kubectl (on the init node), saved at that node's root prompt
attach_k() {
  local dir="$1" name="$2"
  shift 2
  attach_save "$dir" "$name" "root@$KNODE:~# kubectl $(attach_words "$@")" K "$@"
}

attach_run() {
  local ip ns_name svc slices s addrs n pod node mac port cip ans
  attach_pick || { bad "attach: $ATTACH_POD's row of the placement table" "cannot read bootstrap/k8s/serving.env"; summary; return; }
  printf 'pod: %s\nnamespace: %s\nnode: %s\nrail: %s (%s, Vlan%s on %s)\naddress: %s\nmac: %s\n' \
    "$ATTACH_POD" "$ATT_NS" "$ATT_NODE" "$ATT_RAIL" "$ATT_NAD" "$ATT_VLAN" "$ATT_SW" "$ATT_ADDR" "$ATT_MAC" >"$RS/FOLLOWED.txt"
  sec "$ATTACH_POD on $ATT_NODE: eth0 on the cluster network, $ATT_NAD at $ATT_ADDR on rail $ATT_RAIL"

  sec "the pod and its network-status annotation"
  attach_k k8s 1-pod -n "$ATT_NS" get pod "$ATTACH_POD" -o wide
  attach_k k8s 2-network-status -n "$ATT_NS" get pod "$ATTACH_POD" -o "jsonpath={.metadata.annotations.k8s\.v1\.cni\.cncf\.io/network-status}"
  EVID_OFF=1 K -n "$ATT_NS" get pod "$ATTACH_POD" -o json >"$RS/k8s/pod.json" 2>/dev/null || true
  read -r ip n <<<"$(py - "$RS/k8s/pod.json" "$ATT_NAD" "$ATT_ADDR" "$ATT_MAC" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
nets = json.loads(p["metadata"]["annotations"].get("k8s.v1.cni.cncf.io/network-status") or "[]")
d = [x for x in nets if x.get("default")]
r = [x for x in nets if not x.get("default")]
ok = (len(d) == 1 and d[0].get("interface") == "eth0" and d[0].get("ips") == [p["status"].get("podIP")]
      and len(r) == 1 and r[0].get("name", "").split("/")[-1] == sys.argv[2] and r[0].get("interface") == sys.argv[2]
      and r[0].get("ips") == [sys.argv[3]] and r[0].get("mac") == sys.argv[4])
print(p["status"].get("podIP") or "-", 1 if ok else 0)
PY
)" || true
  if [ "${n:-0}" = 1 ]; then
    ok "network-status: eth0 (default) at $ip, the pod's IP, and $ATT_NAD at $ATT_ADDR with MAC $ATT_MAC, as the table places it"
  else
    bad "network-status: eth0 (default) at the pod's IP, and $ATT_NAD at $ATT_ADDR with MAC $ATT_MAC" "$(attach_body k8s/2-network-status | tr -d ' \n' | cut -c 1-200)"
  fi
  [ -n "${ip:-}" ] && [ "$ip" != - ] || { bad "the pod has an address on eth0" "none"; summary; return; }

  sec "the pod's route table, on $ATT_NODE in the pod's network namespace"
  ns_name="$(H "$ATT_NODE" "for n in \$(ip netns list | awk '{print \$1}'); do ip -n \$n -4 -o addr show dev eth0 2>/dev/null | grep -q ' $ip/' && echo \$n; done" 2>/dev/null | head -n 1 || true)"
  if [ -z "$ns_name" ]; then
    bad "$ATT_NODE holds the network namespace whose eth0 is $ip" "none found"
  else
    ok "$ATT_NODE: the pod's network namespace is $ns_name (its eth0 is $ip)"
    attach_save node 1-addresses "$GUEST_USER@$ATT_NODE:~\$ sudo ip -n $ns_name -br address" H "$ATT_NODE" "ip -n $ns_name -br address"
    attach_save node 2-routes "$GUEST_USER@$ATT_NODE:~\$ sudo ip -n $ns_name route" H "$ATT_NODE" "ip -n $ns_name route"
    if attach_body node/2-routes | grep -qE '^default via [0-9.]+ dev eth0( |$)'; then
      ok "the default route leaves on eth0 ($(attach_body node/2-routes | grep '^default' | tr -s ' '))"
    else
      bad "the default route leaves on eth0" "$(attach_body node/2-routes | grep '^default' || echo none)"
    fi
    s="$(attach_body node/2-routes | grep -E " dev $ATT_NAD( |$)" || true)"
    if [ "$(grep -c . <<<"$s")" = 1 ] && grep -qE "^${ATT_ADDR%.*}\.0/24 dev $ATT_NAD proto kernel scope link src $ATT_ADDR" <<<"$s"; then
      ok "on $ATT_NAD only the rail's own prefix, no gateway ($(tr -s ' ' <<<"$s"))"
    else
      bad "on $ATT_NAD only the rail's own prefix" "$(tr '\n' ';' <<<"$s")"
    fi
  fi

  sec "the Services that select the pod: their EndpointSlices"
  attach_k services 1-endpointslices -n "$ATT_NS" get endpointslices -o wide
  EVID_OFF=1 K -n "$ATT_NS" get endpointslices -o json >"$RS/services/endpointslices.json" 2>/dev/null || true
  slices="$(py - "$RS/services/endpointslices.json" "$ATTACH_POD" "$ATT_ADDR" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
pod, rail = sys.argv[2], sys.argv[3]
for sl in d.get("items") or []:
    eps = sl.get("endpoints") or []
    mine = [a for e in eps if (e.get("targetRef") or {}).get("name") == pod for a in e.get("addresses") or []]
    every = [a for e in eps for a in e.get("addresses") or []]
    if mine or rail in every:
        print(sl["metadata"]["labels"].get("kubernetes.io/service-name", "?"), sl["metadata"]["name"], ",".join(mine) or "-",
              "rail" if rail in every else "-")
PY
)" || true
  if [ -z "$slices" ]; then
    bad "an EndpointSlice holds $ATTACH_POD" "none"
  fi
  n=1
  while read -r svc s addrs ans; do
    [ -n "$svc" ] || continue
    n=$((n + 1))
    attach_k services "$n-$svc" -n "$ATT_NS" get endpointslice "$s" -o wide
    if [ "$addrs" = "$ip" ] && [ "$ans" = - ]; then
      ok "Service $svc ($s): $ATTACH_POD at $ip, its eth0 address, and not $ATT_ADDR"
    else
      bad "Service $svc ($s): $ATTACH_POD at $ip only" "$addrs$( [ "$ans" = - ] || echo ", and $ATT_ADDR")"
    fi
  done <<<"$slices"

  sec "a Service's cluster DNS answer, from the Service's client"
  svc="$(head -n 1 <<<"$slices" | awk '{print $1}')"
  local rns rsel rpod
  read -r rns rsel <<<"$(py -c 'import json, sys
try:
    r = json.load(open(sys.argv[1])).get("router") or {}
except (OSError, ValueError):
    r = {}
print(r.get("namespace") or "inference", r.get("selector") or "app.kubernetes.io/name=router")' "$RENDERDIR/gen/trace.json")"
  rpod="$(EVID_OFF=1 K -n "$rns" get pods -l "$rsel" --field-selector status.phase=Running -o 'jsonpath={.items[0].metadata.name}' 2>/dev/null || true)"
  if [ -n "$svc" ] && [ -n "$rpod" ]; then
    attach_k dns 1-service -n "$ATT_NS" get service "$svc" -o wide
    cip="$(EVID_OFF=1 K -n "$ATT_NS" get service "$svc" -o 'jsonpath={.spec.clusterIP}' 2>/dev/null || true)"
    attach_k dns 2-resolve -n "$rns" exec "$rpod" -- python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$svc.$ATT_NS.svc.cluster.local."
    ans="$(attach_body dns/2-resolve | awk 'NR == 1 { print $1 }')"
    if [ -n "$cip" ] && [ "$ans" = "$cip" ]; then
      ok "$svc.$ATT_NS.svc.cluster.local answers $ans in the router pod $rpod, the Service's ClusterIP (not a pod address)"
    else
      bad "$svc.$ATT_NS.svc.cluster.local answers the Service's ClusterIP ${cip:-?}" "${ans:-no answer}"
    fi
  elif [ -z "$svc" ]; then
    skip "a Service's cluster DNS answer" "no Service selects the pod"
  else
    bad "a Service's cluster DNS answer from a router pod" "no Running pod $rsel in $rns"
  fi

  sec "$ATT_SW: the rail $ATT_RAIL pods' MACs in Vlan$ATT_VLAN"
  mkdir -p "$RS/switch"
  { printf '%s# show mac address-table\n' "$ATT_SW"; SW "$ATT_SW" "show mac address-table" | klish_body "show mac address-table" 2>&1 || true; } \
    >"$RS/switch/1-mac-table.txt"
  while read -r pod node mac port crosses; do
    [ -n "$pod" ] || continue
    if attach_body switch/1-mac-table | grep -qiE "^[[:space:]]*$ATT_VLAN[[:space:]]+$mac[[:space:]].*[[:space:]]$port[[:space:]]*$"; then
      ok "$ATT_SW learned $pod's $mac in Vlan$ATT_VLAN on $port, the port facing $node"
    elif [ "$crosses" = 0 ] && ! attach_body switch/1-mac-table | grep -qi "$mac"; then
      skip "$ATT_SW learned $pod's $mac" "absent: its copy's peers all sit on $node, so its traffic stays inside the node"
    else
      bad "$ATT_SW learned $pod's $mac in Vlan$ATT_VLAN on $port, the port facing $node" \
        "$(attach_body switch/1-mac-table | grep -i "$mac" | tr -s ' ' | head -n 1 || true)"
    fi
  done <<<"$ATT_RAIL_PODS"
  summary
}
