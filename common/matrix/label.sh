# shellcheck shell=bash
# common/matrix/label.sh: chapter 2's label run (FRAMEWORK.md 4.8), sourced after lib.sh's sfab_init by
# a lab's label.sh.
#
#   label_run    for every row of gen/decisions.json (the decision table, Table 2-1), read the live
#                object behind it into the result set ($RS), then common/matrix/label.py names each
#                object with the decision label it carries and writes LABELS.md
#
# The reads, one directory a row (label.py's docstring lists the files):
#   view       each population's client looks up the users' hostname through its own resolver (dig in
#              a container, getent ahostsv4 in a VM guest), and each BIND server's zone file as it
#              serves it (sfab-dns's live copy)
#   fw         show routing route, show running nat-policy and show running security-policy in one CLI
#              session, and the running rulebase through the XML API, whose rules carry their
#              descriptions (common/fw/fw-api.sh show: no key or password is printed)
#   routing    each router's show ip route, and the configuration bound into it
#   routeset   every HTTPRoute with its audience and decision labels
#   key        the API gateway's routes ConfigMap (its consumer groups) and one API gateway pod's key
#              logs (compose's, its init container, then the sidecar's): each consumer by fingerprint
#   placement  the placement table as rendered, the serving pods with their decision label and the
#              rail attachments with their annotation
#   forwarding each switch's delivered startup file (its first lines) and its show ip route
#
# It changes nothing on any device.

LBP="$SFAB_COMMON/matrix/label.py"
LB_PLAN="${LB_PLAN:-$RENDERDIR/gen/decisions.json}"
# shellcheck source=common/trace/lib-fwtrace.sh
. "$SFAB_COMMON/trace/lib-fwtrace.sh"

lb_get() { py "$LBP" get --plan "$LB_PLAN" "$1"; }
lb_slug() { printf '%s' "$1" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9][^a-z0-9]*/-/g; s/^-//; s/-$//'; }

label_view() {
  local js pop client kind name server file
  mkdir -p "$RS/view"
  while read -r -u 3 js; do
    [ -n "$js" ] || continue
    pop="$(jq_get "$js" population)" client="$(jq_get "$js" client)" kind="$(jq_get "$js" kind)" name="$(jq_get "$js" name)"
    if [ "$kind" = vm-node ]; then
      H "$client" "getent ahostsv4 $name" >"$RS/view/$(lb_slug "$pop")-lookup.txt" 2>&1 || true
    else
      X "$client" dig "$name" >"$RS/view/$(lb_slug "$pop")-lookup.txt" 2>&1 || true
    fi
  done 3< <(lb_get plan.view.lookups)
  while read -r -u 3 js; do
    [ -n "$js" ] || continue
    server="$(jq_get "$js" server)" file="$(jq_get "$js" file)"
    X "$server" cat "/etc/sfab/dns/zones/$file" >"$RS/view/$server-$file.txt" 2>&1 || true
  done 3< <(lb_get plan.view.zones)
}

label_fw() {
  local l xp
  [ -n "${FW_NODE:-}" ] || return 0
  mkdir -p "$RS/fw"
  FW "show routing route" "show running nat-policy" "show running security-policy" >"$RS/fw/tables-session.txt" 2>&1 || true
  for l in "show routing route" "show running nat-policy" "show running security-policy"; do
    fwt_body "$l" <"$RS/fw/tables-session.txt" >"$RS/fw/$(printf '%s' "${l#show }" | tr -cs 'A-Za-z0-9' '-' | sed 's/-$//').txt" 2>/dev/null || true
  done
  xp="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase"
  _evid "$FW_NODE" xml-api "+ common/fw/fw-api.sh show $xp"
  "$SFAB_COMMON/fw/fw-api.sh" --lab "$RENDERDIR" show "$xp" >"$RS/fw/rulebase.xml" 2>&1 || true
}

label_routing() {
  local js node
  mkdir -p "$RS/routing"
  while read -r -u 3 js; do
    [ -n "$js" ] || continue
    node="$(jq_get "$js" node)"
    FR "$node" "show ip route" >"$RS/routing/$node-ip-route.txt" 2>&1 || true
    X "$node" cat "$(jq_get "$js" conf)" >"$RS/routing/$node-frr.conf" 2>&1 || true
  done 3< <(lb_get plan.routing.routers)
}

label_cluster() {
  local ns pod lab aud
  [ -n "${KNODE:-}" ] || return 0
  lab="$(lb_get plan.routeset.label)" aud="$(lb_get plan.routeset.audience_label)"
  mkdir -p "$RS/routeset" "$RS/key" "$RS/placement"
  K get httproutes -A -L "$aud" -L "$lab" >"$RS/routeset/httproutes.txt" 2>&1 || true
  EVID_OFF=1 K get httproutes -A -o json >"$RS/routeset/httproutes.json" 2>/dev/null || true
  ns="$(lb_get plan.key.namespace)"
  if [ -n "$ns" ]; then
    EVID_OFF=1 K -n "$ns" get configmap "$(lb_get plan.key.configmap)" -o json 2>/dev/null |
      py "$SFAB_COMMON/trace/walktrace.py" cmdata --key "$(lb_get plan.key.file)" >"$RS/key/api-gateway-routes.yaml" 2>/dev/null || true
    pod="$(EVID_OFF=1 K -n "$ns" get pods -l "$(lb_get plan.key.selector)" -o name 2>/dev/null | sort | head -n 1)"
    pod="${pod#pod/}"
    [ -z "$pod" ] || { K -n "$ns" logs "$pod" -c compose --tail=5; K -n "$ns" logs "$pod" -c keys --tail=5; } >"$RS/key/$pod-keys.txt" 2>&1 || true
  fi
  ns="$(lb_get plan.placement.namespace)"
  if [ -n "$ns" ]; then
    cp "$RENDERDIR/$(lb_get plan.placement.table)" "$RS/placement/serving.env"
    K -n "$ns" get pods -o wide -L "$lab" >"$RS/placement/pods.txt" 2>&1 || true
    EVID_OFF=1 K -n "$ns" get pods -o json >"$RS/placement/pods.json" 2>/dev/null || true
    EVID_OFF=1 K -n "$ns" get network-attachment-definitions -o json >"$RS/placement/nads.json" 2>/dev/null || true
  fi
}

label_forwarding() {
  local sw
  mkdir -p "$RS/forwarding"
  for sw in $(lb_get plan.forwarding.switches); do
    X "$sw" head -n 3 /config/startup-config.cfg >"$RS/forwarding/$sw-startup.txt" 2>&1 || true
    SW "$sw" "show ip route" >"$RS/forwarding/$sw-session.txt" 2>&1 || true
    klish_body "show ip route" <"$RS/forwarding/$sw-session.txt" >"$RS/forwarding/$sw-ip-route.txt" 2>/dev/null || true
  done
}

# jq_get JSON KEY: one top-level value of a JSON object (no jq on the lab host is assumed)
jq_get() { py -c 'import json, sys; v = json.loads(sys.argv[1]).get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"; }

label_run() {
  local stamp_args=()
  [ -f "$LB_PLAN" ] || die "label: no $LB_PLAN (chapter.yaml has no decisions: true, or make render)"
  cp "$LB_PLAN" "$RS/decisions.json"
  sec "the decision table: $(lb_get rows | grep -c .) rows, the live object behind each"
  label_view
  label_fw
  label_routing
  label_cluster
  label_forwarding
  [ -z "${SFAB_TICK_STAMP:-}" ] || stamp_args=(--stamp "$SFAB_TICK_STAMP")
  py "$LBP" judge --plan "$LB_PLAN" --dir "$RS" "${stamp_args[@]+"${stamp_args[@]}"}" || true
  summary
}
