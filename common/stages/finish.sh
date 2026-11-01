#!/usr/bin/env bash
# finish.sh: the cluster and its workloads, gated by the inventory's features (FRAMEWORK.md 3.4).
#
# With k8s on (stages.cluster), in order:
#   cluster   sfab-cluster.service on the init node finished in this boot with status 0: inactive
#             (or active and exited, for a unit that remains after exit), ExecMainStatus=0 and an
#             exit timestamp since this boot (timeouts.cluster_polls x cluster_poll_s). Every fifth
#             poll prints the unit's last journal line.
#   ready     every Kubernetes node of the inventory Ready, by name.
#   retract   every control node has joined, so the private keys kubeadm's control nodes take from
#             state/shared leave it: sfab-ca retract on the lab host removes the Kubernetes
#             intermediate's key (sfab-ca init in up puts it back) and the control-plane keys the
#             init node shares (its bootstrap publishes them again at its next run). Then no file
#             under state/shared holds a PEM private key.
#   cilium    Cilium's devices: the running cilium-config's set against the spec's
#             (k8s.cilium_devices); a different set is fixed with helm upgrade --reuse-values from
#             the registry's chart, then the DaemonSet is rolled. Agents read cilium-config only at
#             start, so an agent older than the ConfigMap's last change is drift too, fixed by a roll.
#   apply     bootstrap/k8s/apply.list, each file applied with the harness's kubectl (on the init
#             node, the admin kubeconfig kubeadm wrote there; bootstrap/k8s copied in first) with
#             kubectl apply --server-side. A file whose kinds are not served yet (their CRDs come
#             with a chart) is set aside for apply-late.
#   ca-secrets  bootstrap/k8s/ca-secrets.list, "<intermediate> <namespace>/<secret>" per line:
#             sfab-ca k8s-secret on the lab host writes that intermediate's key pair as the Secret
#             cert-manager's CA issuer reads (the key goes from the lab host's state/ca to the API
#             server through a pipe and is never printed). After apply, so the namespaces exist.
#   idp-secret  with the identity provider (gen/k8s.json identity): its Secret of client secrets
#             and password hashes, from the lab host through a pipe (common/bin/idp-secret.py), then
#             its Deployment rolled out (restarted first when the Secret changed).
#   operators each operator user of the inventory's k8s.operators: a kubeconfig whose client
#             certificate kubeadm issues on the init node (kubeadm kubeconfig user, the cluster CA,
#             validity_h hours, the operators' group, which 07-operators.yaml binds to its
#             ClusterRole), written on the lab host to state/operators/<user>/kubeconfig (0600),
#             where the bastion picks it up for that user. Issued again at every run.
#   charts    bootstrap/k8s/charts.list rows of phase k8s: helm upgrade --install from the in-lab
#             registry's OCI charts, --wait.
#   apply-late  the files apply set aside, now that the charts are in (10 tries, 15 s apart, which
#             also outlasts a webhook that is not serving yet).
# With storage_setup on:
#   storage   build A: common/storage/truenas-setup.py all --node <truenas>; then the pair with
#             every PortChannel, the storage bonds included, in two consecutive polls (the setup
#             makes TrueNAS's data bond, so boot cannot wait for it); then the charts.list rows of
#             phase storage (democratic-csi, whose config Secrets the setup writes);
#             build B: common/storage/ontap-setup.sh <node>.
# With serving on:
#   serving   make -C serving-layer serve with bootstrap/k8s/serving.env.
#   inference the API gateway and the model router (render/inference.py), after the recipe, whose
#             key the router reads: 60-inference-base.yaml applied (the namespace and the key Job's
#             roles); the key Job (61-inference-keys.yaml) run once and removed, its log (each key by
#             its fingerprint only) printed; 62-inference.yaml applied (the API gateway, the router,
#             their Services and the model routes); the router restarted when the Job updated its
#             backend key; then each Deployment rolled out; then, with k8s.network_policy, the
#             policies of the API gateway's and the recipe's namespaces (63-inference-policy.yaml).
#             Nothing prints a key.
# With k8s on, last:
#   settle    frontend: in each round every Kubernetes node pings six peers (offsets 1, 5, 11, 17,
#             23, 29 plus the round number) and each storage data address, connects to every
#             Gateway VIP on TCP 443, and each population's client connects to its answer address
#             on TCP 443 (VIPs answer TCP, never ICMP); 3 clean rounds, at most 40; after 2 bad rounds
#             in a row the node named most often has its bond legs bounced, guest side, at most 4
#             nodes. Rails (GPU nodes with the relay): 2 clean rounds, at most 10, stopping early
#             when the same rails lose twice.
#   events    a health gate (every node Ready, every pod Running or Succeeded), then the Warning
#             events are archived to state/logs/, deleted, and held at 0 for timeouts.events_quiet_s;
#             a new one starts the round again, three rounds at most.
# Always, last: the lab's audit.sh --quick.
#
# charts.list, one release per line ('#' starts a comment):
#   <release> <namespace> <chart> <version> <values file under bootstrap/k8s/, or -> [<phase>]
# <chart> is a full reference (oci://<mirror>/charts/cilium) or a bare chart name, which becomes
# oci://<registry mirror>/<registry charts path>/<name>. phase is k8s (the default) or storage. An
# oci:// chart gets --plain-http when the inventory's registry scheme is http, and --ca-file with the
# lab root (the init node's /shared/ca/root.crt) when it is https.
#
# A step whose inputs are not rendered yet (apply.list, charts.list, a missing tool) prints SKIP and
# writes no marker. A lab with every feature off (M1) runs only the quick audit.
# shellcheck disable=SC2317 # every step function runs through stage_step
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init finish "$@"

RUNDIR="$STATEDIR/run/finish"
mkdir -p "$RUNDIR"
K8S_DIR="$RENDERDIR/bootstrap/k8s"
# where bootstrap/k8s is copied on the init node, which the harness's kubectl and helm read from
INKNODE=/tmp/sfab-k8s
REGISTRY_CA=/shared/ca/root.crt
SFAB_CA="$SFAB_COMMON/ca/sfab-ca"

k8s_nodes() { local g; for g in "${GUESTS[@]+"${GUESTS[@]}"}"; do [ -z "${NODE_K8S[$g]:-}" ] || printf '%s\n' "$g"; done; }
init_node() { local g; for g in "${GUESTS[@]+"${GUESTS[@]}"}"; do [ "${NODE_K8S[$g]:-}" = init ] && { printf '%s\n' "$g"; return 0; }; done; return 1; }
# ijson PATH: an inventory value as JSON, or null when the inventory does not have it
ijson() { inv json "$1" 2>/dev/null || echo null; }

# --- the cluster bootstrap and the nodes -----------------------------------------------------------

cluster_wait() {
  local init out i last="" line rc
  sec "cluster bootstrap"
  init="$(init_node)" || { bad "init node" "no guest has k8s: init"; return 1; }
  for i in $(seq 1 "${TO_CLUSTER_POLLS:-240}"); do
    out="$(EVID_OFF=1 H "$init" "systemctl show -p ActiveState -p SubState -p ExecMainStatus -p ExecMainExitTimestampMonotonic -p NRestarts sfab-cluster.service" 2>/dev/null || true)"
    rc=0
    py - "$out" <<'PY' || rc=$?
import sys
kv = dict(l.split("=", 1) for l in sys.argv[1].splitlines() if "=" in l)
state, sub = kv.get("ActiveState"), kv.get("SubState")
finished = state == "inactive" or (state == "active" and sub == "exited")
ok = finished and kv.get("ExecMainStatus") == "0" and kv.get("ExecMainExitTimestampMonotonic", "0") not in ("", "0")
# failed is final: the unit restarts on failure until its start limit, then stays failed
sys.exit(0 if ok else 2 if state == "failed" else 1)
PY
    if [ "$rc" -eq 0 ]; then
      ok "$init: sfab-cluster.service finished in this boot with status 0 (poll $i, $(printf '%s\n' "$out" | sed -n 's/^NRestarts=//p') restarts)"
      return 0
    fi
    if [ "$rc" -eq 2 ]; then
      line="$(EVID_OFF=1 H "$init" "journalctl -u sfab-cluster.service -n 1 --no-pager -o cat" 2>/dev/null | tail -n 1 || true)"
      bad "$init: sfab-cluster.service finished in this boot" "the unit failed for good: ${line:-no journal line}"
      return 1
    fi
    if [ $((i % 5)) -eq 1 ]; then
      line="$(EVID_OFF=1 H "$init" "journalctl -u sfab-cluster.service -n 1 --no-pager -o cat" 2>/dev/null | tail -n 1 || true)"
      if [ -n "$line" ] && [ "$line" != "$last" ]; then echo "finish: $init: $line"; last="$line"; fi
    fi
    sleep "${TO_CLUSTER_POLL_S:-30}"
  done
  bad "$init: sfab-cluster.service finished in this boot" "$(printf '%s' "$out" | paste -sd ' ' -)"
  return 1
}

# ready_names: the inventory's Kubernetes nodes that kubectl shows Ready, one per line.
ready_names() {
  EVID_OFF=1 K get nodes -o json 2>/dev/null | py -c '
import json, sys
try:
    items = json.load(sys.stdin).get("items") or []
except ValueError:
    items = []
for n in items:
    if any(c.get("type") == "Ready" and c.get("status") == "True" for c in (n.get("status") or {}).get("conditions") or []):
        print(n["metadata"]["name"])
' 2>/dev/null || true
}

nodes_ready() {
  local want=() i got missing n
  sec "nodes Ready"
  mapfile -t want < <(k8s_nodes)
  for i in $(seq 1 "${TO_CLUSTER_POLLS:-240}"); do
    got="$(ready_names)"
    missing=""
    for n in "${want[@]}"; do grep -qx "$n" <<<"$got" || missing="$missing $n"; done
    if [ -z "$missing" ]; then
      ok "all ${#want[@]} nodes Ready: ${want[*]} (poll $i)"
      return 0
    fi
    sleep "${TO_CLUSTER_POLL_S:-30}"
  done
  bad "all ${#want[@]} nodes Ready" "not Ready:$missing"
  return 1
}

retract_keys() {
  local left
  sec "kubeadm keys"
  if ! "$SFAB_CA" -C "$RENDERDIR" retract >"$RUNDIR/retract.txt" 2>&1; then
    bad "sfab-ca retract on the lab host" "$(tail -n 1 "$RUNDIR/retract.txt")"
    return 1
  fi
  left="$(grep -rlI -e 'PRIVATE KEY' "$STATEDIR/shared" 2>/dev/null | sed "s#^$STATEDIR/##" | paste -sd ' ' - || true)"
  if [ -z "$left" ]; then
    ok "kubeadm's keys retracted: no private key left under state/shared/ (sfab-ca retract)"
  else
    bad "kubeadm's keys retracted from state/shared/" "still there: $left"
    return 1
  fi
}

# --- Cilium ------------------------------------------------------------------------------------------

# cilium_state: "<devices, sorted, comma-separated> <stale agents, comma-separated or ->", or
# "unreadable".
cilium_state() {
  EVID_OFF=1 KSH 'kubectl -n kube-system get cm cilium-config -o json; echo "@@"; kubectl -n kube-system get pods -l k8s-app=cilium -o json' 2>/dev/null | py -c '
import json, re, sys
raw = sys.stdin.read().split("@@")
try:
    cm, pods = json.loads(raw[0]), json.loads(raw[1])
except (ValueError, IndexError):
    print("unreadable"); raise SystemExit(0)
devs = sorted({d for d in re.split(r"[ ,]+", (cm.get("data") or {}).get("devices") or "") if d})
md = cm.get("metadata") or {}
times = [m.get("time") for m in md.get("managedFields") or [] if m.get("time")]
changed = max(times) if times else md.get("creationTimestamp") or ""
old = [p["metadata"]["name"] for p in pods.get("items") or [] if ((p.get("status") or {}).get("startTime") or "") < changed]
print((",".join(devs) or "-") + " " + (",".join(old) or "-"))
' 2>/dev/null || echo unreadable
}

roll_cilium() {
  K -n kube-system rollout restart ds/cilium >"$RUNDIR/cilium-roll.txt" 2>&1 &&
    K -n kube-system rollout status ds/cilium --timeout=900s >>"$RUNDIR/cilium-roll.txt" 2>&1
}

# chart_ref NAME_OR_REF: a bare chart name becomes oci://<mirror>/<charts>/<name>.
chart_ref() {
  local c="$1" mirror charts
  case "$c" in *://*) printf '%s\n' "$c"; return 0 ;; esac
  mirror="$(inv get registry.mirror 2>/dev/null || true)"
  charts="$(inv get registry.charts 2>/dev/null || echo charts)"
  [ -n "$mirror" ] || { warn "chart $c: the inventory names no registry mirror"; printf '%s\n' "$c"; return 0; }
  printf 'oci://%s/%s/%s\n' "$mirror" "$charts" "$c"
}
# helm_tls_flags REF: for an oci:// chart, --plain-http when the lab registry serves plain HTTP,
# --ca-file with the lab root when it serves HTTPS.
helm_tls_flags() {
  case "$1" in
    oci://*)
      if [ "$(inv get registry.scheme 2>/dev/null || echo http)" = http ]; then printf '%s\n' "--plain-http"
      else printf '%s\n' "--ca-file $REGISTRY_CA"; fi ;;
  esac
}

cilium_drift() {
  local want state have stale ref ver flags
  sec "Cilium devices and agents"
  want="$(ijson k8s.cilium_devices | py -c 'import json, sys; v = json.load(sys.stdin) or []; print(",".join(sorted(set(v))))')"
  state="$(cilium_state)"
  if [ "$state" = unreadable ]; then bad "Cilium's cilium-config and agents read" "kubectl could not read them on $KNODE"; return 1; fi
  read -r have stale <<<"$state"
  if [ -z "$want" ]; then
    skip "Cilium devices as the spec sets them" "the inventory names no k8s.cilium_devices"
  elif [ "$have" = "$want" ]; then
    ok "Cilium devices are the spec's: $want"
  else
    echo "finish: cilium-config devices '$have', the spec's '$want': helm upgrade --reuse-values"
    ref="$(chart_ref cilium)"
    # the chart version the release runs now: --reuse-values keeps everything else as it is
    ver="$(EVID_OFF=1 KSH 'helm -n kube-system get metadata cilium -o json' 2>/dev/null | py -c 'import json, sys; print(json.load(sys.stdin).get("version", ""))' 2>/dev/null || true)"
    [ -n "$ver" ] || { bad "Cilium devices set to the spec's" "helm shows no cilium release in kube-system to upgrade"; return 1; }
    flags="$(helm_tls_flags "$ref")"
    if KSH "helm -n kube-system upgrade cilium $(printf '%q' "$ref") --version $(printf '%q' "$ver") --reuse-values --set devices='{$want}' --wait --timeout 15m $flags" \
      >"$RUNDIR/cilium-upgrade.txt" 2>&1 && roll_cilium; then
      read -r have stale <<<"$(cilium_state)"
      if [ "$have" = "$want" ]; then ok "Cilium devices set to the spec's ($want) and the agents rolled"; else bad "Cilium devices set to the spec's" "still '$have'"; return 1; fi
    else
      bad "Cilium devices set to the spec's" "$(tail -n 1 "$RUNDIR/cilium-upgrade.txt" "$RUNDIR/cilium-roll.txt" 2>/dev/null | tail -n 1)"
      return 1
    fi
  fi
  if [ "$stale" = - ]; then
    ok "every Cilium agent started after cilium-config last changed"
  else
    echo "finish: Cilium agents older than cilium-config: $stale; rolling the DaemonSet"
    if roll_cilium && [ "$(cilium_state | cut -d' ' -f2)" = - ]; then
      ok "Cilium DaemonSet rolled after a cilium-config change"
    else
      bad "Cilium DaemonSet rolled" "agents still older than cilium-config, or the rollout did not finish"
      return 1
    fi
  fi
}

# --- manifests and charts ------------------------------------------------------------------------------

# copy_in: bootstrap/k8s onto the init node at /tmp/sfab-k8s (a tar stream over SSH), where the
# harness's kubectl and helm read it. Nothing in it is a secret.
copy_in() {
  [ -n "${KNODE:-}" ] || { warn "no Kubernetes init node in $LAB"; return 2; }
  tar -C "$K8S_DIR" -cf - . | EVID_OFF=1 _ssh_guest_in "$GUEST_USER@$(node_mgmt "$KNODE")" \
    "sudo bash -c 'rm -rf $INKNODE && mkdir -p $INKNODE && tar -C $INKNODE -xf -'"
}

# A kind whose CRD a chart has not installed yet, or a webhook not serving yet.
_not_yet() { grep -qE 'no matches for kind|ensure CRDs are installed first|could not find the requested resource|failed calling webhook|connection refused' "$1"; }

k8s_apply() {
  local f n=0 d=0 i=0
  sec "apply"
  [ -f "$K8S_DIR/apply.list" ] || { skip "kubectl apply" "bootstrap/k8s/apply.list is not rendered yet"; return 3; }
  copy_in
  : >"$RUNDIR/apply-late.list"
  while read -r f _; do
    case "$f" in ''|'#'*) continue ;; esac
    i=$((i + 1))
    if K apply --server-side --force-conflicts -f "$INKNODE/$f" >"$RUNDIR/apply-$i.txt" 2>&1; then
      n=$((n + 1))
    elif _not_yet "$RUNDIR/apply-$i.txt"; then
      printf '%s\n' "$f" >>"$RUNDIR/apply-late.list"
      d=$((d + 1))
    else
      bad "kubectl apply --server-side $f" "$(tail -n 1 "$RUNDIR/apply-$i.txt")"
      return 1
    fi
  done <"$K8S_DIR/apply.list"
  ok "$n manifests applied on $KNODE (server-side)$([ "$d" -eq 0 ] || echo ", $d set aside until the charts install their kinds")"
}

charts() {
  local phase="${1:-k8s}" rel ns ref ver vals ph n=0 args flags
  sec "charts ($phase)"
  [ -f "$K8S_DIR/charts.list" ] || { skip "helm charts ($phase)" "bootstrap/k8s/charts.list is not rendered yet"; return 3; }
  copy_in
  while read -r rel ns ref ver vals ph _; do
    case "$rel" in ''|'#'*) continue ;; esac
    [ "${ph:-k8s}" = "$phase" ] || continue
    ref="$(chart_ref "$ref")"
    args=(upgrade --install "$rel" "$ref" --version "$ver" -n "$ns" --create-namespace --wait --timeout 15m)
    [ -z "${vals:-}" ] || [ "$vals" = - ] || args+=(-f "$INKNODE/$vals")
    flags="$(helm_tls_flags "$ref")"
    # shellcheck disable=SC2206 # the flags are words: --plain-http, or --ca-file and its path
    [ -z "$flags" ] || args+=($flags)
    # etcd members that just joined from a snapshot can time out the first writes: an
    # install refused by etcd itself is retried (upgrade --install is idempotent), nothing else is
    local try=1 rc
    while :; do
      KSH "helm $(printf '%q ' "${args[@]}")" >"$RUNDIR/chart-$rel.txt" 2>&1 && rc=0 || rc=$?
      [ "$rc" -ne 0 ] && [ "$try" -lt 3 ] && grep -q 'etcdserver: ' "$RUNDIR/chart-$rel.txt" || break
      cp "$RUNDIR/chart-$rel.txt" "$RUNDIR/chart-$rel.try$try.txt"
      warn "helm upgrade --install $rel: etcd refused the write (try $try of 3), retrying in 30 s"
      try=$((try + 1)); sleep 30
    done
    if [ "$rc" -eq 0 ]; then
      n=$((n + 1))
      [ "$try" -eq 1 ] || ok "helm upgrade --install $rel installed on try $try after etcd refused the write"
    else
      bad "helm upgrade --install $rel" "$(tail -n 1 "$RUNDIR/chart-$rel.txt")"
      return 1
    fi
  done <"$K8S_DIR/charts.list"
  ok "$n charts ($phase) installed from the in-lab registry"
}

apply_late() {
  local f t n=0 left
  sec "apply, after the charts"
  [ -s "$RUNDIR/apply-late.list" ] || { ok "no manifest waited for a chart"; return 0; }
  copy_in
  while read -r f; do
    [ -n "$f" ] || continue
    for t in $(seq 1 "${SFAB_APPLY_TRIES:-10}"); do
      if K apply --server-side --force-conflicts -f "$INKNODE/$f" >"$RUNDIR/apply-late.txt" 2>&1; then n=$((n + 1)); continue 2; fi
      sleep "${SFAB_APPLY_PAUSE_S:-15}"
    done
    bad "kubectl apply --server-side $f, after the charts" "$(tail -n 1 "$RUNDIR/apply-late.txt")"
    return 1
  done <"$RUNDIR/apply-late.list"
  left="$(grep -c . "$RUNDIR/apply-late.list" || true)"
  ok "$n of $left manifests set aside applied after the charts"
}

ca_secrets() {
  local ca ref n=0
  sec "CA secrets"
  [ -f "$K8S_DIR/ca-secrets.list" ] || { skip "CA secrets" "bootstrap/k8s/ca-secrets.list is not rendered yet"; return 3; }
  while read -r ca ref _; do
    case "$ca" in ''|'#'*) continue ;; esac
    # the Secret goes from sfab-ca on the lab host to kubectl on the init node through a pipe;
    # nothing records or prints it (EVID_OFF), and only kubectl's answer is kept
    # (pipefail: a failure on either side fails the step)
    if "$SFAB_CA" -C "$RENDERDIR" k8s-secret "$ca" "$ref" 2>"$RUNDIR/ca-secret-$n.log" |
         EVID_OFF=1 KI apply --server-side --force-conflicts -f - >"$RUNDIR/ca-secret-$n.txt" 2>&1; then
      n=$((n + 1))
    else
      bad "sfab-ca k8s-secret $ca $ref | kubectl apply on $KNODE" "$(tail -n 1 "$RUNDIR/ca-secret-$n.log" "$RUNDIR/ca-secret-$n.txt" 2>/dev/null | tail -n 1)"
      return 1
    fi
  done <"$K8S_DIR/ca-secrets.list"
  ok "$n CA key pair(s) written as Secrets from the lab host (sfab-ca k8s-secret, through a pipe to kubectl on $KNODE)"
}

# idp_secret: the identity provider's credentials (gen/k8s.json identity), the Secret Dex reads its
# client secrets and password hashes from, written from the lab host through a pipe
# (common/bin/idp-secret.py: bcrypt hashes of state/secrets.env's passwords, never the passwords).
# After apply, so its namespace exists; Dex's pod waits for it, and is restarted when it changed.
idp_secret() {
  local ns name dep out
  sec "identity provider credentials"
  ns="$(py -c 'import json,sys; print((json.load(open(sys.argv[1])).get("identity") or {}).get("namespace") or "")' "$RENDERDIR/gen/k8s.json" 2>/dev/null || true)"
  [ -n "$ns" ] || { skip "identity provider credentials" "the lab renders no identity provider"; return 3; }
  name="$(py -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"]["secret"])' "$RENDERDIR/gen/k8s.json")"
  dep="$(py -c 'import json,sys; print(json.load(open(sys.argv[1]))["identity"]["name"])' "$RENDERDIR/gen/k8s.json")"
  # the Secret goes from the lab host to kubectl on the init node through a pipe; nothing records it
  if py "$SFAB_COMMON/bin/idp-secret.py" --k8s "$RENDERDIR/gen/k8s.json" --env "$STATEDIR/secrets.env" 2>"$RUNDIR/idp-secret.log" |
       EVID_OFF=1 KI apply --server-side --force-conflicts -f - >"$RUNDIR/idp-secret.txt" 2>&1; then
    :
  else
    bad "idp-secret.py | kubectl apply on $KNODE" "$(tail -n 1 "$RUNDIR/idp-secret.log" "$RUNDIR/idp-secret.txt" 2>/dev/null | tail -n 1)"
    return 1
  fi
  if grep -q ' configured' "$RUNDIR/idp-secret.txt"; then
    K -n "$ns" rollout restart "deployment/$dep" >/dev/null 2>&1 || true
    echo "finish: the identity provider's credentials changed, so $ns/$dep was restarted"
  fi
  if ! K -n "$ns" rollout status "deployment/$dep" --timeout=600s >"$RUNDIR/idp-rollout.txt" 2>&1; then
    bad "deployment $ns/$dep rolled out" "$(tail -n 1 "$RUNDIR/idp-rollout.txt")"
    return 1
  fi
  ok "the identity provider's credentials written as Secret $ns/$name from the lab host (client secrets and password hashes, through a pipe), $ns/$dep rolled out"
}

# operators: each operator user's short-lived kubeconfig for the bastion (k8s.operators in gen/k8s.json).
operators() {
  local users group hours cfg u out n=0
  sec "operators"
  users="$(py -c 'import json,sys; print(" ".join(json.load(open(sys.argv[1])).get("operators", {}).get("users") or []))' "$RENDERDIR/gen/k8s.json" 2>/dev/null || true)"
  [ -n "$users" ] || { skip "operators' kubeconfigs" "k8s.operators names no user"; return 3; }
  group="$(py -c 'import json,sys; print(json.load(open(sys.argv[1]))["operators"]["group"])' "$RENDERDIR/gen/k8s.json")"
  hours="$(py -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["operators"]["validity_h"]))' "$RENDERDIR/gen/k8s.json")"
  cfg="$(py -c 'import json,sys; print(json.load(open(sys.argv[1]))["admin"]["user_config"])' "$RENDERDIR/gen/k8s.json")"
  for u in $users; do
    out="$STATEDIR/operators/$u"
    mkdir -p "$out"
    chmod 0755 "$STATEDIR/operators" "$out"
    # the kubeconfig holds the operator's private key: it goes from the init node to a 0600 file on
    # the lab host and is never recorded or printed
    if (umask 077; EVID_OFF=1 H "$KNODE" "kubeadm kubeconfig user --config $cfg --client-name $u --org $group --validity-period ${hours}h0m0s" \
          >"$out/kubeconfig.new" 2>"$RUNDIR/operator-$u.err") && grep -q '^kind: Config' "$out/kubeconfig.new"; then
      chmod 0600 "$out/kubeconfig.new"
      mv -f "$out/kubeconfig.new" "$out/kubeconfig"
      n=$((n + 1))
    else
      rm -f "$out/kubeconfig.new"
      bad "kubeadm kubeconfig user --client-name $u on $KNODE" "$(tail -n 1 "$RUNDIR/operator-$u.err" 2>/dev/null)"
      return 1
    fi
  done
  ok "$n operator kubeconfig(s) issued on $KNODE for ${hours} h in group $group (state/operators/<user>/kubeconfig, 0600; the bastion installs each for its user)"
}

# --- storage and serving -----------------------------------------------------------------------------

# storage_bonds: the pair's PortChannels as rendered, the ones facing the storage nodes included,
# in TO_FABRIC_CONSECUTIVE polls in a row. A storage appliance's data bond is made by its setup
# (truenas-setup.py), so before it nothing answers LACP on those ports, and boot's fabric and bond
# waits leave those PortChannels to this step.
storage_bonds() {
  local p a b sw dir="$RUNDIR/storage-bonds" polls=${TO_FABRIC_POLLS:-120} pause=${TO_FABRIC_POLL_S:-15}
  local need=${TO_FABRIC_CONSECUTIVE:-2} good=0 i rc
  [ ${#PAIRS[@]} -gt 0 ] || return 0
  for i in $(seq 1 "$polls"); do
    rc=0
    rm -rf "$dir"
    for p in "${PAIRS[@]}"; do
      read -r a b <<<"${PAIR_MEMBERS[$p]}"
      for sw in "$a" "$b"; do
        mkdir -p "$dir/$sw"
        EVID_OFF=1 SW "$sw" "show mclag brief" "show PortChannel summary" >"$dir/$sw.session" 2>/dev/null || true
        printf '01\tmclag_brief\tklish\t.txt\tshow mclag brief\n02\tportchannel_summary\tklish\t.txt\tshow PortChannel summary\n' >"$dir/$sw.plan"
        py "$SFAB_COMMON/audit/judge.py" split --style klish --plan "$dir/$sw.plan" --session "$dir/$sw.session" --out "$dir/$sw" >/dev/null || true
      done
      SFAB_VERDICT="$dir/verdict-$p.txt" py "$SFAB_COMMON/audit/judge.py" run --set "$dir" --inv "$INV" --render "$RENDERDIR" \
        mclag-pair "$a" "$b" >"$dir/judge-$p.txt" 2>&1 || rc=1
    done
    if [ "$rc" -eq 0 ]; then good=$((good + 1)); [ "$good" -ge "$need" ] && break; else good=0; fi
    sleep "$pause"
  done
  if [ "$good" -ge "$need" ]; then
    ok "pair: every PortChannel up with every member, the storage bonds included ($need consecutive polls, poll $i)"
  else
    bad "pair: the storage bonds up" "$(grep -hE '^  FAIL  ' "$dir"/judge-*.txt 2>/dev/null | head -n 2 | sed 's/^  FAIL  //' | paste -sd ';' -)"
    return 1
  fi
}

TRUENAS_SETUP="${SFAB_TRUENAS_SETUP:-$SFAB_COMMON/storage/truenas-setup.py}"
ONTAP_SETUP="${SFAB_ONTAP_SETUP:-$SFAB_COMMON/storage/ontap-setup.sh}"

storage_setup() {
  local s rc=0
  sec "storage"
  for s in "${STORAGE[@]+"${STORAGE[@]}"}"; do
    case "${NODE_KIND[$s]}" in
      truenas)
        [ -f "$TRUENAS_SETUP" ] || { skip "$s setup" "common/storage/truenas-setup.py is not present"; rc=3; continue; }
        if (cd "$LABDIR" && py "$TRUENAS_SETUP" all --node "$s") >"$RUNDIR/storage-$s.txt" 2>&1; then
          ok "$s: truenas-setup.py all"
        else
          bad "$s: truenas-setup.py all" "$(tail -n 1 "$RUNDIR/storage-$s.txt")"
          return 1
        fi
        storage_bonds || return 1 ;;
      ontap)
        [ -x "$ONTAP_SETUP" ] || { skip "$s setup" "common/storage/ontap-setup.sh is not present"; rc=3; continue; }
        if "$ONTAP_SETUP" "$s" >"$RUNDIR/storage-$s.txt" 2>&1; then ok "$s: ontap-setup.sh"; else bad "$s: ontap-setup.sh" "$(tail -n 1 "$RUNDIR/storage-$s.txt")"; return 1; fi ;;
    esac
  done
  [ "$rc" -eq 0 ] || return "$rc"
  if [ -f "$K8S_DIR/charts.list" ] && grep -qE '^[^#]*[[:space:]]storage([[:space:]]|$)' "$K8S_DIR/charts.list"; then
    charts storage || return 1
  fi
}

serving() {
  sec "serving"
  [ -f "$SFAB_ROOT/serving-layer/Makefile" ] || { skip "make serve" "serving-layer/Makefile is not present"; return 3; }
  [ -f "$K8S_DIR/serving.env" ] || { bad "make serve" "bootstrap/k8s/serving.env is not rendered"; return 1; }
  if make -C "$SFAB_ROOT/serving-layer" serve SERVING_ENV="$K8S_DIR/serving.env" >"$RUNDIR/serving.txt" 2>&1; then
    ok "serving-layer deployed with the placement in serving.env"
  else
    bad "make -C serving-layer serve" "$(tail -n 1 "$RUNDIR/serving.txt")"
    return 1
  fi
}

# inference_get KEY: a value of gen/k8s.json's inference block (a list prints one item per line)
inference_get() {
  py - "$RENDERDIR/gen/k8s.json" "$1" <<'PY'
import json, sys
cur = (json.load(open(sys.argv[1], encoding="utf-8")).get("inference") or {})
for part in sys.argv[2].split("."):
    cur = cur.get(part) if isinstance(cur, dict) else None
if isinstance(cur, list):
    print("\n".join(json.dumps(x, sort_keys=True) if isinstance(x, dict) else str(x) for x in cur))
elif cur is not None:
    print(cur)
PY
}

inference() {
  local ns job base keys layer d restart=0 n=0 jrc=0 pol
  sec "inference"
  base="$(inference_get files.base)" keys="$(inference_get files.keys)" layer="$(inference_get files.layer)"
  ns="$(inference_get namespace)" job="$(inference_get job)"
  if [ -z "$layer" ] || [ ! -f "$K8S_DIR/$layer" ]; then
    skip "the API gateway and the router" "bootstrap/k8s renders no inference layer"
    return 3
  fi
  copy_in
  if ! K apply --server-side --force-conflicts -f "$INKNODE/$base" >"$RUNDIR/inference-base.txt" 2>&1; then
    bad "kubectl apply --server-side $base" "$(tail -n 1 "$RUNDIR/inference-base.txt")"
    return 1
  fi
  K -n "$ns" delete job "$job" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  if ! K apply --server-side --force-conflicts -f "$INKNODE/$keys" >"$RUNDIR/inference-keys-apply.txt" 2>&1; then
    bad "kubectl apply --server-side $keys" "$(tail -n 1 "$RUNDIR/inference-keys-apply.txt")"
    return 1
  fi
  K -n "$ns" wait --for=condition=complete "job/$job" --timeout=300s >/dev/null 2>&1 || jrc=$?
  K -n "$ns" logs "job/$job" >"$RUNDIR/inference-keys.txt" 2>&1 || true
  sed 's/^/  key tool: /' "$RUNDIR/inference-keys.txt"
  K -n "$ns" delete job "$job" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  if [ "$jrc" -ne 0 ]; then
    bad "the key Job $ns/$job" "it did not complete within 300 s"
    return 1
  fi
  ok "the router's master key, the first key of each application caller and the router's backend key, made or copied in the cluster by the key Job (no value printed)"
  grep -q ': updated, ' "$RUNDIR/inference-keys.txt" && restart=1
  if ! K apply --server-side --force-conflicts -f "$INKNODE/$layer" >"$RUNDIR/inference-layer.txt" 2>&1; then
    bad "kubectl apply --server-side $layer" "$(tail -n 1 "$RUNDIR/inference-layer.txt")"
    return 1
  fi
  if [ "$restart" = 1 ]; then
    K -n "$ns" rollout restart "deployment/$(inference_get router.name)" >/dev/null 2>&1 || true
    echo "finish: the router's backend key changed, so the router was restarted"
  fi
  while read -r d; do
    [ -n "$d" ] || continue
    if K -n "$ns" rollout status "deployment/$d" --timeout=600s >"$RUNDIR/inference-rollout-$d.txt" 2>&1; then
      n=$((n + 1))
    else
      bad "deployment $ns/$d rolled out" "$(tail -n 1 "$RUNDIR/inference-rollout-$d.txt")"
      return 1
    fi
  done < <(inference_get deployments)
  ok "$n Deployments in $ns rolled out (the API gateway and the router), with the model routes on $(inference_get routes | grep -c .) Gateway(s)"
  # network policy for the API gateway's namespace and the serving recipe's, last: both exist now
  pol="$(py -c 'import json,sys; print(((json.load(open(sys.argv[1])).get("network_policy") or {}).get("files") or {}).get("inference") or "")' "$RENDERDIR/gen/k8s.json" 2>/dev/null || true)"
  if [ -n "$pol" ] && [ -f "$K8S_DIR/$pol" ]; then
    if ! K apply --server-side --force-conflicts -f "$INKNODE/$pol" >"$RUNDIR/inference-policy.txt" 2>&1; then
      bad "kubectl apply --server-side $pol" "$(tail -n 1 "$RUNDIR/inference-policy.txt")"
      return 1
    fi
    ok "network policy for $ns and $(py -c 'import json,sys; print(json.load(open(sys.argv[1]))["serving"]["namespace"])' "$RENDERDIR/gen/k8s.json"): default deny, then the request path ($pol, $(grep -c 'CiliumNetworkPolicy' "$K8S_DIR/$pol") policies)"
  fi
}

# --- settle --------------------------------------------------------------------------------------------

# The other addresses each node pings every round (storage data addresses), and the TCP 443 targets:
# every Gateway VIP from the nodes; per population, a client and its answer address. From chapter 8
# gen/tenancy.json's audiences.reach gives each population's connect to its own Gateway at this
# step, as the audit reads it: a population the firewall does not yet let through (the internet users
# in chapter 9, before the translation) is no target.
settle_targets() {
  py - "$INV" "$RENDERDIR/gen/tenancy.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
try:
    reach = {r["population"]: r for r in (json.load(open(sys.argv[2], encoding="utf-8")).get("audiences") or {}).get("reach") or []}
except (OSError, ValueError):
    reach = {}
nodes = d.get("nodes") or {}
# The storage data addresses sit on their own Layer 2 VLAN: only the nodes with a unit in it ping
# them ("ping <address> <segment>"), the frontend round sends each to the nodes holding that segment.
for n in d.get("order") or []:
    data = (nodes[n].get("data") or {}) if nodes[n].get("section") == "appliances" else {}
    if data.get("address"):
        print("ping", data["address"].split("/")[0], data.get("vlan") or "")
# the Gateway VIPs the nodes' own audience reaches: the nodes population's (the internal Gateway)
pops = d.get("populations") or {}
nodes_gw = {p.get("gateway") for p in pops.values() if any((nodes.get(c) or {}).get("kind") == "vm-node" for c in p.get("clients") or [])
            or "k8s-nodes" in (p.get("zones") or [])}
for g, v in sorted((d.get("gateways") or {}).items()):
    if v.get("vip") and (not nodes_gw - {None} or g in nodes_gw):
        print("vip", v["vip"], g)
# each population's client at its answer, the populations with an audience only (an internet host
# that is no audience reaches nothing, which chapter 2's matrix proves)
for p, v in sorted(pops.items()):
    if not v.get("gateway") or (p in reach and reach[p].get("outcome") != "reached"):
        continue
    for c in v.get("clients") or []:
        if c in nodes and v.get("answer_address"):
            print("client", c, v["answer_address"], p)
PY
}

# The six peer offsets of the frontend sweep (timeouts.settle_frontend.peer_offsets).
OFFSETS="$(inv json timeouts.settle_frontend.peer_offsets 2>/dev/null | py -c 'import json, sys; print(" ".join(str(int(x)) for x in json.load(sys.stdin) or []))' 2>/dev/null || true)"
[ -n "$OFFSETS" ] || OFFSETS="1 5 11 17 23 29"

frontend_round() {
  local round="$1" nodes=() i j o peer addr bad_nodes=() kind a b c n_ping=() n_vip=() fails=0
  mapfile -t nodes < <(k8s_nodes)
  while read -r kind a b c; do
    case "$kind" in
      ping) n_ping+=("$a:$b") ;;
      vip) n_vip+=("$a") ;;
      client) if ! EVID_OFF=1 X "$a" sh -c "timeout 5 bash -c '</dev/tcp/$b/443'" >/dev/null 2>&1; then fails=$((fails + 1)); echo "finish: round $round: $a cannot reach $b:443 ($c)"; fi ;;
    esac
  done < <(settle_targets)
  local n=${#nodes[@]}
  for i in $(seq 0 $((n - 1))); do
    for o in $OFFSETS; do
      [ "$n" -gt 1 ] || break
      j=$(((i + o + round) % n))
      [ "$j" -ne "$i" ] || continue
      peer="${nodes[$j]}"
      addr="$(inv get "nodes.$peer.address" | cut -d/ -f1)"
      EVID_OFF=1 H "${nodes[$i]}" "ping -c 2 -W 2 -q $addr" >/dev/null 2>&1 || bad_nodes+=("${nodes[$i]}" "$peer")
    done
    for addr in "${n_ping[@]+"${n_ping[@]}"}"; do
      # a storage data address only from a node with a unit in its VLAN (no route reaches it otherwise)
      if [ -n "${addr#*:}" ] && ! inv json "nodes.${nodes[$i]}.bond.vlan_ifs" 2>/dev/null | grep -q "\"vlan\": ${addr#*:}\b"; then continue; fi
      EVID_OFF=1 H "${nodes[$i]}" "ping -c 2 -W 2 -q ${addr%%:*}" >/dev/null 2>&1 || bad_nodes+=("${nodes[$i]}")
    done
    for addr in "${n_vip[@]+"${n_vip[@]}"}"; do
      EVID_OFF=1 H "${nodes[$i]}" "timeout 5 bash -c '</dev/tcp/$addr/443'" >/dev/null 2>&1 || bad_nodes+=("${nodes[$i]}")
    done
  done
  if [ ${#bad_nodes[@]} -eq 0 ] && [ "$fails" -eq 0 ]; then return 0; fi
  if [ ${#bad_nodes[@]} -gt 0 ]; then
    printf '%s\n' "${bad_nodes[@]}" | sort | uniq -c | sort -rn | head -n 1 | awk '{print $2}' >"$RUNDIR/worst"
  else
    : >"$RUNDIR/worst"
  fi
  return 1
}

bounce_legs() {
  local g="$1" legs
  [ -n "$g" ] || return 0
  legs="$(inv get "nodes.$g.bond.members" | paste -sd ' ' -)"
  echo "finish: bouncing $g's bond legs ($legs), guest side"
  EVID_OFF=1 H "$g" "for l in $legs; do ip link set \$l down; done; sleep 8; for l in $legs; do ip link set \$l up; done" >/dev/null 2>&1 || true
}

# rails_settle: ping every rail between the first two relay guests, from each GPU namespace to the
# other node's rail address, until clean rounds or the same rails lose twice. Runs before serving,
# so a rail that carries nothing fails here and not as a crash-looping server, and again in settle.
# A failure saves rails_diag's reads under state/logs.
rails_settle() {
  [ ${#RELAY_GUESTS[@]} -ge 2 ] || return 0
  local a="${RELAY_GUESTS[0]}" b="${RELAY_GUESTS[1]}" rail lost prev="" cleanr=0 addr r
  for r in $(seq 1 "$(inv get timeouts.settle_rails.max_rounds)"); do
    lost=""
    for rail in $(inv json "nodes.$a.rails" | py -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin), key=int)))'); do
      addr="$(inv get "nodes.$b.rails.$rail.address" | cut -d/ -f1)"
      EVID_OFF=1 H "$a" "ip netns exec gpu$rail ping -c 2 -W 2 -q $addr" >/dev/null 2>&1 || lost="$lost $rail"
    done
    if [ -z "$lost" ]; then
      cleanr=$((cleanr + 1))
      [ "$cleanr" -ge "$(inv get timeouts.settle_rails.clean_rounds)" ] && break
    else
      cleanr=0
      [ "$lost" = "$prev" ] && break
      prev="$lost"
    fi
  done
  if [ -z "$lost" ]; then ok "rails: clean rounds between $a and $b"; return 0; fi
  rails_diag "$a" "$b" $lost
  bad "rails settle" "rails$lost lose pings between $a and $b (reads in state/logs/rails-diag-*.txt)"
  return 1
}

# rails_diag A B RAIL...: for each losing rail, what each side holds: the GPU namespaces' neighbors
# and interface counters on both nodes, the rail switch's MAC table and port counters, and inside the
# switch's container the two ports' counters and tc filters (the container's ethN carry the links to
# the switch VM). Read only.
rails_diag() {
  local a="$1" b="$2" f rail sw ea eb na nb g
  shift 2
  f="$STATEDIR/logs/rails-diag-$(utc_compact).txt"
  {
    for rail in "$@"; do
      sw="$(inv get "nodes.$a.rails.$rail.switch")"
      ea="$(inv get "nodes.$a.rails.$rail.switch_eth")"; eb="$(inv get "nodes.$b.rails.$rail.switch_eth")"
      na="$(inv get "nodes.$a.rails.$rail.switch_native")"; nb="$(inv get "nodes.$b.rails.$rail.switch_native")"
      printf '=== rail %s: %s %s (%s/%s) and %s %s (%s/%s)\n' "$rail" "$a" "$sw" "$ea" "$na" "$b" "$sw" "$eb" "$nb"
      for g in "$a" "$b"; do
        printf -- '--- %s: namespace gpu%s\n' "$g" "$rail"
        EVID_OFF=1 H "$g" "ip -n gpu$rail -s link; ip -n gpu$rail neigh; ip -s link show $(inv get "nodes.$g.rails.$rail.ifname")" 2>&1 || true
      done
      printf -- '--- %s: KLISH\n' "$sw"
      EVID_OFF=1 SW "$sw" "show mac address-table" "show interface counters" 2>&1 || true
      printf -- '--- %s container: %s and %s\n' "$sw" "$ea" "$eb"
      dk exec "$(ctr "$sw")" sh -c "ip -s link show $ea; ip -s link show $eb; tc filter show dev $ea ingress; tc filter show dev $eb ingress; tc qdisc show" 2>&1 || true
    done
  } >"$f" 2>&1
  warn "rails: diagnostics saved in ${f#"$RENDERDIR"/}"
}

settle_sweeps() {
  local r clean=0 bad_rounds=0 bounced=0 max cleanw nvip
  sec "settle"
  max="$(inv get timeouts.settle_frontend.max_rounds)"
  cleanw="$(inv get timeouts.settle_frontend.clean_rounds)"
  nvip="$(settle_targets | grep -c '^vip ' || true)"
  for r in $(seq 1 "$max"); do
    if frontend_round "$r"; then
      clean=$((clean + 1)) bad_rounds=0
      [ "$clean" -ge "$cleanw" ] && break
    else
      clean=0 bad_rounds=$((bad_rounds + 1))
      if [ "$bad_rounds" -ge "$(inv get timeouts.settle_frontend.bounce_after)" ] && [ "$bounced" -lt "$(inv get timeouts.settle_frontend.bounce_max_nodes)" ]; then
        bounce_legs "$(cat "$RUNDIR/worst" 2>/dev/null || true)"
        bounced=$((bounced + 1)) bad_rounds=0
      fi
    fi
  done
  if [ "$clean" -ge "$cleanw" ]; then
    local vips="$nvip Gateway VIPs"
    [ "$nvip" -eq 1 ] && vips="1 Gateway VIP"
    ok "frontend: $cleanw clean rounds (round $r, $bounced nodes bounced; nodes, storage, $vips on TCP 443, the populations' clients)"
  else
    bad "frontend settle" "no $cleanw clean rounds in $max"
    return 1
  fi
  rails_settle
}

# --- Warning events ----------------------------------------------------------------------------------

# unhealthy: nodes not Ready and pods neither Running nor Succeeded (completed), one per line.
unhealthy() {
  EVID_OFF=1 KSH 'kubectl get nodes -o json; echo "@@"; kubectl get pods -A -o json' 2>/dev/null | py -c '
import json, sys
raw = sys.stdin.read().split("@@")
try:
    nodes, pods = json.loads(raw[0]), json.loads(raw[1])
except (ValueError, IndexError):
    print("the cluster could not be read"); raise SystemExit(0)
for n in nodes.get("items") or []:
    if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in (n.get("status") or {}).get("conditions") or []):
        print("node " + n["metadata"]["name"])
for p in pods.get("items") or []:
    ph = (p.get("status") or {}).get("phase")
    if ph not in ("Running", "Succeeded"):
        print("pod %s/%s %s" % (p["metadata"]["namespace"], p["metadata"]["name"], ph))
' 2>/dev/null || echo "the cluster could not be read"
}

warning_count() {
  EVID_OFF=1 K get events -A --field-selector type=Warning -o json 2>/dev/null |
    py -c 'import json, sys; print(len(json.load(sys.stdin).get("items") or []))' 2>/dev/null || echo unreadable
}

events_quiet() {
  local quiet="${TO_EVENTS_QUIET_S:-90}" i u round n arch t
  sec "Warning events"
  for i in $(seq 1 "${SFAB_HEALTH_ROUNDS:-30}"); do
    u="$(unhealthy)"
    [ -n "$u" ] || break
    sleep 10
  done
  if [ -n "$u" ]; then
    bad "cluster healthy before the Warning events are cleared" "$(printf '%s\n' "$u" | head -n 5 | paste -sd ';' -)"
    return 1
  fi
  for round in 1 2 3; do
    arch="$STATEDIR/logs/warning-events-$(utc_compact).json"
    EVID_OFF=1 K get events -A --field-selector type=Warning -o json >"$arch" 2>/dev/null || true
    n="$(py -c 'import json, sys; print(len(json.load(open(sys.argv[1])).get("items") or []))' "$arch" 2>/dev/null || echo 0)"
    [ "$n" = 0 ] || EVID_OFF=1 K delete events -A --field-selector type=Warning >/dev/null 2>&1 || true
    echo "finish: $n Warning event(s) archived in ${arch#"$RENDERDIR"/} and cleared (round $round)"
    t=0
    while [ "$t" -lt "$quiet" ]; do
      sleep 10
      t=$((t + 10))
      n="$(warning_count)"
      [ "$n" = 0 ] || break
    done
    if [ "$n" = 0 ]; then
      ok "Warning events archived, cleared and held at 0 for ${quiet}s (round $round)"
      return 0
    fi
  done
  bad "Warning events held at 0 for ${quiet}s" "$(EVID_OFF=1 K get events -A --field-selector type=Warning -o custom-columns=NS:.metadata.namespace,OBJECT:.involvedObject.name,REASON:.reason --no-headers 2>/dev/null | head -n 3 | paste -sd ';' -)"
  return 1
}

# --- the order -----------------------------------------------------------------------------------------

rc=0
if [ "$STAGE_CLUSTER" = 1 ]; then
  for step in "cluster cluster_wait" "ready nodes_ready" "retract retract_keys" "cilium cilium_drift" "apply k8s_apply" \
    "ca-secrets ca_secrets" "idp-secret idp_secret" "operators operators" "charts charts" "apply-late apply_late"; do
    read -r name fn <<<"$step"
    [ "$rc" -ne 0 ] || stage_step finish "$name" "$fn" || rc=1
  done
else
  echo "finish: k8s is off for $LAB: no cluster, charts or sweeps"
fi
if [ "$rc" -eq 0 ] && [ "$STAGE_SERVING" = 1 ]; then stage_step finish rails rails_settle || rc=1; fi
if [ "$rc" -eq 0 ] && [ "$STAGE_STORAGE_SETUP" = 1 ]; then stage_step finish storage storage_setup || rc=1; fi
if [ "$rc" -eq 0 ] && [ "$STAGE_SERVING" = 1 ]; then stage_step finish serving serving || rc=1; fi
if [ "$rc" -eq 0 ] && [ "$STAGE_SERVING" = 1 ]; then stage_step finish inference inference || rc=1; fi
if [ "$rc" -eq 0 ] && [ "$STAGE_CLUSTER" = 1 ]; then
  stage_step finish settle settle_sweeps || rc=1
  [ "$rc" -ne 0 ] || stage_step finish events events_quiet || rc=1
fi
summary || rc=1
if [ "$rc" -eq 0 ]; then
  if [ -x "$LABDIR/audit.sh" ]; then
    echo "finish: audit.sh --quick"
    "$LABDIR/audit.sh" --quick || rc=$?
  else
    echo "finish: $LABDIR/audit.sh is not present; no quick audit"
  fi
fi
exit "$rc"
