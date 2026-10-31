#!/usr/bin/env bash
# collect.sh --set DIR [--quick] [--nodes a,b]: save every node's collection plan into a result set.
#
# Each node's plan comes from common/audit/cmds/ (judge.py plan). Nodes are collected in parallel,
# at most SFAB_COLLECT_JOBS (16) at a time. On a switch every KLISH line of the plan runs in one
# sonic-cli session that judge.py split cuts by prompt; on the firewall the CLI lines share one
# session the same way. Files land as DIR/<node>/NN_<slug>.txt (.json, .xml), each output once;
# the transcript blocks go to DIR/commands.txt in node order. Each node prints one PASS or FAIL
# line for its collection. Nothing is judged here.
# Surfaces (cmds/README.md): klish, cli and cli-set (one session each), vtysh, shell, guest, xml,
# host (a host_* function below), and from M2 exec (docker exec), frr (vtysh in an FRR container),
# kubectl (a shell on the init node, where the harness's kubectl runs with the admin kubeconfig) and
# node (a VM guest over SSH, else docker exec).
# shellcheck disable=SC2317 # the host_* functions run through the plan's dispatch
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init collect "$@"
[ -n "$RS" ] || die "collect.sh needs --set DIR"

JUDGE="$SFAB_COMMON/audit/judge.py"
PART="$RS/.part"
mkdir -p "$PART"

# host-side reads of a node's own container -----------------------------------------------------

host_launcher_log() {
  dk logs "$(ctr "$1")" 2>&1 | grep -E 'KLISH startup config|Startup complete|system ready|bootstrap configuration' || true
}

host_container_env() {
  dk inspect -f '{{json .Config.Env}}' "$(ctr "$1")" | py -c '
import json, sys
keep = ("NUM_NICS", "CLAB_MGMT_PASSTHROUGH", "QEMU_CPU", "QEMU_SMP", "QEMU_MEMORY", "CONNECTION_MODE")
for e in sorted(json.load(sys.stdin) or []):
    k = e.split("=", 1)[0]
    if k in keep:
        print(e)
'
}

# -d adds each bond slave's perm_hwaddr: a slave sends its LACPDUs (and lldpd its LLDP frames) from
# that address, which the switches learn, while ip link shows the slave with its bond's address.
host_container_links() { nsenter -t "$(pid_of "$1")" -n ip -d -j link show; }

host_container_ipv6() {
  local e pid
  pid="$(pid_of "$1")"
  for e in ${NODE_ETHS[$1]}; do
    printf '%s %s\n' "$e" "$(nsenter -t "$pid" -n cat "/proc/sys/net/ipv6/conf/$e/disable_ipv6" 2>/dev/null || echo missing)"
  done
}

host_container_offloads() {
  local e pid
  pid="$(pid_of "$1")"
  for e in ${NODE_ETHS[$1]}; do
    printf '== %s\n' "$e"
    nsenter -t "$pid" -n ethtool -k "$e" 2>/dev/null |
      grep -E '^(tx-checksumming|generic-receive-offload|rx-gro-hw|large-receive-offload):' || true
  done
}

host_fw_commit_marker() {
  local c
  c="$(ctr "$1")"
  dk logs "$c" 2>&1 | grep -F 'XML startup config commit finished' | tail -n 3 || true
  if dk exec "$c" test -f /tmp/lab-startup-committed 2>/dev/null; then
    echo "marker present: /tmp/lab-startup-committed"
  fi
}

host_fw_delivered_config() { dk exec "$(ctr "$1")" cat /config/startup-config.cfg; }

# M2: the containers' own logs and state, read from the lab host
host_container_log_tail() { dk logs --tail "${SFAB_LOG_TAIL:-300}" "$(ctr "$1")" 2>&1; }

host_container_health() {
  dk inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}no-healthcheck{{end}} restarts={{.RestartCount}} started={{.State.StartedAt}}' "$(ctr "$1")"
}

# The login the launcher was given (its --username and --password, else USERNAME and PASSWORD in
# its env): presence, where it came from, and its keyed mark, the one redact.py leaves (an HMAC
# prefix under the lab's redaction key, FRAMEWORK.md 4.3). Never a value.
host_launcher_login() {
  dk inspect -f '{{json .Config}}' "$(ctr "$1")" | py -c '
import json, sys
sys.path.insert(0, sys.argv[1])
import redact
key = redact.read_key(sys.argv[2])
cfg = json.load(sys.stdin)
cmd, env = cfg.get("Cmd") or [], dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)
def arg(name):
    for i, a in enumerate(cmd):
        if a == name and i + 1 < len(cmd):
            return cmd[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None
for what, flag, var in (("username", "--username", "USERNAME"), ("password", "--password", "PASSWORD")):
    v, src = arg(flag), "the launcher command line (" + flag + ")"
    if v is None:
        v, src = env.get(var), "the container env (" + var + ")"
    if v:
        print(what + ": present, from " + src + ", " + redact.mark(v, key))
    else:
        print(what + ": absent")
' "$SFAB_COMMON/audit" "$STATEDIR/secrets/redact.key"
}

# The registry's request log: the lines that name a /v2/ request, with their source addresses.
# Requests from 127.0.0.1 are left out before the last lines are kept: the image's own healthcheck
# (wget to /v2/ every 10 s) and the audit's catalog read. Kept, they fill the window within about
# half an hour and push the nodes' pulls out of it (chapter 3's first deploy, ch03/RESULTS.md, problem 2).
host_registry_access() {
  dk logs --tail "${SFAB_LOG_TAIL_REGISTRY:-20000}" "$(ctr "$1")" 2>&1 | grep -E '/v2/' |
    grep -vE '^127\.0\.0\.1 |remoteaddr[^=]*="?127\.0\.0\.1:' | tail -n "${SFAB_LOG_KEEP:-400}" || true
}

# The registry's catalog, read in the registry's own network namespace from the lab host over HTTPS,
# its certificate verified against the lab root by the name it carries (state/shared/ca/root.crt; the
# registry's leaf from sfab-ca): a read the certificate did not pass is an error, not a catalog.
host_registry_catalog() {
  local name port
  name="$(py -c 'import json, sys; d = json.load(open(sys.argv[1])); l = ((d.get("ca") or {}).get("leaves") or {}); print(next((v["dns"][0] for v in l.values() if v.get("node") == sys.argv[2] and v.get("dns")), ""))' "$INV" "$1")"
  port="$(inv get registry.port 2>/dev/null || echo 5000)"
  if [ -n "$name" ]; then
    nsenter -t "$(pid_of "$1")" -n curl -sS --max-time 20 --cacert "$STATEDIR/shared/ca/root.crt" \
      --resolve "$name:$port:127.0.0.1" "https://$name:$port/v2/_catalog?n=1000"
  else
    nsenter -t "$(pid_of "$1")" -n curl -sS --max-time 20 "http://127.0.0.1:$port/v2/_catalog?n=1000"
  fi
}

# Private keys under the lab's state/shared on the lab host, each named with its mode, never read:
# finish retracts kubeadm's keys once every control node has joined.
host_shared_keys() {
  local f
  if [ -d "$STATEDIR/shared" ]; then
    grep -rlI -e 'PRIVATE KEY' "$STATEDIR/shared" 2>/dev/null | while read -r f; do
      printf '%s state/shared/%s\n' "$(stat -c '%a' "$f")" "${f#"$STATEDIR"/shared/}"
    done
  fi
  echo "scanned state/shared"
}

# _save FILE ARGV...: a text file keeps the command's stderr (an error is evidence too); a machine
# form (.json, .xml) keeps stdout only.
_save() {
  local f="$1"
  shift
  case "$f" in
    *.txt) "$@" >"$f" 2>&1 ;;
    *) "$@" >"$f" 2>/dev/null ;;
  esac
}

# one node ---------------------------------------------------------------------------------------

collect_node() {
  local n="$1" dir="$RS/$1" plan="$PART/$1.plan" nn slug surface ext cmd out rc
  local got=0 want=0 failed=()
  SFAB_VERDICT="$PART/$n.verdict"
  [ -z "${EVID:-}" ] || EVID="$PART/$n.evid"
  : >"$SFAB_VERDICT"
  mkdir -p "$dir"
  local qa=()
  [ "$SFAB_QUICK" = 1 ] && qa=(--quick)
  if ! py "$JUDGE" plan --inv "$INV" --node "$n" "${qa[@]}" >"$plan"; then
    bad "collect $n" "no plan"
    return 0
  fi
  want="$(grep -c . "$plan" || true)"

  # the interactive surfaces first: one session each
  local sess="$PART/$n.session" sub="$PART/$n.sub" cmds=()
  for surface in klish cli; do
    awk -F'\t' -v s="$surface" '$3 == s' "$plan" >"$sub"
    [ -s "$sub" ] || continue
    mapfile -t cmds < <(cut -f5 "$sub")
    rc=0
    if [ "$surface" = klish ]; then SW "$n" "${cmds[@]}" >"$sess" 2>&1 || rc=$?; else FW "${cmds[@]}" >"$sess" 2>&1 || rc=$?; fi
    local style=klish
    [ "$surface" = cli ] && style=panos
    py "$JUDGE" split --style "$style" --plan "$sub" --session "$sess" --out "$dir" >"$PART/$n.missing" || true
    while read -r slug; do [ -z "$slug" ] || failed+=("$slug"); done <"$PART/$n.missing"
    [ "$rc" -eq 0 ] || failed+=("$surface session exit $rc")
  done
  awk -F'\t' '$3 == "cli-set"' "$plan" >"$sub"
  if [ -s "$sub" ]; then
    rc=0
    FW "set cli config-output-format set" "configure" "show" "exit" >"$sess" 2>&1 || rc=$?
    py "$JUDGE" split --style panos --plan "$sub" --session "$sess" --out "$dir" >"$PART/$n.missing" || true
    while read -r slug; do [ -z "$slug" ] || failed+=("$slug"); done <"$PART/$n.missing"
  fi

  # everything else, one command at a time; the plan is read on fd 3, so no command can read it
  while IFS=$'\t' read -r nn slug surface ext cmd <&3; do
    out="$dir/${nn}_${slug}${ext}"
    rc=0
    case "$surface" in
      klish|cli|cli-set) continue ;;
      vtysh) _save "$out" VT "$n" "$cmd" || rc=$? ;;
      shell|shell-json) _save "$out" SH "$n" "$cmd" || rc=$? ;;
      guest|guest-json) _save "$out" H "$n" "$cmd" || rc=$? ;;
      xml) _save "$out" FWX "$cmd" || rc=$? ;;
      exec|exec-json) _save "$out" X "$n" sh -c "$cmd" || rc=$? ;;
      frr|frr-json) _save "$out" FR "$n" "$cmd" || rc=$? ;;
      kubectl|kubectl-json) _save "$out" KSH "$cmd" || rc=$? ;;
      node|node-json)
        if [ "${NODE_KIND[$n]}" = vm-node ]; then _save "$out" H "$n" "$cmd" || rc=$?; else _save "$out" X "$n" sh -c "$cmd" || rc=$?; fi ;;
      host|host-json|host-xml)
        if declare -F "host_$cmd" >/dev/null; then
          local text
          text="$("host_$cmd" "$n" 2>&1)" || rc=$?
          printf '%s\n' "$text" >"$out"
          _evid "$n" host "+ $cmd"$'\n'"$text"
        else
          rc=127
        fi ;;
      *) rc=127 ;;
    esac
    # a guest probe that fails (a ping with no reply) is still evidence; only a dead transport
    # (ssh 255, timeout 124, no such function 127) means nothing was collected. A docker exec
    # into a missing container exits 1 with nothing on stdout, a kubectl read that fails leaves
    # an empty JSON file: both are judged from what was saved.
    case "$rc" in 124|127|255) failed+=("$slug (exit $rc)"); rm -f "$out" ;; esac
  done 3<"$plan"

  # a planned command with no saved file is a failure too (the per-node 00_ALL_OUTPUT.txt that
  # once joined the files here is no longer written: FRAMEWORK.md 4.4, recording size)
  while IFS=$'\t' read -r nn slug _surface ext _cmd; do
    out="$dir/${nn}_${slug}${ext}"
    if [ ! -f "$out" ]; then
      local x seen=0
      for x in "${failed[@]+"${failed[@]}"}"; do [[ "$x" != *"$slug"* ]] || seen=1; done
      [ "$seen" = 1 ] || failed+=("${nn}_${slug} (no file)")
      continue
    fi
    got=$((got + 1))
  done <"$plan"
  if [ "${#failed[@]}" -eq 0 ]; then
    ok "collect $n: $got of $want commands saved"
  else
    bad "collect $n: $got of $want commands saved" "$(IFS=';'; printf '%s' "${failed[*]:0:6}")"
  fi
}

# all nodes ----------------------------------------------------------------------------------------

targets=()
if [ "${#SFAB_NODES[@]}" -gt 0 ]; then
  for n in "${SFAB_NODES[@]}"; do [ -n "${NODE_CTR[$n]:-}" ] || die "no node $n in $LAB"; targets+=("$n"); done
else
  targets=("${NODES[@]}")
fi
[ "$SFAB_QUICK" = 1 ] && [ "${#SFAB_NODES[@]}" -eq 0 ] && targets=("${SWITCHES[@]}" ${FW_NODE:+"$FW_NODE"})

main_verdict="$SFAB_VERDICT"
main_evid="${EVID:-}"
qlabel=""
[ "$SFAB_QUICK" = 1 ] && qlabel=", quick"
sec "collect ($(utc), ${#targets[@]} nodes$qlabel)"
pids=()
for n in "${targets[@]}"; do
  while [ "$(jobs -rp | wc -l)" -ge "${SFAB_COLLECT_JOBS:-16}" ]; do sleep 1; done
  (collect_node "$n") &
  pids+=("$!")
done
for p in "${pids[@]}"; do wait "$p" || true; done

SFAB_VERDICT="$main_verdict"
EVID="$main_evid"
fails=0
for n in "${targets[@]}"; do
  if [ -f "$PART/$n.verdict" ]; then
    while IFS= read -r l; do
      _vline "$l"
      case "$l" in "  FAIL  "*) fails=1 ;; esac
    done <"$PART/$n.verdict"
  else
    bad "collect $n" "the collector died"
    fails=1
  fi
  if [ -n "$EVID" ] && [ -f "$PART/$n.evid" ]; then cat "$PART/$n.evid" >>"$EVID"; fi
done
rm -rf -- "$PART"
exit "$fails"
