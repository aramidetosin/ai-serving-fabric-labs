# shellcheck shell=bash
# common/lib.sh: what every stage, audit, trace and drill script sources (FRAMEWORK.md section 4).
#
#   . "$(dirname "$0")/../common/lib.sh"; sfab_init audit "$@"
#
# sfab_init reads the lab's gen/inventory.json, sets the lab's identity (LAB, BUILD, STATE, STEP,
# PREFIX, CLABDIR, MGMT_NET, INV and the node tables), refuses to go on unless the identity guard
# passes, and opens a result set when the category records one. After it:
#
#   dk ...                docker, refusing any container whose name does not start with $PREFIX
#   clab ...              containerlab deploy or destroy on this lab's own topology, never --cleanup
#   SW sw line...         one KLISH session (sonic-cli over ssh -tt, terminal length 0 first)
#   VT sw cmd             FRR on a switch (sudo vtysh -c)
#   SH sw cmd             the switch's Linux shell
#   FW line... / FWX xml  PAN-OS CLI over ssh -tt / the XML API with the key in X-PAN-KEY
#   H node cmd / HBG      a VM guest over ssh with the lab key, as root; HBG runs it in the background
#   X node argv...        docker exec in the node's own container
#   K args / KSH script   kubectl with the cluster's admin kubeconfig on the init node (KNODE), over SSH
#                         with the lab key: argv, each word quoted for the remote shell / a shell script
#                         where a pipe is needed; KI and KSHI the same with this shell's stdin passed on
#                         (a manifest on a pipe). The bastion holds no admin kubeconfig.
#   FR rtr cmd            vtysh in an FRR container
#
# and the result vocabulary (sec, ok, bad, skip, known, chk, ge, summary; vocab.py prints the same
# lines). With a result set open every runner appends one block to its commands.txt: a
# "### <UTC> <node> <surface>" header, the session as the device printed it (prompts and all),
# or "+ <command>" and the output where the surface has no prompt. EVID_OFF=1 switches the
# transcript off around keyed requests. Credentials never reach a command line: switch and
# firewall passwords travel in SSHPASS (sshpass -e), API keys in 0600 header files.
#
# Scripts run on the lab host as root. Nothing here touches a container outside this lab, a
# network other than the lab's own, or any other workload on the host.

set -euo pipefail

SFAB_COMMON="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SFAB_ROOT="$(dirname "$SFAB_COMMON")"
export SFAB_COMMON SFAB_ROOT
SFAB_HOST_LOCK="${SFAB_HOST_LOCK:-/run/lock/sfab.lock}"
# containerlab's own check for a newer release reaches the internet, which no lab needs at run time
# (chapter 1's first recorded deploy printed its notice); every containerlab call here runs without it
export CLAB_VERSION_CHECK=disable

# ---------------------------------------------------------------------------------------------
# small helpers

die() { printf 'sfab: %s\n' "$*" >&2; exit 1; }
warn() { printf 'sfab: warning: %s\n' "$*" >&2; }
utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }
utc_compact() { date -u +%Y%m%dT%H%M%SZ; }
have() { command -v "$1" >/dev/null 2>&1; }
py() { PYTHONDONTWRITEBYTECODE=1 python3 "$@"; }
inv() { py "$SFAB_COMMON/bin/inv.py" --inv "$INV" "$@"; }
tmpf() { mktemp "${SFAB_TMP:-${TMPDIR:-/tmp}}/sfab.XXXXXX"; }
urlencode() { py -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }

# ---------------------------------------------------------------------------------------------
# identity

_sfab_labdir() {
  local d=""
  if [ -n "${SFAB_LABDIR:-}" ]; then
    d="$SFAB_LABDIR"
  elif [ -f "$(dirname "$0")/chapter.yaml" ]; then
    d="$(dirname "$0")"
  elif [ -f "$PWD/chapter.yaml" ]; then
    d="$PWD"
  fi
  [ -n "$d" ] && [ -f "$d/chapter.yaml" ] || return 1
  (cd "$d" && pwd -P)
}

# One python pass over the inventory: shell assignments for the identity and the node tables.
_inv_env() {
  py - "$1" <<'PY'
import json, shlex, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
q = lambda v: shlex.quote("" if v is None else str(v))
nodes, order = d.get("nodes") or {}, d.get("order") or []
st, mg = d.get("stages") or {}, d.get("mgmt") or {}
out = []
for k, v in (("LAB", d.get("lab")), ("BUILD", d.get("build")), ("PROFILE", d.get("profile")), ("STATE", d.get("state")),
             ("STEP", d.get("step")), ("INV_PREFIX", d.get("prefix")), ("INV_CLABDIR", d.get("clabdir")),
             ("INV_VARIANT", d.get("variant")), ("MGMT_NET", mg.get("network")), ("MGMT_SUBNET", mg.get("subnet")),
             ("MGMT_GW", mg.get("gw")), ("MGMT_BRIDGE", mg.get("bridge")),
             ("LAB_RE", (d.get("naming") or {}).get("lab_re") or r"^sfab-(ch[0-9]{2}[a-z]?|m[0-9]+)$"),
             ("FW_NODE", st.get("fw")), ("BASTION", st.get("bastion")), ("KNODE", st.get("kubectl")),
             ("WAIT_FABRIC", st.get("wait_fabric") or "none"),
             ("GUEST_USER", (d.get("guest") or {}).get("user") or "admin"),
             ("SW_USER_DEFAULT", (d.get("switch") or {}).get("user") or "admin"),
             ("HOST_TICK_WANT", (d.get("host") or {}).get("tick") or 10000)):
    out.append(f"{k}={q(v)}")
for k in ("ca_init", "cluster", "serving", "storage_setup", "guest_hold", "fw_bootstrap"):
    out.append(f"STAGE_{k.upper()}={'1' if st.get(k) else '0'}")
for k, v in sorted((d.get("features") or {}).items()):
    out.append(f"FEATURE_{k.upper()}={'1' if v else '0'}")
arr = lambda name, xs: out.append(f"{name}=(" + " ".join(q(x) for x in xs) + ")")
arr("NODES", order)
arr("SWITCHES", st.get("switches") or [])
arr("GUESTS", st.get("guests") or [])
arr("PAIRS", st.get("pairs") or [])
arr("STORAGE", st.get("storage") or [])
arr("MODULES", st.get("modules") or [])
arr("WATCH_ORDER", (d.get("watchdog") or {}).get("order") or [])
arr("KNOWN_IDS", d.get("known") or [])
arr("GPU_GUESTS", [n for n in order if nodes[n].get("kind") == "vm-node" and nodes[n].get("group") == "gpu"])
arr("RELAY_GUESTS", [n for n in order if nodes[n].get("relay")])
for name, key in (("NODE_MGMT", "mgmt"), ("NODE_KIND", "kind"), ("NODE_CTR", "container"), ("NODE_ROLE", "role"),
                  ("NODE_GROUP", "group"), ("NODE_CLAB_KIND", "clab_kind"), ("NODE_SECTION", "section"),
                  ("NODE_IMAGE", "image"), ("NODE_K8S", "k8s"), ("NODE_NUM_NICS", "num_nics")):
    out.append(f"declare -gA {name}=(" + " ".join(f"[{q(n)}]={q(nodes[n].get(key))}" for n in order) + ")")
out.append("declare -gA NODE_ETHS=(" + " ".join(f"[{q(n)}]={q(' '.join(nodes[n].get('eths') or []))}" for n in order) + ")")
pm = {}
for n in order:
    if nodes[n].get("pair"):
        pm.setdefault(nodes[n]["pair"], []).append(n)
out.append("declare -gA PAIR_MEMBERS=(" + " ".join(f"[{q(p)}]={q(' '.join(m))}" for p, m in sorted(pm.items())) + ")")
for k, v in sorted((d.get("timeouts") or {}).items()):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        out.append(f"TO_{k.upper()}={q(v)}")
for k, v in sorted((d.get("harness") or {}).items()):
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        out.append(f"HN_{k.upper()}={q(v)}")
print("\n".join(out))
PY
}

# sfab_identity: print one problem per line (nothing when the identity holds).
sfab_identity() {
  local want_dir problems=() n
  [ -n "${LAB:-}" ] || { echo "the inventory names no lab"; return 0; }
  [[ "$LAB" =~ $LAB_RE ]] || problems+=("lab name $LAB does not match $LAB_RE")
  want_dir="sfab-$(basename "$LABDIR")${VARIANT:-}"
  [ "$LAB" = "$want_dir" ] || problems+=("lab $LAB does not belong in $LABDIR${VARIANT:+ (variant $VARIANT)}: expected $want_dir")
  [ "${INV_VARIANT:-}" = "${VARIANT:-}" ] || problems+=("the inventory is variant '${INV_VARIANT:-}', the run asks for '${VARIANT:-}'")
  if [ "$PREFIX" != "$LAB-" ] || [ "${INV_PREFIX:-}" != "$PREFIX" ]; then
    problems+=("container prefix ${INV_PREFIX:-unset} is not $LAB-")
  fi
  [ "${INV_CLABDIR:-}" = "clab-$LAB" ] || problems+=("containerlab directory ${INV_CLABDIR:-unset} is not clab-$LAB")
  case "${BUILD:-}" in
    A|B) [ "$MGMT_NET" = "sfab-$(printf '%s' "$BUILD" | tr 'AB' 'ab')-mgmt" ] || problems+=("management network $MGMT_NET is not build $BUILD's own") ;;
    *) problems+=("unknown build '${BUILD:-}'") ;;
  esac
  for n in "${NODES[@]}"; do
    [ "${NODE_CTR[$n]}" = "$PREFIX$n" ] || problems+=("node $n has container ${NODE_CTR[$n]}, not $PREFIX$n")
  done
  if [ -f "$TOPO" ]; then
    local tn tp
    tn="$(sed -n 's/^name:[[:space:]]*//p' "$TOPO" | head -n 1 | tr -d "\"'[:space:]")"
    tp="$(sed -n 's/^prefix:[[:space:]]*//p' "$TOPO" | head -n 1 | tr -d "\"'[:space:]")"
    [ "$tn" = "$LAB" ] || problems+=("topo.clab.yml names lab '$tn', not $LAB")
    [ "$tp" = "__lab-name" ] || problems+=("topo.clab.yml prefix is '$tp', not __lab-name")
  fi
  [ "${#problems[@]}" -eq 0 ] || printf '%s\n' "${problems[@]}"
}

# sfab_init CATEGORY [--quick] [--record|--no-record] [--set DIR] [--nodes a,b] [ARGS...]
# Categories audit, trace, label, matrix, drills, teardown, settle and break-* record a result set unless --no-record
# (--quick implies --no-record). Leftover arguments are in SFAB_ARGS.
sfab_init() {
  SFAB_CATEGORY="${1:?sfab_init needs a category}"
  shift
  SFAB_QUICK=0
  SFAB_ARGS=()
  SFAB_NODES=()
  local record="" set_dir="" a
  while [ $# -gt 0 ]; do
    a="$1"
    case "$a" in
      --quick) SFAB_QUICK=1 ;;
      --record) record=1 ;;
      --no-record) record=0 ;;
      --set) set_dir="${2:?--set needs a directory}"; shift ;;
      --nodes) IFS=',' read -r -a SFAB_NODES <<<"${2:?--nodes needs a list}"; shift ;;
      *) SFAB_ARGS+=("$a") ;;
    esac
    shift
  done
  LABDIR="$(_sfab_labdir)" || die "no lab directory: run from a lab directory (one holding chapter.yaml) or set SFAB_LABDIR"
  VARIANT="${VARIANT:-}"
  if [ -n "$VARIANT" ]; then
    [[ "$VARIANT" =~ ^[a-z][a-z0-9]*$ ]] || die "bad VARIANT '$VARIANT'"
    RENDERDIR="$LABDIR/variants/$VARIANT"
  else
    RENDERDIR="$LABDIR"
  fi
  INV="$RENDERDIR/gen/inventory.json"
  TOPO="$RENDERDIR/topo.clab.yml"
  STATEDIR="$RENDERDIR/state"
  [ -f "$INV" ] || die "no $INV: run make render"
  local envs
  envs="$(_inv_env "$INV")" || die "cannot read $INV"
  eval "$envs"
  PREFIX="$LAB-"
  CLABDIR="$RENDERDIR/clab-$LAB"
  export SFAB_LABDIR="$LABDIR" VARIANT SFAB_INV="$INV" SFAB_RENDERDIR="$RENDERDIR" SFAB_STATEDIR="$STATEDIR" CLABDIR
  export SFAB_KNOWN_IDS="${KNOWN_IDS[*]}"
  local problems
  problems="$(sfab_identity)"
  [ -z "$problems" ] || die "identity guard refuses this lab: $(printf '%s' "$problems" | paste -sd ';' -)"
  mkdir -p "$STATEDIR/run" "$STATEDIR/logs" "$STATEDIR/stage"
  SFAB_TMP="$STATEDIR/run"
  export SFAB_TMP
  SFAB_TICK_STAMP=""
  case "$SFAB_CATEGORY" in
    audit|trace|label|matrix|dbs|rpf|attach|drills|teardown|settle|break-*|heal-*) [ -n "$record" ] || record=1 ;;
    *) [ -n "$record" ] || record=0 ;;
  esac
  [ "$SFAB_QUICK" = 1 ] && [ "$record" = 1 ] && [ -z "$set_dir" ] && record=0
  RS="" RS_OWNER=0
  export RS_RECORD=0
  if [ -n "$set_dir" ]; then
    RS="$(cd "$set_dir" && pwd -P)" || die "no result set $set_dir"
    SFAB_VERDICT="$RS/verdict.txt"
    EVID="${EVID:-$RS/commands.txt}"
  elif [ "$record" = 1 ]; then
    _tick_gate
    rs_open "$SFAB_CATEGORY" "$RENDERDIR/audits"
    export RS_RECORD=1
  else
    case "$SFAB_CATEGORY" in
      audit|collect|dbs|rpf|attach) rs_open "$SFAB_CATEGORY" "$STATEDIR/run/sets" ;;
      *) SFAB_VERDICT="$(mktemp "$STATEDIR/run/verdict.$SFAB_CATEGORY.XXXXXX")" ;;
    esac
  fi
  export RS SFAB_VERDICT
  [ -z "${EVID:-}" ] || export EVID
}

# Read the host tick before recording and stamp the result set when it is not 10000 (FRAMEWORK.md
# 3.1). The tick is never a reason to refuse: another workload on a shared host can move it (any
# container holding CAP_SYS_TIME adjusts the one clock). SFAB_TICK_OVERRIDE is no longer needed.
_tick_gate() {
  local t rc=0
  t="$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null)" || rc=$?
  [ "$rc" -eq 0 ] && return 0
  SFAB_TICK_STAMP="host-tick: ${t:-unreadable}"
  warn "$SFAB_TICK_STAMP (recorded, not refused)"
  return 0
}

# ---------------------------------------------------------------------------------------------
# docker and containerlab, fenced to this lab

_refuse() { printf 'sfab: refusing: %s\n' "$*" >&2; exit 97; }

_own() {
  [[ "${PREFIX:-}" =~ ^sfab-[a-z0-9]+-$ ]] || _refuse "no lab prefix set"
  if [[ "$1" != "$PREFIX"* ]] || ! [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
    _refuse "container '$1' is not in lab $LAB (prefix $PREFIX)"
  fi
}

# dk SUBCOMMAND ARGS...: docker, with every container name checked against $PREFIX.
dk() {
  local sub="${1:-}"
  [ -n "$sub" ] || _refuse "dk with no subcommand"
  shift
  local args=("$@") i=0 a names=() need_val=""
  case "$sub" in
    ps|images|version|info) docker "$sub" "$@"; return ;;
    image) case "${1:-}" in inspect|ls) docker image "$@"; return ;; esac; _refuse "docker image ${1:-}" ;;
    network) case "${1:-}" in inspect|ls) docker network "$@"; return ;; esac; _refuse "docker network ${1:-}" ;;
    exec)
      while [ $i -lt ${#args[@]} ]; do
        a="${args[$i]}"
        case "$a" in
          -e|--env|-u|--user|-w|--workdir|--env-file|--detach-keys) i=$((i + 2)); continue ;;
          -*) i=$((i + 1)); continue ;;
          *) _own "$a"; docker exec "$@"; return ;;
        esac
      done
      _refuse "docker exec with no container" ;;
    cp)
      for a in "$@"; do
        case "$a" in -*) ;; *:*) _own "${a%%:*}"; names+=("$a") ;; esac
      done
      [ ${#names[@]} -eq 1 ] || _refuse "docker cp needs exactly one container:path"
      docker cp "$@"; return ;;
    inspect|logs|rm|stop|start|restart|kill|update|top|port|wait|stats)
      case "$sub" in
        inspect) need_val="-f --format --type" ;;
        logs) need_val="--since --until --tail -n" ;;
        stop|restart) need_val="-t --time -s --signal" ;;
        kill) need_val="-s --signal" ;;
        stats) need_val="--format" ;;
        update) need_val="ALL" ;;
      esac
      while [ $i -lt ${#args[@]} ]; do
        a="${args[$i]}"
        if [[ "$a" == -* ]]; then
          if [[ "$a" != *=* ]] && { [ "$need_val" = ALL ] || [[ " $need_val " == *" $a "* ]]; }; then
            i=$((i + 2))
          else
            i=$((i + 1))
          fi
          continue
        fi
        _own "$a"
        names+=("$a")
        [ "$sub" = top ] || [ "$sub" = port ] && break
        i=$((i + 1))
      done
      [ ${#names[@]} -gt 0 ] || _refuse "docker $sub with no container"
      docker "$sub" "$@"; return ;;
    *) _refuse "docker $sub is not something a lab script does" ;;
  esac
}

# clab deploy|destroy -t <this lab's topo.clab.yml> ...: never --cleanup, never --all. Its output
# passes through redact.py --stream: containerlab prints the output of any lab container that
# exited, and the TrueNAS launcher's output lists its environment, PASSWORD included. The status
# is containerlab's own.
clab() {
  local sub="${1:-}" a t=""
  shift || true
  case "$sub" in deploy|destroy) ;; *) _refuse "containerlab ${sub:-?}" ;; esac
  local args=("$@") i=0
  while [ $i -lt ${#args[@]} ]; do
    a="${args[$i]}"
    case "$a" in
      --cleanup|-c|--all|-a|--cleanup=*|--all=*) _refuse "containerlab $sub $a" ;;
      -t|--topo) t="${args[$((i + 1))]:-}"; i=$((i + 1)) ;;
      -t=*|--topo=*) t="${a#*=}" ;;
    esac
    i=$((i + 1))
  done
  if [ -z "$t" ] || [ "$(cd "$(dirname "$t")" && pwd -P)/$(basename "$t")" != "$TOPO" ]; then
    _refuse "containerlab $sub on '$t', not $TOPO"
  fi
  [ -z "$(sfab_identity)" ] || _refuse "the identity guard fails for $TOPO"
  local pipe_rc rc=0
  containerlab "$sub" "$@" 2>&1 |
    py "$SFAB_COMMON/audit/redact.py" --secrets "$STATEDIR/secrets.env" --key "$STATEDIR/secrets/redact.key" --stream ||
    { pipe_rc=("${PIPESTATUS[@]}"); rc=${pipe_rc[0]}; }
  return "$rc"
}

ctr() { printf '%s\n' "${NODE_CTR[$1]:?no node $1 in $LAB}"; }
node_mgmt() { printf '%s\n' "${NODE_MGMT[$1]:?no node $1 in $LAB}"; }

# state_of NODE: "<StartedAt> <Running>" or "missing".
state_of() {
  local c
  c="$(ctr "$1")"
  dk inspect -f '{{.State.StartedAt}} {{.State.Running}}' "$c" 2>/dev/null || echo missing
}
running() { [ "$(dk inspect -f '{{.State.Running}}' "$(ctr "$1")" 2>/dev/null || true)" = true ]; }
health_of() { dk inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$(ctr "$1")" 2>/dev/null || echo missing; }
pid_of() { dk inspect -f '{{.State.Pid}}' "$(ctr "$1")" 2>/dev/null || echo 0; }

# lab_containers: every container on the host whose name starts with this lab's prefix.
lab_containers() {
  local c
  while read -r c; do
    if [[ "$c" == "$PREFIX"* ]]; then printf '%s\n' "$c"; fi
  done < <(dk ps -a --format '{{.Names}}')
}

all_running() { local n; for n in "${NODES[@]}"; do running "$n" || return 1; done; }
any_exists() { [ -n "$(lab_containers)" ]; }

# _link_up IFNAME "ip -o link output": the interface exists with UP and LOWER_UP among its flags.
_link_up() {
  local line flags
  line="$(printf '%s\n' "$2" | grep -E "^[0-9]+: $1(@[^:]*)?: <" | head -n 1)"
  [ -n "$line" ] || return 1
  flags="${line#*<}"
  flags=",${flags%%>*},"
  [[ "$flags" == *",UP,"* ]] && [[ "$flags" == *",LOWER_UP,"* ]]
}

# links_intact: every expected ethN exists and is up in every container (FRAMEWORK 3.2).
links_intact() {
  local n pid links e bad=0
  for n in "${NODES[@]}"; do
    pid="$(pid_of "$n")"
    if [ -z "$pid" ] || [ "$pid" = 0 ]; then
      printf 'links: %s is not running\n' "$n" >&2
      bad=1
      continue
    fi
    links="$(nsenter -t "$pid" -n ip -o link show 2>/dev/null || true)"
    for e in ${NODE_ETHS[$n]}; do
      if ! _link_up "$e" "$links"; then
        printf 'links: %s %s is missing or down\n' "$n" "$e" >&2
        bad=1
      fi
    done
  done
  return "$bad"
}

host_lock() {
  mkdir -p "$(dirname "$SFAB_HOST_LOCK")"
  exec 9>"$SFAB_HOST_LOCK"
  flock -w "${SFAB_HOST_LOCK_WAIT:-120}" 9 || die "another sfab lab holds $SFAB_HOST_LOCK"
}
host_unlock() { exec 9>&-; }

# ---------------------------------------------------------------------------------------------
# credentials: read from the node's own container (what containerlab passed), never stored

declare -gA _CRED_U=() _CRED_P=()
# _creds NODE: sets CRED_USER and CRED_PASS for the node.
_creds() {
  local n="$1" c out
  if [ -z "${_CRED_U[$n]:-}" ]; then
    c="$(ctr "$n")"
    out="$(dk inspect -f '{{json .Config}}' "$c" | py -c '
import json, sys
cfg = json.load(sys.stdin)
cmd, env = cfg.get("Cmd") or [], dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)
def arg(name):
    for i, a in enumerate(cmd):
        if a == name and i + 1 < len(cmd):
            return cmd[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None
print(arg("--username") or env.get("USERNAME") or "")
print(arg("--password") or env.get("PASSWORD") or "")
')" || return 1
    _CRED_U[$n]="$(printf '%s\n' "$out" | sed -n 1p)"
    _CRED_P[$n]="$(printf '%s\n' "$out" | sed -n 2p)"
  fi
  CRED_USER="${_CRED_U[$n]:-$SW_USER_DEFAULT}"
  CRED_PASS="${_CRED_P[$n]}"
  [ -n "$CRED_PASS" ] || { warn "no password in $n's container"; return 1; }
}

lab_key() { printf '%s\n' "$STATEDIR/secrets/lab_ed25519"; }

_SSH_BASE=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=10
  -o ServerAliveInterval=15 -o ServerAliveCountMax=4)
# shellcheck disable=SC2054 # the comma belongs to the ssh option value
_SSH_PW=("${_SSH_BASE[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive
  -o NumberOfPasswordPrompts=1)

# ---------------------------------------------------------------------------------------------
# the evidence transcript

_evid() {
  [ -n "${EVID:-}" ] && [ "${EVID_OFF:-0}" != 1 ] || return 0
  local block
  block="### $(utc) $1 $2"$'\n'"$3"$'\n\n'
  printf '%s' "$block" >>"$EVID"
  if [ -n "${4:-}" ] && [ -n "${RS:-}" ] && [ -d "$RS/raw" ]; then
    local f
    f="$(mktemp "$RS/raw/$1-$2-XXXXXX")"
    printf '%s' "$4" >"$f"
    mv "$f" "$f.txt"
  fi
}

_clean_session() { tr -d '\r' | sed -e $'s/\x1b\\[[0-9;?]*[A-Za-z]//g' -e $'s/.\x08//g' | grep -v '^Connection to .* closed\.$' || true; }

# _cap NODE SURFACE SHOWN ARGV...: run, print stdout, record stdout and stderr in the transcript.
# _CAP_SSHPASS, when set, is exported to the command only.
_cap() {
  local node="$1" surface="$2" shown="$3" err out e rc=0
  shift 3
  err="$(tmpf)"
  out="$(
    if [ -n "${_CAP_SSHPASS:-}" ]; then SSHPASS="$_CAP_SSHPASS"; export SSHPASS; fi
    "$@" 2>"$err"
  )" || rc=$?
  e="$(cat "$err")"
  rm -f "$err"
  _evid "$node" "$surface" "+ $shown"$'\n'"$out${e:+$'\n'$e}"
  [ -z "$out" ] || printf '%s\n' "$out"
  [ -z "$e" ] || printf '%s\n' "$e" >&2
  return "$rc"
}

# _session NODE SURFACE INPUT ARGV...: an interactive ssh -tt session fed INPUT; prints it cleaned.
# The session runs with no TERM, as it does under a systemd unit, whatever terminal started the
# run: under a terminal type (tmux's screen, xterm, vt100) the PAN-OS CLI redraws its echo of
# each word on one line with ESC [K, and the splitter then finds no command (ch04/RESULTS.md, problem 4).
# With _SESSION_PACE=S the input goes one line at a time, S seconds apart, for a prompt that drops
# what was typed ahead of it: once KLISH's confirmation of clear counters is answered, the session's
# exit typed ahead of it is never read, and the session waits out its timeout (chapter 1's trace).
_paced() {
  local l first=1
  while IFS= read -r l; do
    [ "$first" = 1 ] || sleep "$1"
    first=0
    printf '%s\n' "$l"
  done <<<"$2"
}

_session() {
  local node="$1" surface="$2" input="$3" raw clean rc=0
  shift 3
  raw="$(
    if [ -n "${_CAP_SSHPASS:-}" ]; then SSHPASS="$_CAP_SSHPASS"; export SSHPASS; fi
    if [ -n "${_SESSION_PACE:-}" ]; then
      _paced "$_SESSION_PACE" "$input" | timeout "${SFAB_SESSION_TIMEOUT:-600}" env -u TERM "$@" 2>&1
    else
      timeout "${SFAB_SESSION_TIMEOUT:-600}" env -u TERM "$@" <<<"$input" 2>&1
    fi
  )" || rc=$?
  clean="$(printf '%s\n' "$raw" | _clean_session)"
  _evid "$node" "$surface" "$clean" "$raw"
  [ "$rc" -ne 5 ] || warn "$node: sshpass exit 5, the password was refused"
  printf '%s\n' "$clean"
  return "$rc"
}

# ---------------------------------------------------------------------------------------------
# device runners

_klish_line_ok() {
  case "$1" in
    *'?'*) warn "KLISH line with '?' refused: $1"; return 1 ;;
  esac
  if [[ "$1" =~ \|[[:space:]]*grep[[:space:]]+(-E|.*[\"\']) ]]; then
    warn "KLISH grep -E or a quoted pattern refused: $1"
    return 1
  fi
}

SW() {
  local sw="$1" l input
  shift
  for l in "$@"; do _klish_line_ok "$l" || return 2; done
  _creds "$sw" || return 2
  input="$(printf 'terminal length 0\n'; printf '%s\n' "$@"; printf 'exit\n')"
  _CAP_SSHPASS="$CRED_PASS" _session "$sw" klish "$input" \
    sshpass -e ssh -tt "${_SSH_PW[@]}" "$CRED_USER@$(node_mgmt "$sw")" sonic-cli
}

# VT and SH run one command with ssh -n: ssh must not read the caller's stdin (collect.sh reads
# its plan from there, and a plain ssh swallowed the rest of it).
VT() {
  local sw="$1"
  shift
  _creds "$sw" || return 2
  _CAP_SSHPASS="$CRED_PASS" _cap "$sw" vtysh "vtysh -c '$*'" \
    timeout "${SFAB_CMD_TIMEOUT:-300}" sshpass -e ssh -n "${_SSH_PW[@]}" "$CRED_USER@$(node_mgmt "$sw")" "sudo vtysh -c $(printf '%q' "$*")"
}

SH() {
  local sw="$1"
  shift
  _creds "$sw" || return 2
  _CAP_SSHPASS="$CRED_PASS" _cap "$sw" shell "$*" \
    timeout "${SFAB_CMD_TIMEOUT:-300}" sshpass -e ssh -n "${_SSH_PW[@]}" "$CRED_USER@$(node_mgmt "$sw")" "$*"
}

FW() {
  local fw="${FW_NODE:-}" input
  [ -n "$fw" ] || { warn "no firewall in $LAB"; return 2; }
  _creds "$fw" || return 2
  # No scripting mode: with it on, PAN-OS stops echoing each command after its prompt, and the
  # splitter (judge.py split) finds a command's output by that echo.
  input="$(printf 'set cli pager off\n'; printf '%s\n' "$@"; printf 'exit\n')"
  _CAP_SSHPASS="$CRED_PASS" _session "$fw" panos-cli "$input" \
    sshpass -e ssh -tt "${_SSH_PW[@]}" "$CRED_USER@$(node_mgmt "$fw")"
}

# fw_key_header: the path of a 0600 file holding "X-PAN-KEY: <key>", made by keygen on first use
# and remade when the firewall container restarts. The password travels in a 0600 request body.
fw_key_header() {
  local fw="${FW_NODE:-}" dir hdr stamp now body resp key
  [ -n "$fw" ] || return 2
  dir="$STATEDIR/secrets"
  hdr="$dir/fw-api.hdr"
  stamp="$dir/fw-api.started"
  now="$(state_of "$fw")"
  if [ -s "$hdr" ] && [ "$(cat "$stamp" 2>/dev/null || true)" = "$now" ]; then
    printf '%s\n' "$hdr"
    return 0
  fi
  _creds "$fw" || return 2
  mkdir -p "$dir"
  chmod 700 "$dir"
  body="$(umask 077; mktemp "$dir/.keygen.XXXXXX")"
  printf 'user=%s&password=%s' "$(urlencode "$CRED_USER")" "$(urlencode "$CRED_PASS")" >"$body"
  resp="$(curl -sk --max-time 60 --data "@$body" "https://$(node_mgmt "$fw")/api/?type=keygen" 2>/dev/null || true)"
  rm -f "$body"
  key="$(printf '%s' "$resp" | sed -n 's:.*<key>\([^<]*\)</key>.*:\1:p' | head -n 1)"
  [ -n "$key" ] || { warn "firewall keygen failed"; return 1; }
  (umask 077; printf 'X-PAN-KEY: %s\n' "$key" >"$hdr"; printf '%s\n' "$now" >"$stamp")
  printf '%s\n' "$hdr"
}

# FWX XML [TYPE]: a PAN-OS XML API request (type op by default), the key in the X-PAN-KEY header.
FWX() {
  local xml="$1" type="${2:-op}" hdr fw="${FW_NODE:-}"
  hdr="$(EVID_OFF=1 fw_key_header)" || return 2
  _cap "$fw" xml-api "GET /api/?type=$type&cmd=$xml" \
    curl -sk --max-time 120 -H "@$hdr" "https://$(node_mgmt "$fw")/api/?type=$type&cmd=$(urlencode "$xml")"
}

_ssh_guest() {
  local key
  key="$(lab_key)"
  [ -f "$key" ] || { warn "no lab key at $key (preflight creates it)"; return 2; }
  timeout "${SFAB_CMD_TIMEOUT:-300}" ssh -n "${_SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$key" "$@"
}

H() {
  local n="$1"
  shift
  _cap "$n" guest "$*" _ssh_guest "$GUEST_USER@$(node_mgmt "$n")" "sudo bash -c $(printf '%q' "$*")"
}

# HBG NODE CMD: start CMD in the guest in the background (setsid, stdin from /dev/null).
HBG() {
  local n="$1"
  shift
  _cap "$n" guest "setsid $* &" _ssh_guest "$GUEST_USER@$(node_mgmt "$n")" \
    "sudo setsid bash -c $(printf '%q' "$*") </dev/null >/dev/null 2>&1 &"
}

X() {
  local n="$1" c
  shift
  c="$(ctr "$n")"
  _cap "$n" container "$*" dk exec "$c" "$@"
}

# The cluster's admin kubeconfig, where kubeadm wrote it on the init node; it never leaves it.
KADMIN="${SFAB_KUBECONFIG_ADMIN:-/etc/kubernetes/admin.conf}"

_ssh_guest_in() {  # as _ssh_guest, with this shell's stdin passed on
  local key
  key="$(lab_key)"
  [ -f "$key" ] || { warn "no lab key at $key (preflight creates it)"; return 2; }
  timeout "${SFAB_CMD_TIMEOUT:-300}" ssh "${_SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$key" "$@"
}

_knode() { [ -n "${KNODE:-}" ] || { warn "no Kubernetes init node in $LAB: kubectl runs there"; return 2; }; }

K() {
  _knode || return 2
  _cap "$KNODE" kubectl "kubectl $*" _ssh_guest "$GUEST_USER@$(node_mgmt "$KNODE")" \
    "sudo env KUBECONFIG=$KADMIN kubectl $(printf '%q ' "$@")"
}

KI() {
  _knode || return 2
  _cap "$KNODE" kubectl "kubectl $*" _ssh_guest_in "$GUEST_USER@$(node_mgmt "$KNODE")" \
    "sudo env KUBECONFIG=$KADMIN kubectl $(printf '%q ' "$@")"
}

KSH() {
  _knode || return 2
  _cap "$KNODE" kubectl "$1" _ssh_guest "$GUEST_USER@$(node_mgmt "$KNODE")" \
    "sudo env KUBECONFIG=$KADMIN PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin bash -c $(printf '%q' "$1")"
}

KSHI() {
  _knode || return 2
  _cap "$KNODE" kubectl "$1" _ssh_guest_in "$GUEST_USER@$(node_mgmt "$KNODE")" \
    "sudo env KUBECONFIG=$KADMIN PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin bash -c $(printf '%q' "$1")"
}

FR() {
  local r="$1"
  shift
  _cap "$r" frr "vtysh -c '$*'" dk exec "$(ctr "$r")" vtysh -c "$*"
}

# klish_body CMD: from a KLISH session on stdin, the output of CMD without its prompt line.
klish_body() { py "$SFAB_COMMON/audit/judge.py" body --style klish --command "$1"; }

# retry1 ARGV...: run, and once more after a pause (the first packets of a new flow are lost to ARP).
retry1() { "$@" && return 0; sleep "${SFAB_RETRY_PAUSE:-2}"; "$@"; }
# pchk LABEL ARGV...: PASS when the probe succeeds within one retry.
pchk() {
  local label="$1"
  shift
  if retry1 "$@" >/dev/null 2>&1; then ok "$label"; else bad "$label" "failed twice"; fi
}

# ---------------------------------------------------------------------------------------------
# the result vocabulary (FRAMEWORK.md 4.2; vocab.py prints the same lines)

_one() { printf '%s' "$*" | tr '\n\t' '  ' | tr -s ' ' | sed -e 's/^ //' -e 's/ $//'; }
_vline() {
  printf '%s\n' "$1"
  [ -z "${SFAB_VERDICT:-}" ] || printf '%s\n' "$1" >>"$SFAB_VERDICT"
}
sec() { _vline "== $(_one "$*")"; }
ok() { _vline "  PASS  $(_one "$*")"; }
bad() {
  local l d
  l="$(_one "$1")"
  shift
  d="$(_one "$*")"
  _vline "  FAIL  $l${d:+ -> $d}"
  return 0
}
skip() {
  local l r
  l="$(_one "$1")"
  shift
  r="$(_one "$*")"
  _vline "  SKIP  $l${r:+ ($r)}"
}
# not_run SKIP_LABEL FAIL_LABEL REASON: a check that could not run without the author's lists is a
# SKIP, or a FAIL when SFAB_REQUIRE_NAMECHECK is set (not empty and not 0), which marks a run that
# must not pass without them (FRAMEWORK.md 4.4; the gate and the audit's namecheck use it)
not_run() {
  case "${SFAB_REQUIRE_NAMECHECK:-}" in
    '' | 0) skip "$1" "$3" ;;
    *) bad "$2" "$3, and SFAB_REQUIRE_NAMECHECK is set" ;;
  esac
}
known() {
  local id="$1"
  shift
  if [[ " ${KNOWN_IDS[*]:-} " != *" $id "* ]]; then
    bad "$*" "KNOWN id $id is not in spec/known.yaml"
    return 0
  fi
  _vline "  KNOWN $(_one "$*"): $id"
}
chk() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want $2, got $3"; fi; }
ge() {
  if [[ "$3" =~ ^-?[0-9]+$ ]] && [[ "$2" =~ ^-?[0-9]+$ ]] && [ "$3" -ge "$2" ]; then ok "$1"; else bad "$1" "want >= $2, got $3"; fi
}
# check LABEL DETAIL ARGV...: PASS when ARGV succeeds, else FAIL with DETAIL.
check() {
  local l="$1" d="$2"
  shift 2
  if "$@"; then ok "$l"; else bad "$l" "$d"; fi
}

vcounts() {
  awk '/^  PASS  /{p++} /^  FAIL  /{f++} /^  KNOWN /{k++} /^  SKIP  /{s++} END{printf "%d %d %d %d\n", p, f, k, s}' "${1:-$SFAB_VERDICT}" 2>/dev/null || echo "0 0 0 0"
}
fails_now() { local p f k s; read -r p f k s <<<"$(vcounts "$SFAB_VERDICT")"; printf '%s\n' "$f"; }

# summary: the RESULT line; closes the result set this process opened; non-zero on any FAIL.
summary() {
  local p f k s
  read -r p f k s <<<"$(vcounts "$SFAB_VERDICT")"
  [ -z "${SFAB_TICK_STAMP:-}" ] || _vline "== $SFAB_TICK_STAMP"
  _vline "== RESULT: $p passed, $f failed, $k known platform limitation(s), $s skipped"
  if [ -n "${RS:-}" ] && [ "${RS_OWNER:-0}" = 1 ]; then rs_close; fi
  [ "$f" -eq 0 ]
}

# ---------------------------------------------------------------------------------------------
# stage markers (FRAMEWORK.md 3): state/stage/<stage>.<step>.ok holds the render hash and every
# container's StartedAt; a step whose marker matches is skipped.

render_hash() {
  py - "$RENDERDIR/gen/RENDER.json" <<'PY'
import hashlib, json, sys
try:
    d = json.load(open(sys.argv[1], encoding="utf-8"))
except (OSError, ValueError):
    print("none")
    raise SystemExit(0)
d.pop("generator", None)
print(hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest())
PY
}

marker_text() {
  local n
  printf 'render %s\n' "$(render_hash)"
  for n in "${NODES[@]}"; do printf '%s %s\n' "${NODE_CTR[$n]}" "$(state_of "$n")"; done
}

# stage_step STAGE STEP ARGV...: skip when the marker matches; else run, and write the marker on
# success. ARGV returning 3 means it could not judge (a missing tool): success, no marker.
stage_step() {
  local st="$1" step="$2" f want rc=0 t0=$SECONDS
  shift 2
  f="$STATEDIR/stage/$st.$step.ok"
  want="$(marker_text)"
  if [ -f "$f" ] && [ "$(cat "$f")" = "$want" ]; then
    printf '  marker  %s.%s matches; nothing to do\n' "$st" "$step"
    return 0
  fi
  rm -f "$f"
  "$@" || rc=$?
  if [ "$rc" -eq 3 ]; then
    printf '  step    %s.%s ran without a verdict; no marker written\n' "$st" "$step"
    return 0
  fi
  if [ "$rc" -ne 0 ]; then
    printf '  step    %s.%s failed after %ss (exit %s)\n' "$st" "$step" "$((SECONDS - t0))" "$rc"
    return "$rc"
  fi
  marker_text >"$f"
  printf '  step    %s.%s done in %ss\n' "$st" "$step" "$((SECONDS - t0))"
}

# ---------------------------------------------------------------------------------------------
# result sets (FRAMEWORK.md 4.4)

rs_open() {
  local cat="$1" base="$2"
  RS_TS="$(utc_compact)"
  RS="$base/${LAB}_${cat}_${RS_TS}"
  [ ! -e "$RS" ] || { sleep 1; RS_TS="$(utc_compact)"; RS="$base/${LAB}_${cat}_${RS_TS}"; }
  mkdir -p "$RS/raw"
  RS_OWNER=1
  SFAB_VERDICT="$RS/verdict.txt"
  EVID="$RS/commands.txt"
  : >"$SFAB_VERDICT"
  : >"$EVID"
  RS_START="$(utc)"
  RS_REPO=""
  export RS SFAB_VERDICT EVID
  _run_json
  if [ "$base" = "$STATEDIR/run/sets" ]; then
    # keep the three newest scratch sets, newest by the UTC stamp that ends each name (a sort on the
    # whole name put an audit set behind older dbs sets and removed the set just opened)
    local d old=()
    mapfile -t old < <(find "$base" -mindepth 1 -maxdepth 1 -type d -name "${LAB}_*" | awk -F_ '{ print $NF "\t" $0 }' | sort | cut -f2-)
    old=("${old[@]/#$RS/}")
    local keep=()
    for d in "${old[@]}"; do [ -n "$d" ] && keep+=("$d"); done
    old=("${keep[@]+"${keep[@]}"}")
    # the set just opened is kept whatever its name, and the two newest others beside it
    while [ ${#old[@]} -gt 2 ]; do
      d="${old[0]}"
      old=("${old[@]:1}")
      [ "$(dirname "$d")" = "$base" ] && rm -rf -- "$d"
    done
  fi
}

# RUN.json: lab, labs-repo commit with its dirty flag and source, spec and render sha256, image
# digests, containerlab version, host tick, UTC start and end, stage durations (FRAMEWORK.md 4.4).
_run_json() {
  local clabv tick
  # The labs commit, read once when the set opens: from git, from SFAB_REPO_COMMIT and
  # SFAB_REPO_DIRTY, or from the stamp a copy without .git carries (common/bin/repostate.py).
  # With none of them commit is none and dirty null; a failure must not end the run.
  [ -n "${RS_REPO:-}" ] || RS_REPO="$(py "$SFAB_COMMON/bin/repostate.py" show "$SFAB_ROOT" || true)"
  clabv="$(containerlab version 2>/dev/null | sed -n 's/^[[:space:]]*version:[[:space:]]*//p' | head -n 1 || true)"
  tick="$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null || true)"
  RUN_REPO="$RS_REPO" RUN_CLAB="$clabv" RUN_TICK="$tick" RUN_START="${RS_START:-}" \
    RUN_END="${RS_END:-}" RUN_CATEGORY="$SFAB_CATEGORY" RUN_STAMP="${SFAB_TICK_STAMP:-}" \
    py - "$RS/RUN.json" "$RENDERDIR" "$STATEDIR" "$LAB" <<'PY'
import json, os, sys
out, render, state, lab = sys.argv[1:5]
def load(p):
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return None
rj = load(os.path.join(render, "gen", "RENDER.json")) or {}
import hashlib
try:
    rsha = hashlib.sha256(open(os.path.join(render, "gen", "RENDER.json"), "rb").read()).hexdigest()
except OSError:
    rsha = None
e = os.environ
try:
    repo = json.loads(e.get("RUN_REPO") or "{}")
except ValueError:
    repo = {}
repo = repo if isinstance(repo, dict) else {}
data = {
    "lab": lab,
    "category": e.get("RUN_CATEGORY"),
    "labs_repo": {"commit": repo.get("commit") or "none",
                  "dirty": repo.get("dirty") if isinstance(repo.get("dirty"), bool) else None,
                  "source": repo.get("source")},
    "spec_sha256": (rj.get("spec") or {}).get("sha256"),
    "render_sha256": rsha,
    "images": load(os.path.join(state, "images.json")) or {},
    "containerlab": e.get("RUN_CLAB") or None,
    "host_tick": int(e["RUN_TICK"]) if (e.get("RUN_TICK") or "").isdigit() else None,
    "host_tick_stamp": e.get("RUN_STAMP") or None,
    "utc_start": e.get("RUN_START") or None,
    "utc_end": e.get("RUN_END") or None,
    "stage_durations_s": load(os.path.join(state, "stage", "durations.json")) or {},
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, sort_keys=True)
    f.write("\n")
PY
}

rs_close() {
  RS_END="$(utc)"
  _run_json
  {
    printf 'lab: %s\ncategory: %s\nset: %s\nutc: %s to %s\n' "$LAB" "$SFAB_CATEGORY" "$(basename "$RS")" "$RS_START" "$RS_END"
    [ -z "${SFAB_TICK_STAMP:-}" ] || printf '%s\n' "$SFAB_TICK_STAMP"
    grep -E '^== RESULT: ' "$SFAB_VERDICT" | tail -n 1
  } >"$RS/RESULT.txt"
  find "$RS/raw" -type d -empty -delete 2>/dev/null || true
  redact "$RS"
  # the size policy (FRAMEWORK.md 4.4): large XML and JSON, and a transcript over the text cap,
  # stored compressed once every reader in the run is done with them
  py "$SFAB_COMMON/audit/setsize.py" pack "$RS" >/dev/null || warn "setsize pack: $RS kept some files plain"
  printf '== result set: %s\n' "${RS#"$SFAB_ROOT"/}"
  RS_OWNER=0
}

# redact SET: replace Authorization values, key= parameters, X-PAN-KEY values, set-format secret
# lines, PEM private-key blocks and every value in state/secrets.env, in every text file of SET.
# A redacted value leaves its presence and a prefix of its HMAC under the lab's redaction key
# (state/secrets/redact.key) behind. The lab host's kernel release, which the containers print as
# their own, becomes [redacted: host-kernel], the PA-VM's CPU signature [redacted: host-cpuid] and a
# measured throughput figure [redacted: throughput], each listed in the set's REDACTIONS.md
# (FRAMEWORK.md 4.3).
redact() { py "$SFAB_COMMON/audit/redact.py" --secrets "$STATEDIR/secrets.env" --key "$STATEDIR/secrets/redact.key" "$1"; }

# ---------------------------------------------------------------------------------------------
# audits (FRAMEWORK.md 4.4): collection from common/audit/cmds/, judgment from the saved files

audit_collect() {
  local args=(--set "$RS")
  [ "$SFAB_QUICK" = 1 ] && args+=(--quick)
  [ "${#SFAB_NODES[@]}" -eq 0 ] || args+=(--nodes "$(IFS=,; printf '%s' "${SFAB_NODES[*]}")")
  [ $# -eq 0 ] || args+=(--nodes "$(IFS=,; printf '%s' "$*")")
  local rc=0
  "$SFAB_COMMON/audit/collect.sh" "${args[@]}" || rc=$?
  [ "$rc" -le 1 ] || bad "collection" "collect.sh exited $rc"
}

_judge() {
  local rc=0
  py "$SFAB_COMMON/audit/judge.py" run --set "$RS" --inv "$INV" --render "$RENDERDIR" "$@" || rc=$?
  [ "$rc" -le 1 ] || bad "judge $1" "judge.py exited $rc"
}

_in_set() { local n; for n in "$@"; do [ -d "$RS/$n" ] && printf '%s\n' "$n"; done; true; }

# audit_judge: the shared checks every lab gets, then the firewall, guests and rails it holds.
audit_judge() {
  local sws fws gs rs
  mapfile -t sws < <(_in_set "${SWITCHES[@]}")
  mapfile -t fws < <(_in_set ${FW_NODE:+"$FW_NODE"})
  mapfile -t gs < <(_in_set "${GUESTS[@]}")
  mapfile -t rs < <(_in_set "${RELAY_GUESTS[@]}")
  if [ ${#sws[@]} -gt 0 ]; then
    _judge shared "${sws[@]}"
    _judge vlans "${sws[@]}"
    _judge mac-tables "${sws[@]}"
  fi
  [ ${#fws[@]} -eq 0 ] || _judge firewall "${fws[@]}"
  [ ${#gs[@]} -eq 0 ] || _judge guests "${gs[@]}"
  [ ${#rs[@]} -eq 0 ] || _judge rails "${rs[@]}"
}

audit_forwarding_only() { _judge forwarding-only "$@"; }
audit_mclag_pair() { _judge mclag-pair "$@"; }
audit_l2_hygiene() { _judge l2-hygiene "$@"; }
audit_firewall() { _judge firewall "$@"; }
audit_guests() { _judge guests "$@"; }
audit_rails() { _judge rails "$@"; }

# audit_preflight: the last preflight's lines, then the checks that can change since (the tick,
# other labs), read now without side effects.
audit_preflight() {
  local last="$STATEDIR/preflight.last" l
  if [ -f "$last" ]; then
    sec "preflight, as run at $(sed -n 's/^# preflight //p' "$last" | head -n 1)"
    while IFS= read -r l; do
      case "$l" in "  PASS  "*|"  FAIL  "*|"  SKIP  "*|"  KNOWN "*) _vline "$l" ;; esac
    done <"$last"
  else
    sec "preflight"
    bad "preflight record" "no $last: run make up"
  fi
  # shellcheck source=common/stages/preflight.sh
  SFAB_PF_LIB=1 . "$SFAB_COMMON/stages/preflight.sh"
  sec "preflight, read again now"
  pf_tick
  pf_other_labs
}

# audit_clean: namecheck and sfab check (M1 exit criterion 9).
audit_clean() {
  local out rc=0
  sec "repository"
  mkdir -p "$RS/repo"
  out="$(py "$SFAB_COMMON/tools/namecheck.py" --mask 2>&1)" || rc=$?
  # The saved file keeps the fail lines and the summary, not the warnings. A warning quotes the
  # line it matched, so saving them quoted every earlier set's saved list again, and the file
  # doubled with each audit (M1: 19 lines in its first set, 19439 in its tenth). --mask prints
  # each hit without the text it matched, so no saved file quotes a scrubbed name (chapter 3's
  # RESULTS.md, problem 1: a quoted hit failed every later audit on the set that saved it).
  printf '%s\n' "$out" | grep -v ': warn ' >"$RS/repo/namecheck.txt" || true
  # exit 3: no scrub list ($SFAB_SCRUB_LIST), so the check did not run: a SKIP, not a FAIL, unless
  # SFAB_REQUIRE_NAMECHECK is set (not_run)
  case "$rc" in
    0) ok "namecheck clean" ;;
    3) not_run "namecheck" "namecheck clean" "no scrub list" ;;
    *) bad "namecheck clean" "$(printf '%s\n' "$out" | tail -n 1)" ;;
  esac
  rc=0
  out="$("$SFAB_COMMON/bin/sfab" check "$LABDIR" ${VARIANT:+--variant "$VARIANT"} 2>&1)" || rc=$?
  printf '%s\n' "$out" >"$RS/repo/sfab-check.txt"
  case "$rc" in
    0) ok "sfab check clean" ;;
    3) skip "sfab check" "PyYAML is not installed on this host" ;;
    *) bad "sfab check clean" "$(printf '%s\n' "$out" | grep -v '^sfab: warning' | head -n 1)" ;;
  esac
}
