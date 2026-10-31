#!/usr/bin/env bash
# panos.sh: the PA-VM's CLI over ssh, for audits, traces and the boot stage's enforced check.
#
#   panos.sh [--lab DIR] cli '<command>' ['<command>' ...]   operational commands, their output only
#   panos.sh [--lab DIR] session '<command>' ...             the same, as the session printed it
#   panos.sh [--lab DIR] running-set                         the configuration in set format, secrets hidden
#   panos.sh [--lab DIR] enforced [FILE]                     is every line of bootstrap/fw/enforced.txt there?
#   panos.sh [--lab DIR] login                               which credential source the firewall takes
#
# DIR is the lab directory (default $SFAB_LABDIR, else the current directory). The firewall's
# management address and container come from DIR/gen/inventory.json (or $SFAB_INV) through
# common/bin/inv.py; SFAB_FW_HOST overrides the address.
#
# Sessions are `ssh -tt` under `sshpass -e`, with no TERM (under a terminal type the CLI redraws
# its echo with ESC [K): `set cli pager off`, the commands, then `exit`, piped in. Configuration
# changes do not go through here: `configure` and `commit` are refused, and live changes use
# common/fw/fw-api.sh (the 12.1.2 CLI refuses set syntax for static routes).
# `show log` is refused without a time filter (`receive_time in ...` or `start-time equal ...`),
# because an unfiltered log read blocks every CLI session. A bare `?` is refused.
#
# running-set types `set cli config-output-format set`, `configure`, `show`. That prints the
# candidate, which is the running configuration whenever no change is pending (after a clean
# startup commit, and after every fw-api.sh commit).
#
# enforced compares after removing trailing spaces and folding runs of spaces (PAN-OS prints an
# address entry with a trailing space). The number of reads and the pause between them come from
# the inventory's timeouts (fw_enforced_tries, fw_enforced_pause_s); PANOS_TRIES and PANOS_PAUSE
# override them.
#
# Credentials, in order; a source the firewall refuses (sshpass exit 5) falls through to the next:
#   env        SFAB_FW_PASSWORD (and SFAB_FW_USER, default admin), only when the operator exports
#              it: an explicit override. Nothing generates it and no file is read for it.
#   container  the --username and --password containerlab gave the firewall container's launcher
#              on its command line, which is the paloalto_panos kind's default login; else USERNAME
#              and PASSWORD of the container's environment. Read with docker inspect, as
#              common/klish/session.sh and lib.sh's _creds read a switch's. The launcher never
#              reads its environment for the login (the M1 deploy, dev/m1/RESULTS.md, problem 4).
# The values stay in shell variables. The password reaches sshpass through its environment, never
# a command line, and nothing prints it. The first source taken is kept in PAN_SRC.
#
# Transcripts: with EVID=<file> set and EVID_OFF unset, cli, session and running-set append one
# block: a "### <UTC> <node> panos-cli" header line, then the session as the firewall printed it.
#
# Exit status: 0 ok; 1 a check failed or the session failed; 2 usage; 5 no credential source taken.
#
# Sourcing this file defines the pan_* functions and runs nothing; fw-api.sh does that.

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    set -euo pipefail
fi

PAN_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAN_INVPY="${PAN_HERE}/../bin/inv.py"
PAN_SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o LogLevel=ERROR -o PubkeyAuthentication=no)
PAN_SRC="${PAN_SRC:-}"
PAN_USER=""
PAN_PASS=""
# Reads docker inspect's {{json .Config}} on stdin; prints the user, then the password, one per line:
# the launcher's --username and --password arguments first, then USERNAME and PASSWORD in its env.
PAN_LAUNCHER_PY='
import json, sys
try:
    cfg = json.load(sys.stdin)
except ValueError:
    raise SystemExit(0)
if not isinstance(cfg, dict):
    raise SystemExit(0)
cmd = cfg.get("Cmd") or []
env = dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)
def arg(name):
    for i, a in enumerate(cmd):
        if a == name and i + 1 < len(cmd):
            return cmd[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return None
print(arg("--username") or env.get("USERNAME") or "")
print(arg("--password") or env.get("PASSWORD") or "")
'

pan_err() {
    echo "panos: $*" >&2
}

pan_inv() {
    python3 "$PAN_INVPY" --inv "$PAN_INV" "$@"
}

# pan_init [DIR]: the lab, its inventory, and the firewall's node, container and address.
pan_init() {
    PAN_LABDIR="$(cd "${1:-${SFAB_LABDIR:-$PWD}}" && pwd)" || return 2
    PAN_INV="${SFAB_INV:-$PAN_LABDIR/gen/inventory.json}"
    if [[ ! -f "$PAN_INV" ]]; then
        pan_err "no inventory at $PAN_INV (run make render in the lab)"
        return 2
    fi
    PAN_FW="$(pan_inv nodes --role firewall | head -n 1)"
    if [[ -z "$PAN_FW" ]]; then
        pan_err "the lab has no firewall"
        return 2
    fi
    PAN_PREFIX="$(pan_inv get prefix)"
    PAN_CONTAINER="$(pan_inv get "nodes.${PAN_FW}.container")"
    if [[ -z "$PAN_PREFIX" || "$PAN_CONTAINER" != "${PAN_PREFIX}"* ]]; then
        pan_err "container $PAN_CONTAINER is outside the lab prefix $PAN_PREFIX"
        return 2
    fi
    PAN_HOST="${SFAB_FW_HOST:-$(pan_inv get "nodes.${PAN_FW}.mgmt")}"
    PAN_TRIES="${PANOS_TRIES:-$(pan_inv get timeouts.fw_enforced_tries 2>/dev/null || echo 3)}"
    PAN_PAUSE="${PANOS_PAUSE:-$(pan_inv get timeouts.fw_enforced_pause_s 2>/dev/null || echo 20)}"
}

# pan_cred SOURCE: PAN_USER and PAN_PASS from one source; status 1 when it holds no password.
pan_cred() {
    PAN_USER=""
    PAN_PASS=""
    case "$1" in
        env)
            PAN_PASS="${SFAB_FW_PASSWORD:-}"
            PAN_USER="${SFAB_FW_USER:-admin}"
            ;;
        container)
            # A process substitution, so the inspect output never sits in a variable or a file.
            {
                IFS= read -r PAN_USER || true
                IFS= read -r PAN_PASS || true
            } < <(docker inspect -f '{{json .Config}}' "$PAN_CONTAINER" 2>/dev/null | python3 -c "$PAN_LAUNCHER_PY" 2>/dev/null)
            PAN_USER="${PAN_USER:-admin}"
            ;;
        *) return 1 ;;
    esac
    [[ -n "$PAN_PASS" ]]
}

pan_sources() {
    if [[ -n "$PAN_SRC" ]]; then echo "$PAN_SRC"; else printf '%s\n' env container; fi
}

# pan_guard COMMAND: status 2, with the reason, for what the CLI must never be sent.
pan_guard() {
    local c="$1"
    if [[ "$c" =~ (^|[[:space:]])\?($|[[:space:]]) ]]; then
        pan_err "refusing '?' (it prints help and leaves the line half typed): $c"
        return 2
    fi
    if [[ "$c" =~ ^[[:space:]]*(configure|commit)([[:space:]]|$) ]]; then
        pan_err "refusing '$c': configuration changes go through common/fw/fw-api.sh"
        return 2
    fi
    if [[ "$c" =~ ^[[:space:]]*show[[:space:]]+log([[:space:]]|$) ]] &&
        ! [[ "$c" =~ (receive_time[[:space:]]+in[[:space:]]|start-time[[:space:]]+equal[[:space:]]) ]]; then
        pan_err "refusing '$c': show log needs a time filter (receive_time in last-15-minutes, or start-time equal ...)"
        return 2
    fi
}

# pan_ssh OUT: stdin is the session's input; OUT receives the session with CRs removed. Each
# credential source is tried in turn; the first one taken is kept in PAN_SRC. Call it in the
# current shell (not in $(...) or a pipeline), or PAN_SRC is lost.
pan_ssh() {
    local outf="$1" input src rc=5
    local -a to=()
    input="$(cat)"
    if command -v timeout >/dev/null 2>&1; then to=(timeout "${PANOS_TIMEOUT:-120}"); fi
    while IFS= read -r src; do
        pan_cred "$src" || continue
        if printf '%s\n' "$input" |
            SSHPASS="$PAN_PASS" ${to[@]+"${to[@]}"} env -u TERM sshpass -e ssh -tt "${PAN_SSH_OPTS[@]}" "${PAN_USER}@${PAN_HOST}" 2>/dev/null |
            tr -d '\r' >"$outf"; then
            rc=0
        else
            rc=$?
        fi
        PAN_PASS=""
        [[ "$rc" == 5 ]] && continue
        PAN_SRC="$src"
        return "$rc"
    done < <(pan_sources)
    PAN_PASS=""
    pan_err "the firewall took no credential source (SFAB_FW_PASSWORD, the container's launcher arguments)"
    return 5
}

# pan_banner: drop the login banner and the blank lines at the top of a session.
pan_banner() {
    sed -e '/^Last login: /d' -e '/^Number of failed attempts/d' | sed -e '/./,$!d'
}

# pan_clean COMMAND...: a session without prompts, echoed commands or the banner.
pan_clean() {
    local sent
    sent="$(printf '%s\n' "set cli pager off" "set cli config-output-format set" "exit" "$@")"
    pan_banner | PAN_SENT="$sent" awk '
        BEGIN { n = split(ENVIRON["PAN_SENT"], s, "\n"); for (i = 1; i <= n; i++) skip[s[i]] = 1 }
        /^[^[:space:]]+@[^[:space:]]+[>#]/ { next }
        ($0 in skip) { next }
        { print }' | cat -s
}

# pan_evid SURFACE FILE: append the session in FILE to the transcript when one is open.
pan_evid() {
    [[ -n "${EVID:-}" && -z "${EVID_OFF:-}" ]] || return 0
    {
        printf '### %s %s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$PAN_FW" "$1"
        pan_banner <"$2"
    } >>"$EVID"
}

# pan_session_file OUT COMMAND...: one session for the commands, its raw text in OUT.
pan_session_file() {
    local outf="$1" c rc
    shift
    for c in "$@"; do pan_guard "$c" || return 2; done
    if pan_ssh "$outf" <<<"$(printf 'set cli pager off\n'; printf '%s\n' "$@"; printf 'exit')"; then rc=0; else rc=$?; fi
    [[ "$rc" == 5 ]] && return 5
    pan_evid panos-cli "$outf"
    return "$rc"
}

pan_session() {
    local tmp rc
    tmp="$(mktemp)"
    if pan_session_file "$tmp" "$@"; then rc=0; else rc=$?; fi
    [[ "$rc" == 5 || "$rc" == 2 ]] || cat "$tmp"
    rm -f "$tmp"
    return "$rc"
}

pan_cli() {
    local tmp rc
    tmp="$(mktemp)"
    if pan_session_file "$tmp" "$@"; then rc=0; else rc=$?; fi
    [[ "$rc" == 5 || "$rc" == 2 ]] || pan_clean "$@" <"$tmp"
    rm -f "$tmp"
    return "$rc"
}

# pan_hide: secret leaves of a set-format dump replaced by <hidden>.
pan_hide() {
    sed -E 's/^(set .* (phash|password|private-key|public-key|pre-shared-key|key|secret|bind-password|auth-password|priv-password|community|snmp-community-string|passphrase)) .*/\1 <hidden>/'
}

# pan_running_set_file OUT: the set lines of the configuration, secrets hidden.
pan_running_set_file() {
    local outf="$1" tmp rc
    tmp="$(mktemp)"
    if pan_ssh "$tmp" <<<"$(printf 'set cli pager off\nset cli config-output-format set\nconfigure\nshow\nexit\nexit')"; then
        rc=0
    else
        rc=$?
    fi
    if [[ "$rc" != 5 ]]; then
        pan_hide <"$tmp" >"$tmp.hidden"
        pan_evid panos-cli "$tmp.hidden"
        { grep -E '^set ' "$tmp.hidden" || true; } | { grep -Ev '^set cli ' || true; } >"$outf"
    fi
    rm -f "$tmp" "$tmp.hidden"
    return "$rc"
}

pan_running_set() {
    local tmp rc
    tmp="$(mktemp)"
    if pan_running_set_file "$tmp"; then rc=0; else rc=$?; fi
    cat "$tmp"
    rm -f "$tmp"
    return "$rc"
}

pan_norm() {
    awk '{ $1 = $1; print }' | LC_ALL=C sort -u
}

# pan_enforced FILE: every set line of FILE in the configuration, up to PAN_TRIES reads
# PAN_PAUSE seconds apart. Prints the count, and each line missing from the last read.
pan_enforced() {
    local file="$1" want have missing n m rc try=1
    if [[ ! -r "$file" ]]; then
        pan_err "cannot read $file"
        return 2
    fi
    want="$(mktemp)"
    have="$(mktemp)"
    grep -Ev '^[[:space:]]*(#|$)' "$file" | pan_norm >"$want"
    n="$(grep -c . "$want" || true)"
    while :; do
        if pan_running_set_file "$have.raw"; then rc=0; else rc=$?; fi
        if [[ "$rc" == 5 ]]; then
            rm -f "$want" "$have" "$have.raw"
            return 5
        fi
        pan_norm <"$have.raw" >"$have"
        missing="$(LC_ALL=C comm -23 "$want" "$have" | grep . || true)"
        m="$(printf '%s' "$missing" | grep -c . || true)"
        if [[ "$m" == 0 ]]; then
            echo "enforced: $n of $n lines present (read $try)"
            rm -f "$want" "$have" "$have.raw"
            return 0
        fi
        ((try >= PAN_TRIES)) && break
        try=$((try + 1))
        sleep "$PAN_PAUSE"
    done
    echo "enforced: $((n - m)) of $n lines present after $try reads; missing:"
    printf '%s\n' "$missing" | sed 's/^/  /'
    rm -f "$want" "$have" "$have.raw"
    return 1
}

pan_login() {
    local tmp rc
    tmp="$(mktemp)"
    if pan_session_file "$tmp" "show system info"; then rc=0; else rc=$?; fi
    if [[ "$rc" != 5 ]] && grep -q '^hostname:' "$tmp"; then
        rm -f "$tmp"
        echo "login: the firewall takes the '$PAN_SRC' credential source"
        return 0
    fi
    rm -f "$tmp"
    [[ "$rc" == 5 ]] && return 5
    pan_err "a session opened with '$PAN_SRC' but show system info printed no hostname"
    return 1
}

pan_usage() {
    sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
}

pan_main() {
    local lab=""
    if [[ "${1:-}" == --lab ]]; then
        [[ $# -ge 2 ]] || pan_usage
        lab="$2"
        shift 2
    fi
    [[ $# -ge 1 ]] || pan_usage
    local cmd="$1"
    shift
    case "$cmd" in
        cli | session) [[ $# -ge 1 ]] || pan_usage ;;
        running-set | enforced | login) ;;
        *) pan_usage ;;
    esac
    pan_init "$lab"
    command -v sshpass >/dev/null 2>&1 || {
        pan_err "sshpass is not installed"
        exit 2
    }
    case "$cmd" in
        cli) pan_cli "$@" ;;
        session) pan_session "$@" ;;
        running-set) pan_running_set ;;
        enforced) pan_enforced "${1:-$PAN_LABDIR/bootstrap/fw/enforced.txt}" ;;
        login) pan_login ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    pan_main "$@"
fi
