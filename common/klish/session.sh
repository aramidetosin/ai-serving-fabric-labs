#!/usr/bin/env bash
# session.sh: type KLISH lines into one switch's sonic-cli and print what it answered.
#
# Usage: common/klish/session.sh [--strict] [--addr ADDR] [--raw FILE] <switch> [FILE|-]
#
# Lines come from FILE, or from stdin when FILE is - or absent. Blank lines and lines that start
# with "!" are dropped, as the launcher drops them. The session opens with `terminal length 0`,
# so show output never stops at --more--, and is piped with `ssh -tt` (sonic-cli -c and a plain
# pipe print nothing). A configure terminal left open is closed with `end`, and the session
# ends with `exit`.
#
# Refused before anything is sent:
#   ?                        with a newline it runs the partial command whenever <cr> is valid
#   grep -E, quoted patterns KLISH rejects them; filter the output in the shell instead
#   exit after ip vrf        ip vrf opens no sub-mode, so the exit leaves configuration mode
#   no mclag domain          a deleted and re-created domain wedges iccpd
#
# The address is --addr, else nodes.<switch>.mgmt in gen/inventory.json (or $SFAB_INV); the
# user is switch.user there. The password is $SFAB_SW_PASSWORD; else the one containerlab gave
# the switch's own container (its --password argument or PASSWORD variable, read with docker
# inspect, as lib.sh's _creds reads it), since the switches keep the kind's default credentials
# until M1 shows a generated one is honored; else the SFAB_SW_PASSWORD line of state/secrets.env
# under $SFAB_LABDIR (default: the current directory), read as data and never sourced. It
# reaches sshpass through its environment only.
#
# Output: the session with carriage returns and terminal escapes removed; --raw FILE keeps the
# bytes as received. Exit status: ssh's own (sshpass exits 5 on a wrong password), 2 usage or a
# refused line, 3 no address or password, 4 with --strict when the switch answered "% Error".
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
inv="${here}/../bin/inv.py"

usage() {
    sed -n '3p' "${BASH_SOURCE[0]}" | sed 's/^# //' >&2
    exit 2
}

strict=0
addr=""
raw=""
while [ $# -gt 0 ]; do
    case "$1" in
        --strict) strict=1; shift ;;
        --addr) [ $# -ge 2 ] || usage; addr="$2"; shift 2 ;;
        --raw) [ $# -ge 2 ] || usage; raw="$2"; shift 2 ;;
        -h|--help) usage ;;
        --) shift; break ;;
        -?*) echo "session.sh: unknown option $1" >&2; usage ;;
        *) break ;;
    esac
done
[ $# -ge 1 ] || usage
sw="$1"
src="${2:--}"

work="$(mktemp -d "${TMPDIR:-/tmp}/sfab-session.XXXXXX")"
trap 'rm -rf "$work"' EXIT

if [ "$src" = "-" ]; then
    cat > "$work/in"
else
    [ -r "$src" ] || { echo "session.sh: cannot read $src" >&2; exit 2; }
    cat "$src" > "$work/in"
fi
# Drop comments and blank lines, trim the ends of each line.
sed -e 's/\r$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$work/in" | grep -v -e '^$' -e '^!' > "$work/lines" || true

refuse() {
    echo "session.sh: refused, $1" >&2
    exit 2
}
if grep -n -F '?' "$work/lines" >&2; then refuse "a line holds ? (it would run the partial command)"; fi
if grep -n -E 'grep[[:space:]]+(-[A-Za-z]*E([[:space:]]|$)|["'\''])' "$work/lines" >&2; then
    refuse "KLISH rejects grep -E and quoted patterns; filter the output in the shell"
fi
if grep -n -E '^no[[:space:]]+mclag[[:space:]]+domain' "$work/lines" >&2; then
    refuse "never delete an MCLAG domain"
fi
if awk 'prev ~ /^ip[[:space:]]+vrf[[:space:]]+[^[:space:]]+$/ && $0 == "exit" { print NR": "$0; bad=1 } { prev=$0 } END { exit bad ? 0 : 1 }' "$work/lines" >&2; then
    refuse "exit straight after ip vrf leaves configuration mode"
fi

if [ -z "$addr" ]; then
    addr="$(python3 "$inv" get "nodes.${sw}.mgmt" 2>/dev/null || true)"
fi
[ -n "$addr" ] || { echo "session.sh: no management address for ${sw} (pass --addr, or run in the lab directory)" >&2; exit 3; }
user="$(python3 "$inv" get switch.user 2>/dev/null || true)"
user="${user:-admin}"

pw="${SFAB_SW_PASSWORD:-}"
if [ -z "$pw" ] && command -v docker >/dev/null 2>&1; then
    ctr="$(python3 "$inv" get "nodes.${sw}.container" 2>/dev/null || true)"
    if [ -n "$ctr" ]; then
        pw="$(docker inspect -f '{{json .Config}}' "$ctr" 2>/dev/null | python3 -c '
import json, sys
try:
    cfg = json.load(sys.stdin)
except ValueError:
    raise SystemExit(0)
cmd = cfg.get("Cmd") or []
env = dict(e.split("=", 1) for e in (cfg.get("Env") or []) if "=" in e)
for i, a in enumerate(cmd):
    if a == "--password" and i + 1 < len(cmd):
        print(cmd[i + 1])
        raise SystemExit(0)
    if a.startswith("--password="):
        print(a.split("=", 1)[1])
        raise SystemExit(0)
print(env.get("PASSWORD", ""))
' 2>/dev/null || true)"
    fi
fi
secrets="${SFAB_LABDIR:-.}/state/secrets.env"
if [ -z "$pw" ] && [ -r "$secrets" ]; then
    pw="$(sed -n 's/^SFAB_SW_PASSWORD=//p' "$secrets" | head -n 1)"
    pw="${pw#\"}"; pw="${pw%\"}"; pw="${pw#\'}"; pw="${pw%\'}"
fi
[ -n "$pw" ] || { echo "session.sh: no switch password (set SFAB_SW_PASSWORD or state/secrets.env)" >&2; exit 3; }

open="$(awk '$0 == "configure terminal" { m = 1 } $0 == "end" { m = 0 } END { print m + 0 }' "$work/lines")"
{
    printf 'terminal length 0\n'
    cat "$work/lines"
    if [ "$open" = "1" ]; then printf 'end\n'; fi
    printf 'exit\n'
} > "$work/payload"

tmo=()
if command -v timeout >/dev/null 2>&1; then
    tmo=(timeout "${SFAB_SESSION_TIMEOUT:-600}")
fi
rc=0
SSHPASS="$pw" ${tmo[@]+"${tmo[@]}"} env -u TERM sshpass -e ssh -tt \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
    -o ConnectTimeout=15 -o PubkeyAuthentication=no \
    -o PreferredAuthentications=password,keyboard-interactive \
    "${user}@${addr}" sonic-cli < "$work/payload" > "$work/raw" 2>&1 || rc=$?

if [ -n "$raw" ]; then
    cp "$work/raw" "$raw"
fi
esc="$(printf '\033')"
tr -d '\r' < "$work/raw" | sed -e "s/${esc}\[[0-9;?]*[A-Za-z]//g" > "$work/clean"
cat "$work/clean"

if [ "$rc" -ne 0 ]; then
    exit "$rc"
fi
if [ "$strict" = "1" ] && grep -q -E '%[[:space:]]?Error' "$work/clean"; then
    exit 4
fi
exit 0
