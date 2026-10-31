#!/usr/bin/env bash
# replay.sh: type the rendered KLISH lines a switch's running configuration is missing, then save.
#
# Usage: common/klish/replay.sh [--dry-run] <switch>
#
# Run it in the lab directory, or set SFAB_LABDIR. It reads bootstrap/<switch>/startup-config.cfg
# and gen/klish-normalize.json there, and reaches the switch through session.sh.
#
# 1. Capture `show running-configuration` and compare it with the render (parity.py), which
#    writes the missing lines as KLISH blocks in rendered order.
# 2. Read `show mclag brief`. A block for an MCLAG domain the switch already shows is skipped:
#    replay never edits, deletes or re-creates a live domain (a domain that conflicts needs
#    `sudo systemctl restart iccpd`, not a replay).
# 3. Type each remaining block in its own session (configure terminal, the block, end) and stop
#    at the first "% Error", printing it.
# 4. write memory.
#
# The lines it types are the rendered ones, comments stripped as the launcher strips them; it
# never invents a line. Parity then runs again in boot; a line still missing is a FAIL there.
# --dry-run prints the blocks and types nothing.
#
# Exit status: 0 nothing missing or every block typed, 1 a block failed, 2 usage or input error,
# 3 a block was skipped because its MCLAG domain is live (the rest were typed).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lab="${SFAB_LABDIR:-$PWD}"
export SFAB_LABDIR="$lab"
export SFAB_INV="${SFAB_INV:-${lab}/gen/inventory.json}"

dry=0
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) dry=1; shift ;;
        -h|--help) sed -n '3p' "${BASH_SOURCE[0]}" | sed 's/^# //' >&2; exit 2 ;;
        -?*) echo "replay.sh: unknown option $1" >&2; exit 2 ;;
        *) break ;;
    esac
done
[ $# -eq 1 ] || { sed -n '3p' "${BASH_SOURCE[0]}" | sed 's/^# //' >&2; exit 2; }
sw="$1"

rendered="${lab}/bootstrap/${sw}/startup-config.cfg"
norm="${lab}/gen/klish-normalize.json"
[ -r "$rendered" ] || { echo "replay.sh: no rendered startup file at ${rendered}" >&2; exit 2; }
normarg=()
if [ -r "$norm" ]; then normarg=(--normalize "$norm"); fi

work="$(mktemp -d "${TMPDIR:-/tmp}/sfab-replay.XXXXXX")"
trap 'rm -rf "$work"' EXIT

printf 'show running-configuration\n' | "${here}/session.sh" "$sw" > "${work}/running.txt"

rc=0
python3 "${here}/parity.py" "$rendered" "${work}/running.txt" --switch "$sw" ${normarg[@]+"${normarg[@]}"} \
    --replay "${work}/blocks.txt" --json "${work}/parity.json" || rc=$?
case "$rc" in
    0) echo "replay ${sw}: nothing missing"; exit 0 ;;
    1) ;;
    *) echo "replay.sh: parity failed on ${sw} (exit ${rc})" >&2; exit 2 ;;
esac

# Split the blocks (separated by blank lines) into numbered files.
n=0
cur="${work}/cur"
: > "$cur"
flush() {
    if [ -s "$cur" ]; then
        n=$((n + 1))
        mv "$cur" "$(printf '%s/block.%04d' "$work" "$n")"
        : > "$cur"
    fi
}
while IFS= read -r line || [ -n "$line" ]; do
    if [ -z "$line" ]; then
        flush
    else
        printf '%s\n' "$line" >> "$cur"
    fi
done < "${work}/blocks.txt"
flush

if [ "$dry" = "1" ]; then
    for f in "$work"/block.*; do
        [ -e "$f" ] || continue
        echo "--- $(basename "$f")"
        cat "$f"
    done
    exit 0
fi

printf 'show mclag brief\n' | "${here}/session.sh" "$sw" > "${work}/mclag.txt" || true
live=" $(sed -n 's/^Domain ID[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p' "${work}/mclag.txt" | tr '\n' ' ')"

typed=0
skipped=0
for f in "$work"/block.*; do
    [ -e "$f" ] || continue
    first="$(head -n 1 "$f")"
    dom="$(printf '%s\n' "$first" | sed -n 's/^mclag domain \([0-9][0-9]*\)$/\1/p')"
    if [ -n "$dom" ] && case "$live" in *" ${dom} "*) true ;; *) false ;; esac; then
        echo "  SKIP  replay ${sw}: mclag domain ${dom} is live; replay never edits or re-creates it"
        sed 's/^/        /' "$f"
        skipped=$((skipped + 1))
        continue
    fi
    out="${work}/out.$(basename "$f")"
    src=0
    { printf 'configure terminal\n'; cat "$f"; printf 'end\n'; } | "${here}/session.sh" --strict "$sw" > "$out" || src=$?
    if [ "$src" -ne 0 ]; then
        echo "  FAIL  replay ${sw} -> $(basename "$f") answered with an error (session exit ${src}); stopped"
        grep -n -E -B 2 '%[[:space:]]?Error' "$out" | sed 's/^/        /' || sed 's/^/        /' "$out"
        exit 1
    fi
    typed=$((typed + 1))
done

if [ "$typed" -gt 0 ]; then
    printf 'write memory\n' | "${here}/session.sh" --strict "$sw" > "${work}/save.txt" || {
        echo "  FAIL  replay ${sw} -> write memory answered with an error"
        sed 's/^/        /' "${work}/save.txt"
        exit 1
    }
fi
echo "replay ${sw}: typed ${typed} block(s), skipped ${skipped}"
if [ "$skipped" -gt 0 ]; then
    exit 3
fi
exit 0
