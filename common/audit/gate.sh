#!/usr/bin/env bash
# gate.sh SET...: may these result sets be committed? (FRAMEWORK.md 4.4, make record)
#
# For each set:
#   - namecheck finds nothing in it, and nothing in the repo (a SKIP, not a FAIL, when there is no
#     scrub list: namecheck exits 3 without $SFAB_SCRUB_LIST);
#   - the secret scan is clean: no value from the lab's state/secrets.env in any file (text or
#     binary, captures included, a compressed file read decompressed), no PEM private key, no
#     unredacted Authorization, X-PAN-KEY or key= value, no API key in the sk-<org>-<slug>-<hex> form,
#     and not the lab host's kernel release ($SFAB_HOST_KERNEL, else uname -r on Linux) as a token
#     (redact.py replaces it; a file written by hand into a set, or a journal made without
#     typescript.py, may still hold it);
#   - the literal scan is clean: no literal from the credential literals file namecheck reads
#     ($SFAB_SCRUB_SECRETS, else ~/.config/sfab/scrub-secrets.txt) in any file of the set, captures
#     and compressed files included, in the forms redact_tree.py --check counts: in any case, and in
#     a binary file also in DNS wire form: the whole name, a leading run of its labels before a
#     compression pointer, or a first label of 4 or more characters alone (redact_tree.py
#     wire_forms and literal_hits). A hit prints as its path, and its line in a text file, never
#     the literal (a literal in the path itself prints as a marker). A SKIP when that file is not
#     there or holds no literal; a file $SFAB_SCRUB_SECRETS names that is not there is a FAIL;
#   - every pcap is under harness.pcap_max_mib (5 MiB); a larger one is listed with its sha256 in
#     captures/IGNORED.txt and in the set's .gitignore, so it is never committed;
#   - the recording size policy (setsize.py, FRAMEWORK.md 4.4): no plain text file over the text
#     cap (10 MiB; a capture decode is committed whole, so a larger one means capturing less), no
#     XML or JSON of 256 KiB or more stored plain, and the set's committed bytes, after the pcaps
#     set aside above, within the set cap (64 MiB);
#   - RESULT.txt shows 0 failed (a break set judges its designed failure as a PASS, so it too
#     must show 0 failed).
# Exit 0 when every set passes.
#
# SFAB_REQUIRE_NAMECHECK=1 marks a run that must not pass without the author's lists, as the
# author's own runs must not: with it, a namecheck skipped for want of a scrub list, and a literal
# scan skipped for want of a literals file or a literal in it, is a FAIL instead of a SKIP.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init gate --no-record "$@"
[ "${#SFAB_ARGS[@]}" -gt 0 ] || die "usage: gate.sh SET_DIR..."

limit_mib="${HN_PCAP_MAX_MIB:-5}"
mib() { awk -v b="$1" 'BEGIN { printf "%.1f", b / 1048576 }'; }

# the credential literals file, where namecheck looks for it: only the default may be missing, and
# its path is never printed (it is the author's own)
secrets="${SFAB_SCRUB_SECRETS:-}"
secrets_named=1
if [ -z "$secrets" ]; then
  secrets="${HOME:-}/.config/sfab/scrub-secrets.txt"
  secrets_named=0
fi

for set in "${SFAB_ARGS[@]}"; do
  [ -d "$set" ] || { bad "result set $set" "no such directory"; continue; }
  set="$(cd "$set" && pwd -P)"
  case "$set" in "$RENDERDIR/audits/"*) ;; *) bad "result set $(basename "$set")" "not under $RENDERDIR/audits"; continue ;; esac
  name="$(basename "$set")"
  sec "gate $name"

  rc=0
  out="$(py "$SFAB_COMMON/tools/namecheck.py" --mask "$set" 2>&1)" || rc=$?
  case "$rc" in
    0) ok "namecheck clean in the set" ;;
    3) not_run "namecheck in the set" "namecheck clean in the set" "no scrub list" ;;
    *) bad "namecheck clean in the set" "$(printf '%s\n' "$out" | grep -m 3 -E ' fail |^namecheck: ' | paste -sd ';' -)" ;;
  esac

  out="$(py - "$set" "$STATEDIR/secrets.env" "$SFAB_COMMON/audit" <<'PY'
import os, re, sys, zlib
root, env = sys.argv[1], sys.argv[2]
sys.path.insert(0, sys.argv[3])
import redact
# the lab host's kernel release as redact.py finds it (None off Linux without $SFAB_HOST_KERNEL)
kernel = redact.kernel_rx(redact.host_kernel())
vals = []
try:
    for line in open(env, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip("'\"")
            # user names (SFAB_*_USER) are the platforms' administrators, not secrets
            if len(v) >= 6 and not v.isalpha() and not k.endswith("_USER"):
                vals.append((k, v.encode()))
except OSError:
    pass
pats = [
    ("PEM private key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{16}")),
    ("Authorization value", re.compile(rb"(?im)^\s*Authorization\s*:\s*(?:Bearer|Basic|Token)?\s*(?!<redacted)[A-Za-z0-9._~+/=-]{8,}")),
    ("X-PAN-KEY value", re.compile(rb"(?im)X-PAN-KEY\s*:\s*(?!<redacted)[A-Za-z0-9+/=]{16,}")),
    ("key= value", re.compile(rb"(?i)[?&]key=(?!<redacted)[A-Za-z0-9+/=%]{16,}")),
    ("API key", re.compile(rb"\bsk-[a-z0-9]{2,8}-[a-z0-9-]{1,40}-[0-9a-f]{16,}\b")),
]
hits = []
for d, _ds, fs in os.walk(root):
    for f in sorted(fs):
        p = os.path.join(d, f)
        try:
            data = open(p, "rb").read()
        except OSError:
            continue
        rel = os.path.relpath(p, root)
        if f.endswith(".gz"):
            # a file the set stores compressed is scanned as it decompresses
            # its own name: d is the directory os.walk is in, which the next file's path still needs
            z = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                data = z.decompress(data, 1 << 30)
            except zlib.error:
                data = b""
            if not z.eof:
                hits.append(f"{rel}: does not decompress")
                continue
        for name, v in vals:
            if v in data:
                hits.append(f"{rel}: the value of {name}")
        for label, rx in pats:
            if rx.search(data):
                hits.append(f"{rel}: {label}")
        if kernel is not None and kernel.search(data.decode("utf-8", "surrogateescape")):
            hits.append(f"{rel}: the lab host's kernel release")
for h in hits:
    print(h)
PY
)"
  if [ -z "$out" ]; then ok "secret scan clean"; else bad "secret scan clean" "$(printf '%s\n' "$out" | head -n 3 | paste -sd ';' -)"; fi

  # the author's credential literals in every file, captures included; a hit prints without its text
  if [ ! -f "$secrets" ]; then
    if [ "$secrets_named" = 1 ]; then
      bad "literal scan clean" "the literals file that \$SFAB_SCRUB_SECRETS names does not exist"
    else
      not_run "literal scan" "literal scan clean" "no literals file"
    fi
  else
    rc=0
    out="$(py - "$set" "$secrets" "$SFAB_COMMON/audit" <<'PY'
import sys
sys.path.insert(0, sys.argv[3])
import redact_tree
# exit 0 clean, 10 hits (printed masked), 11 no literal in the file, 12 the file cannot be read
try:
    lits = redact_tree.read_literals(sys.argv[2])
except Exception:
    sys.exit(12)
if not lits:
    sys.exit(11)
hits = redact_tree.literal_hits(sys.argv[1], lits)
for h in hits:
    print(h)
sys.exit(10 if hits else 0)
PY
)" || rc=$?
    case "$rc" in
      0) ok "literal scan clean" ;;
      10) bad "literal scan clean" "$(printf '%s\n' "$out" | wc -l | tr -d ' ') found: $(printf '%s\n' "$out" | head -n 3 | paste -sd ';' -)" ;;
      11) not_run "literal scan" "literal scan clean" "no literal in the literals file" ;;
      12) bad "literal scan clean" "cannot read the literals file" ;;
      *) bad "literal scan clean" "the scan did not finish (exit $rc)" ;;
    esac
  fi

  big=0
  n=0
  while IFS= read -r -d '' pcap; do
    n=$((n + 1))
    size="$(wc -c <"$pcap" | tr -d ' ')"
    if [ "$size" -gt $((limit_mib * 1048576)) ]; then
      rel="${pcap#"$set"/}"
      mkdir -p "$set/captures"
      line="$(sha256sum "$pcap" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$pcap" | cut -d' ' -f1)  $size  $rel"
      grep -qxF "$line" "$set/captures/IGNORED.txt" 2>/dev/null || printf '%s\n' "$line" >>"$set/captures/IGNORED.txt"
      grep -qxF "/$rel" "$set/.gitignore" 2>/dev/null || printf '/%s\n' "$rel" >>"$set/.gitignore"
      big=$((big + 1))
    fi
  done < <(find "$set" -type f -name '*.pcap' -print0)
  ok "captures: $n pcaps, $big over $limit_mib MiB set aside with their sha256 in captures/IGNORED.txt"

  # the recording size policy, on what a commit of the set would carry (after the pcaps above)
  out="$(py "$SFAB_COMMON/audit/setsize.py" check "$set" 2>&1 || true)"
  read -r _ bytes files cap <<<"$(printf '%s\n' "$out" | grep -m 1 '^SIZE ' || echo "SIZE 0 0 0")"
  if [ "$cap" -gt 0 ] && [ "$bytes" -le "$cap" ]; then
    ok "set size: $(mib "$bytes") MiB in $files files, within $(mib "$cap") MiB"
  else
    bad "set size: $(mib "$bytes") MiB in $files files, within $(mib "$cap") MiB" "over the set cap: capture less or split the run"
  fi
  over="$(printf '%s\n' "$out" | awk '$1 == "OVER" { printf "%s%s (%.1f MiB)", sep, $3, $2 / 1048576; sep = "; " }')"
  if [ -z "$over" ]; then ok "no plain text file over the text cap"; else bad "no plain text file over the text cap" "$over"; fi
  plain="$(printf '%s\n' "$out" | awk '$1 == "PLAIN" { printf "%s%s", sep, $3; sep = "; " }')"
  if [ -z "$plain" ]; then ok "large XML and JSON stored compressed"; else bad "large XML and JSON stored compressed" "$plain (common/audit/setsize.py pack)"; fi

  if [ -f "$set/RESULT.txt" ]; then
    res="$(grep -E '^== RESULT: ' "$set/RESULT.txt" | tail -n 1)"
    f="$(printf '%s' "$res" | sed -n 's/.* \([0-9][0-9]*\) failed.*/\1/p')"
    if [ "${f:-x}" = 0 ]; then ok "RESULT shows 0 failed"; else bad "RESULT shows 0 failed" "${res:-no RESULT line}"; fi
  else
    bad "RESULT shows 0 failed" "no RESULT.txt"
  fi
done

sec "gate: the repository"
rc=0
out="$(py "$SFAB_COMMON/tools/namecheck.py" --mask 2>&1)" || rc=$?
case "$rc" in
  0) ok "namecheck clean in the repo" ;;
  3) not_run "namecheck in the repo" "namecheck clean in the repo" "no scrub list" ;;
  *) bad "namecheck clean in the repo" "$(printf '%s\n' "$out" | tail -n 1)" ;;
esac
summary
