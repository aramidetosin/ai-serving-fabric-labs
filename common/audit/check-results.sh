#!/usr/bin/env bash
# check-results.sh DIR...: the closing checks on run directories (make verify).
#
# For each set:
#   - the secret scan is clean: no value from the lab's state/secrets.env in any file (text or
#     binary, captures included, a compressed file read decompressed), no PEM private key, no
#     unredacted Authorization, X-PAN-KEY or key= value, no API key in the sk-<org>-<slug>-<hex> form,
#     and not the lab host's kernel release ($SFAB_HOST_KERNEL, else uname -r on Linux) as a token;
#   - summary.txt shows 0 failed (a break set checks its designed failure as a PASS, so it too
#     must show 0 failed).
# Exit 0 when every set passes.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
sfab_init check-results --no-save "$@"
[ "${#SFAB_ARGS[@]}" -gt 0 ] || die "usage: check-results.sh RUN_DIR..."

for set in "${SFAB_ARGS[@]}"; do
  [ -d "$set" ] || { bad "run directory $set" "no such directory"; continue; }
  set="$(cd "$set" && pwd -P)"
  case "$set" in "$RENDERDIR/runs/"*) ;; *) bad "run directory $(basename "$set")" "not under $RENDERDIR/runs"; continue ;; esac
  name="$(basename "$set")"
  sec "check results $name"

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

  if [ -f "$set/summary.txt" ]; then
    res="$(grep -E '^== RESULT: ' "$set/summary.txt" | tail -n 1)"
    f="$(printf '%s' "$res" | sed -n 's/.* \([0-9][0-9]*\) failed.*/\1/p')"
    if [ "${f:-x}" = 0 ]; then ok "RESULT shows 0 failed"; else bad "RESULT shows 0 failed" "${res:-no RESULT line}"; fi
  else
    bad "RESULT shows 0 failed" "no summary.txt"
  fi
done

summary
