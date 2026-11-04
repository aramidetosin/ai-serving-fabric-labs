#!/usr/bin/env bash
# sfab-frr-restore: compare a running FRR router with its render, or put the render back.
#
#   sfab-frr-restore check     exit 0 when the running configuration is the render; exit 3 and
#                              print the lines FRR would add or remove when it is not
#   sfab-frr-restore restore   link /etc/frr/frr.conf, daemons and vtysh.conf to the render again
#                              (a `write memory` replaces the frr.conf link with a copy), then
#                              reload frr.conf into the running daemons, then check
#
# The render is bootstrap/<router>/ bound read-only at /sfab/bootstrap (SFAB_FRR_CONF_DIR names
# another place). Both use FRR's own frr-reload.py, which compares the file with `show
# running-config` line by line within each block; the comment lines and FRR's own `frr version`
# line are not differences. A break of kind frr ends with `restore`, and the audit runs `check`.
set -euo pipefail

CONF_DIR=${SFAB_FRR_CONF_DIR:-/sfab/bootstrap}
FRR_DIR=${SFAB_FRR_DIR:-/etc/frr}
RELOAD=${SFAB_FRR_RELOAD:-/usr/lib/frr/frr-reload.py}

die() { printf '[frr-restore] FATAL: %s\n' "$*" >&2; exit 1; }

[ -r "$CONF_DIR/frr.conf" ] || die "no $CONF_DIR/frr.conf (the topology binds bootstrap/<router>/ there)"
[ -x "$RELOAD" ] || die "no $RELOAD in this image"

# diff_lines: what frr-reload.py would change, or nothing when the router runs the render.
diff_lines() {
  "$RELOAD" --test --log-level warning "$CONF_DIR/frr.conf" 2>/dev/null |
    awk '/^Lines To (Delete|Add)$/ {on = 1} on && NF && !/^=+$/ {print}'
}

check() {
  local d
  d=$(diff_lines) || die "frr-reload.py could not compare the render with the running configuration"
  if [ -z "$d" ]; then
    echo "[frr-restore] the running configuration is the render ($CONF_DIR/frr.conf)"
    return 0
  fi
  echo "[frr-restore] the running configuration differs from the render:"
  printf '%s\n' "$d"
  return 3
}

restore() {
  local f
  for f in frr.conf daemons vtysh.conf; do
    [ -r "$CONF_DIR/$f" ] || continue
    ln -sfn "$CONF_DIR/$f" "$FRR_DIR/$f"
  done
  # Reload through the link: given any other path, frr-reload.py ends with `write memory`, which
  # would replace the link with a copy again.
  "$RELOAD" --reload --log-level warning "$FRR_DIR/frr.conf" >/dev/null 2>&1 ||
    die "frr-reload.py --reload $FRR_DIR/frr.conf failed (see /var/log/frr/frr-reload.log)"
  check
}

case "${1:-check}" in
  check) check ;;
  restore) restore ;;
  *) die "usage: sfab-frr-restore check|restore" ;;
esac
