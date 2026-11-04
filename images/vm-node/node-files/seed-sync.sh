#!/usr/bin/env bash
# seed-sync.sh: install the node files the NoCloud seed carries, at every boot, before
# netsetup.sh runs (ExecStartPre of sfab-netsetup.service).
#
# cloud-init writes its files once per instance, so a guest on an existing disk would otherwise
# keep the node.env and scripts of its first boot. vm-init.sh writes the current render into the
# seed at every container start: sfab/root/<path> for each file and sfab/MANIFEST, one
# "sha256 mode owner:group path" line per file. A file whose content, mode or owner differs is
# installed; units changed mean a daemon-reload, lldpd's file a restart of lldpd, and networkd's
# files a reload of networkd (a .link file takes effect at the next boot).
#
# On a Kubernetes node the seed also carries sfab-cluster.service. The first time it is here and
# not enabled, it is enabled, so every later boot starts it after this unit, and started without
# blocking: this boot's start-up was planned before the unit existed, and its own ordering (after
# sfab-netsetup.service) makes it wait for netsetup.sh.
set -euo pipefail

log() { printf '[seed-sync] %s\n' "$*"; }

dev=$(blkid -L cidata 2>/dev/null || blkid -L CIDATA 2>/dev/null || true)
if [ -z "$dev" ]; then
  log "no seed device (label cidata): nothing to sync"
  exit 0
fi
mnt=$(mktemp -d /run/sfab-seed.XXXXXX)
cleanup() { umount "$mnt" 2>/dev/null || true; rmdir "$mnt" 2>/dev/null || true; }
trap cleanup EXIT
mount -o ro "$dev" "$mnt"
if [ ! -r "$mnt/sfab/MANIFEST" ]; then
  log "the seed on $dev has no sfab/MANIFEST: nothing to sync"
  exit 0
fi

changed=()
while read -r sha mode owner path; do
  [ -n "${path:-}" ] || continue
  src="$mnt/sfab/root$path"
  if [ ! -f "$src" ] || [ "$(sha256sum < "$src" | cut -c1-64)" != "$sha" ]; then
    log "warning: $path in the seed does not match its manifest line; left as it is"
    continue
  fi
  user=${owner%%:*}
  group=${owner#*:}
  if ! id -u "$user" >/dev/null 2>&1; then
    log "warning: $path belongs to $user, who does not exist yet; left as it is"
    continue
  fi
  if [ -f "$path" ] && [ "$(sha256sum < "$path" | cut -c1-64)" = "$sha" ] \
     && [ "$(stat -c '%a %U:%G' "$path")" = "${mode#0} $owner" ]; then
    continue
  fi
  dir=$(dirname "$path")
  if [ "$user" != root ]; then
    install -d -m 0700 -o "$user" -g "$group" "$dir"
  else
    install -d -m 0755 "$dir"
  fi
  install -m "$mode" -o "$user" -g "$group" "$src" "$path.sfab-new"
  mv -f "$path.sfab-new" "$path"
  changed+=("$path")
done < "$mnt/sfab/MANIFEST"

# cluster_unit: enable and start sfab-cluster.service the first time the seed has installed it.
cluster_unit() {
  local u=sfab-cluster.service
  [ -f "/etc/systemd/system/$u" ] || return 0
  [ "$(systemctl is-enabled "$u" 2>/dev/null || true)" != enabled ] || return 0
  if systemctl enable "$u" >/dev/null 2>&1 && systemctl start --no-block "$u"; then
    log "$u enabled and started (it runs after sfab-netsetup.service)"
  else
    log "warning: could not enable and start $u"
  fi
}

if [ "${#changed[@]}" -eq 0 ]; then
  log "every node file matches the seed"
  cluster_unit
  exit 0
fi
log "installed: ${changed[*]}"
reload=0 lldp=0 networkd=0
for p in "${changed[@]}"; do
  case $p in
    /etc/systemd/system/*) reload=1 ;;
    /etc/lldpd.d/*) lldp=1 ;;
    /etc/systemd/network/*|/etc/systemd/networkd.conf.d/*) networkd=1 ;;
  esac
done
if [ "$reload" = 1 ]; then systemctl daemon-reload || log "warning: daemon-reload failed"; fi
if [ "$lldp" = 1 ]; then systemctl try-restart lldpd.service || true; fi
if [ "$networkd" = 1 ]; then networkctl reload >/dev/null 2>&1 || true; fi
cluster_unit
