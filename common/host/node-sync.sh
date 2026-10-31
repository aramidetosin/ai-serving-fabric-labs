#!/usr/bin/env bash
# common/host/node-sync.sh [--check] [NODE...]: keep the files each VM guest installs at boot equal
# to the lab's current render (FRAMEWORK.md 3.3, step 9). boot runs it after the guests answer.
#
# vm-init.sh writes the render into a guest's NoCloud seed when the guest's container starts, and
# the guest's seed-sync.sh installs that seed at every boot (sfab-netsetup.service). A render that
# changes while the containers run (make render, then make recover) therefore never reaches the
# guests by itself. node-sync builds each guest's seed from the current render exactly as vm-init.sh
# would, by running vm-init.sh itself in its dry-run mode on the lab host (with this repo's
# node-files, the guest's bootstrap/<node>/ and the lab's authorized keys), then compares every file the
# seed's MANIFEST lists with the guest's copy: content by sha256, mode and owner, and node.env as
# sorted lines. Each file that differs is installed over SSH, as seed-sync.sh would install it, and
# applied live:
#
#   units (/etc/systemd/system/)        systemctl daemon-reload
#   lldpd's file                        systemctl try-restart lldpd
#   networkd's files                    networkctl reload (a .link file takes effect at the next boot)
#   node.env or netsetup.sh             netsetup.sh run again, directly: it is idempotent, and
#                                       restarting sfab-netsetup.service would run seed-sync.sh first,
#                                       which puts the container's start-time seed back
#   containerd's hosts.toml, keys       nothing (containerd reads hosts.toml at each pull)
#
# A cluster file that changed on any guest (sfab-cluster.service, cluster-bootstrap.sh, anything
# under a k8s/ directory, or a K8S_ line of node.env) is BOOTSTRAP-CHANGED, and the run exits 3;
# boot then restarts sfab-cluster.service on the init node. Files the render no longer lists are
# left alone.
#
# A guest that reboots inside the same container installs its container's start-time seed again,
# so after such a reboot run node-sync again (make recover does).
#
# Output, one line per finding: "<node> IN-SYNC (N files)", "<node> DRIFT <path>" (--check),
# "<node> UPDATED <path>", "<node> APPLIED <what>", "<node> BOOTSTRAP-CHANGED",
# "<node> UNREACHABLE", "<node> FAILED <what>"; then one summary line.
# Exit: 0 in sync or synced; 1 a problem, or drift under --check; 3 synced and the bootstrap changed.
set -euo pipefail
# shellcheck source=common/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"

check=0
want=()
args=()
for a in "$@"; do
  case "$a" in
    --check) check=1 ;;
    -*) args+=("$a") ;;
    *) want+=("$a") ;;
  esac
done
[ "${CHECK:-0}" != 1 ] || check=1
sfab_init node-sync "${args[@]+"${args[@]}"}"

VM_INIT="${SFAB_VM_INIT:-$SFAB_ROOT/images/vm-node/vm-init.sh}"
NODE_FILES="${SFAB_NODE_FILES_SRC:-$SFAB_ROOT/images/vm-node/node-files}"
PUBKEY="$STATEDIR/secrets/authorized_keys"

targets=()
if [ "${#want[@]}" -gt 0 ]; then
  for n in "${want[@]}"; do
    [[ " ${GUESTS[*]:-} " == *" $n "* ]] || die "node-sync: $n is not a VM guest of $LAB"
    targets+=("$n")
  done
else
  targets=("${GUESTS[@]+"${GUESTS[@]}"}")
fi
if [ "${#targets[@]}" -eq 0 ]; then
  echo "node-sync: $LAB has no VM guest"
  exit 0
fi
[ -f "$VM_INIT" ] || die "node-sync: no $VM_INIT"
[ -d "$NODE_FILES" ] || die "node-sync: no $NODE_FILES"
[ -f "$PUBKEY" ] || die "node-sync: no $PUBKEY (preflight writes it)"

WORK="$(mktemp -d "$SFAB_TMP/node-sync.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# The guest-side helpers, sent with each call (the guest runs them as root through sudo).
# shellcheck disable=SC2016 # expanded by the guest's shell
G_INVENTORY='sfab_nodesync_inventory() {
  local p
  for p in "$@"; do
    if [ -f "$p" ]; then printf "%s %s %s\n" "$(sha256sum < "$p" | cut -c1-64)" "$(stat -c "%a %U:%G" "$p")" "$p"
    else printf "MISSING - - %s\n" "$p"; fi
  done
  if [ -f /etc/sfab/node.env ]; then printf "SORTED %s - /etc/sfab/node.env\n" "$(LC_ALL=C sort /etc/sfab/node.env | sha256sum | cut -c1-64)"; fi
}'
# shellcheck disable=SC2016
G_INSTALL='sfab_nodesync_install() {
  local p=$1 mode=$2 owner=$3 user group d
  user=${owner%%:*}; group=${owner#*:}; d=$(dirname "$p")
  if [ "$user" != root ]; then install -d -m 0700 -o "$user" -g "$group" "$d"; else install -d -m 0755 "$d"; fi
  cat > "$p.sfab-new" && chmod "$mode" "$p.sfab-new" && chown "$user:$group" "$p.sfab-new" && mv -f "$p.sfab-new" "$p"
}'

# gssh NODE SCRIPT: run SCRIPT as root in the guest, stdin passed through (unlike H, whose ssh -n
# keeps the caller's stdin for the caller).
gssh() {
  local n="$1" script="$2"
  timeout "${SFAB_CMD_TIMEOUT:-300}" ssh "${_SSH_BASE[@]}" -o BatchMode=yes -o IdentitiesOnly=yes -i "$(lab_key)" \
    "$GUEST_USER@$(node_mgmt "$n")" "sudo bash -c $(printf '%q' "$script")"
}

sha_of() { if have sha256sum; then sha256sum | cut -c1-64; else shasum -a 256 | cut -c1-64; fi; }

# expected NODE DIR: the seed vm-init.sh would build for NODE from the current render, under DIR.
expected() {
  local n="$1" d="$2"
  mkdir -p "$d"
  SFAB_DRY_RUN=1 SFAB_BOOTSTRAP="$RENDERDIR/bootstrap/$n" SFAB_VM_DIR="$d/vm" SFAB_NODE_FILES="$NODE_FILES" \
    SFAB_AUTHORIZED_KEYS="$PUBKEY" SFAB_SHARED="$d/shared" SFAB_BASE=/nonexistent SFAB_NODE="$n" \
    bash "$VM_INIT" >"$d/vm-init.log" 2>&1
  [ -s "$d/vm/seed/sfab/MANIFEST" ]
}

is_bootstrap() {
  case "$1" in
    */sfab-cluster.service|*cluster-bootstrap*|*/k8s/*) return 0 ;;
  esac
  return 1
}

one() {
  local n="$1" d="$WORK/$1" out="$WORK/$1.out" paths=() remote sha mode owner path have
  local reload=0 lldp=0 networkd=0 links=0 netsetup=0 boot=0 changed=0 count=0
  : >"$out"
  if ! expected "$n" "$d"; then
    echo "$n FAILED building the expected seed: $(tail -n 1 "$d/vm-init.log" 2>/dev/null)" >>"$out"
    return 0
  fi
  while read -r sha mode owner path; do
    [ -n "${path:-}" ] && paths+=("$path")
  done <"$d/vm/seed/sfab/MANIFEST"
  count=${#paths[@]}
  if ! remote="$(EVID_OFF=1 H "$n" "$G_INVENTORY; sfab_nodesync_inventory $(printf '%q ' "${paths[@]}")" 2>/dev/null)"; then
    echo "$n UNREACHABLE" >>"$out"
    return 0
  fi
  local env_sorted guest_env_sorted
  env_sorted="$(LC_ALL=C sort "$d/vm/seed/sfab/root/etc/sfab/node.env" | sha_of)"
  guest_env_sorted="$(printf '%s\n' "$remote" | awk '$1 == "SORTED" { print $2 }')"
  while read -r sha mode owner path; do
    [ -n "${path:-}" ] || continue
    if [ "$path" = /etc/sfab/node.env ]; then
      [ "$env_sorted" != "$guest_env_sorted" ] || continue
    else
      have="$(printf '%s\n' "$remote" | awk -v p="$path" '$4 == p && $1 != "SORTED" { print $1 " " $2 " " $3 }')"
      [ "$have" != "$sha ${mode#0} $owner" ] || continue
    fi
    if [ "$check" = 1 ]; then
      echo "$n DRIFT $path" >>"$out"
      changed=1
      continue
    fi
    if [ "$path" = /etc/sfab/node.env ]; then
      local old
      old="$(EVID_OFF=1 H "$n" "cat /etc/sfab/node.env 2>/dev/null || true" 2>/dev/null || true)"
      if [ "$(printf '%s\n' "$old" | grep '^K8S_' | LC_ALL=C sort)" != "$(grep '^K8S_' "$d/vm/seed/sfab/root$path" | LC_ALL=C sort)" ]; then boot=1; fi
    fi
    if gssh "$n" "$G_INSTALL; sfab_nodesync_install $(printf '%q %q %q' "$path" "$mode" "$owner")" <"$d/vm/seed/sfab/root$path" >/dev/null 2>&1; then
      echo "$n UPDATED $path" >>"$out"
      changed=1
    else
      echo "$n FAILED installing $path" >>"$out"
      return 0
    fi
    if is_bootstrap "$path"; then boot=1; fi
    case "$path" in
      /etc/systemd/system/*) reload=1 ;;
      /etc/lldpd.d/*) lldp=1 ;;
      /etc/systemd/network/*.link) links=1 ;;
      /etc/systemd/network/*|/etc/systemd/networkd.conf.d/*) networkd=1 ;;
    esac
    case "$path" in /etc/sfab/node.env|*/netsetup.sh) netsetup=1 ;; esac
  done <"$d/vm/seed/sfab/MANIFEST"
  if [ "$changed" = 0 ]; then
    echo "$n IN-SYNC ($count files)" >>"$out"
    return 0
  fi
  [ "$check" = 0 ] || return 0
  apply() {
    local what="$1" cmd="$2"
    if EVID_OFF=1 H "$n" "$cmd" >/dev/null 2>&1; then echo "$n APPLIED $what" >>"$out"; else echo "$n FAILED $what" >>"$out"; fi
  }
  [ "$reload" = 0 ] || apply "systemctl daemon-reload" "systemctl daemon-reload"
  [ "$lldp" = 0 ] || apply "lldpd restart" "systemctl try-restart lldpd.service"
  [ "$networkd" = 0 ] || apply "networkctl reload" "networkctl reload"
  [ "$links" = 0 ] || echo "$n APPLIED .link files at the next boot" >>"$out"
  [ "$netsetup" = 0 ] || apply "netsetup.sh run again" "/opt/sfab/bin/netsetup.sh"
  [ "$boot" = 0 ] || echo "$n BOOTSTRAP-CHANGED" >>"$out"
}

pids=()
for n in "${targets[@]}"; do
  (one "$n") &
  pids+=("$!")
done
for p in "${pids[@]}"; do wait "$p" || true; done

all="$(for n in "${targets[@]}"; do cat "$WORK/$n.out" 2>/dev/null || echo "$n FAILED (no result)"; done)"
printf '%s\n' "$all"
total=${#targets[@]}
problems="$(printf '%s\n' "$all" | grep -cE ' (UNREACHABLE|FAILED)' || true)"
drift="$(printf '%s\n' "$all" | grep -c ' DRIFT ' || true)"
updated="$(printf '%s\n' "$all" | grep -c ' UPDATED ' || true)"
if [ "$problems" -gt 0 ]; then
  echo "node-sync: $problems problem(s) on $total guest(s)"
  exit 1
fi
if [ "$check" = 1 ]; then
  if [ "$drift" -gt 0 ]; then echo "node-sync: $drift file(s) drifted on $total guest(s) (--check: nothing changed)"; exit 1; fi
  echo "node-sync: $total/$total guests match the render"
  exit 0
fi
if [ "$updated" -eq 0 ]; then
  echo "node-sync: $total/$total guests match the render"
  exit 0
fi
echo "node-sync: $updated file(s) updated on $total guest(s)"
if grep -q ' BOOTSTRAP-CHANGED$' <<<"$all"; then exit 3; fi
exit 0
