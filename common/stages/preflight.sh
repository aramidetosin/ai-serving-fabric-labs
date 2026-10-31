#!/usr/bin/env bash
# preflight.sh: refuse to deploy unless the host can hold this lab (FRAMEWORK.md 3.1).
#
# Every check prints PASS or FAIL (SKIP where it cannot judge), and any FAIL refuses. The lines
# are kept in state/preflight.last, which the audit replays (M1 exit criterion 1). Preflight
# changes nothing on the host beyond loading the kernel modules the lab needs (idempotent, not
# persistent) and creating the lab's own state/secrets.env and SSH key.
#
# Sourced with SFAB_PF_LIB=1 it only defines the pf_* functions, which then run read-only
# (audit_preflight in lib.sh): modules are checked, not loaded, and secrets are checked, not made.

pf_identity() {
  local p
  p="$(sfab_identity)"
  if [ -z "$p" ]; then
    ok "identity: lab $LAB in $(basename "$LABDIR")${VARIANT:+/variants/$VARIANT}, prefix $PREFIX, network $MGMT_NET"
  else
    while IFS= read -r l; do bad "identity" "$l"; done <<<"$p"
  fi
  if [ -f "$TOPO" ]; then ok "topo.clab.yml present"; else bad "topo.clab.yml present" "run make render"; fi
}

_pin_containerlab() {
  py - "$RENDERDIR/gen/RENDER.json" "$SFAB_ROOT/spec/versions.yaml" <<'PY'
import json, re, sys
try:
    print(((json.load(open(sys.argv[1])).get("versions") or {}).get("tools") or {}).get("containerlab") or "")
    raise SystemExit(0)
except (OSError, ValueError):
    pass
m = re.search(r"^\s*containerlab:\s*([0-9.]+)", open(sys.argv[2]).read(), re.M)
print(m.group(1) if m else "")
PY
}

pf_tools() {
  local v pin t missing=()
  if v="$(dk version --format '{{.Server.Version}}' 2>/dev/null)" && [ -n "$v" ]; then
    ok "docker $v answers"
  else
    bad "docker answers" "docker version failed"
  fi
  pin="$(_pin_containerlab)"
  v="$(containerlab version 2>/dev/null | sed -n 's/^[[:space:]]*version:[[:space:]]*//p' | head -n 1 || true)"
  chk "containerlab at the pinned ${pin:-?}" "${pin:-unpinned}" "${v:-absent}"
  v="$(py -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo absent)"
  if py -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    ok "python3 $v (3.10 or later)"
  else
    bad "python3 3.10 or later" "found $v"
  fi
  for t in sshpass tcpdump nsenter ethtool openssl ssh ssh-keygen curl flock timeout systemd-run ip; do
    have "$t" || missing+=("$t")
  done
  if [ ${#missing[@]} -eq 0 ]; then ok "tools: sshpass tcpdump nsenter ethtool openssl and the rest present"; else bad "tools present" "missing: ${missing[*]}"; fi
}

pf_kvm() {
  if [ -c /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then ok "/dev/kvm read-write"; else bad "/dev/kvm read-write" "absent or not writable"; fi
}

pf_tick() {
  local t rc=0
  t="$(py "$SFAB_COMMON/bin/tick.py" 2>/dev/null)" || rc=$?
  if [ "$rc" -eq 0 ]; then
    ok "host tick $t"
  else
    # The tick is read and recorded, never refused: another workload on a shared host can move it
    # (any container holding CAP_SYS_TIME adjusts the one clock), and a lab must not stop on that.
    skip "host tick ${t:-unreadable}" "reads ${t:-nothing}, not ${HOST_TICK_WANT:-10000}: recorded, not refused; common/bin/tick.py reads it, and run as root with --set it sets it to 10000 (adjtimex(2) ADJ_TICK)"
  fi
}

# A container named sfab-probe-* is a short-lived test container (an image tried on its own),
# not a lab: probes are not labs, so the guard sets them aside and says how many it set aside.
pf_other_labs() {
  local c others=() probes=0 labs procs
  while read -r c; do
    [ -n "$c" ] || continue
    if [[ "$c" == sfab-probe-* ]]; then probes=$((probes + 1)); continue; fi
    if [[ "$c" == sfab-* ]] && [[ "$c" != "$PREFIX"* ]]; then others+=("$c"); fi
  done < <(dk ps --format '{{.Names}}' 2>/dev/null || true)
  local aside=""
  [ "$probes" -eq 0 ] || aside=" ($probes sfab-probe-* container(s) set aside: probes are not labs)"
  if [ ${#others[@]} -eq 0 ]; then ok "no other sfab lab's container running$aside"; else bad "no other sfab lab's container running" "${others[*]:0:5}"; fi
  labs="$(containerlab inspect --all --format json 2>/dev/null | py -c '
import json, sys
lab = sys.argv[1]
try:
    d = json.load(sys.stdin)
except ValueError:
    raise SystemExit(0)
names = set()
if isinstance(d, dict):
    for k, v in d.items():
        if isinstance(v, list):
            if k == "containers":
                names.update(str(x.get("lab_name") or x.get("labName") or "") for x in v if isinstance(x, dict))
            else:
                names.add(k)
print(" ".join(sorted(n for n in names if n.startswith("sfab-") and not n.startswith("sfab-probe-") and n != lab)))
' "$LAB" || true)"
  if [ -z "$labs" ]; then ok "containerlab knows no other sfab lab"; else bad "containerlab knows no other sfab lab" "$labs"; fi
  procs="$(pgrep -af '^([^ ]*/)?(containerlab|clab) (deploy|dep)( |$)' 2>/dev/null || true)"
  if [ -z "$procs" ]; then ok "no containerlab deploy in progress"; else bad "no containerlab deploy in progress" "$(printf '%s' "$procs" | head -n 1)"; fi
}

pf_subnet() {
  local out
  local ids
  ids="$(dk network ls -q 2>/dev/null | paste -sd ' ' - || true)"
  out="$(
    { if [ -n "$ids" ]; then
        # shellcheck disable=SC2086 # one argument per network id
        dk network inspect $ids 2>/dev/null || echo '[]'
      else echo '[]'; fi; } | py -c '
import ipaddress, json, sys
net, subnet, prefix = sys.argv[1], ipaddress.ip_network(sys.argv[2]), sys.argv[3]
try:
    nets = json.load(sys.stdin)
except ValueError:
    nets = []
for n in nets:
    name = n.get("Name")
    subs = [c.get("Subnet") for c in ((n.get("IPAM") or {}).get("Config") or []) if c.get("Subnet")]
    hits = [s for s in subs if ipaddress.ip_network(s, strict=False).overlaps(subnet)]
    if name == net:
        if [str(ipaddress.ip_network(s, strict=False)) for s in subs] != [str(subnet)]:
            print(f"FAIL\t{net} exists with subnet {subs}, want {subnet}")
        foreign = sorted(c.get("Name", "") for c in (n.get("Containers") or {}).values() if not c.get("Name", "").startswith(prefix))
        if foreign:
            print(f"FAIL\t{net} has endpoints outside the lab: {foreign[:5]}")
        else:
            print(f"OK\t{net} exists with {subnet} and only this lab on it")
    elif hits:
        print(f"FAIL\tdocker network {name} holds {hits[0]}, which overlaps {subnet}")
' "$MGMT_NET" "$MGMT_SUBNET" "$PREFIX"
  )"
  local hostaddr
  hostaddr="$(ip -j -4 addr show 2>/dev/null | py -c '
import ipaddress, json, sys
subnet, bridge = ipaddress.ip_network(sys.argv[1]), sys.argv[2]
try:
    links = json.load(sys.stdin)
except ValueError:
    links = []
for l in links:
    for a in l.get("addr_info") or []:
        if a.get("local") and ipaddress.ip_address(a["local"]) in subnet and l.get("ifname") != bridge:
            print(l.get("ifname"), a["local"])
' "$MGMT_SUBNET" "$MGMT_BRIDGE" || true)"
  local fails=0
  while IFS=$'\t' read -r k msg; do
    [ -n "$k" ] || continue
    if [ "$k" = OK ]; then ok "subnet: $msg"; else bad "subnet $MGMT_SUBNET free for $MGMT_NET" "$msg"; fails=1; fi
  done <<<"$out"
  if [ -n "$hostaddr" ]; then
    bad "no host interface but $MGMT_BRIDGE in $MGMT_SUBNET" "$(printf '%s' "$hostaddr" | head -n 1)"
  elif [ "$fails" = 0 ] && ! grep -q '^OK' <<<"$out"; then
    ok "subnet $MGMT_SUBNET held by no docker network or host interface ($MGMT_NET not created yet)"
  fi
}

pf_images() {
  local img id rec
  rec="$(tmpf)"
  printf '{}' >"$rec"
  while read -r img; do
    [ -n "$img" ] || continue
    if id="$(dk image inspect --format '{{.Id}}' "$img" 2>/dev/null)"; then
      py - "$rec" "$img" "$id" "$(dk image inspect --format '{{json .RepoDigests}}' "$img" 2>/dev/null || echo '[]')" <<'PY'
import json, sys
p, img, iid, rd = sys.argv[1:5]
d = json.load(open(p))
try:
    rd = json.loads(rd) or []
except ValueError:
    rd = []
d[img] = {"id": iid, "repo_digests": rd}
json.dump(d, open(p, "w"), indent=2, sort_keys=True)
PY
      ok "image $img present (${id:7:12})"
    else
      case "$img" in
        vrnetlab/*) bad "image $img present" "build it from your own vendor image (vrnetlab images are never pulled)" ;;
        sfab/*) bad "image $img present" "make -C images builds it" ;;
        *) bad "image $img present" "not on this host" ;;
      esac
    fi
  done < <(py -c '
import json, sys
for ref in sorted(json.load(open(sys.argv[1])).get("images") or {}):
    print(ref)
' "$INV")
  if [ "${SFAB_PF_LIB:-0}" != 1 ]; then
    mkdir -p "$STATEDIR"
    printf '\n' >>"$rec"
    chmod 644 "$rec"
    mv "$rec" "$STATEDIR/images.json"
  else
    rm -f "$rec"
  fi
}

# pf_registry: a lab with the in-lab registry binds images/registry/data read-only into it, and
# containerlab refuses a bind whose source is missing. The seed (make -C images registry-seed)
# leaves SEED.json there; a checkout synced with rsync --delete loses a data link (registry-link
# puts it back). A lab without the registry prints nothing here.
pf_registry() {
  local data="$SFAB_ROOT/images/registry/data"
  [ -n "$(inv nodes --kind registry 2>/dev/null | head -n 1)" ] || return 0
  if [ -f "$data/SEED.json" ]; then
    ok "registry data seeded: images/registry/data holds SEED.json$([ ! -L "$data" ] || printf ' (a link to the image store)')"
  elif [ -e "$data" ] || [ -L "$data" ]; then
    bad "registry data seeded" "images/registry/data holds no SEED.json: make -C images registry-seed, or registry-link after a sync"
  else
    bad "registry data seeded" "no images/registry/data: make -C images registry-seed, or registry-link after a sync"
  fi
  pf_registry_local "$data"
}

# pf_registry_local DATA: a lab that runs the serving recipe pulls the two images built here
# (serving.env's SERVING_IMAGE and SERVING_KEYS_IMAGE) from the mirror, which has them only once
# make -C images registry-seed has pushed them; SEED.json lists each push.
pf_registry_local() {
  local data="$1" env="$RENDERDIR/bootstrap/k8s/serving.env" miss
  [ "${STAGE_SERVING:-0}" = 1 ] && [ -f "$data/SEED.json" ] || return 0
  [ -f "$env" ] || { bad "images built here in the registry" "bootstrap/k8s/serving.env is not rendered"; return 0; }
  miss="$(py - "$data/SEED.json" "$env" <<'PY'
import json, shlex, sys
have = {e.get("mirror") for e in (json.load(open(sys.argv[1], encoding="utf-8")).get("local") or [])}
want = []
for line in open(sys.argv[2], encoding="utf-8"):
    k, _, v = line.strip().partition("=")
    if k in ("SERVING_IMAGE", "SERVING_KEYS_IMAGE") and v:
        want.append(shlex.split(v)[0].split("/", 1)[-1])
print(" ".join(w for w in want if w not in have) if want else "SERVING_IMAGE")
PY
)" || miss="SEED.json unreadable"
  if [ -z "$miss" ]; then
    ok "images built here in the registry: SEED.json lists the serving and key images serving.env names"
  else
    bad "images built here in the registry" "$miss not pushed: make -C images registry-seed"
  fi
}

# pf_models: a lab that runs the serving recipe binds images/models read-only into the GPU nodes
# that run a model server, and containerlab refuses a bind whose source is missing. Each model file
# serving.env names must be there at its pinned size (make -C images models-fetch checks the sha256;
# a 15 GB hash at every deploy would cost minutes, so preflight compares sizes). A lab without
# serving prints nothing here.
pf_models() {
  local env="$RENDERDIR/bootstrap/k8s/serving.env" dir="$SFAB_ROOT/images/models" out
  [ "${STAGE_SERVING:-0}" = 1 ] || return 0
  [ -f "$env" ] || { bad "models in images/models" "bootstrap/k8s/serving.env is not rendered"; return 0; }
  if [ ! -d "$dir" ]; then
    bad "models in images/models" "no images/models: make -C images models-fetch, or models-link after a sync"
    return 0
  fi
  out="$(py - "$env" "$dir" <<'PY'
import os, shlex, sys
env, d = sys.argv[1], sys.argv[2]
rows = []
for line in open(env, encoding="utf-8"):
    k, _, v = line.strip().partition("=")
    if k.startswith("SERVING_MODEL_") and k[len("SERVING_MODEL_"):].isdigit():
        w = shlex.split(v)[0].split()
        rows.append((w[3], int(w[4])))
bad = []
for f, size in rows:
    p = os.path.join(d, f)
    have = os.path.getsize(p) if os.path.isfile(p) else None
    if have != size:
        bad.append(f"{f} {'missing' if have is None else f'is {have} bytes, not {size}'}")
print(("FAIL " + "; ".join(bad)) if bad else f"OK {len(rows)} model file(s): " + ", ".join(f for f, _ in rows))
PY
)" || out="FAIL serving.env unreadable"
  case $out in
    OK*) ok "models in images/models$([ ! -L "$dir" ] || printf ' (a link to the models store)'): ${out#OK }, each at its pinned size" ;;
    *) bad "models in images/models" "${out#FAIL }: make -C images models-fetch" ;;
  esac
}

# Budgets count only nodes that are not running yet, so a second `make up` passes on a live lab.
_budget_rest() {
  local n waiting=()
  for n in "${NODES[@]}"; do running "$n" || waiting+=("$n"); done
  py - "$INV" "$1" "${waiting[@]}" <<'PY'
import json, sys
inv, what, waiting = json.load(open(sys.argv[1])), sys.argv[2], set(sys.argv[3:])
nodes = inv.get("nodes") or {}
print(round(sum(float((nodes[n].get("budget") or {}).get(what) or 0) for n in waiting if n in nodes), 2))
PY
}

pf_mem() {
  local avail_kb avail need floor
  avail_kb="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo 2>/dev/null || true)"
  floor="$(inv get budget.floor_gib)"
  need="$(_budget_rest mem_gib)"
  if [ -z "$avail_kb" ]; then bad "free memory" "no MemAvailable in /proc/meminfo"; return 0; fi
  avail="$(awk -v k="$avail_kb" 'BEGIN{printf "%.1f", k / 1048576}')"
  if awk -v a="$avail" -v n="$need" -v f="$floor" 'BEGIN{exit !(a >= n + f)}'; then
    ok "free memory: MemAvailable $avail GiB covers $need GiB for the nodes not yet running plus the $floor GiB floor"
  else
    bad "free memory" "MemAvailable $avail GiB, need $need GiB plus the $floor GiB floor"
  fi
}

pf_cpu() {
  local need cpus over
  need="$(inv get budget.vcpus)"
  over="$(inv get budget.vcpu_overcommit)"
  cpus="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN)"
  if awk -v n="$need" -v c="$cpus" -v o="$over" 'BEGIN{exit !(n <= c * o)}'; then
    ok "vCPUs: $need for the lab within $over x $cpus host CPUs"
  else
    bad "vCPUs" "$need for the lab, more than $over x $cpus"
  fi
}

# pf_disk: the disk budget is what a deploy writes, where it writes it (FRAMEWORK.md 3.1), never a
# disk's virtual size. Two places:
# - state/: the lab's own files (budget.state_base_gib) plus each node's state_gib, less what its
#   state/nodes/<n> already holds (allocated blocks, so a thin disk counts what it uses), never
#   below 0 for a node;
# - Docker's data root (docker info's DockerRootDir): the layer_gib of each node not yet running,
#   the container layer where vrnetlab writes the switches' and the PA-VM's overlays.
# Where the two share a filesystem, its free space must cover both at once.
pf_disk() {
  local n root out verdict label detail waiting=()
  mkdir -p "$STATEDIR"
  for n in "${NODES[@]}"; do running "$n" || waiting+=("$n"); done
  root="$(dk info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
  out="$(py - "$INV" "$STATEDIR" "$root" "${waiting[@]}" <<'PY'
import json, os, sys
inv_path, state, root, waiting = sys.argv[1], sys.argv[2], sys.argv[3], set(sys.argv[4:])
inv = json.load(open(inv_path))
nodes, budget = inv.get("nodes") or {}, inv.get("budget") or {}
G = float(1 << 30)


def used(path):
    total = 0
    for d, _, files in os.walk(path):
        for f in files:
            try:
                total += os.lstat(os.path.join(d, f)).st_blocks * 512
            except OSError:
                pass
    return total / G


def free(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize / G


def b(n, what):
    return float((nodes[n].get("budget") or {}).get(what) or 0)


base = float(budget.get("state_base_gib") or 0)
plan, held, state_need = base, 0.0, base
for n in nodes:
    want, have = b(n, "state_gib"), used(os.path.join(state, "nodes", n))
    plan += want
    held += min(have, want)
    state_need += max(0.0, want - have)
layer_need = sum(b(n, "layer_gib") for n in waiting if n in nodes)
st = "%.1f GiB under state/ (budget %.1f GiB, %.1f GiB of it already there)" % (state_need, plan, held)
if not root or not os.path.isdir(root):
    print("FAIL\tdisk\tdocker info gives no data root (DockerRootDir %r), so the container layers cannot be judged" % root)
    raise SystemExit(0)
ly = "%.1f GiB of container layers under %s for the nodes not yet running" % (layer_need, root)
if os.stat(state).st_dev == os.stat(root).st_dev:
    f = free(state)
    if f >= state_need + layer_need:
        print("PASS\tdisk: %.1f GiB free covers %s and %s, one filesystem (%.1f GiB)" % (f, st, ly, state_need + layer_need))
    else:
        print("FAIL\tdisk\t%.1f GiB free, need %s and %s, one filesystem (%.1f GiB)" % (f, st, ly, state_need + layer_need))
else:
    for where, need, text in (("state/", state_need, st), (root, layer_need, ly)):
        f = free(state if where == "state/" else root)
        if f >= need:
            print("PASS\tdisk: %.1f GiB free under %s covers %s" % (f, where, text))
        else:
            print("FAIL\tdisk under %s\t%.1f GiB free, need %s" % (where, f, text))
PY
)" || true
  [ -n "$out" ] || { bad "disk" "the disk budget could not be read from the inventory"; return 0; }
  while IFS=$'\t' read -r verdict label detail; do
    case "$verdict" in
      PASS) ok "$label" ;;
      *) bad "$label" "$detail" ;;
    esac
  done <<<"$out"
}

pf_modules() {
  local m
  for m in "${MODULES[@]}"; do
    if [ -d "/sys/module/$m" ]; then
      ok "module $m loaded"
    elif [ "${SFAB_PF_LIB:-0}" = 1 ]; then
      bad "module $m loaded" "not loaded"
    elif modprobe "$m" 2>/dev/null; then
      ok "module $m loaded now (modprobe; not persistent)"
    else
      bad "module $m" "modprobe failed"
    fi
  done
  [ ${#MODULES[@]} -gt 0 ] || ok "no kernel module needed"
}

pf_secrets() {
  local out rc=0
  if [ "${SFAB_PF_LIB:-0}" = 1 ]; then
    out="$(py "$SFAB_COMMON/bin/secrets.py" check --state "$STATEDIR" 2>&1)" || rc=$?
  else
    out="$(py "$SFAB_COMMON/bin/secrets.py" ensure --state "$STATEDIR" --lab "$LAB" 2>&1)" || rc=$?
  fi
  [ -z "$out" ] || printf '%s\n' "$out" | sed 's/^/  /'
  if [ "$rc" -eq 0 ]; then ok "state/secrets.env (0600) and the lab SSH key present"; else bad "secrets" "$(printf '%s' "$out" | tail -n 1)"; fi
}

# cloud-init makes a VM guest's login user once per disk, so a disk made for another guest.user
# (every disk before 2026-10-27 was made for sfab) never gets this one. state/guest-user records
# the user the guests' disks were made for; it is written when no guest disk exists yet.
pf_guest_user() {
  local g disks=0 was
  [ "${#GUESTS[@]}" -gt 0 ] || { ok "no VM guest: no login user to match"; return 0; }
  for g in "${GUESTS[@]}"; do [ -f "$STATEDIR/nodes/$g/root.qcow2" ] && disks=$((disks + 1)); done
  if [ "$disks" -eq 0 ]; then
    [ "${SFAB_PF_LIB:-0}" = 1 ] || printf '%s\n' "$GUEST_USER" >"$STATEDIR/guest-user"
    ok "guest login user $GUEST_USER (no guest disk yet)"
    return 0
  fi
  was="$(head -n 1 "$STATEDIR/guest-user" 2>/dev/null || echo sfab)"
  if [ "$was" = "$GUEST_USER" ]; then
    ok "guest login user $GUEST_USER, as the guests' disks were made for"
  else
    bad "guest login user" "the guests' disks were made for $was, the render logs in as $GUEST_USER: run make wipe"
  fi
}

pf_render() {
  local out rc=0
  out="$("$SFAB_COMMON/bin/sfab" check "$LABDIR" ${VARIANT:+--variant "$VARIANT"} 2>&1)" || rc=$?
  case "$rc" in
    0) ok "render: sfab check clean" ;;
    3) skip "render: sfab check" "PyYAML is not installed; the committed render still deploys" ;;
    *) bad "render: sfab check" "$(printf '%s\n' "$out" | grep -v '^sfab: warning' | head -n 2 | paste -sd ' ' -)" ;;
  esac
}

preflight_main() {
  sec "preflight $LAB ($(utc))"
  pf_identity
  pf_tools
  pf_kvm
  pf_tick
  pf_other_labs
  pf_subnet
  pf_images
  pf_registry
  pf_models
  pf_mem
  pf_cpu
  pf_disk
  pf_modules
  pf_secrets
  pf_guest_user
  pf_render
  local rc=0
  summary || rc=$?
  {
    printf '# preflight %s\n' "$(utc)"
    cat "$SFAB_VERDICT"
  } >"$STATEDIR/preflight.last"
  rm -f "$SFAB_VERDICT"
  [ "$rc" -eq 0 ] || { printf 'preflight: refusing to deploy %s\n' "$LAB" >&2; return 1; }
}

if [ "${SFAB_PF_LIB:-0}" != 1 ]; then
  set -euo pipefail
  # shellcheck source=common/lib.sh
  . "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib.sh"
  sfab_init preflight "$@"
  preflight_main
fi
